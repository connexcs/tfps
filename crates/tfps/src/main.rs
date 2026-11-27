//! TFPS — watches SIP on the wire, learns each source's behaviour, and decides.
//!
//! Capture is `AF_PACKET`/`SOCK_DGRAM`, hooking at the netdev layer and **not opening a UDP
//! socket**: the softswitch keeps its own bind and never notices (`SPEC.md` §2).
//!
//! The perimeter already enforces: a source condemned by user-agent, URI injection or
//! credential brute force goes into a map the XDP program consults, and vanishes from
//! sngrep. The **fraud** verdict is report-only by default; `--enforce-behavioural` adds a
//! source-level XDP block. The forged `603` is still missing.
//!
//! Needs `CAP_NET_RAW` (capture), plus `CAP_BPF` and `CAP_NET_ADMIN` (XDP).

use tfps::{apiban, config, say, store, xdp};

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use socket2::{Domain, Protocol, Socket, Type};
use tfps_core::dialplan::DialPlan;
use tfps_core::disposition::{disposition, is_one_way, Disposition};
use tfps_core::engine::{Decision, Engine, Mode};
use tfps_core::net::{classify_other, parse_ipv4_udp, tcp_ports, NotUdp};
use tfps_core::novelty::Timestamp;

/// Where the APIBAN resume point is kept between runs.
const APIBAN_ID_KEY: &str = "apiban_id";

/// How long a feed address stays applied. APIBAN is a rolling list of hotspots, not a
/// permanent verdict, and an address that left the feed a week ago has probably been
/// cleaned up or reassigned.
const APIBAN_RETENTION_SECS: u32 = 7 * 24 * 3600;

/// `AF_PACKET` on Linux. `socket2` exposes no constant for this family, so the value goes
/// in directly — it has been stable in the Linux ABI forever.
const AF_PACKET: i32 = 17;

/// `ETH_P_IP` in network order, as `AF_PACKET`'s `socket(2)` expects.
const ETH_P_IP_BE: i32 = 0x0008;

/// A generous MTU: SIP over UDP rarely exceeds this, and what does gets fragmented.
const BUF: usize = 65_536;

/// With HEP on: no mirrored message for this long, while TCP is seen on the SIP
/// ports, is an alarm. Also how long HEP counts as delivering after its last message.
const HEP_SILENCE_SECS: u32 = 300;

struct Args {
    ports: Vec<u16>,
    intl_prefixes: Vec<String>,
    learn_secs: u32,
    behavioural: bool,
    /// Enforce a behavioural Block in XDP (off by default; requires --behavioural).
    enforce_behavioural: bool,
    stats_every: u64,
    verbose: bool,
    debug_unparsed: bool,
    xdp_obj: PathBuf,
    shared_map: PathBuf,
    iface: Option<String>,
    block_ttl: u64,
    no_enforce: bool,
    /// Report one-way perimeter evidence but do not enforce it (spoofable source).
    no_enforce_one_way: bool,
    db: PathBuf,
    /// `manual_log_dir` from the configuration file.
    manual_log_dir: Option<PathBuf>,
    /// `reapply_manual_bans` from the configuration file.
    reapply_manual_bans: bool,
    checkpoint_every: u64,
    apiban_key: Option<String>,
    ignoreip: Vec<String>,
    home_countries: Vec<String>,
    signatures: Option<PathBuf>,
    config: PathBuf,
    /// Per-peer dial plan from the file. Declaring beats learning because it holds on
    /// that peer's very first call.
    peer_plans: Vec<(Ipv4Addr, DialPlan)>,
    /// The HEP listener's section from the configuration file.
    hep: Option<config::HepConfig>,
    /// Which flags the operator actually passed — the file only fills in the rest.
    given: std::collections::HashSet<String>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            ports: vec![5060],
            // Covers the common shapes; `SPEC.md` §4 says to declare it per PBX.
            intl_prefixes: vec!["+".into(), "00".into(), "011".into(), "9011".into()],
            learn_secs: 30 * 24 * 3600,
            behavioural: false,
            enforce_behavioural: false,
            stats_every: 60,
            verbose: false,
            debug_unparsed: false,
            xdp_obj: PathBuf::from(xdp::DEFAULT_OBJ),
            shared_map: PathBuf::from(xdp::SIPVAULT_DROP_MAP),
            iface: None,
            // One hour. A perimeter block must undo itself, and a scanner that returns is
            // re-blocked on its first packet — the cost of being wrong is one hour.
            block_ttl: 3600,
            no_enforce: false,
            no_enforce_one_way: false,
            db: PathBuf::from(store::DEFAULT_PATH),
            manual_log_dir: None,
            reapply_manual_bans: false,
            // Five minutes. Losing that to a power cut costs five minutes of learning —
            // and checkpointing per packet would be a write bottleneck.
            checkpoint_every: 300,
            apiban_key: None,
            ignoreip: Vec::new(),
            home_countries: Vec::new(),
            signatures: None,
            config: PathBuf::from(config::DEFAULT_PATH),
            peer_plans: Vec::new(),
            hep: None,
            given: std::collections::HashSet::new(),
        }
    }
}

fn usage() -> &'static str {
    "\
tfps — IRSF fraud prevention for SIP networks

USAGE: tfps [options]

  --ports 5060,5080        SIP ports to watch             (default: 5060)
  --intl +,00,011,9011     international dialling prefixes
  --learn-days N           days in learning mode          (default: 30)
  --active                 skip learning (same as --learn-days 0)
  --stats-every N          seconds between reports        (default: 60)
  -v, --verbose            print every international attempt
      --debug-unparsed     show the start of payloads that failed to parse
      --iface eth0         XDP interface               (default: default route)
      --xdp-obj PATH       our BPF object              (default: /usr/local/lib/tfps/tfps_xdp.o)
      --drop-map PATH      a drop map already pinned by another product
      --block-ttl N        seconds a block lasts       (default: 3600, 0 = never expires)
      --no-enforce         observe only, do not load XDP
      --no-enforce-one-way report one-way evidence but do not block it
      --enforce-one-way    override a config that enabled one-way report-only
      --enforce-behavioural enforce behavioural Block in XDP (requires --behavioural)
      --no-enforce-behavioural report-only behavioural verdicts (default)
      --db PATH            SQLite database             (default: /var/lib/tfps/tfps.db)
      --no-db              do not persist (learning dies on restart)
      --checkpoint-every N seconds between writes      (default: 300)
      --ignoreip CIDR      never enforce against this address or network (repeatable)
      --home-country ISO   your own country, not treated as international (repeatable)
      --signatures PATH    file that ADDS signatures to the built-in ones
      --config PATH        configuration               (default: /etc/tfps/config.json)
  -h, --help               this help

Capture is AF_PACKET; it opens no UDP socket and does not clash with the softswitch.
Requires CAP_NET_RAW (run as root).

DISCLAIMER: TFPS cannot detect every type of fraud. It sees SIP on the wire only.
Behavioural detection is experimental; it is report-only unless --enforce-behavioural is set.
Use at your own risk.
"
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        a.given.insert(arg.clone());
        let mut next = |name: &str| it.next().ok_or_else(|| format!("{name} requires a value"));
        match arg.as_str() {
            "-h" | "--help" => {
                say!("{}", usage().trim_end());
                std::process::exit(0);
            }
            "--ports" => {
                a.ports = next("--ports")?
                    .split(',')
                    .map(|p| {
                        p.trim()
                            .parse::<u16>()
                            .map_err(|e| format!("invalid port: {e}"))
                    })
                    .collect::<Result<_, _>>()?;
            }
            "--intl" => {
                a.intl_prefixes = next("--intl")?
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
            }
            "--learn-days" => {
                let d: u32 = next("--learn-days")?.parse().map_err(|e| format!("{e}"))?;
                a.learn_secs = d * 24 * 3600;
            }
            "--active" => a.learn_secs = 0,
            "--behavioural" | "--fraud" => a.behavioural = true,
            "--enforce-behavioural" => a.enforce_behavioural = true,
            "--no-enforce-behavioural" => a.enforce_behavioural = false,
            "--stats-every" => {
                a.stats_every = next("--stats-every")?.parse().map_err(|e| format!("{e}"))?;
            }
            "-v" | "--verbose" => a.verbose = true,
            "--debug-unparsed" => a.debug_unparsed = true,
            "--xdp-obj" => a.xdp_obj = PathBuf::from(next("--xdp-obj")?),
            "--drop-map" => a.shared_map = PathBuf::from(next("--drop-map")?),
            "--iface" => a.iface = Some(next("--iface")?),
            "--block-ttl" => {
                a.block_ttl = next("--block-ttl")?.parse().map_err(|e| format!("{e}"))?;
            }
            "--no-enforce" => a.no_enforce = true,
            "--no-enforce-one-way" => a.no_enforce_one_way = true,
            "--enforce-one-way" => a.no_enforce_one_way = false,
            "--db" => a.db = PathBuf::from(next("--db")?),
            "--no-db" => a.db = PathBuf::new(),
            // The key is a secret: accept config only, never argv (/proc/<pid>/cmdline and
            // shell history are readable by local users).
            "--ignoreip" => a.ignoreip.push(next("--ignoreip")?),
            "--home-country" => a.home_countries.push(next("--home-country")?),
            "--signatures" => a.signatures = Some(PathBuf::from(next("--signatures")?)),
            "--config" => a.config = PathBuf::from(next("--config")?),
            "--checkpoint-every" => {
                a.checkpoint_every = next("--checkpoint-every")?
                    .parse()
                    .map_err(|e| format!("{e}"))?;
            }
            other => return Err(format!("unknown option: {other}")),
        }
    }
    if a.ports.is_empty() {
        return Err("no ports to watch".into());
    }
    Ok(a)
}

/// Applies the file on top of the defaults, **without overriding the command line**.
///
/// Precedence: command line > file > built-in default. It is the order that surprises
/// nobody, and the one that lets you debug in production without editing a file.
fn apply_config(a: &mut Args, c: &config::Config) {
    macro_rules! unless_given {
        ($flag:literal, $field:ident, $val:expr) => {
            if !a.given.contains($flag) {
                if let Some(v) = $val {
                    a.$field = v;
                }
            }
        };
    }
    unless_given!("--ports", ports, c.ports.clone());
    unless_given!("--intl", intl_prefixes, c.intl_prefixes.clone());
    unless_given!("--stats-every", stats_every, c.stats_every);
    unless_given!("--block-ttl", block_ttl, c.block_ttl);
    unless_given!("--checkpoint-every", checkpoint_every, c.checkpoint_every);
    unless_given!("--db", db, c.db.clone());
    // No command-line flags for these two: they are installation settings.
    a.manual_log_dir = c.manual_log_dir.clone();
    a.reapply_manual_bans = c.reapply_manual_bans;
    a.hep = c.hep.clone();
    unless_given!("--xdp-obj", xdp_obj, c.xdp_obj.clone());
    unless_given!("--drop-map", shared_map, c.drop_map.clone());

    if !a.given.contains("--iface") && c.iface.is_some() {
        a.iface = c.iface.clone();
    }
    // The file adds to the command line here rather than replacing it: both are the
    // operator's own words, and dropping either would be a surprise.
    a.ignoreip.extend(c.ignoreip.iter().cloned());
    a.home_countries.extend(c.home_countries.iter().cloned());
    if !a.given.contains("--apiban-key") && c.apiban_key.is_some() {
        a.apiban_key = c.apiban_key.clone();
    }
    if !a.given.contains("--learn-days") && !a.given.contains("--active") {
        if let Some(d) = c.learn_days {
            a.learn_secs = d.saturating_mul(24 * 3600);
        }
    }
    // The file can enable the layer regardless of a CLI --active/--learn-days; those only
    // choose the window, not whether the layer exists.
    if c.behavioural {
        a.behavioural = true;
    }
    if !a.given.contains("--enforce-behavioural") && !a.given.contains("--no-enforce-behavioural") {
        a.enforce_behavioural = c.enforce_behavioural;
    }
    if !a.given.contains("--no-enforce-one-way") && !a.given.contains("--enforce-one-way") {
        a.no_enforce_one_way = c.no_enforce_one_way;
    }

    for (ip, pc) in &c.peers {
        match ip.parse::<Ipv4Addr>() {
            Ok(addr) => {
                let mut plan = DialPlan::new(pc.intl_prefixes.clone());
                if pc.bare_e164 {
                    plan = plan.with_bare_e164();
                }
                a.peer_plans.push((addr, plan));
            }
            // A peer with an invalid IP is a typo that would make the operator believe
            // they declared a plan that does not apply. Never silently.
            Err(e) => {
                eprintln!("WARNING: peer \"{ip}\" in the config is not a valid IPv4 address ({e})")
            }
        }
    }
}

fn now() -> Timestamp {
    Timestamp(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0),
    )
}

fn main() -> ExitCode {
    let mut extra_signatures: Vec<String> = Vec::new();
    let mut extra_injection: Vec<String> = Vec::new();
    let mut extra_scanners: Vec<String> = Vec::new();
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n\n{}", usage());
            return ExitCode::from(2);
        }
    };

    let mut args = args;
    match config::load(&args.config) {
        config::Loaded::File(c, path) => {
            apply_config(&mut args, &c);
            say!("  configuration     : {}", path.display());
            // File signatures are applied after the engine exists; kept here until then.
            extra_signatures = c.signatures.clone();
            extra_injection = c.injection.clone();
            extra_scanners = c.scanners.clone();
        }
        config::Loaded::Absent => {}
        config::Loaded::Broken(e) => {
            // Broken configuration ignored silently would make the operator believe they
            // declared something that does not apply.
            eprintln!("ALARM: invalid configuration, falling back to defaults — {e}");
        }
    }
    let args = args;

    let start = now();

    // The database opens before the engine because it decides **when learning started** —
    // without that, every restart would reset the 30 days and the countdown would lie.
    let db = if args.db.as_os_str().is_empty() {
        None
    } else {
        match store::Store::open(&args.db) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("ALARM: no persistence — {e}");
                eprintln!("       learning will be lost on the next restart.");
                None
            }
        }
    };

    let learn_from = db
        .as_ref()
        .map(|d| match d.learning_started(start.0) {
            Ok(t) => t,
            Err(e) => {
                // Learning still starts now; what is lost is the record of when,
                // which would silently restart the window on the next boot.
                eprintln!("WARNING: learning window: {e}");
                start.0
            }
        })
        .unwrap_or(start.0);

    let mode = if args.learn_secs == 0 {
        Mode::Active
    } else {
        Mode::Learning {
            until: Timestamp(learn_from.saturating_add(args.learn_secs)),
        }
    };

    let plan = DialPlan::new(args.intl_prefixes.clone());
    let mut engine = Engine::new(plan, mode);
    if args.behavioural {
        engine = engine.with_behavioural();
    }
    if args.enforce_behavioural && !args.behavioural {
        eprintln!("WARNING: --enforce-behavioural has no effect without --behavioural");
    }
    let unknown_home = engine.set_home_countries(args.home_countries.iter().map(String::as_str));
    for iso in &unknown_home {
        eprintln!("WARNING: home country \"{iso}\" is not a known ISO label — ignored");
    }

    // Signatures **add** to the built-in ones; they never replace. Replacing would make
    // someone who writes three lines silently lose the 18 shipped ones.
    for sig in &extra_signatures {
        engine.noise_filter.add_signature(sig);
    }
    for pat in &extra_injection {
        engine.noise_filter.add_injection(pat);
    }
    for id in &extra_scanners {
        engine.noise_filter.add_scanner(id);
    }
    for (ip, plan) in &args.peer_plans {
        engine.declare_dial_plan(*ip, plan.clone());
    }
    if !args.peer_plans.is_empty() {
        say!("  declared plans    : {} peers", args.peer_plans.len());
    }
    if let Some(path) = args.signatures.as_ref() {
        match std::fs::read_to_string(path) {
            Ok(txt) => {
                let mut ua = 0usize;
                let mut inj = 0usize;
                for line in txt.lines() {
                    match line.trim().split_once(char::is_whitespace) {
                        Some(("injection", rest)) => {
                            engine.noise_filter.add_injection(rest);
                            inj += 1;
                        }
                        Some(("scanner", rest)) => {
                            engine.noise_filter.add_scanner(rest);
                        }
                        _ => {
                            engine.noise_filter.add_signature(line);
                            ua += 1;
                        }
                    }
                }
                say!(
                    "  extra signatures  : {ua} user-agent, {inj} injection ({})",
                    path.display()
                );
            }
            Err(e) => eprintln!("WARNING: could not read {}: {e}", path.display()),
        }
    }
    let (ua_int, ua_ext) = engine.noise_filter.signature_count();
    let (inj_int, inj_ext) = engine.noise_filter.injection_count();
    let (scan_int, scan_ext) = engine.noise_filter.scanner_count();

    if engine.behavioural_enabled() {
        if let Some(d) = db.as_ref() {
            match d.load_into(&mut engine) {
                Ok((p, c)) if p > 0 || c > 0 => {
                    say!("  state restored    : {p} pairs, {c} peer-country rows");
                }
                Ok(_) => say!("  state restored    : empty database (first run)"),
                Err(e) => eprintln!("WARNING: could not restore state: {e}"),
            }
        }
    }

    say!("tfps {} — starting", env!("CARGO_PKG_VERSION"));
    say!(
        "  disclaimer        : TFPS cannot detect every fraud type; behavioural detection is experimental and report-only unless --enforce-behavioural is set. Use at your own risk."
    );
    say!("  watched ports     : {:?}", args.ports);
    say!("  intl prefixes     : {:?}", args.intl_prefixes);
    // The NANPA footgun: a bare "1" stripped as a prefix turns 1-212-… into 212… which
    // resolves to Morocco, and 1-767… into Russia. +1 numbers must keep their country code.
    let peer_has_one = args
        .peer_plans
        .iter()
        .any(|(_, p)| p.prefixes().iter().any(|x| x == "1"));
    if args.intl_prefixes.iter().any(|p| p == "1") || peer_has_one {
        eprintln!(
            "WARNING: \"1\" is configured as an international prefix. For NANPA (+1), \
             stripping it mis-resolves numbers (1-212 -> Morocco, 1-767 -> Russia). Use \
             `bare_e164` (or the `+` prefix) so +1XXX keeps its country code, and set \
             `home_countries: [\"NANP\"]` for domestic US/Canada."
        );
    }
    // The behavioural layer only reasons about *international* destinations, and the
    // international prefixes are how it tells one from an internal extension or an inbound
    // call to an E.164 DID. Wrong prefixes mean the wrong calls are judged — so with
    // behavioural on, make the operator confirm them rather than trust a default.
    if engine.behavioural_enabled() {
        say!(
            "  ATTENTION         : behavioural detection reasons only about INTERNATIONAL \
             calls. Configure `intl_prefixes` (globally and per peer) for THIS installation \
             — it is how extensions and inbound E.164 DIDs are told apart from real \
             outbound international destinations. Defaults are a starting point, not a fit."
        );
        if engine.home_country_count() == 0 {
            say!(
                "  RECOMMENDED       : set `home_countries` (e.g. [\"BR\"]) so calls to your \
                 own country are treated as national, not international."
            );
        } else {
            say!(
                "  home countries    : {} configured (national, not international)",
                engine.home_country_count()
            );
        }
        say!(
            "  RECOMMENDED       : add your INBOUND gateway IPs to `ignoreip` — they deliver \
             calls to your internal destinations and should never be judged or blocked."
        );
    }
    if !engine.behavioural_enabled() {
        say!("  mode              : PREVENTION (perimeter/fail2ban replacement; --behavioural adds the experimental layer)");
    } else {
        match mode {
            // The mode is announced loudly and repeated: this project's difference from
            // fail2ban is that the incumbent fails silently (`SPEC.md` §12).
            Mode::Active => {
                if args.enforce_behavioural && !args.no_enforce {
                    say!(
                        "  mode              : FRAUD DETECTION, ACTIVE — ENFORCING source-level XDP block (ttl {}s)",
                        args.block_ttl
                    );
                } else if args.enforce_behavioural {
                    say!(
                        "  mode              : FRAUD DETECTION, ACTIVE — REPORT-ONLY (--no-enforce overrides --enforce-behavioural)"
                    );
                } else {
                    say!(
                        "  mode              : FRAUD DETECTION, ACTIVE — REPORT-ONLY (use --enforce-behavioural to block)"
                    );
                }
            }
            Mode::Learning { until } => say!(
                "  mode              : FRAUD DETECTION, LEARNING for {} days (until {}), does NOT block",
                args.learn_secs / 86400,
                until.0
            ),
        }
    }
    if args.no_enforce_one_way {
        say!(
            "  one-way evidence  : REPORT-ONLY (user-agent, scanner, injection, ambiguous-header, reg-scan, auth-volume)"
        );
    }
    // Enforcement: load XDP, or say so loudly and carry on observing. Never pretend.
    // `not_enforcing` says why, for the state file below.
    let mut not_enforcing = String::from("--no-enforce");
    let mut enforcer = if args.no_enforce {
        say!("  enforcement       : OFF via --no-enforce (observe only)");
        None
    } else {
        let iface = args
            .iface
            .clone()
            .or_else(xdp::default_interface)
            .unwrap_or_else(|| "eth0".to_string());
        match xdp::Enforcer::attach(&args.shared_map, &args.xdp_obj, &iface, &args.ports) {
            Ok(e) => {
                say!(
                    "  enforcement       : {} — garbage vanishes from sngrep",
                    e.mode
                );
                say!("  block expires in  : {}s", args.block_ttl);
                Some(e)
            }
            Err(err) => {
                // SPEC §12 requirement: an anti-fraud system that appears to protect
                // without protecting is exactly this project's criticism of the incumbent.
                eprintln!("ALARM: enforcement INACTIVE — {err}");
                not_enforcing = format!("enforcement failed to start: {err}");
                eprintln!("       the system will OBSERVE but will NOT block anything.");
                say!("  enforcement       : INACTIVE (see the alarm above)");
                None
            }
        }
    };
    publish_state(enforcer.as_ref(), &not_enforcing);
    say!(
        "  perimeter         : {ua_int} user-agents (+{ua_ext} from file), \
         {inj_int} injection patterns (+{inj_ext}), {scan_int} scanner ids (+{scan_ext})"
    );

    // One assembly, shared with `tfps_ctl ban` (`tfps::guard`). The daemon's policy on a
    // refused entry: announce it and carry on, because there are hours of traffic ahead
    // and a startup report to say it in.
    let local = xdp::local_addresses();
    let guard = tfps::guard::assemble(&local, args.ignoreip.iter().map(String::as_str));
    for e in &guard.rejected {
        eprintln!("ALARM: ignoreip entry rejected — {e}");
    }
    let mut ignoreip = guard.list;
    // §12 requires the operator to see which rules exist, not just how many.
    say!(
        "  ignoreip          : {} local, {} declared",
        ignoreip.len() - ignoreip.declared(),
        ignoreip.declared()
    );
    for (label, origin, _) in ignoreip.report() {
        say!("                      {label} ({})", origin.describe());
    }

    // A restart starts from an empty block map. With `reapply_manual_bans` set, manual
    // bans still in force are placed again from `tfps_ctl`'s record, through the
    // same gate as every other block: ignoreip first, then registered peers.
    if args.reapply_manual_bans {
        let manual_dir = tfps::manual_log::resolve_dir(args.manual_log_dir.as_deref(), &args.db);
        let (actions, unreadable) = tfps::manual_log::read_all(&manual_dir);
        if unreadable > 0 {
            eprintln!(
                "WARNING: {unreadable} line(s) of the manual-action record in {} could not be read",
                manual_dir.display()
            );
        }
        let plan = tfps::manual_log::reapply_plan(&actions, start.0);
        let exempt = |ip: Ipv4Addr| -> Option<String> {
            ignoreip.exempt(ip).map(str::to_string).or_else(|| {
                engine
                    .is_known_peer(ip, start)
                    .then(|| "registered peer".to_string())
            })
        };
        let enforcing = enforcer.is_some();
        let mut place = |ip: Ipv4Addr, ttl: u64| match enforcer.as_mut() {
            Some(e) => e.block(ip, ttl),
            None => Err("no enforcer".to_string()),
        };
        let report = tfps::manual_log::reapply(
            &plan,
            exempt,
            if enforcing { Some(&mut place) } else { None },
        );
        say!(
            "  manual bans       : {} re-applied from {}, {} exempt, {} failed{}",
            report.reapplied,
            manual_dir.display(),
            report.exempt.len(),
            report.failed.len(),
            if report.observe_only > 0 {
                format!(", {} not placed (observe only)", report.observe_only)
            } else {
                String::new()
            }
        );
        for (ip, rule) in &report.exempt {
            say!("                      {ip} not re-applied: exempt by {rule}");
        }
        for (ip, e) in &report.failed {
            eprintln!("ALARM: could not re-apply the manual ban on {ip}: {e}");
        }
    }

    // The HEP listener, when configured: the decrypted SIP the application server
    // mirrors from its TLS and WebSocket connections. Nothing is bound otherwise.
    let hep_counters = Arc::new(tfps::hep::Counters::default());
    let hep_rx = match args.hep.as_ref().filter(|h| h.enabled) {
        None => None,
        Some(h) => {
            if !h.listen.ip().is_loopback() {
                eprintln!(
                    "WARNING: the HEP listener is on {}, not loopback. Any sender in \
                     `allow_from` can get an address blocked{}.",
                    h.listen,
                    if h.auth_key.is_some() {
                        ""
                    } else {
                        "; set `auth_key` too"
                    }
                );
            }
            if h.transports.is_empty() {
                eprintln!("WARNING: HEP `transports` is empty: every mirrored message is skipped");
            }
            match tfps::hep::spawn(h, Arc::clone(&hep_counters)) {
                Ok((rx, addr)) => {
                    say!(
                        "  HEP input         : UDP {addr}, from {:?}, transports {:?}{}",
                        h.allow_from,
                        h.transports,
                        if h.auth_key.is_some() {
                            ", auth key required"
                        } else {
                            ""
                        }
                    );
                    Some(rx)
                }
                Err(e) => {
                    eprintln!(
                        "ALARM: the HEP listener could not bind {}: {e}. SIP over TLS and \
                         WebSocket will NOT be inspected.",
                        h.listen
                    );
                    None
                }
            }
        }
    };

    let sock = match Socket::new(
        Domain::from(AF_PACKET),
        Type::DGRAM,
        Some(Protocol::from(ETH_P_IP_BE)),
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: could not open the capture socket: {e}");
            eprintln!("       AF_PACKET requires CAP_NET_RAW — run as root.");
            return ExitCode::FAILURE;
        }
    };

    // A read timeout so the loop wakes even with no traffic. **Without this the silence
    // alarm can never fire**: it would sit inside a loop that only runs when a packet
    // arrives, and a system seeing nothing would stay mute — precisely the fail2ban failure
    // mode this project uses as its difference (`SPEC.md` §12).
    // With HEP on, the loop also drains the HEP queue, so it wakes more often: a
    // mirrored message must not wait a second for a packet on a quiet link.
    let read_timeout = if hep_rx.is_some() {
        Duration::from_millis(50)
    } else {
        Duration::from_secs(1)
    };
    if let Err(e) = sock.set_read_timeout(Some(read_timeout)) {
        eprintln!("warning: could not set a read timeout: {e}");
        eprintln!("         the silence alarm may not fire on a quiet link.");
    }

    // `socket2::Socket` implements `Read`, which allows a normal buffer and avoids
    // `MaybeUninit` — and therefore avoids `unsafe`, which the workspace forbids.
    let mut sock = sock;
    let mut buf = vec![0u8; BUF];
    let mut last_report = start.0;
    let mut seen_ports: BTreeMap<u16, u64> = BTreeMap::new();
    // APIBAN on its own thread: HTTP never touches the packet path. It was the synchronous
    // `rest_get()` per INVITE that capped the 2023 TFPS at ~26 calls/s.
    let apiban_rx = args.apiban_key.as_ref().map(|k| {
        // Resume where the last run stopped. Without this the whole feed is refetched on
        // every restart — the module documents the resume, so not wiring it up would have
        // been a promise kept only in a comment.
        let resume = db.as_ref().and_then(|s| s.meta_get(APIBAN_ID_KEY));
        match &resume {
            Some(id) => say!("  APIBAN            : enabled, resuming from id {id}"),
            None => say!("  APIBAN            : enabled, first sync (whole feed)"),
        }
        apiban::spawn(k.clone(), resume)
    });

    // Load the known-good registered peers first, so the APIBAN restore below never blocks
    // one. This runs in prevention mode too — it is perimeter state, not behavioural.
    if let Some(s) = db.as_ref() {
        match s.known_peers_since(
            start
                .0
                .saturating_sub(tfps_core::engine::KNOWN_PEER_TTL_SECS),
        ) {
            Ok(peers) if !peers.is_empty() => {
                for (ip, ts) in &peers {
                    engine.import_known_peer(*ip, *ts);
                }
                say!(
                    "  registered peers  : {} known-good, exempt from banning",
                    peers.len()
                );
            }
            Ok(_) => {}
            Err(e) => eprintln!("WARNING: could not load known peers: {e}"),
        }
    }

    // Re-apply what the feed already gave us. The map died with the previous process and
    // the feed cursor only moves forward, so without this the integration would come back
    // up protecting nothing — and would look perfectly healthy while doing it.
    let mut apiban_total = 0u64;
    if args.apiban_key.is_some() {
        if let (Some(s), Some(e)) = (db.as_ref(), enforcer.as_mut()) {
            match s.apiban_since(start.0.saturating_sub(APIBAN_RETENTION_SECS)) {
                Ok(ips) => {
                    let (mut restored, mut failed) = (0u64, 0u64);
                    for ip in ips {
                        if ignoreip.exempt(ip).is_some() || engine.is_known_peer(ip, start) {
                            continue;
                        }
                        match e.block(ip, u64::from(APIBAN_RETENTION_SECS)) {
                            Ok(()) => restored += 1,
                            // Announcing a restore that did not happen would leave the
                            // operator believing in protection that is not there.
                            Err(_) => failed += 1,
                        }
                    }
                    apiban_total = restored;
                    if restored > 0 {
                        say!("  APIBAN restored   : {restored} addresses from the last 7 days");
                    }
                    if failed > 0 {
                        eprintln!("ALARM: {failed} APIBAN addresses could not be restored");
                    }
                }
                Err(err) => eprintln!("WARNING: could not restore the APIBAN list: {err}"),
            }
        }
    }

    let mut nothing_seen_warned = false;
    let mut db = db;
    let mut last_checkpoint = start.0;
    // Blind spots: counted so they can become a warning. Ignoring them silently would
    // repeat the very failure this project uses as its difference from fail2ban.
    let (mut n_ipv6, mut n_tcp, mut n_frag) = (0u64, 0u64, 0u64);
    let mut blind_warned = false;
    let mut auth_blind_warned = false;
    let policy = Policy {
        enforce_behavioural: args.enforce_behavioural,
        no_enforce_one_way: args.no_enforce_one_way,
        block_ttl: args.block_ttl,
        verbose: args.verbose,
    };
    // HEP's own alarms: silence while TCP is seen on the SIP ports, and a
    // mirrored port that XDP does not cover.
    let mut hep_last = start.0;
    let mut hep_ever = false;
    let mut tcp_at_hep_last = 0u64;
    let mut hep_silence_warned = false;
    let mut hep_port_warned = std::collections::BTreeSet::new();

    loop {
        let n = match sock.read(&mut buf) {
            Ok(n) => n,
            // Timeout and interruption are not errors: they are the chance to report on a quiet link.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                0
            }
            Err(e) => {
                eprintln!("capture error: {e}");
                return ExitCode::FAILURE;
            }
        };

        let t = now();
        if n > 0 {
            if parse_ipv4_udp(&buf[..n]).is_none() {
                match classify_other(&buf[..n]) {
                    NotUdp::Ipv6 => n_ipv6 += 1,
                    // Only counts TCP **on the SIP ports**. Counting all TCP would include
                    // the administrator's own SSH session, turning the warning into noise.
                    NotUdp::Tcp => {
                        if let Some((sp, dp)) = tcp_ports(&buf[..n]) {
                            if args.ports.contains(&sp) || args.ports.contains(&dp) {
                                n_tcp += 1;
                            }
                        }
                    }
                    NotUdp::LaterFragment => n_frag += 1,
                    NotUdp::Other => {}
                }
            }
            if let Some(d) = parse_ipv4_udp(&buf[..n]) {
                let on_port = args.ports.contains(&d.dst_port) || args.ports.contains(&d.src_port);
                if on_port {
                    *seen_ports.entry(d.dst_port).or_insert(0) += 1;
                    // Both addresses go in: a request is judged on its sender, but a
                    // `401` is evidence about whoever is *receiving* it. The engine returns
                    // the subject so the block lands on the right party.
                    let (subject, dec) = engine.observe_packet(d.src, d.dst, d.payload, t);
                    settle(
                        &dec,
                        subject,
                        true, // a UDP source on the wire can be forged
                        t,
                        policy,
                        &mut ignoreip,
                        enforcer.as_mut().map(|e| e as &mut dyn Blocker),
                        db.as_ref(),
                    );
                    if args.debug_unparsed
                        && matches!(&dec, Decision::OutOfScope(r) if *r == "not SIP")
                    {
                        // Diagnostic requirement: "could not parse" has to be investigable,
                        // otherwise the counter is noise nobody knows how to read.
                        let n = d.payload.len().min(72);
                        let preview: String = d.payload[..n]
                            .iter()
                            .map(|b| {
                                if b.is_ascii_graphic() || *b == b' ' {
                                    *b as char
                                } else {
                                    '.'
                                }
                            })
                            .collect();
                        say!(
                            "NOT-SIP peer={} {}:{}->{} len={} [{preview}]",
                            d.src,
                            d.src,
                            d.src_port,
                            d.dst_port,
                            d.payload.len()
                        );
                    }
                }
            }
        }

        // Mirrored SIP from the HEP listener. Bounded per pass, so a flood of it
        // cannot starve the wire capture.
        if let Some(inbox) = hep_rx.as_ref() {
            for m in std::iter::from_fn(|| inbox.try_recv()).take(tfps::hep::QUEUE) {
                // Only TCP mirrors cover the wire's TCP blind spot: HEP over UDP,
                // when accepted, neither suppresses that warning nor resets the
                // silence alarm.
                if m.transport == tfps_core::hep::Transport::Tcp {
                    hep_last = t.0;
                    hep_ever = true;
                    tcp_at_hep_last = n_tcp;
                    hep_silence_warned = false;
                }
                // The server's side of the exchange: where a request went, or where
                // an answer came from.
                let is_response = m.payload.starts_with(b"SIP/2.0 ");
                let server_port = if is_response { m.src_port } else { m.dst_port };
                if let Some(port) = server_port {
                    *seen_ports.entry(port).or_insert(0) += 1;
                    if !args.ports.contains(&port) && hep_port_warned.insert(port) {
                        eprintln!(
                            "WARNING: HEP delivers SIP for port {port}, which is not in `ports` \
                             {:?}. A source blocked from it is NOT dropped there by XDP; add \
                             {port} to `ports`.",
                            args.ports
                        );
                    }
                }
                let (subject, dec) = engine.observe_packet(m.src, m.dst, &m.payload, t);
                settle(
                    &dec,
                    subject,
                    m.transport.spoofable(),
                    t,
                    policy,
                    &mut ignoreip,
                    enforcer.as_mut().map(|e| e as &mut dyn Blocker),
                    db.as_ref(),
                );
            }
        }

        // APIBAN batches, if any. Non-blocking: it only drains what has already arrived.
        if let (Some(rx), Some(e)) = (apiban_rx.as_ref(), enforcer.as_mut()) {
            while let Ok(batch) = rx.try_recv() {
                // Persist the resume point before the addresses: refetching a batch is
                // harmless, whereas losing the id means starting the feed over.
                if let (Some(id), Some(s)) = (&batch.next_id, db.as_ref()) {
                    if let Err(err) = s.meta_set(APIBAN_ID_KEY, id) {
                        eprintln!("WARNING: could not persist the APIBAN resume point: {err}");
                    }
                }
                if let Some(s) = db.as_mut() {
                    if let Err(err) = s.apiban_add(&batch.ips, t.0) {
                        eprintln!("WARNING: could not persist the APIBAN batch: {err}");
                    }
                }
                // No expiry: the APIBAN list is curated, and re-applying it hourly
                // would only generate pointless writes.
                let applied = apiban::apply(
                    &batch.ips,
                    |ip| ignoreip.exempt(ip).map(str::to_string),
                    |ip| engine.is_known_peer(ip, t),
                    |ip| e.block(ip, u64::from(APIBAN_RETENTION_SECS)),
                );
                for (ip, rule) in &applied.exempt {
                    say!("APIBAN: {ip} not blocked, ignoreip={rule}");
                }
                for ip in &applied.known {
                    say!("APIBAN: {ip} not blocked, it is a registered peer");
                }
                // Same alarm the perimeter's own block path raises for the same
                // failure. A feed that condemns nothing while reporting a total is
                // an integration that looks healthy and protects nothing. One line
                // per batch, as the boot-time restore does: a missing or full map
                // fails every address in a 5,000-entry batch the same way, and a
                // burst that size would drown the alarms that matter more.
                if let Some((first_ip, first_err)) = applied.failed.first() {
                    eprintln!(
                        "ALARM: {} of {} APIBAN addresses could not be blocked, first {first_ip}: {first_err}",
                        applied.failed.len(),
                        batch.ips.len()
                    );
                }
                if applied.blocked > 0 {
                    apiban_total += applied.blocked;
                    say!(
                        "APIBAN: {} addresses condemned (total {apiban_total})",
                        applied.blocked
                    );
                }
            }
        }

        // Checkpoint: durable, never on the hot path (`SPEC.md` §10).
        if let Some(s) = db.as_mut() {
            if t.0.saturating_sub(last_checkpoint) >= args.checkpoint_every.max(30) as u32 {
                last_checkpoint = t.0;
                // The control tool runs in another process and cannot read these
                // counters from memory. Writing them at checkpoint is what lets
                // `tfps_ctl stats` show the whole picture instead of only the kernel half.
                let ignoreip_line = ignoreip
                    .report()
                    .map(|(label, _, hits)| format!("{label}={hits}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let mut line = counter_line(&engine.stats);
                if hep_rx.is_some() {
                    for (k, v) in hep_counters.snapshot() {
                        line.push_str(&format!(" {k}={v}"));
                    }
                }
                for (k, v) in [
                    ("stats", line),
                    ("stats_ts", t.0.to_string()),
                    ("started_at", start.0.to_string()),
                    ("ignoreip", ignoreip_line),
                ] {
                    // Not fatal — the daemon keeps deciding — but not silent either:
                    // these are what `tfps_ctl` reads, and a stale number there is
                    // indistinguishable from a current one.
                    if let Err(e) = s.meta_set(k, &v) {
                        eprintln!("WARNING: could not write {k} at checkpoint: {e}");
                    }
                }
                // A 90-day audit window for the block log, and the APIBAN retention prune;
                // both apply whether or not behavioural detection is on.
                s.prune_log(t.0.saturating_sub(90 * 24 * 3600));
                // The manual-action record beside the database keeps the same window
                // as the block log it complements.
                let manual_dir =
                    tfps::manual_log::resolve_dir(args.manual_log_dir.as_deref(), &args.db);
                if let Err(e) = tfps::manual_log::prune(&manual_dir, t.0, 90 * 24 * 3600) {
                    eprintln!("WARNING: could not prune the manual-action record: {e}");
                }
                s.apiban_prune(t.0.saturating_sub(APIBAN_RETENTION_SECS));
                // Known-good peers persist in every mode — they are perimeter protection.
                if let Err(e) = s.save_known_peers(engine.export_known_peers()) {
                    eprintln!("WARNING: could not persist known peers: {e}");
                }
                s.known_peers_prune(t.0.saturating_sub(tfps_core::engine::KNOWN_PEER_TTL_SECS));
                // Only the behavioural layer has learned state worth persisting.
                if engine.behavioural_enabled() {
                    // Refit the benign hypotheses and the volume prior from the traffic seen
                    // so far, then persist. This is the self-calibration: the operator tunes
                    // error rates, never the traffic constants.
                    engine.recalibrate();
                    let p = engine.params();
                    if let Err(e) = s.meta_set(
                        "calibration",
                        &format!(
                            "theta0_prefix={:.3} theta0_range={:.3} theta0c={:.3} theta0u={:.3} prior_mean={:.2}",
                            p.theta0_prefix, p.theta0_range, p.theta0c, p.theta0u, p.prior_mean
                        ),
                    ) {
                        eprintln!("WARNING: could not write calibration at checkpoint: {e}");
                    }
                    match s.checkpoint(&engine) {
                        Ok((n, _)) => {
                            engine.clear_anomaly_dirty();
                            s.peer_anomaly_prune(
                                t.0.saturating_sub(tfps::store::PEER_RETENTION_SECS),
                            );
                            if args.verbose {
                                say!("    checkpoint: {n} sources written");
                            }
                        }
                        Err(e) => eprintln!("ALARM: checkpoint failed — {e}"),
                    }
                }
            }
        }

        if t.0.saturating_sub(last_report) >= args.stats_every.max(1) as u32 {
            last_report = t.0;
            print_stats(&engine, &seen_ports, t, mode);
            if let Some(e) = enforcer.as_ref() {
                if e.has_own_counters() {
                    let c = e.counters();
                    say!(
                        "    XDP: dropped={} seen={} expired={} in_map={} blocked_by_us={}",
                        c.dropped,
                        c.seen,
                        c.expired,
                        e.blocked_count(),
                        e.blocked_by_us
                    );
                } else {
                    // A third-party map: the total is mostly theirs. Only what this
                    // process wrote can be claimed as ours.
                    say!(
                        "    XDP: in_map={} (shared) blocked_by_us={}",
                        e.blocked_count(),
                        e.blocked_by_us
                    );
                }
            }
            // Observability requirement: silence is an alarm, not normality.
            if engine.stats.packets == 0 && !nothing_seen_warned {
                eprintln!(
                    "ALARM: no packets seen on ports {:?} in {}s. \
                     Wrong interface, wrong port, or SIP over TLS?",
                    args.ports, args.stats_every
                );
                nothing_seen_warned = true;
            }
            // A signature that never matches is rotten and the operator needs to know —
            // exactly what fail2ban never did (`SPEC.md` §12).
            if hep_rx.is_some() {
                let c = hep_counters.snapshot();
                say!(
                    "    HEP: {}",
                    c.iter()
                        .map(|(k, v)| format!("{}={v}", k.trim_start_matches("hep_")))
                        .collect::<Vec<_>>()
                        .join(" ")
                );
                // Silence is an alarm: TCP on the SIP ports and nothing mirrored
                // means the sender stopped, and TLS / WebSocket are blind again.
                if n_tcp > tcp_at_hep_last
                    && t.0.saturating_sub(hep_last) >= HEP_SILENCE_SECS
                    && !hep_silence_warned
                {
                    eprintln!(
                        "ALARM: no HEP message in {}s while {} TCP packets were seen on ports \
                         {:?}. SIP over TLS and WebSocket is NOT being inspected; check the \
                         application server's HEP tracing.",
                        t.0.saturating_sub(hep_last),
                        n_tcp - tcp_at_hep_last,
                        args.ports
                    );
                    hep_silence_warned = true;
                }
            }
            // TCP is covered while HEP is delivering: the mirrored messages are
            // that TCP's SIP.
            let hep_delivering = hep_ever && t.0.saturating_sub(hep_last) < HEP_SILENCE_SECS;
            let tcp_blind = if hep_delivering { 0 } else { n_tcp };
            if n_ipv6 + n_tcp > 0 {
                say!(
                    "    blind spots: ipv6={n_ipv6} tcp={n_tcp}{} fragments={n_frag}",
                    if hep_delivering {
                        " (covered by HEP)"
                    } else {
                        ""
                    }
                );
            }
            if n_ipv6 + tcp_blind > 0 && !blind_warned {
                eprintln!(
                    "WARNING: there is SIP this system does NOT analyse on ports {:?} — \
                     IPv6={n_ipv6}, TCP={tcp_blind}. That traffic passes uninspected \
                     (for SIP over TLS and WebSocket, see \"TLS and WebSocket via HEP\" \
                     in the README).",
                    args.ports
                );
                blind_warned = true;
            }
            // The failure rule needs the softswitch's answer. Where none is ever seen it
            // cannot fire, and saying nothing about that would be the exact blindness this
            // project condemns in fail2ban — a rule that structurally cannot match.
            if engine.stats.auth_attempts > 0
                && engine.stats.digest_challenges == 0
                && !auth_blind_warned
            {
                eprintln!(
                    "WARNING: {} credentials presented and not one digest challenge seen on \
                     ports {:?}. \
                     Failed-authentication blocking cannot fire — only the volume backstop \
                     can. Either the softswitch answers on a path this capture does not see, \
                     or it drops these requests without challenging them.",
                    engine.stats.auth_attempts, args.ports
                );
                auth_blind_warned = true;
            }
            // §12.4: a rule that matches zero must be reportable. An exemption is a rule,
            // and a stale one is worse than a stale signature — it is a hole somebody
            // opened deliberately and then forgot.
            let cold = ignoreip.cold();
            if ignoreip.total_hits() > 0 || !cold.is_empty() {
                say!(
                    "    ignoreip: {} exemption(s) applied{}",
                    ignoreip.total_hits(),
                    if cold.is_empty() {
                        String::new()
                    } else {
                        format!(", never matched: {}", cold.join(" "))
                    }
                );
            }
            let total = engine.noise_filter.hits().count();
            if engine.noise_filter.cold_signatures().len() == total
                && engine.stats.sip_parsed > 1000
            {
                eprintln!(
                    "WARNING: none of the {total} user-agent signatures matched in {} \
                     SIP messages. The list may be out of date.",
                    engine.stats.sip_parsed
                );
            }
        }
    }
}

/// What the step from a verdict to a block reads from the command line and file.
#[derive(Debug, Clone, Copy)]
struct Policy {
    enforce_behavioural: bool,
    no_enforce_one_way: bool,
    block_ttl: u64,
    verbose: bool,
}

/// Whatever places a block. The XDP enforcer in the daemon; a recorder in tests.
trait Blocker {
    fn block(&mut self, ip: Ipv4Addr, ttl_secs: u64) -> Result<(), String>;
}

impl Blocker for xdp::Enforcer {
    fn block(&mut self, ip: Ipv4Addr, ttl_secs: u64) -> Result<(), String> {
        xdp::Enforcer::block(self, ip, ttl_secs)
    }
}

/// What became of one judged message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Nothing was tripped.
    Ignored,
    /// Tripped a rule, but `ignoreip` or a host address covers it.
    Exempt,
    /// Condemned while observing only, or one-way evidence under `--no-enforce-one-way`.
    WouldBlock,
    /// Written to the block map.
    Blocked,
    /// The block map refused the write.
    BlockFailed,
}

/// From a verdict to an action: the one path that packets off the wire and
/// messages mirrored over HEP share, so both get the same gate, the same block
/// and the same audit row.
///
/// A registered peer is not shielded here, on either path: its own perimeter
/// evidence still counts (see the comment on `enforcing` below). The gate is
/// `ignoreip`, which holds the host's own addresses.
///
/// `spoofable` says whether the subject's address could have been forged. On the
/// wire (UDP) it could, so `--no-enforce-one-way` keeps request-only evidence
/// report-only. A HEP message that arrived over TCP had its address proved by
/// the handshake, so that flag does not downgrade it.
#[allow(clippy::too_many_arguments)]
fn settle(
    dec: &Decision,
    subject: Ipv4Addr,
    spoofable: bool,
    t: Timestamp,
    p: Policy,
    ignoreip: &mut tfps_core::ignore::IgnoreList,
    blocker: Option<&mut dyn Blocker>,
    db: Option<&store::Store>,
) -> Outcome {
    // Perimeter noise condemns the source: its next packets die at XDP,
    // before the libpcap tap, and vanish from sngrep.
    // A behavioural Block is enforced only when the operator asked for
    // it. It goes through the same disposition gate (ignoreip first) and
    // is written to XDP for block_ttl; the forged 603 is still missing.
    let reason = enforcement_reason(dec, p.enforce_behavioural);
    let reason = reason
        .as_ref()
        .map(|(kind, detail)| (*kind, detail.as_ref()));
    let exempt = reason.and_then(|_| ignoreip.exempt(subject).map(str::to_string));
    // One-way evidence is a request with no response from the expected
    // responder. A UDP source can be spoofed, so with
    // --no-enforce-one-way it is reported but never written to the block
    // map. Auth-failure is response-based and still enforces.
    let one_way = spoofable && reason.is_some_and(|(kind, _)| is_one_way(kind));
    // A total match, not a chain: the defect this replaces was a
    // missing arm, and a chain can silently lack one where an
    // exhaustive match cannot. `SPEC.md` §12 makes silence an alarm.
    // A registered IP no longer bypasses active perimeter evidence. A
    // compromised PBX with valid credentials (the target threat) would
    // otherwise be immune to injection, auth-failure, registration-scan and
    // auth-volume rules for seven days. The APIBAN integration still honours
    // known peers, because that feed is third-party reputation, not our own
    // observation.
    let enforcing = blocker.is_some() && !(p.no_enforce_one_way && one_way);
    let outcome = match disposition(reason, exempt.as_deref(), false, enforcing) {
        Disposition::Ignore => Outcome::Ignored,
        Disposition::ExemptIgnoreIp { kind, detail, rule } => {
            // Judged, reported, not enforced. Staying silent here would hide
            // a compromised trusted peer, which is when it matters most.
            say!("EXEMPT peer={subject} reason={kind} detail={detail} ignoreip={rule}");
            Outcome::Exempt
        }
        Disposition::ExemptKnownPeer { kind, detail } => {
            // A registered peer that authenticated is known-good — never
            // banned, whatever a signature or the feed says. The dynamic
            // ignoreip.
            say!("EXEMPT peer={subject} reason={kind} detail={detail} (registered peer)");
            Outcome::Exempt
        }
        Disposition::WouldBlock { kind, detail } => {
            // Observing only. Nothing is blocked and nothing is written to
            // the audit log, which has no column to say a block did not
            // happen — but the operator is told, which is the whole point of
            // running with --no-enforce / --no-enforce-one-way.
            let why = if p.no_enforce_one_way && one_way {
                "one-way report-only"
            } else {
                "observe only"
            };
            say!("WOULD BLOCK peer={subject} reason={kind} detail={detail} ({why})");
            Outcome::WouldBlock
        }
        Disposition::Block { kind, detail } => {
            // The `None` arm is unreachable by construction: `disposition`
            // returns `Block` only when an enforcer exists, which its own
            // tests pin exhaustively. It alarms rather than being silent,
            // because an unreachable branch that says nothing is how this
            // defect happened in the first place.
            match blocker {
                Some(b) => match b.block(subject, p.block_ttl) {
                    Ok(()) => {
                        say!(
                            "BLOCKED peer={subject} reason={kind} detail={detail} ttl={}s",
                            p.block_ttl
                        );
                        // Durable audit: the operator must be able to
                        // reconstruct the decision later, without relying
                        // on the journal.
                        if let Some(s) = db {
                            if let Err(e) = s.log_block(t.0, subject, kind, detail) {
                                eprintln!("ALARM: blocked {subject} but could not record it: {e}");
                            }
                        }
                        Outcome::Blocked
                    }
                    Err(err) => {
                        eprintln!("ALARM: could not block {subject}: {err}");
                        Outcome::BlockFailed
                    }
                },
                None => {
                    eprintln!("ALARM: condemned {subject} as Block with no enforcer attached");
                    Outcome::BlockFailed
                }
            }
        }
    };
    // When enforcement is on, the BLOCKED/EXEMPT/WOULD BLOCK line from
    // disposition already carries the reason; do not also print the
    // report-only BLOCK line.
    if !(p.enforce_behavioural && matches!(dec, Decision::Block { .. })) {
        report(dec, subject, p.verbose);
    }
    outcome
}

fn enforcement_reason(
    dec: &Decision,
    enforce_behavioural: bool,
) -> Option<(&'static str, Cow<'static, str>)> {
    match dec {
        Decision::Noise { signature } => Some(("user-agent", Cow::Borrowed(signature))),
        Decision::Scanner { id } => Some(("scanner", Cow::Borrowed(id))),
        Decision::Injection { pattern } => Some(("injection", Cow::Borrowed(pattern))),
        Decision::Malformed { header } => Some(("ambiguous-header", Cow::Borrowed(header))),
        Decision::AuthFailure { .. } => Some(("auth-failed", Cow::Borrowed("rejected"))),
        Decision::RegScan { .. } => Some(("reg-scan", Cow::Borrowed("no-success"))),
        Decision::AuthAbuse { .. } => Some(("auth-volume", Cow::Borrowed("no-answer"))),
        Decision::Block {
            country,
            evidence_nats,
            countries,
        } if enforce_behavioural => Some((
            "behavioural",
            Cow::Owned(format!(
                "country={country} evidence={evidence_nats}nats distinct_countries={countries}"
            )),
        )),
        _ => None,
    }
}

fn report(dec: &Decision, peer: Ipv4Addr, verbose: bool) {
    match dec {
        Decision::Block { country, evidence_nats, countries } => say!(
            "BLOCK (report-only, not enforced) peer={peer} country={country} evidence_nats={evidence_nats} distinct_countries={countries}"
        ),
        Decision::WouldBlock { country, evidence_nats, countries } => say!(
            "WOULD BLOCK (learning) peer={peer} country={country} evidence_nats={evidence_nats} distinct_countries={countries}"
        ),
        Decision::Warming { country, evidence_nats, countries } => say!(
            "WARMING peer={peer} country={country} evidence_nats={evidence_nats} distinct_countries={countries} (source warm-up; not blocked)"
        ),
        Decision::Noise { signature } if verbose => {
            say!("noise peer={peer} signature={signature}")
        }
        Decision::Scanner { id } => {
            // Always visible: a self-identifying scanner is a clean, high-confidence catch.
            say!("SCANNER peer={peer} id={id}")
        }
        Decision::Injection { pattern } if verbose => {
            say!("injection peer={peer} pattern={pattern}")
        }
        Decision::Malformed { header } => {
            // Always visible: a duplicate singleton header is a smuggling signal.
            say!("MALFORMED peer={peer} duplicate_header={header}")
        }
        Decision::AuthFailure { failures } => {
            // Always visible: a run of rejected credentials is the precursor of Chain A.
            say!("AUTH FAILURES peer={peer} rejected_credentials_in_window={failures}")
        }
        Decision::RegScan { extensions } => {
            // Always visible: registration scanning / extension enumeration.
            say!("REG SCAN peer={peer} distinct_extensions_no_success={extensions}")
        }
        Decision::AuthAbuse { attempts } => {
            // The backstop fired, which also says the softswitch never answered.
            say!("AUTH VOLUME peer={peer} authenticated_attempts_unanswered={attempts}")
        }
        Decision::UnknownCountry(digits) => {
            // Always visible, even without -v: it is a symptom of a wrong dial plan, and a
            // wrong dial plan means international calls escaping the system entirely.
            say!("UNKNOWN COUNTRY peer={peer} digits={digits}")
        }
        Decision::Pass { country, novel } if verbose => {
            say!("pass peer={peer} country={country} first_time={novel}")
        }
        _ => {}
    }
}

/// The userspace counters as `key=value` pairs, for the database.
///
/// Hand-rolled rather than serialised: the reader is one function in `tfps_ctl`, the format
/// is greppable by eye in `sqlite3`, and a new counter costs one line here.
fn counter_line(s: &tfps_core::engine::Stats) -> String {
    [
        ("packets", s.packets),
        ("sip", s.sip_parsed),
        ("responses", s.responses),
        ("keepalive", s.keepalives),
        ("not_sip", s.not_sip),
        ("noise", s.noise),
        ("injection", s.injections),
        ("auth_att", s.auth_attempts),
        ("auth_fail", s.auth_failures),
        ("auth_ok", s.auth_ok),
        ("auth_chal", s.digest_challenges),
        ("intl_ok", s.intl_completed),
        ("intl_fail", s.intl_failed),
        ("intl_unroutable", s.intl_unroutable),
        ("intl_unanswered", s.intl_unanswered),
        ("auth_volume", s.auth_abuse),
        ("invites", s.invites),
        ("intl", s.international),
        ("unknown_country", s.unknown_country),
        ("first_time", s.novel),
        ("range_novel", s.range_novel),
        ("blocks", s.blocks),
        ("would_block", s.would_block),
        ("warming", s.warming),
        ("known_dropped", s.known_peers_dropped),
        ("pairs_dropped", s.pairs_dropped),
        ("peers_dropped", s.peers_dropped),
    ]
    .iter()
    .map(|(k, v)| format!("{k}={v}"))
    .collect::<Vec<_>>()
    .join(" ")
}

fn print_stats(e: &Engine, ports: &BTreeMap<u16, u64>, t: Timestamp, mode: Mode) {
    let s = &e.stats;
    let mode_label = if !e.behavioural_enabled() {
        "PREVENTION".to_string()
    } else {
        match mode {
            Mode::Active => "ACTIVE".to_string(),
            Mode::Learning { until } => {
                let left = until.0.saturating_sub(t.0);
                format!(
                    "LEARNING ({}d {}h left)",
                    left / 86400,
                    (left % 86400) / 3600
                )
            }
        }
    };
    say!(
        "--- mode={mode_label} packets={} sip={} responses={} keepalive={} not_sip={} noise={} ({}%) injection={} scanners={} reg_scan={} auth_att={} auth_fail={} auth_ok={} auth_chal={} auth_volume={} intl_ok={} intl_fail={} intl_unroutable={} intl_unanswered={} invites={} intl={} \
         unknown_country={} first_time={} blocks={} would_block={} sources={} ports={:?}",
        s.packets,
        s.sip_parsed,
        s.responses,
        s.keepalives,
        s.not_sip,
        s.noise,
        s.noise
            .checked_mul(100)
            .and_then(|n| n.checked_div(s.sip_parsed))
            .unwrap_or(0),
        s.injections,
        s.scanners,
        s.reg_scans,
        s.auth_attempts,
        s.auth_failures,
        s.auth_ok,
        s.digest_challenges,
        s.auth_abuse,
        s.intl_completed,
        s.intl_failed,
        s.intl_unroutable,
        s.intl_unanswered,
        s.invites,
        s.international,
        s.unknown_country,
        s.novel,
        s.blocks,
        s.would_block,
        e.source_count(),
        ports
    );
}

/// Publishes which block map this run enforces through, for `tfps_ctl serve`
/// (`tfps::state`). The choice was made once, just above; the API uses exactly
/// this map instead of working the choice out again.
///
/// Failing to write is not fatal to enforcement, but it is said: the API will
/// report the daemon as not running until the file exists.
fn publish_state(enforcer: Option<&xdp::Enforcer>, not_enforcing: &str) {
    let inactive = |reason: String| tfps::state::ActiveMap::Inactive { reason };
    let map = match enforcer.map(|e| e.active_map()) {
        Some(Ok(map)) => map,
        Some(Err(e)) => inactive(format!("could not identify the block map: {e}")),
        None => inactive(not_enforcing.to_string()),
    };
    let (mode, interface) = match enforcer.and_then(|e| e.attach.clone()) {
        Some((mode, iface)) => (Some(mode), Some(iface)),
        None => (None, None),
    };
    let (pid, pid_start) = tfps::state::this_process();
    let state = tfps::state::State {
        pid,
        pid_start,
        counters: enforcer.and_then(|e| e.counters_id()),
        started_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0),
        map,
        mode,
        interface,
    };
    if let Err(e) = tfps::state::write(std::path::Path::new(tfps::state::DEFAULT_PATH), &state) {
        eprintln!(
            "WARNING: could not publish the enforcement state ({e}); \
             tfps_ctl serve will report tfps as not running"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_behavioural_block_is_only_enforced_when_the_flag_is_set() {
        let dec = Decision::Block {
            country: "GB",
            evidence_nats: 12,
            countries: 7,
        };
        assert!(enforcement_reason(&dec, false).is_none());
        let (kind, detail) = enforcement_reason(&dec, true).expect("enforcing");
        assert_eq!(kind, "behavioural");
        assert!(detail.contains("country=GB"));
        assert!(detail.contains("evidence=12nats"));
    }

    #[test]
    fn malformed_is_mapped_to_the_one_way_reason() {
        let dec = Decision::Malformed { header: "From" };
        let (kind, detail) = enforcement_reason(&dec, false).expect("condemned");
        assert_eq!(kind, "ambiguous-header");
        assert_eq!(detail, "From");
        assert!(is_one_way(kind));
    }

    #[test]
    fn behavioural_enforcement_can_be_enabled_in_config_even_with_active() {
        let on: config::Config =
            serde_json::from_str(r#"{"behavioural": true, "enforce_behavioural": true}"#)
                .expect("parses");
        let mut a = Args::default();
        a.given.insert("--active".into());
        apply_config(&mut a, &on);
        assert!(
            a.behavioural,
            "the file can enable the layer alongside --active"
        );
        assert!(a.enforce_behavioural);

        let mut b = Args::default();
        b.given.insert("--no-enforce-behavioural".into());
        apply_config(&mut b, &on);
        assert!(!b.enforce_behavioural, "the CLI can override the file");
    }

    #[test]
    fn one_way_report_only_can_be_set_in_config_and_overridden_on_the_cli() {
        let on: config::Config =
            serde_json::from_str(r#"{"no_enforce_one_way": true}"#).expect("parses");
        let mut a = Args::default();
        apply_config(&mut a, &on);
        assert!(a.no_enforce_one_way, "the file can opt in");

        let mut b = Args::default();
        b.given.insert("--enforce-one-way".into());
        apply_config(&mut b, &on);
        assert!(!b.no_enforce_one_way, "the CLI can override the file");

        let mut c = Args {
            no_enforce_one_way: true, // what parse_args does for the flag
            ..Default::default()
        };
        c.given.insert("--no-enforce-one-way".into());
        apply_config(&mut c, &serde_json::from_str("{}").expect("parses"));
        assert!(c.no_enforce_one_way);
    }

    #[test]
    fn the_manual_record_settings_come_from_the_config_file() {
        let mut a = Args::default();
        let c: config::Config = serde_json::from_str(
            r#"{"manual_log_dir": "/srv/tfps/manual", "reapply_manual_bans": true}"#,
        )
        .expect("parses");
        apply_config(&mut a, &c);
        assert_eq!(
            a.manual_log_dir.as_deref(),
            Some(std::path::Path::new("/srv/tfps/manual"))
        );
        assert!(a.reapply_manual_bans);

        let mut b = Args::default();
        apply_config(&mut b, &serde_json::from_str("{}").expect("parses"));
        assert!(b.manual_log_dir.is_none());
        assert!(!b.reapply_manual_bans, "off unless the file says so");
    }

    // ── HEP: the same path from verdict to block as the wire ──────────────────

    use std::net::SocketAddr;
    use tfps::hep::{handle, Counters, Settings};
    use tfps_core::hep::build::{sip, Sip};
    use tfps_core::hep::{IPPROTO_TCP, IPPROTO_UDP};

    const CLIENT: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
    const SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);

    /// Records every block instead of writing a kernel map.
    #[derive(Default)]
    struct Recorder(Vec<Ipv4Addr>);

    impl Blocker for Recorder {
        fn block(&mut self, ip: Ipv4Addr, _: u64) -> Result<(), String> {
            self.0.push(ip);
            Ok(())
        }
    }

    fn policy(no_enforce_one_way: bool) -> Policy {
        Policy {
            enforce_behavioural: false,
            no_enforce_one_way,
            block_ttl: 3600,
            verbose: false,
        }
    }

    fn hep(from: (Ipv4Addr, u16), to: (Ipv4Addr, u16), ip_proto: u8, payload: &[u8]) -> Vec<u8> {
        sip(&Sip {
            src: from,
            dst: to,
            ip_proto,
            ts: 1_795_000_000,
            auth_key: None,
            payload,
        })
    }

    fn wss_register(n: u32) -> Vec<u8> {
        format!(
            "REGISTER sip:pbx.example.com SIP/2.0\r\n\
             Via: SIP/2.0/WSS df7jal23ls0d.invalid;branch=z9hG4bK{n};rport\r\n\
             From: <sip:1001@pbx.example.com>;tag=t1\r\n\
             To: <sip:1001@pbx.example.com>\r\n\
             Call-ID: wss-reg\r\n\
             CSeq: {n} REGISTER\r\n\
             Authorization: Digest username=\"1001\", realm=\"pbx\", response=\"deadbeef\"\r\n\
             Contact: <sip:a8k2@df7jal23ls0d.invalid;transport=ws>\r\n\
             Content-Length: 0\r\n\r\n"
        )
        .into_bytes()
    }

    fn unauthorized(n: u32) -> Vec<u8> {
        format!(
            "SIP/2.0 401 Unauthorized\r\n\
             Via: SIP/2.0/WSS df7jal23ls0d.invalid;branch=z9hG4bK{n};rport\r\n\
             From: <sip:1001@pbx.example.com>;tag=t1\r\n\
             To: <sip:1001@pbx.example.com>;tag=s1\r\n\
             Call-ID: wss-reg\r\n\
             CSeq: {n} REGISTER\r\n\
             WWW-Authenticate: Digest realm=\"pbx\", nonce=\"abc{n}\"\r\n\
             Content-Length: 0\r\n\r\n"
        )
        .into_bytes()
    }

    /// Five rejected credentials, each delivered only as HEP over TCP (a WSS
    /// client): what the daemon's loop does with each one.
    fn failed_logins_over_hep(
        p: Policy,
        ignoreip: &mut tfps_core::ignore::IgnoreList,
        mut blocker: Option<&mut Recorder>,
    ) -> Vec<(Ipv4Addr, Outcome)> {
        let mut engine = Engine::new(DialPlan::new(["00"]), Mode::Active);
        let settings = Settings::from_config(&config::HepConfig::default());
        let counters = Counters::default();
        let lo: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let mut out = Vec::new();
        for n in 0..5 {
            for bytes in [
                hep(
                    (CLIENT, 51_234),
                    (SERVER, 443),
                    IPPROTO_TCP,
                    &wss_register(n),
                ),
                hep(
                    (SERVER, 443),
                    (CLIENT, 51_234),
                    IPPROTO_TCP,
                    &unauthorized(n),
                ),
            ] {
                let t = Timestamp(1_795_000_000 + n);
                let m = handle(&bytes, lo, &settings, t.0, &counters).expect("accepted");
                let (subject, dec) = engine.observe_packet(m.src, m.dst, &m.payload, t);
                let outcome = settle(
                    &dec,
                    subject,
                    m.transport.spoofable(),
                    t,
                    p,
                    ignoreip,
                    blocker.as_deref_mut().map(|b| b as &mut dyn Blocker),
                    None,
                );
                out.push((subject, outcome));
            }
        }
        out
    }

    #[test]
    fn failed_logins_seen_only_over_hep_block_the_client_never_the_server() {
        let mut blocks = Recorder::default();
        let mut ignoreip = tfps_core::ignore::IgnoreList::new();
        let got = failed_logins_over_hep(policy(false), &mut ignoreip, Some(&mut blocks));
        assert_eq!(blocks.0, [CLIENT], "the client, once: {got:?}");
        assert_eq!(got.last(), Some(&(CLIENT, Outcome::Blocked)));
        assert!(
            got.iter()
                .all(|(s, o)| *s == CLIENT || *o == Outcome::Ignored),
            "nothing is ever held against the server: {got:?}"
        );

        // --no-enforce: the same verdict, reported and not placed.
        let mut ignoreip = tfps_core::ignore::IgnoreList::new();
        let got = failed_logins_over_hep(policy(false), &mut ignoreip, None);
        assert_eq!(got.last(), Some(&(CLIENT, Outcome::WouldBlock)));
    }

    #[test]
    fn ignoreip_and_host_addresses_still_shield_hep_verdicts() {
        for exempt in ["declared", "local"] {
            let mut ignoreip = tfps_core::ignore::IgnoreList::new();
            match exempt {
                "declared" => ignoreip.add("198.51.100.0/24").unwrap(),
                _ => ignoreip.add_local(CLIENT),
            }
            let mut blocks = Recorder::default();
            let got = failed_logins_over_hep(policy(false), &mut ignoreip, Some(&mut blocks));
            assert!(blocks.0.is_empty(), "{exempt}: {:?}", blocks.0);
            assert_eq!(got.last(), Some(&(CLIENT, Outcome::Exempt)), "{exempt}");
        }
    }

    /// `--no-enforce-one-way` exists because a UDP source can be forged. A HEP
    /// message that arrived over TCP had its source proved by the handshake.
    #[test]
    fn no_enforce_one_way_spares_hep_over_tcp_but_not_udp() {
        let probe = b"OPTIONS sip:test.echo@sip5060.net SIP/2.0\r\n\
                      Via: SIP/2.0/TLS h;branch=z\r\n\
                      From: \"censysinspect\" <sip:censysinspect@censys.io>;tag=t\r\n\
                      To: <sip:test.echo@sip5060.net>\r\n\
                      Call-ID: c\r\nCSeq: 1 OPTIONS\r\n\r\n";
        let settings = Settings {
            udp: true,
            ..Settings::from_config(&config::HepConfig::default())
        };
        let lo: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        for (ip_proto, want) in [
            (IPPROTO_TCP, Outcome::Blocked),
            (IPPROTO_UDP, Outcome::WouldBlock),
        ] {
            let mut engine = Engine::new(DialPlan::new(["00"]), Mode::Active);
            let bytes = hep((CLIENT, 51_234), (SERVER, 5061), ip_proto, probe);
            let m = handle(&bytes, lo, &settings, 1_795_000_000, &Counters::default()).unwrap();
            let t = Timestamp(1_795_000_000);
            let (subject, dec) = engine.observe_packet(m.src, m.dst, &m.payload, t);
            let mut blocks = Recorder::default();
            let got = settle(
                &dec,
                subject,
                m.transport.spoofable(),
                t,
                policy(true),
                &mut tfps_core::ignore::IgnoreList::new(),
                Some(&mut blocks),
                None,
            );
            assert_eq!(got, want, "ip proto {ip_proto}");
        }
        // And wire UDP, which is always spoofable, stays report-only.
        let mut engine = Engine::new(DialPlan::new(["00"]), Mode::Active);
        let t = Timestamp(1_795_000_000);
        let (subject, dec) = engine.observe_packet(CLIENT, SERVER, probe, t);
        let got = settle(
            &dec,
            subject,
            true,
            t,
            policy(true),
            &mut tfps_core::ignore::IgnoreList::new(),
            Some(&mut Recorder::default()),
            None,
        );
        assert_eq!(got, Outcome::WouldBlock);
    }
}
