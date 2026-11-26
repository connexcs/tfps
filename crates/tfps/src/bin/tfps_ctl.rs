//! `tfps_ctl` — inspect what TFPS has learned, and lift or place blocks.
//!
//! The counterpart to `fail2ban-client`, and it exists for the same reason that tool does:
//! a defence nobody can inspect is a defence nobody trusts. `SPEC.md` §12 makes manual
//! unblocking the **precision proxy** — with no labelled data it is the only measure of how
//! often the system is wrong, so the act has to be one command, not a database session.
//!
//! Two sources of truth, and the difference matters to anyone reading the output:
//!
//! - **Blocks live in the kernel.** They are read and written straight into the eBPF map,
//!   so an unban takes effect on the next packet.
//! - **Learning lives in SQLite**, written at checkpoint (every 300 s by default). What is
//!   shown is therefore a snapshot, and `status` says how old it is rather than letting
//!   somebody draw conclusions from stale rows.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Serialize;

use tfps::ctl::{
    action_doc, audit_maps, banned_docs, finite, log_docs, manual_attribution, manual_record,
    map_addresses, now, record_manual, stats_docs, status_docs, unban_docs, ActionDoc, Ctx,
    UnbanOutcome, UnbanTarget,
};
use tfps::say;
use tfps::store::{BlockRow, SourceFilter, Store};
use tfps::xdp::{monotonic_ns, Blocklist};
use tfps_core::disposition::{gate, Gate};
use tfps_core::ignore::{IgnoreList, Origin};

fn usage() -> String {
    format!(
        "tfps_ctl — inspect and control a running TFPS

USAGE: tfps_ctl <command> [options]

  status                       what is running, what is blocked, how fresh the state is
  stats                        every counter: kernel drops, traffic mix, what got blocked
  banned [--why]               list condemned sources, with time left
  unban <ip>... | --all        lift a block. The precision measure of this product
  ban <ip> [--ttl N]           condemn a source by hand (default ttl: 3600s, 0 = forever)
  sources [filters]            list learned sources and the countries they call
  source <peer>                everything known about one source
  peers                        sources by country breadth, when last heard
  countries <peer>             the countries a source has been seen to call
  log [--limit N] [--ip IP]    the block audit log, newest first
  forget <peer> [--a NUMBER]   erase learned state (requires tfps stopped)

MANUAL ACTIONS (ban, unban):
  --source NAME                who asked (default: operator); letters, digits, . _ -
  --reason TEXT                why, up to 256 bytes; kept in manual_actions-YYYYMM.jsonl

SOURCE FILTERS:
  --peer IP                    exactly this peer
  --country ISO                sources that have called this country, e.g. --country GB
  --limit N                    stop after N rows (default 50)

HTTP API (off unless the configuration's \"http\" section enables it):
  serve                        run the JSON API and /metrics in the foreground
  --listen ADDR                IPv4 address:port (default: 127.0.0.1:9060)
  --allow-unban                accept POST /v1/unban (default: off)

GLOBAL:
  --db PATH                    database (default: {db})
  --map PATH                   an explicitly pinned block map
  --json                       machine-readable output, one JSON document per line
  --config PATH                configuration, for ignoreip (default: {cfg})
  -h, --help                   this help

Reading blocks needs CAP_BPF (run as root). Reading learned state only needs the database.
",
        db = tfps::store::DEFAULT_PATH,
        cfg = tfps::config::DEFAULT_PATH
    )
}

struct Args {
    command: String,
    positional: Vec<String>,
    db: PathBuf,
    map: Option<PathBuf>,
    peer: Option<String>,
    a_number: Option<String>,
    country: Option<String>,
    ip: Option<String>,
    limit: usize,
    ttl: u64,
    all: bool,
    why: bool,
    json: bool,
    config: PathBuf,
    /// Who asked for a manual ban or unban (`--source`); `operator` when absent.
    source: Option<String>,
    /// Why, in the asker's words (`--reason`).
    reason: Option<String>,
    /// `serve --listen`: overrides `http.listen`.
    listen: Option<std::net::SocketAddrV4>,
    /// `serve --allow-unban`: turns on `http.allow_unban`.
    allow_unban: bool,
    /// Whether `--db` was on the command line, so `serve` can tell an explicit
    /// path from the default and let the configuration's `db` fill the latter.
    db_given: bool,
}

impl Args {
    /// The paths the library's commands read; the rest of the command line
    /// stays here.
    fn ctx(&self) -> Ctx {
        Ctx {
            db: self.db.clone(),
            map: self.map.clone(),
            shared_map: None,
            config: self.config.clone(),
        }
    }
}

fn parse(argv: &[String]) -> Result<Args, String> {
    let mut a = Args {
        command: String::new(),
        positional: Vec::new(),
        db: PathBuf::from(tfps::store::DEFAULT_PATH),
        map: None,
        peer: None,
        a_number: None,
        country: None,
        ip: None,
        limit: 50,
        ttl: 3600,
        all: false,
        why: false,
        json: false,
        config: PathBuf::from(tfps::config::DEFAULT_PATH),
        source: None,
        reason: None,
        listen: None,
        allow_unban: false,
        db_given: false,
    };
    let mut it = argv.iter();
    let value = |name: &str, it: &mut std::slice::Iter<'_, String>| -> Result<String, String> {
        it.next()
            .cloned()
            .ok_or_else(|| format!("{name} requires a value"))
    };
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--db" => {
                a.db = PathBuf::from(value("--db", &mut it)?);
                a.db_given = true;
            }
            "--map" => a.map = Some(PathBuf::from(value("--map", &mut it)?)),
            "--config" => a.config = PathBuf::from(value("--config", &mut it)?),
            "--peer" => a.peer = Some(value("--peer", &mut it)?),
            "--a" => a.a_number = Some(value("--a", &mut it)?),
            "--country" => a.country = Some(value("--country", &mut it)?),
            "--ip" => a.ip = Some(value("--ip", &mut it)?),
            "--limit" => {
                a.limit = value("--limit", &mut it)?
                    .parse()
                    .map_err(|e| format!("invalid --limit: {e}"))?
            }
            "--ttl" => {
                a.ttl = value("--ttl", &mut it)?
                    .parse()
                    .map_err(|e| format!("invalid --ttl: {e}"))?
            }
            "--all" => a.all = true,
            "--why" => a.why = true,
            "--json" => a.json = true,
            "--source" => {
                let v = value("--source", &mut it)?;
                tfps::manual_log::check_source(&v)?;
                a.source = Some(v);
            }
            "--reason" => {
                let v = value("--reason", &mut it)?;
                tfps::manual_log::check_reason(&v)?;
                a.reason = Some(v);
            }
            "--listen" => {
                a.listen = Some(
                    value("--listen", &mut it)?
                        .parse()
                        .map_err(|e| format!("invalid --listen (IPv4 address:port): {e}"))?,
                )
            }
            "--allow-unban" => a.allow_unban = true,
            "-h" | "--help" => return Err(String::new()),
            other if other.starts_with('-') => return Err(format!("unknown option: {other}")),
            other if a.command.is_empty() => a.command = other.to_string(),
            other => a.positional.push(other.to_string()),
        }
    }
    if a.command.is_empty() {
        return Err(String::new());
    }
    // Who asked and why describe a manual action; on any other command they
    // would be accepted and then ignored, which reads as recorded when it is not.
    if (a.source.is_some() || a.reason.is_some()) && !matches!(a.command.as_str(), "ban" | "unban")
    {
        return Err("--source and --reason apply to ban and unban only".into());
    }
    if (a.listen.is_some() || a.allow_unban) && a.command != "serve" {
        return Err("--listen and --allow-unban apply to serve only".into());
    }
    if a.json && a.command == "serve" {
        return Err("serve answers in JSON over HTTP; --json does not apply".into());
    }
    Ok(a)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse(&argv) {
        Ok(a) => a,
        Err(e) if e.is_empty() => {
            say!("{}", usage().trim_end());
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("error: {e}\n\n{}", usage());
            return ExitCode::from(2);
        }
    };

    let r = match args.command.as_str() {
        "status" => status(&args),
        "stats" => stats(&args),
        "banned" => banned(&args),
        "unban" => unban(&args),
        "ban" => ban(&args),
        "sources" => sources(&args),
        "source" => source(&args),
        "peers" => peers(&args),
        "countries" => countries(&args),
        "log" => log(&args),
        "forget" => forget(&args),
        "serve" => serve(&args),
        other => Err(format!("unknown command: {other}")),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------- commands

fn status(args: &Args) -> Result<(), String> {
    if args.json {
        say!("{}", tfps::json_line(&status_docs(&args.ctx()))?);
        return Ok(());
    }
    say!("database          : {}", args.db.display());
    match Store::open_readonly(&args.db).and_then(|s| s.totals()) {
        Ok((pairs, peers, newest)) => {
            say!("learned state     : {pairs} pairs across {peers} peers");
            if newest > 0 {
                say!(
                    "last checkpoint   : {} ago (state is a snapshot, not live)",
                    ago(now().saturating_sub(newest))
                );
            }
        }
        Err(e) => say!("learned state     : unavailable — {e}"),
    }
    match Blocklist::open(args.map.as_deref()).and_then(|b| Ok((b.entries()?, b.source))) {
        Ok((e, source)) => {
            let permanent = e.iter().filter(|(_, until)| *until == 0).count();
            say!("enforcement       : {source}");
            say!(
                "blocked now       : {} ({permanent} without expiry)",
                e.len()
            );
        }
        Err(e) => {
            say!("enforcement       : unreachable — {e}");
            say!("                    (learned state above is still readable)");
        }
    }
    Ok(())
}

/// The whole picture, from the two places it lives.
///
/// **The kernel half is live; the userspace half is a snapshot.** They are printed apart,
/// with the snapshot's age stated, because presenting a five-minute-old packet count beside
/// a current drop count as if both were now would be the kind of quiet inaccuracy this
/// project exists to avoid.
fn stats(args: &Args) -> Result<(), String> {
    if args.json {
        say!("{}", tfps::json_line(&stats_docs(&args.ctx())?)?);
        return Ok(());
    }
    match tfps::xdp::live_counters() {
        Ok(c) => {
            let share = if c.seen > 0 {
                100.0 * c.dropped as f64 / c.seen as f64
            } else {
                0.0
            };
            say!("KERNEL  (live)");
            say!("  seen on SIP ports : {}", c.seen);
            say!(
                "  dropped by XDP    : {} ({share:.1}% — gone before sngrep)",
                c.dropped
            );
            say!("  blocks expired    : {}", c.expired);
        }
        Err(e) => say!("KERNEL  (live)\n  unavailable — {e}"),
    }
    let s = Store::open_readonly(&args.db)?;
    if let Ok(e) = Blocklist::open(args.map.as_deref()).and_then(|b| b.entries()) {
        // A perimeter block often lands on an IP that is also on the feed; attribute it to the
        // reason we condemned it (the audit log), not to the feed it happens to appear on.
        // Both are asked only about the addresses in the map.
        let among = map_addresses(&e);
        let audit = s.logged_among(&among).unwrap_or_default();
        let apiban = s.apiban_among(&among).unwrap_or_default();
        let perimeter = e
            .iter()
            .filter(|(ip, _)| audit.contains(&ip.to_string()))
            .count();
        let feed = e
            .iter()
            .filter(|(ip, _)| !audit.contains(&ip.to_string()) && apiban.contains(&ip.to_string()))
            .count();
        say!("  condemned now     : {}", e.len());
        say!("    perimeter/manual : {perimeter}");
        say!("    APIBAN feed only : {feed}");
    }

    let now = now();
    match (s.meta_get("stats"), s.meta_get("stats_ts")) {
        (Some(line), ts) => {
            let age = ts
                .and_then(|t| t.parse::<u32>().ok())
                .map(|t| ago(now.saturating_sub(t)))
                .unwrap_or_else(|| "unknown".into());
            say!("\nTRAFFIC  (as of the last checkpoint, {age} ago)");
            // Two columns, so twenty counters stay readable in a terminal.
            let pairs: Vec<(&str, &str)> = line
                .split_whitespace()
                .filter_map(|kv| kv.split_once('='))
                .collect();
            for row in pairs.chunks(2) {
                let cell = |(k, v): &(&str, &str)| format!("{k:<16} {v:>10}");
                say!(
                    "  {}   {}",
                    cell(&row[0]),
                    row.get(1).map(cell).unwrap_or_default()
                );
            }
        }
        _ => say!("\nTRAFFIC\n  no checkpoint yet — the daemon writes these every 5 minutes"),
    }
    if let Some(t) = s.meta_get("started_at").and_then(|v| v.parse::<u32>().ok()) {
        say!("  {:<16} {:>10}", "running for", ago(now.saturating_sub(t)));
    }

    if let Some(line) = s.meta_get("ignoreip").filter(|l| !l.is_empty()) {
        say!("\nIGNOREIP  (exempt from enforcement, still judged and reported)");
        for entry in line.split_whitespace() {
            if let Some((label, hits)) = entry.rsplit_once('=') {
                let note = if hits == "0" { "  never matched" } else { "" };
                say!("  {label:<22} {hits:>8}{note}");
            }
        }
    }

    if let Some(cal) = s.meta_get("calibration").filter(|c| !c.is_empty()) {
        say!("\nCALIBRATION  (benign hypotheses learned from this deployment)");
        for kv in cal.split_whitespace() {
            if let Some((k, v)) = kv.split_once('=') {
                say!("  {k:<16} {v:>10}");
            }
        }
    }

    let (pairs, peers, _) = s.totals()?;
    let (countries, calls) = s.country_spread()?;
    say!("\nLEARNED");
    say!("  {:<16} {:>10}", "pairs", pairs);
    say!("  {:<16} {:>10}", "peers", peers);
    say!("  {:<16} {:>10}", "countries", countries);
    say!("  {:<16} {:>10}", "intl calls", calls);

    say!("\nBLOCKS BY REASON  (perimeter/manual — the APIBAN feed is a separate list)");
    say!(
        "  {:<16} {:>10}  {}",
        "apiban (feed)",
        s.apiban_count().unwrap_or(0),
        "permanent, not audit-logged"
    );
    for (label, since) in [
        ("last hour", 3600u32),
        ("last day", 86400),
        ("last week", 604_800),
    ] {
        let rows = s.blocks_by_reason(now.saturating_sub(since))?;
        let total: u32 = rows.iter().map(|(_, n)| n).sum();
        let detail: Vec<String> = rows.iter().map(|(r, n)| format!("{r}:{n}")).collect();
        say!("  {label:<16} {total:>10}  {}", detail.join(" "));
    }
    Ok(())
}

/// The manual-ban records for what `place` actually blocked.
///
/// Exempt and failed addresses are not recorded: nothing was blocked, so the
/// record lists only blocks that took effect and can explain what `banned`
/// shows.
fn manual_bans(
    out: &Placed,
    source: Option<&str>,
    reason: Option<&str>,
    now_wall: u32,
    ttl: u64,
) -> Vec<tfps::manual_log::ManualAction> {
    out.blocked
        .iter()
        .map(|ip| tfps::manual_log::ManualAction {
            ts: now_wall,
            verb: tfps::manual_log::ManualVerb::Ban,
            ip: *ip,
            source: source.unwrap_or("operator").to_string(),
            reason: reason.map(str::to_string),
            expires: ban_expires(now_wall, ttl),
        })
        .collect()
}

/// Which count of `banned`'s summary line a block falls in.
#[derive(Debug, PartialEq, Eq)]
enum Tally {
    /// The perimeter's own blocks and manually placed ones: what "perimeter/manual"
    /// has always counted.
    PerimeterManual,
    /// Blocks only the APIBAN feed explains.
    Apiban,
    /// Blocks nothing explains.
    Unattributed,
}

/// The summary count for a block explained by a manual ban, the audit log or
/// the feed, in that order of precedence.
fn tally_of(manual: bool, audit: bool, apiban: bool) -> Tally {
    if manual || audit {
        Tally::PerimeterManual
    } else if apiban {
        Tally::Apiban
    } else {
        Tally::Unattributed
    }
}

fn banned(args: &Args) -> Result<(), String> {
    if args.json {
        for doc in banned_docs(&args.ctx())? {
            say!("{}", tfps::json_line(&doc)?);
        }
        return Ok(());
    }
    let entries = Blocklist::open(args.map.as_deref())?.entries()?;
    if entries.is_empty() {
        say!("nothing is blocked");
        return Ok(());
    }
    // Attribute each block once, block_log winning over the APIBAN feed — a scanner is
    // often on both (APIBAN's honeypots catch the same tools), and the *reason* we
    // condemned it is the perimeter one, not the feed. Load both sets once.
    // The audit log and the feed are asked only about the addresses in the map.
    let store = Store::open_readonly(&args.db).ok();
    let among = map_addresses(&entries);
    let apiban = store
        .as_ref()
        .and_then(|s| s.apiban_among(&among).ok())
        .unwrap_or_default();
    // ip -> (reason, detail, first_seen) from its most recent block, and ip -> that block's time.
    let (audit, newest) = audit_maps(
        store
            .as_ref()
            .and_then(|s| s.block_summaries(&among).ok())
            .unwrap_or_default(),
    );
    let wanted: std::collections::HashSet<Ipv4Addr> = entries.iter().map(|(ip, _)| *ip).collect();
    let manual = manual_record(&args.ctx(), &wanted);

    let now_ns = monotonic_ns();
    let (mut n_perimeter, mut n_apiban, mut n_unknown) = (0usize, 0usize, 0usize);
    say!("{:<16} {:>10}  REASON", "SOURCE", "EXPIRES IN");
    for (ip, until) in &entries {
        let left = if *until == 0 {
            "never".to_string()
        } else {
            ago(((*until).saturating_sub(now_ns) / 1_000_000_000) as u32)
        };
        let ip_s = ip.to_string();
        // A manual ban no daemon block has superseded wins; then block_log; then the
        // feed; then unknown. A manual ban counts as perimeter/manual, as before.
        let by_manual = manual_attribution(*ip, &manual, newest.get(&ip_s).copied());
        let by_audit = audit.get(&ip_s);
        let by_feed = apiban.contains(&ip_s);
        match tally_of(by_manual.is_some(), by_audit.is_some(), by_feed) {
            Tally::PerimeterManual => n_perimeter += 1,
            Tally::Apiban => n_apiban += 1,
            Tally::Unattributed => n_unknown += 1,
        }
        let why = if let Some((_, detail, source)) = by_manual {
            format!("manual ({detail}) by {source}")
        } else if let Some((reason, detail, _)) = by_audit {
            format!("{reason} ({detail})")
        } else if by_feed {
            "apiban (feed)".to_string()
        } else {
            "not in this audit log".to_string()
        };
        if args.why {
            say!("{ip_s:<16} {left:>10}  {why}");
        } else {
            say!("{ip_s:<16} {left:>10}");
        }
    }
    say!(
        "\n{} blocked — {n_perimeter} perimeter/manual, {n_apiban} APIBAN feed{}",
        entries.len(),
        if n_unknown > 0 {
            format!(", {n_unknown} unattributed")
        } else {
            String::new()
        }
    );
    Ok(())
}

fn unban(args: &Args) -> Result<(), String> {
    let target = if args.all {
        UnbanTarget::All
    } else {
        UnbanTarget::Addresses(&args.positional)
    };
    let UnbanOutcome { docs, failed } = unban_docs(
        &args.ctx(),
        target,
        args.source.as_deref(),
        args.reason.as_deref(),
    )?;
    // `--all` has only ever reported once every removal succeeded. The address
    // form reports each address it handled, so on a kernel failure part-way
    // through, the ones lifted before it are still printed ahead of the error.
    if args.all {
        if let Some(e) = failed {
            return Err(e);
        }
    }
    if args.json {
        for doc in &docs {
            say!("{}", tfps::json_line(doc)?);
        }
        return failed.map_or(Ok(()), Err);
    }
    if args.all {
        say!("unbanned {} sources", docs.len());
        return Ok(());
    }
    for doc in &docs {
        let ip = doc.ip.as_deref().unwrap_or_default();
        // Saying "unbanned" for an address that was never there would be a small lie the
        // operator acts on: they would stop looking for the real block.
        if doc.applied {
            say!("unbanned {ip}");
        } else {
            say!("{ip} was not blocked");
        }
    }
    failed.map_or(Ok(()), Err)
}

/// Which entry exempted a hand-placed block, and where that entry came from.
#[derive(Debug, PartialEq, Eq)]
struct Exemption {
    origin: Origin,
    rule: String,
}

/// What `place` did with a list of addresses. Every address lands in exactly one.
#[derive(Debug, Default, PartialEq, Eq)]
struct Placed {
    blocked: Vec<Ipv4Addr>,
    exempt: Vec<(Ipv4Addr, Exemption)>,
    failed: Vec<(Ipv4Addr, String)>,
}

/// Places blocks by hand, refusing what the daemon refuses.
///
/// The guard is consulted **before** the kernel, and a refused address touches
/// nothing at all. `xdp::local_addresses` says why in its own doc comment: it
/// exists "so the system cannot condemn the machine it is defending", and a
/// command placing a block from outside the daemon has exactly the same
/// obligation. One typo at a root prompt blackholes the box, and on a remote
/// host that is the last command anybody gets to run.
///
/// Every input is an argument so the whole decision is drivable from a test:
/// the kernel map needs `CAP_BPF` and a pinned path and cannot be opened by one.
fn place(
    ips: &[Ipv4Addr],
    guard: &mut IgnoreList,
    mut block: impl FnMut(Ipv4Addr) -> Result<(), String>,
) -> Placed {
    let mut out = Placed::default();
    for &ip in ips {
        // The same gate as the daemon (`tfps_core::disposition::gate`), with one
        // deliberate difference: a hand ban is the operator overriding the
        // registered-peer heuristic, so that test is answered `false` here and
        // both non-exempt arms lead to the write.
        let why = guard.exempt_entry(ip).map(|(rule, origin)| Exemption {
            origin,
            rule: rule.to_string(),
        });
        match gate(why, false) {
            Gate::Exempt(why) => out.exempt.push((ip, why)),
            Gate::KnownPeer | Gate::Enforce => match block(ip) {
                Ok(()) => out.blocked.push(ip),
                Err(e) => out.failed.push((ip, e)),
            },
        }
    }
    out
}

/// A hand ban's expiry, as a wall-clock epoch second for `action_doc` to carry.
///
/// This is genuinely new arithmetic: the human path below only ever turns
/// `args.ttl` into a relative duration (`ago(args.ttl as u32)`), never an
/// absolute time. `Blocklist::insert` computes the kernel deadline as
/// `monotonic_ns() + ttl_secs * 1e9`; this computes the same instant
/// directly in wall-clock terms — `now_wall + ttl_secs` — without reading
/// anything back from the kernel, because the caller already knows both
/// inputs at the moment it asks for the write. `0` means "forever" (see
/// `Blocklist::insert`), which has no expiry to report.
fn ban_expires(now_wall: u32, ttl_secs: u64) -> Option<u32> {
    if ttl_secs == 0 {
        None
    } else {
        // `--ttl` parses into a `u64` with no upper bound, so a ttl past
        // `u32::MAX` gets here. `as u32` would wrap it first and leave
        // `saturating_add` nothing to save: `--ttl 4294967296` would report an
        // expiry of now. Clamp before the add, not after.
        Some(now_wall.saturating_add(u32::try_from(ttl_secs).unwrap_or(u32::MAX)))
    }
}

/// Maps one `Placed` outcome to the JSONL documents `ban --json` prints —
/// one per input address, in the same blocked/exempt/failed bucket order
/// the human path below already iterates.
///
/// This is the one place that DECIDES which refusal string an address
/// gets; `action_doc` only renders a string it is already handed. The two
/// policy strings are `CONTEXT.md`'s own words for the two kinds of ignoreip
/// entry — **local** (the host's own addresses, discovered) and **declared**
/// (the operator's) — which are also the `Origin` variants' names. Folding
/// `"kernel"` into `"local"`, or swapping the two `Origin` arms, would
/// compile cleanly and pass every `action_doc` test — see
/// `ban_action_docs_maps_each_placed_outcome_to_its_own_refusal`, which
/// drives this function through a real `Placed` instead.
fn ban_action_docs(out: &Placed, expires: Option<u32>, source: Option<&str>) -> Vec<ActionDoc> {
    let mut docs = Vec::with_capacity(out.blocked.len() + out.exempt.len() + out.failed.len());
    for ip in &out.blocked {
        docs.push(action_doc(Some(&ip.to_string()), "ban", None, expires));
    }
    for (ip, why) in &out.exempt {
        let reason = match why.origin {
            Origin::Local => "local",
            Origin::Declared => "declared",
        };
        docs.push(action_doc(Some(&ip.to_string()), "ban", Some(reason), None));
    }
    for (ip, _e) in &out.failed {
        docs.push(action_doc(
            Some(&ip.to_string()),
            "ban",
            Some("kernel"),
            None,
        ));
    }
    docs.into_iter().map(|d| d.with_source(source)).collect()
}

/// The per-address diagnostics for whatever `place` refused or failed to
/// write, on stderr, in both plain and `--json` mode.
///
/// stderr is not the JSON stream, so printing these here corrupts nothing on
/// stdout. `--json` mode needs them for a reason plain mode does not: per
/// `ActionDoc`'s doc comment, a kernel write failure is deliberately rendered
/// as the categorical label `"refused":"kernel"`, the same shape a policy
/// refusal gets — `ban_action_docs` never puts the underlying `Blocklist`
/// error string into the document, and `ActionDoc` gains no field here to
/// hold it. Without this function's stderr output, a `--json` caller learns
/// THAT a write failed but never WHY; the specific reason (map missing,
/// permission, ...) exists only in `e` below, and this is the only place it
/// is still rendered.
fn report_ban_diagnostics(out: &Placed) {
    for (ip, why) in &out.exempt {
        match why.origin {
            Origin::Local => {
                eprintln!("error: refusing to block {ip}: it is an address of this host")
            }
            Origin::Declared => eprintln!(
                "error: refusing to block {ip}: ignoreip={} says never enforce against it",
                why.rule
            ),
        }
    }
    for (ip, e) in &out.failed {
        eprintln!("error: could not block {ip}: {e}");
    }
}

fn ban(args: &Args) -> Result<(), String> {
    if args.positional.is_empty() {
        return Err("give at least one address".into());
    }
    let mut ips = Vec::with_capacity(args.positional.len());
    for raw in &args.positional {
        ips.push(raw.parse::<Ipv4Addr>().map_err(|e| format!("{raw}: {e}"))?);
    }
    // The daemon's own entries as of its last checkpoint, when there is a database to
    // read them from. This is how a hand ban honours `--ignoreip` given on the daemon's
    // command line, which no file records. Absent or unreadable is the `--no-db` case
    // and is not an error here; the file and the host still apply.
    let persisted = Store::open_readonly(&args.db)
        .ok()
        .and_then(|s| s.meta_get("ignoreip"));
    let mut guard = enforcement_guard(
        &tfps::xdp::local_addresses(),
        tfps::config::load(&args.config),
        persisted.as_deref(),
    )?;
    // The map is opened on the first address that survives the guard, not before.
    // Refusing to blackhole the host is a decision this tool can make on its own,
    // and making it conditional on CAP_BPF and a running daemon would mean the
    // answer to "would this have blocked my box?" depends on who is asking.
    let mut b: Option<Blocklist> = None;
    let out = place(&ips, &mut guard, |ip| {
        let bl = match b.as_mut() {
            Some(bl) => bl,
            None => b.insert(Blocklist::open(args.map.as_deref())?),
        };
        bl.insert(ip, args.ttl)
    });
    record_manual(
        &args.ctx(),
        &manual_bans(
            &out,
            args.source.as_deref(),
            args.reason.as_deref(),
            now(),
            args.ttl,
        ),
    );

    if args.json {
        // Render `out` exactly as computed above — the same guard decision
        // the human path below prints as prose. The final `Ok`/`Err` is
        // shared with the human path too (mirrored below), so `--json`
        // changes only the rendering, never the exit code. The per-address
        // stderr diagnostics are shared too, via `report_ban_diagnostics`:
        // `--json` renders a kernel failure as the flattened
        // `"refused":"kernel"` on stdout, so stderr is the only place the
        // specific reason is still available to a `--json` caller.
        let expires = ban_expires(now(), args.ttl);
        for doc in ban_action_docs(&out, expires, args.source.as_deref()) {
            say!("{}", tfps::json_line(&doc)?);
        }
        report_ban_diagnostics(&out);
        return if out.exempt.is_empty() && out.failed.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "{} of {} addresses were not blocked",
                out.exempt.len() + out.failed.len(),
                ips.len()
            ))
        };
    }

    let how = if args.ttl == 0 {
        "with no expiry".to_string()
    } else {
        format!("for {}", ago(args.ttl as u32))
    };
    for ip in &out.blocked {
        say!("blocked {ip} {how}");
    }
    report_ban_diagnostics(&out);
    // NOT recorded in block_log, deliberately. A hand-placed block still leaves
    // no trace, so `banned --why` cannot explain it — that is a real gap, and
    // fixing it means opening the database read-write from this tool, which the
    // note on `Store::open_readonly` forbids on purpose and which would run a
    // migration from a binary that is not the daemon. That is a decision about
    // this tool's contract, not a bug fix, so it is left alone here.
    if out.exempt.is_empty() && out.failed.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} of {} addresses were not blocked",
            out.exempt.len() + out.failed.len(),
            ips.len()
        ))
    }
}

/// The exemptions the daemon applies, assembled by the daemon's own code.
///
/// `tfps::guard::assemble` is the one assembly; what differs here is the inputs
/// and the policy. The host's addresses come from the kernel as they do for the
/// daemon; the declared entries come from the configuration file and from the
/// list the daemon persisted at its last checkpoint, which also carries whatever
/// `--ignoreip` it was started with. Everything arrives as an argument so the
/// assembly is drivable from a test; `ban` is the only caller.
///
/// An empty host set is refused, not accepted. `local_addresses` returns nothing
/// when `/proc/net/fib_trie` cannot be read, and a real host is never empty --
/// loopback alone is a LOCAL route whenever `lo` is up. So empty means the read
/// failed, and a guard built without the host's addresses is exactly the guard
/// that lets a typo blackhole the box.
///
/// The policy on a bad input is the one place this tool differs from the daemon,
/// on purpose. The daemon alarms and carries on, with hours of traffic ahead and
/// a startup report to say it in; this command has one write to make, and the
/// alternative is making it while an exemption the operator believes in is
/// silently absent. So a malformed entry or a broken file aborts.
fn enforcement_guard(
    local: &[Ipv4Addr],
    loaded: tfps::config::Loaded,
    persisted: Option<&str>,
) -> Result<IgnoreList, String> {
    if local.is_empty() {
        return Err(
            "could not read this host's addresses from /proc/net/fib_trie; \
             refusing to place a block without the host guard"
                .into(),
        );
    }
    let from_file = match loaded {
        tfps::config::Loaded::File(c, _) => c.ignoreip.clone(),
        tfps::config::Loaded::Absent => Vec::new(),
        tfps::config::Loaded::Broken(e) => return Err(e),
    };
    let from_daemon: Vec<String> = persisted
        .map(|line| {
            tfps::guard::labels_from_checkpoint(line)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let guard = tfps::guard::assemble(
        local,
        from_file.iter().chain(&from_daemon).map(String::as_str),
    );
    if let Some(e) = guard.rejected.into_iter().next() {
        return Err(e);
    }
    Ok(guard.list)
}

/// What `sources --json` says about one learned pair: the same fields the
/// human COUNTRIES/RATE/LAST columns already print, per row.
///
/// `countries` is `SourceRow.n_countries`, the stored column — see `SourceDoc`
/// below for why that and not the decoded list's length.
#[derive(Serialize)]
struct SourceRowDoc {
    peer: String,
    countries: u32,
    /// `null` when the stored rate is not a finite number.
    ///
    /// `rate_a` is `REAL NOT NULL` and SQLite stores an infinity faithfully, so
    /// a non-finite value can reach here. JSON cannot spell one — `serde_json`
    /// renders it `null` whatever the field is declared as — so the type says so
    /// rather than promising a number it cannot always supply.
    rate: Option<f64>,
    last_seen: u32,
}

/// Built from a `SourceRow`'s already-loaded fields — no transformation,
/// just field selection, the same as `status_doc`.
fn source_row_doc(peer: &str, countries: u32, rate: f64, last_seen: u32) -> SourceRowDoc {
    SourceRowDoc {
        peer: peer.to_string(),
        countries,
        rate: finite(rate),
        last_seen,
    }
}

fn sources(args: &Args) -> Result<(), String> {
    let s = Store::open_readonly(&args.db)?;
    let f = SourceFilter {
        peer: args.peer.as_deref(),
        country: args.country.as_deref(),
        limit: args.limit,
    };
    let rows = s.find_sources(&f)?;
    if args.json {
        // Reuses the same `rows` the human path below iterates, already
        // limited by `SourceFilter.limit` inside `find_sources` — no
        // separate limiting logic to keep in sync.
        for r in &rows {
            say!(
                "{}",
                tfps::json_line(&source_row_doc(
                    &r.peer,
                    r.n_countries,
                    r.rate_a,
                    r.last_seen
                ))?
            );
        }
        return Ok(());
    }
    if rows.is_empty() {
        say!("no source matches");
        return Ok(());
    }
    say!("{:<16} {:>8} {:>9}  COUNTRIES", "PEER", "COUNTRIES", "LAST");
    let now = now();
    for r in &rows {
        let c = r.countries();
        let shown: Vec<&str> = c.iter().take(10).copied().collect();
        let tail = if c.len() > shown.len() {
            format!(" +{}", c.len() - shown.len())
        } else {
            String::new()
        };
        say!(
            "{:<16} {:>8} {:>9}  {}{}",
            r.peer,
            r.n_countries,
            ago(now.saturating_sub(r.last_seen)),
            shown.join(","),
            tail
        );
    }
    say!("\n{} sources", rows.len());
    Ok(())
}

/// What `source --json` says about one peer: the same fields `source`'s
/// human path already prints, plus the full country list it already
/// decodes to print the chunked lines below.
///
/// `countries` is `SourceRow.n_countries` — the SAME stored column
/// `SourceRowDoc`/`PeerRowDoc` use — not `c.len()`, the decoded list's
/// length, even though `c.len()` is what `source`'s own human "countries
/// known" line prints just below. The two counts are equal for any row
/// written under the current country table: `n_countries` is incremented
/// once per newly-set bit (`anomaly.rs`), and `decode_bitmap` decodes via
/// the literal inverse (`country.rs`). But they are not equal *by
/// invariant*: `decode_bitmap` silently drops a bit whose index has no
/// current `CODES` entry, while `n_countries` is a raw, unconditional
/// counter, so a row written under a past, since-renumbered-or-pruned
/// version of that table could show the two counts apart. Consistency
/// wins over the human path's own choice here: `countries` means
/// `n_countries` wherever it is a scalar in this contract, full stop, so
/// `sources --json` and `source --json` never disagree about the same
/// peer. A consumer wanting the decoded count takes
/// `countries_known.len()` instead.
#[derive(Serialize)]
struct SourceDoc {
    peer: String,
    countries: u32,
    /// `null` when the stored rate is not a finite number.
    ///
    /// `rate_a` is `REAL NOT NULL` and SQLite stores an infinity faithfully, so
    /// a non-finite value can reach here. JSON cannot spell one — `serde_json`
    /// renders it `null` whatever the field is declared as — so the type says so
    /// rather than promising a number it cannot always supply.
    rate: Option<f64>,
    last_seen: u32,
    countries_known: Vec<String>,
}

/// Built from a `SourceRow`'s already-loaded fields and its already-decoded
/// country list — no transformation, just field selection. `countries` is the
/// caller's `SourceRow.n_countries`, never recomputed from `countries_known`.
fn source_doc(
    peer: &str,
    countries: u32,
    rate: f64,
    last_seen: u32,
    countries_known: &[&str],
) -> SourceDoc {
    SourceDoc {
        peer: peer.to_string(),
        countries,
        rate: finite(rate),
        last_seen,
        countries_known: countries_known.iter().map(|c| c.to_string()).collect(),
    }
}

fn source(args: &Args) -> Result<(), String> {
    let [peer] = args.positional.as_slice() else {
        return Err("usage: tfps_ctl source <peer>".into());
    };
    let s = Store::open_readonly(&args.db)?;
    let rows = s.find_sources(&SourceFilter {
        peer: Some(peer),
        limit: usize::MAX,
        ..Default::default()
    })?;
    let Some(r) = rows.first() else {
        return Err(format!("no source {peer} in the database"));
    };
    let c = r.countries();
    if args.json {
        // `r.n_countries`, not `c.len()` — see `SourceDoc`'s doc comment.
        say!(
            "{}",
            tfps::json_line(&source_doc(
                &r.peer,
                r.n_countries,
                r.rate_a,
                r.last_seen,
                &c
            ))?
        );
        return Ok(());
    }
    say!("peer              : {}", r.peer);
    say!(
        "last seen         : {} ago",
        ago(now().saturating_sub(r.last_seen))
    );
    say!("learned rate      : {:.2} intl calls / window", r.rate_a);
    say!("countries known   : {}", c.len());
    for chunk in c.chunks(12) {
        say!("                    {}", chunk.join(" "));
    }
    say!(
        "\nThe detector fires when a source's evidence — several dialling prefixes, a burst \
         of novel destination ranges, or a volume spike against this baseline — crosses \
         the bound."
    );
    Ok(())
}

/// What `peers --json` says about one peer: the same two columns `peers`'s
/// human path already prints, per row. `countries` is the stored count — see
/// `SourceDoc` above.
#[derive(Serialize)]
struct PeerRowDoc {
    peer: String,
    countries: u32,
    last_seen: u32,
}

/// Built from one already-loaded `s.peers()` row — no transformation, just
/// field selection.
fn peer_row_doc(peer: &str, countries: u32, last_seen: u32) -> PeerRowDoc {
    PeerRowDoc {
        peer: peer.to_string(),
        countries,
        last_seen,
    }
}

fn peers(args: &Args) -> Result<(), String> {
    let s = Store::open_readonly(&args.db)?;
    let rows = s.peers()?;
    if args.json {
        // `s.peers()` applies no limit itself (see store.rs); `.take` here
        // is the same limiting the human loop below applies to the same
        // `rows`.
        for (peer, ncoun, last) in rows.iter().take(args.limit) {
            say!("{}", tfps::json_line(&peer_row_doc(peer, *ncoun, *last))?);
        }
        return Ok(());
    }
    if rows.is_empty() {
        say!("no peer learned yet");
        return Ok(());
    }
    say!("{:<16} {:>9} {:>9}  COUNTRIES", "PEER", "COUNTRIES", "LAST");
    let now = now();
    for (peer, ncoun, last) in rows.iter().take(args.limit) {
        let seen: Vec<&str> = s.peer_countries(peer).unwrap_or_default();
        say!(
            "{:<16} {:>9} {:>9}  {}",
            peer,
            ncoun,
            ago(now.saturating_sub(*last)),
            seen.iter().take(6).copied().collect::<Vec<_>>().join(" ")
        );
    }
    say!("\n{} sources", rows.len());
    Ok(())
}

/// What `countries --json` says about one peer's learned country set.
///
/// The human view below chunks this list purely to wrap a terminal
/// (`chunks(16)`, joined with spaces); a program wants the list itself, so
/// this is a JSON array — never the joined, chunked string — and an empty
/// list renders `[]`, never `null`.
///
/// The field is `countries_known`, the name `SourceDoc` already gives the same
/// array, and not `countries`, which is a `u32` in `SourceRowDoc`, `SourceDoc`
/// and `PeerRowDoc`. One field name carrying a scalar in three documents and an
/// array in a fourth is the ambiguity `CONTEXT.md` exists to prevent.
#[derive(Serialize)]
struct CountriesDoc {
    peer: String,
    countries_known: Vec<String>,
}

/// Built from an already-decoded country list — no transformation, just
/// field selection and the `&str` -> owned `String` conversion `json_line`
/// needs.
fn countries_doc(peer: &str, countries: &[&str]) -> CountriesDoc {
    CountriesDoc {
        peer: peer.to_string(),
        countries_known: countries.iter().map(|c| c.to_string()).collect(),
    }
}

fn countries(args: &Args) -> Result<(), String> {
    let [peer] = args.positional.as_slice() else {
        return Err("usage: tfps_ctl countries <peer>".into());
    };
    let s = Store::open_readonly(&args.db)?;
    let names = s.peer_countries(peer)?;
    if names.is_empty() {
        return Err(format!("nothing learned for source {peer}"));
    }
    if args.json {
        say!("{}", tfps::json_line(&countries_doc(peer, &names))?);
        return Ok(());
    }
    say!("{peer} has been seen to call {} countries:", names.len());
    for chunk in names.chunks(16) {
        say!("  {}", chunk.join(" "));
    }
    Ok(())
}

fn log(args: &Args) -> Result<(), String> {
    if args.json {
        for doc in log_docs(&args.ctx(), args.limit, args.ip.as_deref())? {
            say!("{}", tfps::json_line(&doc)?);
        }
        return Ok(());
    }
    let s = Store::open_readonly(&args.db)?;
    let rows: Vec<BlockRow> = s.blocks(args.limit, args.ip.as_deref())?;
    if rows.is_empty() {
        say!("the audit log is empty");
        return Ok(());
    }
    say!("{:<9} {:<16} {:<14} DETAIL", "AGE", "SOURCE", "REASON");
    let now = now();
    for r in &rows {
        say!(
            "{:<9} {:<16} {:<14} {}",
            ago(now.saturating_sub(r.ts)),
            r.ip,
            r.reason,
            r.detail
        );
    }
    Ok(())
}

/// What `forget --json` says about one erase.
#[derive(Serialize)]
struct ForgetDoc {
    peer: String,
    forgotten: usize,
}

/// Built from arguments so it is drivable from a test without a database.
fn forget_doc(peer: &str, forgotten: usize) -> ForgetDoc {
    ForgetDoc {
        peer: peer.to_string(),
        forgotten,
    }
}

fn forget(args: &Args) -> Result<(), String> {
    let Some(peer) = args.positional.first() else {
        return Err("usage: tfps_ctl forget <peer> [--a NUMBER]".into());
    };
    // A running daemon holds the working set in memory and would write it straight back at
    // the next checkpoint. Deleting rows underneath it would look like it worked and then
    // quietly undo itself — the exact class of silent failure this project exists to avoid.
    if Blocklist::open(args.map.as_deref()).is_ok() {
        return Err(
            "tfps appears to be running: its in-memory state would be written back at the \
             next checkpoint, undoing this. Stop the service first (systemctl stop tfps)."
                .into(),
        );
    }
    let s = Store::open(Path::new(&args.db))?;
    let n = s.forget(peer, args.a_number.as_deref())?;
    if args.json {
        say!("{}", tfps::json_line(&forget_doc(peer, n))?);
        return Ok(());
    }
    say!("forgot {n} pairs for {peer}");
    Ok(())
}

/// `serve`: the JSON API, in the foreground, until the process is stopped.
///
/// Off unless the configuration enables it, and then it says so and exits 0, so
/// the unit can be installed and left alone without systemd restarting it.
fn serve(args: &Args) -> Result<(), String> {
    let (http, config_db, config_map) = match tfps::config::load(&args.config) {
        tfps::config::Loaded::File(c, _) => (c.http.unwrap_or_default(), c.db, c.drop_map),
        tfps::config::Loaded::Absent => (tfps::config::HttpConfig::default(), None, None),
        // A broken file must not quietly turn into "the API is off".
        tfps::config::Loaded::Broken(e) => return Err(e),
    };
    let Some((listen, opts)) = serve_settings(&http, args.listen, args.allow_unban) else {
        say!(
            "the HTTP API is off: set \"http\": {{\"enabled\": true}} in {} to serve it",
            args.config.display()
        );
        return Ok(());
    };
    let listener =
        std::net::TcpListener::bind(listen).map_err(|e| format!("listening on {listen}: {e}"))?;
    if let Some(w) = tfps::api::bind_warning(listen, opts.allow_unban) {
        eprintln!("{w}");
    }
    eprintln!(
        "tfps_ctl serve: listening on http://{listen}/ (unban over HTTP: {})",
        if opts.allow_unban { "on" } else { "off" }
    );
    tfps::api::serve(
        listener,
        std::sync::Arc::new(tfps::api::CtlBackend(serve_ctx(
            args, config_db, config_map,
        ))),
        opts,
    )
    .map_err(|e| format!("serving: {e}"))
}

/// The paths `serve` reads, resolved as the daemon resolves them.
///
/// - Database: `--db`, else the configuration's `db`, else the default.
/// - Block map: `--map`, else the configuration's `drop_map` as a shared map,
///   which each read tries first and passes over for the usual lookup when it
///   is absent or unusable (`Blocklist::open_preferring`) — the same fallback
///   the daemon applies to it at startup.
///
/// The unit runs `serve` with no flags, so without this an installation whose
/// daemon uses a configured `db` or `drop_map` would be served from different
/// state, and unbans would land in the wrong map and the wrong record.
fn serve_ctx(args: &Args, config_db: Option<PathBuf>, config_map: Option<PathBuf>) -> Ctx {
    let mut ctx = args.ctx();
    if !args.db_given {
        if let Some(db) = config_db {
            ctx.db = db;
        }
    }
    if args.map.is_none() {
        ctx.shared_map = config_map;
    }
    ctx
}

/// The listen address and options `serve` runs with, or `None` when the API is
/// off. The command line beats the file, which beats the default; neither flag
/// turns the API on by itself, so `enabled` stays the one switch.
fn serve_settings(
    http: &tfps::config::HttpConfig,
    listen: Option<std::net::SocketAddrV4>,
    allow_unban: bool,
) -> Option<(std::net::SocketAddrV4, tfps::api::Options)> {
    if !http.enabled {
        return None;
    }
    Some((
        listen.unwrap_or(http.listen),
        tfps::api::Options {
            allow_unban: allow_unban || http.allow_unban,
        },
    ))
}

// ---------------------------------------------------------------- helpers

/// A compact duration. Operators read these in a column, so the widest case has to stay
/// short: `3d4h` rather than `3 days, 4 hours`.
fn ago(secs: u32) -> String {
    match secs {
        0 => "now".to_string(),
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86400 => format!("{}h{}m", s / 3600, (s % 3600) / 60),
        s => format!("{}d{}h", s / 86400, (s % 86400) / 3600),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Result<Args, String> {
        parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, last)
    }

    /// One top-level handler's body: everything between the `{` that opens
    /// `fn <name>(args: &Args)` and the `}` that closes it.
    ///
    /// The end is the first `"\n}\n"` after the opening brace. rustfmt puts a
    /// top-level function's closing brace alone at column 0, and nothing inside
    /// the function is ever at column 0, so this is exact rather than a
    /// heuristic — `cargo fmt --all --check` is one of this repository's gates,
    /// which is what makes that layout something a test may rely on.
    ///
    /// Scanning instead for the next `"\nfn "`/`"\nstruct "` — what the two
    /// tests below used to do, each with its own copy of the marker list —
    /// overshoots EVERY handler in this file, by between 2 and 23 lines, because
    /// the doc comment and `#[derive(...)]` attribute of the following item sit
    /// between the closing brace and that item's own keyword. A check meant to
    /// read one handler then reads its neighbour's preamble too, and a doc
    /// comment mentioning `args.json` is enough to make the check below pass
    /// for a handler that has no such branch at all.
    fn handler_body<'a>(src: &'a str, name: &str) -> &'a str {
        let sig = format!("\nfn {name}(args: &Args)");
        let start = src.find(&sig).unwrap_or_else(|| {
            panic!("no handler `fn {name}(args: &Args)` found for advertised command `{name}`")
        });
        let body_start = start
            + src[start..]
                .find('{')
                .unwrap_or_else(|| panic!("handler `{name}` has no opening brace"))
            + 1;
        let body_end = body_start
            + src[body_start..]
                .find("\n}\n")
                .unwrap_or_else(|| panic!("handler `{name}` has no closing brace at column 0"));
        &src[body_start..body_end]
    }

    /// The guard the daemon builds: this host's addresses, plus what the
    /// operator declared.
    fn guard(local: &[Ipv4Addr], declared: &[&str]) -> IgnoreList {
        let mut g = IgnoreList::new();
        for a in local {
            g.add_local(*a);
        }
        for d in declared {
            g.add(d).expect("fixture: the declared entry must parse");
        }
        g
    }

    // THE DEFECT, half one. `xdp::local_addresses` exists, in its own words, "so
    // the system cannot condemn the machine it is defending" — and `ban` never
    // asked. One typo at a root prompt blackholes the box, and on a remote host
    // that is the last command you get to run.
    #[test]
    fn the_host_is_never_condemned_by_hand() {
        let host = Ipv4Addr::new(10, 0, 0, 60);
        let mut g = guard(&[host], &[]);
        let mut written = Vec::new();
        let out = place(&[host], &mut g, |a| {
            written.push(a);
            Ok(())
        });
        assert!(
            written.is_empty(),
            "the host's own address must never reach the kernel map"
        );
        assert_eq!(out.blocked, Vec::<Ipv4Addr>::new());
        assert_eq!(out.exempt.len(), 1);
        assert_eq!(out.exempt[0].1.origin, Origin::Local);
    }

    // THE DEFECT, half two. The operator declared "never enforce against this
    // range". A hand-placed block went round it without a word.
    #[test]
    fn a_declared_ignoreip_range_is_refused_by_hand_too() {
        let mut g = guard(&[], &["203.0.113.0/24"]);
        let mut written = Vec::new();
        let out = place(&[ip(7)], &mut g, |a| {
            written.push(a);
            Ok(())
        });
        assert!(
            written.is_empty(),
            "a declared range must not be overridden silently"
        );
        assert_eq!(out.exempt.len(), 1);
        assert_eq!(out.exempt[0].1.origin, Origin::Declared);
        assert_eq!(
            out.exempt[0].1.rule, "203.0.113.0/24",
            "the refusal must name the entry, so the operator knows what to change"
        );
    }

    // NEGATIVE CONTROL. The command still has to work. An address nothing
    // exempts is blocked exactly once and reported as blocked.
    #[test]
    fn an_ordinary_address_is_still_blocked() {
        let mut g = guard(&[Ipv4Addr::new(10, 0, 0, 60)], &["192.168.0.0/16"]);
        let mut written = Vec::new();
        let out = place(&[ip(7)], &mut g, |a| {
            written.push(a);
            Ok(())
        });
        assert_eq!(written, vec![ip(7)]);
        assert_eq!(out.blocked, vec![ip(7)]);
        assert!(out.exempt.is_empty());
        assert!(out.failed.is_empty());
    }

    // A refusal must not take the rest of the batch down with it, and the
    // outcomes must stay disjoint: every address lands in exactly one bucket.
    #[test]
    fn one_refusal_does_not_stop_the_others() {
        let host = Ipv4Addr::new(10, 0, 0, 60);
        let mut g = guard(&[host], &["192.168.0.0/16"]);
        let batch = [ip(1), host, Ipv4Addr::new(192, 168, 1, 5), ip(2)];
        let mut written = Vec::new();
        let out = place(&batch, &mut g, |a| {
            written.push(a);
            Ok(())
        });
        assert_eq!(written, vec![ip(1), ip(2)]);
        assert_eq!(out.blocked, vec![ip(1), ip(2)]);
        assert_eq!(out.exempt.len(), 2);
        assert_eq!(
            out.blocked.len() + out.exempt.len() + out.failed.len(),
            batch.len(),
            "every address must land in exactly one outcome"
        );
    }

    // NEGATIVE CONTROL. A kernel refusal is not an exemption. Conflating them
    // would tell the operator their own configuration stopped a write that the
    // map actually rejected.
    #[test]
    fn a_kernel_failure_is_not_an_exemption() {
        let mut g = guard(&[], &[]);
        let out = place(&[ip(7)], &mut g, |_| Err("map is full".into()));
        assert!(out.exempt.is_empty());
        assert_eq!(out.failed, vec![(ip(7), "map is full".to_string())]);
        assert!(out.blocked.is_empty());
    }

    // An empty guard refuses nothing: the fixture must be able to say "no" only
    // because something was put in it, not by construction.
    #[test]
    fn an_empty_guard_refuses_nothing() {
        let host = Ipv4Addr::new(10, 0, 0, 60);
        let mut g = guard(&[], &[]);
        let out = place(&[host, ip(7)], &mut g, |_| Ok(()));
        assert_eq!(out.blocked, vec![host, ip(7)]);
        assert!(out.exempt.is_empty());
    }

    // The seam the tests above do not reach: `place` honours whatever guard it
    // is handed, so the guard has to be shown to contain the two real sources.
    // Dropping either loop in `enforcement_guard` would pass every test above.
    #[test]
    fn the_guard_is_built_from_the_host_and_the_file() {
        let host = Ipv4Addr::new(10, 0, 0, 60);
        let cfg = tfps::config::Config {
            ignoreip: vec!["203.0.113.0/24".to_string()],
            ..Default::default()
        };
        let mut g = enforcement_guard(
            &[host],
            tfps::config::Loaded::File(Box::new(cfg), PathBuf::new()),
            None,
        )
        .expect("a readable host and a well-formed file build a guard");
        assert_eq!(
            g.exempt_entry(host).map(|(_, o)| o),
            Some(Origin::Local),
            "the host's own address comes from the kernel"
        );
        assert_eq!(
            g.exempt_entry(Ipv4Addr::new(203, 0, 113, 7))
                .map(|(_, o)| o),
            Some(Origin::Declared),
            "the declared range comes from the file"
        );
        assert!(
            g.exempt_entry(Ipv4Addr::new(8, 8, 8, 8)).is_none(),
            "nothing else is exempt"
        );
    }

    // What the daemon persisted at checkpoint is honoured too: that is where an
    // entry given as `--ignoreip` on its command line lives, and no file has it.
    #[test]
    fn the_daemons_own_entries_are_honoured_by_a_hand_ban() {
        let host = Ipv4Addr::new(10, 0, 0, 60);
        let mut g = enforcement_guard(
            &[host],
            tfps::config::Loaded::Absent,
            Some("10.0.0.60=0 198.51.100.0/24=7"),
        )
        .expect("checkpoint labels are well-formed entries");
        assert_eq!(
            g.exempt_entry(Ipv4Addr::new(198, 51, 100, 9))
                .map(|(_, o)| o),
            Some(Origin::Declared)
        );
        assert_eq!(
            g.exempt_entry(host).map(|(_, o)| o),
            Some(Origin::Local),
            "the host stays local even when the checkpoint lists it too"
        );
    }

    // A fresh install has no file at all. That must not weaken the host guard.
    #[test]
    fn an_absent_file_still_guards_the_host() {
        let host = Ipv4Addr::new(10, 0, 0, 60);
        let mut g = enforcement_guard(&[host], tfps::config::Loaded::Absent, None)
            .expect("no file is the normal case");
        assert!(g.exempt_entry(host).is_some());
        assert!(g.exempt_entry(ip(8)).is_none(), "nothing was declared");
    }

    // `local_addresses` returns nothing only when /proc/net/fib_trie could not be
    // read: loopback alone is a LOCAL route on any host with `lo` up. A guard
    // built without the host is the guard that lets a typo blackhole the box, so
    // the command refuses to run rather than run unguarded.
    #[test]
    fn an_unreadable_host_set_refuses_to_place_anything() {
        let err = enforcement_guard(&[], tfps::config::Loaded::Absent, None)
            .expect_err("no host addresses must not become no host guard");
        assert!(
            err.contains("fib_trie"),
            "the operator is told what failed: {err}"
        );
    }

    // A broken file and a malformed entry both abort, where the daemon alarms
    // and continues. This tool has one write to make and the alternative is
    // making it while an exemption the operator believes in is silently absent.
    #[test]
    fn a_broken_file_or_entry_aborts_rather_than_weakening_the_guard() {
        let host = Ipv4Addr::new(10, 0, 0, 60);
        assert!(enforcement_guard(
            &[host],
            tfps::config::Loaded::Broken("EOF while parsing".into()),
            None
        )
        .is_err());
        let cfg = tfps::config::Config {
            ignoreip: vec!["203.0.113.0/33".to_string()],
            ..Default::default()
        };
        assert!(enforcement_guard(
            &[host],
            tfps::config::Loaded::File(Box::new(cfg), PathBuf::new()),
            None,
        )
        .is_err());
    }

    #[test]
    fn the_command_comes_first_and_addresses_follow() {
        let a = args(&["unban", "1.2.3.4", "5.6.7.8"]).unwrap();
        assert_eq!(a.command, "unban");
        assert_eq!(a.positional, ["1.2.3.4", "5.6.7.8"]);
    }

    #[test]
    fn filters_parse() {
        let a = args(&[
            "pairs",
            "--peer",
            "10.0.0.5",
            "--country",
            "gb",
            "--limit",
            "5",
        ])
        .unwrap();
        assert_eq!(a.peer.as_deref(), Some("10.0.0.5"));
        assert_eq!(a.country.as_deref(), Some("gb"));
        assert_eq!(a.limit, 5);
    }

    #[test]
    fn an_option_with_no_value_is_an_error_not_a_default() {
        // Silently defaulting would make `--limit` at the end of a line mean something the
        // operator did not ask for.
        assert!(args(&["sources", "--limit"]).is_err());
        assert!(args(&["banned", "--bogus"]).is_err());
    }

    /// The consumer builds argv as [subcommand, "--json", ...], so the flag has to
    /// parse in that slot. The flat loop means every position works; this pins it.
    #[test]
    fn json_flag_defaults_off_and_parses_in_any_position() {
        assert!(!args(&["status"]).unwrap().json, "default must be off");
        assert!(args(&["status", "--json"]).unwrap().json);
        assert!(args(&["log", "--json", "--limit", "10"]).unwrap().json);
        assert!(args(&["log", "--limit", "10", "--json"]).unwrap().json);
    }

    /// --json must not swallow the next word the way --db does.
    #[test]
    fn json_flag_takes_no_value() {
        let a = args(&["log", "--json", "--limit", "7"]).unwrap();
        assert_eq!(a.limit, 7, "--json must not consume --limit");
    }

    #[test]
    fn durations_stay_narrow_enough_for_a_column() {
        assert_eq!(ago(0), "now");
        assert_eq!(ago(45), "45s");
        assert_eq!(ago(600), "10m");
        assert_eq!(ago(3700), "1h1m");
        assert_eq!(ago(200_000), "2d7h");
        assert!(ago(u32::MAX).len() <= 9);
    }

    /// The arithmetic `ban --json` uses to turn `--ttl` into an absolute
    /// expiry: genuinely new logic — the human path only ever prints a
    /// relative duration (`ago(args.ttl as u32)`), never an absolute time —
    /// so it is pinned directly with concrete values rather than only
    /// indirectly through `action_doc`.
    #[test]
    fn ban_expires_turns_a_ttl_into_an_absolute_epoch_or_none() {
        assert_eq!(
            ban_expires(1_756_800_000, 3600),
            Some(1_756_803_600),
            "an absolute expiry is now_wall + the ttl"
        );
        assert_eq!(
            ban_expires(1_756_800_000, 0),
            None,
            "ttl 0 means forever (see Blocklist::insert), which has no expiry"
        );
        assert_eq!(
            ban_expires(0, 1),
            Some(1),
            "a fixture now_wall of zero is still real arithmetic, not a special case"
        );
    }

    /// `--ttl` parses into a `u64` with no upper bound, so a ttl above
    /// `u32::MAX` reaches this function. `ttl_secs as u32` wraps there, and
    /// `saturating_add` cannot help afterwards because the value it is handed
    /// has already wrapped: `--ttl 4294967296` would report an expiry of *now*,
    /// i.e. a block that has already elapsed, for a ban that in the kernel lasts
    /// essentially forever.
    /// A rate that is not a finite number must say so as `null`, and the field
    /// must be TYPED nullable so the contract and the wire agree.
    ///
    /// `rate_a` is a `REAL NOT NULL` column and SQLite stores an infinity
    /// faithfully, so a non-finite value is reachable from the database. JSON
    /// has no way to spell one: `serde_json` renders it `null` regardless of
    /// what the field is declared as. Left as a bare `f64`, the document would
    /// promise a number and hand back `null` — a consumer deserialising into
    /// `f64` gets a parse error rather than a value, with nothing on stderr and
    /// exit 0. Making it `Option<f64>` changes no wire byte; it stops the type
    /// from lying about what can arrive.
    #[test]
    fn a_non_finite_rate_is_null_and_the_field_admits_it() {
        for bad in [f64::INFINITY, f64::NEG_INFINITY, f64::NAN] {
            let d = source_row_doc("203.0.113.9", 3, bad, 1756800000);
            assert_eq!(d.rate, None, "a non-finite rate is not a number: {bad}");
            assert_eq!(
                tfps::json_line(&d).unwrap(),
                r#"{"peer":"203.0.113.9","countries":3,"rate":null,"last_seen":1756800000}"#
            );
        }
        let ok = source_row_doc("203.0.113.9", 3, 1.5, 1756800000);
        assert_eq!(ok.rate, Some(1.5), "a finite rate is unchanged");
        assert_eq!(
            tfps::json_line(&ok).unwrap(),
            r#"{"peer":"203.0.113.9","countries":3,"rate":1.5,"last_seen":1756800000}"#,
            "the wire bytes for a finite rate must not move"
        );
        // `source` carries the same field and must answer the same way.
        let one = source_doc("203.0.113.9", 3, f64::INFINITY, 1756800000, &["GB"]);
        assert_eq!(one.rate, None);
        assert!(tfps::json_line(&one).unwrap().contains(r#""rate":null"#));
    }

    #[test]
    fn ban_expires_saturates_a_ttl_too_large_for_the_field() {
        assert_eq!(
            ban_expires(1_000, u64::from(u32::MAX) + 1),
            Some(u32::MAX),
            "a ttl one second past the field's range is far future, not now"
        );
        assert_eq!(
            ban_expires(1_000, u64::MAX),
            Some(u32::MAX),
            "and the largest ttl there is saturates too"
        );
        assert_eq!(
            ban_expires(1_000, u64::from(u32::MAX)),
            Some(u32::MAX),
            "the last ttl that fits still saturates on the add, not wraps"
        );
    }

    /// `action_doc`'s own tests are handed the refusal string already
    /// decided — they cannot catch a bug in the code that DECIDES it. This
    /// drives a real `Placed` through `place()` (the same way
    /// `a_kernel_failure_is_not_an_exemption` does, no live kernel needed)
    /// so the `Origin::Local => "local"` / `Origin::Declared => "declared"` /
    /// `failed => "kernel"` mapping in `ban_action_docs` is checked against
    /// concrete addresses. Swapping the two `Origin` arms, or folding
    /// `"kernel"` into `"local"`, must turn this red.
    #[test]
    fn ban_action_docs_maps_each_placed_outcome_to_its_own_refusal() {
        let host = Ipv4Addr::new(10, 0, 0, 60);
        let declared_ip = Ipv4Addr::new(203, 0, 113, 7);
        let blocked_ip = Ipv4Addr::new(198, 51, 100, 5);
        let failed_ip = Ipv4Addr::new(198, 51, 100, 6);
        let mut g = guard(&[host], &["203.0.113.0/24"]);
        let out = place(&[host, declared_ip, blocked_ip, failed_ip], &mut g, |ip| {
            if ip == failed_ip {
                Err("map is full".into())
            } else {
                Ok(())
            }
        });
        assert_eq!(
            out.blocked,
            vec![blocked_ip],
            "fixture sanity: one address blocks"
        );
        assert_eq!(
            out.exempt.len(),
            2,
            "fixture sanity: two addresses are exempt"
        );
        assert_eq!(out.failed, vec![(failed_ip, "map is full".to_string())]);

        let docs = ban_action_docs(&out, Some(1756921210), None);
        assert_eq!(
            docs.len(),
            4,
            "every input address gets exactly one document"
        );

        let blocked = &docs[0];
        assert_eq!(blocked.ip.as_deref(), Some("198.51.100.5"));
        assert!(blocked.applied);
        assert_eq!(blocked.refused, None);
        assert_eq!(
            blocked.expires,
            Some(1756921210),
            "an epoch integer, not an RFC3339 string"
        );

        let local = &docs[1];
        assert_eq!(
            local.ip.as_deref(),
            Some("10.0.0.60"),
            "this host's own address is the Origin::Local case"
        );
        assert!(!local.applied);
        assert_eq!(
            local.refused.as_deref(),
            Some("local"),
            "Origin::Local must render as \"local\", not \"declared\""
        );
        assert_eq!(local.expires, None, "a refusal has no expiry");

        let declared = &docs[2];
        assert_eq!(
            declared.ip.as_deref(),
            Some("203.0.113.7"),
            "the declared ignoreip range is the Origin::Declared case"
        );
        assert!(!declared.applied);
        assert_eq!(
            declared.refused.as_deref(),
            Some("declared"),
            "Origin::Declared must render as \"declared\", not \"local\""
        );
        assert_eq!(declared.expires, None);

        let failed = &docs[3];
        assert_eq!(failed.ip.as_deref(), Some("198.51.100.6"));
        assert!(!failed.applied);
        assert_eq!(
            failed.refused.as_deref(),
            Some("kernel"),
            "a kernel write failure must not be folded into a policy refusal"
        );
        assert_eq!(failed.expires, None);
    }

    #[test]
    fn output_goes_through_the_pipe_safe_macro() {
        // `tfps_ctl pairs | head` closes the pipe early. Rust ignores SIGPIPE, so a plain
        // `println!` panics there — this file must not contain one.
        // The needle is assembled at runtime, otherwise this test's own source would
        // contain the very thing it forbids and fail against itself.
        let needle = concat!("print", "ln!(");
        let src = include_str!("tfps_ctl.rs");
        // `eprintln!` ends in the same characters and is fine: stderr is not the piped
        // stream, and a diagnostic that cannot be written is not worth surviving for.
        let hits = src
            .match_indices(needle)
            .filter(|(i, _)| !src[..*i].ends_with(char::is_alphabetic))
            .count();
        assert_eq!(
            hits, 0,
            "use say!() instead of {needle}) so a closed pipe ends the run instead of panicking"
        );
    }

    #[test]
    fn forget_doc_names_the_peer_and_the_count() {
        assert_eq!(
            tfps::json_line(&forget_doc("203.0.113.9", 12)).unwrap(),
            r#"{"peer":"203.0.113.9","forgotten":12}"#
        );
    }

    #[test]
    fn a_source_row_is_one_object_per_line_with_no_count_line() {
        let d = source_row_doc("203.0.113.9", 12, 1.5, 1756800000);
        assert_eq!(
            tfps::json_line(&d).unwrap(),
            r#"{"peer":"203.0.113.9","countries":12,"rate":1.5,"last_seen":1756800000}"#
        );
    }

    /// `peers --json`'s row is the same shape minus `rate` — `peers`'s human
    /// path never prints a rate column, so there is none to carry.
    #[test]
    fn a_peer_row_has_no_rate_field() {
        let d = peer_row_doc("203.0.113.9", 7, 1756800000);
        assert_eq!(
            tfps::json_line(&d).unwrap(),
            r#"{"peer":"203.0.113.9","countries":7,"last_seen":1756800000}"#
        );
    }

    /// `source --json` answers about ONE peer with an object that also carries
    /// the full country list — the same list the human path already decodes
    /// to print its chunked lines, here as an array instead.
    #[test]
    fn a_source_doc_carries_the_full_country_list_as_an_array() {
        let d = source_doc("203.0.113.9", 3, 1.5, 1756800000, &["GB", "DE", "FR"]);
        assert_eq!(
            tfps::json_line(&d).unwrap(),
            r#"{"peer":"203.0.113.9","countries":3,"rate":1.5,"last_seen":1756800000,"countries_known":["GB","DE","FR"]}"#
        );
    }

    /// Pins that `SourceDoc.countries` is the caller's stored count, passed
    /// straight through, and never recomputed here as
    /// `countries_known.len()`. The two counts are equal by construction
    /// for a row written under the current country table (see `SourceDoc`'s
    /// doc comment for why they are not equal *by invariant*), so a test
    /// using equal values would pass whichever one `source_doc` actually
    /// used; deliberately mismatched values are what would catch a future
    /// edit that swapped `countries` for `countries_known.len()`.
    #[test]
    fn a_source_doc_countries_is_the_stored_count_not_the_decoded_length() {
        let d = source_doc("203.0.113.9", 5, 1.5, 1756800000, &["GB", "DE", "FR"]);
        assert_eq!(
            d.countries, 5,
            "must be the caller's stored count (5), not countries_known.len() (3)"
        );
    }

    /// The human view chunks countries to wrap a terminal. A program wants the
    /// list, so the array is the countries themselves and never a joined string.
    #[test]
    fn countries_are_an_array_not_the_wrapped_string() {
        let d = countries_doc("203.0.113.9", &["GB", "DE", "FR"]);
        assert_eq!(
            tfps::json_line(&d).unwrap(),
            r#"{"peer":"203.0.113.9","countries_known":["GB","DE","FR"]}"#
        );
    }

    #[test]
    fn a_peer_with_no_countries_is_an_empty_array_not_null() {
        let line = tfps::json_line(&countries_doc("203.0.113.9", &[])).unwrap();
        assert!(line.contains(r#""countries_known":[]"#), "{line}");
    }

    /// Every subcommand `usage()` advertises must accept --json AND its handler
    /// must actually branch on it. `parse()` sets `args.json` unconditionally for
    /// ANY command word — it never checks the word against `main()`'s dispatch
    /// table, so `assert!(a.json, ...)` on the parsed `Args` is true for a
    /// fictional command with no JSON rendering at all, just as it is for a real
    /// one. What the JSON contract actually requires is that the handler
    /// function honours the flag, so this reads each handler's own source (the
    /// same `include_str!` technique `output_goes_through_the_pipe_safe_macro`,
    /// above, already uses) and looks for an `args.json` branch there, instead
    /// of trusting the parser to have validated anything. `handler_body` is what
    /// makes "there" mean this handler and not the next one — see its own
    /// comment.
    #[test]
    fn every_advertised_subcommand_accepts_json() {
        let help = usage();
        let names: Vec<String> = help
            .lines()
            .skip_while(|l| !l.starts_with("USAGE:"))
            .take_while(|l| !l.starts_with("SOURCE FILTERS:"))
            .filter(|l| l.starts_with("  ") && !l.trim().is_empty())
            .filter_map(|l| l.split_whitespace().next().map(str::to_string))
            .filter(|w| w.chars().all(|c| c.is_ascii_lowercase()))
            .collect();
        assert_eq!(names.len(), 11, "expected 11 subcommands, got {names:?}");

        let src = include_str!("tfps_ctl.rs");
        for n in &names {
            assert!(
                handler_body(src, n).contains("args.json"),
                "`{n}`'s handler has no args.json branch — it accepts the flag but ignores it"
            );
        }
    }

    /// `report_ban_diagnostics` exists because `ban --json` once silently dropped
    /// the specific kernel-failure reason a caller needs to tell "map missing"
    /// from "permission denied" — collapsing both to the same
    /// `"refused":"kernel"` and printing nothing else. The fix was to call the
    /// same diagnostics function from both of `ban`'s branches; nothing but this
    /// test stops a future edit from quietly deleting one of those two calls and
    /// reintroducing exactly that regression, since `cargo test` would stay green
    /// either way otherwise.
    ///
    /// Two calls, one per branch, is the whole requirement, so counting them in
    /// `ban`'s own body says it directly. Which branch a surviving call sits in
    /// does not need finding: `ban` has exactly one `if args.json` block and one
    /// path past it, so a body holding two calls has one on each.
    #[test]
    fn ban_reports_diagnostics_in_both_json_and_plain_mode() {
        let src = include_str!("tfps_ctl.rs");
        let calls = handler_body(src, "ban")
            .matches("report_ban_diagnostics(")
            .count();
        assert_eq!(
            calls, 2,
            "`ban` must call report_ban_diagnostics from both its --json branch and its \
             plain path; {calls} call(s) found, so one mode is silently losing the \
             specific kernel-failure reason again"
        );
    }

    #[test]
    fn serve_flags_parse_and_belong_to_serve_only() {
        let a = args(&["serve", "--listen", "0.0.0.0:8080", "--allow-unban"]).expect("parses");
        assert_eq!(
            a.listen.map(|l| l.to_string()).as_deref(),
            Some("0.0.0.0:8080")
        );
        assert!(a.allow_unban);
        assert!(args(&["status", "--allow-unban"]).is_err());
        assert!(args(&["status", "--listen", "127.0.0.1:1"]).is_err());
        assert!(
            args(&["serve", "--listen", "[::1]:9060"]).is_err(),
            "IPv4 only"
        );
        assert!(args(&["serve", "--json"]).is_err());
    }

    #[test]
    fn serve_runs_only_when_enabled_and_the_command_line_wins() {
        let mut http = tfps::config::HttpConfig::default();
        assert_eq!(
            serve_settings(&http, None, true),
            None,
            "a flag does not turn it on"
        );
        http.enabled = true;
        let (listen, opts) = serve_settings(&http, None, false).expect("on");
        assert_eq!(listen.to_string(), "127.0.0.1:9060");
        assert!(
            !opts.allow_unban,
            "unban is a second switch, off by default"
        );
        let other = "0.0.0.0:8080".parse().unwrap();
        let (listen, opts) = serve_settings(&http, Some(other), true).expect("on");
        assert_eq!((listen, opts.allow_unban), (other, true));
        http.allow_unban = true;
        assert!(
            serve_settings(&http, None, false)
                .expect("on")
                .1
                .allow_unban
        );
    }

    #[test]
    fn serve_reads_the_database_the_daemon_writes() {
        let configured = Some(PathBuf::from("/srv/tfps/state.db"));
        let a = args(&["serve"]).expect("parses");
        assert_eq!(
            serve_ctx(&a, configured.clone(), None).db,
            Path::new("/srv/tfps/state.db")
        );
        assert_eq!(
            serve_ctx(&a, None, None).db,
            Path::new(tfps::store::DEFAULT_PATH),
            "no db in the file: the default"
        );
        let a = args(&["serve", "--db", "/tmp/x.db"]).expect("parses");
        assert_eq!(
            serve_ctx(&a, configured, None).db,
            Path::new("/tmp/x.db"),
            "the command line beats the file"
        );
    }

    #[test]
    fn serve_reads_the_map_the_daemon_enforces_through() {
        let pin = || Some(PathBuf::from("/sys/fs/bpf/shared_drop"));
        let a = args(&["serve"]).expect("parses");
        let c = serve_ctx(&a, None, pin());
        assert_eq!(
            (c.map, c.shared_map),
            (None, pin()),
            "drop_map is a shared map with the daemon's fallback, not an explicit pin"
        );
        let c = serve_ctx(&a, None, None);
        assert_eq!((c.map, c.shared_map), (None, None));
        let a = args(&["serve", "--map", "/sys/fs/bpf/other"]).expect("parses");
        let c = serve_ctx(&a, None, pin());
        assert_eq!(
            (c.map, c.shared_map),
            (Some(PathBuf::from("/sys/fs/bpf/other")), None),
            "the command line beats the file, and an explicit pin has no fallback"
        );
    }

    #[test]
    fn the_help_text_advertises_serve() {
        let u = usage();
        for w in ["serve", "--listen", "--allow-unban"] {
            assert!(u.contains(w), "{w}");
        }
    }

    #[test]
    fn the_help_text_advertises_the_flag() {
        assert!(
            usage().contains("--json"),
            "an undocumented flag is an unusable one"
        );
    }

    // ── manual bans and unbans leave a record ──────────────────────────────

    #[test]
    fn ban_takes_a_source_and_a_reason() {
        let a = args(&[
            "ban",
            "203.0.113.20",
            "--source",
            "sipnab",
            "--reason",
            "scanner seen by sipnab",
        ])
        .expect("parses");
        assert_eq!(a.source.as_deref(), Some("sipnab"));
        assert_eq!(a.reason.as_deref(), Some("scanner seen by sipnab"));
        let a = args(&["unban", "203.0.113.20", "--source", "sipnab"]).expect("parses");
        assert_eq!(a.source.as_deref(), Some("sipnab"));
    }

    #[test]
    fn a_bad_source_or_reason_is_refused_before_anything_runs() {
        for bad in [
            vec!["ban", "203.0.113.20", "--source", "has space"],
            vec!["ban", "203.0.113.20", "--reason", "two\nlines"],
            vec!["ban", "203.0.113.20", "--source"],
        ] {
            let Err(e) = args(&bad) else {
                panic!("{bad:?} must be refused");
            };
            assert!(
                e.contains("--source") || e.contains("--reason"),
                "{bad:?}: {e}"
            );
        }
    }

    #[test]
    fn source_and_reason_belong_to_ban_and_unban_only() {
        let Err(e) = args(&["banned", "--source", "sipnab"]) else {
            panic!("--source on banned must be refused");
        };
        assert!(e.contains("--source") && e.contains("ban"), "{e}");
        let Err(e) = args(&["status", "--reason", "why"]) else {
            panic!("--reason on status must be refused");
        };
        assert!(e.contains("--reason"), "{e}");
    }

    #[test]
    fn only_addresses_actually_blocked_are_recorded() {
        let out = Placed {
            blocked: vec![ip(1), ip(2)],
            exempt: vec![(
                ip(3),
                Exemption {
                    origin: Origin::Local,
                    rule: "203.0.113.3".to_string(),
                },
            )],
            failed: vec![(ip(4), "map full".to_string())],
        };
        let recs = manual_bans(&out, Some("sipnab"), Some("scan"), 1_000, 3600);
        let ips: Vec<Ipv4Addr> = recs.iter().map(|r| r.ip).collect();
        assert_eq!(ips, vec![ip(1), ip(2)]);
        assert!(recs
            .iter()
            .all(|r| r.source == "sipnab" && r.reason.as_deref() == Some("scan")));
        assert!(recs.iter().all(|r| r.expires == ban_expires(1_000, 3600)));
    }

    #[test]
    fn a_ban_with_no_source_is_the_operators() {
        let out = Placed {
            blocked: vec![ip(1)],
            exempt: vec![],
            failed: vec![],
        };
        let recs = manual_bans(&out, None, None, 1_000, 0);
        assert_eq!(recs[0].source, "operator");
        assert_eq!(recs[0].reason, None);
        assert_eq!(recs[0].expires, None, "a ban with no expiry records none");
    }

    #[test]
    fn banned_keeps_its_summary_wording() {
        let body = handler_body(include_str!("tfps_ctl.rs"), "banned");
        assert!(
            body.contains("perimeter/manual"),
            "the summary keeps its words"
        );
        assert!(
            !body.contains("manually, "),
            "manual bans count as perimeter/manual"
        );
    }

    #[test]
    fn ban_and_unban_write_the_record() {
        let src = include_str!("tfps_ctl.rs");
        assert!(
            handler_body(src, "ban").contains("record_manual("),
            "ban must record what it did"
        );
        // unban's record is written inside `ctl::unban_docs`, pinned by
        // `unban_docs_records_what_it_did` there; this pins that the command
        // goes through it rather than removing blocks itself.
        let unban = handler_body(src, "unban");
        assert!(unban.contains("unban_docs("), "{unban}");
        assert!(!unban.contains(".remove("), "{unban}");
    }

    #[test]
    fn banned_explains_a_manual_ban_in_both_renderings() {
        // The JSON rendering is `ctl::banned_docs`, which has its own check
        // (`banned_docs_consults_the_manual_record`).
        let body = handler_body(include_str!("tfps_ctl.rs"), "banned");
        assert!(body.contains("banned_docs("), "the JSON path: {body}");
        assert_eq!(
            body.matches("manual_attribution(").count(),
            1,
            "the human path must consult the manual record too"
        );
    }

    #[test]
    fn the_daemon_prunes_the_manual_record_on_the_audit_window() {
        let daemon = include_str!("../main.rs");
        assert!(
            daemon.contains("tfps::manual_log::prune("),
            "the daemon owns retention; without it the manual record grows forever"
        );
    }

    #[test]
    fn a_ban_reply_names_the_given_source_and_keeps_operator_otherwise() {
        let out = Placed {
            blocked: vec![ip(1)],
            exempt: vec![],
            failed: vec![],
        };
        let named = ban_action_docs(&out, None, Some("sipnab"));
        assert!(
            tfps::json_line(&named[0])
                .unwrap()
                .ends_with(r#""source":"sipnab"}"#),
            "the reply must not contradict the record"
        );
        let plain = ban_action_docs(&out, None, None);
        assert!(
            tfps::json_line(&plain[0])
                .unwrap()
                .ends_with(r#""source":"operator"}"#),
            "no --source: the reply is byte-for-byte what it was"
        );
    }

    #[test]
    fn both_unban_replies_name_the_given_source() {
        // Both the --all path and the single-address path are one call to
        // `ctl::unban_docs`, which names the source on every reply
        // (`unban_docs_names_the_source_on_every_reply`).
        let body = handler_body(include_str!("tfps_ctl.rs"), "unban");
        assert!(body.contains("args.source.as_deref()"), "{body}");
    }

    #[test]
    fn a_manual_ban_counts_as_perimeter_manual_in_the_summary() {
        assert_eq!(tally_of(true, false, false), Tally::PerimeterManual);
        assert_eq!(
            tally_of(true, true, true),
            Tally::PerimeterManual,
            "manual wins"
        );
        assert_eq!(tally_of(false, true, false), Tally::PerimeterManual);
        assert_eq!(tally_of(false, false, true), Tally::Apiban);
        assert_eq!(tally_of(false, false, false), Tally::Unattributed);
    }

    #[test]
    fn the_record_directory_comes_from_the_config_file_when_set() {
        let dir = std::env::temp_dir().join(format!("tfps-ctl-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let cfg = dir.join("config.json");
        std::fs::write(&cfg, r#"{"manual_log_dir": "/srv/tfps/manual"}"#).expect("write");
        let a = args(&[
            "banned",
            "--config",
            cfg.to_str().unwrap(),
            "--db",
            "/var/lib/tfps/tfps.db",
        ])
        .expect("parses");
        assert_eq!(
            tfps::ctl::manual_dir(&a.ctx()),
            std::path::Path::new("/srv/tfps/manual")
        );
        std::fs::write(&cfg, "{}").expect("write");
        assert_eq!(
            tfps::ctl::manual_dir(&a.ctx()),
            std::path::Path::new("/var/lib/tfps"),
            "default: beside the database"
        );
        std::fs::remove_dir_all(&dir).expect("clean up");
    }

    #[test]
    fn every_manual_record_access_goes_through_the_configured_directory() {
        // The record is read and written in `ctl`, which has its own check
        // (`the_record_is_reached_only_through_manual_dir`); this command must
        // not go around it.
        let src = include_str!("tfps_ctl.rs");
        let start = src.find("\nmod tests {").expect("tests module");
        let code = &src[..start];
        assert!(
            !code.contains("manual_log::append(") && !code.contains("manual_log::latest_for("),
            "the record is found through ctl's manual_dir, never straight from the database path"
        );
    }

    #[test]
    fn the_daemon_re_applies_manual_bans_only_when_configured_and_through_its_guard() {
        let daemon = include_str!("../main.rs");
        let at = daemon
            .find("if args.reapply_manual_bans")
            .expect("gated on the setting");
        let block = &daemon[at..at + daemon[at..].find("\n    }\n").expect("block ends")];
        assert!(block.contains("tfps::manual_log::reapply("), "{block}");
        assert!(
            block.contains("ignoreip.exempt("),
            "exemptions apply: {block}"
        );
        assert!(
            block.contains("is_known_peer("),
            "registered peers apply: {block}"
        );
    }
}
