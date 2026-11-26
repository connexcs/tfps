//! The read and unban logic behind `tfps_ctl`, as functions that return documents.
//!
//! `tfps_ctl` prints these documents through `say!`, which ends the process when
//! stdout goes away, so nothing in this module prints to stdout or exits. That is
//! what lets a caller other than the command line, such as an HTTP server, ask the
//! same questions and get the same answers: one implementation, two renderings.
//!
//! Every document here is exactly what the matching `tfps_ctl <command> --json`
//! prints, one per line. Their field order and null-not-zero rules are part of
//! that contract, and the tests below pin them.
//!
//! Sources of truth are the ones `tfps_ctl`'s own module comment describes: blocks
//! are read from, and lifted in, the kernel map; reasons and learned state come
//! from SQLite and the manual-action record beside it.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::store::{BlockRow, Store};
use crate::xdp::{monotonic_ns, Blocklist};

/// Where the state lives: the paths every command reads, without the rest of
/// the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ctx {
    /// The SQLite database (`--db`).
    pub db: PathBuf,
    /// An explicitly pinned block map (`--map`), or `None` for the usual lookup.
    pub map: Option<PathBuf>,
    /// The daemon's configured shared map (`drop_map`), used when `map` is `None`:
    /// tried first, and passed over for the usual lookup when it is absent or
    /// unusable, exactly as the daemon does at startup.
    pub shared_map: Option<PathBuf>,
    /// The configuration file (`--config`), read for `manual_log_dir`.
    pub config: PathBuf,
}

impl Default for Ctx {
    fn default() -> Self {
        Ctx {
            db: PathBuf::from(crate::store::DEFAULT_PATH),
            map: None,
            shared_map: None,
            config: PathBuf::from(crate::config::DEFAULT_PATH),
        }
    }
}

/// The addresses in a block map read, as the store's lookups take them.
pub fn map_addresses(entries: &[(Ipv4Addr, u64)]) -> std::collections::HashSet<String> {
    entries.iter().map(|(ip, _)| ip.to_string()).collect()
}

/// The audit log's answers per address, split the way attribution uses them:
/// `ip -> (reason, detail, first_seen)` for `banned_attribution`, and
/// `ip -> newest block time` for `manual_attribution`.
#[allow(clippy::type_complexity)]
pub fn audit_maps(
    summaries: std::collections::HashMap<String, crate::store::BlockSummary>,
) -> (
    std::collections::HashMap<String, (String, String, u32)>,
    std::collections::HashMap<String, u32>,
) {
    let mut audit = std::collections::HashMap::with_capacity(summaries.len());
    let mut newest = std::collections::HashMap::with_capacity(summaries.len());
    for (ip, s) in summaries {
        newest.insert(ip.clone(), s.newest);
        audit.insert(ip, (s.reason, s.detail, s.first_seen));
    }
    (audit, newest)
}

/// The block map `ctx` names: an explicit pin as given, else the configured
/// shared map with the daemon's fallback, else the usual lookup.
fn open_blocklist(ctx: &Ctx) -> Result<Blocklist, String> {
    match (&ctx.map, &ctx.shared_map) {
        (Some(pin), _) => Blocklist::open(Some(pin)),
        (None, Some(shared)) => Blocklist::open_preferring(shared),
        (None, None) => Blocklist::open(None),
    }
}

// ---------------------------------------------------------------- commands

/// `status --json`: what is enforcing, how much is blocked, how fresh the
/// learned state is.
///
/// Never fails: a map that will not open reads as `"inactive"`, and an
/// unreadable database nulls the learned totals, as `StatusDoc` describes.
pub fn status_docs(ctx: &Ctx) -> StatusDoc {
    let blocked = open_blocklist(ctx).map(|b| (b.entries().len(), b.source));
    let totals = Store::open_readonly(&ctx.db).and_then(|s| s.totals()).ok();
    status_doc(blocked, totals, &ctx.db, env!("CARGO_PKG_VERSION"))
}

/// `stats --json`: every counter, as one document.
///
/// Fails when the database cannot be opened or its totals cannot be read: a
/// reader is better served by no document than by one with invented totals.
/// The kernel counters and the condemnation summary are `null` rather than an
/// error when their maps cannot be read, as `StatsDoc` describes.
pub fn stats_docs(ctx: &Ctx) -> Result<StatsDoc, String> {
    let kernel = crate::xdp::live_counters()
        .ok()
        .map(|c| (c.seen, c.dropped, c.expired));
    let s = Store::open_readonly(&ctx.db)?;
    // `null`, not `(0, 0, 0)`, when the blocklist map cannot be opened —
    // the same reason `kernel` above is `None` rather than zeroed: a
    // consumer reading `condemned_now: 0` off a box whose map could not
    // even be opened would conclude nothing is blocked, the exact wrong
    // reading this null is here to prevent. The audit log and the feed are
    // asked only about the addresses in the map.
    let condemnation = open_blocklist(ctx).ok().map(|b| {
        let entries = b.entries();
        let among = map_addresses(&entries);
        let audit = s.logged_among(&among).unwrap_or_default();
        let apiban = s.apiban_among(&among).unwrap_or_default();
        condemnation_counts(&entries, &audit, &apiban)
    });
    let now = now();
    let stats_line = s.meta_get("stats");
    let stats_ts = s.meta_get("stats_ts").and_then(|t| t.parse::<u32>().ok());
    let traffic = traffic_doc(stats_line.as_deref(), stats_ts, now);
    let running_for_secs = s
        .meta_get("started_at")
        .and_then(|v| v.parse::<u32>().ok())
        .map(|t| now.saturating_sub(t));
    let ignoreip = ignoreip_doc(s.meta_get("ignoreip").as_deref());
    let calibration = calibration_doc(s.meta_get("calibration").as_deref());
    // `?` here, not `unwrap_or_default`: the human path propagates these two
    // the same way, and a JSON reader is better served by no document and a
    // non-zero exit than by a document with invented totals.
    let (pairs, peers, _) = s.totals()?;
    let (countries, intl_calls) = s.country_spread()?;
    let window = |since: u32| s.blocks_by_reason(now.saturating_sub(since));
    let blocks = blocks_doc(
        s.apiban_count().unwrap_or(0),
        window(3600)?,
        window(86_400)?,
        window(604_800)?,
    );
    Ok(stats_doc(
        kernel,
        condemnation,
        traffic,
        running_for_secs,
        ignoreip,
        calibration,
        learned_doc(pairs, peers, countries, intl_calls),
        blocks,
    ))
}

/// `banned --why --json`: every condemned source, with its reason, its
/// attribution and its expiry, in the kernel map's order.
///
/// Fails only when the block map cannot be opened. An unreadable database or
/// manual record leaves rows unattributed rather than failing the listing:
/// the blocks themselves are still the kernel's to report.
pub fn banned_docs(ctx: &Ctx) -> Result<Vec<BannedDoc>, String> {
    let b = open_blocklist(ctx)?;
    let entries = b.entries();
    // Both sets are loaded for the same reason the human path loads both: an
    // address on the feed alone is attributable, and reading only the audit
    // log reports it as unattributed.
    // The audit log and the feed are asked only about what the map holds.
    let store = Store::open_readonly(&ctx.db).ok();
    let among = map_addresses(&entries);
    let (audit, newest) = audit_maps(
        store
            .as_ref()
            .and_then(|s| s.block_summaries(&among).ok())
            .unwrap_or_default(),
    );
    let wanted: std::collections::HashSet<Ipv4Addr> = entries.iter().map(|(ip, _)| *ip).collect();
    let manual = manual_record(ctx, &wanted);
    let apiban = store
        .as_ref()
        .and_then(|s| s.apiban_among(&among).ok())
        .unwrap_or_default();
    let now_wall = now();
    let now_mono = monotonic_ns();
    let mut docs = Vec::with_capacity(entries.len());
    for (ip, until) in &entries {
        let ip_s = ip.to_string();
        let (why, first_seen) = banned_attribution(&ip_s, &audit, &apiban);
        let expires = expires_epoch(*until, now_wall, now_mono);
        let doc = match manual_attribution(*ip, &manual, newest.get(&ip_s).copied()) {
            Some((reason, detail, source)) => {
                banned_doc(&ip_s, Some((&reason, &detail)), first_seen, expires)
                    .with_source(Some(&source))
            }
            None => banned_doc(&ip_s, why, first_seen, expires),
        };
        docs.push(doc);
    }
    Ok(docs)
}

/// `log --json`: the block audit log, newest first, at most `limit` rows,
/// optionally for one address.
pub fn log_docs(ctx: &Ctx, limit: usize, ip: Option<&str>) -> Result<Vec<LogDoc>, String> {
    let s = Store::open_readonly(&ctx.db)?;
    let rows: Vec<BlockRow> = s.blocks(limit, ip)?;
    // Every row in block_log got there through `log_block`, which main.rs
    // calls only from the `Disposition::Block` arm — so every row here is an
    // enforced block: `enforced` and `disposition` are constant, the latter
    // `CONTEXT.md`'s `block`. `expires`/`unbanned_at` are not columns
    // block_log has yet (see its schema in store.rs); they are `null` until a
    // future store change adds them, which needs no change to this
    // document's shape.
    Ok(rows
        .iter()
        .map(|r| log_doc(r, None, None, true, "block"))
        .collect())
}

/// `(blocked now, of which permanent)`, counted from the block map alone. For
/// `/metrics`: the map is the state of the system, and counting it reads no
/// database and moves no address anywhere.
pub fn map_counts(ctx: &Ctx) -> Result<(usize, usize), String> {
    let entries = open_blocklist(ctx)?.entries();
    let permanent = entries.iter().filter(|(_, until)| *until == 0).count();
    Ok((entries.len(), permanent))
}

/// Which blocks `unban_docs` lifts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnbanTarget<'a> {
    /// Everything the block map holds at the moment it is read.
    All,
    /// These addresses, as given. Every one is parsed before any is removed.
    Addresses(&'a [String]),
}

/// `unban --json`: lift blocks, record each one actually lifted in the
/// manual-action record, and say what happened to each address.
///
/// One `ActionDoc` per address, in order: `applied` when it was removed,
/// `refused: "not-blocked"` when it was not there. `source` names who asked
/// and defaults to `operator`, as on the command line.
///
/// **All addresses are parsed before any block is touched**, so a typo in the
/// list lifts nothing rather than lifting the addresses before it. And
/// whatever was removed is recorded even when a later kernel write fails, so
/// the record never misses an unban that took effect.
///
/// `source` and `reason` are held to the same rules as `--source` and
/// `--reason` (`manual_log::check_source` / `check_reason`), here and not only
/// in the CLI's parser, because they are written to the manual-action record
/// and a caller other than the command line reaches this function directly.
///
/// `Err` means nothing was touched: bad input, or a map that will not open.
/// A kernel failure part-way through is not an `Err`: it is
/// `UnbanOutcome::failed`, beside the documents for the addresses handled
/// before it, so a caller can still say which blocks were lifted.
pub fn unban_docs(
    ctx: &Ctx,
    target: UnbanTarget<'_>,
    source: Option<&str>,
    reason: Option<&str>,
) -> Result<UnbanOutcome, String> {
    if let Some(s) = source {
        crate::manual_log::check_source(s)?;
    }
    if let Some(r) = reason {
        crate::manual_log::check_reason(r)?;
    }
    let ips: Option<Vec<Ipv4Addr>> = match target {
        UnbanTarget::All => None,
        UnbanTarget::Addresses([]) => return Err("give at least one address, or --all".into()),
        UnbanTarget::Addresses(raw) => Some(parse_addresses(raw)?),
    };
    let mut b = open_blocklist(ctx)?;
    // A listing taken moments earlier is not a guarantee about now, so `--all`
    // reports what `remove` says was actually there, like the address form.
    let ips = ips.unwrap_or_else(|| b.entries().into_iter().map(|(ip, _)| ip).collect());
    let (removed, failed) = remove_each(&ips, |ip| b.remove(ip));
    record_manual(ctx, &manual_unbans(&removed, source, reason, now()));
    let docs = removed
        .iter()
        .map(|(ip, was_removed)| {
            let refused = if *was_removed {
                None
            } else {
                Some("not-blocked")
            };
            action_doc(Some(&ip.to_string()), "unban", refused, None).with_source(source)
        })
        .collect();
    Ok(UnbanOutcome { docs, failed })
}

/// What `unban_docs` did once it reached the map.
#[derive(Debug)]
pub struct UnbanOutcome {
    /// One per address handled, in order, up to any failure.
    pub docs: Vec<ActionDoc>,
    /// The kernel error that stopped it part-way, if one did. The addresses
    /// after it were not attempted.
    pub failed: Option<String>,
}

/// Every address in `raw`, or the first one that will not parse, named.
fn parse_addresses(raw: &[String]) -> Result<Vec<Ipv4Addr>, String> {
    raw.iter()
        .map(|r| r.parse().map_err(|e| format!("{r}: {e}")))
        .collect()
}

/// Calls `remove` for each address in order, stopping at the first error.
///
/// Returns what was attempted before the error, each with whether it was
/// there, and the error. The caller records the first half whether or not
/// there is a second: those removals have already happened.
fn remove_each(
    ips: &[Ipv4Addr],
    mut remove: impl FnMut(Ipv4Addr) -> Result<bool, String>,
) -> (Vec<(Ipv4Addr, bool)>, Option<String>) {
    let mut done = Vec::with_capacity(ips.len());
    for &ip in ips {
        match remove(ip) {
            Ok(was) => done.push((ip, was)),
            Err(e) => return (done, Some(e)),
        }
    }
    (done, None)
}

// ---------------------------------------------------------------- documents and helpers

/// What `status` tells a program.
///
/// `tfps_ctl`'s module comment says `status` exists so that nobody "draws
/// conclusions from stale rows", which is why the learned-state totals and the
/// checkpoint time are here and not only in the human view: a `--json` consumer
/// without them has exactly the blindness the command was written to prevent.
///
/// `map` is `Blocklist::source` — which of the three planes was opened: an
/// explicit pin, a third party's shared pin, or the daemon's own map by name.
/// The human path prints it as `enforcement :`; a program needs it to tell the
/// daemon's own enforcement from somebody else's map, and it is free at the
/// call site.
///
/// `pairs`/`peers`/`last_checkpoint` are `null`, never zeroed, when the
/// database cannot be read — the same null-not-zero rule `stats --json`'s
/// `kernel` and `condemnation` blocks follow, and for the same reason. Zero
/// pairs is an idle box; an unreadable database is a broken one.
/// `last_checkpoint` is an epoch second, and `null` when nothing has been
/// checkpointed yet: `Store::totals` coalesces that case to 0, which as a time
/// would read as 1970.
///
/// `mode` and `interface` stay `None`, and the nullability is not a
/// placeholder: this tool opens the blocklist **map**, not the XDP
/// **program**, so the attach mode and interface are not visible to it. Only
/// the daemon knows them, at attach time. Recording them is a daemon change,
/// and this is an output-formatting change.
#[derive(Serialize)]
pub struct StatusDoc {
    pub enforcement: &'static str,
    pub mode: Option<String>,
    pub interface: Option<String>,
    pub map: Option<String>,
    pub blocked_now: usize,
    pub pairs: Option<u32>,
    pub peers: Option<u32>,
    pub last_checkpoint: Option<u32>,
    pub db: String,
    pub version: String,
}

/// Built from arguments so it is drivable from a test: the real caller opens a
/// BPF map, which needs `CAP_BPF`, and a database.
///
/// `blocked` carries the map's own name alongside its entry count because the
/// two come from the same successful open — binding them in one `Result` is
/// what stops `enforcement: "inactive"` from ever appearing beside a named
/// `map`. `totals` is `Store::totals`'s `(pairs, peers, newest)`, or `None`
/// when the database could not be read.
pub fn status_doc(
    blocked: Result<(usize, String), String>,
    totals: Option<(u32, u32, u32)>,
    db: &Path,
    version: &str,
) -> StatusDoc {
    let (enforcement, blocked_now, map) = match blocked {
        Ok((n, source)) => ("active", n, Some(source)),
        Err(_) => ("inactive", 0, None),
    };
    StatusDoc {
        enforcement,
        mode: None,
        interface: None,
        map,
        blocked_now,
        pairs: totals.map(|(pairs, _, _)| pairs),
        peers: totals.map(|(_, peers, _)| peers),
        last_checkpoint: totals.and_then(|(_, _, newest)| (newest > 0).then_some(newest)),
        db: db.display().to_string(),
        version: version.to_string(),
    }
}

/// The live KERNEL block of `stats --json`, or absent entirely when the
/// counters cannot be read — see `StatsDoc`'s doc comment.
#[derive(Serialize)]
pub struct KernelDoc {
    pub seen: u64,
    pub dropped: u64,
    pub expired: u64,
}

/// The TRAFFIC block of `stats --json`: the last checkpoint's counters,
/// straight from the `stats` meta line the human TRAFFIC block already
/// parses, as a map instead of two print columns — a program has no use for
/// column alignment. `age_secs` is the raw interval, not `ago()`'s
/// formatted string: a consumer recomputes its own presentation, the same
/// reasoning that keeps `log_doc`'s times as epoch integers rather than
/// strings.
///
/// The counters are integers for the same reason. They are `u64` counts in the
/// daemon (`main.rs`'s `counter_line` writes `engine::Stats`, every field a
/// `u64`), and rendering them as strings put `"udp":"120"` in the same document
/// as `"seen":120` — the same kind of number, two types, so a consumer would
/// have to know which command produced a field before it could add it up.
///
/// A value that does not parse is `null`, not dropped and not zero: the key
/// still tells a consumer the daemon reported that counter, and dropping it
/// would leave "the daemon never wrote this" and "this line is corrupt"
/// indistinguishable.
#[derive(Serialize)]
pub struct TrafficDoc {
    pub age_secs: Option<u32>,
    pub counters: std::collections::BTreeMap<String, Option<u64>>,
}

/// The condemnation-summary block of `stats --json`: of everything
/// currently condemned in the kernel, how many trace back to the
/// perimeter/manual audit log versus appear only because they are also on
/// the APIBAN feed. Absent entirely when `Blocklist::open` fails — see
/// `StatsDoc`'s doc comment.
#[derive(Serialize)]
pub struct CondemnationDoc {
    pub condemned_now: usize,
    pub perimeter_manual: usize,
    pub apiban_feed_only: usize,
}

/// What `stats --json` says: the live KERNEL block, the condemnation
/// summary, and the checkpointed TRAFFIC block, as one document instead of
/// three.
///
/// The rest of what the human path prints follows them: `running_for_secs`,
/// `ignoreip`, `calibration`, `learned` and `blocks`. `stats --json` is the
/// whole of `stats`, so nobody has to fall back to parsing the columns for the
/// half a program could not otherwise reach.
///
/// The first three are `null`, never zeroed, when their source cannot be read:
/// `kernel` when the counters are unreachable, `condemnation` when
/// `Blocklist::open` fails (a *different* kernel map from the one `kernel`
/// reads — see `xdp::Blocklist::open` vs `xdp::live_counters`, either can
/// fail independently of the other), `traffic` before the first checkpoint
/// exists. A tool that could not read a counter and a counter that
/// genuinely reads zero are different facts; conflating them would report
/// "nothing was dropped", or "nothing is blocked", about a box whose
/// enforcement has failed or whose map this tool simply could not open.
#[derive(Serialize)]
pub struct StatsDoc {
    pub kernel: Option<KernelDoc>,
    pub condemnation: Option<CondemnationDoc>,
    pub traffic: Option<TrafficDoc>,
    /// Seconds since the daemon started, from `meta.started_at`; `null` when it
    /// has not written one yet.
    pub running_for_secs: Option<u32>,
    /// `label -> hit count` for the exempt entries. `null` for a count that
    /// will not parse, so a corrupt line is distinguishable from an absent one.
    pub ignoreip: Option<std::collections::BTreeMap<String, Option<u64>>>,
    /// The benign hypotheses the engine has learned. Values are floats and
    /// share `rate`'s non-finite rule.
    pub calibration: Option<std::collections::BTreeMap<String, Option<f64>>>,
    pub learned: LearnedDoc,
    pub blocks: BlocksDoc,
}

/// The four totals the human `LEARNED` block prints.
///
/// `pairs` and `peers` come from `Store::totals`, which counts the same column
/// twice — they are always equal today. Both are carried because both are what
/// the human view shows; if that query is ever split, these fields start
/// carrying two different numbers without a contract change.
#[derive(Serialize)]
pub struct LearnedDoc {
    pub pairs: u32,
    pub peers: u32,
    pub countries: u32,
    pub intl_calls: u32,
}

/// One block-counting window: the total, and the split by reason behind it.
#[derive(Serialize)]
pub struct WindowDoc {
    pub total: u32,
    pub by_reason: std::collections::BTreeMap<String, u32>,
}

/// What the human `BLOCKS BY REASON` block prints. The APIBAN feed is counted
/// apart from the windows because it is permanent and never audit-logged.
#[derive(Serialize)]
pub struct BlocksDoc {
    pub apiban_feed: usize,
    pub last_hour: WindowDoc,
    pub last_day: WindowDoc,
    pub last_week: WindowDoc,
}

pub fn learned_doc(pairs: u32, peers: u32, countries: u32, intl_calls: u32) -> LearnedDoc {
    LearnedDoc {
        pairs,
        peers,
        countries,
        intl_calls,
    }
}

pub fn window_doc(rows: Vec<(String, u32)>) -> WindowDoc {
    WindowDoc {
        total: rows.iter().map(|(_, n)| n).sum(),
        by_reason: rows.into_iter().collect(),
    }
}

pub fn blocks_doc(
    apiban_feed: usize,
    hour: Vec<(String, u32)>,
    day: Vec<(String, u32)>,
    week: Vec<(String, u32)>,
) -> BlocksDoc {
    BlocksDoc {
        apiban_feed,
        last_hour: window_doc(hour),
        last_day: window_doc(day),
        last_week: window_doc(week),
    }
}

/// `label=hits` pairs, split from the right because the label is operator text.
/// A count that will not parse is `null`, never dropped.
pub fn ignoreip_doc(line: Option<&str>) -> Option<std::collections::BTreeMap<String, Option<u64>>> {
    let line = line.filter(|l| !l.trim().is_empty())?;
    Some(
        line.split_whitespace()
            .filter_map(|e| e.rsplit_once('='))
            .map(|(label, hits)| (label.to_string(), hits.parse::<u64>().ok()))
            .collect(),
    )
}

/// `key=value` pairs whose values are floats, through the same `finite()` rule
/// `rate` uses — `"inf".parse::<f64>()` succeeds, and an infinity is not a
/// number a reader can use.
pub fn calibration_doc(
    line: Option<&str>,
) -> Option<std::collections::BTreeMap<String, Option<f64>>> {
    let line = line.filter(|l| !l.trim().is_empty())?;
    Some(
        line.split_whitespace()
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_string(), v.parse::<f64>().ok().and_then(finite)))
            .collect(),
    )
}

/// Built from already-computed values, the same way `status_doc` is: no
/// transformation happens here beyond wrapping. The nontrivial pieces —
/// `condemnation_counts`'s perimeter/feed split and `traffic_doc`'s
/// checkpoint parsing — are computed and tested on their own.
#[allow(clippy::too_many_arguments)]
pub fn stats_doc(
    kernel: Option<(u64, u64, u64)>,
    condemnation: Option<(usize, usize, usize)>,
    traffic: Option<TrafficDoc>,
    running_for_secs: Option<u32>,
    ignoreip: Option<std::collections::BTreeMap<String, Option<u64>>>,
    calibration: Option<std::collections::BTreeMap<String, Option<f64>>>,
    learned: LearnedDoc,
    blocks: BlocksDoc,
) -> StatsDoc {
    StatsDoc {
        kernel: kernel.map(|(seen, dropped, expired)| KernelDoc {
            seen,
            dropped,
            expired,
        }),
        condemnation: condemnation.map(|(condemned_now, perimeter_manual, apiban_feed_only)| {
            CondemnationDoc {
                condemned_now,
                perimeter_manual,
                apiban_feed_only,
            }
        }),
        traffic,
        running_for_secs,
        ignoreip,
        calibration,
        learned,
        blocks,
    }
}

/// The perimeter/feed split inside one already-open blocklist read: how many
/// of `entries` trace back to the perimeter/manual audit log versus appear
/// only because they are also on the APIBAN feed. Mirrors the
/// `perimeter`/`feed` split `tfps_ctl stats`'s human path computes inline, pulled out
/// so it is drivable with concrete addresses instead of a live kernel map
/// and database. Whether the blocklist could be opened at all — the
/// `Option` `stats` wraps this in for `stats_doc` — is decided by the
/// caller, not here: this function only ever runs once a read has already
/// succeeded.
pub fn condemnation_counts(
    entries: &[(Ipv4Addr, u64)],
    audit: &std::collections::HashSet<String>,
    apiban: &std::collections::HashSet<String>,
) -> (usize, usize, usize) {
    let perimeter = entries
        .iter()
        .filter(|(ip, _)| audit.contains(&ip.to_string()))
        .count();
    let feed = entries
        .iter()
        .filter(|(ip, _)| !audit.contains(&ip.to_string()) && apiban.contains(&ip.to_string()))
        .count();
    (entries.len(), perimeter, feed)
}

/// Parses the checkpoint's `stats` meta line into `stats --json`'s TRAFFIC
/// block. `None` when there is no checkpoint yet — the human path's "no
/// checkpoint yet" case — not an empty map, because the daemon has produced
/// no numbers at all yet, a different fact from zero of them.
pub fn traffic_doc(line: Option<&str>, ts: Option<u32>, now: u32) -> Option<TrafficDoc> {
    let line = line?;
    let counters = line
        .split_whitespace()
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.parse::<u64>().ok()))
        .collect();
    Some(TrafficDoc {
        age_secs: ts.map(|t| now.saturating_sub(t)),
        counters,
    })
}

/// What `banned --json` says about one currently-condemned source.
///
/// `first_seen`/`expires` are epoch seconds, the same as every other time in
/// this contract (`log_doc`, `expires_epoch`, `traffic_doc`'s `age_secs`, the
/// row documents' `last_seen`). A consumer recomputes its own presentation; a
/// document that rendered one command's times as integers and another's as
/// formatted strings would make it guess which it had been handed.
///
/// `first_seen` is the time of the oldest audit row for the address the log
/// still holds, and `reason`/`detail` come from its newest row
/// (`Store::block_summaries`, asked only about the addresses in the block map).
#[derive(Serialize)]
pub struct BannedDoc {
    pub ip: String,
    pub reason: Option<String>,
    pub detail: Option<String>,
    /// Who placed a manual ban (`--source`, or `operator`). Present only on a
    /// manually placed row, so every other row keeps its exact bytes and a
    /// consumer that pins them sees no change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub first_seen: Option<u32>,
    pub expires: Option<u32>,
    pub enforced: bool,
}

/// Built from arguments so it is drivable from a test: the real caller needs
/// `CAP_BPF` to open the kernel map and a database file to attribute a reason.
/// `enforced` is always `true` — every row this feeds comes from the kernel's
/// own blocklist (`Blocklist::entries`), which by construction lists only what
/// is presently enforced. `first_seen`/`expires` arrive already as epoch
/// seconds (or `None`) and are carried through unchanged.
pub fn banned_doc(
    ip: &str,
    why: Option<(&str, &str)>,
    first_seen: Option<u32>,
    expires: Option<u32>,
) -> BannedDoc {
    let (reason, detail) = match why {
        Some((reason, detail)) => (Some(reason.to_string()), Some(detail.to_string())),
        None => (None, None),
    };
    BannedDoc {
        ip: ip.to_string(),
        reason,
        detail,
        source: None,
        first_seen,
        expires,
        enforced: true,
    }
}

impl BannedDoc {
    /// The same row, naming who placed it when it was placed manually.
    pub fn with_source(mut self, source: Option<&str>) -> Self {
        self.source = source.map(str::to_string);
        self
    }
}

/// Who placed a block manually and why, when the latest manual action for `ip`
/// is a ban and no daemon block of it is newer.
///
/// Returns `("manual", detail, source)`. A daemon block newer than the manual ban
/// is the better explanation of why the address is blocked now, so it wins,
/// the same "most recent reason wins" rule `--why` applies to the audit log.
pub fn manual_attribution(
    ip: Ipv4Addr,
    latest: &std::collections::HashMap<Ipv4Addr, crate::manual_log::ManualAction>,
    newest_audit_ts: Option<u32>,
) -> Option<(String, String, String)> {
    let a = latest.get(&ip)?;
    if a.verb != crate::manual_log::ManualVerb::Ban {
        return None;
    }
    if newest_audit_ts.is_some_and(|ts| ts > a.ts) {
        return None;
    }
    let detail = a
        .reason
        .clone()
        .unwrap_or_else(|| "no reason given".to_string());
    Some(("manual".to_string(), detail, a.source.clone()))
}

/// The manual-unban records for addresses `unban` actually removed.
pub fn manual_unbans(
    removed: &[(Ipv4Addr, bool)],
    source: Option<&str>,
    reason: Option<&str>,
    now_wall: u32,
) -> Vec<crate::manual_log::ManualAction> {
    removed
        .iter()
        .filter(|(_, was)| *was)
        .map(|(ip, _)| crate::manual_log::ManualAction {
            ts: now_wall,
            verb: crate::manual_log::ManualVerb::Unban,
            ip: *ip,
            source: source.unwrap_or("operator").to_string(),
            reason: reason.map(str::to_string),
            expires: None,
        })
        .collect()
}

/// The latest manual action for each address in `wanted`, read from beside the
/// database.
///
/// Lines that cannot be read are reported on stderr and skipped, so an
/// operator knows the record is incomplete.
pub fn manual_record(
    ctx: &Ctx,
    wanted: &std::collections::HashSet<Ipv4Addr>,
) -> std::collections::HashMap<Ipv4Addr, crate::manual_log::ManualAction> {
    let found = crate::manual_log::latest_for(&manual_dir(ctx), wanted);
    if found.unreadable > 0 {
        eprintln!(
            "WARNING: {} line(s) of the manual-action record could not be read",
            found.unreadable
        );
    }
    found.by_ip
}

/// The record directory: `manual_log_dir` from the configuration file, else the
/// database's directory; the same rule the daemon uses.
pub fn manual_dir(ctx: &Ctx) -> std::path::PathBuf {
    let configured = match crate::config::load(&ctx.config) {
        crate::config::Loaded::File(c, _) => c.manual_log_dir,
        _ => None,
    };
    crate::manual_log::resolve_dir(configured.as_deref(), &ctx.db)
}

/// Write `actions` to the record, and say so on stderr when that fails.
///
/// The ban or unban has already happened by the time this runs, so a failed
/// write cannot undo it. Saying so on stderr is the most useful thing left to
/// do: the operator hears about it.
pub fn record_manual(ctx: &Ctx, actions: &[crate::manual_log::ManualAction]) {
    if actions.is_empty() {
        return;
    }
    let mode = crate::manual_log::mode_of(&ctx.db);
    if let Err(e) = crate::manual_log::append(&manual_dir(ctx), actions, mode) {
        eprintln!(
            "WARNING: {} manual action(s) took effect but were not recorded: {e}",
            actions.len()
        );
    }
}

/// Turns a kernel blocklist expiry into wall-clock epoch seconds, or `None`
/// for "never expires".
///
/// `until` is `CLOCK_MONOTONIC` nanoseconds (see `Blocklist::insert`), not
/// wall-clock time, so it is not an epoch second and cannot be reported as one.
/// Correlating it against a `(now_wall, now_mono)` pair read together turns the
/// monotonic delta into an absolute epoch second — the same trick the human
/// path uses on the same `until` value to produce a countdown instead of an
/// absolute time. `saturating_sub` means an entry whose monotonic deadline
/// has already passed (the kernel would normally have dropped it by the
/// time `entries()` is read) reports zero seconds left rather than
/// underflowing.
pub fn expires_epoch(until: u64, now_wall: u32, now_mono: u64) -> Option<u32> {
    if until == 0 {
        return None;
    }
    let secs_left = until.saturating_sub(now_mono) / 1_000_000_000;
    // `until` is a raw `u64` from a BPF map — ours, or a third party's under
    // `--map`. A delta past `u32::MAX` seconds wraps under `as u32` into a
    // plausible-looking near-future expiry, which is worse than an obviously
    // saturated one.
    Some(now_wall.saturating_add(u32::try_from(secs_left).unwrap_or(u32::MAX)))
}

/// The attribution `banned` applies to one condemned address, in the same
/// precedence `tfps_ctl banned`'s human path already prints: the audit log's own reason
/// wins, then the APIBAN feed, then nothing.
///
/// A perimeter block often lands on an address the feed also carries, and the
/// reason we condemned it is the perimeter one — the same "block_log reason
/// wins" ordering `condemnation_counts` applies to the same two sets. The feed
/// case renders as `("apiban", "feed")`, the human line's own two words split
/// at the seam its `{reason} ({detail})` format already puts between them;
/// without it, "blocked by the feed" and "not in this audit log" reach a
/// consumer as the same two nulls.
///
/// `first_seen` comes from the audit row and only from it. The feed carries no
/// per-address time, and there is nothing to substitute: the kernel entry's
/// expiry is a different fact and would be a lie under this name.
pub fn banned_attribution<'a>(
    ip: &str,
    audit: &'a std::collections::HashMap<String, (String, String, u32)>,
    apiban: &std::collections::HashSet<String>,
) -> (Option<(&'a str, &'a str)>, Option<u32>) {
    match audit.get(ip) {
        Some((reason, detail, ts)) => (Some((reason.as_str(), detail.as_str())), Some(*ts)),
        None if apiban.contains(ip) => (Some(("apiban", "feed")), None),
        None => (None, None),
    }
}

/// What `ban --json` and `unban --json` each say about one address.
///
/// `applied` is derived from `refused.is_none()` in `action_doc`, never set
/// independently, so the two facts cannot disagree — see
/// `applied_is_exactly_the_absence_of_a_refusal`. A policy refusal
/// (`"local"`, `"declared"`, `"not-blocked"`) and a kernel write failure
/// (`"kernel"`) are deliberately different strings: the first means the
/// system worked as designed, the second means enforcement itself is
/// broken, and one term for both would report "refused as configured" about
/// a box that is not blocking anything — see
/// `a_kernel_failure_is_reported_separately_from_a_policy_refusal`. `ip` is
/// never `null` in this build: both commands parse addresses with `?`
/// before any per-address work, so an unparseable address aborts the whole
/// command (not rendered as JSON at all) rather than ever reaching this
/// document.
#[derive(Debug, Serialize)]
pub struct ActionDoc {
    pub ip: Option<String>,
    pub action: String,
    pub applied: bool,
    pub refused: Option<String>,
    pub expires: Option<u32>,
    pub source: String,
}

/// Built from arguments so it is drivable from a test without touching the
/// kernel map. `refused` is what `place`'s existing guard (or, for `unban`,
/// `Blocklist::remove`'s return value) already decided — this only renders
/// that decision, never re-derives it.
pub fn action_doc(
    ip: Option<&str>,
    action: &str,
    refused: Option<&str>,
    expires: Option<u32>,
) -> ActionDoc {
    ActionDoc {
        ip: ip.map(str::to_string),
        action: action.to_string(),
        applied: refused.is_none(),
        refused: refused.map(str::to_string),
        expires,
        source: "operator".to_string(),
    }
}

impl ActionDoc {
    /// The same reply, naming who asked when `--source` was given. Without it
    /// the reply keeps `"operator"`, byte for byte what it was.
    pub fn with_source(mut self, source: Option<&str>) -> Self {
        if let Some(s) = source {
            self.source = s.to_string();
        }
        self
    }
}

/// A rate a reader can use, or `None`. One rule in one place, so the two
/// documents carrying this field cannot disagree about a non-finite value.
pub fn finite(v: f64) -> Option<f64> {
    v.is_finite().then_some(v)
}

/// What `log --json` says about one row of the block audit log.
///
/// `first_seen`/`expires`/`unbanned_at` are epoch integers, as every time in
/// this contract is — `banned_doc` above carries the same two field names the
/// same way. See `log_doc_carries_epoch_integers_not_strings`.
#[derive(Serialize)]
pub struct LogDoc {
    pub ip: String,
    pub reason: String,
    pub detail: String,
    pub first_seen: u32,
    pub expires: Option<u32>,
    pub unbanned_at: Option<u32>,
    pub enforced: bool,
    pub disposition: String,
}

/// Built from one audit row — which already carries `ip`/`reason`/`detail`/
/// `ts` as one unit — plus whatever else only the caller knows. No database
/// needed to drive it from a test. `reason` is `BlockRow.reason`, the store
/// column of that name, and the human path's `REASON` header — one term for
/// one thing, per `CONTEXT.md`.
///
/// `disposition` is `CONTEXT.md`'s word for what the perimeter does with a
/// source it has judged, and its value is one of that entry's four: **ignore**,
/// **exempt**, **would-block** or **block**. The glossary grounds those in
/// `tfps_core::disposition`, whose variants are `Ignore`, `ExemptIgnoreIp`,
/// `ExemptKnownPeer` and `Block` — so `"blocked"`, the past tense this field
/// used to carry, names none of them. A **verdict** is a different statement
/// again (pass, challenge or block, about an attempt) and is not what this
/// field holds.
pub fn log_doc(
    row: &BlockRow,
    expires: Option<u32>,
    unbanned_at: Option<u32>,
    enforced: bool,
    disposition: &str,
) -> LogDoc {
    LogDoc {
        ip: row.ip.clone(),
        reason: row.reason.clone(),
        detail: row.detail.clone(),
        first_seen: row.ts,
        expires,
        unbanned_at,
        enforced,
        disposition: disposition.to_string(),
    }
}

pub fn now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, last)
    }

    #[test]
    fn status_doc_reports_an_open_map_as_active() {
        let d = status_doc(
            Ok((3, "own map id 7".to_string())),
            Some((120, 4, 1_756_800_000)),
            Path::new("/var/lib/tfps/tfps.db"),
            "0.1.0",
        );
        assert_eq!(d.enforcement, "active");
        assert_eq!(d.blocked_now, 3);
        assert_eq!(d.mode, None, "the control tool cannot see the attach mode");
        assert_eq!(d.interface, None);
        assert_eq!(
            crate::json_line(&d).unwrap(),
            r#"{"enforcement":"active","mode":null,"interface":null,"map":"own map id 7","blocked_now":3,"pairs":120,"peers":4,"last_checkpoint":1756800000,"db":"/var/lib/tfps/tfps.db","version":"0.1.0"}"#
        );
    }

    #[test]
    fn status_doc_reports_an_unopenable_map_as_inactive_with_nothing_blocked() {
        let d = status_doc(
            Err("no such map".to_string()),
            Some((120, 4, 1_756_800_000)),
            Path::new("/x"),
            "0.1.0",
        );
        assert_eq!(d.enforcement, "inactive");
        assert_eq!(d.blocked_now, 0, "inactive means we are blocking nothing");
        assert_eq!(
            d.map, None,
            "there is no map to name when the map could not be opened"
        );
        assert_eq!(
            crate::json_line(&d).unwrap(),
            r#"{"enforcement":"inactive","mode":null,"interface":null,"map":null,"blocked_now":0,"pairs":120,"peers":4,"last_checkpoint":1756800000,"db":"/x","version":"0.1.0"}"#
        );
    }

    /// `Blocklist::open` prefers an explicit pin, then a third party's shared
    /// pin, then our own map by name, and records which in `b.source` "for the
    /// operator to see which plane they are editing" (its own words). The human
    /// path prints that string; without it in the document, a program cannot
    /// tell the daemon's own map from a third party's pinned one, which is the
    /// difference between editing enforcement and editing somebody else's.
    #[test]
    fn status_doc_names_the_map_it_read() {
        for source in [
            "own map id 7",
            "pinned map /sys/fs/bpf/tfps/blocked",
            "shared map /sys/fs/bpf/sipvault/drop",
        ] {
            let d = status_doc(Ok((0, source.to_string())), None, Path::new("/x"), "0.1.0");
            assert_eq!(
                d.map.as_deref(),
                Some(source),
                "the three planes must stay distinguishable"
            );
        }
    }

    /// The learned-state totals get the null-not-zero treatment `kernel` and
    /// `condemnation` already get in `stats --json`: a database this tool could
    /// not open and a database with nothing learned in it are different facts,
    /// and `"pairs":0` for the first would report an idle box instead of an
    /// unreadable one.
    #[test]
    fn status_doc_nulls_the_learned_totals_when_the_store_is_unreadable() {
        let d = status_doc(
            Ok((3, "own map id 7".to_string())),
            None,
            Path::new("/x"),
            "0.1.0",
        );
        assert_eq!(d.pairs, None);
        assert_eq!(d.peers, None);
        assert_eq!(d.last_checkpoint, None);
        let line = crate::json_line(&d).unwrap();
        assert!(line.contains(r#""pairs":null"#), "{line}");
        assert!(
            line.contains(r#""blocked_now":3"#),
            "the kernel half is independent: {line}"
        );
    }

    /// `totals()` returns `COALESCE(MAX(last_seen), 0)`, so a database that
    /// exists but has never been checkpointed reports 0 — which as an epoch
    /// second is 1970-01-01, an answer a consumer would age to fifty-odd years.
    /// The human path prints the line only when it is non-zero; this nulls it
    /// for the same reason.
    #[test]
    fn status_doc_nulls_an_unwritten_checkpoint_rather_than_reporting_epoch_zero() {
        let d = status_doc(
            Ok((0, "own map id 7".to_string())),
            Some((0, 0, 0)),
            Path::new("/x"),
            "0.1.0",
        );
        assert_eq!(d.last_checkpoint, None, "never checkpointed is not 1970");
        assert_eq!(
            d.pairs,
            Some(0),
            "an empty database really did read zero pairs"
        );
    }

    // A DELIBERATE CONTRACT CHANGE, not a test relaxed to fit the code:
    // `first_seen`/`expires` were RFC3339 strings here and epoch integers in
    // `log_doc`, `expires_epoch`, `traffic_doc`'s `age_secs` and the three row
    // documents' `last_seen` — two sites against six, for the same kind of
    // value. The rule this contract states about itself (see `TrafficDoc`:
    // "a consumer recomputes its own presentation") settles it in favour of the
    // six. These expectations are the new contract; the old string literals were
    // removed, not loosened.
    #[test]
    fn banned_doc_carries_epoch_times_and_nulls_an_unattributed_source() {
        let attributed = banned_doc(
            "198.51.100.10",
            Some(("user-agent", "pplsip")),
            Some(1756917600),
            Some(1756921200),
        );
        assert_eq!(attributed.ip, "198.51.100.10");
        assert_eq!(attributed.reason.as_deref(), Some("user-agent"));
        assert_eq!(attributed.detail.as_deref(), Some("pplsip"));
        assert_eq!(
            attributed.first_seen,
            Some(1756917600),
            "an epoch integer, not an RFC3339 string"
        );
        assert_eq!(attributed.expires, Some(1756921200));
        assert!(attributed.enforced);
        assert_eq!(
            crate::json_line(&attributed).unwrap(),
            r#"{"ip":"198.51.100.10","reason":"user-agent","detail":"pplsip","first_seen":1756917600,"expires":1756921200,"enforced":true}"#
        );
        let bare = banned_doc("198.51.100.12", None, None, None);
        assert_eq!(bare.ip, "198.51.100.12");
        assert_eq!(bare.reason, None);
        assert_eq!(bare.detail, None);
        assert_eq!(bare.first_seen, None);
        assert_eq!(bare.expires, None);
        assert!(bare.enforced, "a listed source is enforced by definition");
        assert_eq!(
            crate::json_line(&bare).unwrap(),
            r#"{"ip":"198.51.100.12","reason":null,"detail":null,"first_seen":null,"expires":null,"enforced":true}"#
        );
    }

    /// `banned`'s human path puts every condemned address in one of three
    /// classes, in this order: the audit log's own reason, then the APIBAN feed
    /// ("apiban (feed)"), then "not in this audit log". `--json` read the audit
    /// log and nothing else, so the second and third collapsed into the same
    /// two nulls — a consumer told "we do not know why this is blocked" about an
    /// address the box can account for exactly. `stats --json` already gets this
    /// split right, through `condemnation_counts`.
    ///
    /// The feed case renders as `("apiban", "feed")`: the human path's own two
    /// words, split at the seam its own `{reason} ({detail})` format already
    /// puts between them.
    #[test]
    fn banned_attribution_mirrors_the_human_paths_three_classes() {
        let mut audit = std::collections::HashMap::new();
        audit.insert(
            "198.51.100.10".to_string(),
            ("scanner".to_string(), "sipvicious".to_string(), 1756800000),
        );
        // Also on the feed: the audit reason still wins, the same precedence the
        // human path and `condemnation_counts` both apply.
        audit.insert(
            "198.51.100.11".to_string(),
            ("user-agent".to_string(), "pplsip".to_string(), 1756800100),
        );
        let apiban: std::collections::HashSet<String> =
            ["198.51.100.11".to_string(), "198.51.100.20".to_string()]
                .into_iter()
                .collect();

        assert_eq!(
            banned_attribution("198.51.100.10", &audit, &apiban),
            (Some(("scanner", "sipvicious")), Some(1756800000)),
            "an audited address reports its own reason"
        );
        assert_eq!(
            banned_attribution("198.51.100.11", &audit, &apiban),
            (Some(("user-agent", "pplsip")), Some(1756800100)),
            "on both, the audit reason wins — we condemned it for the perimeter reason"
        );
        assert_eq!(
            banned_attribution("198.51.100.20", &audit, &apiban),
            (Some(("apiban", "feed")), None),
            "on the feed only: attributed to the feed, not collapsed into unattributed"
        );
        assert_eq!(
            banned_attribution("198.51.100.30", &audit, &apiban),
            (None, None),
            "on neither: a hand ban with no audit row and no feed entry"
        );
    }

    // The reconstruction `banned --json` uses to turn a kernel expiry
    // (CLOCK_MONOTONIC nanoseconds) into wall-clock epoch seconds. This is
    // genuinely new arithmetic — the human path only ever produces a
    // relative countdown from the same `until` value, never an absolute
    // time — so it is pinned directly.
    #[test]
    fn expires_epoch_reconstructs_wall_clock_from_a_monotonic_delta() {
        let now_mono: u64 = 10_000_000_000_000; // an arbitrary monotonic "now"
        let now_wall: u32 = 1_756_800_000;

        // A live entry: 3600s of monotonic time remain until expiry.
        let until = now_mono + 3600 * 1_000_000_000;
        assert_eq!(
            expires_epoch(until, now_wall, now_mono),
            Some(now_wall + 3600),
            "a live entry's expiry is now + the remaining monotonic delta"
        );

        // An already-expired entry. The kernel would normally have dropped
        // this by the time `entries()` is read, but the arithmetic must
        // not underflow (a plain subtraction would panic in debug builds)
        // or produce a time in the past relative to `until`.
        let expired_until = now_mono - 60 * 1_000_000_000;
        assert_eq!(
            expires_epoch(expired_until, now_wall, now_mono),
            Some(now_wall),
            "an already-elapsed delta saturates to zero seconds left, not underflow"
        );

        // `until == 0` means "never expires" (see `Blocklist::insert`).
        assert_eq!(
            expires_epoch(0, now_wall, now_mono),
            None,
            "a permanent block has no expiry to report"
        );
    }

    /// Every time this contract carries is an epoch integer, `log`'s included:
    /// a consumer recomputes its own presentation, and a document that mixed
    /// integers and formatted strings for the same kind of value would make a
    /// consumer guess which it had. This pins the type, not just the number.
    #[test]
    fn log_doc_carries_epoch_integers_not_strings() {
        let row = BlockRow {
            ts: 1756800000,
            ip: "198.51.100.10".to_string(),
            reason: "scanner".to_string(),
            detail: "sipvicious".to_string(),
        };
        let d = log_doc(&row, Some(1756803600), None, true, "block");
        assert_eq!(d.ip, "198.51.100.10");
        assert_eq!(d.reason, "scanner");
        assert_eq!(d.detail, "sipvicious");
        assert_eq!(d.first_seen, 1756800000, "an epoch integer, not a string");
        assert_eq!(d.expires, Some(1756803600));
        assert_eq!(d.unbanned_at, None);
        assert!(d.enforced);
        assert_eq!(
            d.disposition, "block",
            "the glossary's disposition (CONTEXT.md), not the past tense"
        );
        assert_eq!(
            crate::json_line(&d).unwrap(),
            r#"{"ip":"198.51.100.10","reason":"scanner","detail":"sipvicious","first_seen":1756800000,"expires":1756803600,"unbanned_at":null,"enforced":true,"disposition":"block"}"#
        );
    }

    /// `detail` is a SIP `User-Agent`: an attacker writes it. The contract is
    /// one JSON document per line, so a raw newline in that field would end the
    /// line early and every following field would land in a record the consumer
    /// never sees as malformed — it would just parse as a shorter object.
    ///
    /// The human rendering genuinely is broken this way today (a newline splits
    /// the column layout across lines); this pins that the JSON one is not.
    #[test]
    fn a_hostile_detail_cannot_break_the_one_document_per_line_contract() {
        let row = BlockRow {
            ts: 1756800000,
            ip: "10.0.0.1".to_string(),
            reason: "scanner".to_string(),
            detail: "friendly\nscanner\r\n\"quoted\" \\slash\\ \u{1}ctrl\t{\"ip\":\"1.2.3.4\"}"
                .to_string(),
        };
        // Guard the fixture before trusting the assertions below: a `detail`
        // that did not actually contain the hostile bytes would make every
        // check here pass while proving nothing.
        assert!(row.detail.contains('\n') && row.detail.contains('\r'));
        assert!(row.detail.contains('"') && row.detail.contains('\\'));
        assert!(
            row.detail.contains('\u{1}'),
            "fixture must carry a control char"
        );

        let line = crate::json_line(&log_doc(&row, None, None, true, "block")).unwrap();
        assert!(
            !line.contains('\n'),
            "a raw newline would split the record: {line}"
        );
        assert!(!line.contains('\r'), "a bare CR would too: {line}");
        assert!(
            !line.contains('\u{1}'),
            "a raw control character is not valid inside a JSON string: {line}"
        );
        // and the value must survive exactly, not merely be made safe
        let back: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(
            back["detail"].as_str().unwrap(),
            row.detail,
            "escaping must be lossless"
        );
        assert_eq!(back["ip"].as_str().unwrap(), "10.0.0.1");
    }

    /// The same class of cast on the way back out of the kernel. `until` is a
    /// raw `u64` read from a BPF map — our own daemon's or, with `--map`, a
    /// third party's — so a value whose remaining delta exceeds `u32::MAX`
    /// seconds is an input this function must survive rather than assume away.
    /// `secs_left as u32` wraps it into a plausible-looking near-future expiry,
    /// which is worse than an obviously saturated one.
    #[test]
    fn expires_epoch_saturates_a_delta_too_large_for_the_field() {
        assert_eq!(
            expires_epoch(u64::MAX, 1_000, 0),
            Some(u32::MAX),
            "an 18-billion-second delta saturates; wrapping it invents a nearby expiry"
        );
        let just_over = (u64::from(u32::MAX) + 1) * 1_000_000_000;
        assert_eq!(
            expires_epoch(just_over, 1_000, 0),
            Some(u32::MAX),
            "one second past the field's range is already past it"
        );
    }

    #[test]
    fn action_doc_renders_every_outcome_the_guard_can_produce() {
        let applied = action_doc(Some("198.51.100.20"), "ban", None, Some(1756921210));
        assert_eq!(
            crate::json_line(&applied).unwrap(),
            r#"{"ip":"198.51.100.20","action":"ban","applied":true,"refused":null,"expires":1756921210,"source":"operator"}"#
        );
        for (ip, action, reason) in [
            ("192.0.2.1", "ban", "local"),
            ("192.0.2.77", "ban", "declared"),
            ("198.51.100.7", "ban", "kernel"),
            ("198.51.100.21", "unban", "not-blocked"),
        ] {
            let line = crate::json_line(&action_doc(Some(ip), action, Some(reason), None)).unwrap();
            assert!(line.contains(&format!(r#""ip":"{ip}""#)), "{line}");
            assert!(line.contains(&format!(r#""refused":"{reason}""#)), "{line}");
            assert!(
                line.contains(r#""applied":false"#),
                "a refusal never applied: {line}"
            );
            assert!(
                line.contains(r#""expires":null"#),
                "a refusal has no expiry: {line}"
            );
        }
    }

    /// `applied` and `refused` are the same fact twice. They may never disagree.
    #[test]
    fn applied_is_exactly_the_absence_of_a_refusal() {
        assert!(action_doc(Some("1.2.3.4"), "unban", None, None).applied);
        assert!(!action_doc(Some("1.2.3.4"), "unban", Some("not-blocked"), None).applied);
    }

    /// A kernel write failure is not a policy refusal. Folding them together would
    /// report "refused as configured" about a box whose enforcement is broken.
    #[test]
    fn a_kernel_failure_is_reported_separately_from_a_policy_refusal() {
        let kernel = crate::json_line(&action_doc(
            Some("198.51.100.7"),
            "ban",
            Some("kernel"),
            None,
        ))
        .unwrap();
        let policy =
            crate::json_line(&action_doc(Some("192.0.2.1"), "ban", Some("local"), None)).unwrap();
        assert!(kernel.contains(r#""refused":"kernel""#));
        assert!(policy.contains(r#""refused":"local""#));
        assert_ne!(kernel, policy);
    }

    /// Unreachable kernel counters are null, not zero. A tool that cannot read a
    /// counter and a counter that reads zero are different answers, and a
    /// consumer that cannot tell them apart will report "nothing was dropped"
    /// `ignoreip` is written by the daemon as `label=hits` pairs. A hit count
    /// that will not parse becomes `null` rather than vanishing, for the same
    /// reason the traffic counters do: a reader must be able to tell "the
    /// daemon never wrote this" from "this line is corrupt".
    ///
    /// The label is split from the RIGHT, because a CIDR label is arbitrary
    /// operator text and the human path splits it the same way.
    #[test]
    fn ignoreip_doc_keeps_a_corrupt_hit_count_as_null() {
        let d = ignoreip_doc(Some("10.0.0.0/24=5 192.168.0.0/16=0 weird=xx")).unwrap();
        assert_eq!(d.get("10.0.0.0/24"), Some(&Some(5)));
        assert_eq!(
            d.get("192.168.0.0/16"),
            Some(&Some(0)),
            "zero is a real count"
        );
        assert_eq!(
            d.get("weird"),
            Some(&None),
            "unparseable is null, not dropped"
        );
        assert_eq!(d.len(), 3, "no entry may be silently discarded");
        assert_eq!(ignoreip_doc(None), None, "absent is absent");
        assert_eq!(
            ignoreip_doc(Some("")),
            None,
            "empty is absent, not an empty map"
        );
    }

    /// `calibration` is written as `theta0_prefix={:.3} theta0_range={:.3}
    /// theta0c={:.3} prior_mean={:.2}` — floats. `"inf".parse::<f64>()` succeeds, so the
    /// non-finite hazard that made `rate` nullable applies here too: route it
    /// through the same `finite()` rule rather than letting serde decide.
    #[test]
    fn calibration_doc_nulls_a_non_finite_value() {
        let d =
            calibration_doc(Some("theta0_prefix=0.125 theta0c=inf prior_mean=nonsense")).unwrap();
        assert_eq!(d.get("theta0_prefix"), Some(&Some(0.125)));
        assert_eq!(d.get("theta0c"), Some(&None), "an infinity is not a number");
        assert_eq!(d.get("prior_mean"), Some(&None), "nor is unparseable text");
        assert_eq!(d.len(), 3, "no entry may be silently discarded");
        assert_eq!(calibration_doc(Some("")), None);
    }

    /// The four learned totals and the three block windows the human view
    /// prints, as data. `pairs` and `peers` come from one query that counts the
    /// same column twice — see the doc comment on `LearnedDoc`.
    #[test]
    fn learned_and_blocks_carry_the_human_views_numbers() {
        let l = learned_doc(12, 12, 40, 300);
        assert_eq!(
            crate::json_line(&l).unwrap(),
            r#"{"pairs":12,"peers":12,"countries":40,"intl_calls":300}"#
        );
        let b = blocks_doc(
            9,
            vec![("scanner".to_string(), 3), ("injection".to_string(), 1)],
            vec![("scanner".to_string(), 30)],
            vec![],
        );
        assert_eq!(
            b.last_hour.total, 4,
            "the window total is the sum of its reasons"
        );
        assert_eq!(b.last_week.total, 0);
        assert_eq!(
            crate::json_line(&b.last_hour).unwrap(),
            r#"{"total":4,"by_reason":{"injection":1,"scanner":3}}"#
        );
        assert_eq!(b.apiban_feed, 9);
    }

    /// about a box whose enforcement is broken.
    #[test]
    fn stats_doc_nulls_the_kernel_block_when_counters_are_unreachable() {
        let d = stats_doc(
            None,
            Some((7, 5, 2)),
            None,
            None,
            None,
            None,
            learned_doc(0, 0, 0, 0),
            blocks_doc(0, vec![], vec![], vec![]),
        );
        let line = crate::json_line(&d).unwrap();
        assert!(line.contains(r#""kernel":null"#), "{line}");
        assert!(line.contains(r#""condemned_now":7"#), "{line}");
    }

    #[test]
    fn stats_doc_reports_live_counters_when_they_are_readable() {
        let d = stats_doc(
            Some((100, 40, 3)),
            Some((7, 5, 2)),
            None,
            None,
            None,
            None,
            learned_doc(0, 0, 0, 0),
            blocks_doc(0, vec![], vec![], vec![]),
        );
        let line = crate::json_line(&d).unwrap();
        assert!(line.contains(r#""seen":100"#), "{line}");
        assert!(line.contains(r#""dropped":40"#), "{line}");
        assert!(line.contains(r#""expired":3"#), "{line}");
    }

    /// The condemnation summary gets the same null-not-zero treatment as the
    /// kernel block, and for the same reason: `Blocklist::open` failing is a
    /// different fact from a blocklist that is genuinely empty, and a
    /// consumer reading `condemned_now: 0` off a box whose map could not
    /// even be opened would draw exactly the wrong conclusion — "nothing is
    /// blocked" — about a box this tool simply could not check.
    #[test]
    fn stats_doc_nulls_the_condemnation_block_when_the_blocklist_is_unreachable() {
        let d = stats_doc(
            Some((100, 40, 3)),
            None,
            None,
            None,
            None,
            None,
            learned_doc(0, 0, 0, 0),
            blocks_doc(0, vec![], vec![], vec![]),
        );
        let line = crate::json_line(&d).unwrap();
        assert!(line.contains(r#""condemnation":null"#), "{line}");
        assert!(
            line.contains(r#""seen":100"#),
            "the kernel block is independent and must still report: {line}"
        );
    }

    /// The perimeter/feed split `stats --json`'s condemnation summary uses,
    /// pinned directly with concrete addresses — the same reason
    /// `expires_epoch` above is tested on its own
    /// rather than only indirectly through `stats_doc`, which never sees more
    /// than the three already-computed counts.
    #[test]
    fn condemnation_counts_splits_perimeter_from_feed_only() {
        let audit: std::collections::HashSet<String> =
            ["198.51.100.10".to_string()].into_iter().collect();
        let apiban: std::collections::HashSet<String> =
            ["198.51.100.10".to_string(), "198.51.100.20".to_string()]
                .into_iter()
                .collect();
        let entries = vec![
            // On both the audit log and the feed: attributed to the audit
            // log, the same "block_log reason wins" precedence the human
            // path already uses in `banned`.
            (Ipv4Addr::new(198, 51, 100, 10), 0u64),
            // On the feed only.
            (Ipv4Addr::new(198, 51, 100, 20), 0u64),
            // On neither — a hand ban with no audit row and no feed entry.
            (Ipv4Addr::new(198, 51, 100, 30), 0u64),
        ];
        let (condemned_now, perimeter_manual, apiban_feed_only) =
            condemnation_counts(&entries, &audit, &apiban);
        assert_eq!(
            condemned_now, 3,
            "every entry counts toward the total regardless of attribution"
        );
        assert_eq!(
            perimeter_manual, 1,
            "the audited-and-on-the-feed entry is attributed to the audit log, not the feed"
        );
        assert_eq!(
            apiban_feed_only, 1,
            "only the feed-only entry counts here; the unattributed entry counts toward neither"
        );
    }

    #[test]
    fn condemnation_counts_is_all_zero_for_an_empty_blocklist() {
        let audit = std::collections::HashSet::new();
        let apiban = std::collections::HashSet::new();
        assert_eq!(condemnation_counts(&[], &audit, &apiban), (0, 0, 0));
    }

    /// The checkpoint-line parsing and age arithmetic `stats --json`'s TRAFFIC
    /// block uses. `age_secs` is a raw interval, not `ago()`'s formatted
    /// string — a program recomputes its own presentation, the same
    /// reasoning that keeps `log_doc`'s times as epoch integers.
    #[test]
    fn traffic_doc_parses_the_checkpoint_line_and_ages_it_in_raw_seconds() {
        let d = traffic_doc(
            Some("udp=120 syn=40 auth_fail=3"),
            Some(1_756_800_000),
            1_756_800_600,
        )
        .expect("a checkpoint line is present");
        assert_eq!(
            d.age_secs,
            Some(600),
            "raw seconds, not a formatted duration string"
        );
        assert_eq!(
            d.counters.get("udp"),
            Some(&Some(120)),
            "an integer, not the string \"120\" — `kernel.seen` in the same document is one"
        );
        assert_eq!(d.counters.get("syn"), Some(&Some(40)));
        assert_eq!(d.counters.get("auth_fail"), Some(&Some(3)));
        assert_eq!(d.counters.len(), 3, "no extra or dropped counters");
    }

    #[test]
    fn traffic_doc_is_none_when_there_is_no_checkpoint_yet() {
        assert!(
            traffic_doc(None, None, 1_756_800_000).is_none(),
            "no checkpoint yet is a different fact from a checkpoint with zero counters"
        );
    }

    #[test]
    fn traffic_doc_ages_null_when_the_checkpoint_has_no_timestamp() {
        let d = traffic_doc(Some("udp=120"), None, 1_756_800_600)
            .expect("a counters line without a timestamp still parses");
        assert_eq!(d.age_secs, None);
        assert_eq!(d.counters.get("udp"), Some(&Some(120)));
    }

    /// A counter the daemon wrote and this tool cannot read as a number is
    /// `null` — the key survives, so "the daemon never reported this counter"
    /// stays distinguishable from "this checkpoint line is corrupt". Dropping
    /// the key would collapse the two, the same conflation `stats --json`'s
    /// null-not-zero blocks exist to prevent one level up.
    #[test]
    fn traffic_doc_nulls_a_counter_it_cannot_read_rather_than_dropping_it() {
        let d = traffic_doc(Some("udp=120 syn=? auth_fail=3"), None, 1_756_800_600)
            .expect("a checkpoint line is present");
        assert_eq!(d.counters.len(), 3, "the unreadable counter keeps its key");
        assert_eq!(d.counters.get("syn"), Some(&None));
        assert_eq!(d.counters.get("udp"), Some(&Some(120)));
    }

    fn manual(
        ts: u32,
        verb: crate::manual_log::ManualVerb,
        source: &str,
        reason: Option<&str>,
    ) -> crate::manual_log::ManualAction {
        crate::manual_log::ManualAction {
            ts,
            verb,
            ip: ip(20),
            source: source.to_string(),
            reason: reason.map(str::to_string),
            expires: None,
        }
    }

    #[test]
    fn only_addresses_actually_removed_are_recorded_as_unbanned() {
        let removed = vec![(ip(1), true), (ip(2), false)];
        let recs = manual_unbans(&removed, Some("sipnab"), None, 2_000);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].ip, ip(1));
        assert_eq!(recs[0].verb, crate::manual_log::ManualVerb::Unban);
    }

    /// The latest action per address, as `latest_for` answers it.
    fn latest_of(
        actions: &[crate::manual_log::ManualAction],
    ) -> std::collections::HashMap<Ipv4Addr, crate::manual_log::ManualAction> {
        let mut m = std::collections::HashMap::new();
        for a in actions {
            let keep = m
                .get(&a.ip)
                .is_none_or(|held: &crate::manual_log::ManualAction| held.ts <= a.ts);
            if keep {
                m.insert(a.ip, a.clone());
            }
        }
        m
    }

    #[test]
    fn a_manual_ban_explains_a_block_nothing_else_explains() {
        let latest = latest_of(&[manual(
            500,
            crate::manual_log::ManualVerb::Ban,
            "sipnab",
            Some("scan"),
        )]);
        let got = manual_attribution(ip(20), &latest, None);
        assert_eq!(
            got,
            Some((
                "manual".to_string(),
                "scan".to_string(),
                "sipnab".to_string()
            ))
        );
    }

    #[test]
    fn a_newer_daemon_block_outranks_an_older_manual_ban() {
        let latest = latest_of(&[manual(
            500,
            crate::manual_log::ManualVerb::Ban,
            "sipnab",
            Some("scan"),
        )]);
        assert_eq!(manual_attribution(ip(20), &latest, Some(600)), None);
        assert!(
            manual_attribution(ip(20), &latest, Some(400)).is_some(),
            "an older daemon block does not"
        );
    }

    #[test]
    fn a_manual_unban_explains_nothing() {
        let latest = latest_of(&[
            manual(
                500,
                crate::manual_log::ManualVerb::Ban,
                "sipnab",
                Some("scan"),
            ),
            manual(600, crate::manual_log::ManualVerb::Unban, "operator", None),
        ]);
        assert_eq!(manual_attribution(ip(20), &latest, None), None);
    }

    #[test]
    fn a_manual_ban_with_no_reason_says_so_rather_than_leaving_it_blank() {
        let latest = latest_of(&[manual(
            500,
            crate::manual_log::ManualVerb::Ban,
            "operator",
            None,
        )]);
        let (reason, detail, source) =
            manual_attribution(ip(20), &latest, None).expect("attributed");
        assert_eq!(
            (reason.as_str(), detail.as_str(), source.as_str()),
            ("manual", "no reason given", "operator")
        );
    }

    #[test]
    fn banned_json_names_who_placed_a_manual_ban() {
        let doc = banned_doc(&ip(20).to_string(), Some(("manual", "scan")), None, None)
            .with_source(Some("sipnab"));
        let v = serde_json::to_value(&doc).expect("serializes");
        assert_eq!(v["source"], "sipnab");
        assert_eq!(v["reason"], "manual");
        let plain = serde_json::to_value(banned_doc(&ip(21).to_string(), None, None, None))
            .expect("serializes");
        assert!(plain["source"].is_null(), "not a manual ban: {plain}");
    }

    // ── the command functions ──────────────────────────────────────────────

    /// One top-level function's body in this file: from `fn <name>(` to the
    /// `}` that closes it at column 0, which rustfmt guarantees (`cargo fmt
    /// --all --check` is a gate). The same technique as `tfps_ctl`'s
    /// `handler_body`.
    fn fn_body(name: &str) -> &'static str {
        let src = include_str!("ctl.rs");
        let sig = format!("\npub fn {name}(");
        let start = src
            .find(&sig)
            .unwrap_or_else(|| panic!("no `pub fn {name}(` in ctl.rs"));
        let len = src[start..]
            .find("\n}\n")
            .expect("rustfmt closes it at column 0");
        &src[start..start + len]
    }

    /// A database path of this test's own, removed first.
    fn scratch_db(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "tfps-ctl-{tag}-{}-{:?}.db",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// Paths that exist nowhere, so nothing here can reach a real map or
    /// database on the machine running the tests.
    fn nowhere() -> Ctx {
        let dir = std::env::temp_dir().join(format!("tfps-ctl-nowhere-{}", std::process::id()));
        Ctx {
            db: dir.join("absent.db"),
            map: Some(dir.join("absent-map")),
            shared_map: None,
            config: dir.join("absent.json"),
        }
    }

    /// `status` must report the binary's real version, never a literal. The
    /// `status_doc` tests pass a version in as an argument, so they prove the
    /// document serialises whatever it is given — they cannot catch the CALL
    /// SITE regressing to a typed-in string.
    #[test]
    fn status_reports_the_crate_version_not_a_literal() {
        assert!(
            fn_body("status_docs").contains("env!(\"CARGO_PKG_VERSION\")"),
            "status must pass the crate version to status_doc, never a literal"
        );
    }

    #[test]
    fn status_docs_nulls_what_it_cannot_read() {
        let d = status_docs(&nowhere());
        assert_eq!(d.enforcement, "inactive");
        assert_eq!(d.map, None);
        assert_eq!((d.pairs, d.peers, d.last_checkpoint), (None, None, None));
        assert_eq!(d.version, env!("CARGO_PKG_VERSION"));
    }

    /// `log_doc_carries_epoch_integers_not_strings` hands the document its own
    /// value, so it proves only that whatever it is given comes back out — it
    /// cannot see the CALL SITE choosing a word outside the glossary.
    ///
    /// `CONTEXT.md`'s Disposition entry enumerates **ignore**, **exempt**,
    /// **would-block** and **block**, and grounds them in
    /// `tfps_core::disposition`. `"blocked"` is none of them, and this is the
    /// one field a consumer is most likely to match against that vocabulary.
    #[test]
    fn log_passes_a_glossary_disposition_to_the_document() {
        assert!(
            fn_body("log_docs").contains(r#"log_doc(r, None, None, true, "block")"#),
            "log must pass CONTEXT.md's disposition `block`, not a past tense or \
             any other word outside the glossary"
        );
    }

    /// What `log --json` printed before this module existed: one `log_doc`
    /// per row of `Store::blocks`, newest first, honouring `--limit` and `--ip`.
    #[test]
    fn log_docs_are_the_audit_rows_newest_first() {
        let db = scratch_db("log");
        {
            let s = Store::open(&db).expect("open");
            s.log_block(100, ip(1), "scanner", "friendly-scanner")
                .expect("log");
            s.log_block(200, ip(2), "auth_failure", "401 x5")
                .expect("log");
            s.log_block(300, ip(1), "user-agent", "sipvicious")
                .expect("log");
        }
        let ctx = Ctx {
            db: db.clone(),
            ..nowhere()
        };
        let lines = |limit, only: Option<&str>| -> Vec<String> {
            log_docs(&ctx, limit, only)
                .expect("readable")
                .iter()
                .map(|d| crate::json_line(d).expect("serialises"))
                .collect()
        };
        assert_eq!(
            lines(50, None),
            [
                r#"{"ip":"203.0.113.1","reason":"user-agent","detail":"sipvicious","first_seen":300,"expires":null,"unbanned_at":null,"enforced":true,"disposition":"block"}"#,
                r#"{"ip":"203.0.113.2","reason":"auth_failure","detail":"401 x5","first_seen":200,"expires":null,"unbanned_at":null,"enforced":true,"disposition":"block"}"#,
                r#"{"ip":"203.0.113.1","reason":"scanner","detail":"friendly-scanner","first_seen":100,"expires":null,"unbanned_at":null,"enforced":true,"disposition":"block"}"#,
            ]
        );
        assert_eq!(lines(1, None).len(), 1, "--limit");
        assert_eq!(lines(50, Some("203.0.113.1")).len(), 2, "--ip");
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn log_and_stats_fail_without_a_database() {
        assert!(log_docs(&nowhere(), 50, None).is_err());
        assert!(
            stats_docs(&nowhere()).is_err(),
            "no document rather than one with invented totals"
        );
    }

    #[test]
    fn stats_docs_reads_the_learned_totals_and_the_feed() {
        let db = scratch_db("stats");
        {
            let mut s = Store::open(&db).expect("open");
            s.apiban_add(&[ip(5), ip(6)], 100).expect("feed");
            s.log_block(now(), ip(1), "scanner", "x").expect("log");
        }
        let d = stats_docs(&Ctx {
            db: db.clone(),
            ..nowhere()
        })
        .expect("readable");
        assert!(
            d.condemnation.is_none(),
            "the map cannot be opened: null, not zero"
        );
        assert!(d.traffic.is_none(), "no checkpoint yet");
        assert_eq!(d.blocks.apiban_feed, 2);
        assert_eq!(d.blocks.last_hour.total, 1);
        assert_eq!(d.blocks.last_hour.by_reason.get("scanner"), Some(&1));
        assert_eq!(d.learned.pairs, 0);
        let _ = std::fs::remove_file(&db);
    }

    /// A configured shared map that is present but unusable is passed over for
    /// the daemon's own map, as the daemon itself does; an explicit pin is not.
    /// No kernel here, so each case is told apart by which open failed.
    #[test]
    fn an_unusable_shared_map_falls_back_like_the_daemon_and_an_explicit_pin_does_not() {
        let stale = scratch_db("stale-pin");
        std::fs::write(&stale, b"not a BPF pin").expect("write");
        let open = |map: Option<&PathBuf>, shared: Option<&PathBuf>| {
            let ctx = Ctx {
                map: map.cloned(),
                shared_map: shared.cloned(),
                ..nowhere()
            };
            open_blocklist(&ctx).err().expect("no kernel map here")
        };
        let own = open(None, None);
        assert_eq!(
            open(None, Some(&stale)),
            own,
            "an unusable shared pin falls back to the usual lookup"
        );
        assert_eq!(
            open(None, Some(&stale.with_extension("absent"))),
            own,
            "so does an absent one"
        );
        assert!(
            open(Some(&stale), None).contains(&stale.display().to_string()),
            "an explicit pin is opened as given, with no fallback"
        );
        let _ = std::fs::remove_file(&stale);
    }

    #[test]
    fn banned_docs_fails_when_the_map_cannot_be_opened() {
        assert!(banned_docs(&nowhere()).is_err());
    }

    #[test]
    fn banned_docs_consults_the_manual_record() {
        let body = fn_body("banned_docs");
        assert!(body.contains("manual_record(ctx,"), "{body}");
        assert!(body.contains("manual_attribution("), "{body}");
    }

    #[test]
    fn unban_docs_records_what_it_did() {
        let body = fn_body("unban_docs");
        assert!(body.contains("record_manual("), "{body}");
        // Recorded unconditionally, after the removals and with no early
        // return between: the removals before a failed kernel write have
        // happened and must not be missing from the record.
        let removed = body.find("remove_each(").expect("removes");
        let record = body.find("record_manual(").expect("records");
        assert!(removed < record, "{body}");
        assert!(!body[removed..record].contains("return"), "{body}");
    }

    #[test]
    fn unban_docs_names_the_source_on_every_reply() {
        assert_eq!(
            fn_body("unban_docs")
                .matches(".with_source(source)")
                .count(),
            1,
            "one rendering for --all and the address list"
        );
    }

    /// A typo in the list lifts nothing: the address is named before the map
    /// is even opened. `nowhere()`'s map does not exist, so reaching it would
    /// fail with a map error instead.
    #[test]
    fn unban_docs_parses_every_address_before_touching_the_map() {
        let raw = ["203.0.113.1".to_string(), "203.0.113.x".to_string()];
        let e =
            unban_docs(&nowhere(), UnbanTarget::Addresses(&raw), None, None).expect_err("refused");
        assert!(e.starts_with("203.0.113.x: "), "{e}");
    }

    /// The record's rules hold for every caller, not just the CLI's parser:
    /// a bad `source` or `reason` is refused before the map is touched.
    /// `nowhere()`'s map does not exist, so reaching it would fail differently.
    #[test]
    fn unban_docs_refuses_a_bad_source_or_reason_before_touching_the_map() {
        let raw = ["203.0.113.1".to_string()];
        let unban = |source, reason| {
            unban_docs(&nowhere(), UnbanTarget::Addresses(&raw), source, reason)
                .expect_err("refused")
        };
        assert!(unban(Some("has space"), None).starts_with("--source "));
        assert!(unban(Some(""), None).starts_with("--source "));
        assert!(unban(None, Some("line\nbreak")).starts_with("--reason "));
        assert!(unban(None, Some("")).starts_with("--reason "));
        assert!(
            !unban(Some("panel"), Some("ok")).starts_with("--"),
            "valid values pass the check and reach the map"
        );
    }

    #[test]
    fn unban_docs_wants_an_address_or_all() {
        let e =
            unban_docs(&nowhere(), UnbanTarget::Addresses(&[]), None, None).expect_err("refused");
        assert_eq!(e, "give at least one address, or --all");
    }

    #[test]
    fn remove_each_keeps_what_was_done_before_a_failure() {
        let (done, err) = remove_each(&[ip(1), ip(2), ip(3), ip(4)], |a| match a {
            a if a == ip(2) => Ok(false),
            a if a == ip(3) => Err("kernel said no".into()),
            _ => Ok(true),
        });
        assert_eq!(done, [(ip(1), true), (ip(2), false)]);
        assert_eq!(err.as_deref(), Some("kernel said no"));
        assert_eq!(
            remove_each(&[ip(1)], |_| Ok(true)),
            (vec![(ip(1), true)], None)
        );
    }

    #[test]
    fn the_record_is_reached_only_through_manual_dir() {
        let src = include_str!("ctl.rs");
        let code = &src[..src
            .find("\n#[cfg(test)]\nmod tests {")
            .expect("tests module")];
        assert!(
            !code.contains("manual_log::append(&ctx.db")
                && !code.contains("manual_log::latest_for(&ctx.db"),
            "the record is found through manual_dir, never straight from the database path"
        );
        assert!(
            code.matches("manual_dir(ctx)").count() >= 2,
            "record_manual and manual_record"
        );
    }
}
