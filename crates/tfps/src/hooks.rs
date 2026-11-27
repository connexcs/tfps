//! Webhooks: a JSON POST to each configured URL when a source is blocked, unblocked,
//! or its block expires.
//!
//! **Sent by `tfps_ctl serve`, never by the daemon.** The packet path gains no HTTP
//! client. `serve` notices events by polling what the daemon already writes:
//!
//! - **`block`**: new rows in `block_log` (written at block time), and manual bans
//!   in the manual-action record.
//! - **`unblock`**: manual unbans in the manual-action record, with who and why.
//! - **`expired`**: a block this watcher saw placed whose expiry instant has passed.
//!   Expiry happens in the kernel, so it is noticed by polling, to within one poll.
//! - **`unblock` with `"source":"unknown"`**: a watched block that left the map
//!   before its expiry with no unban on record (the map's LRU eviction under a
//!   spoofed flood, or another program editing a shared map). It is reported one
//!   poll late, so an unban whose record is still being written is not misreported.
//!
//! What it does not report, by design: APIBAN feed blocks (thousands per sync, and not
//! this host's own evidence); expiries that happened while `serve` was not running
//! (the first poll after a start, or after the daemon restarts with a fresh map, only
//! builds the baseline). Delivery is at-least-once within the retry budget, not
//! guaranteed: a URL that stays down past its retries loses that event, counted.
//!
//! Each URL has its own worker thread and bounded queue, so a slow or dead endpoint
//! delays nobody else. Where reading stopped is kept in a cursor file, so a restart
//! neither replays history nor skips what was written meanwhile.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::ctl::Ctx;
use crate::manual_log::{ManualAction, ManualVerb, Position};
use crate::store::{BlockRow, Store};

/// Events waiting per URL. Past this, a new event for that URL is dropped, counted.
pub const QUEUE: usize = 1000;
/// `block_log` rows read per poll; a busier poll is followed by another at once.
const ROWS_PER_POLL: usize = 1000;
/// How the cursor file is named, beside the database.
pub const CURSOR_FILE: &str = "hooks.cursor";

/// One event, exactly as POSTed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Event {
    /// `"block"`, `"unblock"` or `"expired"`.
    pub event: &'static str,
    pub ip: String,
    /// When it happened, as a Unix time.
    pub ts: u32,
    pub reason: Option<String>,
    pub detail: Option<String>,
    /// When the block lapses, as a Unix time; `null` for no expiry and for the
    /// end of a block.
    pub expires: Option<u32>,
    /// Who did it: `"tfps"` for the daemon and for an expiry, the manual action's
    /// source for a manual ban or unban, `"unknown"` for an unexplained removal.
    pub source: String,
    /// This host's name, so a receiver of several hosts' events can tell them apart.
    pub host: String,
}

// ---------------------------------------------------------------- cursor

/// Where reading stopped, kept across restarts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    /// The last `block_log` row number read.
    pub block_log: i64,
    /// That row's whole content (`store::block_log_key`), so a row number
    /// reused after the table was emptied is recognised as a different row.
    pub block_log_key: String,
    /// Where reading the manual-action record stopped.
    pub manual: Position,
}

/// The saved cursor, or `None` when there is none yet (or it cannot be read).
pub fn load_cursor(path: &Path) -> Option<Cursor> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// Saves `cursor` atomically: a temporary file beside it, then a rename.
pub fn save_cursor(path: &Path, cursor: &Cursor) -> Result<(), String> {
    let json = serde_json::to_vec(cursor).map_err(|e| format!("serialising the cursor: {e}"))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, json).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("replacing {}: {e}", path.display()))
}

// ---------------------------------------------------------------- watcher

/// Which daemon run a block map belongs to: its pid and process start time, from
/// the state file. A different value means the daemon restarted with a new map.
pub type DaemonRun = (u32, u64);

/// What one poll saw.
pub struct Seen<'a> {
    /// New `block_log` rows, oldest first.
    pub blocks: &'a [BlockRow],
    /// New manual actions, oldest first.
    pub manual: &'a [ManualAction],
    /// The block map now and the daemon run it belongs to; `None` when it could
    /// not be read, in which case nothing is concluded from its absence.
    pub map: Option<(DaemonRun, &'a [(Ipv4Addr, u64)])>,
    /// Addresses the audit log or the manual record know about, among those in
    /// the map; only needed when a baseline is taken ([`Watcher::needs_baseline`]).
    pub known: &'a HashSet<Ipv4Addr>,
    pub now_wall: u32,
    pub now_mono: u64,
}

/// Turns what each poll sees into events. Holds no I/O, so every rule is testable.
pub struct Watcher {
    host: String,
    /// The daemon run whose map the watched blocks are in; `None` before a baseline.
    run: Option<DaemonRun>,
    /// Blocks this watcher saw placed and still watches, with their kernel expiry
    /// (monotonic ns, `0` = none), once the map has been read with them in it.
    watched: HashMap<Ipv4Addr, Option<u64>>,
    /// Watched blocks found missing from the map on the last poll, unexplained.
    missing: HashSet<Ipv4Addr>,
}

impl Watcher {
    pub fn new(host: String) -> Self {
        Watcher {
            host,
            run: None,
            watched: HashMap::new(),
            missing: HashSet::new(),
        }
    }

    /// Whether the next poll with a map from `run` takes a new baseline: the first
    /// time, and after the daemon restarts with a new map.
    pub fn needs_baseline(&self, run: DaemonRun) -> bool {
        self.run != Some(run)
    }

    /// The events for one poll, in order.
    pub fn poll(&mut self, seen: &Seen<'_>) -> Vec<Event> {
        let mut out = Vec::new();
        let in_map: HashMap<Ipv4Addr, u64> = seen
            .map
            .map(|(_, entries)| entries.iter().copied().collect())
            .unwrap_or_default();
        let expires = |ip: Ipv4Addr| {
            in_map
                .get(&ip)
                .and_then(|&u| crate::ctl::expires_epoch(u, seen.now_wall, seen.now_mono))
        };

        for row in seen.blocks {
            let Ok(ip) = row.ip.parse::<Ipv4Addr>() else {
                continue;
            };
            out.push(self.event(
                "block",
                ip,
                row.ts,
                Some(row.reason.clone()),
                Some(row.detail.clone()),
                expires(ip),
                "tfps",
            ));
            self.watch(ip);
        }
        for a in seen.manual {
            match a.verb {
                ManualVerb::Ban => {
                    out.push(self.event(
                        "block",
                        a.ip,
                        a.ts,
                        Some("manual".into()),
                        a.reason.clone(),
                        a.expires,
                        &a.source,
                    ));
                    self.watch(a.ip);
                }
                ManualVerb::Unban => {
                    out.push(self.event(
                        "unblock",
                        a.ip,
                        a.ts,
                        a.reason.clone(),
                        None,
                        None,
                        &a.source,
                    ));
                    self.watched.remove(&a.ip);
                    self.missing.remove(&a.ip);
                }
            }
        }

        let Some((run, entries)) = seen.map else {
            return out; // the map cannot be read: nothing is concluded from it
        };
        if self.needs_baseline(run) {
            // A new map: watch what is in it that the audit log or the manual
            // record explain (never the APIBAN feed), and report nothing missing.
            self.run = Some(run);
            self.missing.clear();
            let fresh: HashSet<Ipv4Addr> = self.watched.keys().copied().collect();
            self.watched = entries
                .iter()
                .filter(|(ip, _)| seen.known.contains(ip) || fresh.contains(ip))
                .map(|&(ip, until)| (ip, Some(until)))
                .collect();
            return out;
        }

        let mut ended = Vec::new();
        for (&ip, until) in self.watched.iter_mut() {
            if let Some(&now_until) = in_map.get(&ip) {
                *until = Some(now_until);
            }
            let lapsed = matches!(*until, Some(u) if u != 0 && u <= seen.now_mono);
            if until.is_none() && !in_map.contains_key(&ip) {
                // Logged but never in the map (enforcement off): no block to end.
                ended.push((ip, "never"));
            } else if lapsed {
                ended.push((ip, "expired"));
            } else if !in_map.contains_key(&ip) && until.is_some() {
                if self.missing.contains(&ip) {
                    ended.push((ip, "unknown"));
                } else {
                    self.missing.insert(ip);
                }
            } else {
                self.missing.remove(&ip);
            }
        }
        ended.sort();
        for (ip, why) in ended {
            self.watched.remove(&ip);
            self.missing.remove(&ip);
            if why == "never" {
                continue;
            }
            out.push(match why {
                "expired" => self.event("expired", ip, seen.now_wall, None, None, None, "tfps"),
                _ => self.event("unblock", ip, seen.now_wall, None, None, None, "unknown"),
            });
        }
        out
    }

    /// Starts (or keeps) watching `ip`; its expiry is learned from the map.
    fn watch(&mut self, ip: Ipv4Addr) {
        self.watched.insert(ip, None);
        self.missing.remove(&ip);
    }

    #[allow(clippy::too_many_arguments)]
    fn event(
        &self,
        event: &'static str,
        ip: Ipv4Addr,
        ts: u32,
        reason: Option<String>,
        detail: Option<String>,
        expires: Option<u32>,
        source: &str,
    ) -> Event {
        Event {
            event,
            ip: ip.to_string(),
            ts,
            reason,
            detail,
            expires,
            source: source.to_string(),
            host: self.host.clone(),
        }
    }
}

// ---------------------------------------------------------------- delivery

/// How each event is delivered to one URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retry {
    /// Each attempt's limit, from connecting to reading the answer.
    pub timeout: Duration,
    /// The waits between attempts; their number is the number of retries.
    pub backoff: Vec<Duration>,
}

impl Default for Retry {
    fn default() -> Self {
        Retry {
            timeout: Duration::from_secs(5),
            backoff: [1, 2, 4].map(Duration::from_secs).to_vec(),
        }
    }
}

/// Delivery outcomes per URL, for `/metrics`, and how many deliveries are still
/// in flight.
#[derive(Debug, Default)]
pub struct Stats {
    per_url: Vec<[AtomicU64; 3]>,
    /// Events queued for a URL and not yet delivered, failed or dropped.
    pending: std::sync::atomic::AtomicUsize,
}

/// The outcomes counted, as `tfps_hook_deliveries_total`'s `result` label.
pub const RESULTS: [&str; 3] = ["delivered", "failed", "queue_full"];
const DELIVERED: usize = 0;
const FAILED: usize = 1;
const QUEUE_FULL: usize = 2;

impl Stats {
    pub fn new(urls: usize) -> Self {
        Stats {
            per_url: (0..urls).map(|_| Default::default()).collect(),
            pending: Default::default(),
        }
    }

    fn add(&self, url: usize, result: usize) {
        if let Some(c) = self.per_url.get(url) {
            c[result].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Whether every queued event has reached an outcome: the moment the
    /// cursor can be saved without losing an event still in a queue.
    pub fn idle(&self) -> bool {
        self.pending.load(Ordering::SeqCst) == 0
    }

    /// `(url index, result, count)` for every URL and result.
    pub fn snapshot(&self) -> Vec<(usize, &'static str, u64)> {
        self.per_url
            .iter()
            .enumerate()
            .flat_map(|(i, c)| {
                RESULTS
                    .iter()
                    .enumerate()
                    .map(move |(r, name)| (i, *name, c[r].load(Ordering::Relaxed)))
            })
            .collect()
    }
}

/// One queue and one worker thread per URL.
pub struct Sender {
    queues: Vec<SyncSender<Arc<Vec<u8>>>>,
    stats: Arc<Stats>,
}

impl Sender {
    /// Starts a worker for each of `urls`, each with a queue of `queue` events.
    pub fn start(urls: &[String], retry: &Retry, queue: usize, stats: Arc<Stats>) -> Self {
        let queues = urls
            .iter()
            .enumerate()
            .map(|(i, url)| {
                let (tx, rx) = sync_channel(queue);
                let (url, retry, stats) = (url.clone(), retry.clone(), Arc::clone(&stats));
                std::thread::spawn(move || deliver(i, &url, &rx, &retry, &stats));
                tx
            })
            .collect();
        Sender { queues, stats }
    }

    /// Queues `event` for every URL. A full queue drops it for that URL, counted,
    /// rather than wait: the poll loop must not stall behind a dead endpoint.
    pub fn send(&self, event: &Event) {
        let Ok(body) = serde_json::to_vec(event) else {
            return;
        };
        let body = Arc::new(body);
        for (i, q) in self.queues.iter().enumerate() {
            self.stats.pending.fetch_add(1, Ordering::SeqCst);
            let refused = match q.try_send(Arc::clone(&body)) {
                Ok(()) => continue,
                Err(TrySendError::Full(_)) => QUEUE_FULL,
                Err(TrySendError::Disconnected(_)) => FAILED,
            };
            self.stats.add(i, refused);
            self.stats.pending.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// One URL's worker: POST each event, retrying with backoff, then give up on it.
fn deliver(index: usize, url: &str, rx: &Receiver<Arc<Vec<u8>>>, retry: &Retry, stats: &Stats) {
    let agent = crate::apiban::agent(retry.timeout);
    for body in rx {
        let mut attempt = 0;
        loop {
            let answer = agent
                .post(url)
                .header("Content-Type", "application/json")
                .send(body.as_slice());
            let error = match answer {
                Ok(r) if r.status().is_success() => {
                    stats.add(index, DELIVERED);
                    stats.pending.fetch_sub(1, Ordering::SeqCst);
                    break;
                }
                Ok(r) => format!("status {}", r.status().as_u16()),
                Err(e) => e.to_string(),
            };
            match retry.backoff.get(attempt) {
                Some(wait) => {
                    attempt += 1;
                    std::thread::sleep(*wait);
                }
                None => {
                    stats.add(index, FAILED);
                    stats.pending.fetch_sub(1, Ordering::SeqCst);
                    eprintln!(
                        "tfps_ctl serve: webhook {index} ({url}) failed after {} attempts: {error}; event dropped",
                        attempt + 1
                    );
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------- polling

/// This host's name, for the events.
pub fn host_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_string())
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

/// Where the cursor is kept: beside the database, in the daemon's state directory.
pub fn cursor_path(ctx: &Ctx) -> PathBuf {
    ctx.db
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(CURSOR_FILE)
}

/// Watches and delivers until the process ends. Never returns on its own; every
/// failure to read is said and retried at the next poll, never fatal.
pub fn run(ctx: &Ctx, urls: &[String], every: Duration, stats: Arc<Stats>) {
    let sender = Sender::start(urls, &Retry::default(), QUEUE, Arc::clone(&stats));
    let mut watcher = Watcher::new(host_name());
    let manual_dir = crate::ctl::manual_dir(ctx);
    let cursor_file = cursor_path(ctx);
    let mut cursor = match load_cursor(&cursor_file) {
        Some(c) => c,
        None => loop {
            // No cursor yet: start at the current end, so history is not replayed.
            match Store::open_readonly(&ctx.db).and_then(|s| s.block_log_tail()) {
                Ok((row, key)) => {
                    let c = Cursor {
                        block_log: row,
                        block_log_key: key,
                        manual: crate::manual_log::end_position(&manual_dir),
                    };
                    save_or_say(&cursor_file, &c);
                    break c;
                }
                Err(e) => {
                    eprintln!("tfps_ctl serve: webhooks waiting for the database: {e}");
                    std::thread::sleep(every.max(Duration::from_secs(5)));
                }
            }
        },
    };
    let mut said = None::<String>;
    let mut saved = cursor.clone();
    loop {
        let more = match poll_once(ctx, &manual_dir, &mut cursor, &mut watcher, &sender) {
            Ok(more) => {
                said = None;
                more
            }
            Err(e) => {
                if said.as_deref() != Some(&e) {
                    eprintln!("tfps_ctl serve: webhooks: {e}");
                    said = Some(e);
                }
                false
            }
        };
        // Saved only when nothing is in flight: an event still queued when
        // `serve` stops is then sent again after the restart, never skipped.
        if stats.idle() && cursor != saved {
            save_or_say(&cursor_file, &cursor);
            saved = cursor.clone();
        }
        if !more {
            std::thread::sleep(every);
        }
    }
}

fn save_or_say(path: &Path, cursor: &Cursor) {
    if let Err(e) = save_cursor(path, cursor) {
        eprintln!("tfps_ctl serve: webhooks: {e}");
    }
}

/// One poll: read what is new, send its events, move the cursor. Returns whether
/// there is more to read at once.
fn poll_once(
    ctx: &Ctx,
    manual_dir: &Path,
    cursor: &mut Cursor,
    watcher: &mut Watcher,
    sender: &Sender,
) -> Result<bool, String> {
    let store = Store::open_readonly(&ctx.db)?;
    // Row numbers that started again (the table emptied by pruning, then
    // refilled) are read from the first row: every row of a refilled table
    // is new.
    let batch = store.block_log_batch(cursor.block_log, &cursor.block_log_key, ROWS_PER_POLL)?;
    let more = batch.rows.len() == ROWS_PER_POLL;
    let last = batch
        .rows
        .last()
        .map(|(row, r)| (*row, crate::store::block_log_key(r)));
    if batch.restarted && last.is_none() {
        cursor.block_log = 0;
        cursor.block_log_key.clear();
    }
    let blocks: Vec<BlockRow> = batch.rows.into_iter().map(|(_, r)| r).collect();
    let (manual, manual_pos, unreadable) =
        crate::manual_log::read_after(manual_dir, &cursor.manual);
    if unreadable > 0 {
        eprintln!(
            "WARNING: {unreadable} line(s) of the manual-action record could not be read; \
             their webhook events are not sent"
        );
    }

    let run = ctx
        .state
        .as_deref()
        .and_then(|p| crate::state::read_live(p).ok())
        .map(|s| (s.pid, s.pid_start))
        .unwrap_or((0, 0));
    let map = crate::ctl::map_entries(ctx).ok();
    let known: HashSet<Ipv4Addr> = match &map {
        Some(entries) if watcher.needs_baseline(run) => known_among(&store, manual_dir, entries),
        _ => HashSet::new(),
    };
    let events = watcher.poll(&Seen {
        blocks: &blocks,
        manual: &manual,
        map: map.as_deref().map(|m| (run, m)),
        known: &known,
        now_wall: crate::ctl::now(),
        now_mono: crate::xdp::monotonic_ns(),
    });
    for e in &events {
        sender.send(e);
    }
    if let Some((row, key)) = last {
        cursor.block_log = row;
        cursor.block_log_key = key;
    }
    cursor.manual = manual_pos;
    Ok(more)
}

/// Of the addresses in the map, those this host's own blocking explains: what a
/// baseline watches, so APIBAN feed blocks never produce events.
///
/// An address the audit log mentions is ours unless its map entry is
/// permanent and the address is on the APIBAN feed: the perimeter blocked it
/// once, but what holds it now is the feed's permanent block. An address whose
/// latest manual action is a ban is ours either way.
fn known_among(store: &Store, manual_dir: &Path, entries: &[(Ipv4Addr, u64)]) -> HashSet<Ipv4Addr> {
    let among = crate::ctl::map_addresses(entries);
    let logged = store.logged_among(&among).unwrap_or_default();
    let feed = store.apiban_among(&among).unwrap_or_default();
    let mut known: HashSet<Ipv4Addr> = entries
        .iter()
        .filter(|(ip, until)| {
            let s = ip.to_string();
            logged.contains(&s) && !(*until == 0 && feed.contains(&s))
        })
        .map(|(ip, _)| *ip)
        .collect();
    let wanted: HashSet<Ipv4Addr> = entries.iter().map(|(ip, _)| *ip).collect();
    let manual = crate::manual_log::latest_for(manual_dir, &wanted);
    known.extend(
        manual
            .by_ip
            .iter()
            .filter(|(_, a)| a.verb == ManualVerb::Ban)
            .map(|(ip, _)| *ip),
    );
    known
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Instant;

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, last)
    }

    fn row(last: u8, ts: u32) -> BlockRow {
        BlockRow {
            ts,
            ip: ip(last).to_string(),
            reason: "scanner".into(),
            detail: "friendly-scanner".into(),
        }
    }

    fn manual(verb: ManualVerb, last: u8, ts: u32) -> ManualAction {
        ManualAction {
            ts,
            verb,
            ip: ip(last),
            source: "panel".into(),
            reason: Some("customer asked".into()),
            expires: None,
        }
    }

    const RUN: DaemonRun = (100, 5);
    const SEC: u64 = 1_000_000_000;

    /// One poll with the given inputs, at `now` seconds of both clocks.
    fn poll(
        w: &mut Watcher,
        blocks: &[BlockRow],
        manual: &[ManualAction],
        map: Option<&[(Ipv4Addr, u64)]>,
        known: &[Ipv4Addr],
        now: u64,
    ) -> Vec<(&'static str, Ipv4Addr, String)> {
        let known: HashSet<Ipv4Addr> = known.iter().copied().collect();
        w.poll(&Seen {
            blocks,
            manual,
            map: map.map(|m| (RUN, m)),
            known: &known,
            now_wall: 1_795_000_000 + now as u32,
            now_mono: now * SEC,
        })
        .into_iter()
        .map(|e| (e.event, e.ip.parse().unwrap(), e.source))
        .collect()
    }

    fn baseline(w: &mut Watcher, map: &[(Ipv4Addr, u64)], known: &[Ipv4Addr]) {
        assert!(
            poll(w, &[], &[], Some(map), known, 1).is_empty(),
            "a baseline reports nothing"
        );
    }

    #[test]
    fn a_block_is_reported_with_its_reason_and_expiry() {
        let mut w = Watcher::new("sbc1".into());
        baseline(&mut w, &[], &[]);
        let map = [(ip(1), 3600 * SEC)];
        let known = HashSet::new();
        let events = w.poll(&Seen {
            blocks: &[row(1, 1_795_000_000)],
            manual: &[],
            map: Some((RUN, &map)),
            known: &known,
            now_wall: 1_795_000_000,
            now_mono: 0,
        });
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(
            serde_json::to_string(e).unwrap(),
            r#"{"event":"block","ip":"203.0.113.1","ts":1795000000,"reason":"scanner","detail":"friendly-scanner","expires":1795003600,"source":"tfps","host":"sbc1"}"#
        );
    }

    /// The three ends of a block are told apart: its expiry passing, a manual
    /// unban, and a removal nothing explains.
    #[test]
    fn expiry_manual_unban_and_unexplained_removal_are_told_apart() {
        let mut w = Watcher::new("h".into());
        let all = [(ip(1), 10 * SEC), (ip(2), 0), (ip(3), 0)];
        baseline(&mut w, &all, &[ip(1), ip(2), ip(3)]);

        // 1 expires at 10 s; it is reported once its instant passes.
        assert!(poll(&mut w, &[], &[], Some(&all), &[], 5).is_empty());
        assert_eq!(
            poll(&mut w, &[], &[], Some(&all), &[], 11),
            [("expired", ip(1), "tfps".into())]
        );

        // 2 is unbanned by hand: reported with who did it.
        let left = [(ip(3), 0)];
        assert_eq!(
            poll(
                &mut w,
                &[],
                &[manual(ManualVerb::Unban, 2, 1)],
                Some(&left),
                &[],
                12
            ),
            [("unblock", ip(2), "panel".into())]
        );

        // 3 vanishes with nothing to explain it: after one poll of grace,
        // reported as an unblock by an unknown hand.
        assert!(
            poll(&mut w, &[], &[], Some(&[]), &[], 13).is_empty(),
            "grace"
        );
        assert_eq!(
            poll(&mut w, &[], &[], Some(&[]), &[], 14),
            [("unblock", ip(3), "unknown".into())]
        );
        assert!(
            poll(&mut w, &[], &[], Some(&[]), &[], 15).is_empty(),
            "once only"
        );
    }

    /// The grace poll is what stops an unban whose record lands a moment after
    /// the map changed from being reported as unexplained.
    #[test]
    fn an_unban_recorded_a_poll_late_is_still_a_manual_unban() {
        let mut w = Watcher::new("h".into());
        baseline(&mut w, &[(ip(1), 0)], &[ip(1)]);
        assert!(poll(&mut w, &[], &[], Some(&[]), &[], 2).is_empty());
        assert_eq!(
            poll(
                &mut w,
                &[],
                &[manual(ManualVerb::Unban, 1, 2)],
                Some(&[]),
                &[],
                3
            ),
            [("unblock", ip(1), "panel".into())]
        );
        assert!(poll(&mut w, &[], &[], Some(&[]), &[], 4).is_empty());
    }

    #[test]
    fn apiban_feed_blocks_never_produce_events() {
        let mut w = Watcher::new("h".into());
        baseline(&mut w, &[(ip(9), 0)], &[]); // not in the audit log or manual record
        assert!(poll(&mut w, &[], &[], Some(&[]), &[], 2).is_empty());
        assert!(poll(&mut w, &[], &[], Some(&[]), &[], 3).is_empty());
    }

    #[test]
    fn an_unreadable_map_concludes_nothing() {
        let mut w = Watcher::new("h".into());
        baseline(&mut w, &[(ip(1), 0)], &[ip(1)]);
        for t in 2..6 {
            assert!(poll(&mut w, &[], &[], None, &[], t).is_empty());
        }
        assert!(
            poll(&mut w, &[], &[], Some(&[(ip(1), 0)]), &[], 7).is_empty(),
            "still there"
        );
    }

    #[test]
    fn a_daemon_restart_takes_a_new_baseline_instead_of_reporting_everything() {
        let mut w = Watcher::new("h".into());
        baseline(&mut w, &[(ip(1), 0), (ip(2), 0)], &[ip(1), ip(2)]);
        let known = HashSet::new();
        let events = w.poll(&Seen {
            blocks: &[],
            manual: &[],
            map: Some(((101, 9), &[])), // a new run, a fresh empty map
            known: &known,
            now_wall: 0,
            now_mono: 0,
        });
        assert!(events.is_empty(), "{events:?}");
        assert!(poll_run(&mut w, (101, 9), 2).is_empty());
        assert!(poll_run(&mut w, (101, 9), 3).is_empty());
    }

    fn poll_run(w: &mut Watcher, run: DaemonRun, now: u64) -> Vec<Event> {
        let known = HashSet::new();
        w.poll(&Seen {
            blocks: &[],
            manual: &[],
            map: Some((run, &[])),
            known: &known,
            now_wall: 0,
            now_mono: now * SEC,
        })
    }

    #[test]
    fn a_manual_ban_is_a_block_event_and_is_watched() {
        let mut w = Watcher::new("h".into());
        baseline(&mut w, &[], &[]);
        let mut ban = manual(ManualVerb::Ban, 4, 2);
        ban.expires = Some(1_795_000_100);
        let events = w.poll(&Seen {
            blocks: &[],
            manual: &[ban],
            map: Some((RUN, &[(ip(4), 50 * SEC)])),
            known: &HashSet::new(),
            now_wall: 1_795_000_002,
            now_mono: 2 * SEC,
        });
        assert_eq!(events.len(), 1);
        assert_eq!(
            (
                events[0].event,
                events[0].reason.as_deref(),
                events[0].detail.as_deref()
            ),
            ("block", Some("manual"), Some("customer asked"))
        );
        assert_eq!(events[0].expires, Some(1_795_000_100));
        assert_eq!(
            poll(&mut w, &[], &[], Some(&[(ip(4), 50 * SEC)]), &[], 51),
            [("expired", ip(4), "tfps".into())]
        );
    }

    /// With enforcement off the daemon logs blocks it never places; they are not
    /// watched forever, and end without an event.
    #[test]
    fn a_logged_block_that_never_reached_the_map_is_let_go_quietly() {
        let mut w = Watcher::new("h".into());
        baseline(&mut w, &[], &[]);
        assert_eq!(
            poll(&mut w, &[row(1, 1)], &[], Some(&[]), &[], 2).len(),
            1,
            "the block event"
        );
        assert!(w.watched.is_empty(), "not watched");
        for t in 3..6 {
            assert!(poll(&mut w, &[], &[], Some(&[]), &[], t).is_empty());
        }
    }

    /// A permanent block on the APIBAN feed is the feed's, even when the
    /// perimeter once blocked the same address; a perimeter block with an
    /// expiry, and a manual ban, are ours.
    #[test]
    fn the_baseline_watches_only_this_hosts_own_blocks() {
        let p = std::env::temp_dir().join(format!("tfps-hooks-known-{}.db", std::process::id()));
        let dir = p.with_extension("manual");
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_dir_all(&dir);
        let mut s = Store::open(&p).unwrap();
        for last in [1, 2] {
            s.log_block(100, ip(last), "scanner", "x").unwrap();
        }
        s.apiban_add(&[ip(2), ip(3)], 100).unwrap();
        crate::manual_log::append(&dir, &[manual(ManualVerb::Ban, 4, 1_795_000_000)], 0o600)
            .unwrap();
        let entries = [
            (ip(1), 50 * SEC), // perimeter block with an expiry: ours
            (ip(2), 0),        // once a perimeter block, now the feed's permanent one
            (ip(3), 0),        // the feed only
            (ip(4), 0),        // a manual ban
        ];
        let mut got: Vec<_> = known_among(&s, &dir, &entries).into_iter().collect();
        got.sort();
        assert_eq!(got, [ip(1), ip(4)]);
        drop(s);
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_cursor_survives_a_restart() {
        let path = std::env::temp_dir().join(format!("tfps-hooks-cursor-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert_eq!(load_cursor(&path), None);
        let c = Cursor {
            block_log: 42,
            block_log_key: "1795000000\t203.0.113.1\tscanner\tx".into(),
            manual: Position {
                file: "manual_actions-202611.jsonl".into(),
                offset: 120,
            },
        };
        save_cursor(&path, &c).unwrap();
        assert_eq!(load_cursor(&path), Some(c));
        let _ = std::fs::remove_file(&path);
    }

    // ── delivery ───────────────────────────────────────────────────────────

    /// A local receiver that answers every request with `status` after `delay`,
    /// and passes each body it got to the returned channel.
    fn receiver(status: u16, delay: Duration) -> (String, Receiver<String>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/hook", l.local_addr().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let tx = tx.clone();
                std::thread::spawn(move || {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while let Ok(n) = s.read(&mut chunk) {
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        let text = String::from_utf8_lossy(&buf);
                        if let Some((head, body)) = text.split_once("\r\n\r\n") {
                            let len: usize = head
                                .lines()
                                .find_map(|l| {
                                    let (k, v) = l.split_once(':')?;
                                    k.eq_ignore_ascii_case("content-length")
                                        .then(|| v.trim().parse().ok())?
                                })
                                .unwrap_or(0);
                            if body.len() >= len {
                                let _ = tx.send(body.to_string());
                                break;
                            }
                        }
                    }
                    std::thread::sleep(delay);
                    let _ = write!(
                        s,
                        "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                });
            }
        });
        (url, rx)
    }

    fn quick() -> Retry {
        Retry {
            timeout: Duration::from_millis(500),
            backoff: vec![Duration::from_millis(20), Duration::from_millis(20)],
        }
    }

    fn event() -> Event {
        Event {
            event: "block",
            ip: "203.0.113.1".into(),
            ts: 1,
            reason: None,
            detail: None,
            expires: None,
            source: "tfps".into(),
            host: "h".into(),
        }
    }

    fn wait_for(stats: &Stats, url: usize, result: &str, n: u64) {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            if stats
                .snapshot()
                .iter()
                .any(|&(i, r, c)| i == url && r == result && c >= n)
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("{url}/{result} never reached {n}: {:?}", stats.snapshot());
    }

    #[test]
    fn every_url_receives_the_event_as_json() {
        let (a, ra) = receiver(200, Duration::ZERO);
        let (b, rb) = receiver(204, Duration::ZERO);
        let stats = Arc::new(Stats::new(2));
        let s = Sender::start(&[a, b], &quick(), 10, Arc::clone(&stats));
        s.send(&event());
        let expected = serde_json::to_string(&event()).unwrap();
        assert_eq!(ra.recv_timeout(Duration::from_secs(5)).unwrap(), expected);
        assert_eq!(rb.recv_timeout(Duration::from_secs(5)).unwrap(), expected);
        wait_for(&stats, 0, "delivered", 1);
        wait_for(&stats, 1, "delivered", 1);
    }

    #[test]
    fn a_failing_url_is_retried_then_counted_as_failed() {
        let (url, rx) = receiver(500, Duration::ZERO);
        let stats = Arc::new(Stats::new(1));
        let s = Sender::start(&[url], &quick(), 10, Arc::clone(&stats));
        s.send(&event());
        wait_for(&stats, 0, "failed", 1);
        assert_eq!(rx.try_iter().count(), 3, "one attempt and two retries");
    }

    /// A URL that never answers holds only its own worker: the other URL gets
    /// its events at once.
    #[test]
    fn a_dead_url_does_not_delay_the_others() {
        let (slow, _rs) = receiver(200, Duration::from_secs(30));
        let (fast, rf) = receiver(200, Duration::ZERO);
        let stats = Arc::new(Stats::new(2));
        let s = Sender::start(&[slow, fast], &quick(), 10, Arc::clone(&stats));
        let start = Instant::now();
        for _ in 0..3 {
            s.send(&event());
        }
        for _ in 0..3 {
            rf.recv_timeout(Duration::from_secs(2))
                .expect("the live URL is not held up");
        }
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
        wait_for(&stats, 1, "delivered", 3);
    }

    #[test]
    fn the_sender_is_idle_only_when_every_event_has_an_outcome() {
        let (url, rx) = receiver(200, Duration::from_millis(300));
        let stats = Arc::new(Stats::new(1));
        let s = Sender::start(&[url], &quick(), 10, Arc::clone(&stats));
        assert!(stats.idle());
        s.send(&event());
        assert!(
            !stats.idle(),
            "in flight: the cursor must not move past it yet"
        );
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        wait_for(&stats, 0, "delivered", 1);
        assert!(stats.idle());
    }

    #[test]
    fn a_full_queue_drops_and_counts_instead_of_waiting() {
        let (slow, _r) = receiver(200, Duration::from_secs(30));
        let stats = Arc::new(Stats::new(1));
        let s = Sender::start(&[slow], &quick(), 1, Arc::clone(&stats));
        let start = Instant::now();
        for _ in 0..10 {
            s.send(&event());
        }
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "send never waits"
        );
        wait_for(&stats, 0, "queue_full", 7);
    }
}
