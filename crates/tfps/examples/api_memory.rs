//! Peak memory of `tfps_ctl serve` answering `/v1/blocks` for a full block map.
//!
//! The kernel map holds at most 65,536 entries. This serves a simulated map of
//! that size through the real routing, response building and worker pool, and
//! builds the same per-address tables the real attribution builds (summaries,
//! reasons, feed membership) for every request. Run it, hit it from separate
//! processes so the clients' memory is not counted, then read the server's peak
//! resident set from /proc:
//!
//! ```sh
//! cargo run --release -p tfps --example api_memory &
//! for i in 1 2 3 4; do curl -s -o /dev/null -H 'Host: 127.0.0.1:19099' \
//!     127.0.0.1:19099/v1/blocks & done; wait
//! grep VmHWM /proc/$(pgrep -f examples/api_memory)/status
//! ```
//!
//! The kernel map read itself (12 bytes per entry) is not simulated.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, TcpListener};
use std::sync::Arc;

use tfps::api::{serve, Backend, Options};
use tfps::ctl::{banned_doc, BannedDoc, DbCounts, LogDoc, StatsDoc, StatusDoc, UnbanOutcome};

const ENTRIES: u32 = 65_536;

struct FullMap;

impl Backend for FullMap {
    fn status(&self) -> StatusDoc {
        unimplemented!("only /v1/blocks is measured")
    }
    fn stats(&self) -> Result<StatsDoc, String> {
        Err("not measured".into())
    }
    fn banned(&self) -> Result<Vec<BannedDoc>, String> {
        // The same shapes the real path holds at once: the map's addresses, the
        // per-address audit summary, the feed matches, then the documents.
        let entries: Vec<(Ipv4Addr, u64)> = (0..ENTRIES)
            .map(|i| {
                (
                    Ipv4Addr::from(0x0a00_0000 + i),
                    u64::from(i) * 1_000_000_000,
                )
            })
            .collect();
        let among: HashSet<String> = entries.iter().map(|(ip, _)| ip.to_string()).collect();
        let audit: HashMap<String, (String, String, u32)> = among
            .iter()
            .map(|ip| {
                (
                    ip.clone(),
                    (
                        "user-agent".to_string(),
                        "friendly-scanner sipvicious/0.3.4".to_string(),
                        1_795_000_000,
                    ),
                )
            })
            .collect();
        let apiban: HashSet<String> = among.iter().take(2_000).cloned().collect();
        Ok(entries
            .iter()
            .map(|(ip, until)| {
                let s = ip.to_string();
                let why = audit
                    .get(&s)
                    .map(|(r, d, _)| (r.as_str(), d.as_str()))
                    .or_else(|| apiban.contains(&s).then_some(("apiban", "feed")));
                let expires = (*until > 0).then_some(1_795_003_600);
                banned_doc(&s, why, Some(1_795_000_000), expires)
            })
            .collect())
    }
    fn banned_one(&self, _: Ipv4Addr) -> Result<Option<BannedDoc>, String> {
        Ok(None)
    }
    fn log(&self, _: usize, _: Option<&str>) -> Result<Vec<LogDoc>, String> {
        Ok(Vec::new())
    }
    fn kernel_counters(&self) -> Option<(u64, u64, u64)> {
        None
    }
    fn map_counts(&self) -> Result<(usize, usize), String> {
        Ok((ENTRIES as usize, 0))
    }
    fn db_counts(&self) -> Result<DbCounts, String> {
        Err("not measured".into())
    }
    fn unban(&self, _: &[String], _: &str, _: Option<&str>) -> Result<UnbanOutcome, String> {
        Err("not measured".into())
    }
}

fn main() -> std::io::Result<()> {
    let listen = "127.0.0.1:19099";
    let listener = TcpListener::bind(listen)?;
    eprintln!("serving a simulated {ENTRIES}-entry map on http://{listen}/v1/blocks");
    serve(
        listener,
        Arc::new(FullMap),
        Options::new(false, vec![listen.to_string()], None),
    )
}
