//! The dashboard against sample data, for looking at it and taking screenshots
//! without a daemon, a kernel map or a database.
//!
//! ```sh
//! cargo run -p tfps --example dashboard_demo
//! # then open http://127.0.0.1:19060/
//! ```
//!
//! Pass `--token SECRET` to see the page ask for a token. Every value here is
//! invented; the addresses are from the documentation ranges (RFC 5737).

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, TcpListener};
use std::sync::Arc;

use tfps::api::{allowed_hosts, serve, Backend, Options};
use tfps::ctl::{
    banned_doc, blocks_doc, learned_doc, log_doc, now, stats_doc, status_doc, traffic_doc,
    BannedDoc, DbCounts, LogDoc, StatsDoc, StatusDoc, UnbanOutcome,
};
use tfps::store::BlockRow;

const LISTEN: &str = "127.0.0.1:19060";

/// Blocks in the demo map: most of the 762 documentation addresses.
const BLOCKED: usize = 700;

/// The reasons the perimeter gives, with a detail each and how often they occur.
const REASONS: [(&str, &[&str], u32); 6] = [
    (
        "scanner",
        &["friendly-scanner", "sipvicious", "sipcli/v1.8", "pplsip"],
        40,
    ),
    (
        "user-agent",
        &[
            "VaxSIPUserAgent/3.1",
            "PortSIP VoIP SDK",
            "Cisco-SIPGateway/IOS-12.x",
        ],
        22,
    ),
    ("auth-failed", &["rejected"], 18),
    ("reg-scan", &["no-success"], 9),
    ("injection", &["'", "xp_cmdshell", "<script>"], 4),
    ("auth-volume", &["no-answer"], 3),
];

/// A small deterministic generator, so every run looks the same.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

struct Demo {
    blocks: Vec<BannedDoc>,
    /// `(time, address, reason, detail)`, newest first.
    log: Vec<(u32, String, &'static str, &'static str)>,
    start: u32,
}

impl Demo {
    fn new() -> Self {
        let now = now();
        let mut rng = Rng(0x5eed_1234_abcd_9876);
        let total: u32 = REASONS.iter().map(|r| r.2).sum();
        let pick = |rng: &mut Rng| {
            let mut n = rng.below(u64::from(total)) as u32;
            for (reason, details, weight) in REASONS {
                if n < weight {
                    return (reason, details[rng.below(details.len() as u64) as usize]);
                }
                n -= weight;
            }
            ("scanner", "friendly-scanner")
        };
        let ip = |rng: &mut Rng| {
            let nets = [[198, 51, 100], [203, 0, 113], [192, 0, 2]];
            let n = nets[rng.below(3) as usize];
            Ipv4Addr::new(n[0], n[1], n[2], 1 + rng.below(254) as u8).to_string()
        };

        // Every address in the three documentation ranges once, shuffled: a
        // block map holds each address at most once, and so must the demo.
        let mut pool: Vec<String> = [[198, 51, 100], [203, 0, 113], [192, 0, 2]]
            .iter()
            .flat_map(|n| (1..=254u8).map(move |h| Ipv4Addr::new(n[0], n[1], n[2], h).to_string()))
            .collect();
        for i in (1..pool.len()).rev() {
            pool.swap(i, rng.below(i as u64 + 1) as usize);
        }
        let mut blocks = Vec::new();
        for (i, addr) in pool.into_iter().take(BLOCKED).enumerate() {
            let first = now - rng.below(3_500) as u32;
            let doc = match i % 10 {
                // Feed entries: no reason of ours, no expiry for a week.
                0 | 1 => banned_doc(
                    &addr,
                    Some(("apiban", "feed")),
                    None,
                    Some(now + 6 * 86_400),
                ),
                2 if i % 30 == 2 => banned_doc(
                    &addr,
                    Some(("manual", "fraud ticket #4821")),
                    Some(first),
                    None,
                )
                .with_source(Some("noc")),
                _ => {
                    let (reason, detail) = pick(&mut rng);
                    banned_doc(
                        &addr,
                        Some((reason, detail)),
                        Some(first),
                        Some(first + 3_600),
                    )
                }
            };
            blocks.push(doc);
        }

        let mut log = Vec::new();
        let mut ts = now - 20;
        for _ in 0..50 {
            let (reason, detail) = pick(&mut rng);
            log.push((ts, ip(&mut rng), reason, detail));
            ts -= 15 + rng.below(240) as u32;
        }
        Demo {
            blocks,
            log,
            start: now - 6 * 86_400 - 5 * 3_600 - 1_380,
        }
    }

    fn windows() -> [Vec<(String, u32)>; 3] {
        let scale = |k: u32| {
            REASONS
                .iter()
                .map(|(r, _, w)| (r.to_string(), w * k))
                .collect::<Vec<_>>()
        };
        [scale(2), scale(31), scale(197)]
    }
}

impl Backend for Demo {
    fn status(&self) -> StatusDoc {
        status_doc(
            Ok((self.blocks.len(), "own map id 412 (tfps)".into())),
            Some((18_442, 18_442, now() - 140)),
            std::path::Path::new("/var/lib/tfps/tfps.db"),
            env!("CARGO_PKG_VERSION"),
        )
    }
    fn stats(&self) -> Result<StatsDoc, String> {
        let now = now();
        let [h, d, w] = Self::windows();
        let line = "packets=48211934 sip=47933112 responses=23190402 keepalive=1210442 \
                    not_sip=278822 noise=96112 injection=412 auth_att=512004 auth_fail=9402 \
                    auth_ok=498120 invites=1820433 intl=40221 blocks=6114 would_block=0 \
                    hep_received=912044 hep_sip=911870 hep_rejected_sender=0 hep_bad_auth=0 \
                    hep_malformed=0 hep_skipped_udp=150 hep_stale=24 hep_dropped=0";
        let feed = self
            .blocks
            .iter()
            .filter(|b| b.reason.as_deref() == Some("apiban"));
        let feed = feed.count();
        let mut ignoreip = BTreeMap::new();
        ignoreip.insert("10.0.0.0/8".to_string(), Some(18_204));
        ignoreip.insert("203.0.113.7".to_string(), Some(0));
        ignoreip.insert("this host 192.0.2.10".to_string(), Some(3_311));
        Ok(stats_doc(
            Some((52_904_118, 4_712_993, 18_220)),
            Some((self.blocks.len(), self.blocks.len() - feed, feed)),
            traffic_doc(Some(line), Some(now - 140), now),
            Some(now - self.start),
            Some(ignoreip),
            None,
            learned_doc(18_442, 18_442, 61, 40_221),
            blocks_doc(4_812, h, d, w),
        ))
    }
    fn banned(&self) -> Result<Vec<BannedDoc>, String> {
        Ok(self.blocks.clone())
    }
    fn banned_one(&self, ip: Ipv4Addr) -> Result<Option<BannedDoc>, String> {
        let ip = ip.to_string();
        Ok(self.blocks.iter().find(|b| b.ip == ip).cloned())
    }
    fn log(&self, limit: usize, _: Option<&str>) -> Result<Vec<LogDoc>, String> {
        Ok(self
            .log
            .iter()
            .take(limit)
            .map(|(ts, ip, reason, detail)| {
                let row = BlockRow {
                    ts: *ts,
                    ip: ip.clone(),
                    reason: reason.to_string(),
                    detail: detail.to_string(),
                };
                log_doc(&row, Some(ts + 3_600), None, true, "block")
            })
            .collect())
    }
    fn kernel_counters(&self) -> Option<(u64, u64, u64)> {
        Some((52_904_118, 4_712_993, 18_220))
    }
    fn map_counts(&self) -> Result<(usize, usize), String> {
        Ok((self.blocks.len(), 0))
    }
    fn db_counts(&self) -> Result<DbCounts, String> {
        Err("not part of the demo".into())
    }
    fn unban(&self, _: &[String], _: &str, _: Option<&str>) -> Result<UnbanOutcome, String> {
        Err("the demo is read-only".into())
    }
}

fn main() -> std::io::Result<()> {
    let token = std::env::args().skip_while(|a| a != "--token").nth(1);
    let listener = TcpListener::bind(LISTEN)?;
    let hosts = allowed_hosts(LISTEN.parse().expect("an address"), &[]);
    eprintln!("dashboard demo on http://{LISTEN}/ (sample data)");
    serve(
        listener,
        Arc::new(Demo::new()),
        Options::new(false, hosts, token),
    )
}
