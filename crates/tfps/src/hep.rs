//! The daemon's HEP3 listener: the decrypted SIP an application server mirrors.
//!
//! It runs on its own thread, like APIBAN, so the packet loop never waits on it.
//! The thread reads the socket, drops senders that are not allowed, parses and
//! filters each packet (`tfps_core::hep`), and hands what passes to the main loop
//! over a **bounded** channel. When the main loop falls behind, a message is
//! dropped and counted rather than queued without limit: HEP must never slow the
//! wire capture down.
//!
//! The main loop then judges each message exactly as it judges a packet off the
//! wire, with one difference: a message that arrived over TCP has a source
//! address the TCP handshake proved, so it is not one-way evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tfps_core::hep::{classify, parse, Filter, Skip, Transport};

use crate::config::{HepConfig, HepTransport};

/// How many messages may wait for the main loop.
pub const QUEUE: usize = 4096;

/// How many payload bytes may wait for the main loop. One datagram can carry
/// almost 64 KiB, so the message count alone would let an allowed sender hold
/// about 256 MiB; this caps it at 16 MiB, whichever limit is reached first.
pub const QUEUE_BYTES: usize = 16 * 1024 * 1024;

/// A message captured more than this many seconds before it arrived is stale: a
/// replayed backlog must not trigger blocks for behaviour that is over.
pub const STALE_SECS: u32 = 5;

/// One mirrored SIP message, for the main loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivered {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub transport: Transport,
    pub payload: Vec<u8>,
    /// The datagram itself cannot have been forged: it came from a loopback
    /// address, which the network cannot fake, or it carried the configured
    /// `auth_key`. Only then is the transport it claims believed.
    pub proven: bool,
}

impl Delivered {
    /// Whether the message's source address could have been forged, for
    /// `--no-enforce-one-way`. A TCP transport says the handshake proved it, but
    /// that is the HEP sender's claim, believed only from a sender that is
    /// itself [`proven`](Self::proven).
    pub fn spoofable(&self) -> bool {
        self.transport.spoofable() || !self.proven
    }
}

/// What the listener has done, shared with the main loop for its reports.
#[derive(Debug, Default)]
pub struct Counters {
    /// Datagrams read from the socket.
    pub received: AtomicU64,
    /// Messages handed to the engine.
    pub sip: AtomicU64,
    pub rejected_sender: AtomicU64,
    pub bad_auth: AtomicU64,
    pub malformed: AtomicU64,
    pub skipped_udp: AtomicU64,
    pub skipped_tcp: AtomicU64,
    pub skipped_ipv6: AtomicU64,
    pub skipped_proto: AtomicU64,
    pub stale: AtomicU64,
    /// Dropped because the queue to the main loop was full.
    pub dropped: AtomicU64,
    /// Payload bytes waiting in the queue: added by the listener, taken off by
    /// the main loop as it receives.
    queued_bytes: AtomicUsize,
}

impl Counters {
    /// Every counter, named as in the daemon's checkpointed stats line.
    pub fn snapshot(&self) -> [(&'static str, u64); 11] {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        [
            ("hep_received", g(&self.received)),
            ("hep_sip", g(&self.sip)),
            ("hep_rejected_sender", g(&self.rejected_sender)),
            ("hep_bad_auth", g(&self.bad_auth)),
            ("hep_malformed", g(&self.malformed)),
            ("hep_skipped_udp", g(&self.skipped_udp)),
            ("hep_skipped_tcp", g(&self.skipped_tcp)),
            ("hep_skipped_ipv6", g(&self.skipped_ipv6)),
            ("hep_skipped_proto", g(&self.skipped_proto)),
            ("hep_stale", g(&self.stale)),
            ("hep_dropped", g(&self.dropped)),
        ]
    }

    fn bump(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }
}

/// The listener's settings, taken from the configuration once.
#[derive(Debug, Clone)]
pub struct Settings {
    pub allow_from: Vec<Ipv4Addr>,
    pub tcp: bool,
    pub udp: bool,
    pub auth_key: Option<Vec<u8>>,
}

impl Settings {
    pub fn from_config(c: &HepConfig) -> Self {
        Settings {
            allow_from: c.allow_from.clone(),
            tcp: c.transports.contains(&HepTransport::Tcp),
            udp: c.transports.contains(&HepTransport::Udp),
            auth_key: c.auth_key.as_ref().map(|k| k.as_bytes().to_vec()),
        }
    }
}

/// Judges one datagram from `sender`, counting what happened to it. Returns the
/// message when it should reach the engine.
pub fn handle(
    datagram: &[u8],
    sender: SocketAddr,
    s: &Settings,
    now: u32,
    counters: &Counters,
) -> Option<Delivered> {
    Counters::bump(&counters.received);
    let sender_v4 = match sender {
        SocketAddr::V4(a) => Some(*a.ip()),
        SocketAddr::V6(a) => a.ip().to_ipv4_mapped(),
    };
    let allowed = sender_v4.is_some_and(|ip| s.allow_from.contains(&ip));
    if !allowed {
        Counters::bump(&counters.rejected_sender);
        return None;
    }
    let Ok(hep) = parse(datagram) else {
        Counters::bump(&counters.malformed);
        return None;
    };
    let filter = Filter {
        tcp: s.tcp,
        udp: s.udp,
        auth_key: s.auth_key.as_deref(),
        now,
        stale_secs: STALE_SECS,
    };
    match classify(&hep, &filter) {
        Ok(m) => Some(Delivered {
            src: m.src,
            dst: m.dst,
            src_port: m.src_port,
            dst_port: m.dst_port,
            transport: m.transport,
            payload: m.payload.to_vec(),
            // `classify` has already refused a packet without the key when one
            // is configured, so a configured key means this one carried it.
            proven: sender_v4.is_some_and(|ip| ip.is_loopback()) || s.auth_key.is_some(),
        }),
        Err(skip) => {
            Counters::bump(match skip {
                Skip::BadAuth => &counters.bad_auth,
                Skip::Ipv6 => &counters.skipped_ipv6,
                Skip::Proto | Skip::Compressed => &counters.skipped_proto,
                Skip::Udp => &counters.skipped_udp,
                Skip::Tcp => &counters.skipped_tcp,
                Skip::Stale => &counters.stale,
                Skip::Incomplete => &counters.malformed,
            });
            None
        }
    }
}

/// Offers a message to the main loop without waiting. Counts it as handed over,
/// or as dropped when the queue is full, by messages or by bytes. Returns false
/// when the main loop is gone.
pub fn offer(tx: &SyncSender<Delivered>, m: Delivered, counters: &Counters) -> bool {
    let len = m.payload.len();
    // One listener thread adds; the main loop only subtracts. So the room seen
    // here can only grow before the add below.
    if counters.queued_bytes.load(Ordering::Acquire) + len > QUEUE_BYTES {
        Counters::bump(&counters.dropped);
        return true;
    }
    counters.queued_bytes.fetch_add(len, Ordering::AcqRel);
    // Counted before it is handed over, and taken back if it is not: once the
    // main loop holds a message, its count is already there to read.
    Counters::bump(&counters.sip);
    match tx.try_send(m) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => {
            counters.sip.fetch_sub(1, Ordering::Relaxed);
            counters.queued_bytes.fetch_sub(len, Ordering::AcqRel);
            Counters::bump(&counters.dropped);
            true
        }
        Err(TrySendError::Disconnected(_)) => {
            counters.sip.fetch_sub(1, Ordering::Relaxed);
            counters.queued_bytes.fetch_sub(len, Ordering::AcqRel);
            false
        }
    }
}

/// With HEP on: no message mirrored for a port for this long, while TCP is seen
/// on it, is an alarm. Also how long a port counts as covered after its last one.
pub const SILENCE_SECS: u32 = 300;

/// Which SIP ports' TCP the HEP stream covers, port by port.
///
/// The wire capture counts TCP on the SIP ports it cannot read. HEP covers a
/// port only while messages for that port arrive over TCP: a stream for 443
/// says nothing about 5061, and HEP over UDP covers no TCP at all.
#[derive(Debug, Clone)]
pub struct Coverage {
    start: u32,
    /// TCP packets seen on the wire, per SIP port.
    tcp: BTreeMap<u16, u64>,
    /// Per port: when a TCP message for it last arrived over HEP, and the wire's
    /// TCP count for the port at that moment.
    mirrored: BTreeMap<u16, (u32, u64)>,
    /// Ports already alarmed about since their last HEP message.
    alarmed: BTreeSet<u16>,
}

/// A port whose TCP is seen on the wire with no HEP message for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Silent {
    pub port: u16,
    /// Seconds since its last HEP message (or since start, if none).
    pub secs: u32,
    /// TCP packets seen on it since then.
    pub packets: u64,
}

impl Coverage {
    pub fn new(start: u32) -> Self {
        Coverage {
            start,
            tcp: BTreeMap::new(),
            mirrored: BTreeMap::new(),
            alarmed: BTreeSet::new(),
        }
    }

    /// The wire capture saw a TCP packet for SIP port `port`.
    pub fn tcp_seen(&mut self, port: u16) {
        *self.tcp.entry(port).or_insert(0) += 1;
    }

    /// A message for SIP port `port` arrived over HEP with TCP transport.
    pub fn mirrored(&mut self, port: u16, now: u32) {
        let seen = self.tcp.get(&port).copied().unwrap_or(0);
        self.mirrored.insert(port, (now, seen));
        self.alarmed.remove(&port);
    }

    fn covered(&self, port: u16, now: u32) -> bool {
        self.mirrored
            .get(&port)
            .is_some_and(|(at, _)| now.saturating_sub(*at) < SILENCE_SECS)
    }

    /// TCP packets on ports HEP is not covering now.
    pub fn uncovered(&self, now: u32) -> u64 {
        self.tcp
            .iter()
            .filter(|(p, _)| !self.covered(**p, now))
            .map(|(_, n)| n)
            .sum()
    }

    /// TCP packets on all SIP ports.
    pub fn total(&self) -> u64 {
        self.tcp.values().sum()
    }

    /// Ports newly silent: TCP seen on them since their last HEP message, and
    /// none for `SILENCE_SECS`. Each is returned once until HEP covers it again.
    pub fn newly_silent(&mut self, now: u32) -> Vec<Silent> {
        let mut out = Vec::new();
        for (&port, &seen) in &self.tcp {
            let (at, seen_then) = self.mirrored.get(&port).copied().unwrap_or((self.start, 0));
            let secs = now.saturating_sub(at);
            if seen > seen_then && secs >= SILENCE_SECS && self.alarmed.insert(port) {
                out.push(Silent {
                    port,
                    secs,
                    packets: seen - seen_then,
                });
            }
        }
        out
    }
}

/// The main loop's end of the queue. Receiving a message gives its bytes back.
pub struct Inbox {
    rx: Receiver<Delivered>,
    counters: Arc<Counters>,
}

impl Inbox {
    pub fn new(rx: Receiver<Delivered>, counters: Arc<Counters>) -> Self {
        Inbox { rx, counters }
    }

    /// The next waiting message, if any, without blocking.
    pub fn try_recv(&self) -> Option<Delivered> {
        let m = self.rx.try_recv().ok()?;
        self.taken(&m);
        Some(m)
    }

    /// The next message, waiting up to `timeout` for one.
    pub fn recv_timeout(&self, timeout: std::time::Duration) -> Option<Delivered> {
        let m = self.rx.recv_timeout(timeout).ok()?;
        self.taken(&m);
        Some(m)
    }

    fn taken(&self, m: &Delivered) {
        self.counters
            .queued_bytes
            .fetch_sub(m.payload.len(), Ordering::AcqRel);
    }
}

/// Binds the listener and starts its thread. A bind failure is returned, so the
/// daemon can say so at startup instead of running without the input it was
/// configured to have.
pub fn spawn(c: &HepConfig, counters: Arc<Counters>) -> std::io::Result<(Inbox, SocketAddr)> {
    let sock = UdpSocket::bind(c.listen)?;
    let local = sock.local_addr()?;
    let settings = Settings::from_config(c);
    let (tx, rx) = mpsc::sync_channel(QUEUE);
    let inbox = Inbox::new(rx, Arc::clone(&counters));
    std::thread::Builder::new()
        .name("tfps-hep".into())
        .spawn(move || {
            let mut buf = vec![0u8; 65_535];
            loop {
                let (n, sender) = match sock.recv_from(&mut buf) {
                    Ok(r) => r,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        eprintln!("ALARM: HEP listener stopped: {e}");
                        return;
                    }
                };
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0);
                if let Some(m) = handle(&buf[..n], sender, &settings, now, &counters) {
                    if !offer(&tx, m, &counters) {
                        return; // the main loop is gone
                    }
                }
            }
        })?;
    Ok((inbox, local))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tfps_core::hep::build::{sip, Sip};
    use tfps_core::hep::{IPPROTO_TCP, IPPROTO_UDP};

    const CLIENT: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
    const SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
    const NOW: u32 = 1_795_000_000;

    fn loopback() -> SocketAddr {
        "127.0.0.1:40000".parse().unwrap()
    }

    fn packet(ip_proto: u8, ts: u32, key: Option<&str>) -> Vec<u8> {
        sip(&Sip {
            src: (CLIENT, 51_234),
            dst: (SERVER, 5061),
            ip_proto,
            ts,
            auth_key: key,
            payload: b"OPTIONS sip:x SIP/2.0\r\n\r\n",
        })
    }

    fn settings() -> Settings {
        Settings::from_config(&HepConfig::default())
    }

    fn count(c: &Counters, name: &str) -> u64 {
        c.snapshot()
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| *v)
            .expect(name)
    }

    #[test]
    fn a_tcp_message_from_loopback_is_delivered() {
        let c = Counters::default();
        let m = handle(
            &packet(IPPROTO_TCP, NOW, None),
            loopback(),
            &settings(),
            NOW,
            &c,
        )
        .expect("delivered");
        assert_eq!((m.src, m.dst), (CLIENT, SERVER));
        assert_eq!(m.transport, Transport::Tcp);
        assert_eq!(m.dst_port, Some(5061));
        assert_eq!(count(&c, "hep_received"), 1);
    }

    #[test]
    fn a_sender_not_allowed_is_dropped_and_counted() {
        let c = Counters::default();
        let stranger: SocketAddr = "192.0.2.9:40000".parse().unwrap();
        assert!(handle(
            &packet(IPPROTO_TCP, NOW, None),
            stranger,
            &settings(),
            NOW,
            &c
        )
        .is_none());
        assert_eq!(count(&c, "hep_rejected_sender"), 1);
        // An IPv4 sender seen through a dual-stack socket is still itself.
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:40000".parse().unwrap();
        assert!(handle(
            &packet(IPPROTO_TCP, NOW, None),
            mapped,
            &settings(),
            NOW,
            &c
        )
        .is_some());
    }

    #[test]
    fn each_refusal_has_its_counter() {
        let c = Counters::default();
        let keyed = Settings {
            auth_key: Some(b"s3cret".to_vec()),
            ..settings()
        };
        let lo = loopback();
        assert!(handle(
            &packet(IPPROTO_TCP, NOW, Some("wrong")),
            lo,
            &keyed,
            NOW,
            &c
        )
        .is_none());
        assert!(handle(
            &packet(IPPROTO_TCP, NOW, Some("s3cret")),
            lo,
            &keyed,
            NOW,
            &c
        )
        .is_some());
        assert!(handle(&packet(IPPROTO_UDP, NOW, None), lo, &settings(), NOW, &c).is_none());
        assert!(handle(
            &packet(IPPROTO_TCP, NOW - 60, None),
            lo,
            &settings(),
            NOW,
            &c
        )
        .is_none());
        assert!(handle(b"HEP3\x00\x05", lo, &settings(), NOW, &c).is_none());
        assert_eq!(count(&c, "hep_bad_auth"), 1);
        assert_eq!(count(&c, "hep_skipped_udp"), 1);
        assert_eq!(count(&c, "hep_stale"), 1);
        assert_eq!(count(&c, "hep_malformed"), 1);
        assert_eq!(count(&c, "hep_received"), 5);
    }

    #[test]
    fn a_full_queue_drops_and_counts_without_waiting() {
        let c = Counters::default();
        let (tx, rx) = mpsc::sync_channel(1);
        let m = handle(
            &packet(IPPROTO_TCP, NOW, None),
            loopback(),
            &settings(),
            NOW,
            &c,
        )
        .unwrap();
        assert!(offer(&tx, m.clone(), &c));
        assert!(offer(&tx, m.clone(), &c), "full is not an error");
        assert_eq!(count(&c, "hep_sip"), 1);
        assert_eq!(count(&c, "hep_dropped"), 1);
        drop(rx);
        let queued = c.queued_bytes.load(Ordering::Acquire);
        assert!(!offer(&tx, m, &c), "the main loop is gone");
        assert_eq!(count(&c, "hep_sip"), 1, "not counted as handed over");
        assert_eq!(
            c.queued_bytes.load(Ordering::Acquire),
            queued,
            "nor as queued"
        );
    }

    /// Large messages fill the byte budget before the message count, and
    /// receiving one gives its bytes back.
    #[test]
    fn the_queue_is_bounded_by_bytes_too() {
        let c = Arc::new(Counters::default());
        let (tx, rx) = mpsc::sync_channel(QUEUE);
        let inbox = Inbox::new(rx, Arc::clone(&c));
        let big = Delivered {
            src: CLIENT,
            dst: SERVER,
            src_port: None,
            dst_port: None,
            transport: Transport::Tcp,
            payload: vec![b'x'; 60_000],
            proven: true,
        };
        let fits = QUEUE_BYTES / big.payload.len();
        for _ in 0..fits + 10 {
            assert!(offer(&tx, big.clone(), &c));
        }
        assert_eq!(count(&c, "hep_sip"), fits as u64);
        assert_eq!(count(&c, "hep_dropped"), 10, "dropped by bytes, not count");
        assert!(inbox.try_recv().is_some());
        assert!(offer(&tx, big, &c), "room again once one is taken");
        assert_eq!(count(&c, "hep_sip"), fits as u64 + 1);
    }

    #[test]
    fn coverage_is_per_port_and_alarms_once_per_silence() {
        let start = 1_000;
        let mut c = Coverage::new(start);
        for _ in 0..3 {
            c.tcp_seen(443);
            c.tcp_seen(5061);
        }
        assert_eq!((c.total(), c.uncovered(start)), (6, 6));
        // 443 is mirrored; 5061 is not.
        c.mirrored(443, start + 10);
        assert_eq!(c.uncovered(start + 20), 3, "only 5061 is uncovered");
        let silent = c.newly_silent(start + SILENCE_SECS);
        assert_eq!(
            silent,
            [Silent {
                port: 5061,
                secs: SILENCE_SECS,
                packets: 3
            }],
            "443's stream does not hide 5061"
        );
        assert!(c.newly_silent(start + SILENCE_SECS + 60).is_empty(), "once");
        // 443 goes quiet while its TCP continues.
        c.tcp_seen(443);
        let later = start + 10 + SILENCE_SECS;
        assert_eq!(c.uncovered(later), 7, "443 no longer counts as covered");
        assert_eq!(c.newly_silent(later)[0].port, 443);
        // HEP for 5061 resumes: covered again, and it can alarm again later.
        c.mirrored(5061, later);
        assert_eq!(c.uncovered(later), 4);
        c.tcp_seen(5061);
        assert_eq!(
            c.newly_silent(later + SILENCE_SECS)[0],
            Silent {
                port: 5061,
                secs: SILENCE_SECS,
                packets: 1
            }
        );
    }

    #[test]
    fn a_port_with_no_tcp_never_alarms() {
        let mut c = Coverage::new(0);
        c.mirrored(443, 0);
        assert!(c.newly_silent(SILENCE_SECS * 10).is_empty());
        assert_eq!(c.uncovered(SILENCE_SECS * 10), 0);
    }

    /// The transport is believed only from a sender that cannot be forged: a
    /// loopback address, or one that carried the configured key.
    #[test]
    fn tcp_evidence_is_trusted_only_from_a_proven_sender() {
        let c = Counters::default();
        let remote: SocketAddr = "10.0.0.3:40000".parse().unwrap();
        let open = Settings {
            allow_from: vec![Ipv4Addr::LOCALHOST, Ipv4Addr::new(10, 0, 0, 3)],
            ..settings()
        };
        let keyed = Settings {
            auth_key: Some(b"s3cret".to_vec()),
            ..open.clone()
        };
        let tcp = |key| packet(IPPROTO_TCP, NOW, key);
        for (what, sender, s, key, spoofable) in [
            ("loopback, no key", loopback(), &open, None, false),
            ("remote, no key", remote, &open, None, true),
            ("remote, with key", remote, &keyed, Some("s3cret"), false),
        ] {
            let m = handle(&tcp(key), sender, s, NOW, &c).expect(what);
            assert_eq!(m.transport, Transport::Tcp, "{what}");
            assert_eq!(m.spoofable(), spoofable, "{what}");
        }
        // UDP is spoofable whoever sends it.
        let udp_ok = Settings {
            udp: true,
            ..open.clone()
        };
        let m = handle(
            &packet(IPPROTO_UDP, NOW, None),
            loopback(),
            &udp_ok,
            NOW,
            &c,
        )
        .unwrap();
        assert!(m.spoofable());
    }

    /// The real socket: bind, send from loopback, receive on the channel.
    #[test]
    fn the_listener_receives_over_udp() {
        let cfg = HepConfig {
            enabled: true,
            listen: "127.0.0.1:0".parse().unwrap(),
            ..HepConfig::default()
        };
        let counters = Arc::new(Counters::default());
        let (inbox, addr) = spawn(&cfg, Arc::clone(&counters)).expect("binds");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .send_to(&packet(IPPROTO_TCP, now, None), addr)
            .unwrap();
        let m = inbox
            .recv_timeout(Duration::from_secs(5))
            .expect("delivered");
        assert_eq!(m.src, CLIENT);
        assert_eq!(count(&counters, "hep_sip"), 1);
    }
}
