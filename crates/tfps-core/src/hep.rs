//! HEP3 (the Homer Encapsulation Protocol, version 3): the decrypted SIP an
//! application server mirrors to TFPS.
//!
//! TFPS cannot read SIP over TLS or secure WebSocket on the wire. The server that
//! terminates them (OpenSIPS, on the same host) can send each message it handles,
//! after decryption and WebSocket de-framing, as one HEP3 packet. This module turns
//! such a packet into what [`crate::engine::Engine::observe_packet`] takes: the two
//! addresses and the SIP message.
//!
//! Pure, like the rest of this crate: no socket, no clock. The receiver passes the
//! time in.
//!
//! The format is a `HEP3` marker, a 16-bit total length, then chunks. Each chunk
//! is a 16-bit vendor id, a 16-bit type and a 16-bit length that counts its own
//! six-byte header. Every length is checked before it is used: a packet that lies
//! about a length is [`Malformed`], never a panic. The release build aborts on a
//! panic, which would take the daemon down for one bad packet.

use std::net::Ipv4Addr;

/// The packet's first four bytes.
pub const MARKER: &[u8; 4] = b"HEP3";

/// The generic vendor: the chunk types below. Any other vendor's chunks are skipped.
const VENDOR_GENERIC: u16 = 0;

/// The six-byte header of every chunk, and of the packet.
const HEADER: usize = 6;

/// IP family values in chunk 1.
const FAMILY_V4: u8 = 2;
const FAMILY_V6: u8 = 10;

/// IP protocol values in chunk 2.
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// What OpenSIPS's `tracer` puts in chunk 2 for a message over TLS: it has no
/// IP protocol of its own, so `pipport2su()` borrows `IPPROTO_IDP` (22) as a
/// "fake proto type" (`modules/tracer/tracer.c`).
pub const OPENSIPS_TLS: u8 = 22;

/// What OpenSIPS's `tracer` puts in chunk 2 for WebSocket, plain or secure:
/// `IPPROTO_ESP` (50), the same way. Its test is a `"ws"` prefix, so `wss`
/// matches it too.
pub const OPENSIPS_WS: u8 = 50;

/// Payload protocol value in chunk 11 for SIP.
pub const PROTO_SIP: u8 = 1;

/// The generic chunks this module reads, as one HEP3 packet carries them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hep<'a> {
    /// Chunk 1: 2 for IPv4, 10 for IPv6.
    pub family: Option<u8>,
    /// Chunk 2: the transport the message arrived on (6 = TCP, 17 = UDP).
    pub ip_proto: Option<u8>,
    /// Chunks 3 and 4.
    pub src: Option<Ipv4Addr>,
    pub dst: Option<Ipv4Addr>,
    /// Chunks 5 or 6 were present: the message is IPv6.
    pub ipv6: bool,
    /// Chunks 7 and 8.
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    /// Chunk 9: when the sender captured it, in Unix seconds.
    pub ts_secs: Option<u32>,
    /// Chunk 11: what the payload is (1 = SIP).
    pub proto_type: Option<u8>,
    /// Chunk 14: the shared secret, if the sender set one.
    pub auth_key: Option<&'a [u8]>,
    /// Chunk 15: the message itself.
    pub payload: Option<&'a [u8]>,
    /// Chunk 16 was present: a compressed payload, which is not supported.
    pub compressed: bool,
}

/// Why a packet is not HEP3 this module can read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformed {
    /// Shorter than the six-byte packet header.
    TooShort,
    /// Does not start with `HEP3` (HEP1 and HEP2 are not supported).
    NotHep3,
    /// The total length is smaller than the header or larger than what arrived.
    TotalLength,
    /// A chunk's length is smaller than its header or runs past the packet.
    ChunkLength,
    /// A fixed-size generic chunk has the wrong size, such as a 3-byte address.
    ChunkSize { kind: u16 },
}

/// Reads one HEP3 packet.
///
/// Bytes after the packet's total length are ignored. Unknown generic chunks and
/// every vendor chunk are skipped by their length. A generic chunk that appears
/// twice keeps its last value.
pub fn parse(buf: &[u8]) -> Result<Hep<'_>, Malformed> {
    if buf.len() < HEADER {
        return Err(Malformed::TooShort);
    }
    if &buf[..4] != MARKER {
        return Err(Malformed::NotHep3);
    }
    let total = usize::from(u16::from_be_bytes([buf[4], buf[5]]));
    if total < HEADER || total > buf.len() {
        return Err(Malformed::TotalLength);
    }
    let buf = &buf[..total];
    let mut hep = Hep::default();
    let mut at = HEADER;
    while at < buf.len() {
        let Some(head) = buf.get(at..at + HEADER) else {
            return Err(Malformed::ChunkLength);
        };
        let vendor = u16::from_be_bytes([head[0], head[1]]);
        let kind = u16::from_be_bytes([head[2], head[3]]);
        let len = usize::from(u16::from_be_bytes([head[4], head[5]]));
        if len < HEADER {
            return Err(Malformed::ChunkLength);
        }
        let Some(body) = buf.get(at + HEADER..at + len) else {
            return Err(Malformed::ChunkLength);
        };
        at += len;
        if vendor != VENDOR_GENERIC {
            continue;
        }
        let size = |n: usize| {
            if body.len() == n {
                Ok(body)
            } else {
                Err(Malformed::ChunkSize { kind })
            }
        };
        match kind {
            1 => hep.family = Some(size(1)?[0]),
            2 => hep.ip_proto = Some(size(1)?[0]),
            3 => hep.src = Some(v4(size(4)?)),
            4 => hep.dst = Some(v4(size(4)?)),
            5 | 6 => {
                size(16)?;
                hep.ipv6 = true;
            }
            7 => hep.src_port = Some(be16(size(2)?)),
            8 => hep.dst_port = Some(be16(size(2)?)),
            9 => hep.ts_secs = Some(be32(size(4)?)),
            10 => {
                size(4)?; // microseconds: not needed for a seconds-level stale check
            }
            11 => hep.proto_type = Some(size(1)?[0]),
            14 => hep.auth_key = Some(body),
            15 => hep.payload = Some(body),
            16 => hep.compressed = true,
            _ => {} // capture id, correlation id, node name and the rest: not used
        }
    }
    Ok(hep)
}

fn v4(b: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// The transport a mirrored message arrived on at the application server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// TCP, and everything carried over it: TLS, WebSocket, secure WebSocket.
    /// Chunk 2 says 6, or OpenSIPS's [`OPENSIPS_TLS`] or [`OPENSIPS_WS`].
    Tcp,
    /// UDP, which TFPS already sees on the wire.
    Udp,
}

impl Transport {
    /// A source address on this transport can be forged: no handshake proved it.
    pub fn spoofable(self) -> bool {
        matches!(self, Transport::Udp)
    }
}

/// What the receiver accepts.
#[derive(Debug, Clone)]
pub struct Filter<'a> {
    /// Accept messages that arrived over TCP (TLS, WS, WSS).
    pub tcp: bool,
    /// Accept messages that arrived over UDP. Off by default: the wire capture
    /// already sees them, and accepting both would count each message twice.
    pub udp: bool,
    /// When set, chunk 14 must hold exactly this.
    pub auth_key: Option<&'a [u8]>,
    /// The receive time, in Unix seconds.
    pub now: u32,
    /// A message captured more than this many seconds before `now` is stale.
    pub stale_secs: u32,
}

/// Why a well-formed packet is not handed to the engine. Each has its own counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// The shared secret is missing or wrong.
    BadAuth,
    /// An IPv6 message: detection and enforcement are IPv4 only.
    Ipv6,
    /// Not SIP (RTCP, logs, …), or a transport other than TCP or UDP.
    Proto,
    /// A compressed payload, which is not supported.
    Compressed,
    /// Arrived over UDP, and UDP is not accepted.
    Udp,
    /// Arrived over TCP, and TCP is not accepted.
    Tcp,
    /// Captured too long ago: a replayed backlog must not block for old behaviour.
    Stale,
    /// A required chunk is missing (family, addresses, transport or payload).
    Incomplete,
}

/// A mirrored SIP message, ready for the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub transport: Transport,
    pub payload: &'a [u8],
}

/// Decides whether a parsed packet reaches the engine.
///
/// The secret is checked first, so a sender without it learns nothing from which
/// other rule would have applied.
pub fn classify<'a>(hep: &Hep<'a>, f: &Filter<'_>) -> Result<Message<'a>, Skip> {
    if let Some(key) = f.auth_key {
        if !hep.auth_key.is_some_and(|k| same(k, key)) {
            return Err(Skip::BadAuth);
        }
    }
    if hep.ipv6 || hep.family == Some(FAMILY_V6) {
        return Err(Skip::Ipv6);
    }
    if hep.proto_type != Some(PROTO_SIP) {
        return Err(Skip::Proto);
    }
    // A compressed chunk makes the packet unsupported even beside a plain payload
    // chunk: which of the two is the message is not this module's guess to make.
    if hep.compressed {
        return Err(Skip::Compressed);
    }
    let Some(payload) = hep.payload else {
        return Err(Skip::Incomplete);
    };
    let transport = match hep.ip_proto {
        // TLS and WebSocket run over TCP, whatever number the sender chose to say so.
        Some(IPPROTO_TCP | OPENSIPS_TLS | OPENSIPS_WS) => Transport::Tcp,
        Some(IPPROTO_UDP) => Transport::Udp,
        Some(_) => return Err(Skip::Proto),
        None => return Err(Skip::Incomplete),
    };
    match transport {
        Transport::Tcp if !f.tcp => return Err(Skip::Tcp),
        Transport::Udp if !f.udp => return Err(Skip::Udp),
        _ => {}
    }
    let (Some(src), Some(dst)) = (hep.src, hep.dst) else {
        return Err(Skip::Incomplete);
    };
    match hep.family {
        Some(FAMILY_V4) => {}
        // Without the family chunk the addresses are not known to be IPv4.
        None => return Err(Skip::Incomplete),
        Some(_) => return Err(Skip::Proto),
    }
    if let Some(ts) = hep.ts_secs {
        if f.now.saturating_sub(ts) > f.stale_secs {
            return Err(Skip::Stale);
        }
    }
    Ok(Message {
        src,
        dst,
        src_port: hep.src_port,
        dst_port: hep.dst_port,
        transport,
        payload,
    })
}

/// Compares two secrets in time that depends only on their lengths.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Builds HEP3 packets. Used by the tests here and in the daemon, and by anything
/// that needs to send TFPS a message the way OpenSIPS does.
pub mod build {
    use super::*;

    /// One generic chunk.
    pub fn chunk(kind: u16, body: &[u8]) -> Vec<u8> {
        vendor_chunk(VENDOR_GENERIC, kind, body)
    }

    /// One chunk of any vendor.
    pub fn vendor_chunk(vendor: u16, kind: u16, body: &[u8]) -> Vec<u8> {
        let len = u16::try_from(HEADER + body.len()).expect("a chunk fits in 64 KiB");
        let mut c = Vec::with_capacity(HEADER + body.len());
        c.extend_from_slice(&vendor.to_be_bytes());
        c.extend_from_slice(&kind.to_be_bytes());
        c.extend_from_slice(&len.to_be_bytes());
        c.extend_from_slice(body);
        c
    }

    /// A packet from its chunks.
    pub fn packet(chunks: &[Vec<u8>]) -> Vec<u8> {
        let body: usize = chunks.iter().map(Vec::len).sum();
        let total = u16::try_from(HEADER + body).expect("a packet fits in 64 KiB");
        let mut p = Vec::with_capacity(HEADER + body);
        p.extend_from_slice(MARKER);
        p.extend_from_slice(&total.to_be_bytes());
        for c in chunks {
            p.extend_from_slice(c);
        }
        p
    }

    /// What one mirrored message says about itself.
    #[derive(Debug, Clone)]
    pub struct Sip<'a> {
        pub src: (Ipv4Addr, u16),
        pub dst: (Ipv4Addr, u16),
        pub ip_proto: u8,
        pub ts: u32,
        pub auth_key: Option<&'a str>,
        pub payload: &'a [u8],
    }

    /// The chunks OpenSIPS `proto_hep` sends for a SIP message with the plain
    /// (Homer 5) payload, in its order: family, protocol, addresses, ports,
    /// timestamp, payload type, capture id, the optional secret, then the message.
    pub fn sip(m: &Sip<'_>) -> Vec<u8> {
        let mut chunks = vec![
            chunk(1, &[FAMILY_V4]),
            chunk(2, &[m.ip_proto]),
            chunk(3, &m.src.0.octets()),
            chunk(4, &m.dst.0.octets()),
            chunk(7, &m.src.1.to_be_bytes()),
            chunk(8, &m.dst.1.to_be_bytes()),
            chunk(9, &m.ts.to_be_bytes()),
            chunk(10, &0u32.to_be_bytes()),
            chunk(11, &[PROTO_SIP]),
            chunk(12, &2001u32.to_be_bytes()),
        ];
        if let Some(k) = m.auth_key {
            chunks.push(chunk(14, k.as_bytes()));
        }
        chunks.push(chunk(15, m.payload));
        packet(&chunks)
    }
}

#[cfg(test)]
mod tests {
    use super::build::{chunk, packet, sip, vendor_chunk, Sip};
    use super::*;

    const CLIENT: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
    const SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
    const NOW: u32 = 1_795_000_000;

    fn filter() -> Filter<'static> {
        Filter {
            tcp: true,
            udp: false,
            auth_key: None,
            now: NOW,
            stale_secs: 5,
        }
    }

    fn message(payload: &[u8]) -> Vec<u8> {
        sip(&Sip {
            src: (CLIENT, 51_234),
            dst: (SERVER, 5061),
            ip_proto: IPPROTO_TCP,
            ts: NOW,
            auth_key: None,
            payload,
        })
    }

    #[test]
    fn a_mirrored_message_reads_back_whole() {
        let p = message(b"OPTIONS sip:x SIP/2.0\r\n\r\n");
        let h = parse(&p).expect("valid");
        assert_eq!(h.family, Some(2));
        assert_eq!(h.ip_proto, Some(IPPROTO_TCP));
        assert_eq!((h.src, h.dst), (Some(CLIENT), Some(SERVER)));
        assert_eq!((h.src_port, h.dst_port), (Some(51_234), Some(5061)));
        assert_eq!(h.ts_secs, Some(NOW));
        assert_eq!(h.proto_type, Some(PROTO_SIP));
        assert_eq!(h.payload, Some(&b"OPTIONS sip:x SIP/2.0\r\n\r\n"[..]));
        let m = classify(&h, &filter()).expect("accepted");
        assert_eq!(
            (m.src, m.dst, m.transport),
            (CLIENT, SERVER, Transport::Tcp)
        );
    }

    #[test]
    fn unknown_and_vendor_chunks_are_skipped_by_length() {
        let p = packet(&[
            vendor_chunk(0x0003, 15, b"a vendor's own payload chunk"),
            chunk(1, &[2]),
            chunk(2, &[IPPROTO_TCP]),
            chunk(3, &CLIENT.octets()),
            chunk(4, &SERVER.octets()),
            chunk(19, b"node name"),
            chunk(200, &[]),
            chunk(11, &[PROTO_SIP]),
            chunk(15, b"BYE sip:x SIP/2.0\r\n\r\n"),
        ]);
        let h = parse(&p).expect("valid");
        assert_eq!(
            h.payload,
            Some(&b"BYE sip:x SIP/2.0\r\n\r\n"[..]),
            "the vendor's chunk 15 is not the payload"
        );
        assert!(classify(&h, &filter()).is_ok());
    }

    #[test]
    fn lengths_that_lie_are_malformed() {
        assert_eq!(parse(b"HEP3"), Err(Malformed::TooShort));
        assert_eq!(parse(b"HEP2\x00\x06"), Err(Malformed::NotHep3));
        let good = message(b"OPTIONS sip:x SIP/2.0\r\n\r\n");

        // Total length larger than what arrived: truncated in transit.
        let mut big = good.clone();
        big[4..6].copy_from_slice(&u16::try_from(good.len() + 1).unwrap().to_be_bytes());
        assert_eq!(parse(&big), Err(Malformed::TotalLength));
        // Smaller than the header.
        let mut tiny = good.clone();
        tiny[4..6].copy_from_slice(&5u16.to_be_bytes());
        assert_eq!(parse(&tiny), Err(Malformed::TotalLength));
        // Cut off mid-packet.
        assert_eq!(parse(&good[..good.len() - 3]), Err(Malformed::TotalLength));

        // A chunk that claims to run past the end.
        let mut over = packet(&[chunk(15, b"abc")]);
        over[10..12].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(parse(&over), Err(Malformed::ChunkLength));
        // A chunk shorter than its own header: would loop forever if accepted.
        let mut under = packet(&[chunk(15, b"abc")]);
        under[10..12].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(parse(&under), Err(Malformed::ChunkLength));
        // Half a chunk header at the end.
        let mut half = packet(&[chunk(1, &[2])]);
        half.extend_from_slice(&[0, 0, 0]);
        let total = u16::try_from(half.len()).unwrap();
        half[4..6].copy_from_slice(&total.to_be_bytes());
        assert_eq!(parse(&half), Err(Malformed::ChunkLength));
        // A 3-byte IPv4 address.
        assert_eq!(
            parse(&packet(&[chunk(3, &[1, 2, 3])])),
            Err(Malformed::ChunkSize { kind: 3 })
        );
    }

    #[test]
    fn trailing_bytes_after_the_packet_are_ignored() {
        let mut p = message(b"OPTIONS sip:x SIP/2.0\r\n\r\n");
        p.extend_from_slice(b"junk");
        assert!(parse(&p).is_ok());
    }

    #[test]
    fn ipv6_is_counted_and_skipped() {
        let p = packet(&[
            chunk(1, &[10]),
            chunk(2, &[IPPROTO_TCP]),
            chunk(5, &[0; 16]),
            chunk(6, &[0; 16]),
            chunk(11, &[PROTO_SIP]),
            chunk(15, b"OPTIONS sip:x SIP/2.0\r\n\r\n"),
        ]);
        let h = parse(&p).expect("valid");
        assert!(h.ipv6);
        assert_eq!(classify(&h, &filter()), Err(Skip::Ipv6));
    }

    #[test]
    fn a_payload_that_is_not_sip_is_skipped() {
        let p = packet(&[
            chunk(1, &[2]),
            chunk(2, &[IPPROTO_UDP]),
            chunk(3, &CLIENT.octets()),
            chunk(4, &SERVER.octets()),
            chunk(11, &[5]), // RTCP
            chunk(15, b"\x80\xc8\x00\x06"),
        ]);
        assert_eq!(classify(&parse(&p).unwrap(), &filter()), Err(Skip::Proto));
        // SCTP is neither of the transports this understands.
        let sctp = packet(&[
            chunk(2, &[132]),
            chunk(3, &CLIENT.octets()),
            chunk(4, &SERVER.octets()),
            chunk(11, &[PROTO_SIP]),
            chunk(15, b"OPTIONS sip:x SIP/2.0\r\n\r\n"),
        ]);
        assert_eq!(
            classify(&parse(&sctp).unwrap(), &filter()),
            Err(Skip::Proto)
        );
    }

    /// OpenSIPS marks TLS as 22 and WS / WSS as 50 in chunk 2. Both are TCP:
    /// judged when TCP is accepted, not spoofable, and skipped as TCP otherwise.
    #[test]
    fn opensips_tls_and_websocket_numbers_are_tcp() {
        for ip_proto in [IPPROTO_TCP, OPENSIPS_TLS, OPENSIPS_WS] {
            let bytes = sip(&Sip {
                src: (CLIENT, 51_234),
                dst: (SERVER, 443),
                ip_proto,
                ts: NOW,
                auth_key: None,
                payload: b"OPTIONS sip:x SIP/2.0\r\n\r\n",
            });
            let h = parse(&bytes).unwrap();
            let m = classify(&h, &filter()).expect("accepted as TCP");
            assert_eq!(m.transport, Transport::Tcp, "{ip_proto}");
            assert!(!m.transport.spoofable());
            let udp_only = Filter {
                tcp: false,
                udp: true,
                ..filter()
            };
            assert_eq!(classify(&h, &udp_only), Err(Skip::Tcp), "{ip_proto}");
        }
    }

    #[test]
    fn a_compressed_payload_is_skipped() {
        let p = packet(&[
            chunk(2, &[IPPROTO_TCP]),
            chunk(3, &CLIENT.octets()),
            chunk(4, &SERVER.octets()),
            chunk(11, &[PROTO_SIP]),
            chunk(16, b"\x1f\x8b\x08\x00"),
        ]);
        let h = parse(&p).expect("valid");
        assert!(h.compressed);
        assert_eq!(classify(&h, &filter()), Err(Skip::Compressed));
        // Beside a plain payload chunk too: the packet is still not one this reads.
        let both = packet(&[
            chunk(1, &[2]),
            chunk(2, &[IPPROTO_TCP]),
            chunk(3, &CLIENT.octets()),
            chunk(4, &SERVER.octets()),
            chunk(11, &[PROTO_SIP]),
            chunk(15, b"OPTIONS sip:x SIP/2.0\r\n\r\n"),
            chunk(16, b"\x1f\x8b\x08\x00"),
        ]);
        assert_eq!(
            classify(&parse(&both).unwrap(), &filter()),
            Err(Skip::Compressed)
        );
    }

    #[test]
    fn missing_addresses_or_transport_are_incomplete() {
        let no_dst = packet(&[
            chunk(2, &[IPPROTO_TCP]),
            chunk(3, &CLIENT.octets()),
            chunk(11, &[PROTO_SIP]),
            chunk(15, b"x"),
        ]);
        assert_eq!(
            classify(&parse(&no_dst).unwrap(), &filter()),
            Err(Skip::Incomplete)
        );
        let no_proto = packet(&[
            chunk(3, &CLIENT.octets()),
            chunk(4, &SERVER.octets()),
            chunk(11, &[PROTO_SIP]),
            chunk(15, b"x"),
        ]);
        assert_eq!(
            classify(&parse(&no_proto).unwrap(), &filter()),
            Err(Skip::Incomplete)
        );
        let no_family = packet(&[
            chunk(2, &[IPPROTO_TCP]),
            chunk(3, &CLIENT.octets()),
            chunk(4, &SERVER.octets()),
            chunk(11, &[PROTO_SIP]),
            chunk(15, b"x"),
        ]);
        assert_eq!(
            classify(&parse(&no_family).unwrap(), &filter()),
            Err(Skip::Incomplete),
            "IPv4 addresses without the family chunk are not trusted as IPv4"
        );
    }

    #[test]
    fn only_the_accepted_transports_pass() {
        let udp = sip(&Sip {
            src: (CLIENT, 5060),
            dst: (SERVER, 5060),
            ip_proto: IPPROTO_UDP,
            ts: NOW,
            auth_key: None,
            payload: b"OPTIONS sip:x SIP/2.0\r\n\r\n",
        });
        let h = parse(&udp).unwrap();
        assert_eq!(
            classify(&h, &filter()),
            Err(Skip::Udp),
            "UDP off by default"
        );
        let both = Filter {
            udp: true,
            ..filter()
        };
        let m = classify(&h, &both).expect("UDP opted in");
        assert!(m.transport.spoofable());
        let udp_only = Filter {
            tcp: false,
            udp: true,
            ..filter()
        };
        let tcp_bytes = message(b"x");
        let tcp = parse(&tcp_bytes).unwrap();
        assert_eq!(classify(&tcp, &udp_only), Err(Skip::Tcp));
        assert!(!Transport::Tcp.spoofable());
    }

    #[test]
    fn the_shared_secret_must_match_exactly() {
        let with = |key: Option<&'static str>| {
            sip(&Sip {
                src: (CLIENT, 1),
                dst: (SERVER, 5061),
                ip_proto: IPPROTO_TCP,
                ts: NOW,
                auth_key: key,
                payload: b"x",
            })
        };
        let f = Filter {
            auth_key: Some(b"s3cret"),
            ..filter()
        };
        for (key, ok) in [
            (Some("s3cret"), true),
            (Some("s3cre"), false),
            (Some("s3cretX"), false),
            (Some("S3cret"), false),
            (None, false),
        ] {
            let bytes = with(key);
            let got = classify(&parse(&bytes).unwrap(), &f);
            assert_eq!(got.is_ok(), ok, "{key:?}: {got:?}");
            if !ok {
                assert_eq!(got, Err(Skip::BadAuth));
            }
        }
        // With no secret configured, one sent anyway is not checked.
        assert!(classify(&parse(&with(Some("anything"))).unwrap(), &filter()).is_ok());
    }

    #[test]
    fn a_message_older_than_the_cutoff_is_stale() {
        let at = |ts: u32| {
            sip(&Sip {
                src: (CLIENT, 1),
                dst: (SERVER, 5061),
                ip_proto: IPPROTO_TCP,
                ts,
                auth_key: None,
                payload: b"x",
            })
        };
        let f = filter();
        assert!(
            classify(&parse(&at(NOW - 5)).unwrap(), &f).is_ok(),
            "5 s is fine"
        );
        assert_eq!(
            classify(&parse(&at(NOW - 6)).unwrap(), &f),
            Err(Skip::Stale)
        );
        assert!(
            classify(&parse(&at(NOW + 30)).unwrap(), &f).is_ok(),
            "a sender clock ahead is not a replay"
        );
    }

    /// Synthetic fixtures, built to the HEP3 layout OpenSIPS `proto_hep` sends with
    /// the plain (Homer 5) payload: a WSS REGISTER answered 401 then 200, a WSS
    /// INVITE and a TLS INVITE, with chunk 2 as OpenSIPS's `tracer` sets it for
    /// each transport. Not captured from a live OpenSIPS.
    mod fixtures {
        use super::*;
        use crate::dialplan::DialPlan;
        use crate::engine::{Engine, Mode};
        use crate::novelty::Timestamp;

        const CLIENT_PORT: u16 = 51_234;

        fn from_client(ip_proto: u8, server_port: u16, payload: &[u8]) -> Vec<u8> {
            sip(&Sip {
                src: (CLIENT, CLIENT_PORT),
                dst: (SERVER, server_port),
                ip_proto,
                ts: NOW,
                auth_key: None,
                payload,
            })
        }

        fn to_client(ip_proto: u8, server_port: u16, payload: &[u8]) -> Vec<u8> {
            sip(&Sip {
                src: (SERVER, server_port),
                dst: (CLIENT, CLIENT_PORT),
                ip_proto,
                ts: NOW,
                auth_key: None,
                payload,
            })
        }

        const WSS_REGISTER: &[u8] = b"REGISTER sip:pbx.example.com SIP/2.0\r\n\
Via: SIP/2.0/WSS df7jal23ls0d.invalid;branch=z9hG4bK1;rport\r\n\
Max-Forwards: 70\r\n\
From: <sip:1001@pbx.example.com>;tag=8rq\r\n\
To: <sip:1001@pbx.example.com>\r\n\
Call-ID: 9t6c1r2u\r\n\
CSeq: 1 REGISTER\r\n\
Contact: <sip:a8k2@df7jal23ls0d.invalid;transport=ws>;expires=600\r\n\
User-Agent: JsSIP 3.10.0\r\n\
Content-Length: 0\r\n\r\n";

        const WSS_401: &[u8] = b"SIP/2.0 401 Unauthorized\r\n\
Via: SIP/2.0/WSS df7jal23ls0d.invalid;branch=z9hG4bK1;rport=51234;received=198.51.100.7\r\n\
From: <sip:1001@pbx.example.com>;tag=8rq\r\n\
To: <sip:1001@pbx.example.com>;tag=srv1\r\n\
Call-ID: 9t6c1r2u\r\n\
CSeq: 1 REGISTER\r\n\
WWW-Authenticate: Digest realm=\"pbx.example.com\", nonce=\"Z2l2ZW4=\"\r\n\
Content-Length: 0\r\n\r\n";

        const WSS_REGISTER_AUTH: &[u8] = b"REGISTER sip:pbx.example.com SIP/2.0\r\n\
Via: SIP/2.0/WSS df7jal23ls0d.invalid;branch=z9hG4bK2;rport\r\n\
Max-Forwards: 70\r\n\
From: <sip:1001@pbx.example.com>;tag=8rq\r\n\
To: <sip:1001@pbx.example.com>\r\n\
Call-ID: 9t6c1r2u\r\n\
CSeq: 2 REGISTER\r\n\
Authorization: Digest username=\"1001\", realm=\"pbx.example.com\", nonce=\"Z2l2ZW4=\", uri=\"sip:pbx.example.com\", response=\"6629fae49393a05397450978507c4ef1\"\r\n\
Contact: <sip:a8k2@df7jal23ls0d.invalid;transport=ws>;expires=600\r\n\
User-Agent: JsSIP 3.10.0\r\n\
Content-Length: 0\r\n\r\n";

        const WSS_200: &[u8] = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/WSS df7jal23ls0d.invalid;branch=z9hG4bK2;rport=51234;received=198.51.100.7\r\n\
From: <sip:1001@pbx.example.com>;tag=8rq\r\n\
To: <sip:1001@pbx.example.com>;tag=srv2\r\n\
Call-ID: 9t6c1r2u\r\n\
CSeq: 2 REGISTER\r\n\
Contact: <sip:a8k2@df7jal23ls0d.invalid;transport=ws>;expires=600\r\n\
Content-Length: 0\r\n\r\n";

        const WSS_INVITE: &[u8] = b"INVITE sip:1002@pbx.example.com SIP/2.0\r\n\
Via: SIP/2.0/WSS df7jal23ls0d.invalid;branch=z9hG4bK3;rport\r\n\
Max-Forwards: 70\r\n\
From: <sip:1001@pbx.example.com>;tag=inv1\r\n\
To: <sip:1002@pbx.example.com>\r\n\
Call-ID: 4c0ld2x\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:a8k2@df7jal23ls0d.invalid;transport=ws;ob>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 0\r\n\r\n";

        const TLS_INVITE: &[u8] = b"INVITE sip:0044201234567@pbx.example.com SIP/2.0\r\n\
Via: SIP/2.0/TLS 198.51.100.7:51234;branch=z9hG4bK4;rport\r\n\
Max-Forwards: 70\r\n\
From: <sip:1001@pbx.example.com>;tag=tls1\r\n\
To: <sip:0044201234567@pbx.example.com>\r\n\
Call-ID: tls-call-1\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:1001@198.51.100.7:51234;transport=tls>\r\n\
Content-Length: 0\r\n\r\n";

        /// Parses, passes the default filter, and returns what the engine gets.
        fn accept(bytes: &[u8]) -> Message<'_> {
            let h = parse(bytes).expect("well-formed");
            classify(&h, &filter()).expect("accepted by the default filter")
        }

        #[test]
        fn each_fixture_reaches_the_engine_with_the_client_as_subject() {
            let mut e = Engine::new(DialPlan::new(["00"]), Mode::Active);
            let t = Timestamp(NOW);
            let exchange = [
                // Chunk 2 as OpenSIPS's tracer sets it: 50 for WSS, 22 for TLS.
                (
                    from_client(OPENSIPS_WS, 443, WSS_REGISTER),
                    (CLIENT, SERVER),
                ),
                (to_client(OPENSIPS_WS, 443, WSS_401), (SERVER, CLIENT)),
                (
                    from_client(OPENSIPS_WS, 443, WSS_REGISTER_AUTH),
                    (CLIENT, SERVER),
                ),
                (to_client(OPENSIPS_WS, 443, WSS_200), (SERVER, CLIENT)),
                (from_client(OPENSIPS_WS, 443, WSS_INVITE), (CLIENT, SERVER)),
                (
                    from_client(OPENSIPS_TLS, 5061, TLS_INVITE),
                    (CLIENT, SERVER),
                ),
            ];
            for (bytes, (src, dst)) in &exchange {
                let m = accept(bytes);
                assert_eq!((m.src, m.dst), (*src, *dst));
                assert_eq!(m.transport, Transport::Tcp);
                let (subject, _) = e.observe_packet(m.src, m.dst, m.payload, t);
                assert_eq!(
                    subject, CLIENT,
                    "requests and answers are both about the client"
                );
            }
            assert_eq!(e.stats.sip_parsed, 4, "four requests");
            assert_eq!(e.stats.responses, 2, "the 401 and the 200");
            assert_eq!(e.stats.not_sip, 0);
            assert_eq!(
                e.stats.digest_challenges, 1,
                "the 401 was read as a challenge"
            );
            assert!(
                e.is_known_peer(CLIENT, t),
                "the 200 to an authenticated REGISTER marks the client, not the server"
            );
            assert!(!e.is_known_peer(SERVER, t));
        }
    }

    /// Arbitrary bytes never panic, whether random, or a valid packet with bytes
    /// changed, cut short or lengthened.
    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let seed = message(b"INVITE sip:1000@x SIP/2.0\r\nVia: SIP/2.0/TLS h\r\n\r\n");
        for i in 0..20_000 {
            let mut buf = if i % 2 == 0 {
                let n = (next() % 300) as usize;
                let mut b: Vec<u8> = (0..n).map(|_| next() as u8).collect();
                if i % 4 == 0 && b.len() >= 4 {
                    b[..4].copy_from_slice(MARKER);
                }
                b
            } else {
                seed.clone()
            };
            for _ in 0..(next() % 6) {
                if buf.is_empty() {
                    break;
                }
                let at = (next() as usize) % buf.len();
                buf[at] = next() as u8;
            }
            if i % 3 == 0 {
                let cut = (next() as usize) % (buf.len() + 1);
                buf.truncate(cut);
            }
            if let Ok(h) = parse(&buf) {
                let _ = classify(&h, &filter());
            }
        }
    }
}
