//! The JSON-over-HTTP API that `tfps_ctl serve` runs, and its Prometheus page.
//!
//! **A separate process, off by default.** It needs nothing from the daemon's
//! engine: blocks are in the kernel map, and reasons are in `block_log` and the
//! manual-action record, which `tfps::ctl` already reads. So the HTTP parser never
//! shares a process with the packet loop, its four capabilities, or its
//! `panic = "abort"`.
//!
//! **A small HTTP/1.1 server on `std::net`, on purpose.** The release binaries are
//! static musl builds with documented sizes, so there is no async runtime here,
//! and the off-the-shelf synchronous server sets no socket timeouts and grows a
//! thread per busy connection. This one has a fixed pool of [`WORKERS`] threads, a
//! bounded queue in front of them, read and write timeouts, a cap on the header
//! block and on the body, and answers one request per connection.
//!
//! **There is no authentication.** Anyone who can reach the listen address can read
//! the blocks, and can lift them when `allow_unban` is on. What this module does
//! enforce costs nothing and stops a web page in a local browser from acting on the
//! API: any request carrying an `Origin` header is refused, and the one route that
//! changes anything takes only `POST` with `Content-Type: application/json`.
//!
//! The routing is [`route`], a plain function from a parsed [`Request`] to a
//! [`Response`] over a [`Backend`], so every rule here is testable without a
//! socket, a kernel map, or a database.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::mpsc::{sync_channel, Receiver, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::ctl::{
    ActionDoc, BannedDoc, Ctx, LogDoc, StatsDoc, StatusDoc, UnbanOutcome, UnbanTarget,
};

/// Worker threads. Each handles one connection at a time, start to finish.
pub const WORKERS: usize = 4;
/// Accepted connections waiting for a worker. Past this, a new connection gets a
/// 503 straight away rather than an unbounded wait.
pub const QUEUE: usize = 16;
/// How long a read or a write on one connection may stall.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// The request line and headers together.
pub const MAX_HEADER_BYTES: usize = 8 * 1024;
/// A request body.
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Addresses in one `POST /v1/unban`.
pub const MAX_UNBAN_ADDRESSES: usize = 256;
/// `GET /v1/log` rows when `limit` is not given, and the most it may ask for.
pub const DEFAULT_LOG_LIMIT: usize = 50;
pub const MAX_LOG_LIMIT: usize = 1000;
/// Who an unban is recorded as when the request does not say.
pub const DEFAULT_SOURCE: &str = "http";

// ---------------------------------------------------------------- backend

/// Where the answers come from. [`CtlBackend`] reads the real kernel map and
/// database through `tfps::ctl`; a test substitutes its own.
pub trait Backend: Send + Sync {
    fn status(&self) -> StatusDoc;
    fn stats(&self) -> Result<StatsDoc, String>;
    fn banned(&self) -> Result<Vec<BannedDoc>, String>;
    fn log(&self, limit: usize, ip: Option<&str>) -> Result<Vec<LogDoc>, String>;
    /// The XDP program's `(seen, dropped, expired)` counters, `None` when unreadable.
    fn kernel_counters(&self) -> Option<(u64, u64, u64)>;
    /// `(blocked now, of which permanent)`, counted from the block map.
    fn map_counts(&self) -> Result<(usize, usize), String>;
    /// Lift these already-validated addresses. `Err` means nothing was touched.
    fn unban(
        &self,
        ips: &[String],
        source: &str,
        reason: Option<&str>,
    ) -> Result<UnbanOutcome, String>;
}

/// The real thing: every answer is the matching `tfps_ctl --json` document.
pub struct CtlBackend(pub Ctx);

impl Backend for CtlBackend {
    fn status(&self) -> StatusDoc {
        crate::ctl::status_docs(&self.0)
    }
    fn stats(&self) -> Result<StatsDoc, String> {
        crate::ctl::stats_docs(&self.0)
    }
    fn banned(&self) -> Result<Vec<BannedDoc>, String> {
        crate::ctl::banned_docs(&self.0)
    }
    fn log(&self, limit: usize, ip: Option<&str>) -> Result<Vec<LogDoc>, String> {
        crate::ctl::log_docs(&self.0, limit, ip)
    }
    fn kernel_counters(&self) -> Option<(u64, u64, u64)> {
        crate::xdp::live_counters()
            .ok()
            .map(|c| (c.seen, c.dropped, c.expired))
    }
    fn map_counts(&self) -> Result<(usize, usize), String> {
        crate::ctl::map_counts(&self.0)
    }
    fn unban(
        &self,
        ips: &[String],
        source: &str,
        reason: Option<&str>,
    ) -> Result<UnbanOutcome, String> {
        crate::ctl::unban_docs(&self.0, UnbanTarget::Addresses(ips), Some(source), reason)
    }
}

/// What the operator switched on. The listen address lives with the listener.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    pub allow_unban: bool,
}

// ---------------------------------------------------------------- HTTP

/// One parsed request. Header names are lower-cased; the target is split at `?`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// The first value of a header, by lower-case name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// One response: always a complete body with its length, then the connection closes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
    /// `Allow`, on a 405.
    pub allow: Option<&'static str>,
}

const JSON: &str = "application/json";
const PROMETHEUS: &str = "text/plain; version=0.0.4; charset=utf-8";

impl Response {
    fn json(status: u16, body: String) -> Self {
        Response {
            status,
            content_type: JSON,
            body,
            allow: None,
        }
    }

    /// `{"error":"<message>"}`.
    pub fn error(status: u16, message: &str) -> Self {
        #[derive(Serialize)]
        struct E<'a> {
            error: &'a str,
        }
        Self::json(status, to_json(&E { error: message }))
    }

    fn method_not_allowed(allow: &'static str) -> Self {
        Response {
            allow: Some(allow),
            ..Self::error(405, "method not allowed")
        }
    }

    /// The bytes on the wire.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut head = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n\
             Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n",
            self.status,
            reason_phrase(self.status),
            self.content_type,
            self.body.len()
        );
        if let Some(a) = self.allow {
            head.push_str(&format!("Allow: {a}\r\n"));
        }
        head.push_str("\r\n");
        let mut out = head.into_bytes();
        out.extend_from_slice(self.body.as_bytes());
        out
    }
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

/// Serialises a value that cannot fail to serialise (plain structs, strings,
/// integers and maps with string keys). A failure would be a bug here, and the
/// answer to it is a 500 rather than a panic, which would abort the process.
fn to_json<T: Serialize + ?Sized>(v: &T) -> String {
    serde_json::to_string(v)
        .unwrap_or_else(|e| format!("{{\"error\":\"serialising the response: {e}\"}}"))
}

/// Reads one request, refusing anything past the limits before it is buffered.
///
/// `before_body` is called once the headers are accepted and a body is coming, so
/// the caller can send `100 Continue` to a client that asked for it.
pub fn read_request<R: BufRead>(
    r: &mut R,
    mut before_body: impl FnMut(),
) -> Result<Request, Response> {
    let mut used = 0usize;
    let mut line = |r: &mut R| -> Result<String, Response> {
        let mut buf = Vec::new();
        let room = (MAX_HEADER_BYTES - used) as u64;
        let n = r
            .by_ref()
            .take(room)
            .read_until(b'\n', &mut buf)
            .map_err(|e| io_error_response(&e))?;
        used += n;
        if n == 0 {
            return Err(Response::error(400, "the request ended early"));
        }
        if buf.last() != Some(&b'\n') {
            return Err(Response::error(
                431,
                &format!("the request line and headers must fit in {MAX_HEADER_BYTES} bytes"),
            ));
        }
        String::from_utf8(buf)
            .map(|s| s.trim_end_matches(['\r', '\n']).to_string())
            .map_err(|_| Response::error(400, "the request head is not UTF-8"))
    };

    let request_line = line(r)?;
    let mut parts = request_line.split(' ');
    let (method, target, version) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(t), Some(v), None) if !m.is_empty() && t.starts_with('/') => (m, t, v),
        _ => return Err(Response::error(400, "malformed request line")),
    };
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(Response::error(
            400,
            "only HTTP/1.0 and HTTP/1.1 are spoken here",
        ));
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));

    let mut headers = Vec::new();
    loop {
        let l = line(r)?;
        if l.is_empty() {
            break;
        }
        let (name, value) = l
            .split_once(':')
            .ok_or_else(|| Response::error(400, "malformed header line"))?;
        if name.is_empty() || name.contains(char::is_whitespace) {
            return Err(Response::error(400, "malformed header name"));
        }
        headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
    }
    let mut req = Request {
        method: method.to_string(),
        path: path.to_string(),
        query: query.to_string(),
        headers,
        body: Vec::new(),
    };

    if req.header("transfer-encoding").is_some() {
        return Err(Response::error(
            411,
            "chunked bodies are not accepted; send Content-Length",
        ));
    }
    let length = match req.header("content-length") {
        None => 0,
        Some(v) => v
            .parse::<usize>()
            .map_err(|_| Response::error(400, "Content-Length is not a number"))?,
    };
    if length > MAX_BODY_BYTES {
        return Err(Response::error(
            413,
            &format!("the body must be at most {MAX_BODY_BYTES} bytes"),
        ));
    }
    if req.method == "POST" && req.header("content-length").is_none() {
        return Err(Response::error(411, "a POST needs Content-Length"));
    }
    if length > 0 {
        if req
            .header("expect")
            .is_some_and(|e| e.eq_ignore_ascii_case("100-continue"))
        {
            before_body();
        }
        req.body = vec![0; length];
        r.read_exact(&mut req.body)
            .map_err(|e| io_error_response(&e))?;
    }
    Ok(req)
}

fn io_error_response(e: &std::io::Error) -> Response {
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
            Response::error(408, "the request took too long")
        }
        std::io::ErrorKind::UnexpectedEof => Response::error(400, "the request ended early"),
        _ => Response::error(400, "the request could not be read"),
    }
}

/// Reads, routes and answers one connection, then lets it close.
///
/// `r` and `w` are the two halves of one connection (`TcpStream::try_clone`),
/// so a `100 Continue` can be written while the request is still being read.
pub fn handle_connection<R: Read, W: Write>(r: R, mut w: W, backend: &dyn Backend, opts: Options) {
    let mut reader = BufReader::new(r);
    let parsed = read_request(&mut reader, || {
        let _ = w.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
        let _ = w.flush();
    });
    let response = match parsed {
        Ok(req) => route(&req, backend, opts),
        Err(resp) => resp,
    };
    let _ = w.write_all(&response.to_bytes());
    let _ = w.flush();
}

// ---------------------------------------------------------------- routing

/// Every rule the API applies, in order: refuse cross-origin requests, find the
/// route, check its method and media type, then answer.
pub fn route(req: &Request, backend: &dyn Backend, opts: Options) -> Response {
    // A browser adds `Origin` to every cross-origin request and to every POST.
    // Nothing that legitimately uses this API is a web page, so refusing it is
    // free, and it stops a page in a local browser from lifting a block.
    if req.header("origin").is_some() {
        return Response::error(
            403,
            "requests from a web page (with an Origin header) are refused",
        );
    }
    let get_only = |f: &dyn Fn() -> Response| {
        if req.method == "GET" {
            f()
        } else {
            Response::method_not_allowed("GET")
        }
    };
    match req.path.as_str() {
        "/v1/health" => get_only(&|| health()),
        "/v1/status" => get_only(&|| Response::json(200, to_json(&backend.status()))),
        "/v1/stats" => get_only(&|| match backend.stats() {
            Ok(d) => Response::json(200, to_json(&d)),
            Err(e) => Response::error(503, &e),
        }),
        "/v1/blocks" => get_only(&|| match backend.banned() {
            Ok(docs) => Response::json(200, to_json(&docs)),
            Err(e) => Response::error(503, &e),
        }),
        "/v1/log" => get_only(&|| log(req, backend)),
        "/v1/unban" => {
            if req.method == "POST" {
                unban(req, backend, opts)
            } else {
                Response::method_not_allowed("POST")
            }
        }
        "/metrics" => get_only(&|| Response {
            status: 200,
            content_type: PROMETHEUS,
            body: metrics(backend),
            allow: None,
        }),
        p => match p.strip_prefix("/v1/blocks/") {
            Some(ip) => get_only(&|| one_block(ip, backend)),
            None => Response::error(404, "no such endpoint"),
        },
    }
}

fn health() -> Response {
    #[derive(Serialize)]
    struct Health {
        ok: bool,
        version: &'static str,
    }
    Response::json(
        200,
        to_json(&Health {
            ok: true,
            version: env!("CARGO_PKG_VERSION"),
        }),
    )
}

fn one_block(ip: &str, backend: &dyn Backend) -> Response {
    let Ok(ip) = ip.parse::<Ipv4Addr>() else {
        return Response::error(400, "not an IPv4 address");
    };
    let ip = ip.to_string();
    match backend.banned() {
        Ok(docs) => match docs.into_iter().find(|d| d.ip == ip) {
            Some(d) => Response::json(200, to_json(&d)),
            None => Response::error(404, "not blocked"),
        },
        Err(e) => Response::error(503, &e),
    }
}

/// `?limit=N&ip=A.B.C.D`, with no percent-decoding: neither value needs any,
/// and a value that would have needed it is refused rather than guessed at.
fn query_params(query: &str) -> Result<BTreeMap<&str, &str>, String> {
    let mut out = BTreeMap::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if out.insert(k, v).is_some() {
            return Err(format!("{k} is given twice"));
        }
    }
    Ok(out)
}

fn log(req: &Request, backend: &dyn Backend) -> Response {
    let params = match query_params(&req.query) {
        Ok(p) => p,
        Err(e) => return Response::error(400, &e),
    };
    if let Some(k) = params.keys().find(|k| !matches!(**k, "limit" | "ip")) {
        return Response::error(400, &format!("unknown parameter {k}; use limit and ip"));
    }
    let limit = match params.get("limit") {
        None => DEFAULT_LOG_LIMIT,
        Some(v) => match v.parse::<usize>() {
            Ok(n) if (1..=MAX_LOG_LIMIT).contains(&n) => n,
            _ => {
                return Response::error(
                    400,
                    &format!("limit must be a whole number from 1 to {MAX_LOG_LIMIT}"),
                )
            }
        },
    };
    let ip = match params.get("ip") {
        None => None,
        Some(v) => match v.parse::<Ipv4Addr>() {
            Ok(a) => Some(a.to_string()),
            Err(_) => return Response::error(400, "ip is not an IPv4 address"),
        },
    };
    match backend.log(limit, ip.as_deref()) {
        Ok(docs) => Response::json(200, to_json(&docs)),
        Err(e) => Response::error(503, &e),
    }
}

/// The body of `POST /v1/unban`. An unknown field is an error, as in the
/// configuration file: a misspelt `reason` must not be silently dropped.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnbanBody {
    ips: Vec<String>,
    source: Option<String>,
    reason: Option<String>,
}

fn is_json(req: &Request) -> bool {
    req.header("content-type").is_some_and(|ct| {
        ct.split(';')
            .next()
            .is_some_and(|m| m.trim().eq_ignore_ascii_case(JSON))
    })
}

fn unban(req: &Request, backend: &dyn Backend, opts: Options) -> Response {
    if !opts.allow_unban {
        return Response::error(
            403,
            "unbanning over HTTP is off; set http.allow_unban or pass --allow-unban",
        );
    }
    if !is_json(req) {
        return Response::error(415, "send the body as Content-Type: application/json");
    }
    let body: UnbanBody = match serde_json::from_slice(&req.body) {
        Ok(b) => b,
        Err(e) => return Response::error(400, &format!("the body: {e}")),
    };
    if body.ips.is_empty() {
        return Response::error(400, "ips must list at least one address");
    }
    if body.ips.len() > MAX_UNBAN_ADDRESSES {
        return Response::error(
            400,
            &format!("at most {MAX_UNBAN_ADDRESSES} addresses per request"),
        );
    }
    // Checked here, not left to `unban_docs`, so that a bad request is a 400 and
    // the only error `unban_docs` can still return means the map is unreachable.
    for ip in &body.ips {
        if ip.parse::<Ipv4Addr>().is_err() {
            return Response::error(400, &format!("{ip}: not an IPv4 address"));
        }
    }
    let source = body.source.as_deref().unwrap_or(DEFAULT_SOURCE);
    if let Err(e) = crate::manual_log::check_source(source) {
        return Response::error(400, &e.replacen("--source", "source", 1));
    }
    if let Some(r) = body.reason.as_deref() {
        if let Err(e) = crate::manual_log::check_reason(r) {
            return Response::error(400, &e.replacen("--reason", "reason", 1));
        }
    }
    match backend.unban(&body.ips, source, body.reason.as_deref()) {
        Err(e) => Response::error(503, &e),
        Ok(out) => unban_response(&out),
    }
}

/// 200 when every address came off; 422 when any was not blocked (the documents
/// say which); 500 when the kernel failed part-way, with the documents for the
/// addresses handled before it.
fn unban_response(out: &UnbanOutcome) -> Response {
    if let Some(e) = &out.failed {
        #[derive(Serialize)]
        struct Partial<'a> {
            error: &'a str,
            results: &'a [ActionDoc],
        }
        return Response::json(
            500,
            to_json(&Partial {
                error: e,
                results: &out.docs,
            }),
        );
    }
    let all = out.docs.iter().all(|d| d.applied);
    Response::json(if all { 200 } else { 422 }, to_json(&out.docs))
}

// ---------------------------------------------------------------- metrics

/// The Prometheus page: counts read from the kernel, and nothing else.
///
/// The block map is the state of the system, so every number here is either a
/// kernel counter or a count of the map's entries. No address leaves the map and
/// no database is read, so a scrape costs the same however long the audit log
/// grows. A value that cannot be read is left out, never reported as 0.
fn metrics(backend: &dyn Backend) -> String {
    render_metrics(&MetricInputs {
        kernel: backend.kernel_counters(),
        blocked: backend.map_counts().ok(),
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Everything `/metrics` shows, each part `None` when it could not be read.
pub struct MetricInputs<'a> {
    /// `(seen, dropped, expired)` from the XDP program's counters.
    pub kernel: Option<(u64, u64, u64)>,
    /// `(blocked now, of which permanent)` from the block map.
    pub blocked: Option<(usize, usize)>,
    pub version: &'a str,
}

/// Prometheus text exposition format 0.0.4.
pub fn render_metrics(m: &MetricInputs<'_>) -> String {
    let mut out = String::new();
    let mut family = |name: &str, kind: &str, help: &str, samples: &[(String, String)]| {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
        for (labels, value) in samples {
            out.push_str(&format!("{name}{labels} {value}\n"));
        }
    };
    let one = |v: String| vec![(String::new(), v)];

    family(
        "tfps_build_info",
        "gauge",
        "The running tfps_ctl version.",
        &[(labels(&[("version", m.version)]), "1".into())],
    );
    if let Some((seen, dropped, expired)) = m.kernel {
        family(
            "tfps_xdp_seen_total",
            "counter",
            "Packets the XDP program saw on the SIP ports.",
            &one(seen.to_string()),
        );
        family(
            "tfps_xdp_dropped_total",
            "counter",
            "Packets the XDP program dropped from blocked sources.",
            &one(dropped.to_string()),
        );
        family(
            "tfps_xdp_expired_total",
            "counter",
            "Blocks the kernel expired.",
            &one(expired.to_string()),
        );
    }
    if let Some((total, permanent)) = m.blocked {
        family(
            "tfps_blocked_sources",
            "gauge",
            "Sources in the kernel block map now.",
            &one(total.to_string()),
        );
        family(
            "tfps_blocked_sources_permanent",
            "gauge",
            "Sources in the kernel block map with no expiry.",
            &one(permanent.to_string()),
        );
    }
    out
}

/// `{a="x",b="y"}`, with each value escaped as the format requires.
fn labels(pairs: &[(&str, &str)]) -> String {
    let inner: Vec<String> = pairs
        .iter()
        .map(|(k, v)| {
            let v = v
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n");
            format!("{k}=\"{v}\"")
        })
        .collect();
    format!("{{{}}}", inner.join(","))
}

// ---------------------------------------------------------------- server

/// The startup warning for a listener other people can reach, or `None` on loopback.
///
/// It is a warning and not a refusal: the reverse proxy that adds authentication
/// may well be on another host.
pub fn bind_warning(addr: SocketAddrV4, allow_unban: bool) -> Option<String> {
    if addr.ip().is_loopback() {
        return None;
    }
    let what = if allow_unban {
        "read every block and lift them"
    } else {
        "read every block"
    };
    Some(format!(
        "WARNING: the HTTP API is listening on {addr}, which is not a loopback address. \
         It has no authentication: anyone who can reach it can {what}. \
         Put a reverse proxy with authentication in front of it, or firewall the port."
    ))
}

/// Accepts connections forever, handing each to one of [`WORKERS`] threads.
///
/// Returns only if accepting fails in a way that will not recover.
pub fn serve(
    listener: TcpListener,
    backend: Arc<dyn Backend>,
    opts: Options,
) -> std::io::Result<()> {
    let (tx, rx) = sync_channel::<TcpStream>(QUEUE);
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..WORKERS {
        let rx = Arc::clone(&rx);
        let backend = Arc::clone(&backend);
        std::thread::spawn(move || worker(&rx, backend.as_ref(), opts));
    }
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            // A client that went away between SYN and accept, or a transient
            // shortage of descriptors: neither is a reason to stop serving.
            Err(e) => {
                eprintln!("tfps_ctl serve: accept: {e}");
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        match tx.try_send(stream) {
            Ok(()) => {}
            Err(TrySendError::Full(mut s)) => {
                let _ = s.set_write_timeout(Some(IO_TIMEOUT));
                let _ = s.write_all(&Response::error(503, "busy; try again").to_bytes());
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err(std::io::Error::other("every worker has stopped"))
            }
        }
    }
    Ok(())
}

fn worker(rx: &Mutex<Receiver<TcpStream>>, backend: &dyn Backend, opts: Options) {
    loop {
        // The lock is held only while waiting for the next connection, never
        // while handling one. A poisoned lock means another worker panicked
        // mid-wait, and the receiver itself is still sound.
        let next = match rx.lock() {
            Ok(guard) => guard.recv(),
            Err(poisoned) => poisoned.into_inner().recv(),
        };
        let Ok(stream) = next else { return };
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        match stream.try_clone() {
            Ok(w) => handle_connection(stream, w, backend, opts),
            Err(e) => eprintln!("tfps_ctl serve: connection: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctl::{action_doc, banned_doc, log_doc};
    use crate::store::BlockRow;
    use std::io::Cursor;

    /// A backend with fixed answers, so every route is testable without a
    /// kernel map or a database. `None` means "that source cannot be read".
    #[derive(Default)]
    struct Fake {
        map: bool,
        db: bool,
        /// The address at which the kernel fails during `unban`, if any.
        kernel_fails_at: Option<&'static str>,
        /// Every `unban` call that reached the backend.
        unbanned: Mutex<Vec<UnbanCall>>,
    }

    /// `(addresses, source, reason)` of one `unban` call.
    type UnbanCall = (Vec<String>, String, Option<String>);

    fn up() -> Fake {
        Fake {
            map: true,
            db: true,
            ..Fake::default()
        }
    }

    const BLOCKED: [&str; 4] = ["203.0.113.1", "203.0.113.2", "203.0.113.3", "198.51.100.9"];

    impl Fake {
        fn docs(&self) -> Vec<BannedDoc> {
            vec![
                banned_doc(
                    BLOCKED[0],
                    Some(("scanner", "friendly-scanner")),
                    Some(100),
                    Some(4000),
                ),
                banned_doc(BLOCKED[1], Some(("manual", "abuse desk")), None, None)
                    .with_source(Some("panel")),
                banned_doc(BLOCKED[2], None, None, Some(5000)),
                banned_doc(BLOCKED[3], Some(("apiban", "feed")), None, None),
            ]
        }
    }

    impl Backend for Fake {
        fn status(&self) -> StatusDoc {
            crate::ctl::status_doc(
                if self.map {
                    Ok((4, "own map id 7".into()))
                } else {
                    Err("no map".into())
                },
                self.db.then_some((10, 10, 1_000)),
                std::path::Path::new("/var/lib/tfps/tfps.db"),
                "9.9.9",
            )
        }
        fn stats(&self) -> Result<StatsDoc, String> {
            if !self.db {
                return Err("opening the database: no such file".into());
            }
            Ok(crate::ctl::stats_doc(
                self.map.then_some((1000, 40, 3)),
                None,
                crate::ctl::traffic_doc(Some("udp=120 syn=40 bad=xx"), Some(1_000), 1_060),
                None,
                None,
                None,
                crate::ctl::learned_doc(5, 5, 3, 77),
                crate::ctl::blocks_doc(2, vec![], vec![], vec![]),
            ))
        }
        fn banned(&self) -> Result<Vec<BannedDoc>, String> {
            if self.map {
                Ok(self.docs())
            } else {
                Err("opening the block map: not found".into())
            }
        }
        fn log(&self, limit: usize, ip: Option<&str>) -> Result<Vec<LogDoc>, String> {
            if !self.db {
                return Err("no database".into());
            }
            let rows = [
                (300, "203.0.113.1"),
                (200, "203.0.113.2"),
                (100, "203.0.113.1"),
            ];
            Ok(rows
                .iter()
                .filter(|(_, a)| ip.is_none_or(|w| w == *a))
                .take(limit)
                .map(|(ts, a)| {
                    let row = BlockRow {
                        ts: *ts,
                        ip: a.to_string(),
                        reason: "scanner".into(),
                        detail: "x".into(),
                    };
                    log_doc(&row, None, None, true, "block")
                })
                .collect())
        }
        fn kernel_counters(&self) -> Option<(u64, u64, u64)> {
            self.map.then_some((1000, 40, 3))
        }
        fn map_counts(&self) -> Result<(usize, usize), String> {
            let docs = self.banned()?;
            let permanent = docs.iter().filter(|d| d.expires.is_none()).count();
            Ok((docs.len(), permanent))
        }
        fn unban(
            &self,
            ips: &[String],
            source: &str,
            reason: Option<&str>,
        ) -> Result<UnbanOutcome, String> {
            if !self.map {
                return Err("opening the block map: not found".into());
            }
            self.unbanned.lock().unwrap().push((
                ips.to_vec(),
                source.to_string(),
                reason.map(str::to_string),
            ));
            let mut docs = Vec::new();
            for ip in ips {
                if self.kernel_fails_at == Some(ip.as_str()) {
                    return Ok(UnbanOutcome {
                        docs,
                        failed: Some(format!("removing {ip}: EPERM")),
                    });
                }
                let refused = (!BLOCKED.contains(&ip.as_str())).then_some("not-blocked");
                docs.push(action_doc(Some(ip), "unban", refused, None).with_source(Some(source)));
            }
            Ok(UnbanOutcome { docs, failed: None })
        }
    }

    fn get(path: &str) -> Request {
        let (path, query) = path.split_once('?').unwrap_or((path, ""));
        Request {
            method: "GET".into(),
            path: path.into(),
            query: query.into(),
            ..Request::default()
        }
    }

    fn post_unban(body: &str) -> Request {
        Request {
            method: "POST".into(),
            path: "/v1/unban".into(),
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
            ..Request::default()
        }
    }

    const ON: Options = Options { allow_unban: true };
    const OFF: Options = Options { allow_unban: false };

    fn json(r: &Response) -> serde_json::Value {
        assert_eq!(r.content_type, JSON, "{r:?}");
        serde_json::from_str(&r.body).expect("valid JSON")
    }

    // ── reading requests off the wire ──────────────────────────────────────

    fn parse(raw: &str) -> Result<Request, Response> {
        read_request(&mut Cursor::new(raw.as_bytes().to_vec()), || {})
    }

    #[test]
    fn a_request_is_split_into_method_path_query_headers_and_body() {
        let r = parse(
            "POST /v1/unban?x=1 HTTP/1.1\r\nHost: 127.0.0.1:9060\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        )
        .expect("parses");
        assert_eq!(
            (r.method.as_str(), r.path.as_str(), r.query.as_str()),
            ("POST", "/v1/unban", "x=1")
        );
        assert_eq!(
            r.header("content-type"),
            Some("application/json"),
            "names are lower-cased"
        );
        assert_eq!(r.body, b"{}");
    }

    #[test]
    fn malformed_requests_are_400() {
        for raw in [
            "GET\r\n\r\n",
            "GET /v1/health\r\n\r\n",
            "GET v1/health HTTP/1.1\r\n\r\n",
            "GET /v1/health HTTP/2\r\n\r\n",
            "GET /v1/health HTTP/1.1\r\nno colon here\r\n\r\n",
            "GET /v1/health HTTP/1.1\r\nContent-Length: ten\r\n\r\n",
            "GET /v1/health HTTP/1.1\r\n",
            "POST /v1/unban HTTP/1.1\r\nContent-Length: 10\r\n\r\n{}",
        ] {
            assert_eq!(parse(raw).expect_err(raw).status, 400, "{raw:?}");
        }
    }

    #[test]
    fn an_oversized_head_is_refused_before_it_is_buffered() {
        let raw = format!(
            "GET /v1/health HTTP/1.1\r\nX: {}\r\n\r\n",
            "a".repeat(MAX_HEADER_BYTES)
        );
        assert_eq!(parse(&raw).expect_err("too big").status, 431);
    }

    #[test]
    fn an_oversized_body_is_refused_before_it_is_read() {
        let raw = format!(
            "POST /v1/unban HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        assert_eq!(parse(&raw).expect_err("too big").status, 413);
    }

    #[test]
    fn chunked_bodies_and_posts_without_a_length_are_411() {
        let chunked =
            "POST /v1/unban HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert_eq!(parse(chunked).expect_err("chunked").status, 411);
        assert_eq!(
            parse("POST /v1/unban HTTP/1.1\r\n\r\n")
                .expect_err("no length")
                .status,
            411
        );
    }

    #[test]
    fn expect_100_continue_is_answered_before_the_body_is_read() {
        let raw = "POST /v1/unban HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n{}";
        let mut asked = 0;
        read_request(&mut Cursor::new(raw.as_bytes().to_vec()), || asked += 1).expect("parses");
        assert_eq!(asked, 1);
    }

    #[test]
    fn a_whole_connection_gets_one_complete_response_and_closes() {
        let mut out = Vec::new();
        handle_connection(
            Cursor::new(b"GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n".to_vec()),
            &mut out,
            &up(),
            OFF,
        );
        let text = String::from_utf8(out).expect("utf-8");
        let (head, body) = text.split_once("\r\n\r\n").expect("head and body");
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert!(head.contains("Connection: close"), "{head}");
        assert!(
            head.contains(&format!("Content-Length: {}", body.len())),
            "{head}"
        );
        assert_eq!(
            body,
            format!(r#"{{"ok":true,"version":"{}"}}"#, env!("CARGO_PKG_VERSION"))
        );
    }

    // ── what every route refuses ───────────────────────────────────────────

    #[test]
    fn any_request_with_an_origin_header_is_refused() {
        for (path, method) in [
            ("/v1/blocks", "GET"),
            ("/v1/unban", "POST"),
            ("/metrics", "GET"),
        ] {
            let mut r = if method == "POST" {
                post_unban(r#"{"ips":["203.0.113.1"]}"#)
            } else {
                get(path)
            };
            r.headers
                .push(("origin".into(), "http://evil.example".into()));
            assert_eq!(route(&r, &up(), ON).status, 403, "{path}");
        }
        assert!(up().unbanned.lock().unwrap().is_empty());
    }

    #[test]
    fn unknown_paths_are_404_and_wrong_methods_405() {
        assert_eq!(route(&get("/v2/blocks"), &up(), ON).status, 404);
        assert_eq!(route(&get("/"), &up(), ON).status, 404);
        let mut r = get("/v1/blocks");
        r.method = "DELETE".into();
        let resp = route(&r, &up(), ON);
        assert_eq!((resp.status, resp.allow), (405, Some("GET")));
        let resp = route(&get("/v1/unban"), &up(), ON);
        assert_eq!((resp.status, resp.allow), (405, Some("POST")));
        assert!(String::from_utf8(resp.to_bytes())
            .unwrap()
            .contains("\r\nAllow: POST\r\n"));
    }

    // ── read endpoints ─────────────────────────────────────────────────────

    #[test]
    fn health_names_the_version() {
        let v = json(&route(&get("/v1/health"), &up(), OFF));
        assert_eq!(v["ok"], true);
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn status_is_the_status_document_even_when_nothing_can_be_read() {
        let fake = Fake::default();
        let r = route(&get("/v1/status"), &fake, OFF);
        assert_eq!(r.status, 200);
        assert_eq!(r.body, crate::json_line(&fake.status()).unwrap());
        assert_eq!(json(&r)["enforcement"], "inactive");
    }

    /// `/v1/blocks` is `banned --why --json` as one array: each element is
    /// byte-for-byte the line the CLI prints for the same documents.
    #[test]
    fn blocks_are_the_cli_lines_as_one_array() {
        let fake = up();
        let r = route(&get("/v1/blocks"), &fake, OFF);
        assert_eq!(r.status, 200);
        let lines: Vec<String> = fake
            .docs()
            .iter()
            .map(|d| crate::json_line(d).unwrap())
            .collect();
        assert_eq!(r.body, format!("[{}]", lines.join(",")));
        let v = json(&r);
        assert_eq!(v[0]["reason"], "scanner", "every block carries its reason");
        assert_eq!(v[1]["source"], "panel");
    }

    #[test]
    fn one_block_by_address() {
        let r = route(&get("/v1/blocks/203.0.113.2"), &up(), OFF);
        assert_eq!(r.status, 200);
        assert_eq!(r.body, crate::json_line(&up().docs()[1]).unwrap());
        assert_eq!(route(&get("/v1/blocks/192.0.2.1"), &up(), OFF).status, 404);
        assert_eq!(route(&get("/v1/blocks/not-an-ip"), &up(), OFF).status, 400);
    }

    #[test]
    fn an_unreadable_map_or_database_is_503() {
        let down = Fake::default();
        for p in [
            "/v1/blocks",
            "/v1/blocks/203.0.113.1",
            "/v1/stats",
            "/v1/log",
        ] {
            let r = route(&get(p), &down, OFF);
            assert_eq!(r.status, 503, "{p}");
            assert!(json(&r)["error"].is_string(), "{p}");
        }
    }

    #[test]
    fn the_log_takes_a_capped_limit_and_an_address() {
        let n = |q: &str| {
            json(&route(&get(&format!("/v1/log{q}")), &up(), OFF))
                .as_array()
                .unwrap()
                .len()
        };
        assert_eq!(n(""), 3);
        assert_eq!(n("?limit=1"), 1);
        assert_eq!(n("?ip=203.0.113.1"), 2);
        assert_eq!(n("?limit=1&ip=203.0.113.1"), 1);
        for bad in [
            "?limit=0",
            "?limit=1001",
            "?limit=x",
            "?ip=nope",
            "?ip=1.2.3.4&ip=1.2.3.5",
            "?other=1",
        ] {
            assert_eq!(
                route(&get(&format!("/v1/log{bad}")), &up(), OFF).status,
                400,
                "{bad}"
            );
        }
    }

    // ── unban ──────────────────────────────────────────────────────────────

    #[test]
    fn unban_is_403_unless_allowed_and_nothing_is_touched() {
        let fake = up();
        let r = route(&post_unban(r#"{"ips":["203.0.113.1"]}"#), &fake, OFF);
        assert_eq!(r.status, 403);
        assert!(fake.unbanned.lock().unwrap().is_empty());
    }

    #[test]
    fn unban_takes_json_only() {
        let mut r = post_unban(r#"{"ips":["203.0.113.1"]}"#);
        r.headers = vec![("content-type".into(), "text/plain".into())];
        assert_eq!(route(&r, &up(), ON).status, 415);
        r.headers.clear();
        assert_eq!(route(&r, &up(), ON).status, 415);
        r.headers = vec![(
            "content-type".into(),
            "Application/JSON; charset=utf-8".into(),
        )];
        assert_eq!(
            route(&r, &up(), ON).status,
            200,
            "parameters and case are fine"
        );
    }

    #[test]
    fn unban_refuses_bad_bodies_before_touching_anything() {
        let too_many: Vec<String> = (0..=MAX_UNBAN_ADDRESSES)
            .map(|i| format!("\"10.0.{}.{}\"", i / 256, i % 256))
            .collect();
        let too_many = format!(r#"{{"ips":[{}]}}"#, too_many.join(","));
        let fake = up();
        for body in [
            "not json",
            "{}",
            r#"{"ips":[]}"#,
            r#"{"ips":["203.0.113.1"],"reasn":"typo"}"#,
            r#"{"ips":["203.0.113.1","nope"]}"#,
            r#"{"ips":["203.0.113.1"],"source":"has space"}"#,
            r#"{"ips":["203.0.113.1"],"reason":"line\nbreak"}"#,
            too_many.as_str(),
        ] {
            let r = route(&post_unban(body), &fake, ON);
            assert_eq!(r.status, 400, "{body:.60}");
            assert!(json(&r)["error"].is_string());
        }
        assert!(fake.unbanned.lock().unwrap().is_empty());
    }

    #[test]
    fn unban_records_http_as_the_source_unless_told_otherwise() {
        let fake = up();
        let r = route(&post_unban(r#"{"ips":["203.0.113.1"]}"#), &fake, ON);
        assert_eq!(r.status, 200);
        assert_eq!(json(&r)[0]["source"], "http");
        let r = route(
            &post_unban(r#"{"ips":["203.0.113.2"],"source":"panel","reason":"customer asked"}"#),
            &fake,
            ON,
        );
        assert_eq!(json(&r)[0]["source"], "panel");
        let calls = fake.unbanned.lock().unwrap();
        assert_eq!(calls[0].1, "http");
        assert_eq!(
            (calls[1].1.as_str(), calls[1].2.as_deref()),
            ("panel", Some("customer asked"))
        );
    }

    #[test]
    fn unban_is_200_when_all_came_off_and_422_when_any_was_not_blocked() {
        let r = route(
            &post_unban(r#"{"ips":["203.0.113.1","203.0.113.2"]}"#),
            &up(),
            ON,
        );
        assert_eq!(r.status, 200);
        let r = route(
            &post_unban(r#"{"ips":["203.0.113.1","192.0.2.7"]}"#),
            &up(),
            ON,
        );
        assert_eq!(r.status, 422);
        let v = json(&r);
        assert_eq!(v[0]["applied"], true);
        assert_eq!(v[1]["refused"], "not-blocked");
    }

    #[test]
    fn a_kernel_failure_part_way_is_500_with_what_was_done() {
        let fake = Fake {
            kernel_fails_at: Some("203.0.113.2"),
            ..up()
        };
        let r = route(
            &post_unban(r#"{"ips":["203.0.113.1","203.0.113.2","203.0.113.3"]}"#),
            &fake,
            ON,
        );
        assert_eq!(r.status, 500);
        let v = json(&r);
        assert!(v["error"].as_str().unwrap().contains("EPERM"));
        assert_eq!(v["results"].as_array().unwrap().len(), 1);
        assert_eq!(v["results"][0]["ip"], "203.0.113.1");
    }

    #[test]
    fn an_unreachable_map_makes_unban_503() {
        let r = route(
            &post_unban(r#"{"ips":["203.0.113.1"]}"#),
            &Fake {
                db: true,
                ..Fake::default()
            },
            ON,
        );
        assert_eq!(r.status, 503);
    }

    // ── metrics ────────────────────────────────────────────────────────────

    /// Enough of the text format to catch a malformed page: every sample's family
    /// is declared once by `# TYPE` before it, names and labels are well formed,
    /// and every value is a number. Returns `name{labels} -> value`.
    fn parse_prometheus(text: &str) -> BTreeMap<String, f64> {
        let mut typed = std::collections::HashSet::new();
        let mut samples = BTreeMap::new();
        let name_ok = |n: &str| {
            !n.is_empty()
                && n.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
                && !n.starts_with(|c: char| c.is_ascii_digit())
        };
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let (name, kind) = rest.split_once(' ').expect("TYPE name kind");
                assert!(name_ok(name), "{line}");
                assert!(["counter", "gauge"].contains(&kind), "{line}");
                assert!(
                    typed.insert(name.to_string()),
                    "TYPE declared twice: {line}"
                );
                continue;
            }
            if line.starts_with("# HELP ") {
                continue;
            }
            assert!(
                !line.starts_with('#') && !line.is_empty(),
                "stray line: {line:?}"
            );
            let (series, value) = line.rsplit_once(' ').expect("series value");
            let name = series.split('{').next().unwrap();
            assert!(name_ok(name), "{line}");
            assert!(typed.contains(name), "sample before its TYPE: {line}");
            if let Some(l) = series.strip_prefix(name) {
                if !l.is_empty() {
                    assert!(l.starts_with('{') && l.ends_with('}'), "{line}");
                }
            }
            let v: f64 = value
                .parse()
                .unwrap_or_else(|_| panic!("not a number: {line}"));
            assert!(
                samples.insert(series.to_string(), v).is_none(),
                "duplicate series: {line}"
            );
        }
        samples
    }

    #[test]
    fn metrics_parse_and_carry_the_kernels_counts() {
        let r = route(&get("/metrics"), &up(), OFF);
        assert_eq!(r.status, 200);
        assert!(r.content_type.starts_with("text/plain; version=0.0.4"));
        let m = parse_prometheus(&r.body);
        assert_eq!(m["tfps_xdp_seen_total"], 1000.0);
        assert_eq!(m["tfps_xdp_dropped_total"], 40.0);
        assert_eq!(m["tfps_xdp_expired_total"], 3.0);
        assert_eq!(m["tfps_blocked_sources"], 4.0);
        assert_eq!(m["tfps_blocked_sources_permanent"], 2.0);
        assert_eq!(
            m[&format!(
                r#"tfps_build_info{{version="{}"}}"#,
                env!("CARGO_PKG_VERSION")
            )],
            1.0
        );
        assert_eq!(
            m.len(),
            6,
            "nothing but kernel counts and the version: {m:?}"
        );
    }

    /// No address and no database: a scrape must not depend on how long the
    /// audit log is, so the database being unreadable changes nothing.
    #[test]
    fn metrics_read_no_database() {
        let no_db = Fake {
            map: true,
            ..Fake::default()
        };
        assert_eq!(
            route(&get("/metrics"), &no_db, OFF).body,
            route(&get("/metrics"), &up(), OFF).body
        );
        assert!(!fn_body("metrics").contains("stats()"));
        assert!(!fn_body("metrics").contains("banned()"));
        assert!(!fn_body("metrics").contains("log("));
    }

    #[test]
    fn metrics_omit_what_cannot_be_read_and_never_report_it_as_zero() {
        let m = parse_prometheus(&route(&get("/metrics"), &Fake::default(), OFF).body);
        assert_eq!(m.len(), 1, "only build_info is left: {m:?}");
    }

    #[test]
    fn a_label_value_is_escaped() {
        assert_eq!(labels(&[("k", "a\\b\"c\nd")]), r#"{k="a\\b\"c\nd"}"#);
    }

    /// One top-level function's body in this file, for checks on what it calls.
    fn fn_body(name: &str) -> &'static str {
        let src = include_str!("api.rs");
        let start = src
            .find(&format!("\nfn {name}("))
            .unwrap_or_else(|| panic!("no `fn {name}(` in api.rs"));
        let len = src[start..]
            .find("\n}\n")
            .expect("rustfmt closes it at column 0");
        &src[start..start + len]
    }

    // ── the listener ───────────────────────────────────────────────────────

    #[test]
    fn a_non_loopback_listener_is_warned_about() {
        assert_eq!(bind_warning("127.0.0.1:9060".parse().unwrap(), true), None);
        assert_eq!(
            bind_warning("127.10.0.1:9060".parse().unwrap(), false),
            None
        );
        let w = bind_warning("0.0.0.0:9060".parse().unwrap(), false).expect("warns");
        assert!(
            w.starts_with("WARNING") && w.contains("no authentication"),
            "{w}"
        );
        assert!(!w.contains("lift"), "{w}");
        let w = bind_warning("192.0.2.1:9060".parse().unwrap(), true).expect("warns");
        assert!(w.contains("lift"), "{w}");
    }

    /// The whole path once, over a real loopback socket.
    #[test]
    fn serve_answers_over_a_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || serve(listener, Arc::new(up()), OFF));
        let mut s = TcpStream::connect(addr).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(b"GET /v1/blocks/203.0.113.1 HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out)
            .expect("the server closes the connection");
        assert!(out.starts_with("HTTP/1.1 200 OK\r\n"), "{out}");
        assert!(
            out.ends_with(&crate::json_line(&up().docs()[0]).unwrap()),
            "{out}"
        );
    }

    /// A client that connects and says nothing is cut off by the read timeout,
    /// not held forever.
    #[test]
    fn a_silent_client_is_not_waited_on_forever() {
        let (mut client, server) = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
            (c, l.accept().unwrap().0)
        };
        server
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let w = server.try_clone().unwrap();
        let start = std::time::Instant::now();
        handle_connection(server, w, &up(), OFF);
        assert!(start.elapsed() < Duration::from_secs(2));
        let mut out = String::new();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.read_to_string(&mut out).unwrap();
        assert!(out.starts_with("HTTP/1.1 408 "), "{out}");
    }
}
