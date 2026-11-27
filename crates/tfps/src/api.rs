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
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::mpsc::{sync_channel, Receiver, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::ctl::{
    ActionDoc, BannedDoc, Ctx, DbCounts, LogDoc, StatsDoc, StatusDoc, UnbanOutcome, UnbanTarget,
};

/// Worker threads. Each handles one connection at a time, start to finish.
pub const WORKERS: usize = 4;
/// Accepted connections waiting for a worker. Past this, a new connection gets a
/// 503 straight away rather than an unbounded wait.
pub const QUEUE: usize = 16;
/// How long a single read or write on one connection may stall.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// How long reading a whole request may take, and separately how long writing
/// its response may take: a deadline, not an inactivity timeout, so a client
/// trickling a byte at a time cannot hold a worker for longer than this.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
/// Header lines in one request.
pub const MAX_HEADERS: usize = 32;
/// Full `/v1/blocks` listings in progress at once. A listing of a full map costs
/// tens of megabytes while it is built and written, so they take turns rather
/// than multiply under the service's memory limit; a request that cannot get a
/// turn before its deadline gets 503.
pub const MAX_LISTINGS: usize = 1;
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
    /// One address's document, `None` when it is not blocked.
    fn banned_one(&self, ip: Ipv4Addr) -> Result<Option<BannedDoc>, String>;
    fn log(&self, limit: usize, ip: Option<&str>) -> Result<Vec<LogDoc>, String>;
    /// The XDP program's `(seen, dropped, expired)` counters, `None` when unreadable.
    fn kernel_counters(&self) -> Option<(u64, u64, u64)>;
    /// `(blocked now, of which permanent)`, counted from the block map.
    fn map_counts(&self) -> Result<(usize, usize), String>;
    /// The counts `/metrics` reads from SQLite. No addresses.
    fn db_counts(&self) -> Result<DbCounts, String>;
    /// Webhook delivery outcomes, `(url index, result, count)`; empty with no hooks.
    fn hook_deliveries(&self) -> Vec<(usize, &'static str, u64)> {
        Vec::new()
    }
    /// Lift these already-validated addresses. `Err` means nothing was touched.
    fn unban(
        &self,
        ips: &[String],
        source: &str,
        reason: Option<&str>,
    ) -> Result<UnbanOutcome, String>;
}

/// The real thing: every answer is the matching `tfps_ctl --json` document. The
/// second field is the webhook sender's delivery counts, when hooks are on.
pub struct CtlBackend(pub Ctx, pub Option<Arc<crate::hooks::Stats>>);

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
    fn banned_one(&self, ip: Ipv4Addr) -> Result<Option<BannedDoc>, String> {
        crate::ctl::banned_doc_for(&self.0, ip)
    }
    fn log(&self, limit: usize, ip: Option<&str>) -> Result<Vec<LogDoc>, String> {
        crate::ctl::log_docs(&self.0, limit, ip)
    }
    fn kernel_counters(&self) -> Option<(u64, u64, u64)> {
        crate::ctl::kernel_counters(&self.0)
    }
    fn map_counts(&self) -> Result<(usize, usize), String> {
        crate::ctl::map_counts(&self.0)
    }
    fn db_counts(&self) -> Result<DbCounts, String> {
        crate::ctl::db_counts(&self.0)
    }
    fn hook_deliveries(&self) -> Vec<(usize, &'static str, u64)> {
        self.1.as_ref().map(|s| s.snapshot()).unwrap_or_default()
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Accept `POST /v1/unban`.
    pub allow_unban: bool,
    /// The `Host` values a request may carry, compared without regard to case.
    /// A request naming any other host is refused: that is what stops a web page
    /// that rebinds its own name to this address from reading the API.
    pub hosts: Vec<String>,
    /// When set, every route but `/v1/health` needs `Authorization: Bearer <token>`.
    pub token: Option<String>,
    /// [`REQUEST_DEADLINE`], shortened by tests.
    pub deadline: Duration,
}

impl Options {
    pub fn new(allow_unban: bool, hosts: Vec<String>, token: Option<String>) -> Self {
        Options {
            allow_unban,
            hosts,
            token,
            deadline: REQUEST_DEADLINE,
        }
    }
}

/// The `Host` values `serve` accepts by default: the listen address as clients
/// write it, plus `localhost` with the same port when listening on loopback,
/// plus the operator's own `extra` (for a reverse proxy's public name).
pub fn allowed_hosts(listen: SocketAddrV4, extra: &[String]) -> Vec<String> {
    let mut hosts = vec![listen.to_string()];
    if listen.ip().is_loopback() {
        hosts.push(format!("localhost:{}", listen.port()));
    }
    hosts.extend(extra.iter().map(|h| h.trim().to_ascii_lowercase()));
    hosts
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
    /// `WWW-Authenticate: Bearer`, on a 401.
    pub challenge: bool,
    /// A listing written to the socket one document at a time, instead of
    /// `body`: a full block map would otherwise sit in memory a second time as
    /// one JSON string. Sent without `Content-Length`, ended by closing.
    pub docs: Option<Vec<BannedDoc>>,
}

const JSON: &str = "application/json";
const PROMETHEUS: &str = "text/plain; version=0.0.4; charset=utf-8";
const HTML: &str = "text/html; charset=utf-8";

/// The dashboard: one page, its stylesheet and its script, built into the
/// binary. They hold no data; the script reads the `/v1` routes like any
/// other client, from the same origin, under the same `Host` check and token.
const DASHBOARD_HTML: &str = include_str!("dashboard/index.html");
const DASHBOARD_CSS: &str = include_str!("dashboard/dashboard.css");
const DASHBOARD_JS: &str = include_str!("dashboard/dashboard.js");

/// The routes of the dashboard's own files: served without the token (the
/// page has to load before it can ask for one), and read-only.
const DASHBOARD_FILES: [&str; 3] = ["/", "/dashboard.css", "/dashboard.js"];

/// What the dashboard page may load: only its own stylesheet and script, and
/// only this API to talk to. No inline script or style, nothing from another
/// origin, no frames, no forms sent anywhere.
const DASHBOARD_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
     connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; \
     frame-ancestors 'none'";

impl Response {
    fn json(status: u16, body: String) -> Self {
        Response {
            status,
            content_type: JSON,
            body,
            allow: None,
            challenge: false,
            docs: None,
        }
    }

    /// A JSON array streamed from `docs`, byte for byte what `json(200,
    /// to_json(&docs))` would send.
    fn listing(docs: Vec<BannedDoc>) -> Self {
        Response {
            docs: Some(docs),
            ..Self::json(200, String::new())
        }
    }

    /// The body as it goes on the wire, for tests and the busy reply.
    pub fn body_text(&self) -> String {
        match &self.docs {
            Some(docs) => to_json(docs),
            None => self.body.clone(),
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

    fn unauthorized() -> Self {
        Response {
            challenge: true,
            ..Self::error(401, "this API needs Authorization: Bearer <token>")
        }
    }

    /// The bytes on the wire.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.head();
        out.extend_from_slice(self.body_text().as_bytes());
        out
    }

    /// The status line and headers, ending with the blank line.
    fn head(&self) -> Vec<u8> {
        let mut head = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\n\
             Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n",
            self.status,
            reason_phrase(self.status),
            self.content_type,
        );
        if self.docs.is_none() {
            head.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }
        if let Some(a) = self.allow {
            head.push_str(&format!("Allow: {a}\r\n"));
        }
        if self.challenge {
            head.push_str("WWW-Authenticate: Bearer\r\n");
        }
        if self.content_type == HTML {
            head.push_str(&format!(
                "Content-Security-Policy: {DASHBOARD_CSP}\r\n\
                 X-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\n"
            ));
        }
        head.push_str("\r\n");
        head.into_bytes()
    }
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
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

/// One connection, as the server reads and writes it.
pub trait Conn: Read + Write {
    /// Bounds the next read or write to `remaining` (never above [`IO_TIMEOUT`]).
    fn limit(&mut self, remaining: Duration) -> std::io::Result<()>;
}

impl Conn for TcpStream {
    fn limit(&mut self, remaining: Duration) -> std::io::Result<()> {
        let t = remaining.clamp(Duration::from_millis(1), IO_TIMEOUT);
        self.set_read_timeout(Some(t))?;
        self.set_write_timeout(Some(t))
    }
}

impl<C: Conn + ?Sized> Conn for &mut C {
    fn limit(&mut self, remaining: Duration) -> std::io::Result<()> {
        (**self).limit(remaining)
    }
}

/// Time left before `deadline`, or `None` when it has passed.
fn remaining(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
}

/// Whether `head` has a line ending other than CRLF: a bare LF, or a CR not
/// followed by LF. HTTP/1.1 parsers disagree on what to do with those, and that
/// disagreement between a proxy and this server is how requests get smuggled,
/// so they are refused rather than interpreted.
fn bad_line_ending(head: &[u8]) -> bool {
    head.iter().enumerate().any(|(i, &b)| match b {
        b'\n' => i == 0 || head[i - 1] != b'\r',
        b'\r' => head.get(i + 1).is_some_and(|&n| n != b'\n'),
        _ => false,
    })
}

/// Reads one request through `httparse`, refusing anything past the limits
/// before it is buffered, and anything not read in full by `deadline`.
///
/// On top of what `httparse` checks (the request line, header names against the
/// token grammar), this refuses: line endings other than CRLF; any
/// `Transfer-Encoding`; a `Content-Length` or `Host` given more than once; a
/// `Content-Length` that is not plain digits. A client that asks for
/// `100-continue` is told to go ahead once its headers are accepted.
pub fn read_request<C: Conn>(c: &mut C, deadline: Instant) -> Result<Request, Response> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let mut read_some = |c: &mut C, buf: &mut Vec<u8>| -> Result<(), Response> {
        let left =
            remaining(deadline).ok_or_else(|| Response::error(408, "the request took too long"))?;
        c.limit(left).map_err(|e| io_error_response(&e))?;
        match c.read(&mut chunk) {
            Ok(0) => Err(Response::error(400, "the request ended early")),
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                Ok(())
            }
            Err(e) => Err(io_error_response(&e)),
        }
    };

    let head_end = loop {
        let end = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
        let head = &buf[..end.unwrap_or(buf.len())];
        if bad_line_ending(head) {
            return Err(Response::error(400, "lines must end with CRLF"));
        }
        if end.unwrap_or(buf.len()) > MAX_HEADER_BYTES {
            return Err(Response::error(
                431,
                &format!("the request line and headers must fit in {MAX_HEADER_BYTES} bytes"),
            ));
        }
        if let Some(end) = end {
            break end;
        }
        read_some(c, &mut buf)?;
    };

    let mut slots = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Request::new(&mut slots);
    match parsed.parse(&buf[..head_end]) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => return Err(Response::error(400, "incomplete request")),
        Err(httparse::Error::TooManyHeaders) => {
            return Err(Response::error(
                431,
                &format!("at most {MAX_HEADERS} header lines"),
            ))
        }
        Err(e) => return Err(Response::error(400, &format!("malformed request: {e}"))),
    }
    let (Some(method), Some(target), Some(_)) = (parsed.method, parsed.path, parsed.version) else {
        return Err(Response::error(400, "malformed request line"));
    };
    if !target.starts_with('/') {
        return Err(Response::error(400, "the request target must be a path"));
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = Vec::with_capacity(parsed.headers.len());
    for h in parsed.headers.iter() {
        let value = std::str::from_utf8(h.value)
            .map_err(|_| Response::error(400, "a header value is not UTF-8"))?;
        headers.push((h.name.to_ascii_lowercase(), value.trim().to_string()));
    }
    let mut req = Request {
        method: method.to_string(),
        path: path.to_string(),
        query: query.to_string(),
        headers,
        body: Vec::new(),
    };

    let count = |name: &str| req.headers.iter().filter(|(n, _)| n == name).count();
    if count("transfer-encoding") > 0 {
        return Err(Response::error(
            411,
            "Transfer-Encoding is not accepted; send Content-Length",
        ));
    }
    if count("content-length") > 1 || count("host") > 1 {
        return Err(Response::error(
            400,
            "Content-Length and Host may appear once each",
        ));
    }
    let length = match req.header("content-length") {
        None => 0,
        Some(v) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => v
            .parse::<usize>()
            .map_err(|_| Response::error(413, "Content-Length is too large"))?,
        Some(_) => return Err(Response::error(400, "Content-Length is not a number")),
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
        let mut body = buf.split_off(head_end);
        let continue_asked = req
            .header("expect")
            .is_some_and(|e| e.eq_ignore_ascii_case("100-continue"));
        if continue_asked
            && body.is_empty()
            && write_by(c, b"HTTP/1.1 100 Continue\r\n\r\n", deadline)
        {
            let _ = c.flush();
        }
        while body.len() < length {
            read_some(c, &mut body)?;
        }
        body.truncate(length);
        req.body = body;
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

/// Writes all of `bytes` by `deadline`. Every single `write` is bounded by the
/// time left at that moment, so a reader taking a few bytes at a time cannot
/// stretch one call past the deadline, as `write_all` with one timeout would.
fn write_by<C: Conn>(c: &mut C, mut bytes: &[u8], deadline: Instant) -> bool {
    while !bytes.is_empty() {
        let Some(left) = remaining(deadline) else {
            return false;
        };
        if c.limit(left).is_err() {
            return false;
        }
        match c.write(bytes) {
            Ok(0) => return false,
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    true
}

/// Writes `resp` by `deadline`, a slice at a time, each write bounded by the time
/// left. A reader too slow to take it in time is abandoned rather than waited on.
/// A listing is serialised a document at a time into a small buffer, never whole.
fn write_response<C: Conn>(c: &mut C, resp: &Response, deadline: Instant) {
    const SLICE: usize = 16 * 1024;
    let mut send = |bytes: &[u8]| -> bool {
        bytes
            .chunks(SLICE)
            .all(|piece| write_by(c, piece, deadline))
    };
    if !send(&resp.head()) {
        return;
    }
    match &resp.docs {
        None => {
            if !send(resp.body.as_bytes()) {
                return;
            }
        }
        Some(docs) => {
            let mut buf = Vec::with_capacity(2 * SLICE);
            buf.push(b'[');
            for (i, doc) in docs.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                if serde_json::to_writer(&mut buf, doc).is_err() {
                    return;
                }
                if buf.len() >= SLICE {
                    if !send(&buf) {
                        return;
                    }
                    buf.clear();
                }
            }
            buf.push(b']');
            if !send(&buf) {
                return;
            }
        }
    }
    let _ = c.flush();
}

/// A counting gate: at most `max` holders at once, waiting no later than a deadline.
struct Gate {
    held: std::sync::Mutex<usize>,
    freed: std::sync::Condvar,
    max: usize,
}

/// One turn through a [`Gate`], given back when dropped.
struct Turn<'a>(&'a Gate);

impl Gate {
    const fn new(max: usize) -> Self {
        Gate {
            held: std::sync::Mutex::new(0),
            freed: std::sync::Condvar::new(),
            max,
        }
    }

    fn enter(&self, deadline: Instant) -> Option<Turn<'_>> {
        let mut held = self.held.lock().unwrap_or_else(|p| p.into_inner());
        while *held >= self.max {
            let left = remaining(deadline)?;
            held = self
                .freed
                .wait_timeout(held, left)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
        *held += 1;
        Some(Turn(self))
    }
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        let mut held = self.0.held.lock().unwrap_or_else(|p| p.into_inner());
        *held -= 1;
        self.0.freed.notify_one();
    }
}

/// Full listings in progress; see [`MAX_LISTINGS`].
static LISTINGS: Gate = Gate::new(MAX_LISTINGS);

/// Reads, routes and answers one connection, then lets it close. Reading the
/// request and writing the response each get `opts.deadline`.
pub fn handle_connection<C: Conn>(mut c: C, backend: &dyn Backend, opts: &Options) {
    let deadline = Instant::now() + opts.deadline;
    let req = match read_request(&mut c, deadline) {
        Ok(req) => req,
        Err(resp) => return write_response(&mut c, &resp, Instant::now() + opts.deadline),
    };
    // A full listing holds its turn while it is built and while it is written.
    let _turn = if req.path == "/v1/blocks" && req.method == "GET" {
        match LISTINGS.enter(deadline) {
            Some(turn) => Some(turn),
            None => {
                let busy = Response::error(503, "another block listing is in progress; try again");
                return write_response(&mut c, &busy, Instant::now() + opts.deadline);
            }
        }
    } else {
        None
    };
    let response = route(&req, backend, opts);
    write_response(&mut c, &response, Instant::now() + opts.deadline);
}

/// Equal secrets, compared in time that does not depend on where they differ.
fn same_secret(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------- routing

/// Every rule the API applies, in order: refuse requests from web pages, refuse
/// hosts it does not answer to, check the token, find the route, check its
/// method and media type, then answer.
pub fn route(req: &Request, backend: &dyn Backend, opts: &Options) -> Response {
    // A browser adds `Origin` to every cross-origin request and to every POST.
    // Nothing that legitimately uses this API is a web page, so refusing it is
    // free, and it stops a page in a local browser from lifting a block.
    if req.header("origin").is_some() {
        return Response::error(
            403,
            "requests from a web page (with an Origin header) are refused",
        );
    }
    // A page that rebinds its own name to this address sends that name as Host;
    // only the names this API is configured to answer to get through.
    match req.header("host") {
        Some(h) if opts.hosts.iter().any(|a| a.eq_ignore_ascii_case(h)) => {}
        Some(h) => {
            return Response::error(
                403,
                &format!("Host {h:?} is not one this API answers to; see http.hosts"),
            )
        }
        None => return Response::error(403, "a Host header is required"),
    }
    if let Some(token) = &opts.token {
        let given = req
            .header("authorization")
            .and_then(|a| a.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map(|(_, t)| t.trim());
        let ok = given.is_some_and(|t| same_secret(t.as_bytes(), token.as_bytes()));
        let open = req.path == "/v1/health" || DASHBOARD_FILES.contains(&req.path.as_str());
        if !ok && !open {
            return Response::unauthorized();
        }
    }
    let get_only = |f: &dyn Fn() -> Response| {
        if req.method == "GET" {
            f()
        } else {
            Response::method_not_allowed("GET")
        }
    };
    let file = |content_type: &'static str, body: &'static str| Response {
        status: 200,
        content_type,
        body: body.to_string(),
        allow: None,
        challenge: false,
        docs: None,
    };
    match req.path.as_str() {
        "/" => get_only(&|| file(HTML, DASHBOARD_HTML)),
        "/dashboard.css" => get_only(&|| file("text/css; charset=utf-8", DASHBOARD_CSS)),
        "/dashboard.js" => get_only(&|| file("text/javascript; charset=utf-8", DASHBOARD_JS)),
        "/v1/health" => get_only(&|| health()),
        "/v1/status" => get_only(&|| Response::json(200, to_json(&backend.status()))),
        "/v1/stats" => get_only(&|| match backend.stats() {
            Ok(d) => Response::json(200, to_json(&d)),
            Err(e) => Response::error(503, &e),
        }),
        "/v1/blocks" => get_only(&|| match backend.banned() {
            Ok(docs) => Response::listing(docs),
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
            challenge: false,
            docs: None,
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
    match backend.banned_one(ip) {
        Ok(Some(d)) => Response::json(200, to_json(&d)),
        Ok(None) => Response::error(404, "not blocked"),
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

fn unban(req: &Request, backend: &dyn Backend, opts: &Options) -> Response {
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

/// The Prometheus page: counts, and never an address.
///
/// What is blocked now comes from the kernel (its counters, and a count of the
/// block map's entries). History and learned state come from the daemon's SQLite
/// database through counting queries (`COUNT`/`GROUP BY`, and the checkpointed
/// counters), so a scrape's cost does not grow with the audit log. A value that
/// cannot be read is left out, never reported as 0.
fn metrics(backend: &dyn Backend) -> String {
    render_metrics(&MetricInputs {
        kernel: backend.kernel_counters(),
        blocked: backend.map_counts().ok(),
        db: backend.db_counts().ok(),
        hooks: backend.hook_deliveries(),
        now: crate::ctl::now(),
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Everything `/metrics` shows, each part `None` when it could not be read.
pub struct MetricInputs<'a> {
    /// `(seen, dropped, expired)` from the XDP program's counters.
    pub kernel: Option<(u64, u64, u64)>,
    /// `(blocked now, of which permanent)` from the block map.
    pub blocked: Option<(usize, usize)>,
    /// Counts from SQLite.
    pub db: Option<DbCounts>,
    /// Webhook delivery outcomes, `(url index, result, count)`.
    pub hooks: Vec<(usize, &'static str, u64)>,
    /// For turning the checkpoint's age into a timestamp.
    pub now: u32,
    pub version: &'a str,
}

/// Prometheus text exposition format 0.0.4.
pub fn render_metrics(m: &MetricInputs<'_>) -> String {
    let mut out = String::new();
    let mut family = |name: &str, kind: &str, help: &str, samples: &[(String, String)]| {
        if samples.is_empty() {
            return;
        }
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
    if let Some(d) = &m.db {
        let mut samples = Vec::new();
        for (window, rows) in [
            ("1h", &d.blocks_1h),
            ("24h", &d.blocks_24h),
            ("7d", &d.blocks_7d),
        ] {
            for (reason, n) in rows {
                samples.push((
                    labels(&[("window", window), ("reason", reason)]),
                    n.to_string(),
                ));
            }
        }
        family(
            "tfps_blocks_logged",
            "gauge",
            "Blocks the daemon logged in the window, by reason.",
            &samples,
        );
        family(
            "tfps_apiban_feed_entries",
            "gauge",
            "Addresses on the APIBAN feed list.",
            &one(d.apiban_feed.to_string()),
        );
        if let Some(t) = &d.traffic {
            let samples: Vec<_> = t
                .counters
                .iter()
                .filter_map(|(k, v)| v.map(|v| (labels(&[("counter", k)]), v.to_string())))
                .collect();
            family(
                "tfps_traffic_total",
                "counter",
                "Daemon traffic counters as of its last checkpoint.",
                &samples,
            );
            if let Some(age) = t.age_secs {
                family(
                    "tfps_checkpoint_timestamp_seconds",
                    "gauge",
                    "When the daemon last checkpointed, as a Unix time.",
                    &one(m.now.saturating_sub(age).to_string()),
                );
            }
        }
        let l = &d.learned;
        for (name, help, v) in [
            (
                "tfps_learned_pairs",
                "Learned peer/destination pairs.",
                l.pairs,
            ),
            ("tfps_learned_peers", "Peers with learned state.", l.peers),
            (
                "tfps_learned_countries",
                "Destination countries seen.",
                l.countries,
            ),
            (
                "tfps_learned_intl_calls",
                "International calls learned from.",
                l.intl_calls,
            ),
        ] {
            family(name, "gauge", help, &one(v.to_string()));
        }
    }
    let samples: Vec<_> = m
        .hooks
        .iter()
        .map(|(i, result, n)| {
            (
                labels(&[("url_index", &i.to_string()), ("result", result)]),
                n.to_string(),
            )
        })
        .collect();
    family(
        "tfps_hook_deliveries_total",
        "counter",
        "Webhook events by URL (its index in the hooks list) and outcome.",
        &samples,
    );
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
    let opts = Arc::new(opts);
    for _ in 0..WORKERS {
        let rx = Arc::clone(&rx);
        let backend = Arc::clone(&backend);
        let opts = Arc::clone(&opts);
        std::thread::spawn(move || worker(&rx, backend.as_ref(), &opts));
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

fn worker(rx: &Mutex<Receiver<TcpStream>>, backend: &dyn Backend, opts: &Options) {
    loop {
        // The lock is held only while waiting for the next connection, never
        // while handling one. A poisoned lock means another worker panicked
        // mid-wait, and the receiver itself is still sound.
        let next = match rx.lock() {
            Ok(guard) => guard.recv(),
            Err(poisoned) => poisoned.into_inner().recv(),
        };
        let Ok(stream) = next else { return };
        handle_connection(stream, backend, opts);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctl::{action_doc, banned_doc, log_doc};
    use crate::store::BlockRow;

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
        fn banned_one(&self, ip: Ipv4Addr) -> Result<Option<BannedDoc>, String> {
            let ip = ip.to_string();
            Ok(self.banned()?.into_iter().find(|d| d.ip == ip))
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
        fn db_counts(&self) -> Result<DbCounts, String> {
            if !self.db {
                return Err("no database".into());
            }
            Ok(DbCounts {
                blocks_1h: vec![("scanner".into(), 2)],
                blocks_24h: vec![("scanner".into(), 5), ("weird \"reason\"\n".into(), 1)],
                blocks_7d: vec![("scanner".into(), 9)],
                apiban_feed: 2,
                traffic: crate::ctl::traffic_doc(
                    Some("udp=120 syn=40 bad=xx hep_sip=7 hep_rejected_sender=2"),
                    Some(1_000),
                    1_060,
                ),
                learned: crate::ctl::learned_doc(5, 5, 3, 77),
            })
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

    const HOST: &str = "127.0.0.1:9060";

    fn host() -> (String, String) {
        ("host".into(), HOST.into())
    }

    fn get(path: &str) -> Request {
        let (path, query) = path.split_once('?').unwrap_or((path, ""));
        Request {
            method: "GET".into(),
            path: path.into(),
            query: query.into(),
            headers: vec![host()],
            ..Request::default()
        }
    }

    fn post_unban(body: &str) -> Request {
        Request {
            method: "POST".into(),
            path: "/v1/unban".into(),
            headers: vec![host(), ("content-type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
            ..Request::default()
        }
    }

    fn opts(allow_unban: bool) -> Options {
        Options {
            deadline: Duration::from_secs(2),
            ..Options::new(allow_unban, vec![HOST.into(), "x".into()], None)
        }
    }

    fn on() -> Options {
        opts(true)
    }

    fn off() -> Options {
        opts(false)
    }

    /// A connection in memory: what the client sends arrives in the given
    /// pieces, one per read, each after `delay`; what the server writes is kept.
    #[derive(Default)]
    struct TestConn {
        pieces: std::collections::VecDeque<Vec<u8>>,
        delay: Duration,
        written: Vec<u8>,
    }

    impl TestConn {
        fn new(raw: &str) -> Self {
            Self::pieces(&[raw.as_bytes()])
        }
        fn pieces(pieces: &[&[u8]]) -> Self {
            TestConn {
                pieces: pieces.iter().map(|p| p.to_vec()).collect(),
                ..TestConn::default()
            }
        }
        fn written(&self) -> String {
            String::from_utf8_lossy(&self.written).into_owned()
        }
    }

    impl Read for TestConn {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            std::thread::sleep(self.delay);
            let Some(mut piece) = self.pieces.pop_front() else {
                return Ok(0);
            };
            let n = piece.len().min(buf.len());
            buf[..n].copy_from_slice(&piece[..n]);
            if n < piece.len() {
                self.pieces.push_front(piece.split_off(n));
            }
            Ok(n)
        }
    }

    impl Write for TestConn {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Conn for TestConn {
        fn limit(&mut self, _: Duration) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A reader that takes `per_write` bytes per write, each after `delay`, and
    /// remembers every limit the server set.
    struct Trickle {
        per_write: usize,
        delay: Duration,
        written: usize,
        limits: Vec<Duration>,
    }

    impl Read for Trickle {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for Trickle {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            std::thread::sleep(self.delay);
            let n = buf.len().min(self.per_write);
            self.written += n;
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Conn for Trickle {
        fn limit(&mut self, remaining: Duration) -> std::io::Result<()> {
            self.limits.push(remaining);
            Ok(())
        }
    }

    /// A slow reader that keeps taking a few bytes is still cut off at the
    /// deadline: the limit is set again before every write, not once per slice.
    #[test]
    fn a_trickling_reader_is_cut_off_at_the_deadline() {
        let resp = Response::json(200, "x".repeat(64 * 1024));
        let mut c = Trickle {
            per_write: 16,
            delay: Duration::from_millis(5),
            written: 0,
            limits: Vec::new(),
        };
        let started = Instant::now();
        write_response(&mut c, &resp, started + Duration::from_millis(100));
        let took = started.elapsed();
        assert!(
            took < Duration::from_millis(400),
            "abandoned near the deadline, took {took:?}"
        );
        assert!(c.written < 64 * 1024, "not everything was sent");
        assert!(
            c.limits.len() > 2,
            "a limit before each write, not one per 16 KiB slice: {}",
            c.limits.len()
        );
        assert!(
            c.limits.windows(2).all(|w| w[1] <= w[0]),
            "each limit is the time left, shrinking"
        );
    }

    fn json(r: &Response) -> serde_json::Value {
        assert_eq!(r.content_type, JSON, "{r:?}");
        serde_json::from_str(&r.body_text()).expect("valid JSON")
    }

    // ── reading requests off the wire ──────────────────────────────────────

    fn parse(raw: &str) -> Result<Request, Response> {
        read_request(
            &mut TestConn::new(raw),
            Instant::now() + Duration::from_secs(5),
        )
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
        let head = b"POST /v1/unban HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n";
        let mut c = TestConn::pieces(&[head, b"{}"]);
        let r = read_request(&mut c, Instant::now() + Duration::from_secs(5)).expect("parses");
        assert_eq!(r.body, b"{}");
        assert_eq!(c.written(), "HTTP/1.1 100 Continue\r\n\r\n");
    }

    #[test]
    fn the_review_cases_are_refused() {
        for (raw, why) in [
            (
                "POST /v1/unban HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
                "a duplicate Content-Length",
            ),
            (
                "POST /v1/unban HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}",
                "conflicting Content-Lengths",
            ),
            (
                "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
                "a duplicate Host",
            ),
            (
                "GET / HTTP/1.1\r\nBad Name: x\r\n\r\n",
                "a space in a header name",
            ),
            (
                "GET / HTTP/1.1\r\nX(y): z\r\n\r\n",
                "a separator in a header name",
            ),
            ("GET / HTTP/1.1\nHost: x\n\n", "bare LF line endings"),
            ("GET / HTTP/1.1\r\nHost: x\n\r\n", "a bare LF mid-head"),
            ("GET / HTTP/1.1\r\nHost: x\rY: z\r\n\r\n", "a bare CR"),
            (
                "GET / HTTP/1.1\r\nContent-Length: +2\r\n\r\n{}",
                "a signed length",
            ),
        ] {
            let status = parse(raw).expect_err(why).status;
            assert!(status == 400, "{why}: got {status}");
        }
        let te =
            "POST /v1/unban HTTP/1.1\r\nContent-Length: 2\r\nTransfer-Encoding: identity\r\n\r\n{}";
        assert_eq!(parse(te).expect_err("any TE").status, 411);
    }

    #[test]
    fn too_many_header_lines_are_431() {
        let raw = format!(
            "GET / HTTP/1.1\r\n{}\r\n",
            (0..=MAX_HEADERS)
                .map(|i| format!("X-{i}: y\r\n"))
                .collect::<String>()
        );
        assert_eq!(parse(&raw).expect_err("too many").status, 431);
    }

    /// The deadline covers the whole request: a client that keeps sending a
    /// byte at a time, each well inside the per-read timeout, is still cut off.
    #[test]
    fn a_trickling_client_is_cut_off_at_the_deadline() {
        let raw = "GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n";
        let bytes: Vec<&[u8]> = raw.as_bytes().chunks(1).collect();
        let mut c = TestConn::pieces(&bytes);
        c.delay = Duration::from_millis(30);
        let start = Instant::now();
        let e = read_request(&mut c, start + Duration::from_millis(300)).expect_err("cut off");
        assert_eq!(e.status, 408);
        assert!(
            start.elapsed() < Duration::from_millis(600),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn a_whole_connection_gets_one_complete_response_and_closes() {
        let mut c = TestConn::new("GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n");
        handle_connection(&mut c, &up(), &off());
        let text = c.written();
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

    // ── host and token ─────────────────────────────────────────────────────

    #[test]
    fn only_the_configured_hosts_are_answered() {
        let mut r = get("/v1/blocks");
        assert_eq!(route(&r, &up(), &off()).status, 200);
        r.headers = vec![("host".into(), "127.0.0.1:9060".to_uppercase())];
        assert_eq!(route(&r, &up(), &off()).status, 200, "case does not matter");
        r.headers = vec![("host".into(), "evil.example:9060".into())];
        assert_eq!(
            route(&r, &up(), &off()).status,
            403,
            "a rebinding page's name"
        );
        r.headers.clear();
        assert_eq!(route(&r, &up(), &off()).status, 403, "no Host at all");
    }

    #[test]
    fn the_default_hosts_are_the_listen_address_and_localhost_on_loopback() {
        let lo = "127.0.0.1:9060".parse().unwrap();
        assert_eq!(allowed_hosts(lo, &[]), ["127.0.0.1:9060", "localhost:9060"]);
        let any = "192.0.2.1:80".parse().unwrap();
        assert_eq!(
            allowed_hosts(any, &[" Proxy.Example ".into()]),
            ["192.0.2.1:80", "proxy.example"]
        );
    }

    /// The dashboard is three files at fixed paths, each with its own type. The
    /// page carries a policy that lets it load only those files and talk only to
    /// this API.
    #[test]
    fn the_dashboard_is_served_with_a_strict_policy() {
        let page = route(&get("/"), &up(), &off());
        assert_eq!((page.status, page.content_type), (200, HTML));
        assert!(page
            .body
            .contains("<script src=\"/dashboard.js\"></script>"));
        let head = String::from_utf8(page.head()).unwrap();
        assert!(
            head.contains(&format!("\r\nContent-Security-Policy: {DASHBOARD_CSP}\r\n")),
            "{head}"
        );
        assert!(head.contains("\r\nX-Frame-Options: DENY\r\n"));
        assert!(head.contains("\r\nX-Content-Type-Options: nosniff\r\n"));
        assert!(DASHBOARD_CSP.contains("script-src 'self';"));
        assert!(
            !DASHBOARD_CSP.contains("unsafe"),
            "no inline script or style"
        );

        let css = route(&get("/dashboard.css"), &up(), &off());
        assert_eq!(
            (css.status, css.content_type),
            (200, "text/css; charset=utf-8")
        );
        let js = route(&get("/dashboard.js"), &up(), &off());
        assert_eq!(
            (js.status, js.content_type),
            (200, "text/javascript; charset=utf-8")
        );
        assert!(
            !String::from_utf8(js.head())
                .unwrap()
                .contains("Content-Security-Policy"),
            "the policy belongs to the page"
        );

        let mut post = get("/");
        post.method = "POST".into();
        assert_eq!(route(&post, &up(), &on()).status, 405, "read-only");
    }

    /// Block details are often attacker-chosen SIP text, so the page never
    /// writes data as HTML, and loads nothing from anywhere else.
    #[test]
    fn the_dashboard_never_writes_data_as_html_or_loads_from_elsewhere() {
        for banned in [
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
        ] {
            assert!(!DASHBOARD_JS.contains(banned), "{banned}");
        }
        for file in [DASHBOARD_HTML, DASHBOARD_CSS, DASHBOARD_JS] {
            assert!(!file.contains("://"), "every reference is same-origin");
        }
        // Behind a proxy with its own login (HTTP Basic), the browser must
        // re-send it on the page's requests, and to this origin only.
        assert!(DASHBOARD_JS.contains(r#"credentials: "same-origin""#));
        assert!(!DASHBOARD_JS.contains(r#"credentials: "omit""#));
        assert!(!DASHBOARD_JS.contains(r#"credentials: "include""#));
        assert!(
            !DASHBOARD_HTML.contains("<script>") && !DASHBOARD_HTML.contains("style="),
            "no inline script or style, which the policy would block"
        );
        assert!(
            !DASHBOARD_JS.contains("/v1/unban"),
            "read-only: the page never asks to lift a block"
        );
    }

    /// The page and its files hold no data, so they load without the token
    /// (the page then asks for it); the Host check still applies to them.
    #[test]
    fn the_dashboard_files_need_no_token_but_still_a_known_host() {
        let o = Options {
            token: Some("s3cret".into()),
            ..off()
        };
        for path in DASHBOARD_FILES {
            assert_eq!(route(&get(path), &up(), &o).status, 200, "{path}");
            let mut r = get(path);
            r.headers = vec![("host".into(), "rebound.example".into())];
            assert_eq!(route(&r, &up(), &o).status, 403, "{path}");
        }
        assert_eq!(
            route(&get("/v1/status"), &up(), &o).status,
            401,
            "the data itself still needs the token"
        );
    }

    #[test]
    fn a_token_guards_every_route_but_health() {
        let o = Options {
            token: Some("s3cret".into()),
            ..off()
        };
        let with = |path: &str, auth: Option<&str>| {
            let mut r = get(path);
            if let Some(a) = auth {
                r.headers.push(("authorization".into(), a.into()));
            }
            route(&r, &up(), &o)
        };
        let denied = with("/v1/blocks", None);
        assert_eq!(denied.status, 401);
        assert!(String::from_utf8(denied.to_bytes())
            .unwrap()
            .contains("\r\nWWW-Authenticate: Bearer\r\n"));
        assert_eq!(with("/v1/blocks", Some("Bearer wrong")).status, 401);
        assert_eq!(with("/v1/blocks", Some("Basic s3cret")).status, 401);
        assert_eq!(with("/v1/blocks", Some("Bearer s3cret")).status, 200);
        assert_eq!(
            with("/metrics", Some("bearer s3cret")).status,
            200,
            "scheme is case-blind"
        );
        assert_eq!(with("/v1/health", None).status, 200, "health stays open");
    }

    #[test]
    fn secrets_compare_equal_only_when_identical() {
        assert!(same_secret(b"abc", b"abc"));
        assert!(!same_secret(b"abc", b"abd"));
        assert!(!same_secret(b"abc", b"abcd"));
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
            assert_eq!(route(&r, &up(), &on()).status, 403, "{path}");
        }
        assert!(up().unbanned.lock().unwrap().is_empty());
    }

    #[test]
    fn unknown_paths_are_404_and_wrong_methods_405() {
        assert_eq!(route(&get("/v2/blocks"), &up(), &on()).status, 404);
        assert_eq!(route(&get("/index.html"), &up(), &on()).status, 404);
        let mut r = get("/v1/blocks");
        r.method = "DELETE".into();
        let resp = route(&r, &up(), &on());
        assert_eq!((resp.status, resp.allow), (405, Some("GET")));
        let resp = route(&get("/v1/unban"), &up(), &on());
        assert_eq!((resp.status, resp.allow), (405, Some("POST")));
        assert!(String::from_utf8(resp.to_bytes())
            .unwrap()
            .contains("\r\nAllow: POST\r\n"));
    }

    // ── read endpoints ─────────────────────────────────────────────────────

    #[test]
    fn health_names_the_version() {
        let v = json(&route(&get("/v1/health"), &up(), &off()));
        assert_eq!(v["ok"], true);
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn status_is_the_status_document_even_when_nothing_can_be_read() {
        let fake = Fake::default();
        let r = route(&get("/v1/status"), &fake, &off());
        assert_eq!(r.status, 200);
        assert_eq!(r.body, crate::json_line(&fake.status()).unwrap());
        assert_eq!(json(&r)["enforcement"], "inactive");
    }

    /// `/v1/blocks` is `banned --why --json` as one array: each element is
    /// byte-for-byte the line the CLI prints for the same documents.
    #[test]
    fn blocks_are_the_cli_lines_as_one_array() {
        let fake = up();
        let r = route(&get("/v1/blocks"), &fake, &off());
        assert_eq!(r.status, 200);
        let lines: Vec<String> = fake
            .docs()
            .iter()
            .map(|d| crate::json_line(d).unwrap())
            .collect();
        assert_eq!(r.body_text(), format!("[{}]", lines.join(",")));
        let v = json(&r);
        assert_eq!(v[0]["reason"], "scanner", "every block carries its reason");
        assert_eq!(v[1]["source"], "panel");
    }

    /// What goes on the wire for a streamed listing: the same bytes the
    /// buffered body would have been, with no Content-Length and the end of the
    /// body marked by closing.
    #[test]
    fn a_streamed_listing_sends_the_same_bytes_as_a_buffered_one() {
        let mut c = TestConn::new("GET /v1/blocks HTTP/1.1\r\nHost: x\r\n\r\n");
        handle_connection(&mut c, &up(), &off());
        let text = c.written();
        let (head, body) = text.split_once("\r\n\r\n").expect("head and body");
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert!(!head.contains("Content-Length"), "{head}");
        assert!(head.contains("Connection: close"), "{head}");
        assert_eq!(body, to_json(&up().docs()));
    }

    #[test]
    fn the_listing_gate_takes_turns_and_gives_up_at_the_deadline() {
        let gate = Gate::new(1);
        let first = gate
            .enter(Instant::now() + Duration::from_secs(1))
            .expect("free");
        let start = Instant::now();
        assert!(
            gate.enter(start + Duration::from_millis(100)).is_none(),
            "no second turn while the first is held"
        );
        assert!(start.elapsed() >= Duration::from_millis(100), "it waited");
        drop(first);
        assert!(gate
            .enter(Instant::now() + Duration::from_millis(100))
            .is_some());
    }

    #[test]
    fn one_block_by_address() {
        let r = route(&get("/v1/blocks/203.0.113.2"), &up(), &off());
        assert_eq!(r.status, 200);
        assert_eq!(r.body, crate::json_line(&up().docs()[1]).unwrap());
        assert_eq!(
            route(&get("/v1/blocks/192.0.2.1"), &up(), &off()).status,
            404
        );
        assert_eq!(
            route(&get("/v1/blocks/not-an-ip"), &up(), &off()).status,
            400
        );
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
            let r = route(&get(p), &down, &off());
            assert_eq!(r.status, 503, "{p}");
            assert!(json(&r)["error"].is_string(), "{p}");
        }
    }

    #[test]
    fn the_log_takes_a_capped_limit_and_an_address() {
        let n = |q: &str| {
            json(&route(&get(&format!("/v1/log{q}")), &up(), &off()))
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
                route(&get(&format!("/v1/log{bad}")), &up(), &off()).status,
                400,
                "{bad}"
            );
        }
    }

    // ── unban ──────────────────────────────────────────────────────────────

    #[test]
    fn unban_is_403_unless_allowed_and_nothing_is_touched() {
        let fake = up();
        let r = route(&post_unban(r#"{"ips":["203.0.113.1"]}"#), &fake, &off());
        assert_eq!(r.status, 403);
        assert!(fake.unbanned.lock().unwrap().is_empty());
    }

    #[test]
    fn unban_takes_json_only() {
        let mut r = post_unban(r#"{"ips":["203.0.113.1"]}"#);
        r.headers = vec![host(), ("content-type".into(), "text/plain".into())];
        assert_eq!(route(&r, &up(), &on()).status, 415);
        r.headers = vec![host()];
        assert_eq!(route(&r, &up(), &on()).status, 415);
        r.headers = vec![
            host(),
            (
                "content-type".into(),
                "Application/JSON; charset=utf-8".into(),
            ),
        ];
        assert_eq!(
            route(&r, &up(), &on()).status,
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
            let r = route(&post_unban(body), &fake, &on());
            assert_eq!(r.status, 400, "{body:.60}");
            assert!(json(&r)["error"].is_string());
        }
        assert!(fake.unbanned.lock().unwrap().is_empty());
    }

    #[test]
    fn unban_records_http_as_the_source_unless_told_otherwise() {
        let fake = up();
        let r = route(&post_unban(r#"{"ips":["203.0.113.1"]}"#), &fake, &on());
        assert_eq!(r.status, 200);
        assert_eq!(json(&r)[0]["source"], "http");
        let r = route(
            &post_unban(r#"{"ips":["203.0.113.2"],"source":"panel","reason":"customer asked"}"#),
            &fake,
            &on(),
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
            &on(),
        );
        assert_eq!(r.status, 200);
        let r = route(
            &post_unban(r#"{"ips":["203.0.113.1","192.0.2.7"]}"#),
            &up(),
            &on(),
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
            &on(),
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
            &on(),
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
    fn metrics_parse_and_carry_the_kernel_and_database_counts() {
        let r = route(&get("/metrics"), &up(), &off());
        assert_eq!(r.status, 200);
        assert!(r.content_type.starts_with("text/plain; version=0.0.4"));
        let m = parse_prometheus(&r.body);
        assert_eq!(m["tfps_xdp_seen_total"], 1000.0);
        assert_eq!(m["tfps_xdp_dropped_total"], 40.0);
        assert_eq!(m["tfps_xdp_expired_total"], 3.0);
        assert_eq!(m["tfps_blocked_sources"], 4.0);
        assert_eq!(m["tfps_blocked_sources_permanent"], 2.0);
        assert_eq!(
            m[r#"tfps_blocks_logged{window="1h",reason="scanner"}"#],
            2.0
        );
        assert_eq!(
            m[r#"tfps_blocks_logged{window="7d",reason="scanner"}"#],
            9.0
        );
        assert_eq!(m["tfps_apiban_feed_entries"], 2.0);
        assert_eq!(m[r#"tfps_traffic_total{counter="udp"}"#], 120.0);
        // The HEP listener's counters ride the same checkpoint line.
        assert_eq!(m[r#"tfps_traffic_total{counter="hep_sip"}"#], 7.0);
        assert_eq!(
            m[r#"tfps_traffic_total{counter="hep_rejected_sender"}"#],
            2.0
        );
        assert!(
            !m.keys().any(|k| k.contains(r#"counter="bad""#)),
            "a counter that will not parse is left out"
        );
        assert_eq!(
            m["tfps_checkpoint_timestamp_seconds"] as u32,
            crate::ctl::now() - 60
        );
        assert_eq!(m["tfps_learned_intl_calls"], 77.0);
        assert_eq!(
            m[&format!(
                r#"tfps_build_info{{version="{}"}}"#,
                env!("CARGO_PKG_VERSION")
            )],
            1.0
        );
    }

    /// Counts only: `/metrics` never builds the block listing, the stats
    /// document or the log, which are the reads that carry addresses.
    #[test]
    fn hook_deliveries_are_exported_per_url_and_result() {
        struct WithHooks;
        impl Backend for WithHooks {
            fn status(&self) -> StatusDoc {
                up().status()
            }
            fn stats(&self) -> Result<StatsDoc, String> {
                Err("x".into())
            }
            fn banned(&self) -> Result<Vec<BannedDoc>, String> {
                Err("x".into())
            }
            fn banned_one(&self, _: Ipv4Addr) -> Result<Option<BannedDoc>, String> {
                Err("x".into())
            }
            fn log(&self, _: usize, _: Option<&str>) -> Result<Vec<LogDoc>, String> {
                Err("x".into())
            }
            fn kernel_counters(&self) -> Option<(u64, u64, u64)> {
                None
            }
            fn map_counts(&self) -> Result<(usize, usize), String> {
                Err("x".into())
            }
            fn db_counts(&self) -> Result<DbCounts, String> {
                Err("x".into())
            }
            fn unban(
                &self,
                _: &[String],
                _: &str,
                _: Option<&str>,
            ) -> Result<UnbanOutcome, String> {
                Err("x".into())
            }
            fn hook_deliveries(&self) -> Vec<(usize, &'static str, u64)> {
                vec![(0, "delivered", 7), (0, "failed", 1), (1, "queue_full", 2)]
            }
        }
        let m = parse_prometheus(&route(&get("/metrics"), &WithHooks, &off()).body);
        assert_eq!(
            m[r#"tfps_hook_deliveries_total{url_index="0",result="delivered"}"#],
            7.0
        );
        assert_eq!(
            m[r#"tfps_hook_deliveries_total{url_index="1",result="queue_full"}"#],
            2.0
        );
        let plain = route(&get("/metrics"), &up(), &off()).body;
        assert!(
            !plain.contains("tfps_hook_deliveries_total"),
            "no hooks, no family"
        );
    }

    #[test]
    fn metrics_read_counts_and_never_addresses() {
        let body = fn_body("metrics");
        for call in ["banned(", "banned_one(", "stats(", "log("] {
            assert!(!body.contains(call), "{call} in metrics: {body}");
        }
        assert!(!route(&get("/metrics"), &up(), &off())
            .body
            .contains("203.0.113."));
    }

    #[test]
    fn metrics_omit_what_cannot_be_read_and_never_report_it_as_zero() {
        let m = parse_prometheus(&route(&get("/metrics"), &Fake::default(), &off()).body);
        assert_eq!(m.len(), 1, "only build_info is left: {m:?}");
        let no_db = Fake {
            map: true,
            ..Fake::default()
        };
        let m = parse_prometheus(&route(&get("/metrics"), &no_db, &off()).body);
        assert!(
            m.contains_key("tfps_blocked_sources"),
            "the kernel half stands alone"
        );
        assert!(!m.keys().any(|k| k.starts_with("tfps_blocks_logged")
            || k.starts_with("tfps_learned_")
            || k.starts_with("tfps_traffic_")));
    }

    #[test]
    fn a_reason_label_is_escaped_on_the_page() {
        let body = route(&get("/metrics"), &up(), &off()).body;
        assert!(
            body.contains(r#"tfps_blocks_logged{window="24h",reason="weird \"reason\"\n"} 1"#),
            "{body}"
        );
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
        std::thread::spawn(move || serve(listener, Arc::new(up()), off()));
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
        let o = Options {
            deadline: Duration::from_millis(200),
            ..off()
        };
        let start = std::time::Instant::now();
        handle_connection(server, &up(), &o);
        assert!(start.elapsed() < Duration::from_secs(2));
        let mut out = String::new();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.read_to_string(&mut out).unwrap();
        assert!(out.starts_with("HTTP/1.1 408 "), "{out}");
    }
}
