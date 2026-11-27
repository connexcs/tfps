//! Configuration file — `/etc/tfps/config.json`.
//!
//! **Every field is optional and the system works without the file.** That is not a
//! convenience: it is constraint 1 of the project. What lives here is **installation**
//! configuration (where to look, how to read the numbers) plus optional integrations —
//! never **policy** configuration, which would say what fraud is. The fourteen knobs of the
//! 2023 `defines.m4` have no equivalent.
//!
//! Precedence: **command line beats the file, which beats the built-in default.**
//!
//! ```json
//! {
//!   "ports": [5060, 5061],
//!   "intl_prefixes": ["+", "00", "011", "9011"],
//!   "peers": { "10.0.0.5": { "intl_prefixes": ["9011"], "bare_e164": false } },
//!   "signatures": ["MyLocalScanner", "=sipsak"],
//!   "injection": ["xp_cmdshell"],
//!   "ignoreip": ["10.0.0.0/8", "203.0.113.7"],
//!   "home_countries": ["BR"],
//!   "behavioural": false,
//!   "enforce_behavioural": false,
//!   "no_enforce_one_way": false,
//!   "apiban_key": "...",
//!   "learn_days": 30,
//!   "block_ttl": 3600,
//!   "http": { "enabled": false, "listen": "127.0.0.1:9060", "allow_unban": false }
//! }
//! ```

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const DEFAULT_PATH: &str = "/etc/tfps/config.json";

/// A PBX's dial plan.
///
/// Declaring beats learning because it holds on that peer's **very first** call instead of
/// waiting for convergence — and 20.3% of destinations do not resolve to a country without
/// correct prefix stripping. Learning keeps running in parallel, and disagreement becomes
/// an alarm.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerConfig {
    /// That PBX's international dialling prefixes, e.g. `["9011", "011"]`.
    #[serde(default)]
    pub intl_prefixes: Vec<String>,
    /// The PBX sends plain E.164 with no prefix. Common in wholesale.
    ///
    /// An explicit flag rather than an empty prefix, because the semantics are dangerous:
    /// with it on, `2125551234` is Morocco; with it off, it is a domestic US number.
    #[serde(default)]
    pub bare_e164: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub ports: Option<Vec<u16>>,
    /// Default prefixes, used for peers with no declared plan.
    pub intl_prefixes: Option<Vec<String>>,
    /// Per-PBX plan, keyed by source IP.
    #[serde(default)]
    pub peers: BTreeMap<String, PeerConfig>,
    /// User-agent signatures that **add** to the built-in ones.
    ///
    /// Prefix by default; `=text` matches exactly. They never replace: a file that replaced
    /// would make someone who writes three lines silently lose the 18 shipped ones.
    #[serde(default)]
    pub signatures: Vec<String>,
    /// URI injection patterns that add to the built-in ones.
    #[serde(default)]
    pub injection: Vec<String>,
    /// Scanner identity markers (domains or tool names) that **add** to the built-in list,
    /// matched in the From/To/Contact/Request-URI — e.g. a new research scanner's domain.
    #[serde(default)]
    pub scanners: Vec<String>,
    /// Sources never enforced against, e.g. `["10.0.0.0/8"]`. Named after `fail2ban`'s
    /// field of the same purpose.
    ///
    /// The host's own addresses are always exempt and need no entry here. This is for
    /// trusted carriers and management ranges. An exempt source is still evaluated,
    /// counted and reported — the entry changes **enforcement scope**, never a verdict,
    /// which is what keeps it inside `SPEC.md` §11.
    #[serde(default, alias = "ignore")]
    pub ignoreip: Vec<String>,
    /// The operator's own country/countries, ISO labels (`+1` is `NANP`). A destination
    /// resolving to one of these is national, not international, and is excluded from the
    /// behavioural layer — this is what stops an inbound call to your own E.164 DID from
    /// being judged as an international destination.
    #[serde(default)]
    pub home_countries: Vec<String>,
    /// Turn on behavioural fraud detection (dialling-prefix and destination-range novelty). **Off by
    /// default**: the product is noise reduction, and the behavioural layer is an opt-in
    /// extra most installs will not need.
    #[serde(default)]
    pub behavioural: bool,
    /// Enforce a behavioural `Block` by writing the source into XDP for `block_ttl`.
    /// **Off by default**: the behavioural verdict is report-only unless the operator opts
    /// in. It requires `behavioural: true`; learning mode still never blocks.
    #[serde(default)]
    pub enforce_behavioural: bool,
    /// Do not enforce **one-way** perimeter evidence: user-agent noise, scanner identity,
    /// Request-URI injection, duplicate singleton headers, registration scanning and the
    /// auth-volume backstop. Those verdicts are still reported, but nothing is written to
    /// the block map. Response-based evidence (a rejected credential) and the APIBAN feed
    /// keep enforcing. Off by default: the current product blocks one-way evidence.
    #[serde(default)]
    pub no_enforce_one_way: bool,
    pub apiban_key: Option<String>,
    pub learn_days: Option<u32>,
    pub block_ttl: Option<u64>,
    pub stats_every: Option<u64>,
    pub checkpoint_every: Option<u64>,
    pub iface: Option<String>,
    pub db: Option<PathBuf>,
    /// Where `tfps_ctl` keeps its record of manual bans and unbans. Absent: the
    /// database's directory.
    pub manual_log_dir: Option<PathBuf>,
    /// Re-apply unexpired manual bans from that record when the daemon starts,
    /// through the same guard a manual ban passes. Off unless set: a restart has
    /// always started from an empty block map, and an operator who relies on
    /// that must not find old bans back without asking for them.
    #[serde(default)]
    pub reapply_manual_bans: bool,
    pub xdp_obj: Option<PathBuf>,
    pub drop_map: Option<PathBuf>,
    /// The optional JSON-over-HTTP API served by `tfps_ctl serve`. The daemon
    /// itself ignores this section: the API is a separate process.
    pub http: Option<HttpConfig>,
    /// Webhook URLs (`http://` or `https://`), each POSTed a JSON document when
    /// a source is blocked, unblocked, or its block expires. Sent by
    /// `tfps_ctl serve`, never by the daemon. Empty: no webhooks.
    #[serde(default)]
    pub hooks: Vec<String>,
    /// How often, in seconds, `tfps_ctl serve` looks for new events. Default 1.
    pub hooks_poll_secs: Option<u64>,
}

/// The webhook URLs that are not `http://` or `https://` URLs with a host, as
/// the HTTP client that sends them parses them (so a bad port or a space is
/// refused at start, not at the first event). A typo here would otherwise send
/// nothing, silently.
pub fn bad_hooks(hooks: &[String]) -> Vec<&str> {
    hooks
        .iter()
        .filter(|u| {
            let Ok(uri) = u.parse::<ureq::http::Uri>() else {
                return true;
            };
            let scheme_ok = matches!(uri.scheme_str(), Some("http" | "https"));
            let host_ok = uri.host().is_some_and(|h| !h.is_empty());
            // The parser reads a port lazily, so a non-numeric one passes it:
            // whatever follows the host's last `:` must be a port number.
            let port_ok = uri.authority().is_some_and(|a| {
                let hostport = a.as_str().rsplit('@').next().unwrap_or("");
                match hostport.strip_prefix('[') {
                    Some(v6) => v6.split_once(']').is_some_and(|(_, rest)| {
                        rest.is_empty()
                            || rest
                                .strip_prefix(':')
                                .is_some_and(|p| p.parse::<u16>().is_ok())
                    }),
                    None => hostport
                        .rsplit_once(':')
                        .is_none_or(|(_, p)| p.parse::<u16>().is_ok()),
                }
            });
            !(scheme_ok && host_ok && port_ok)
        })
        .map(String::as_str)
        .collect()
}

/// Where the default listener goes: loopback only, so nothing is reachable
/// from the network until somebody decides it should be.
pub const DEFAULT_HTTP_LISTEN: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9060);

/// The `http` section: `tfps_ctl serve`'s listener.
///
/// **Off unless `enabled` is true**, and unbanning over HTTP is a second switch
/// that is also off. Requests must name an allowed `Host` (the listen address,
/// `localhost` on loopback, and `hosts`), which stops a DNS-rebinding web page;
/// `token_file` adds a bearer token for machine-to-machine access. TLS stays a
/// reverse proxy's job.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpConfig {
    #[serde(default)]
    pub enabled: bool,
    /// An IPv4 `address:port`. Default `127.0.0.1:9060`.
    #[serde(default = "default_http_listen")]
    pub listen: SocketAddrV4,
    /// Accept `POST /v1/unban`. Off: that route answers 403.
    #[serde(default)]
    pub allow_unban: bool,
    /// Further `Host` values to accept, such as the name a reverse proxy passes
    /// on (`"tfps.example.com"`, or `"tfps.example.com:8443"` when clients send
    /// a port). The listen address, and `localhost` on loopback, need no entry.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Listening on a non-loopback address must be asked for explicitly: without
    /// this, `serve` refuses to start rather than expose the API by a typo.
    #[serde(default)]
    pub allow_remote: bool,
    /// A file holding a bearer token. When set, every route but `/v1/health`
    /// needs `Authorization: Bearer <token>`. The file must be readable by its
    /// owner only.
    pub token_file: Option<PathBuf>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        HttpConfig {
            enabled: false,
            listen: DEFAULT_HTTP_LISTEN,
            allow_unban: false,
            hosts: Vec::new(),
            allow_remote: false,
            token_file: None,
        }
    }
}

fn default_http_listen() -> SocketAddrV4 {
    DEFAULT_HTTP_LISTEN
}

/// The read result, so the configuration's origin shows up in the startup report. The
/// operator needs to know whether the file was read, absent, or broken.
pub enum Loaded {
    /// File read successfully.
    File(Box<Config>, PathBuf),
    /// Absent — normal and expected.
    Absent,
    /// Present but unreadable. **Never silent**: broken configuration ignored quietly
    /// makes the operator believe they declared something that does not apply.
    Broken(String),
}

pub fn load(path: &Path) -> Loaded {
    if !path.exists() {
        return Loaded::Absent;
    }
    match std::fs::read_to_string(path) {
        Err(e) => Loaded::Broken(format!("reading {}: {e}", path.display())),
        Ok(txt) => match serde_json::from_str::<Config>(&txt) {
            Ok(c) => Loaded::File(Box::new(c), path.to_path_buf()),
            Err(e) => Loaded::Broken(format!("{}: {e}", path.display())),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Config, String> {
        serde_json::from_str(s).map_err(|e| e.to_string())
    }

    #[test]
    fn an_empty_file_is_valid() {
        // The core promise: nothing is mandatory.
        let c = parse("{}").expect("an empty object must be accepted");
        assert!(c.ports.is_none());
        assert!(c.signatures.is_empty());
        assert!(c.peers.is_empty());
    }

    #[test]
    fn parses_the_readme_example() {
        let c = parse(
            r#"{
              "ports": [5060, 5061],
              "intl_prefixes": ["+", "00"],
              "peers": { "10.0.0.5": { "intl_prefixes": ["9011"], "bare_e164": false } },
              "signatures": ["MyLocalScanner", "=sipsak"],
              "injection": ["xp_cmdshell"],
              "ignoreip": ["10.0.0.0/8"],
              "apiban_key": "abc",
              "learn_days": 30,
              "block_ttl": 3600
            }"#,
        )
        .expect("the documented example must parse");
        assert_eq!(c.ports.as_deref(), Some(&[5060u16, 5061][..]));
        assert_eq!(c.peers["10.0.0.5"].intl_prefixes, ["9011"]);
        assert_eq!(c.signatures.len(), 2);
        assert_eq!(c.ignoreip, ["10.0.0.0/8"]);
        assert_eq!(c.apiban_key.as_deref(), Some("abc"));
    }

    #[test]
    fn a_config_from_the_previous_version_still_loads() {
        // The field was renamed `ignore` -> `ignoreip`. With `deny_unknown_fields` and no
        // alias, an existing config would fail to parse and the daemon would fall back to
        // built-in defaults — silently dropping the operator's apiban_key, ports and
        // exemptions. The alias is what stops a rename from erasing a live configuration.
        let c = parse(r#"{"ignore": ["10.0.0.0/8"], "ports": [5060]}"#)
            .expect("a config written by the previous version must still load");
        assert_eq!(c.ignoreip, ["10.0.0.0/8"]);
    }

    #[test]
    fn an_unknown_field_is_an_error_not_silence() {
        // A typo that got ignored would make the operator believe APIBAN was enabled when
        // it was not. `deny_unknown_fields` refuses and names the offending field.
        let e = parse(r#"{"apiban_kei": "x"}"#).unwrap_err();
        assert!(
            e.contains("apiban_kei"),
            "the error must name the offending field: {e}"
        );
        // And the correct field still works, obviously.
        assert_eq!(
            parse(r#"{"apiban_key": "x"}"#)
                .unwrap()
                .apiban_key
                .as_deref(),
            Some("x")
        );
    }

    #[test]
    fn broken_json_becomes_a_readable_error_not_a_panic() {
        assert!(parse("{").is_err());
        assert!(parse("").is_err());
        assert!(parse(r#"{"ports": "not a list"}"#).is_err());
    }

    #[test]
    fn an_absent_file_is_not_an_error() {
        let p = std::path::Path::new("/path/that/does/not/exist/config.json");
        assert!(matches!(load(p), Loaded::Absent));
    }

    #[test]
    fn behavioural_enforcement_is_off_by_default_and_opt_in() {
        assert!(!parse("{}").expect("empty").enforce_behavioural);
        assert!(
            parse(r#"{"enforce_behavioural": true}"#)
                .expect("parses")
                .enforce_behavioural
        );
    }

    #[test]
    fn one_way_enforcement_is_off_by_default_and_opt_in() {
        assert!(
            !parse("{}").expect("empty").no_enforce_one_way,
            "the current product still enforces one-way evidence"
        );
        assert!(
            parse(r#"{"no_enforce_one_way": true}"#)
                .expect("parses")
                .no_enforce_one_way
        );
    }

    #[test]
    fn the_manual_action_record_can_be_moved_and_is_beside_the_database_by_default() {
        let c = parse(r#"{"manual_log_dir": "/srv/tfps/manual"}"#).expect("parses");
        assert_eq!(
            c.manual_log_dir.as_deref(),
            Some(std::path::Path::new("/srv/tfps/manual"))
        );
        assert!(parse("{}").expect("empty").manual_log_dir.is_none());
    }

    #[test]
    fn the_http_api_is_off_loopback_and_read_only_by_default() {
        assert!(parse("{}").expect("empty").http.is_none());
        let h = parse(r#"{"http": {}}"#)
            .expect("parses")
            .http
            .expect("present");
        assert_eq!(h, HttpConfig::default());
        assert!(!h.enabled && !h.allow_unban);
        assert_eq!(h.listen.to_string(), "127.0.0.1:9060");
        let h =
            parse(r#"{"http": {"enabled": true, "listen": "0.0.0.0:8080", "allow_unban": true}}"#)
                .expect("parses")
                .http
                .expect("present");
        assert!(h.enabled && h.allow_unban);
        assert_eq!(h.listen.to_string(), "0.0.0.0:8080");
        assert!(!h.allow_remote && h.hosts.is_empty() && h.token_file.is_none());
        let h = parse(
            r#"{"http": {"hosts": ["tfps.example.com"], "allow_remote": true,
                         "token_file": "/etc/tfps/api-token"}}"#,
        )
        .expect("parses")
        .http
        .expect("present");
        assert_eq!(h.hosts, ["tfps.example.com"]);
        assert!(h.allow_remote);
        assert_eq!(
            h.token_file.as_deref(),
            Some(Path::new("/etc/tfps/api-token"))
        );
    }

    /// The file the installer writes when there is none must load. If it did
    /// not, the daemon would run on built-in defaults while the operator edits a
    /// file that is never applied.
    #[test]
    fn the_shipped_example_configuration_loads() {
        let c = parse(include_str!("../../../packaging/config.example.json"))
            .expect("packaging/config.example.json must parse");
        assert_eq!(
            c.http,
            Some(HttpConfig::default()),
            "shipped with the API off"
        );
    }

    #[test]
    fn the_http_section_refuses_typos_and_ipv6() {
        let e = parse(r#"{"http": {"enable": true}}"#).unwrap_err();
        assert!(e.contains("enable"), "{e}");
        assert!(parse(r#"{"http": {"listen": "[::1]:9060"}}"#).is_err());
        assert!(
            parse(r#"{"http": {"listen": "127.0.0.1"}}"#).is_err(),
            "a port is required"
        );
    }

    #[test]
    fn hooks_are_off_by_default_and_must_be_http_urls() {
        let c = parse("{}").expect("empty");
        assert!(c.hooks.is_empty() && c.hooks_poll_secs.is_none());
        let c = parse(r#"{"hooks": ["https://panel.example.com/tfps/events", "http://127.0.0.1:8080/hook", "https://[::1]:8443/h"], "hooks_poll_secs": 5}"#)
            .expect("parses");
        assert_eq!(c.hooks.len(), 3);
        assert_eq!(c.hooks_poll_secs, Some(5));
        assert!(bad_hooks(&c.hooks).is_empty());
        let bad = vec![
            "ftp://x/y".to_string(),
            "panel.example.com/hook".to_string(),
            "https:///nohost".to_string(),
            "http://has space/x".to_string(),
            "https://panel.example:bad-port/hook".to_string(),
            "https://panel.example/a path".to_string(),
        ];
        assert_eq!(
            bad_hooks(&bad),
            bad.iter().map(String::as_str).collect::<Vec<_>>()
        );
    }

    #[test]
    fn re_applying_manual_bans_at_startup_is_off_unless_asked_for() {
        assert!(!parse("{}").expect("empty").reapply_manual_bans);
        assert!(
            parse(r#"{"reapply_manual_bans": true}"#)
                .expect("parses")
                .reapply_manual_bans
        );
    }
}
