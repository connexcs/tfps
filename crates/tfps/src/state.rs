//! What the running daemon is enforcing through, published for `tfps_ctl serve`.
//!
//! The daemon chooses its block map once, at startup: a shared map another product
//! pinned, or its own. Anything else that reads or edits blocks must use **that**
//! map, not work the choice out again. A map that appeared after the daemon
//! started, or a second map with the same name, would otherwise be read and
//! edited while the daemon enforces through a different one.
//!
//! So the daemon writes this file when it starts, and the API opens exactly the map
//! it names. The file lives in the daemon's runtime directory (`RuntimeDirectory=tfps`),
//! which systemd removes when the daemon stops: a missing file means "the daemon is
//! not running", and the API says so instead of guessing.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Where the daemon publishes its state.
pub const DEFAULT_PATH: &str = "/run/tfps/state.json";

/// The daemon's enforcement, as it chose it at startup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    /// The daemon's process id, so a reader can tell one run from the next.
    pub pid: u32,
    /// When the daemon started, as a Unix time.
    pub started_at: u32,
    pub map: ActiveMap,
    /// How the daemon's own XDP program is attached: `"native (DRV)"` or
    /// `"generic (SKB)"`. `None` for a shared map or when enforcement is off.
    pub mode: Option<String>,
    /// The interface the program is attached to, when it is the daemon's own.
    pub interface: Option<String>,
}

/// The block map the daemon enforces through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActiveMap {
    /// The daemon's own map, by kernel map id. Unambiguous even when several
    /// loaded maps share the name `blocked`.
    Own { id: u32 },
    /// A drop map another product pinned, by its pin path.
    Shared { pin: PathBuf },
    /// Enforcement is off (`--no-enforce`) or failed to start; nothing is blocked.
    Inactive { reason: String },
}

/// Writes `state` to `path` atomically: a temporary file beside it, then a rename,
/// so a reader never sees half a file. Creates the directory when it is missing,
/// for a daemon run by hand rather than by its unit.
pub fn write(path: &Path, state: &State) -> Result<(), String> {
    let dir = path
        .parent()
        .ok_or_else(|| format!("{} has no directory", path.display()))?;
    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let json = serde_json::to_vec(state).map_err(|e| format!("serialising the state: {e}"))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("replacing {}: {e}", path.display()))
}

/// Reads the daemon's state. A missing file is reported as the daemon not running.
pub fn read(path: &Path) -> Result<State, String> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "tfps is not running ({} is absent): there is no enforcement to read",
                path.display()
            ))
        }
        Err(e) => return Err(format!("reading {}: {e}", path.display())),
    };
    serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tfps-state-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("state.json")
    }

    #[test]
    fn what_is_written_reads_back_for_each_kind_of_map() {
        let path = scratch("roundtrip");
        for map in [
            ActiveMap::Own { id: 42 },
            ActiveMap::Shared {
                pin: PathBuf::from("/sys/fs/bpf/sipvault/drop_ips"),
            },
            ActiveMap::Inactive {
                reason: "--no-enforce".into(),
            },
        ] {
            let s = State {
                pid: 1234,
                started_at: 1_795_000_000,
                map,
                mode: Some("native (DRV)".into()),
                interface: Some("eth0".into()),
            };
            write(&path, &s).expect("write");
            assert_eq!(read(&path).expect("read"), s);
        }
        assert!(
            !path.with_extension("json.tmp").exists(),
            "the temporary file is renamed away"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_missing_file_means_the_daemon_is_not_running() {
        let e = read(&scratch("absent")).expect_err("absent");
        assert!(e.contains("not running"), "{e}");
    }

    #[test]
    fn the_file_format_is_pinned() {
        let s = State {
            pid: 7,
            started_at: 100,
            map: ActiveMap::Own { id: 42 },
            mode: Some("generic (SKB)".into()),
            interface: Some("eth0".into()),
        };
        assert_eq!(
            serde_json::to_string(&s).unwrap(),
            r#"{"pid":7,"started_at":100,"map":{"kind":"own","id":42},"mode":"generic (SKB)","interface":"eth0"}"#
        );
        assert!(
            serde_json::from_str::<State>(
                r#"{"pid":7,"started_at":100,"map":{"kind":"own","id":42},"mode":null,"interface":null,"extra":1}"#
            )
            .is_err(),
            "an unknown field is refused, not ignored"
        );
    }
}
