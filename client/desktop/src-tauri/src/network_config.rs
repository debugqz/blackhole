//! Local (non-database) record of the operator-chosen DHT bootstrap
//! peers and TURN relay this client's daemon should use. Stored outside
//! the SQLCipher database, same reasoning as `prf_unlock.rs`: the Tauri
//! shell needs these *before* the daemon process even starts, to pass
//! them as env vars (`BLACKHOLE_BOOTSTRAP_PEERS`/`BLACKHOLE_TURN_SERVERS`/
//! `_USERNAME`/`_CREDENTIAL` — `daemon/src/main.rs`,
//! `bh_calls::transport::default_ice_servers`) on the spawned
//! [`std::process::Command`]; an env var set on an already-running
//! process can't be changed after the fact, which is exactly the gap
//! that made this client's real-network connection not survive an app
//! restart before this module existed — it only ever worked when
//! something external (a wrapper script, a shell that already had the
//! vars exported) launched the app.
//!
//! Nothing in here is secret in the zero-knowledge sense (SPEC.md §2.3)
//! — a bootstrap multiaddr and a TURN relay's address are meant to be
//! publicly known/reachable, that's the whole point of a bootstrap node
//! (docs/THREAT_MODEL.md §3.5). The TURN credential is still a shared
//! secret in the ordinary sense (whoever has it can use the relay), so
//! this file gets the same owner-only permissions `api_token` already
//! does, not because it's part of this app's cryptographic trust
//! boundary.
//!
//! **Precedence**: an env var already present in this process's own
//! environment (e.g. a developer launching `pnpm tauri dev` with
//! `BLACKHOLE_BOOTSTRAP_PEERS` exported, exactly as this client was first
//! connected to a real network before this module existed) always wins
//! over a saved value here — [`apply_to_command`] only fills in a var
//! that isn't already set, so the ad hoc override path this codebase's
//! other `BLACKHOLE_*` env vars already document keeps working
//! unchanged.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::Manager;

const CONFIG_FILE_NAME: &str = "network_config.json";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Comma-separated `Multiaddr`s in `.../p2p/<PeerId>` form — same
    /// format and parsing `daemon/src/main.rs` already documents for
    /// `BLACKHOLE_BOOTSTRAP_PEERS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_peers: Option<String>,
    /// Comma-separated `turn:`/`turns:` URLs — same format
    /// `bh_calls::transport::default_ice_servers` parses from
    /// `BLACKHOLE_TURN_SERVERS`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_servers: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_credential: Option<String>,
}

impl NetworkConfig {
    fn is_empty(&self) -> bool {
        self == &NetworkConfig::default()
    }
}

fn config_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join(CONFIG_FILE_NAME))
}

#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

/// A missing file (the common case — nobody has overridden the default
/// network yet) reads as the all-`None` default, not an error. Plain
/// function over a path (rather than a `tauri::AppHandle`) so this is
/// testable without spinning up a real Tauri app, same shape as
/// `prf_unlock.rs`'s own `read_config_at`.
fn read_config_at(path: &std::path::Path) -> Result<NetworkConfig, String> {
    if !path.exists() {
        return Ok(NetworkConfig::default());
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

/// A `bootstrap_peers` entry is a `Multiaddr` string ending in `/p2p/<PeerId>`
/// (the same format `daemon/src/main.rs`'s `BLACKHOLE_BOOTSTRAP_PEERS`
/// parser documents) — this is a shape check, not a full `Multiaddr`
/// parser (this crate doesn't depend on `multiaddr`), but it's enough to
/// catch a pasted URL, empty string, or other obviously-wrong value at
/// save time instead of only downstream, silently, when the daemon's own
/// parser drops it.
fn looks_like_multiaddr(entry: &str) -> bool {
    let entry = entry.trim();
    entry.starts_with('/') && entry.contains("/p2p/")
}

/// A `turn_servers` entry must be a `turn:`/`turns:` URL — the format
/// `bh_calls::transport::default_ice_servers` parses from
/// `BLACKHOLE_TURN_SERVERS`.
fn looks_like_turn_url(entry: &str) -> bool {
    let entry = entry.trim();
    entry.starts_with("turn:") || entry.starts_with("turns:")
}

/// Validates every comma-separated entry in `raw` against `is_valid`,
/// rejecting the whole save if any single entry doesn't look right —
/// catches a copy-paste mistake immediately, at the point the user (or a
/// compromised webview — this is a plain, unauthenticated-by-the-OS
/// `#[tauri::command]`, see this module's own doc comment on why nothing
/// here is a cryptographic secret, but a rewritten bootstrap/TURN config
/// is still a real DHT-eclipse/traffic-metadata tradeoff worth catching
/// early) can silently persist, rather than only failing much later and
/// silently downstream in the daemon's own lenient parser.
fn validate_comma_separated(raw: &str, is_valid: impl Fn(&str) -> bool) -> Result<(), String> {
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if !is_valid(entry) {
            return Err(format!("'{entry}' doesn't look like a valid entry"));
        }
    }
    Ok(())
}

fn validate_config(config: &NetworkConfig) -> Result<(), String> {
    if let Some(peers) = &config.bootstrap_peers {
        validate_comma_separated(peers, looks_like_multiaddr)
            .map_err(|e| format!("bootstrap_peers: {e}"))?;
    }
    if let Some(servers) = &config.turn_servers {
        validate_comma_separated(servers, looks_like_turn_url)
            .map_err(|e| format!("turn_servers: {e}"))?;
    }
    Ok(())
}

fn write_config_at(path: &std::path::Path, config: &NetworkConfig) -> Result<(), String> {
    if config.is_empty() {
        if path.exists() {
            std::fs::remove_file(path).map_err(|e| e.to_string())?;
        }
        return Ok(());
    }
    validate_config(config)?;
    let bytes = serde_json::to_vec_pretty(config).map_err(|e| e.to_string())?;
    std::fs::write(path, bytes).map_err(|e| e.to_string())?;
    restrict_permissions(path).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_network_config(app: tauri::AppHandle) -> Result<NetworkConfig, String> {
    read_config_at(&config_path(&app)?)
}

/// Saving an all-empty config (every field cleared in the UI) deletes the
/// file rather than writing an empty JSON object — back to "no override,
/// use the compiled-in defaults" exactly like it was before any override
/// was ever saved. A non-empty config is validated first (see
/// [`validate_config`]) — malformed `bootstrap_peers`/`turn_servers` are
/// rejected here rather than silently written and only failing later,
/// downstream, in the daemon's own lenient parser.
#[tauri::command]
pub fn save_network_config(app: tauri::AppHandle, config: NetworkConfig) -> Result<(), String> {
    write_config_at(&config_path(&app)?, &config)
}

/// Sets `key` on `cmd` from `value` — but only if this process's own
/// environment doesn't already define `key`, and only if `value` isn't
/// blank. See this module's own doc comment for why an ambient env var
/// wins over a saved one.
fn apply_one(cmd: &mut std::process::Command, key: &str, value: &Option<String>) {
    if std::env::var_os(key).is_some() {
        return;
    }
    if let Some(value) = value {
        if !value.trim().is_empty() {
            cmd.env(key, value);
        }
    }
}

/// Applies every field of `config` onto `cmd` as the corresponding
/// `BLACKHOLE_*` env var, ready to call right before
/// `daemon_lifecycle.rs` spawns the daemon child process.
pub(crate) fn apply_to_command(config: &NetworkConfig, cmd: &mut std::process::Command) {
    apply_one(cmd, "BLACKHOLE_BOOTSTRAP_PEERS", &config.bootstrap_peers);
    apply_one(cmd, "BLACKHOLE_TURN_SERVERS", &config.turn_servers);
    apply_one(cmd, "BLACKHOLE_TURN_USERNAME", &config.turn_username);
    apply_one(cmd, "BLACKHOLE_TURN_CREDENTIAL", &config.turn_credential);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_config_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "bh-desktop-network-config-test-{name}-{}.json",
            std::process::id()
        ))
    }

    #[test]
    fn reading_a_missing_config_is_the_default() {
        let path = temp_config_path("missing");
        let _ = std::fs::remove_file(&path);
        assert_eq!(read_config_at(&path).unwrap(), NetworkConfig::default());
    }

    #[test]
    fn write_then_read_round_trips() {
        let path = temp_config_path("roundtrip");
        let config = NetworkConfig {
            bootstrap_peers: Some("/ip4/1.2.3.4/tcp/4001/p2p/12D3abc".to_string()),
            turn_servers: Some("turn:1.2.3.4:3478".to_string()),
            turn_username: Some("user".to_string()),
            turn_credential: Some("secret".to_string()),
        };
        write_config_at(&path, &config).unwrap();
        assert_eq!(read_config_at(&path).unwrap(), config);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn saving_an_all_empty_config_removes_the_file() {
        let path = temp_config_path("clear");
        write_config_at(
            &path,
            &NetworkConfig {
                bootstrap_peers: Some("/ip4/1.2.3.4/tcp/4001/p2p/12D3abc".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(path.exists());
        write_config_at(&path, &NetworkConfig::default()).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn write_config_at_rejects_a_malformed_bootstrap_peer() {
        let path = temp_config_path("bad-bootstrap");
        let config = NetworkConfig {
            bootstrap_peers: Some("not-a-multiaddr".to_string()),
            ..Default::default()
        };
        assert!(write_config_at(&path, &config).is_err());
        assert!(
            !path.exists(),
            "an invalid config must not be written to disk"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_config_at_rejects_a_malformed_turn_url() {
        let path = temp_config_path("bad-turn");
        let config = NetworkConfig {
            turn_servers: Some("https://not-a-turn-url.example".to_string()),
            ..Default::default()
        };
        assert!(write_config_at(&path, &config).is_err());
        assert!(
            !path.exists(),
            "an invalid config must not be written to disk"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_config_at_accepts_multiple_valid_comma_separated_entries() {
        let path = temp_config_path("multi-valid");
        let config = NetworkConfig {
            bootstrap_peers: Some(
                "/ip4/1.2.3.4/tcp/4001/p2p/12D3abc, /ip4/5.6.7.8/tcp/4001/p2p/12D3def".to_string(),
            ),
            turn_servers: Some("turn:1.2.3.4:3478,turns:5.6.7.8:5349".to_string()),
            ..Default::default()
        };
        assert!(write_config_at(&path, &config).is_ok());
        assert_eq!(read_config_at(&path).unwrap(), config);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn apply_to_command_sets_only_non_empty_fields() {
        let config = NetworkConfig {
            bootstrap_peers: Some("/ip4/1.2.3.4/tcp/4001/p2p/12D3abc".to_string()),
            turn_servers: None,
            turn_username: Some("".to_string()),
            turn_credential: Some("secret".to_string()),
        };
        let mut cmd = std::process::Command::new("true");
        apply_to_command(&config, &mut cmd);
        let envs: std::collections::HashMap<_, _> = cmd
            .get_envs()
            .filter_map(|(k, v)| v.map(|v| (k.to_owned(), v.to_owned())))
            .collect();
        assert_eq!(
            envs.get(std::ffi::OsStr::new("BLACKHOLE_BOOTSTRAP_PEERS"))
                .map(|v| v.to_str().unwrap()),
            Some("/ip4/1.2.3.4/tcp/4001/p2p/12D3abc")
        );
        assert!(!envs.contains_key(std::ffi::OsStr::new("BLACKHOLE_TURN_SERVERS")));
        assert!(!envs.contains_key(std::ffi::OsStr::new("BLACKHOLE_TURN_USERNAME")));
        assert_eq!(
            envs.get(std::ffi::OsStr::new("BLACKHOLE_TURN_CREDENTIAL"))
                .map(|v| v.to_str().unwrap()),
            Some("secret")
        );
    }
}
