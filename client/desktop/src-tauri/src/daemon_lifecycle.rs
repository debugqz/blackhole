//! Spawns and supervises the daemon child process from the Tauri shell —
//! previously nonexistent: the daemon was assumed to already be running
//! (started separately, e.g. `cargo run -p bh-daemon` in dev), which is
//! exactly why THREAT_MODEL.md §3.7's passkey/TOTP screen could only ever
//! be a client-UI gate shown *after* the daemon had already opened the
//! SQLCipher database — there was no earlier point in the client's own
//! lifecycle to gate. [`ensure_daemon_running`] is that earlier point: it
//! optionally takes the database-unlock secret (see
//! `prf_unlock.rs`) and passes it as `BLACKHOLE_DB_PIN` to the spawned
//! process, so a PRF-gated profile's daemon never even starts with an
//! openable database until the secret has been supplied.
//!
//! **Scope note**: resolves the daemon binary via `BLACKHOLE_DAEMON_BIN`
//! or a monorepo-relative dev fallback (`cargo tauri dev`'s own build
//! output). Production packaging (bundling the daemon as a Tauri
//! "sidecar" binary with `tauri.conf.json`'s `bundle.externalBin`,
//! platform-specific code signing) is a separate follow-up, not attempted
//! here — this module's job is the spawn/health-check/teardown lifecycle,
//! not distribution.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Mutex;
use std::time::Duration;

const DAEMON_PORT: u16 = 47_853;
const HEALTH_CHECK_ATTEMPTS: u32 = 50;
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_millis(100);

/// Owns the spawned daemon child process, if this Tauri process is the one
/// that started it (a daemon already running — e.g. launched manually in
/// dev, or from a previous app instance that didn't exit cleanly — is left
/// alone: [`ensure_daemon_running`] only ever spawns when the health check
/// fails).
#[derive(Default)]
pub struct DaemonProcess(Mutex<Option<Child>>);

impl Drop for DaemonProcess {
    /// Best-effort cleanup: if this process spawned the daemon, don't leave
    /// it running as an orphan after the Tauri app exits. Not a substitute
    /// for a real graceful-shutdown signal (SIGTERM handling, flushing any
    /// in-flight writes) — that's the daemon's own concern if it needs one;
    /// this just ensures *something* stops it rather than leaking the
    /// process indefinitely.
    fn drop(&mut self) {
        if let Ok(mut guard) = self.0.lock() {
            if let Some(mut child) = guard.take() {
                let _ = child.kill();
            }
        }
    }
}

fn default_daemon_binary_path() -> PathBuf {
    // `client/desktop/src-tauri` -> workspace root -> `target/<profile>`.
    // Deterministic for this monorepo's layout under `cargo tauri dev`;
    // overridden by `BLACKHOLE_DAEMON_BIN` for anything else (packaged
    // builds, CI, a differently-laid-out checkout).
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    // Matches `[[bin]] name` in `daemon/Cargo.toml` — the package is
    // named `bh-daemon` but the binary itself is `blackhole-daemon`.
    let binary_name = if cfg!(windows) {
        "blackhole-daemon.exe"
    } else {
        "blackhole-daemon"
    };
    manifest_dir
        .join("..")
        .join("..")
        .join("..")
        .join("target")
        .join(profile)
        .join(binary_name)
}

fn daemon_binary_path() -> PathBuf {
    std::env::var("BLACKHOLE_DAEMON_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_daemon_binary_path())
}

/// `/health` is gated by the same bearer-token check as every other
/// route (`server.rs`'s `require_bearer_token`), so this can only report
/// healthy once the token file exists *and* the daemon accepts it —
/// which also means a health check against a stale token (e.g. a
/// previous daemon process's, if the data dir was somehow shared) fails
/// closed rather than reporting false health.
fn daemon_health_ok() -> bool {
    let Some(token) = crate::read_api_token() else {
        return false;
    };
    ureq::get(format!("http://127.0.0.1:{DAEMON_PORT}/health"))
        .header("Authorization", format!("Bearer {token}"))
        .call()
        .is_ok_and(|resp| resp.status().is_success())
}

/// Ensures the daemon is reachable, spawning it (with `db_pin` as
/// `BLACKHOLE_DB_PIN` if the active profile's database key is
/// PIN-protected — see `prf_unlock.rs` — and this profile's saved
/// `network_config::NetworkConfig`, if any, as
/// `BLACKHOLE_BOOTSTRAP_PEERS`/`BLACKHOLE_TURN_*`) if it isn't already.
/// Idempotent: if a daemon is already answering health checks (started
/// manually, or by an earlier call this process made), this is a no-op
/// rather than a second spawn racing the first for the same port.
#[tauri::command]
pub async fn ensure_daemon_running(
    app: tauri::AppHandle,
    state: tauri::State<'_, DaemonProcess>,
    db_pin: Option<String>,
) -> Result<(), String> {
    if daemon_health_ok() {
        return Ok(());
    }

    {
        let mut guard = state
            .0
            .lock()
            .map_err(|_| "daemon process lock poisoned".to_string())?;
        if guard.is_none() {
            let mut cmd = Command::new(daemon_binary_path());
            if let Some(pin) = &db_pin {
                cmd.env("BLACKHOLE_DB_PIN", pin);
            }
            let network_config = crate::network_config::get_network_config(app)
                .unwrap_or_else(|_| crate::network_config::NetworkConfig::default());
            crate::network_config::apply_to_command(&network_config, &mut cmd);
            let child = cmd
                .spawn()
                .map_err(|e| format!("failed to spawn daemon: {e}"))?;
            *guard = Some(child);
        }
        // Falls through to the health-check poll below either way: a
        // daemon we already spawned on a previous (failed) call might
        // just need more time, not a second spawn attempt.
    }

    for _ in 0..HEALTH_CHECK_ATTEMPTS {
        if daemon_health_ok() {
            return Ok(());
        }
        std::thread::sleep(HEALTH_CHECK_INTERVAL);
    }
    Err("daemon did not become healthy in time".to_string())
}

/// Stops the daemon this process spawned, if any — used when the user
/// explicitly quits, or when re-locking (clearing `BLACKHOLE_DB_PIN`
/// requires a fresh process, not just closing the database handle, since
/// the key was only ever supplied once at process startup).
#[tauri::command]
pub fn stop_daemon(state: tauri::State<'_, DaemonProcess>) {
    if let Ok(mut guard) = state.0.lock() {
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `cargo test` runs tests in this file concurrently by default, and
    // both tests below mutate the same process-wide `BLACKHOLE_DAEMON_BIN`
    // env var — without this lock they race (one test's `set_var` landing
    // between the other's `set_var`/assert/restore), causing sporadic
    // failures unrelated to either test's actual logic.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn env_var_override_wins_over_the_dev_fallback() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: serialized against the other test in this module via
        // `ENV_LOCK`, and the var is restored before returning.
        let previous = std::env::var("BLACKHOLE_DAEMON_BIN").ok();
        unsafe { std::env::set_var("BLACKHOLE_DAEMON_BIN", "/custom/path/to/daemon") };
        assert_eq!(
            daemon_binary_path(),
            PathBuf::from("/custom/path/to/daemon")
        );
        match previous {
            Some(v) => unsafe { std::env::set_var("BLACKHOLE_DAEMON_BIN", v) },
            None => unsafe { std::env::remove_var("BLACKHOLE_DAEMON_BIN") },
        }
    }

    #[test]
    fn dev_fallback_points_at_the_workspace_target_dir() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = std::env::var("BLACKHOLE_DAEMON_BIN").ok();
        unsafe { std::env::remove_var("BLACKHOLE_DAEMON_BIN") };
        let path = daemon_binary_path();
        unsafe {
            match &previous {
                Some(v) => std::env::set_var("BLACKHOLE_DAEMON_BIN", v),
                None => std::env::remove_var("BLACKHOLE_DAEMON_BIN"),
            }
        }
        let path_str = path.to_string_lossy();
        assert!(
            path_str.ends_with("blackhole-daemon") || path_str.ends_with("blackhole-daemon.exe")
        );
        assert!(path_str.contains("target"));
    }
}
