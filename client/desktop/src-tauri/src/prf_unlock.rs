//! Local (non-database) record of *which* enrolled passkey credential —
//! if any — the database-unlock gate (THREAT_MODEL.md §3.7) is bound to.
//! Deliberately stored outside the SQLCipher database, in a plain JSON
//! file under the Tauri app's own config directory: the client needs this
//! *before* the daemon (and its database) has even started, to know which
//! credential to request a WebAuthn PRF assertion against. Nothing in
//! here is secret — a credential id and relying-party id are exactly what
//! a normal `navigator.credentials.get()` call already needs to send to
//! the browser, and are meaningless without the physical authenticator
//! that can actually produce a PRF result for them.
//!
//! **Why PRF and not TOTP**: closing §3.7 for real requires a secret that
//! isn't simply *readable* by whoever can read this file or the OS
//! keystore (the exact attacker model the gap describes) — a WebAuthn
//! PRF-extension result is derived by the authenticator's own hardware
//! (secure enclave / TPM / security key) from the credential's private
//! key, and isn't extractable from OS-level storage the way a TOTP secret
//! (which *has* to sit in a keystore in the clear for anything to verify
//! a live code without the database open) would be. See `main.ts`'s PRF
//! enrollment/unlock flow for where the actual derivation happens — this
//! module only remembers which credential to ask for.
//!
//! **Scope note**: one config, tied to whichever profile is active when
//! it was saved — not per-multi-profile (`bh_storage::profiles`). Extending
//! this to track a gate per profile is a real follow-up, not attempted
//! here, consistent with this pass's other single-profile-first
//! simplifications.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::Manager;

const CONFIG_FILE_NAME: &str = "prf_unlock_gate.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrfUnlockConfig {
    /// Base64url-encoded WebAuthn credential id — the same encoding
    /// `navigator.credentials`' JSON glue already uses elsewhere in this
    /// client (see `main.ts`'s `base64urlToBuffer`/`bufferToBase64url`).
    pub credential_id_b64url: String,
    /// The relying party id the credential was created under
    /// (`BLACKHOLE_RP_ID` at enrollment time) — needed to build a
    /// same-origin `navigator.credentials.get()` call before the daemon
    /// (which is otherwise the source of truth for this) is even running.
    pub rp_id: String,
}

fn config_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join(CONFIG_FILE_NAME))
}

/// `None` means no PRF-based database gate is configured — the normal,
/// default state; the daemon starts without waiting on anything. Plain
/// function over a path (rather than a `tauri::AppHandle`) so this is
/// testable without spinning up a real Tauri app; the `#[tauri::command]`
/// below is a thin wrapper that resolves the real config path.
fn read_config_at(path: &std::path::Path) -> Result<Option<PrfUnlockConfig>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| e.to_string())
}

fn write_config_at(path: &std::path::Path, config: &PrfUnlockConfig) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(config).map_err(|e| e.to_string())?;
    std::fs::write(path, bytes).map_err(|e| e.to_string())
}

fn remove_config_at(path: &std::path::Path) -> Result<(), String> {
    if path.exists() {
        std::fs::remove_file(path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub fn get_prf_unlock_config(app: tauri::AppHandle) -> Result<Option<PrfUnlockConfig>, String> {
    read_config_at(&config_path(&app)?)
}

#[tauri::command]
pub fn save_prf_unlock_config(
    app: tauri::AppHandle,
    config: PrfUnlockConfig,
) -> Result<(), String> {
    write_config_at(&config_path(&app)?, &config)
}

/// Called when the user disables the database-unlock gate (after
/// successfully clearing the underlying DB PIN via the already-running
/// daemon — see `main.ts`) — from then on the daemon starts unconditionally
/// again, same as a profile that never enabled this.
#[tauri::command]
pub fn clear_prf_unlock_config(app: tauri::AppHandle) -> Result<(), String> {
    remove_config_at(&config_path(&app)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_config_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "bh-desktop-prf-unlock-test-{name}-{}.json",
            std::process::id()
        ))
    }

    #[test]
    fn reading_a_missing_config_is_none() {
        let path = temp_config_path("missing");
        let _ = std::fs::remove_file(&path);
        assert_eq!(read_config_at(&path).unwrap(), None);
    }

    #[test]
    fn write_then_read_round_trips() {
        let path = temp_config_path("roundtrip");
        let config = PrfUnlockConfig {
            credential_id_b64url: "abc123".to_string(),
            rp_id: "localhost".to_string(),
        };
        write_config_at(&path, &config).unwrap();
        let loaded = read_config_at(&path).unwrap().unwrap();
        assert_eq!(loaded.credential_id_b64url, "abc123");
        assert_eq!(loaded.rp_id, "localhost");
        remove_config_at(&path).unwrap();
        assert_eq!(read_config_at(&path).unwrap(), None);
    }

    #[test]
    fn removing_an_already_missing_config_is_not_an_error() {
        let path = temp_config_path("remove-missing");
        let _ = std::fs::remove_file(&path);
        assert!(remove_config_at(&path).is_ok());
    }
}
