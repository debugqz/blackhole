//! PIN/passphrase layer in front of the SQLCipher database key
//! (`docs/THREAT_MODEL.md` §3.7, ranked gap #7) — HTTP surface over
//! `bh_storage::db_key_lock`. Runs against the *currently active, already
//! unlocked* profile: the daemon needs the raw key to have opened its
//! database in the first place, so setting/clearing a PIN is a runtime
//! operation on an already-running daemon (mirroring how Signal Desktop
//! lets you set a PIN from inside the already-unlocked app), not a
//! pre-boot gate. Enforcement of an already-set PIN happens once, at the
//! daemon's next startup, in `daemon/src/main.rs::load_or_create_db_key`.
//!
//! Scoped to the messaging database's key (`keystore::DB_KEY_LABEL`) only
//! — the payments database (`keystore::PAYMENTS_DB_KEY_LABEL`) is a
//! separate key by design (`bh_storage::payments_db`) and is not wrapped
//! by this endpoint; extending PIN protection to it symmetrically is a
//! natural follow-up, not done here.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use bh_storage::db_key_lock::{self, DbKeyState};
use bh_storage::keystore::DB_KEY_LABEL;
use serde::Deserialize;

use crate::AppState;

#[derive(Deserialize)]
pub struct DbPinRequest {
    pub pin: String,
}

/// Minimum PIN length `set_db_pin` accepts. This gates a brute-force-
/// resistant lock in front of the SQLCipher database key
/// (THREAT_MODEL.md §3.7) — a 1-character PIN defeats the point of having
/// one at all.
const MIN_PIN_LEN: usize = 4;

/// Enables PIN protection on the active profile's database key. Fails
/// with `409 Conflict` if a PIN is already set (clear it first — this
/// endpoint doesn't do an atomic "change PIN," matching how `clear_pin`
/// itself only ever restores to unprotected).
pub async fn set_db_pin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DbPinRequest>,
) -> StatusCode {
    if req.pin.chars().count() < MIN_PIN_LEN {
        return StatusCode::BAD_REQUEST;
    }
    let keystore = state.keystore();
    let current = match db_key_lock::load_db_key_state(&keystore, DB_KEY_LABEL) {
        Ok(state) => state,
        Err(err) => {
            tracing::error!(%err, "failed to read db key state");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };
    let raw_key = match current {
        Some(DbKeyState::Unprotected(key)) => key,
        Some(DbKeyState::PinProtected(_)) => return StatusCode::CONFLICT,
        None => return StatusCode::PRECONDITION_FAILED,
    };
    match db_key_lock::set_pin(&keystore, DB_KEY_LABEL, &req.pin, &raw_key) {
        Ok(()) => StatusCode::OK,
        Err(err) => {
            tracing::error!(%err, "failed to set db pin");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

/// Disables PIN protection, given the correct current PIN. `401
/// Unauthorized` for a wrong PIN, `409 Conflict` if no PIN is set.
pub async fn clear_db_pin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DbPinRequest>,
) -> StatusCode {
    let keystore = state.keystore();
    let sealed = match db_key_lock::load_db_key_state(&keystore, DB_KEY_LABEL) {
        Ok(Some(DbKeyState::PinProtected(blob))) => blob,
        Ok(Some(DbKeyState::Unprotected(_))) | Ok(None) => return StatusCode::CONFLICT,
        Err(err) => {
            tracing::error!(%err, "failed to read db key state");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };
    match db_key_lock::clear_pin(&keystore, DB_KEY_LABEL, &req.pin, &sealed) {
        Ok(_) => StatusCode::OK,
        Err(bh_storage::StorageError::InvalidPin) => StatusCode::UNAUTHORIZED,
        Err(err) => {
            tracing::error!(%err, "failed to clear db pin");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[derive(serde::Serialize)]
pub struct DbPinStatus {
    pub pin_set: bool,
}

pub async fn db_pin_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<DbPinStatus>, StatusCode> {
    let keystore = state.keystore();
    let state = db_key_lock::load_db_key_state(&keystore, DB_KEY_LABEL).map_err(|err| {
        tracing::error!(%err, "failed to read db key state");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(DbPinStatus {
        pin_set: matches!(state, Some(DbKeyState::PinProtected(_))),
    }))
}
