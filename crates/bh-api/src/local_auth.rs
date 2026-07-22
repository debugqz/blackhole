//! Local-unlock gate (passkey/TOTP) for the Tauri client, backed by
//! `bh-crypto::auth`. This gates the **client-side UI only** — it is shown
//! after the daemon has already opened the SQLCipher database, and does
//! not close THREAT_MODEL.md §3.7's "no PIN/passphrase layer in front of
//! the DB key" gap. Redesigning daemon startup to gate the DB key itself
//! behind passkey/TOTP is a real follow-up, not attempted here (risk of
//! turning a demo feature into a real account lockout is deliberately
//! avoided by keeping this additive and opt-in — the screen only appears
//! if something is actually enrolled).
//!
//! `AppState::passkey` is this daemon's WebAuthn relying party, built once
//! at startup from `BLACKHOLE_RP_ID`/`BLACKHOLE_RP_ORIGIN`. Those defaults
//! (`localhost`/`http://localhost:47853`) only suit the loopback dev
//! daemon — the packaged Tauri webview's real origin is platform-specific
//! and must be set/verified manually per platform (see `bh-crypto::auth`'s
//! own doc comment).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use bh_crypto::auth::TotpSecret;
use bh_storage::models::{PasskeyCredential, TotpSecretRow};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Uuid,
};

use crate::AppState;

#[derive(Default)]
pub struct LocalAuthRegistry {
    passkey_reg: Mutex<HashMap<String, PasskeyRegistration>>,
    passkey_auth: Mutex<HashMap<String, PasskeyAuthentication>>,
    /// Unconfirmed TOTP enrollments — not persisted until
    /// [`totp_enroll_confirm`] proves possession with a real code.
    pending_totp: Mutex<HashMap<String, TotpSecret>>,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

/// There is exactly one local-auth identity per profile — a fixed nil UUID
/// is fine here (WebAuthn's `user_id` only needs to be stable and unique
/// *within this relying party*, which is scoped to one profile already).
fn local_user_id() -> Uuid {
    Uuid::nil()
}

#[derive(Serialize)]
pub struct LocalAuthStatus {
    pub passkey_enrolled: bool,
    pub totp_enrolled: bool,
}

pub async fn status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<LocalAuthStatus>, StatusCode> {
    let passkey_enrolled = !state
        .db()
        .list_passkey_credentials()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .is_empty();
    let totp_enrolled = state
        .db()
        .get_totp_secret()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .is_some();
    Ok(Json(LocalAuthStatus {
        passkey_enrolled,
        totp_enrolled,
    }))
}

// ---------------------------------------------------------------------
// Passkey enrollment
// ---------------------------------------------------------------------

#[derive(Serialize)]
pub struct PasskeyRegisterStartResponse {
    pub ceremony_id: String,
    pub challenge_json: serde_json::Value,
}

pub async fn passkey_register_start(
    State(state): State<Arc<AppState>>,
) -> Result<Json<PasskeyRegisterStartResponse>, StatusCode> {
    let (challenge, reg_state) = state
        .passkey
        .start_registration(local_user_id(), "local", "Blackhole local unlock", None)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let ceremony_id = uuid::Uuid::new_v4().to_string();
    state
        .local_auth
        .passkey_reg
        .lock()
        .expect("local_auth registry lock poisoned")
        .insert(ceremony_id.clone(), reg_state);

    let challenge_json =
        serde_json::to_value(challenge).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(PasskeyRegisterStartResponse {
        ceremony_id,
        challenge_json,
    }))
}

#[derive(Deserialize)]
pub struct PasskeyRegisterFinishRequest {
    pub ceremony_id: String,
    pub credential_json: serde_json::Value,
    pub label: Option<String>,
}

pub async fn passkey_register_finish(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PasskeyRegisterFinishRequest>,
) -> Result<StatusCode, StatusCode> {
    let reg_state = state
        .local_auth
        .passkey_reg
        .lock()
        .expect("local_auth registry lock poisoned")
        .remove(&req.ceremony_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let credential: RegisterPublicKeyCredential =
        serde_json::from_value(req.credential_json).map_err(|_| StatusCode::BAD_REQUEST)?;
    let passkey = state
        .passkey
        .finish_registration(&credential, &reg_state)
        .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;

    let credential_id = hex::encode(passkey.cred_id().as_ref());
    let passkey_blob =
        serde_json::to_vec(&passkey).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .db()
        .upsert_passkey_credential(&PasskeyCredential {
            credential_id,
            passkey_blob,
            label: req.label,
            enrolled_at: now(),
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------
// Passkey authentication (unlock)
// ---------------------------------------------------------------------

#[derive(Serialize)]
pub struct PasskeyAuthStartResponse {
    pub ceremony_id: String,
    pub challenge_json: serde_json::Value,
}

pub async fn passkey_auth_start(
    State(state): State<Arc<AppState>>,
) -> Result<Json<PasskeyAuthStartResponse>, StatusCode> {
    let stored = state
        .db()
        .list_passkey_credentials()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if stored.is_empty() {
        return Err(StatusCode::PRECONDITION_FAILED);
    }
    let known: Vec<Passkey> = stored
        .iter()
        .filter_map(|c| serde_json::from_slice(&c.passkey_blob).ok())
        .collect();

    let (challenge, auth_state) = state
        .passkey
        .start_authentication(&known)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let ceremony_id = uuid::Uuid::new_v4().to_string();
    state
        .local_auth
        .passkey_auth
        .lock()
        .expect("local_auth registry lock poisoned")
        .insert(ceremony_id.clone(), auth_state);

    let challenge_json =
        serde_json::to_value(challenge).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(PasskeyAuthStartResponse {
        ceremony_id,
        challenge_json,
    }))
}

#[derive(Deserialize)]
pub struct PasskeyAuthFinishRequest {
    pub ceremony_id: String,
    pub credential_json: serde_json::Value,
}

pub async fn passkey_auth_finish(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PasskeyAuthFinishRequest>,
) -> Result<StatusCode, StatusCode> {
    let auth_state = state
        .local_auth
        .passkey_auth
        .lock()
        .expect("local_auth registry lock poisoned")
        .remove(&req.ceremony_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let credential: PublicKeyCredential =
        serde_json::from_value(req.credential_json).map_err(|_| StatusCode::BAD_REQUEST)?;
    state
        .passkey
        .finish_authentication(&credential, &auth_state)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(StatusCode::OK)
}

/// What the client ever sees for an enrolled passkey — deliberately omits
/// `passkey_blob`, which never needs to leave the daemon (same precedent as
/// `files::FileMetaPublic` omitting `file_key`).
#[derive(Serialize)]
pub struct PasskeyCredentialPublic {
    pub credential_id: String,
    pub label: Option<String>,
    pub enrolled_at: i64,
}

impl From<PasskeyCredential> for PasskeyCredentialPublic {
    fn from(c: PasskeyCredential) -> Self {
        PasskeyCredentialPublic {
            credential_id: c.credential_id,
            label: c.label,
            enrolled_at: c.enrolled_at,
        }
    }
}

/// Lists enrolled passkeys so the client can offer per-credential removal
/// (`passkey_delete`) instead of only an aggregate enrolled/not-enrolled
/// flag.
pub async fn passkey_list(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<PasskeyCredentialPublic>>, StatusCode> {
    state
        .db()
        .list_passkey_credentials()
        .map(|creds| Json(creds.into_iter().map(Into::into).collect()))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn passkey_delete(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(credential_id): axum::extract::Path<String>,
) -> StatusCode {
    match state.db().delete_passkey_credential(&credential_id) {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

// ---------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------

#[derive(Serialize)]
pub struct TotpEnrollStartResponse {
    pub ceremony_id: String,
    pub provisioning_uri: String,
    pub qr_svg: String,
    pub base32_secret: String,
}

pub async fn totp_enroll_start(
    State(state): State<Arc<AppState>>,
) -> Result<Json<TotpEnrollStartResponse>, StatusCode> {
    let secret = TotpSecret::generate("local", "Blackhole")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let provisioning_uri = secret.provisioning_uri();
    let qr_svg =
        bh_crypto::qr::to_svg(&provisioning_uri).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let base32_secret = secret.base32_secret();

    let ceremony_id = uuid::Uuid::new_v4().to_string();
    state
        .local_auth
        .pending_totp
        .lock()
        .expect("local_auth registry lock poisoned")
        .insert(ceremony_id.clone(), secret);

    Ok(Json(TotpEnrollStartResponse {
        ceremony_id,
        provisioning_uri,
        qr_svg,
        base32_secret,
    }))
}

#[derive(Deserialize)]
pub struct TotpEnrollConfirmRequest {
    pub ceremony_id: String,
    pub code: String,
}

pub async fn totp_enroll_confirm(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TotpEnrollConfirmRequest>,
) -> Result<StatusCode, StatusCode> {
    let secret = state
        .local_auth
        .pending_totp
        .lock()
        .expect("local_auth registry lock poisoned")
        .remove(&req.ceremony_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    if !secret.verify(&req.code) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    state
        .db()
        .set_totp_secret(&TotpSecretRow {
            base32_secret: secret.base32_secret(),
            enrolled_at: now(),
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct TotpVerifyRequest {
    pub code: String,
}

pub async fn totp_verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TotpVerifyRequest>,
) -> Result<StatusCode, StatusCode> {
    let row = state
        .db()
        .get_totp_secret()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::PRECONDITION_FAILED)?;
    let secret = TotpSecret::from_base32(&row.base32_secret, "local", "Blackhole")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if secret.verify(&req.code) {
        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

pub async fn totp_delete(State(state): State<Arc<AppState>>) -> StatusCode {
    match state.db().delete_totp_secret() {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
