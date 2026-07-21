//! Safety-number verification endpoints (SPEC.md §3): lets the UI show a
//! comparable fingerprint for a contact and record the result once the
//! user has actually compared it out-of-band. Verification is never
//! automatic — this crate only ever *records* a verification the user
//! performed, it never asserts one on their behalf.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use bh_crypto::safety_number as sn;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::AppState;

/// Both public keys packed as `signing(32) || agreement(32)` — the same
/// convention `identity::create_identity` uses for `own_identity` and that
/// `contacts::add_contact` expects for a contact's `identity_public_key`.
fn split_keys(bytes: &[u8]) -> Option<(VerifyingKey, X25519PublicKey)> {
    if bytes.len() != 64 {
        return None;
    }
    let signing = VerifyingKey::from_bytes(bytes[..32].try_into().ok()?).ok()?;
    let agreement = X25519PublicKey::from(<[u8; 32]>::try_from(&bytes[32..]).ok()?);
    Some((signing, agreement))
}

#[derive(Serialize)]
pub struct SafetyNumberResponse {
    pub digits: String,
    pub grouped: String,
    pub qr_svg: String,
}

pub async fn get_safety_number(
    State(state): State<Arc<AppState>>,
    Path(contact_id): Path<String>,
) -> Result<Json<SafetyNumberResponse>, StatusCode> {
    let own = state
        .db()
        .get_own_identity()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::PRECONDITION_FAILED)?;
    let contact = state
        .db()
        .get_contact(&contact_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let (my_signing, my_agreement) =
        split_keys(&own.identity_public_key).ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let (their_signing, their_agreement) =
        split_keys(&contact.identity_public_key).ok_or(StatusCode::UNPROCESSABLE_ENTITY)?;

    let digits = sn::safety_number(&my_agreement, &my_signing, &their_agreement, &their_signing);
    let grouped = sn::format_grouped(&digits);
    let qr_svg = sn::to_qr_svg(&digits).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(SafetyNumberResponse {
        digits,
        grouped,
        qr_svg,
    }))
}

#[derive(Deserialize)]
pub struct SetVerifiedRequest {
    pub verified: bool,
}

pub async fn set_verified(
    State(state): State<Arc<AppState>>,
    Path(contact_id): Path<String>,
    Json(req): Json<SetVerifiedRequest>,
) -> StatusCode {
    match state.db().set_contact_verified(&contact_id, req.verified) {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
