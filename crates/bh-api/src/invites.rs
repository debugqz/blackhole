//! Expiring / limited-use invite links (SPEC.md §3). Creating an invite
//! records it in this identity's own `issued_invites` ledger
//! (`bh-storage::invites`) so expiry/use-limits can be enforced without a
//! server — see that module's doc comment for why enforcement has to live
//! with the issuer. Decoding a scanned link is a separate, storage-free
//! operation: the scanning party only gets to *see* the embedded expiry,
//! not authoritatively enforce it (only the issuer's ledger can).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use bh_crypto::identity::IdentityKeyPair;
use bh_crypto::invite::InvitePayload;
use bh_storage::invites::InviteValidity;
use bh_storage::models::IssuedInvite;
use serde::{Deserialize, Serialize};

use crate::AppState;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

fn load_identity(state: &AppState) -> Result<IdentityKeyPair, StatusCode> {
    let stored = state
        .db()
        .get_own_identity()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::PRECONDITION_FAILED)?;
    let bytes: [u8; 64] = stored
        .identity_private_key
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    IdentityKeyPair::import_bytes(&bytes).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Deserialize)]
pub struct CreateInviteRequest {
    pub display_name: Option<String>,
    /// Invite becomes unredeemable this many seconds from now, if set.
    pub expires_in_secs: Option<i64>,
    /// Maximum number of times the issuer will accept a handshake using
    /// this token, if set (e.g. `Some(1)` for a single-use invite).
    pub max_uses: Option<i64>,
}

#[derive(Serialize)]
pub struct CreateInviteResponse {
    pub link: String,
    pub qr_svg: String,
    pub token: String,
    pub expires_at: Option<i64>,
}

pub async fn create_invite(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateInviteRequest>,
) -> Result<Json<CreateInviteResponse>, StatusCode> {
    let identity = load_identity(&state)?;
    let created_at = now();

    let mut payload = InvitePayload::for_identity(&identity, req.display_name)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let expires_at = req.expires_in_secs.map(|secs| created_at + secs);
    if let Some(expires_at) = expires_at {
        payload = payload.with_expiry(expires_at);
    }

    state
        .db()
        .record_issued_invite(&IssuedInvite {
            token: payload.token.to_vec(),
            created_at,
            expires_at,
            max_uses: req.max_uses,
            use_count: 0,
            revoked: false,
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let link = payload
        .to_link()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let qr_svg = payload
        .to_qr_svg()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(CreateInviteResponse {
        link,
        qr_svg,
        token: hex::encode(payload.token),
        expires_at,
    }))
}

#[derive(Serialize)]
pub struct DecodedInvite {
    pub identity_signing_key: String,
    pub identity_agreement_key: String,
    pub display_name: Option<String>,
    pub expires_at: Option<i64>,
    pub locally_expired: bool,
}

#[derive(Deserialize)]
pub struct DecodeInviteRequest {
    pub link: String,
}

/// Parses a scanned invite link. Storage-free — this doesn't consult any
/// ledger, so it works equally well for links issued by *other* people's
/// identities.
pub async fn decode_invite(
    Json(req): Json<DecodeInviteRequest>,
) -> Result<Json<DecodedInvite>, StatusCode> {
    let payload = InvitePayload::from_link(&req.link).map_err(|_| StatusCode::BAD_REQUEST)?;
    let now = now();
    Ok(Json(DecodedInvite {
        identity_signing_key: hex::encode(payload.identity_signing_key.to_bytes()),
        identity_agreement_key: hex::encode(payload.identity_agreement_key.as_bytes()),
        display_name: payload.display_name.clone(),
        expires_at: payload.expires_at,
        locally_expired: payload.is_expired(now),
    }))
}

#[derive(Serialize)]
pub struct InviteValidityResponse {
    pub validity: &'static str,
}

fn validity_str(v: InviteValidity) -> &'static str {
    match v {
        InviteValidity::Valid => "valid",
        InviteValidity::Unknown => "unknown",
        InviteValidity::Expired => "expired",
        InviteValidity::Revoked => "revoked",
        InviteValidity::UseLimitReached => "use_limit_reached",
    }
}

/// Represents a handshake attempt arriving that names this token — records
/// one use if (and only if) it's still valid. Once `bh-network` is wired
/// in, this is what the daemon calls before completing an inbound X3DH
/// handshake that references an invite token.
pub async fn consume_invite(
    State(state): State<Arc<AppState>>,
    Path(token_hex): Path<String>,
) -> Result<Json<InviteValidityResponse>, StatusCode> {
    let token = hex::decode(&token_hex).map_err(|_| StatusCode::BAD_REQUEST)?;
    let validity = state
        .db()
        .consume_invite(&token, now())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(InviteValidityResponse {
        validity: validity_str(validity),
    }))
}

pub async fn revoke_invite(
    State(state): State<Arc<AppState>>,
    Path(token_hex): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let token = hex::decode(&token_hex).map_err(|_| StatusCode::BAD_REQUEST)?;
    state
        .db()
        .revoke_invite(&token)
        .map(|()| StatusCode::OK)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
