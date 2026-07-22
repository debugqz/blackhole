//! Local, daemon-side endpoint for the opt-in "opaque wake" push feature
//! (see `crates/bh-push-relay` for the actual relay design/rationale, and
//! `docs/SPEC.md` §5.6). This module only manages *this identity's own*
//! registration state — whether wake pings are enabled at all, and the
//! opaque, rotating token that would be handed to the relay's
//! `POST /register` if/when the daemon's mailbox code
//! (`bh_network::mailbox`) is wired up to actually call out to a relay.
//! That wiring is out of scope here — see the `// TODO(real-push)` marker
//! next to `bh_network::mailbox::Mailbox::push`.
//!
//! The token generated here is intentionally *not* derived from the
//! identity key or any contact/conversation id — it's random bytes, with
//! no way to link it back to who's messaging whom even if the relay
//! operator is fully compromised. It rotates every time push is
//! (re-)enabled, rather than being a fixed, permanently-issued value.
//!
//! Push is opt-in and defaults to off: enabling it costs a small amount of
//! metadata (the relay learns "some client, at roughly this time, wants a
//! wake") that a fully-offline/manually-polling user doesn't pay.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use bh_storage::models::PushRegistration;
use serde::{Deserialize, Serialize};

use crate::AppState;

const TOKEN_BYTES: usize = 32;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

fn generate_token() -> Result<String, StatusCode> {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(hex::encode(bytes))
}

#[derive(Deserialize)]
pub struct SetPushRegistrationRequest {
    pub enabled: bool,
}

#[derive(Serialize)]
pub struct PushRegistrationResponse {
    pub enabled: bool,
    /// Only present in the response to a request that just (re-)enabled
    /// push — this is the opaque token this device would register with
    /// the relay. Never the identity key, never a contact or conversation
    /// id. Deliberately omitted from plain status checks (`GET`) so it
    /// isn't handed out on every idle poll.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// Enables or disables push registration for the active profile. Enabling
/// generates a fresh opaque token (rotating it, if one already existed);
/// disabling deletes the stored registration entirely, token included.
pub async fn set_push_registration(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SetPushRegistrationRequest>,
) -> Result<Json<PushRegistrationResponse>, StatusCode> {
    if req.enabled {
        let token = generate_token()?;
        state
            .db()
            .set_push_registration(&PushRegistration {
                token: token.clone(),
                enabled: true,
                updated_at: now(),
            })
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(Json(PushRegistrationResponse {
            enabled: true,
            token: Some(token),
        }))
    } else {
        state
            .db()
            .clear_push_registration()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(Json(PushRegistrationResponse {
            enabled: false,
            token: None,
        }))
    }
}

/// Current status only — never returns the token itself (see
/// `PushRegistrationResponse::token` doc comment).
pub async fn get_push_registration(
    State(state): State<Arc<AppState>>,
) -> Result<Json<PushRegistrationResponse>, StatusCode> {
    let reg = state
        .db()
        .get_push_registration()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let enabled = reg.map(|r| r.enabled).unwrap_or(false);
    Ok(Json(PushRegistrationResponse {
        enabled,
        token: None,
    }))
}
