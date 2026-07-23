//! Local, daemon-side endpoint for the opt-in "opaque wake" push feature
//! (see `crates/bh-push-relay` for the actual relay design/rationale, and
//! `docs/SPEC.md` §5.6). Manages *this identity's own* registration state
//! — whether wake pings are enabled, the opaque rotating token, and, now,
//! the `relay_url` of the `bh-push-relay` instance that token was
//! registered with.
//!
//! When a live network is attached and `relay_url` is supplied, enabling
//! push actually: (1) calls the relay's real `POST /register`, and (2)
//! signs and publishes a `bh_crypto::push_relay::PushRelayRecord` to the
//! DHT (`bh_network::push_relay_directory`) so a contact's daemon can
//! discover it and call `POST {relay_url}/wake/{token}` after a real send
//! — see `message_crypto.rs`'s `wake_recipient_best_effort`, the send-side
//! half of this wiring (previously the `// TODO(real-push)` marker next to
//! `bh_network::mailbox::Mailbox::push` this module's own doc used to
//! point at). Both the relay call and the DHT publish must succeed before
//! anything is written to local storage — see `set_push_registration`'s
//! own comment for why "enabled" must be atomic with "actually reachable."
//! With no live network (tests, or a daemon that hasn't attached one) or
//! no `relay_url` supplied, this falls back to the pre-existing
//! local-storage-only behavior, same posture every other
//! network-touching feature in this codebase already has.
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

use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use bh_crypto::identity::recipient_key_hash;
use bh_crypto::push_relay::PushRelayRecord;
use bh_network::push_relay_directory;
use bh_network::supervised::SupervisedNetwork;
use bh_storage::models::PushRegistration;
use serde::{Deserialize, Serialize};

use crate::AppState;

const TOKEN_BYTES: usize = 32;
/// Interactive calls (the user is waiting on the `POST /push/registration`
/// response) — short enough not to hang the request indefinitely against
/// an unreachable relay.
const RELAY_REGISTER_TIMEOUT: Duration = Duration::from_secs(10);

/// Shared client for every daemon-to-relay HTTP call in this crate
/// (`push.rs`'s own `/register` call, and `message_crypto.rs`'s
/// `/wake/:token` call) — a fresh `reqwest::Client` per request would
/// rebuild its own connection pool every time for no benefit. No
/// client-wide default timeout; each call site sets its own explicit
/// per-request `.timeout(..)` instead, since "interactive register" and
/// "best-effort background wake" want different bounds.
pub(crate) fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(reqwest::Client::new)
}

fn is_http_or_https(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

#[derive(Deserialize)]
struct RelayRegisterResponse {
    registered: bool,
}

/// Calls the relay's real `POST /register` (`bh-push-relay/src/server.rs`'s
/// `RegisterRequest`/`RegisterResponse` contract).
async fn register_with_relay(relay_url: &str, token: &str) -> Result<(), StatusCode> {
    let response = http_client()
        .post(format!("{}/register", relay_url.trim_end_matches('/')))
        .timeout(RELAY_REGISTER_TIMEOUT)
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if !response.status().is_success() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let body: RelayRegisterResponse = response
        .json()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if body.registered {
        Ok(())
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

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
    /// Base URL of the `bh-push-relay` instance to register with (e.g.
    /// `https://relay.example`) — required for push to actually work over
    /// the real network (see module doc); omitting it keeps the
    /// pre-existing local-only behavior. Ignored when `enabled` is
    /// `false`.
    #[serde(default)]
    pub relay_url: Option<String>,
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

/// Signs and publishes this identity's `PushRelayRecord` to the DHT (used
/// both by [`set_push_registration`] at enable-time and by
/// [`republish_own_registration_best_effort`] on the daemon's periodic
/// tick).
async fn publish_own_push_registration(
    state: &AppState,
    network: &SupervisedNetwork,
    relay_url: &str,
    token: &str,
) -> Result<(), StatusCode> {
    let identity = crate::message_crypto::own_identity_keypair(state)?;
    let record = PushRelayRecord::sign(&identity, relay_url.to_string(), token.to_string());
    let key_hash = recipient_key_hash(&identity.public_identity_bytes());
    push_relay_directory::publish_own_registration(&network.dht(), &key_hash, record.to_bytes())
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

/// Enables or disables push registration for the active profile. Enabling
/// generates a fresh opaque token (rotating it, if one already existed).
///
/// If a live network is attached and `relay_url` is supplied, this also
/// registers the token with the relay and publishes a signed
/// `PushRelayRecord` to the DHT *before* writing anything to local
/// storage — "enabled" must be atomic with "actually reachable," the same
/// reasoning `message_crypto.rs`'s `load_or_establish_session` doc comment
/// gives for not persisting a session before its handshake is actually
/// delivered. A relay/DHT failure here surfaces as `503` rather than
/// silently leaving the profile in a state where it thinks push is on but
/// no contact could ever actually reach it.
///
/// Disabling deletes the stored registration entirely, token included —
/// there's no relay-side unregister call to make (`bh-push-relay` has none
/// today; a stale token simply stops being used, and carries no linkable
/// metadata on its own, SPEC.md §5.6).
pub async fn set_push_registration(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SetPushRegistrationRequest>,
) -> Result<Json<PushRegistrationResponse>, StatusCode> {
    if req.enabled {
        if let Some(relay_url) = &req.relay_url {
            if !is_http_or_https(relay_url) {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
        let token = generate_token()?;

        if let (Some(network), Some(relay_url)) = (state.network.as_ref(), &req.relay_url) {
            register_with_relay(relay_url, &token).await?;
            publish_own_push_registration(&state, network, relay_url, &token).await?;
        }

        state
            .db()
            .set_push_registration(&PushRegistration {
                token: token.clone(),
                enabled: true,
                updated_at: now(),
                relay_url: req.relay_url.clone(),
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

/// Re-publishes this profile's `PushRelayRecord` to the DHT, if push is
/// enabled with a `relay_url` on record — Kademlia records expire, so a
/// long-lived daemon needs to redo this periodically, same reasoning
/// `prekey_directory`'s own doc comment gives and the same pattern
/// `tree_head::publish_own_tree_head` already established. Does **not**
/// re-call the relay's `POST /register` — unlike a DHT record, the
/// relay-side registration doesn't expire, so there's nothing to redo
/// there. Best-effort: logs and returns on any failure, never propagates
/// one, since this runs on a background tick with no caller to report to.
pub async fn republish_own_registration_best_effort(
    state: &Arc<AppState>,
    network: &SupervisedNetwork,
) {
    let reg = match state.db().get_push_registration() {
        Ok(Some(reg)) => reg,
        Ok(None) => return,
        Err(err) => {
            tracing::debug!(%err, "push: failed to read registration, skipping republish");
            return;
        }
    };
    if !reg.enabled {
        return;
    }
    let Some(relay_url) = reg.relay_url else {
        return;
    };
    if let Err(err) = publish_own_push_registration(state, network, &relay_url, &reg.token).await {
        tracing::warn!(
            %err,
            "push: failed to republish push-relay registration (will retry next tick)"
        );
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
