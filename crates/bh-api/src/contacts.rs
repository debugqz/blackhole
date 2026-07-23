use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use bh_storage::models::Contact;
use serde::{Deserialize, Serialize};

use crate::AppState;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

/// A purely local, client-side trust heuristic (see module doc /
/// `compute_trust_level`) — never a substitute for actually verifying a
/// safety number, just a UI signal for "how well do I actually know this
/// contact." `Blocked` and `Verified` reflect real explicit user actions;
/// `Established`/`New` are inferred from local activity alone.
#[derive(Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    Blocked,
    Verified,
    Established,
    New,
}

/// Thresholds for the `Established` heuristic — tunable without a schema
/// change, since `TrustLevel` is never persisted (see `ContactView`'s doc
/// comment).
const ESTABLISHED_MIN_MESSAGES: i64 = 10;
const ESTABLISHED_MIN_AGE_SECONDS: i64 = 3 * 24 * 60 * 60;

/// `blocked` is checked before `verified` — a blocked contact is actively
/// distrusted right now, regardless of whether it was verified in the
/// past. Only `Verified` reflects a real cryptographic guarantee (a
/// confirmed safety number); `Established` is just "we've talked a fair
/// amount over a few days," a much weaker signal shown so a longtime
/// unverified contact doesn't look identical to one added five minutes
/// ago.
fn compute_trust_level(contact: &Contact, message_count: i64, now: i64) -> TrustLevel {
    if contact.blocked {
        return TrustLevel::Blocked;
    }
    if contact.verified {
        return TrustLevel::Verified;
    }
    if message_count >= ESTABLISHED_MIN_MESSAGES
        && now - contact.added_at >= ESTABLISHED_MIN_AGE_SECONDS
    {
        return TrustLevel::Established;
    }
    TrustLevel::New
}

/// The API-facing view of a contact: the stored row plus a derived trust
/// heuristic — never persisted, computed fresh each time, same pattern as
/// `payment_requests::PaymentRequestView`.
#[derive(Serialize)]
pub struct ContactView {
    #[serde(flatten)]
    pub contact: Contact,
    pub trust_level: TrustLevel,
}

pub async fn list_contacts(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ContactView>>, StatusCode> {
    let contacts = state
        .db()
        .list_contacts()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let counts = state
        .db()
        .message_counts_by_contact()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let now = now();
    let views = contacts
        .into_iter()
        .map(|c| {
            let count = counts.get(&c.contact_id).copied().unwrap_or(0);
            let trust_level = compute_trust_level(&c, count, now);
            ContactView {
                contact: c,
                trust_level,
            }
        })
        .collect();
    Ok(Json(views))
}

#[derive(Deserialize)]
pub struct AddContactRequest {
    pub contact_id: String,
    /// Hex-encoded identity public key, typically decoded from an invite
    /// link/QR (`bh_crypto::invite`).
    pub identity_public_key: String,
    pub display_name: Option<String>,
}

pub async fn add_contact(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddContactRequest>,
) -> Result<StatusCode, StatusCode> {
    let identity_public_key =
        hex::decode(&req.identity_public_key).map_err(|_| StatusCode::BAD_REQUEST)?;
    state
        .db()
        .upsert_contact(&Contact {
            contact_id: req.contact_id,
            identity_public_key,
            display_name: req.display_name,
            verified: false,
            blocked: false,
            added_at: now(),
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::CREATED)
}

pub async fn block_contact(
    State(state): State<Arc<AppState>>,
    Path(contact_id): Path<String>,
) -> StatusCode {
    match state.db().set_contact_blocked(&contact_id, true) {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
