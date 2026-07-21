use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use bh_storage::models::Contact;
use serde::Deserialize;

use crate::AppState;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

pub async fn list_contacts(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<Contact>>, StatusCode> {
    state
        .db()
        .list_contacts()
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
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
