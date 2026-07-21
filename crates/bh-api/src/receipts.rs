//! Delivery/read receipt endpoints. These operate purely on local storage:
//! the actual encrypted receipt envelope (`bh_crypto::envelope::Envelope::Receipt`)
//! is what would travel over the wire once `bh-network` is wired into the
//! daemon (CLAUDE.md repo layout) — decrypting one of those and calling
//! `upsert_receipt` here is the intended integration point. SPEC.md §2.3:
//! nothing about a receipt is ever visible to the network layer in
//! plaintext, since it's just more Double Ratchet/MLS ciphertext until
//! decrypted by the intended recipient.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use bh_storage::models::{MessageReceipt, ReceiptStatus};
use serde::Deserialize;

use crate::AppState;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

#[derive(Deserialize)]
pub struct RecordReceiptRequest {
    pub contact_id: String,
    #[serde(rename = "status")]
    pub status: RequestReceiptStatus,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestReceiptStatus {
    Delivered,
    Read,
}

pub async fn record_receipt(
    State(state): State<Arc<AppState>>,
    Path(message_id): Path<String>,
    Json(req): Json<RecordReceiptRequest>,
) -> StatusCode {
    let status = match req.status {
        RequestReceiptStatus::Delivered => ReceiptStatus::Delivered,
        RequestReceiptStatus::Read => ReceiptStatus::Read,
    };
    match state.db().upsert_receipt(&MessageReceipt {
        message_id,
        contact_id: req.contact_id,
        status,
        updated_at: now(),
    }) {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

pub async fn list_receipts(
    State(state): State<Arc<AppState>>,
    Path(message_id): Path<String>,
) -> Result<Json<Vec<MessageReceipt>>, StatusCode> {
    state
        .db()
        .list_receipts_for_message(&message_id)
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
