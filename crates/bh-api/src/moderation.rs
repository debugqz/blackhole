//! Client-side moderation and abuse handling (SPEC.md §8) — everything
//! here operates only on the local user's own data. There is no
//! server-side content scanning anywhere in this codebase, and there
//! never will be: that's a design principle, not a missing feature.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use bh_storage::models::{Message, MessageRequest, MessageRequestStatus};
use serde::{Deserialize, Serialize};

use crate::AppState;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

pub async fn unblock_contact(
    State(state): State<Arc<AppState>>,
    Path(contact_id): Path<String>,
) -> StatusCode {
    match state.db.set_contact_blocked(&contact_id, false) {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// "Solicitudes de mensaje" (SPEC.md §8): new contact from someone
/// unverified defaults to a request, not the main chat list, until
/// accepted. Whatever calls this after receiving a first message from an
/// unknown sender is responsible for the "is this sender already a known
/// contact" check — this endpoint just records the request once that's
/// been decided.
pub async fn list_message_requests(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<MessageRequest>>, StatusCode> {
    state
        .db
        .list_pending_message_requests()
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn accept_message_request(
    State(state): State<Arc<AppState>>,
    Path(contact_id): Path<String>,
) -> StatusCode {
    match state
        .db
        .set_message_request_status(&contact_id, MessageRequestStatus::Accepted)
    {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

pub async fn decline_message_request(
    State(state): State<Arc<AppState>>,
    Path(contact_id): Path<String>,
) -> StatusCode {
    match state
        .db
        .set_message_request_status(&contact_id, MessageRequestStatus::Declined)
    {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Voluntary report bundle (SPEC.md §8): the reporting user explicitly
/// picks which of their own messages to include — this never has access
/// to anything the user didn't name. There's no submission transport wired
/// up (no moderation-review infrastructure exists yet); this just compiles
/// the bundle the client would send somewhere, once that exists.
#[derive(Deserialize)]
pub struct CreateReportRequest {
    pub contact_id: String,
    pub reason: String,
    pub message_ids: Vec<String>,
}

#[derive(Serialize)]
pub struct ReportBundle {
    pub contact_id: String,
    pub reason: String,
    pub created_at: i64,
    pub messages: Vec<Message>,
}

pub async fn create_report(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateReportRequest>,
) -> Result<Json<ReportBundle>, StatusCode> {
    let messages = state
        .db
        .get_messages_by_ids(&req.message_ids)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ReportBundle {
        contact_id: req.contact_id,
        reason: req.reason,
        created_at: now(),
        messages,
    }))
}
