use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use bh_storage::models::{Conversation, Message};
use serde::{Deserialize, Serialize};

use crate::AppState;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

pub async fn list_conversations(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<Conversation>>, StatusCode> {
    state
        .db()
        .list_conversations()
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Deserialize)]
pub struct CreateDirectConversationRequest {
    pub contact_id: String,
}

pub async fn create_direct_conversation(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateDirectConversationRequest>,
) -> Result<Json<Conversation>, StatusCode> {
    let conversation_id = uuid::Uuid::new_v4().to_string();
    let created_at = now();
    state
        .db()
        .create_direct_conversation(&conversation_id, &req.contact_id, created_at)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .db()
        .get_conversation(&conversation_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)
        .map(Json)
}

#[derive(Deserialize)]
pub struct ListMessagesQuery {
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    50
}

pub async fn list_messages(
    State(state): State<Arc<AppState>>,
    Path(conversation_id): Path<String>,
    Query(query): Query<ListMessagesQuery>,
) -> Result<Json<Vec<Message>>, StatusCode> {
    state
        .db()
        .list_messages(&conversation_id, query.limit)
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Sends (i.e. stores locally as outgoing) a message in a conversation.
/// This is a local-storage operation only — actual network transmission
/// waits on `bh-network` being wired into the daemon (see CLAUDE.md repo
/// layout). The disappearing-messages timer, if the conversation has one
/// set, is applied automatically here rather than left to the caller.
#[derive(Deserialize)]
pub struct SendMessageRequest {
    pub body: String,
    pub reply_to_message_id: Option<String>,
}

#[derive(Serialize)]
pub struct SendMessageResponse {
    pub message: Message,
}

pub async fn send_message(
    State(state): State<Arc<AppState>>,
    Path(conversation_id): Path<String>,
    Json(req): Json<SendMessageRequest>,
) -> Result<Json<SendMessageResponse>, StatusCode> {
    let sent_at = now();
    let expires_at = state
        .db()
        .compute_message_expiry(&conversation_id, sent_at)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let message = Message {
        message_id: uuid::Uuid::new_v4().to_string(),
        conversation_id,
        sender_contact_id: None,
        body: Some(req.body),
        sent_at,
        received_at: None,
        expires_at,
        deleted_at: None,
        reply_to_message_id: req.reply_to_message_id,
    };
    state
        .db()
        .insert_message(&message)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(SendMessageResponse { message }))
}

#[derive(Deserialize)]
pub struct SetDisappearingTimerRequest {
    /// Seconds until a newly-sent message in this conversation
    /// self-destructs; `None`/omitted turns the timer off.
    pub timer_secs: Option<i64>,
}

pub async fn set_disappearing_timer(
    State(state): State<Arc<AppState>>,
    Path(conversation_id): Path<String>,
    Json(req): Json<SetDisappearingTimerRequest>,
) -> StatusCode {
    match state
        .db()
        .set_disappearing_timer(&conversation_id, req.timer_secs)
    {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
