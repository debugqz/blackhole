use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use bh_crypto::envelope::Envelope;
use bh_storage::models::{Conversation, ConversationKind, Message};
use serde::{Deserialize, Serialize};

use crate::AppState;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

/// Every `GET /conversations` call is also this profile's "first access"
/// check for the singleton local "Notes to self" conversation: lazily
/// creating it here means an existing profile that predates this feature
/// still picks one up, not just brand-new ones created via `POST
/// /identity`'s eager bootstrap call — see `identity.rs`.
pub async fn list_conversations(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<Conversation>>, StatusCode> {
    state
        .db()
        .ensure_self_conversation(now())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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
    /// Omitted (or `null`) means "sent by the local user" — the normal
    /// case, and the only one that matters for a direct conversation or an
    /// ordinary group. For a broadcast channel (`groups.broadcast_only`),
    /// this is also how the group's simulated non-owner shadow members
    /// (see `groups.rs` module doc) are exercised attempting to post: a
    /// group conversation whose backing group is broadcast-only rejects
    /// any send that names a `sender_contact_id` other than the local
    /// user, since only the channel's owner (always the local user — this
    /// daemon never joins a group it didn't create) may post.
    #[serde(default)]
    pub sender_contact_id: Option<String>,
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
    let conversation = state
        .db()
        .get_conversation(&conversation_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // `sender_contact_id` is only ever honored for `Group` conversations,
    // where it's how a broadcast channel's simulated non-owner shadow
    // members (see `groups.rs` module doc) are exercised attempting to
    // post. Silently ignored (forced to the real local-user sender) for
    // `Direct`/`SelfNotes` — a 1:1 or self conversation has no
    // "post as this other party" concept, and honoring an
    // attacker-controlled `sender_contact_id` there would let a
    // compromised webview forge messages that look like they came from a
    // verified contact.
    let sender_contact_id = if conversation.kind == ConversationKind::Group {
        req.sender_contact_id
    } else {
        None
    };
    if sender_contact_id.is_some() {
        let group = state
            .db()
            .get_group_for_conversation(&conversation_id)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if group.is_some_and(|g| g.broadcast_only) {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    let message_id = uuid::Uuid::new_v4().to_string();

    match conversation.kind {
        // No counterparty for a self-conversation, so there is no
        // encryption session/ratchet to establish or advance before
        // storing the message — it goes straight into the
        // SQLCipher-encrypted local store as plain local scratch data,
        // same trust boundary as everything else in this database, just
        // without a Double Ratchet/MLS layer on top (that layer exists to
        // protect messages *in transit* between two parties, and there is
        // no transit here).
        ConversationKind::SelfNotes => {
            tracing::trace!(%conversation_id, "storing self-note, no crypto session needed");
        }
        // Real X3DH/Double Ratchet encryption + mailbox push
        // (`message_crypto::send_encrypted_over_network`) — but only when
        // `bh-network` is actually attached (`state.network`); every
        // caller that never attaches one (including this crate's own
        // integration test suite) keeps today's local-storage-only
        // behavior, matching `network.rs`'s `GET /network/status`
        // reporting `enabled: false` rather than erroring in that case.
        ConversationKind::Direct => {
            if let Some(network) = &state.network {
                let contact_id = conversation
                    .contact_id
                    .as_deref()
                    .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
                let contact = state
                    .db()
                    .get_contact(contact_id)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                    .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
                // Wrapped in `Envelope::Text` (rather than sent as raw
                // body bytes) so the mailbox/receive loop can tell a chat
                // message apart from a `Envelope::Call` call-signal
                // sharing the same session/mailbox — see
                // `message_receive.rs`'s `deliver_decrypted` and
                // `calls.rs`'s module doc for why signaling deliberately
                // rides the same already-authenticated channel instead of
                // a separate one.
                // `reply_to_message_id` deliberately isn't forwarded here:
                // it's a locally-generated id on this side, meaningless on
                // the recipient's own `messages` table (whose FK would
                // just reject it) — quote-reply over the real network is
                // out of scope for this pass, same as reactions/receipts.
                let envelope_bytes = Envelope::Text {
                    body: req.body.clone(),
                    reply_to_message_id: None,
                }
                .encode()
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                crate::message_crypto::send_encrypted_over_network(
                    &state,
                    network,
                    &contact,
                    &message_id,
                    &envelope_bytes,
                )
                .await?;
            } else {
                tracing::trace!(%conversation_id, "storing message (no live network attached)");
            }
        }
        // Real MLS ciphertext fan-out over the network is a separate
        // follow-up from the Direct/X3DH wiring above — see
        // `message_crypto`'s module doc for why this pass scoped to
        // `Direct` only.
        ConversationKind::Group => {
            tracing::trace!(%conversation_id, "storing group message");
        }
    }

    let sent_at = now();
    let expires_at = state
        .db()
        .compute_message_expiry(&conversation_id, sent_at)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let message = Message {
        message_id,
        conversation_id,
        sender_contact_id,
        body: Some(req.body),
        sent_at,
        received_at: None,
        expires_at,
        deleted_at: None,
        reply_to_message_id: req.reply_to_message_id,
        edited_at: None,
    };
    // `insert_group_message` re-checks the broadcast-only restriction
    // itself (defense in depth on top of the `403` check above — see its
    // own doc comment) for every conversation, not just groups; the
    // check is a no-op for `Direct`/`SelfNotes` since those always have
    // `sender_contact_id: None` by this point.
    state
        .db()
        .insert_group_message(&message)
        .map_err(|e| match e {
            bh_storage::StorageError::Forbidden(_) => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        })?;

    Ok(Json(SendMessageResponse { message }))
}

/// Edits a message's body, storing over the same local-storage path
/// `send_message` uses today (the real per-message encryption-session call
/// lands here too, once `bh-network` is wired in) — never a silent
/// overwrite, since `Database::edit_message` archives the previous body
/// into `message_edits` first.
///
/// Only messages the local user sent themselves can be edited — a message
/// with `sender_contact_id: Some(_)` came from a contact, and editing
/// someone else's message makes no sense in an E2EE system where each
/// party only controls their own ratchet output.
#[derive(Deserialize)]
pub struct EditMessageRequest {
    pub body: String,
}

#[derive(Serialize)]
pub struct EditMessageResponse {
    pub message: Message,
}

pub async fn edit_message(
    State(state): State<Arc<AppState>>,
    Path((_conversation_id, message_id)): Path<(String, String)>,
    Json(req): Json<EditMessageRequest>,
) -> Result<Json<EditMessageResponse>, StatusCode> {
    let existing = state
        .db()
        .get_message(&message_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if existing.sender_contact_id.is_some() {
        return Err(StatusCode::FORBIDDEN);
    }
    if existing.deleted_at.is_some() {
        return Err(StatusCode::NOT_FOUND);
    }

    let edited_at = now();
    let message = state
        .db()
        .edit_message(&message_id, &req.body, edited_at)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(EditMessageResponse { message }))
}

#[derive(Serialize)]
pub struct MessageEditsResponse {
    pub edits: Vec<bh_storage::models::MessageEdit>,
}

/// Lists a message's prior versions, oldest first — the "view edit
/// history" affordance behind the client's "edited" label.
pub async fn list_message_edits(
    State(state): State<Arc<AppState>>,
    Path((_conversation_id, message_id)): Path<(String, String)>,
) -> Result<Json<MessageEditsResponse>, StatusCode> {
    state
        .db()
        .list_message_edits(&message_id)
        .map(|edits| Json(MessageEditsResponse { edits }))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
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
