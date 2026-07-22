//! Encrypted export/import of a conversation's history — portability
//! without depending on cloud backup infrastructure. Reuses
//! `bh_crypto::backup::seal`/`open` (Argon2id-derived key, ChaCha20-Poly1305)
//! exactly as the multi-device backup feature does (SPEC.md §4): the only
//! thing that changes here is *what* plaintext goes into that envelope —
//! one conversation's messages/reactions/receipts instead of a whole-account
//! backup blob.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bh_storage::models::{
    Conversation, ConversationKind, Message, MessageReceipt, PaymentRequest, Reaction,
};
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Serialize, Deserialize)]
struct ConversationBundle {
    conversation: Conversation,
    messages: Vec<Message>,
    reactions: Vec<Reaction>,
    receipts: Vec<MessageReceipt>,
    #[serde(default)]
    payment_requests: Vec<PaymentRequest>,
}

#[derive(Deserialize)]
pub struct ExportRequest {
    pub passphrase: String,
}

#[derive(Serialize)]
pub struct ExportResponse {
    /// Base64 of the sealed (encrypted) bundle — safe to write to a file
    /// or send over any transport, since it's unreadable without
    /// `passphrase`.
    pub sealed_base64: String,
}

pub async fn export_conversation(
    State(state): State<Arc<AppState>>,
    Path(conversation_id): Path<String>,
    Json(req): Json<ExportRequest>,
) -> Result<Json<ExportResponse>, StatusCode> {
    let conversation = state
        .db()
        .get_conversation(&conversation_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    if conversation.kind == ConversationKind::SelfNotes {
        // Every profile already has exactly one singleton self-conversation
        // (`ensure_self_conversation`), created locally rather than
        // recreated from an imported bundle the way `Direct`/`Group`
        // conversations are — see `import_conversation` below. An export
        // that can never be usefully re-imported isn't worth producing.
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    let messages = state
        .db()
        .list_messages(&conversation_id, i64::MAX)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut reactions = Vec::new();
    let mut receipts = Vec::new();
    let mut payment_requests = Vec::new();
    for message in &messages {
        reactions.extend(
            state
                .db()
                .list_reactions(&message.message_id)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        );
        receipts.extend(
            state
                .db()
                .list_receipts_for_message(&message.message_id)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        );
        if let Some(payment_request) = state
            .db()
            .get_payment_request(&message.message_id)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            payment_requests.push(payment_request);
        }
    }

    let bundle = ConversationBundle {
        conversation,
        messages,
        reactions,
        receipts,
        payment_requests,
    };
    let plaintext = serde_json::to_vec(&bundle).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let sealed = bh_crypto::backup::seal(&req.passphrase, &plaintext)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ExportResponse {
        sealed_base64: BASE64.encode(sealed),
    }))
}

#[derive(Deserialize)]
pub struct ImportRequest {
    pub passphrase: String,
    pub sealed_base64: String,
}

#[derive(Serialize)]
pub struct ImportResponse {
    pub conversation_id: String,
    pub messages_imported: usize,
}

/// Restores a bundle produced by [`export_conversation`]. Requires that any
/// contact/group the conversation references already exists locally (this
/// only recreates the conversation/messages/reactions/receipts, not
/// contacts or key material) — the intended use is moving history to a
/// device that's already linked/has the same contacts, not onboarding a
/// stranger's data cold.
pub async fn import_conversation(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ImportRequest>,
) -> Result<Json<ImportResponse>, StatusCode> {
    let sealed = BASE64
        .decode(&req.sealed_base64)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let plaintext =
        bh_crypto::backup::open(&req.passphrase, &sealed).map_err(|_| StatusCode::FORBIDDEN)?;
    let bundle: ConversationBundle =
        serde_json::from_slice(&plaintext).map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;

    match bundle.conversation.kind {
        ConversationKind::Direct => {
            let contact_id = bundle
                .conversation
                .contact_id
                .as_deref()
                .ok_or(StatusCode::UNPROCESSABLE_ENTITY)?;
            state
                .db()
                .create_direct_conversation(
                    &bundle.conversation.conversation_id,
                    contact_id,
                    bundle.conversation.created_at,
                )
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }
        ConversationKind::Group => {
            let group_id = bundle
                .conversation
                .group_id
                .as_deref()
                .ok_or(StatusCode::UNPROCESSABLE_ENTITY)?;
            state
                .db()
                .create_group_conversation(
                    &bundle.conversation.conversation_id,
                    group_id,
                    bundle.conversation.created_at,
                )
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }
        // `export_conversation` never produces a bundle with this kind —
        // see its rejection above — so a bundle claiming to be one is
        // malformed/hand-crafted input, not a real export.
        ConversationKind::SelfNotes => return Err(StatusCode::UNPROCESSABLE_ENTITY),
    }
    if let Some(timer) = bundle.conversation.disappearing_timer_secs {
        state
            .db()
            .set_disappearing_timer(&bundle.conversation.conversation_id, Some(timer))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    let messages_imported = bundle.messages.len();
    for message in &bundle.messages {
        state
            .db()
            .insert_message(message)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    for reaction in &bundle.reactions {
        state
            .db()
            .add_reaction(reaction)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    for receipt in &bundle.receipts {
        state
            .db()
            .upsert_receipt(receipt)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    for payment_request in &bundle.payment_requests {
        state
            .db()
            .insert_payment_request(payment_request)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    Ok(Json(ImportResponse {
        conversation_id: bundle.conversation.conversation_id,
        messages_imported,
    }))
}
