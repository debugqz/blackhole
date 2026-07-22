//! Sending stickers from a purchased sticker pack inside chat messages
//! (SPEC.md §12/§15). Ownership is enforced here, server-side, against the
//! *messaging* database's `cosmetic_inventory` table via
//! `bh_storage::Database::is_cosmetic_owned` (see
//! `crates/bh-storage/src/cosmetics.rs`) — never re-derived from the
//! payments database's `cosmetic_catalog`/`purchases` tables, and never
//! trusted from the client. See `crates/bh-api/src/cosmetics.rs` for the
//! sticker pack catalog/contents this validates `sticker_id` against, and
//! CLAUDE.md for the payments/messaging isolation rule this keeps: this
//! handler only ever calls `state.db()`, never `state.payments_db()`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use bh_storage::models::{CosmeticKind, Message, MessageSticker};
use serde::{Deserialize, Serialize};

use crate::cosmetics::pack_for_sticker;
use crate::AppState;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

#[derive(Deserialize)]
pub struct SendStickerRequest {
    pub sticker_id: String,
    pub reply_to_message_id: Option<String>,
}

#[derive(Serialize)]
pub struct SendStickerResponse {
    pub message: Message,
    pub sticker: MessageSticker,
}

/// Sends a sticker into a conversation, storing it locally as an outgoing
/// message exactly like `conversations::send_message` (actual network
/// transmission is still a separate follow-up — see CLAUDE.md's repo
/// layout notes). Rejects with:
/// - `400` if `sticker_id` isn't a real sticker inside any known pack
///   (`cosmetics::pack_for_sticker`), so a client can't smuggle an
///   arbitrary string through as if it were a sticker;
/// - `403` if this profile's `cosmetic_inventory` doesn't own the pack that
///   sticker belongs to — checked against the messaging database only,
///   the same accessor `cosmetics::equip` effectively uses for equipping.
pub async fn send_sticker(
    State(state): State<Arc<AppState>>,
    Path(conversation_id): Path<String>,
    Json(req): Json<SendStickerRequest>,
) -> Result<Json<SendStickerResponse>, StatusCode> {
    let pack_item_id = pack_for_sticker(&req.sticker_id).ok_or(StatusCode::BAD_REQUEST)?;

    let owned = state
        .db()
        .is_cosmetic_owned(CosmeticKind::StickerPack, pack_item_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !owned {
        return Err(StatusCode::FORBIDDEN);
    }

    let sent_at = now();
    let expires_at = state
        .db()
        .compute_message_expiry(&conversation_id, sent_at)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let message = Message {
        message_id: uuid::Uuid::new_v4().to_string(),
        conversation_id,
        sender_contact_id: None,
        body: None,
        sent_at,
        received_at: None,
        expires_at,
        deleted_at: None,
        reply_to_message_id: req.reply_to_message_id,
        edited_at: None,
    };
    state
        .db()
        .insert_message(&message)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let sticker = MessageSticker {
        message_id: message.message_id.clone(),
        pack_item_id: pack_item_id.to_string(),
        sticker_id: req.sticker_id,
    };
    state
        .db()
        .insert_message_sticker(&sticker)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(SendStickerResponse { message, sticker }))
}

pub async fn get_message_sticker(
    State(state): State<Arc<AppState>>,
    Path(message_id): Path<String>,
) -> Result<Json<MessageSticker>, StatusCode> {
    state
        .db()
        .get_message_sticker(&message_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)
        .map(Json)
}
