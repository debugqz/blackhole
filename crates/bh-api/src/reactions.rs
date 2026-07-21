use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use bh_storage::models::Reaction;
use serde::Deserialize;

use crate::AppState;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

#[derive(Deserialize)]
pub struct AddReactionRequest {
    pub emoji: String,
}

pub async fn add_reaction(
    State(state): State<Arc<AppState>>,
    Path(message_id): Path<String>,
    Json(req): Json<AddReactionRequest>,
) -> StatusCode {
    let reaction = Reaction {
        message_id,
        contact_id: None,
        emoji: req.emoji,
        reacted_at: now(),
    };
    match state.db().add_reaction(&reaction) {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

pub async fn remove_reaction(
    State(state): State<Arc<AppState>>,
    Path((message_id, emoji)): Path<(String, String)>,
) -> StatusCode {
    match state.db().remove_reaction(&message_id, None, &emoji) {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

pub async fn list_reactions(
    State(state): State<Arc<AppState>>,
    Path(message_id): Path<String>,
) -> Result<Json<Vec<Reaction>>, StatusCode> {
    state
        .db()
        .list_reactions(&message_id)
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
