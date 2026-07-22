use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use bh_storage::search::MessageSearchResult;
use serde::Deserialize;

use crate::AppState;

#[derive(Deserialize)]
pub struct SearchQuery {
    /// The search text. Required — an absent/blank `q` returns an empty
    /// result set rather than erroring (mirrors `Database::search_messages`
    /// treating a blank query as "no search").
    #[serde(default)]
    pub q: String,
    /// Optional conversation to scope the search to; omitted searches
    /// every conversation this profile has.
    pub conversation_id: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    50
}

/// `GET /search?q=...&conversation_id=...&limit=...` — full-text search
/// over this profile's own, already-decrypted local message history
/// (`bh_storage::search`). This is a pure local database query: the query
/// text and every result stay inside this daemon process and are never
/// sent to a relay or observable by the operator — see CLAUDE.md, this is
/// not "content scanning" in the forbidden sense, it's the user searching
/// their own mailbox after the daemon has already decrypted it locally.
pub async fn search_messages(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<Vec<MessageSearchResult>>, StatusCode> {
    state
        .db()
        .search_messages(&query.q, query.conversation_id.as_deref(), query.limit)
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
