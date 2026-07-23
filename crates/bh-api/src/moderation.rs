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
    match state.db().set_contact_blocked(&contact_id, false) {
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
        .db()
        .list_pending_message_requests()
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn accept_message_request(
    State(state): State<Arc<AppState>>,
    Path(contact_id): Path<String>,
) -> StatusCode {
    match state
        .db()
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
        .db()
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
        .db()
        .get_messages_by_ids(&req.message_ids)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ReportBundle {
        contact_id: req.contact_id,
        reason: req.reason,
        created_at: now(),
        messages,
    }))
}

// ---------------- shareable blocklists ----------------
//
// A blocklist export is a courtesy, not a moderation system: it's a
// copyable text blob (mirrors `bh_crypto::invite::InvitePayload::
// to_link`'s convention — plain base64 JSON, no passphrase/encryption,
// since none of this is secret content) that a friend can paste into
// their own client. Decoding only ever *previews* which entries match the
// importer's own existing contacts; applying only ever blocks contacts the
// importer already has and explicitly selected — nothing here creates a
// new contact or blocks anyone automatically. Keeps CLAUDE.md's "no
// content moderation, ever" intact: every real effect is a same-user,
// explicit, local `set_contact_blocked` call, identical to the one behind
// the existing `POST /contacts/:id/block` button.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

const BLOCKLIST_SCHEME_PREFIX: &str = "blackhole://blocklist?d=";
const BLOCKLIST_VERSION: u8 = 1;

#[derive(Serialize, Deserialize)]
struct BlocklistEntry {
    /// Hex-encoded `Contact.identity_public_key` — the only thing that's
    /// portable across two different daemons' contact books.
    /// `Contact.contact_id` is just a convention (the client happens to
    /// set it to the hex signing key when accepting an invite), not an
    /// enforced invariant, so it's not used for matching.
    identity_public_key: String,
    /// The exporter's own local nickname for this contact — informational
    /// only, shown to the importer as a hint, never used to decide a
    /// match.
    label: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct BlocklistPayload {
    version: u8,
    entries: Vec<BlocklistEntry>,
}

#[derive(Serialize)]
pub struct ExportBlocklistResponse {
    pub link: String,
    pub count: i64,
}

pub async fn export_blocklist(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ExportBlocklistResponse>, StatusCode> {
    let contacts = state
        .db()
        .list_contacts()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let entries: Vec<BlocklistEntry> = contacts
        .into_iter()
        .filter(|c| c.blocked)
        .map(|c| BlocklistEntry {
            identity_public_key: hex::encode(&c.identity_public_key),
            label: c.display_name,
        })
        .collect();
    let count = entries.len() as i64;
    let payload = BlocklistPayload {
        version: BLOCKLIST_VERSION,
        entries,
    };
    let json = serde_json::to_vec(&payload).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let link = format!("{BLOCKLIST_SCHEME_PREFIX}{}", URL_SAFE_NO_PAD.encode(json));
    Ok(Json(ExportBlocklistResponse { link, count }))
}

#[derive(Deserialize)]
pub struct DecodeBlocklistRequest {
    pub link: String,
}

#[derive(Serialize)]
pub struct DecodedBlocklistEntry {
    pub identity_public_key: String,
    pub label: Option<String>,
    pub matched_contact_id: Option<String>,
    pub matched_display_name: Option<String>,
    pub already_blocked: bool,
}

fn decode_blocklist_payload(link: &str) -> Result<BlocklistPayload, StatusCode> {
    let encoded = link
        .strip_prefix(BLOCKLIST_SCHEME_PREFIX)
        .ok_or(StatusCode::BAD_REQUEST)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let payload: BlocklistPayload =
        serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    if payload.version != BLOCKLIST_VERSION {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(payload)
}

/// Storage-free preview (mirrors `invites::decode_invite`) — parses the
/// blob and reports which entries match this profile's own contacts, but
/// blocks nothing. A separate, explicit call to [`apply_blocklist`] is the
/// only thing that ever changes state.
pub async fn decode_blocklist(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DecodeBlocklistRequest>,
) -> Result<Json<Vec<DecodedBlocklistEntry>>, StatusCode> {
    let payload = decode_blocklist_payload(&req.link)?;
    let contacts = state
        .db()
        .list_contacts()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let decoded = payload
        .entries
        .into_iter()
        .map(|entry| {
            let matched = hex::decode(&entry.identity_public_key)
                .ok()
                .and_then(|key_bytes| contacts.iter().find(|c| c.identity_public_key == key_bytes));
            DecodedBlocklistEntry {
                identity_public_key: entry.identity_public_key,
                label: entry.label,
                matched_contact_id: matched.map(|c| c.contact_id.clone()),
                matched_display_name: matched.and_then(|c| c.display_name.clone()),
                already_blocked: matched.is_some_and(|c| c.blocked),
            }
        })
        .collect();
    Ok(Json(decoded))
}

#[derive(Deserialize)]
pub struct ApplyBlocklistRequest {
    /// The importer's own explicit selection — never "every match," since
    /// the decision has to stay theirs, not the exporter's.
    pub contact_ids: Vec<String>,
}

#[derive(Serialize)]
pub struct ApplyBlocklistResponse {
    pub blocked_count: i64,
}

pub async fn apply_blocklist(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ApplyBlocklistRequest>,
) -> Result<Json<ApplyBlocklistResponse>, StatusCode> {
    let mut blocked_count = 0i64;
    for contact_id in &req.contact_ids {
        // Only ever acts on a contact that genuinely already exists — never
        // creates one, defense in depth against a hand-crafted request
        // naming an id the earlier `decode` step never actually matched.
        let exists = state
            .db()
            .get_contact(contact_id)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .is_some();
        if !exists {
            continue;
        }
        state
            .db()
            .set_contact_blocked(contact_id, true)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        blocked_count += 1;
    }
    Ok(Json(ApplyBlocklistResponse { blocked_count }))
}
