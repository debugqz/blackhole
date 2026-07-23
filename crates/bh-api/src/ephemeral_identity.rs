//! Ephemeral identities: a throwaway `IdentityKeyPair`, generated on
//! demand and good for a caller-chosen number of days, meant to be handed
//! out via an invite (`invites::create_invite`'s optional
//! `ephemeral_identity_id`) instead of the profile's real identity for a
//! one-off interaction with a stranger — without exposing the real
//! identity's public keys, and with automatic, total cleanup once it
//! expires (`bh_storage::ephemeral_identity::spawn_ephemeral_identity_sweeper`,
//! wired in `state.rs`).
//!
//! **Deliberate v1 scoping, documented rather than hidden** (same spirit
//! as `groups.rs`/`device_sync.rs`'s "shadow member"/"shadow identity"
//! simplifications, and `message_crypto.rs`'s own list of accepted v1
//! trades): the message pipeline (`message_crypto.rs`/`message_receive.rs`)
//! assumes exactly one identity per profile — it publishes/polls a single
//! prekey bundle and mailbox, both keyed off `own_identity`. Widening that
//! to poll N identities' mailboxes and publish N prekey bundles is a much
//! larger, separate follow-up, so this pass does **not** publish a prekey
//! bundle for an ephemeral identity or attempt real cross-daemon delivery
//! under one. To keep the identity genuinely demoable/testable (compose
//! messages, have something real to wipe) without a live remote stranger,
//! creating one also creates a locally-generated shadow contact + Direct
//! conversation standing in for "whoever redeems the invite" — a plain
//! `Contact`/`Conversation` row pair, not MLS machinery. That conversation
//! always stays local-storage-only (`conversations::send_message`'s
//! `Direct` arm skips the real-network branch whenever
//! `Conversation::ephemeral_identity_id` is set), regardless of whether
//! `bh-network` is attached — sending under the profile's real identity
//! over the real network for a conversation that's supposed to be a
//! different identity entirely would be actively wrong, not just
//! incomplete.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use bh_crypto::identity::IdentityKeyPair;
use bh_storage::models::Contact;
use serde::{Deserialize, Serialize};

use crate::AppState;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

#[derive(Deserialize)]
pub struct CreateEphemeralIdentityRequest {
    pub label: Option<String>,
    pub ttl_days: i64,
}

#[derive(Serialize)]
pub struct EphemeralIdentityView {
    pub id: String,
    pub label: Option<String>,
    pub public_signing_key: String,
    pub public_agreement_key: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub conversation_id: String,
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateEphemeralIdentityRequest>,
) -> Result<Json<EphemeralIdentityView>, StatusCode> {
    if req.ttl_days < 1 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let identity = IdentityKeyPair::generate().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // The "whoever redeems this" stand-in (see module doc) — its private
    // key is intentionally never persisted, only its public bytes go into
    // the shadow `Contact` row below.
    let shadow = IdentityKeyPair::generate().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let id = uuid::Uuid::new_v4().to_string();
    let shadow_contact_id = uuid::Uuid::new_v4().to_string();
    let conversation_id = uuid::Uuid::new_v4().to_string();
    let created_at = now();
    let expires_at = created_at + req.ttl_days * 86_400;

    let display_name = Some(
        req.label
            .as_deref()
            .map(|label| format!("Invite: {label}"))
            .unwrap_or_else(|| "Ephemeral contact".to_string()),
    );
    state
        .db()
        .upsert_contact(&Contact {
            contact_id: shadow_contact_id.clone(),
            identity_public_key: shadow.public_identity_bytes().to_vec(),
            display_name,
            verified: false,
            blocked: false,
            added_at: created_at,
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Must precede `create_ephemeral_identity_conversation` below: that
    // insert's `ephemeral_identity_id` column is a real `REFERENCES
    // ephemeral_identity(id)` foreign key (`ON DELETE CASCADE`), enforced
    // immediately (`PRAGMA foreign_keys = ON`, always set — see `db.rs`),
    // so the referenced row has to exist first.
    state
        .db()
        .create_ephemeral_identity(&bh_storage::models::EphemeralIdentity {
            id: id.clone(),
            label: req.label.clone(),
            identity_public_key: identity.public_identity_bytes().to_vec(),
            identity_private_key: identity.export_bytes().to_vec(),
            shadow_contact_id: Some(shadow_contact_id.clone()),
            conversation_id: conversation_id.clone(),
            created_at,
            expires_at,
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .db()
        .create_ephemeral_identity_conversation(
            &id,
            &conversation_id,
            &shadow_contact_id,
            created_at,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(EphemeralIdentityView {
        id,
        label: req.label,
        public_signing_key: hex::encode(identity.public_signing_key().to_bytes()),
        public_agreement_key: hex::encode(identity.public_agreement_key().to_bytes()),
        created_at,
        expires_at,
        conversation_id,
    }))
}

pub async fn list(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<EphemeralIdentityView>>, StatusCode> {
    let identities = state
        .db()
        .list_ephemeral_identities()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let views = identities
        .into_iter()
        .filter_map(|row| {
            let bytes: [u8; 64] = row.identity_public_key.as_slice().try_into().ok()?;
            Some(EphemeralIdentityView {
                id: row.id,
                label: row.label,
                public_signing_key: hex::encode(&bytes[..32]),
                public_agreement_key: hex::encode(&bytes[32..]),
                created_at: row.created_at,
                expires_at: row.expires_at,
                conversation_id: row.conversation_id,
            })
        })
        .collect();
    Ok(Json(views))
}

pub async fn revoke(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> StatusCode {
    match state.db().wipe_ephemeral_identity(&id) {
        Ok(true) => StatusCode::OK,
        Ok(false) => StatusCode::NOT_FOUND,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
