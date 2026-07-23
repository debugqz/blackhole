//! Keeps already-linked devices in sync (SPEC.md §4), complementing
//! `device_link.rs`'s account-identity handoff: once a device is linked,
//! new messages sent/received on the primary device should become
//! visible on it too.
//!
//! **Real cross-process push now exists**, gated on both a live
//! `state.network` and the target `Device` row having a real
//! `identity_agreement_key` on record (`schema.rs`'s `SCHEMA_V18` —
//! `None` for a device linked before that column existed, or one whose
//! agreement key hasn't been established yet): [`sync_device`] builds a
//! throwaway in-memory `Contact` from the `Device` row
//! (`device.public_key || device.identity_agreement_key` is the same
//! 64-byte layout `Contact.identity_public_key` already uses) and pushes
//! each pending `Direct`-conversation message to it via
//! `message_crypto::send_encrypted_over_network` — the *exact* same real
//! X3DH/Double-Ratchet-over-mailbox pipeline `conversations::send_message`
//! uses for `Direct` messages, just addressed to a device's identity
//! instead of a contact's, wrapped in a new `Envelope::DeviceSyncMessage`
//! variant. The receiving device needs no new receive-side plumbing at
//! all: `message_receive.rs`'s existing dispatch already polls this
//! identity's own mailbox and now has one more `Envelope` arm for it. This
//! pass only syncs `Direct` conversations (`Group`/`SelfNotes` sync over
//! the real network is a follow-up, matching `message_crypto.rs`'s own
//! staged-scope precedent), and assumes the receiving device already
//! knows the relevant contact (contact sync itself is a separate
//! follow-up, not attempted here).
//!
//! **Falls back to the pre-existing local simulation** whenever there's
//! no live network or the device has no agreement key on record: this
//! daemon plays both ends of a Double Ratchet session against a
//! locally-generated, throwaway "shadow" identity representing *that
//! device's* ratchet endpoint (same "throwaway identity keyed by the
//! peer's id" trick `groups.rs::ensure_shadow_member` uses for contacts,
//! not the peer's real key material) — a real, if locally simulated,
//! crypto round-trip (`ratchet_roundtrip_ok`), exactly like
//! `groups::mls_self_test` proves the MLS path works rather than
//! asserting it by fiat. The live ratchet `Session` pair for this shadow
//! path is not persisted — mirrors `groups.rs`'s in-memory-only MLS
//! state; `[DeviceSyncRegistry]` holds it only for the daemon's process
//! lifetime. What *does* survive a restart either way (schema v7,
//! `device_sync_cursor`) is the delivery cursor, so a restart never
//! re-delivers history.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use bh_crypto::envelope::Envelope;
use bh_crypto::identity::IdentityKeyPair;
use bh_crypto::ratchet::{self, PreKeyBundle, Session, SignedPreKey};
use bh_storage::models::{Contact, ConversationKind};
use serde::{Deserialize, Serialize};

use crate::AppState;

/// Live (in-memory-only, see module doc) Double Ratchet session state for
/// every linked device that has synced at least once this process
/// lifetime. Two maps, mirroring `groups.rs`'s `own_members`/
/// `shadow_members` split: `primary_sessions` is the primary device's
/// sending endpoint for a given target device, `device_sessions` is that
/// device's own receiving endpoint.
#[derive(Default)]
pub struct DeviceSyncRegistry {
    primary_sessions: Mutex<HashMap<String, Session>>,
    device_sessions: Mutex<HashMap<String, Session>>,
}

const LOCK_POISON_MSG: &str = "device sync registry lock poisoned";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

fn own_identity_keypair(state: &AppState) -> Result<IdentityKeyPair, StatusCode> {
    let own = state
        .db()
        .get_own_identity()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::PRECONDITION_FAILED)?;
    let bytes: [u8; 64] = own
        .identity_private_key
        .as_slice()
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    IdentityKeyPair::import_bytes(&bytes).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Ensures a live Double Ratchet session pair exists for `device_id`,
/// establishing one via a real X3DH handshake if this is the first sync
/// since the daemon started (or since this device was linked). See
/// module doc for why the "device" side of the handshake is a
/// locally-generated shadow identity rather than the device's real
/// signing key.
fn ensure_shadow_session(state: &AppState, device_id: &str) -> Result<(), StatusCode> {
    let registry = state.device_sync();
    {
        let primary_sessions = registry.primary_sessions.lock().expect(LOCK_POISON_MSG);
        if primary_sessions.contains_key(device_id) {
            return Ok(());
        }
    }

    let own_identity = own_identity_keypair(state)?;

    let device_identity =
        IdentityKeyPair::generate().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let device_spk = SignedPreKey::generate(&device_identity, 1);
    let bundle = PreKeyBundle {
        identity_agreement_key: device_identity.public_agreement_key(),
        identity_signing_key: device_identity.public_signing_key(),
        signed_prekey_id: device_spk.id,
        signed_prekey: device_spk.public,
        signed_prekey_signature: device_spk.signature,
        pq_prekey: device_spk.pq_prekey.public_key(),
        pq_prekey_signature: device_spk.pq_prekey_signature,
        one_time_prekey_id: None,
        one_time_prekey: None,
    };

    let (primary_secret, initial_message) = ratchet::x3dh_initiate(&own_identity, &bundle)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let device_secret =
        ratchet::x3dh_respond(&device_identity, &device_spk, None, &initial_message)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let associated_data = device_id.as_bytes().to_vec();
    let primary_session =
        Session::init_as_initiator(primary_secret, device_spk.public, associated_data.clone());
    let device_session =
        Session::init_as_responder(device_secret, device_spk.secret, associated_data);

    state
        .device_sync()
        .primary_sessions
        .lock()
        .expect(LOCK_POISON_MSG)
        .insert(device_id.to_string(), primary_session);
    state
        .device_sync()
        .device_sessions
        .lock()
        .expect(LOCK_POISON_MSG)
        .insert(device_id.to_string(), device_session);
    Ok(())
}

/// One message a linked device pulled in a `GET /devices/:id/sync` call.
#[derive(Serialize)]
pub struct SyncedMessage {
    pub message_id: String,
    pub conversation_id: String,
    pub sender_contact_id: Option<String>,
    pub body: Option<String>,
    pub sent_at: i64,
    /// Shadow (local-simulation) path: whether this message's plaintext
    /// really round-tripped through a Double Ratchet encrypt (primary
    /// side) / decrypt (device side) — see module doc. `false` would mean
    /// the shadow crypto path itself is broken, not that the message
    /// failed to sync (a broken round-trip still advances the cursor
    /// rather than the device getting stuck forever on one bad message).
    /// Real-network path: whether this message was actually pushed to the
    /// device's real mailbox (delivery/decryption is async from the
    /// caller's point of view there, so this can't report a decrypt
    /// result synchronously the way the shadow path does).
    pub ratchet_roundtrip_ok: bool,
}

#[derive(Serialize)]
pub struct DeviceSyncResponse {
    pub device_id: String,
    pub synced: Vec<SyncedMessage>,
    pub cursor_sent_at: i64,
    pub cursor_message_id: Option<String>,
}

#[derive(Deserialize)]
pub struct SyncQuery {
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    100
}

/// The real-network half of [`sync_device`] (see module doc): pushes each
/// pending `Direct`-conversation message to `device`'s real mailbox
/// instead of encrypting-and-immediately-decrypting in-process. Stops at
/// the first push failure (rather than skipping it and continuing) so the
/// cursor never advances past a message the device might not actually
/// have received.
async fn sync_device_over_network(
    state: &AppState,
    network: &bh_network::supervised::SupervisedNetwork,
    device: &bh_storage::models::Device,
    agreement_key: Vec<u8>,
    limit: i64,
) -> Result<Json<DeviceSyncResponse>, StatusCode> {
    let pseudo_contact = Contact {
        contact_id: device.device_id.clone(),
        identity_public_key: [device.public_key.clone(), agreement_key].concat(),
        display_name: device.name.as_deref().map(|n| format!("[device] {n}")),
        verified: false,
        blocked: false,
        added_at: 0,
    };
    // `message_crypto::send_encrypted_over_network` persists the session
    // it establishes via `sessions.contact_id`, which has a `NOT NULL
    // REFERENCES contacts(contact_id)` foreign key — reusing that
    // machinery for a device (rather than inventing a parallel per-device
    // session store, a real follow-up the module doc for `message_crypto`
    // already flags) means this pseudo-contact needs a real backing row.
    // Idempotent: only inserted if missing, never overwrites a real
    // contact that happens to share this id (impossible in practice —
    // `device.device_id` is this device's own hex signing key, a disjoint
    // namespace from any contact's).
    if state
        .db()
        .get_contact(&pseudo_contact.contact_id)
        .ok()
        .flatten()
        .is_none()
    {
        state
            .db()
            .upsert_contact(&pseudo_contact)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    let (cursor_sent_at, cursor_message_id) = state
        .db()
        .get_device_sync_cursor(&device.device_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .unwrap_or((0, None));

    let pending = state
        .db()
        .list_messages_since(cursor_sent_at, cursor_message_id.as_deref(), limit)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut synced = Vec::new();
    let mut new_cursor = (cursor_sent_at, cursor_message_id);
    for message in &pending {
        // Only `Direct` conversations sync over the real network this pass
        // — see module doc.
        let Ok(Some(conversation)) = state.db().get_conversation(&message.conversation_id) else {
            continue;
        };
        if conversation.kind != ConversationKind::Direct {
            continue;
        }
        let Some(peer_contact_id) = conversation.contact_id.clone() else {
            continue;
        };

        let envelope_bytes = Envelope::DeviceSyncMessage {
            message_id: message.message_id.clone(),
            peer_contact_id,
            sender_contact_id: message.sender_contact_id.clone(),
            body: message.body.clone(),
            sent_at: message.sent_at,
        }
        .encode()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let pushed = match crate::message_crypto::send_encrypted_over_network(
            state,
            network,
            &pseudo_contact,
            &message.message_id,
            &envelope_bytes,
        )
        .await
        {
            Ok(()) => true,
            Err(err) => {
                tracing::warn!(?err, "device sync: push to real mailbox failed");
                false
            }
        };

        synced.push(SyncedMessage {
            message_id: message.message_id.clone(),
            conversation_id: message.conversation_id.clone(),
            sender_contact_id: message.sender_contact_id.clone(),
            body: message.body.clone(),
            sent_at: message.sent_at,
            // Repurposed for the real path: whether this entry was
            // actually pushed to the device's real mailbox (delivery
            // itself is async from here, unlike the shadow path's
            // synchronous decrypt-and-verify) — see this field's own doc
            // comment.
            ratchet_roundtrip_ok: pushed,
        });
        if !pushed {
            break;
        }
        new_cursor = (message.sent_at, Some(message.message_id.clone()));
    }

    if let (sent_at, Some(message_id)) = &new_cursor {
        state
            .db()
            .advance_device_sync_cursor(&device.device_id, *sent_at, message_id, now())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    Ok(Json(DeviceSyncResponse {
        device_id: device.device_id.clone(),
        synced,
        cursor_sent_at: new_cursor.0,
        cursor_message_id: new_cursor.1,
    }))
}

/// Pulls every message sent since this device's last sync, encrypting
/// each with the primary device's shadow ratchet session and decrypting
/// it with the target device's own shadow session (a real, if locally
/// simulated, crypto round trip — see module doc), then advances the
/// device's persisted delivery cursor past the batch actually returned.
pub async fn sync_device(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<SyncQuery>,
) -> Result<Json<DeviceSyncResponse>, StatusCode> {
    let device = state
        .db()
        .get_device(&device_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    if device.owner != bh_storage::models::DeviceOwner::Own {
        return Err(StatusCode::NOT_FOUND);
    }
    if device.revoked_at.is_some() {
        return Err(StatusCode::GONE);
    }

    if let (Some(network), Some(agreement_key)) =
        (state.network.clone(), device.identity_agreement_key.clone())
    {
        return sync_device_over_network(&state, &network, &device, agreement_key, query.limit)
            .await;
    }

    ensure_shadow_session(&state, &device_id)?;

    let (cursor_sent_at, cursor_message_id) = state
        .db()
        .get_device_sync_cursor(&device_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .unwrap_or((0, None));

    let pending = state
        .db()
        .list_messages_since(cursor_sent_at, cursor_message_id.as_deref(), query.limit)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let registry = state.device_sync();
    let mut primary_sessions = registry.primary_sessions.lock().expect(LOCK_POISON_MSG);
    let mut device_sessions = registry.device_sessions.lock().expect(LOCK_POISON_MSG);
    let primary_session = primary_sessions
        .get_mut(&device_id)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let device_session = device_sessions
        .get_mut(&device_id)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut synced = Vec::with_capacity(pending.len());
    let mut new_cursor = (cursor_sent_at, cursor_message_id);
    for message in &pending {
        let plaintext = message.body.clone().unwrap_or_default();
        let roundtrip_ok = match primary_session.encrypt(plaintext.as_bytes()) {
            Ok(ciphertext) => device_session
                .decrypt(&ciphertext)
                .map(|decrypted| decrypted == plaintext.as_bytes())
                .unwrap_or(false),
            Err(_) => false,
        };

        synced.push(SyncedMessage {
            message_id: message.message_id.clone(),
            conversation_id: message.conversation_id.clone(),
            sender_contact_id: message.sender_contact_id.clone(),
            body: message.body.clone(),
            sent_at: message.sent_at,
            ratchet_roundtrip_ok: roundtrip_ok,
        });
        new_cursor = (message.sent_at, Some(message.message_id.clone()));
    }
    drop(primary_sessions);
    drop(device_sessions);

    if let (sent_at, Some(message_id)) = &new_cursor {
        state
            .db()
            .advance_device_sync_cursor(&device_id, *sent_at, message_id, now())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    Ok(Json(DeviceSyncResponse {
        device_id,
        synced,
        cursor_sent_at: new_cursor.0,
        cursor_message_id: new_cursor.1,
    }))
}

#[derive(Serialize)]
pub struct DeviceSyncStatusResponse {
    pub device_id: String,
    pub cursor_sent_at: i64,
    pub cursor_message_id: Option<String>,
    pub pending_count: i64,
}

/// A cheap, non-mutating peek at how far behind a device is — the
/// desktop client uses this for the "N pending" badge without consuming
/// (and thus advancing the cursor for) anything.
pub async fn sync_status(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
) -> Result<Json<DeviceSyncStatusResponse>, StatusCode> {
    let device = state
        .db()
        .get_device(&device_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    if device.owner != bh_storage::models::DeviceOwner::Own {
        return Err(StatusCode::NOT_FOUND);
    }

    let (cursor_sent_at, cursor_message_id) = state
        .db()
        .get_device_sync_cursor(&device_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .unwrap_or((0, None));

    // `i64::MAX` limit: this is a count-only peek, so cap generously
    // rather than truncate silently at the same page size `sync_device`
    // uses for an actual pull.
    let pending_count = state
        .db()
        .list_messages_since(cursor_sent_at, cursor_message_id.as_deref(), 1_000_000)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .len() as i64;

    Ok(Json(DeviceSyncStatusResponse {
        device_id,
        cursor_sent_at,
        cursor_message_id,
        pending_count,
    }))
}
