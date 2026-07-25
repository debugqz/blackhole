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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use bh_crypto::envelope::{Envelope, SyncedContact};
use bh_crypto::identity::IdentityKeyPair;
use bh_crypto::ratchet::{self, PreKeyBundle, Session, SignedPreKey};
use bh_storage::models::Contact;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

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

    // Mirror the contact book before any message: a mirrored message
    // names its conversation by `contact_id`, and the receiving device
    // refuses one it has no contact row for (it cannot invent an identity
    // nobody verified). Sending contacts first is what keeps a device's
    // very first sync from bouncing every message it is sent.
    push_contact_sync(state, network, &pseudo_contact).await;

    let mut synced = Vec::new();
    let mut new_cursor = (cursor_sent_at, cursor_message_id);
    for message in &pending {
        // Every conversation kind mirrors now, not just `Direct`. Under
        // the hub model that costs nothing extra: this device already
        // decrypted the message with whatever real state it needed (a
        // ratchet session, or MLS for a group), and what travels here is
        // the resulting plaintext either way — a secondary is never an MLS
        // member. See the design doc's §4.
        let Ok(Some(conversation)) = state.db().get_conversation(&message.conversation_id) else {
            continue;
        };
        let Some(reference) = crate::device_delegation::conversation_ref(&conversation) else {
            // An ephemeral-identity conversation deliberately doesn't
            // speak for the account, so it has no cross-device name and
            // is not mirrored.
            continue;
        };

        let envelope_bytes = Envelope::DeviceSyncMessage {
            message_id: message.message_id.clone(),
            conversation: reference,
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

/// How many contacts travel in one `Envelope::ContactSync`. `Envelope::
/// encode` pads to size buckets up to 64 KiB and then grows in whole
/// blocks, and `bh-network::mailbox` caps a DHT record — so the contact
/// book is mirrored in batches rather than as one list that would waste
/// padding at best and be rejected at worst.
const CONTACT_SYNC_BATCH: usize = 32;

/// How often the primary sweeps its linked devices. Slow on purpose: this
/// is a catch-up mechanism for a device that was offline, not the delivery
/// path for a live conversation, and every push costs proof-of-work.
const DEVICE_SYNC_INTERVAL: Duration = Duration::from_secs(30);

/// How many messages one automatic sweep pushes per device, so a long
/// backlog drains over several ticks instead of in one burst.
const AUTOMATIC_SYNC_LIMIT: i64 = 32;

/// Mirrors this profile's contact book to one linked device.
///
/// Only public identity material travels (see `bh_crypto::envelope::
/// SyncedContact`): no ratchet session, no prekey, nothing a secondary
/// could encrypt to a contact with, because it never needs to — it
/// delegates. `verified` is mirrored rather than recomputed because
/// safety-number verification is a human act performed against the
/// account's identity, so it belongs to the account rather than to
/// whichever device happened to perform it.
///
/// Pseudo-contacts are skipped: the rows this account keeps for its own
/// devices and its primary are local plumbing (`device_role::
/// ensure_pseudo_contact`), and mirroring them would show a user their own
/// devices as if they were people.
async fn push_contact_sync(
    state: &AppState,
    network: &bh_network::supervised::SupervisedNetwork,
    device_contact: &Contact,
) {
    let Ok(contacts) = state.db().list_contacts() else {
        return;
    };
    let own_device_keys: Vec<Vec<u8>> = state
        .db()
        .list_own_devices()
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.public_key)
        .collect();
    let real: Vec<SyncedContact> = contacts
        .into_iter()
        .filter(|c| {
            c.identity_public_key.len() >= 32
                && !own_device_keys
                    .iter()
                    .any(|k| k.as_slice() == &c.identity_public_key[..32])
        })
        .map(|c| SyncedContact {
            contact_id: c.contact_id,
            identity_public_key: c.identity_public_key,
            display_name: c.display_name,
            verified: c.verified,
            blocked: c.blocked,
            added_at: c.added_at,
        })
        .collect();

    for (index, batch) in real.chunks(CONTACT_SYNC_BATCH).enumerate() {
        let Ok(bytes) = (Envelope::ContactSync {
            contacts: batch.to_vec(),
        })
        .encode() else {
            continue;
        };
        // A stable id per (device, batch) rather than a fresh uuid: a
        // re-sent batch overwrites its own previous mailbox entry instead
        // of piling a new copy of the contact book into the manifest on
        // every sweep.
        let entry_id = format!("contact-sync-{}-{index}", device_contact.contact_id);
        if let Err(err) = crate::message_crypto::send_encrypted_over_network(
            state,
            network,
            device_contact,
            &entry_id,
            &bytes,
        )
        .await
        {
            tracing::warn!(?err, "device sync: contact mirror push failed");
            return;
        }
    }
}

/// The secondary side: writes mirrored contacts into this device's own
/// book.
///
/// Ids are preserved verbatim, which is not incidental — it is what makes
/// `ConversationRef::Direct` mean the same thing on both devices (see that
/// type's doc comment). Never deletes: a contact missing from a batch may
/// simply be in another batch, and this device losing contacts because a
/// sync was truncated would be worse than briefly keeping a stale one.
pub(crate) fn apply_contact_sync(state: &AppState, contacts: Vec<SyncedContact>) {
    for synced in contacts {
        let contact = Contact {
            contact_id: synced.contact_id,
            identity_public_key: synced.identity_public_key,
            display_name: synced.display_name,
            verified: synced.verified,
            blocked: synced.blocked,
            added_at: synced.added_at,
        };
        if let Err(err) = state.db().upsert_contact(&contact) {
            tracing::warn!(%err, "device sync: failed to apply a mirrored contact");
        }
    }
}

/// Runs device sync on a cadence instead of waiting for someone to press
/// "Sync now".
///
/// A secondary that only receives what the user manually pushed to it is a
/// viewer, not a device — this is what makes the pair behave like one
/// account. Spawned once against the whole `AppState` and re-reads the
/// active profile every tick, the same shape `message_receive::
/// spawn_receive_loop` uses (and for the same reason: it never holds a
/// per-profile handle across a tick, so a profile switch needs no restart).
pub fn spawn_device_sync_loop(state: Arc<AppState>, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            device_sync_tick(&state).await;
        }
    })
}

/// The default-cadence spawn, for `daemon/src/main.rs`.
pub fn spawn_default_device_sync_loop(state: Arc<AppState>) -> JoinHandle<()> {
    spawn_device_sync_loop(state, DEVICE_SYNC_INTERVAL)
}

async fn device_sync_tick(state: &AppState) {
    let Some(network) = state.network.as_ref() else {
        return;
    };

    // A secondary has nothing to push — it has no devices of its own —
    // but it does have delegated sends that may still be waiting on a
    // primary that was offline. Draining them here means "the primary came
    // back" is enough, with no user action.
    if let Some(linked) = crate::device_role::active_linked_account(state) {
        crate::device_delegation::retry_pending_delegations(state, &linked).await;
        return;
    }

    let Ok(devices) = state.db().list_own_devices() else {
        return;
    };
    for device in devices {
        if device.revoked_at.is_some() {
            continue;
        }
        let Some(agreement_key) = device.identity_agreement_key.clone() else {
            // Linked before per-device agreement keys existed, so it
            // cannot be addressed on the network at all — see this
            // module's doc comment.
            continue;
        };
        if let Err(err) =
            sync_device_over_network(state, network, &device, agreement_key, AUTOMATIC_SYNC_LIMIT)
                .await
        {
            tracing::debug!(?err, device_id = %device.device_id, "automatic device sync failed");
        }
    }
}
