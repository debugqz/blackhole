//! Real X3DH + Double Ratchet wiring for `conversations.rs::send_message`
//! and the mailbox-pull receive loop (`message_receive.rs`) — the seam
//! CLAUDE.md's `daemon/` entry and `conversations.rs`'s own doc comments
//! have long pointed at ("lands here once `bh-network` is wired into
//! send/receive"). Only exercised when `AppState::network` is actually
//! attached; every caller falls back to today's local-storage-only
//! behavior when it's `None` (no live daemon network, or an integration
//! test that never attaches one — see `state.rs`'s doc on that field).
//!
//! **Deliberate v1 scoping, documented rather than hidden** (same spirit
//! as `groups.rs`/`device_sync.rs`'s "shadow member" simplifications):
//! - One session per contact, not per-device (`sessions.session_id ==
//!   contact_id`, `device_id` always `"primary"`) — multi-device fan-out
//!   for a *contact's* other devices isn't modeled yet, only for one's own
//!   linked devices (`device_link.rs`/`device_sync.rs`, which is a
//!   different, already-real feature).
//! - One long-term signed prekey that never rotates, no one-time
//!   prekeys — see `bh-storage::schema`'s `SCHEMA_V15` doc comment for why
//!   this is an accepted trade rather than a bug.
//! - Only `Direct` conversations get real network wiring here. `Group`
//!   still stores locally-only (see `conversations.rs`) — real MLS
//!   ciphertext fan-out via `Mailbox::fan_out` is a separate follow-up,
//!   not attempted in this pass.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use bh_crypto::identity::{recipient_key_hash, IdentityKeyPair};
use bh_crypto::pq_hybrid::HybridSecretKey;
use bh_crypto::ratchet::{
    self, session_associated_data, InitialMessage, PreKeyBundle, RatchetMessage, Session,
    SignedPreKey,
};
use bh_network::mailbox::Mailbox;
use bh_network::supervised::SupervisedNetwork;
use bh_network::{prekey_directory, sealed_sender};
use bh_storage::models::{Contact, OwnPrekey, Session as StoredSession};
use ed25519_dalek::Signature;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

use crate::AppState;

/// How long a pushed mailbox entry survives before the network expires it
/// — independent of (and shorter than) `Mailbox::push`'s hard cap, chosen
/// generously enough that a recipient offline for a few days still gets
/// it, without pretending to be permanent storage.
const MAILBOX_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

/// This identity's one non-rotating signed prekey id (see module doc).
const OWN_SIGNED_PREKEY_ID: u32 = 1;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

/// Loads this profile's real identity keypair — same pattern as
/// `device_sync.rs::own_identity_keypair`, duplicated rather than shared
/// across modules per this codebase's existing convention (see e.g. every
/// file's own private `now()`).
pub(crate) fn own_identity_keypair(state: &AppState) -> Result<IdentityKeyPair, StatusCode> {
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

/// The envelope actually pushed to the mailbox (after sealed-sender
/// wrapping): a Double Ratchet ciphertext, plus — only on the very first
/// message to a contact with no existing session — the X3DH handshake
/// message the recipient needs to derive the same shared secret before
/// they can decrypt anything.
pub(crate) struct OutgoingEnvelope {
    pub initial_message: Option<InitialMessage>,
    pub ratchet_message: RatchetMessage,
}

impl OutgoingEnvelope {
    pub fn to_bytes(&self) -> Vec<u8> {
        let ratchet_bytes = self.ratchet_message.to_bytes();
        let mut out = Vec::with_capacity(1 + ratchet_bytes.len() + 64);
        match &self.initial_message {
            Some(im) => {
                let im_bytes = im.to_bytes();
                out.push(1);
                out.extend_from_slice(&(im_bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(&im_bytes);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&ratchet_bytes);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let has_initial = *bytes.first()?;
        let mut offset = 1;
        let initial_message = match has_initial {
            0 => None,
            1 => {
                let len_bytes: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
                let len = u32::from_be_bytes(len_bytes) as usize;
                offset += 4;
                let im = InitialMessage::from_bytes(bytes.get(offset..offset + len)?).ok()?;
                offset += len;
                Some(im)
            }
            _ => return None,
        };
        let ratchet_message = RatchetMessage::from_bytes(bytes.get(offset..)?).ok()?;
        Some(Self {
            initial_message,
            ratchet_message,
        })
    }
}

/// Loads this identity's long-term signed prekey, generating (and
/// persisting) one on first use if it doesn't exist yet — see module doc
/// for the "one, non-rotating" v1 scoping.
pub(crate) fn ensure_own_signed_prekey(
    state: &AppState,
    identity: &IdentityKeyPair,
) -> Result<SignedPreKey, StatusCode> {
    if let Some(row) = state
        .db()
        .get_own_prekey()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        let secret_bytes: [u8; 32] = row
            .signed_prekey_secret
            .as_slice()
            .try_into()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let secret = X25519Secret::from(secret_bytes);
        let public = X25519PublicKey::from(&secret);
        let signature_bytes: [u8; 64] = row
            .signed_prekey_signature
            .as_slice()
            .try_into()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let signature = Signature::from_bytes(&signature_bytes);
        let pq_seed: [u8; 96] = row
            .pq_prekey_seed
            .as_slice()
            .try_into()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let pq_prekey = HybridSecretKey::from_seed_bytes(&pq_seed);
        let pq_sig_bytes: [u8; 64] = row
            .pq_prekey_signature
            .as_slice()
            .try_into()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let pq_prekey_signature = Signature::from_bytes(&pq_sig_bytes);
        return Ok(SignedPreKey {
            id: row.signed_prekey_id as u32,
            secret,
            public,
            signature,
            pq_prekey,
            pq_prekey_signature,
        });
    }

    let secret = X25519Secret::random();
    let public = X25519PublicKey::from(&secret);
    let signature = identity.sign(public.as_bytes());
    let (pq_seed, pq_prekey) = HybridSecretKey::generate_with_seed();
    let pq_prekey_signature = identity.sign(&pq_prekey.public_key().to_bytes());

    state
        .db()
        .set_own_prekey(&OwnPrekey {
            signed_prekey_id: OWN_SIGNED_PREKEY_ID as i64,
            signed_prekey_secret: secret.to_bytes().to_vec(),
            signed_prekey_signature: signature.to_bytes().to_vec(),
            pq_prekey_seed: pq_seed.to_vec(),
            pq_prekey_signature: pq_prekey_signature.to_bytes().to_vec(),
            created_at: now(),
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(SignedPreKey {
        id: OWN_SIGNED_PREKEY_ID,
        secret,
        public,
        signature,
        pq_prekey,
        pq_prekey_signature,
    })
}

fn own_prekey_bundle(identity: &IdentityKeyPair, signed_prekey: &SignedPreKey) -> PreKeyBundle {
    PreKeyBundle {
        identity_agreement_key: identity.public_agreement_key(),
        identity_signing_key: identity.public_signing_key(),
        signed_prekey_id: signed_prekey.id,
        signed_prekey: signed_prekey.public,
        signed_prekey_signature: signed_prekey.signature,
        pq_prekey: signed_prekey.pq_prekey.public_key(),
        pq_prekey_signature: signed_prekey.pq_prekey_signature,
        one_time_prekey_id: None,
        one_time_prekey: None,
    }
}

/// Best-effort: publishes this identity's own bundle so a contact can
/// reach us first. Failures are logged, not propagated — a transient DHT
/// hiccup here shouldn't fail whatever the caller (a send, or the receive
/// loop's periodic tick) was actually doing.
pub(crate) async fn publish_own_bundle_best_effort(
    network: &SupervisedNetwork,
    identity: &IdentityKeyPair,
    signed_prekey: &SignedPreKey,
) {
    let bundle = own_prekey_bundle(identity, signed_prekey);
    let key_hash = recipient_key_hash(&identity.public_identity_bytes());
    if let Err(err) =
        prekey_directory::publish_own_bundle(&network.dht(), &key_hash, bundle.to_bytes()).await
    {
        tracing::warn!(%err, "failed to publish own prekey bundle (will retry on next tick/send)");
    }
}

fn contact_agreement_key(contact: &Contact) -> Result<X25519PublicKey, StatusCode> {
    let bytes: [u8; 32] = contact
        .identity_public_key
        .get(32..64)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(X25519PublicKey::from(bytes))
}

/// Loads the persisted session with `contact`, or establishes a fresh one
/// via a real X3DH handshake against their published `PreKeyBundle` if
/// none exists yet. Returns the live `Session` plus, only when a session
/// was just established, the `InitialMessage` the recipient needs.
///
/// Deliberately does **not** persist a freshly-established session —
/// that only happens in [`send_encrypted_over_network`] once the mailbox
/// push actually succeeds. Persisting it here instead would let a
/// session get established (and reused as "no `InitialMessage` needed"
/// on the very next call) even though the recipient never actually
/// received that handshake, if the push after establishment failed —
/// stranding the recipient with no way to ever derive the shared secret.
/// Establish-and-send must be atomic; a retry after a failed send must
/// redo the whole handshake, not skip straight to "session already
/// exists."
async fn load_or_establish_session(
    state: &AppState,
    identity: &IdentityKeyPair,
    contact: &Contact,
    network: &SupervisedNetwork,
) -> Result<(Session, Option<InitialMessage>), StatusCode> {
    if let Some(row) = state
        .db()
        .get_session(&contact.contact_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        let session = Session::from_bytes(&row.ratchet_state)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        return Ok((session, None));
    }

    let their_key_hash = recipient_key_hash(&contact.identity_public_key);
    let bundle_bytes = prekey_directory::fetch_bundle(&network.dht(), &their_key_hash)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let bundle = PreKeyBundle::from_bytes(&bundle_bytes).map_err(|_| StatusCode::BAD_GATEWAY)?;

    let (shared_secret, initial_message) =
        ratchet::x3dh_initiate(identity, &bundle).map_err(|_| StatusCode::BAD_GATEWAY)?;
    let associated_data = session_associated_data(
        &identity.public_identity_bytes(),
        &contact.identity_public_key,
    );
    let session = Session::init_as_initiator(shared_secret, bundle.signed_prekey, associated_data);

    Ok((session, Some(initial_message)))
}

/// Encrypts `plaintext` for `contact` (establishing a session first if
/// needed) and pushes it to their mailbox. On success, this identity's own
/// bundle is also (best-effort) republished, so an eventual first reply
/// finds it fresh. Called from `conversations.rs::send_message`'s
/// `Direct` arm; see module doc for exactly what's scoped in v1.
pub(crate) async fn send_encrypted_over_network(
    state: &AppState,
    network: &SupervisedNetwork,
    contact: &Contact,
    message_id: &str,
    plaintext: &[u8],
) -> Result<(), StatusCode> {
    let identity = own_identity_keypair(state)?;
    let signed_prekey = ensure_own_signed_prekey(state, &identity)?;

    let (mut session, initial_message) =
        load_or_establish_session(state, &identity, contact, network).await?;
    let ratchet_message = session
        .encrypt(plaintext)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let envelope = OutgoingEnvelope {
        initial_message,
        ratchet_message,
    };
    let recipient_agreement_key = contact_agreement_key(contact)?;
    let sent_at = now();
    let sealed = sealed_sender::seal(
        &identity,
        &recipient_agreement_key,
        envelope.to_bytes(),
        sent_at,
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Compact binary framing, not `serde_json` — see `SealedSenderEnvelope::
    // to_bytes`'s doc comment for why JSON-encoding a `Vec<u8>` this size
    // (an X3DH `InitialMessage` on a first contact) is a real, not just
    // theoretical, problem for a single DHT record's size/round-trip time.
    let ciphertext = sealed.to_bytes();

    let their_key_hash = recipient_key_hash(&contact.identity_public_key);
    let pow = Mailbox::solve_pow(&their_key_hash, message_id.as_bytes(), &ciphertext, sent_at);
    network
        .mailbox()
        .push(
            &their_key_hash,
            message_id.as_bytes(),
            ciphertext,
            MAILBOX_TTL_SECONDS,
            sent_at,
            &pow,
        )
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    // Only persisted now that delivery actually succeeded — see
    // `load_or_establish_session`'s doc comment for why persisting any
    // earlier would risk stranding the recipient.
    state
        .db()
        .upsert_session(&StoredSession {
            session_id: contact.contact_id.clone(),
            contact_id: contact.contact_id.clone(),
            device_id: "primary".to_string(),
            ratchet_state: session.to_bytes(),
            updated_at: now(),
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    publish_own_bundle_best_effort(network, &identity, &signed_prekey).await;
    Ok(())
}
