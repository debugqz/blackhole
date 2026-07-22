//! Opt-in "typing…" presence indicator.
//!
//! Design constraints (see CLAUDE.md non-negotiables and
//! `docs/THREAT_MODEL.md`'s metadata-minimization posture before touching
//! this file):
//!
//! - **Off by default.** Gated by a single global toggle in
//!   `bh_storage::settings` (`typing_indicators_enabled`, default OFF — see
//!   that module). `send_typing_ping` below checks it first and does
//!   nothing at all — no encryption, no state update — when it's off.
//! - **Ephemeral, never durable.** The typing signal itself never touches
//!   `messages` or any other table: it lives only in the in-memory
//!   [`PresenceRegistry`], profile-scoped like `groups`/`device_sync` (see
//!   `state.rs`'s `ProfileSession`) since conversation ids are per-profile
//!   and nothing here should survive a profile switch. It expires on its
//!   own after [`TYPING_TTL_SECS`] and is gone entirely on daemon restart.
//!   The one thing that *is* persisted is the on/off preference, which is
//!   exactly as sensitive as any other local UI setting.
//! - **Exactly as sealed as a real message.** The wire payload is
//!   `bh_crypto::envelope::Envelope::Typing`, encoded and run through the
//!   real X3DH + Double Ratchet code in `bh_crypto::ratchet` — the same
//!   envelope/ratchet machinery `Envelope::Text` would use for a real
//!   message. A mailbox/relay/operator sees indistinguishable ciphertext
//!   whether the sender is typing or sending real content.
//!
//! **Network-wiring gap.** Like every other still-local feature documented
//! in CLAUDE.md's `bh-api` entry (receipts, reactions, disappearing-timer
//! change notices — see `receipts.rs`'s module doc for the pattern this
//! follows), the encrypted envelope produced here has nowhere to go yet:
//! `bh-network` isn't wired into `bh-api`, so `conversations::send_message`
//! doesn't encrypt outgoing messages at all today. That leaves this module
//! with no live peer to X3DH against, and — unlike a real contact — this
//! daemon never holds the other side's private identity key material in
//! the first place. To still exercise the *real* Double Ratchet code
//! end-to-end today rather than fake the encryption, [`establish_shadow_session`]
//! generates a local stand-in identity/prekey for the contact's side of the
//! handshake purely so `encrypt`/`decrypt` run through genuine
//! Signal-Protocol code (same "shadow" trick `groups.rs`/`device_sync.rs`
//! use elsewhere in this crate). When `bh-network` delivery lands, this
//! shadow handshake must be replaced by a real X3DH exchange against the
//! contact's published prekey bundle (fetched via mailboxes, SPEC.md
//! §5.3), and the resulting `RatchetMessage` must go out over the wire —
//! at which point the "decrypt with the shadow session" step in
//! `send_typing_ping` becomes "the peer decrypts it on their end," and
//! `mark_typing`/`GET .../typing` becomes what happens on receipt of an
//! incoming `Envelope::Typing`, not a same-daemon echo.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use bh_crypto::envelope::Envelope;
use bh_crypto::identity::IdentityKeyPair;
use bh_crypto::ratchet::{self, PreKeyBundle, Session, SignedPreKey};
use bh_storage::models::{Contact, OwnIdentity};
use serde::{Deserialize, Serialize};

use crate::AppState;

/// How long a typing ping keeps the indicator lit before it's treated as
/// stale. Purely a local display heuristic — never sent over the wire.
const TYPING_TTL_SECS: i64 = 8;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

/// The sender-side and shadow-receiver-side halves of one conversation's
/// Double Ratchet session — see the module doc for why both halves live in
/// this one daemon for now.
struct ConversationRatchet {
    sender: Mutex<Session>,
    shadow_receiver: Mutex<Session>,
}

struct TypingEntry {
    contact_id: String,
    last_seen_at: i64,
}

/// In-memory-only presence state. Profile-scoped (see the module doc):
/// held in `ProfileSession` alongside (but independently of) the active
/// profile's database, and swapped fresh/empty on every `switch_active`
/// exactly like `GroupRegistry`/`DeviceSyncRegistry`. Nothing in here is
/// ever written to disk; dropping the daemon process drops all of it.
#[derive(Default)]
pub struct PresenceRegistry {
    ratchets: Mutex<HashMap<String, Arc<ConversationRatchet>>>,
    typing: Mutex<HashMap<String, TypingEntry>>,
}

impl PresenceRegistry {
    fn ratchet_for(
        &self,
        conversation_id: &str,
        own: &OwnIdentity,
        contact: &Contact,
    ) -> Result<Arc<ConversationRatchet>, StatusCode> {
        let mut ratchets = self
            .ratchets
            .lock()
            .expect("presence ratchet registry lock poisoned");
        if let Some(existing) = ratchets.get(conversation_id) {
            return Ok(Arc::clone(existing));
        }
        let established = establish_shadow_session(own, contact, conversation_id)?;
        let established = Arc::new(established);
        ratchets.insert(conversation_id.to_string(), Arc::clone(&established));
        Ok(established)
    }

    fn mark_typing(&self, conversation_id: &str, contact_id: &str) {
        let mut typing = self
            .typing
            .lock()
            .expect("presence typing-state lock poisoned");
        typing.insert(
            conversation_id.to_string(),
            TypingEntry {
                contact_id: contact_id.to_string(),
                last_seen_at: now(),
            },
        );
    }

    /// `Some(contact_id)` if a typing ping for this conversation is still
    /// within the TTL; prunes (and returns `None` for) stale entries.
    fn typing_contact(&self, conversation_id: &str) -> Option<String> {
        let mut typing = self
            .typing
            .lock()
            .expect("presence typing-state lock poisoned");
        match typing.get(conversation_id) {
            Some(entry) if now() - entry.last_seen_at <= TYPING_TTL_SECS => {
                Some(entry.contact_id.clone())
            }
            Some(_) => {
                typing.remove(conversation_id);
                None
            }
            None => None,
        }
    }

    /// Wipes every in-memory session and typing entry — used when the user
    /// turns the feature off, so no cached ratchet state or stale "is
    /// typing" flag lingers after opt-out.
    pub fn clear(&self) {
        self.ratchets
            .lock()
            .expect("presence ratchet registry lock poisoned")
            .clear();
        self.typing
            .lock()
            .expect("presence typing-state lock poisoned")
            .clear();
    }
}

/// Builds a local stand-in Double Ratchet session pair for `conversation_id`
/// so the typing signal is encrypted/decrypted through real X3DH + Double
/// Ratchet code today, without a live network or the contact's private key
/// material. See the module doc for the full rationale and what changes
/// once `bh-network` delivery is wired in.
fn establish_shadow_session(
    own: &OwnIdentity,
    contact: &Contact,
    conversation_id: &str,
) -> Result<ConversationRatchet, StatusCode> {
    let key_bytes: &[u8; 64] = own
        .identity_private_key
        .as_slice()
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let identity =
        IdentityKeyPair::import_bytes(key_bytes).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // A real handshake would X3DH against the contact's own published
    // prekey bundle (fetched via mailboxes, SPEC.md §5.3). We don't have
    // that here — no live bh-network, and by definition we never hold the
    // contact's private key material — so a local shadow identity stands
    // in on the other side of the handshake, purely to run the real
    // crypto end-to-end (mirrors how message-send doesn't encrypt at all
    // yet for the identical reason — see `conversations::send_message`).
    let shadow_peer = IdentityKeyPair::generate().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let shadow_spk = SignedPreKey::generate(&shadow_peer, 1);
    let bundle = PreKeyBundle {
        identity_agreement_key: shadow_peer.public_agreement_key(),
        identity_signing_key: shadow_peer.public_signing_key(),
        signed_prekey_id: shadow_spk.id,
        signed_prekey: shadow_spk.public,
        signed_prekey_signature: shadow_spk.signature,
        pq_prekey: shadow_spk.pq_prekey.public_key(),
        pq_prekey_signature: shadow_spk.pq_prekey_signature,
        one_time_prekey_id: None,
        one_time_prekey: None,
    };

    let (alice_sk, initial_msg) = ratchet::x3dh_initiate(&identity, &bundle)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let bob_sk = ratchet::x3dh_respond(&shadow_peer, &shadow_spk, None, &initial_msg)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Associated data binds each ratchet message to this conversation and
    // to the real contact's identity key, so a payload that somehow ended
    // up associated with the wrong conversation/contact fails to decrypt
    // rather than silently being accepted.
    let mut associated_data = format!("blackhole-typing-v1:{conversation_id}:").into_bytes();
    associated_data.extend_from_slice(&contact.identity_public_key);

    let sender = Session::init_as_initiator(alice_sk, shadow_spk.public, associated_data.clone());
    let shadow_receiver = Session::init_as_responder(bob_sk, shadow_spk.secret, associated_data);

    Ok(ConversationRatchet {
        sender: Mutex::new(sender),
        shadow_receiver: Mutex::new(shadow_receiver),
    })
}

#[derive(Serialize)]
pub struct TypingIndicatorSettingResponse {
    pub enabled: bool,
}

pub async fn get_typing_indicator_setting(
    State(state): State<Arc<AppState>>,
) -> Result<Json<TypingIndicatorSettingResponse>, StatusCode> {
    let enabled = state
        .db()
        .typing_indicators_enabled()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(TypingIndicatorSettingResponse { enabled }))
}

#[derive(Deserialize)]
pub struct SetTypingIndicatorSettingRequest {
    pub enabled: bool,
}

/// Flips the opt-in toggle. Turning it off also clears any in-memory
/// session/typing state immediately, rather than letting it linger until
/// it would naturally expire.
pub async fn set_typing_indicator_setting(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SetTypingIndicatorSettingRequest>,
) -> Result<StatusCode, StatusCode> {
    state
        .db()
        .set_typing_indicators_enabled(req.enabled)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !req.enabled {
        state.presence().clear();
    }
    Ok(StatusCode::OK)
}

#[derive(Serialize)]
pub struct TypingPingResponse {
    /// `false` when the opt-in setting is off — in that case nothing was
    /// constructed, encrypted, or recorded, not even locally. Opt-out
    /// means silence, not a "typing indicators disabled" signal.
    pub sent: bool,
    /// Ciphertext length of the encrypted ephemeral payload that was
    /// actually produced, present only when `sent` is `true`. Exposed so
    /// callers (including tests) can confirm this went through real AEAD
    /// encryption.
    pub ciphertext_len: Option<usize>,
}

/// Encrypts and "delivers" one typing ping for `conversation_id`. No-op
/// (not even a database read beyond the settings check) when the opt-in
/// setting is off.
pub async fn send_typing_ping(
    State(state): State<Arc<AppState>>,
    Path(conversation_id): Path<String>,
) -> Result<Json<TypingPingResponse>, StatusCode> {
    let enabled = state
        .db()
        .typing_indicators_enabled()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !enabled {
        return Ok(Json(TypingPingResponse {
            sent: false,
            ciphertext_len: None,
        }));
    }

    let conversation = state
        .db()
        .get_conversation(&conversation_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    // Group typing indicators would need the MLS group session instead of
    // a 1:1 Double Ratchet one; out of scope here — direct conversations
    // only for now.
    let contact_id = conversation.contact_id.ok_or(StatusCode::BAD_REQUEST)?;
    let contact = state
        .db()
        .get_contact(&contact_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let own = state
        .db()
        .get_own_identity()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::PRECONDITION_FAILED)?;

    let ratchet_pair = state
        .presence()
        .ratchet_for(&conversation_id, &own, &contact)?;

    let plaintext = Envelope::Typing
        .encode()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let message = {
        let mut sender = ratchet_pair
            .sender
            .lock()
            .expect("presence sender session lock poisoned");
        sender
            .encrypt(&plaintext)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    };
    let ciphertext_len = message.ciphertext.len();

    // "Delivery": until bh-network is wired (see module doc), the sealed
    // payload is decrypted immediately with the paired shadow session
    // instead of going out over the wire. Only a successful decrypt of a
    // genuine `Envelope::Typing` updates the visible presence state — a
    // corrupted or wrongly-bound payload would fail here exactly like it
    // would on a real remote peer.
    let decrypted = {
        let mut shadow = ratchet_pair
            .shadow_receiver
            .lock()
            .expect("presence shadow-receiver session lock poisoned");
        shadow
            .decrypt(&message)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    };
    let envelope = Envelope::decode(&decrypted).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if matches!(envelope, Envelope::Typing) {
        state.presence().mark_typing(&conversation_id, &contact_id);
    }

    Ok(Json(TypingPingResponse {
        sent: true,
        ciphertext_len: Some(ciphertext_len),
    }))
}

#[derive(Serialize)]
pub struct TypingStatusResponse {
    pub typing: bool,
    pub contact_id: Option<String>,
}

/// Polling read of the current in-memory typing state for a conversation —
/// the client-side stand-in for real-time push until `bh-network` fan-out
/// exists (see module doc). Always available regardless of the opt-in
/// setting so a client that just flipped the setting off still sees the
/// indicator clear rather than freeze on a stale value.
pub async fn get_typing_status(
    State(state): State<Arc<AppState>>,
    Path(conversation_id): Path<String>,
) -> Json<TypingStatusResponse> {
    match state.presence().typing_contact(&conversation_id) {
        Some(contact_id) => Json(TypingStatusResponse {
            typing: true,
            contact_id: Some(contact_id),
        }),
        None => Json(TypingStatusResponse {
            typing: false,
            contact_id: None,
        }),
    }
}
