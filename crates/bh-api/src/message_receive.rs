//! The receive side of `message_crypto.rs`'s real X3DH/Double Ratchet
//! wiring: a periodic background task that pulls this identity's mailbox,
//! unseals/decrypts whatever's there, and stores it as an incoming
//! message — the counterpart `conversations.rs`'s doc comments have long
//! pointed at as "once `bh-network` is wired into send/receive." Spawned
//! once from `daemon/src/main.rs` against the whole `Arc<AppState>`
//! (not a specific profile): every tick reads `state.db()`/`state.network`
//! fresh, so it automatically follows whichever profile is currently
//! active, the same way the expiry sweeper's *replacement* does on
//! `switch_active` — except this loop never needs restarting, since it
//! never holds a per-profile handle across a tick.
//!
//! Mailbox delivery is poll-based (`Mailbox::pull`, not a push/subscribe
//! API — see that module's doc comment), so "real-time" here means "within
//! one tick interval," not instant delivery. An unrecognized sender's
//! message is deliberately left in the mailbox rather than dropped (this
//! codebase already has a message-request concept for "someone messaged me
//! first," `bh-storage::message_requests`, but wiring first-contact
//! delivery through it is a follow-up — this pass only delivers messages
//! from *already-added* contacts) — see [`process_one`] for exactly where.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bh_crypto::identity::{recipient_key_hash, IdentityKeyPair};
use bh_crypto::ratchet::{self, session_associated_data, RatchetMessage, Session, SignedPreKey};
use bh_network::sealed_sender::{self, SealedSenderEnvelope};
use bh_storage::models::{Contact, Message, Session as StoredSession};
use tokio::task::JoinHandle;
use x25519_dalek::StaticSecret as X25519Secret;

use crate::message_crypto::{
    ensure_own_signed_prekey, own_identity_keypair, publish_own_bundle_best_effort,
    OutgoingEnvelope,
};
use crate::AppState;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

/// Spawns the loop; runs for the daemon's process lifetime, following
/// whichever profile is currently active (see module doc).
pub fn spawn_receive_loop(state: Arc<AppState>, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            receive_tick(&state).await;
        }
    })
}

async fn receive_tick(state: &AppState) {
    let Some(network) = state.network.as_ref() else {
        return;
    };
    let Ok(identity) = own_identity_keypair(state) else {
        // No identity bootstrapped yet — routine before `POST /identity`,
        // not worth a warning every tick.
        return;
    };
    let signed_prekey = match ensure_own_signed_prekey(state, &identity) {
        Ok(spk) => spk,
        Err(err) => {
            tracing::warn!(
                ?err,
                "receive loop: failed to load/create own signed prekey"
            );
            return;
        }
    };

    let own_key_hash = recipient_key_hash(&identity.public_identity_bytes());
    let pulled = match network.mailbox().pull(&own_key_hash, now()).await {
        Ok(pulled) => pulled,
        Err(err) => {
            tracing::warn!(%err, "receive loop: mailbox pull failed");
            return;
        }
    };

    for (message_id_bytes, ciphertext) in pulled {
        let outcome = process_one(state, &identity, &signed_prekey, &ciphertext);
        match outcome {
            ProcessOutcome::Delivered | ProcessOutcome::Unprocessable => {
                if let Err(err) = network
                    .mailbox()
                    .delete(&own_key_hash, &message_id_bytes)
                    .await
                {
                    tracing::warn!(%err, "receive loop: failed to delete processed mailbox entry");
                }
            }
            ProcessOutcome::UnknownSender => {
                // Left in the mailbox deliberately — see module doc.
            }
        }
    }

    publish_own_bundle_best_effort(network, &identity, &signed_prekey).await;
}

enum ProcessOutcome {
    Delivered,
    /// Malformed, undecryptable, or otherwise never going to succeed no
    /// matter how many times it's retried — safe (and necessary, to avoid
    /// piling up forever) to delete.
    Unprocessable,
    /// Well-formed, but from an identity that isn't (yet) a known
    /// contact — left for a future tick, in case that changes.
    UnknownSender,
}

fn find_contact_by_signing_key(state: &AppState, signing_key: &[u8; 32]) -> Option<Contact> {
    state.db().list_contacts().ok()?.into_iter().find(|c| {
        c.identity_public_key.len() >= 32 && c.identity_public_key[..32] == signing_key[..]
    })
}

fn process_one(
    state: &AppState,
    identity: &IdentityKeyPair,
    signed_prekey: &SignedPreKey,
    ciphertext: &[u8],
) -> ProcessOutcome {
    let Some(sealed) = SealedSenderEnvelope::from_bytes(ciphertext) else {
        return ProcessOutcome::Unprocessable;
    };
    let Ok(unsealed) = sealed_sender::unseal(identity.agreement_secret(), &sealed) else {
        return ProcessOutcome::Unprocessable;
    };
    let Some(envelope) = OutgoingEnvelope::from_bytes(&unsealed.inner_message) else {
        return ProcessOutcome::Unprocessable;
    };

    let sender_signing_bytes = unsealed.sender_identity.to_bytes();
    let Some(contact) = find_contact_by_signing_key(state, &sender_signing_bytes) else {
        return ProcessOutcome::UnknownSender;
    };

    let session = match &envelope.initial_message {
        Some(initial_message) => {
            let mut their_identity_bytes = [0u8; 64];
            their_identity_bytes[..32].copy_from_slice(&sender_signing_bytes);
            their_identity_bytes[32..]
                .copy_from_slice(initial_message.sender_identity_agreement_key.as_bytes());

            let Ok(shared_secret) =
                ratchet::x3dh_respond(identity, signed_prekey, None, initial_message)
            else {
                return ProcessOutcome::Unprocessable;
            };
            let associated_data =
                session_associated_data(&identity.public_identity_bytes(), &their_identity_bytes);
            Session::init_as_responder(
                shared_secret,
                X25519Secret::from(signed_prekey.secret.to_bytes()),
                associated_data,
            )
        }
        None => {
            let Ok(Some(row)) = state.db().get_session(&contact.contact_id) else {
                return ProcessOutcome::Unprocessable;
            };
            match Session::from_bytes(&row.ratchet_state) {
                Ok(s) => s,
                Err(_) => return ProcessOutcome::Unprocessable,
            }
        }
    };

    deliver_decrypted(
        state,
        &contact,
        session,
        &envelope.ratchet_message,
        unsealed.timestamp,
    )
}

fn deliver_decrypted(
    state: &AppState,
    contact: &Contact,
    mut session: Session,
    ratchet_message: &RatchetMessage,
    sent_at: i64,
) -> ProcessOutcome {
    let decrypted = session.decrypt(ratchet_message);

    // Persisted regardless of outcome: a failed AEAD check still advances
    // the receiving chain/skipped-key cache (see `bh-crypto::ratchet`'s
    // `decrypt` — the same trade-off Signal's own implementation makes),
    // so the stored state must reflect that either way.
    if let Err(err) = state.db().upsert_session(&StoredSession {
        session_id: contact.contact_id.clone(),
        contact_id: contact.contact_id.clone(),
        device_id: "primary".to_string(),
        ratchet_state: session.to_bytes(),
        updated_at: now(),
    }) {
        tracing::warn!(%err, "receive loop: failed to persist session");
    }

    let Ok(plaintext) = decrypted else {
        return ProcessOutcome::Unprocessable;
    };

    let Ok(conversation) = state
        .db()
        .ensure_direct_conversation(&contact.contact_id, now())
    else {
        return ProcessOutcome::Unprocessable;
    };
    let received_at = now();
    let expires_at = state
        .db()
        .compute_message_expiry(&conversation.conversation_id, received_at)
        .unwrap_or(None);

    // Own message id, not derivable from the ciphertext record's mailbox
    // key (that's the *sender's* message id, useful for logs but not
    // guaranteed globally unique across senders) — a fresh local id, same
    // as every other locally-inserted message.
    let message = Message {
        message_id: uuid::Uuid::new_v4().to_string(),
        conversation_id: conversation.conversation_id,
        sender_contact_id: Some(contact.contact_id.clone()),
        body: Some(String::from_utf8_lossy(&plaintext).into_owned()),
        sent_at,
        received_at: Some(received_at),
        expires_at,
        deleted_at: None,
        reply_to_message_id: None,
        edited_at: None,
    };
    match state.db().insert_message(&message) {
        Ok(()) => ProcessOutcome::Delivered,
        Err(err) => {
            tracing::warn!(%err, "receive loop: failed to insert decrypted message");
            ProcessOutcome::Unprocessable
        }
    }
}
