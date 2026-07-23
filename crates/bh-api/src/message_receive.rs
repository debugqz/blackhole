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
//!
//! **Also the delivery path for real call signaling** (`calls.rs`'s
//! `send_call_signal`/`handle_incoming_call_signal`): a decrypted
//! plaintext is decoded as a `bh_crypto::envelope::Envelope`, not assumed
//! to be raw message-body text, and dispatched by variant —
//! `Envelope::Text` down the existing message-insert path,
//! `Envelope::Call` into `CallRegistry` — precisely so an offer/answer/
//! hangup looks identical, from a mailbox operator's point of view, to an
//! ordinary chat message (see `envelope.rs`'s module doc on why that
//! matters). Reaction/receipt/typing envelopes aren't sent over the
//! network by any caller yet, so they're accepted-and-ignored here rather
//! than treated as malformed.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bh_crypto::envelope::Envelope;
use bh_crypto::identity::{recipient_key_hash, IdentityKeyPair};
use bh_crypto::mls::MlsMember;
use bh_crypto::ratchet::{self, session_associated_data, RatchetMessage, Session, SignedPreKey};
use bh_network::sealed_sender::{self, SealedSenderEnvelope};
use bh_storage::models::{Contact, Group as StoredGroup, Message, Session as StoredSession};
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
        let outcome = process_one(state, &identity, &signed_prekey, &ciphertext).await;
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

    receive_group_messages(state, network).await;

    publish_own_bundle_best_effort(network, &identity, &signed_prekey).await;
    crate::mls_key_package::publish_own_key_package_best_effort(state, network).await;
}

/// Polls every locally-known group's shared fan-out mailbox
/// (`Mailbox::fan_out`'s counterpart, `Mailbox::pull` keyed by `group_id`
/// instead of an identity's own key hash — see `conversations.rs`'s
/// `Group` send arm). Unlike the identity mailbox above, entries are
/// **never deleted** here: the same mailbox key is shared by every group
/// member, and deleting an entry the moment *this* daemon has processed it
/// would race members who haven't pulled it yet. Instead,
/// `GroupRegistry::already_attempted_group_message` skips anything this
/// process has already tried (success or failure) — a message this daemon
/// already decrypted, or a commit whose epoch has already passed, both
/// fail `openmls`'s own replay/epoch validation on a second attempt
/// anyway, so re-trying an untracked entry would just be wasted work, not
/// a correctness problem; the tracking here exists purely to bound that
/// work instead of re-attempting every entry every tick until it finally
/// TTL-expires.
async fn receive_group_messages(
    state: &AppState,
    network: &bh_network::supervised::SupervisedNetwork,
) {
    let Ok(groups) = state.db().list_groups() else {
        return;
    };
    for group in groups {
        let Ok(group_id_bytes) = hex::decode(&group.group_id) else {
            continue;
        };
        let pulled = match network.mailbox().pull(&group_id_bytes, now()).await {
            Ok(pulled) => pulled,
            Err(err) => {
                tracing::warn!(%err, group_id = %group.group_id, "receive loop: group mailbox pull failed");
                continue;
            }
        };
        for (message_id_bytes, ciphertext) in pulled {
            if state
                .groups()
                .already_attempted_group_message(&group.group_id, &message_id_bytes)
            {
                continue;
            }
            state
                .groups()
                .mark_group_message_attempted(&group.group_id, message_id_bytes);
            deliver_group_message(state, &group.group_id, &ciphertext);
        }
    }
}

/// Decrypts and (for an application message) delivers one group ciphertext
/// already known to belong to `group_id`. Errors (unknown group state,
/// stale-epoch commit, a message this daemon can't yet decrypt) are
/// deliberately swallowed here — see `receive_group_messages`'s doc
/// comment for why that's an expected steady-state outcome, not just a
/// failure to log.
fn deliver_group_message(state: &AppState, group_id: &str, ciphertext: &[u8]) {
    let Ok(decrypted) = crate::groups::decrypt_group_message(state, group_id, ciphertext) else {
        return;
    };
    // `None` means this was a commit (membership change) — `Group::decrypt_
    // with_sender` already merged it into the live group state as a side
    // effect; nothing left to deliver as a chat message.
    let Some(plaintext) = decrypted.plaintext else {
        return;
    };
    let Ok(Envelope::Text { body, .. }) = Envelope::decode(&plaintext) else {
        return;
    };
    let Some(conversation) = state
        .db()
        .get_conversation_for_group(group_id)
        .ok()
        .flatten()
    else {
        // A group this daemon knows about (it came from `list_groups()`)
        // but has no local conversation row for is an inconsistent state
        // that shouldn't happen in practice (every path that creates a
        // `groups` row also creates the matching `conversations` row) —
        // nothing sensible to deliver into, so this is dropped rather than
        // panicking the receive loop.
        return;
    };
    let sender_contact_id = find_contact_by_identity_public_key(state, &decrypted.sender_identity)
        .map(|c| c.contact_id);

    let received_at = now();
    let expires_at = state
        .db()
        .compute_message_expiry(&conversation.conversation_id, received_at)
        .unwrap_or(None);
    let message = Message {
        message_id: uuid::Uuid::new_v4().to_string(),
        conversation_id: conversation.conversation_id,
        sender_contact_id,
        body: Some(body),
        sent_at: received_at,
        received_at: Some(received_at),
        expires_at,
        deleted_at: None,
        reply_to_message_id: None,
        edited_at: None,
    };
    if let Err(err) = state.db().insert_group_message(&message) {
        tracing::warn!(%err, "receive loop: failed to insert decrypted group message");
    }
}

/// Processes a real `GroupInvite`: joins the group from the `Welcome` this
/// identity's own currently-published key package was just consumed to
/// produce, persists it exactly like `groups::create_group` does for the
/// inviter's own side (own-member signer key + a local `groups`/
/// `conversations` row pair), caches the live state in the in-process
/// `GroupRegistry` so an immediate follow-up request doesn't need to
/// reload it, and — since this identity's key package is now consumed —
/// immediately regenerates and republishes a fresh one (see
/// `mls_key_package`'s module doc for why that can't wait for the next
/// periodic tick).
async fn handle_group_invite(
    state: &AppState,
    group_id: &str,
    name: Option<String>,
    welcome: &[u8],
    ratchet_tree: &[u8],
    broadcast_only: bool,
) {
    let Ok(Some(own)) = state.db().get_own_identity() else {
        return;
    };
    let Ok(Some(key_package)) = state.db().get_own_mls_key_package() else {
        tracing::warn!("received a GroupInvite but have no own MLS key package on record");
        return;
    };
    let Ok(provider) = state.mls_provider() else {
        return;
    };
    let Ok(member) = MlsMember::from_stored_signer(
        &own.identity_public_key,
        provider,
        &key_package.signer_public_key,
    ) else {
        tracing::warn!("failed to reconstruct the MLS member that consumed the key package");
        return;
    };
    let Ok(group) = member.join_group(welcome, ratchet_tree) else {
        tracing::warn!(%group_id, "failed to join group from a real GroupInvite's Welcome");
        return;
    };

    let created_at = now();
    if let Err(err) = state.db().create_group(&StoredGroup {
        group_id: group_id.to_string(),
        name,
        mls_state: member.signature_public_key(),
        epoch: group.epoch() as i64,
        created_at,
        broadcast_only,
    }) {
        tracing::warn!(%err, %group_id, "failed to persist joined group's own-member state");
        return;
    }
    let conversation_id = uuid::Uuid::new_v4().to_string();
    if let Err(err) = state
        .db()
        .create_group_conversation(&conversation_id, group_id, created_at)
    {
        tracing::warn!(%err, %group_id, "failed to create the joined group's conversation");
        return;
    }

    state
        .groups()
        .cache_own_member_and_group(group_id, member, group);

    if let Some(network) = state.network.as_ref() {
        if let Err(err) =
            crate::mls_key_package::regenerate_and_publish_own_key_package(state, network).await
        {
            tracing::warn!(
                ?err,
                "failed to rotate own MLS key package after joining a group"
            );
        }
    }
}

/// Maps a group message's sender identity bytes (this profile's own real
/// members use their full 64-byte `identity_public_key` as their MLS
/// identity — see `groups.rs::create_group`) back to a known `Contact`.
/// `None` for a shadow member's identity (raw `contact_id` bytes, not a
/// real `identity_public_key`) or a sender this profile hasn't added as a
/// contact — either way, the message is still delivered, just without an
/// attributed sender (mirrors `find_contact_by_signing_key`'s
/// `UnknownSender` handling not applying here, since a group message has
/// nowhere else useful to go).
fn find_contact_by_identity_public_key(
    state: &AppState,
    identity_public_key: &[u8],
) -> Option<Contact> {
    state
        .db()
        .list_contacts()
        .ok()?
        .into_iter()
        .find(|c| c.identity_public_key == identity_public_key)
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

async fn process_one(
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
    .await
}

async fn deliver_decrypted(
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

    match Envelope::decode(&plaintext) {
        Ok(Envelope::Text { body, .. }) => deliver_text_message(state, contact, &body, sent_at),
        Ok(Envelope::Call(signal)) => {
            crate::calls::handle_incoming_call_signal(state, contact, signal).await;
            ProcessOutcome::Delivered
        }
        Ok(Envelope::GroupInvite {
            group_id,
            name,
            welcome,
            ratchet_tree,
            broadcast_only,
        }) => {
            handle_group_invite(
                state,
                &group_id,
                name,
                &welcome,
                &ratchet_tree,
                broadcast_only,
            )
            .await;
            ProcessOutcome::Delivered
        }
        Ok(Envelope::DeviceSyncMessage {
            message_id,
            peer_contact_id,
            sender_contact_id,
            body,
            sent_at,
        }) => deliver_synced_message(
            state,
            &message_id,
            &peer_contact_id,
            sender_contact_id,
            body,
            sent_at,
        ),
        // Reaction/Receipt/DisappearingTimerChanged/Typing envelopes
        // aren't produced by any network sender yet (see module doc) —
        // accepted and dropped rather than retried forever.
        Ok(_) => ProcessOutcome::Delivered,
        Err(_) => ProcessOutcome::Unprocessable,
    }
}

/// Delivers one message pushed by a real `device_sync::sync_device_over_
/// network` call — this identity is the linked device, `contact` (from
/// the enclosing sealed-sender envelope) is the primary that pushed it.
/// `peer_contact_id` identifies which local `Direct` conversation to
/// materialize/reuse (`ensure_direct_conversation`); this device must
/// already know that contact (contact sync itself is a separate
/// follow-up — see `device_sync.rs`'s module doc), so an unknown
/// `peer_contact_id` is dropped rather than retried forever.
fn deliver_synced_message(
    state: &AppState,
    message_id: &str,
    peer_contact_id: &str,
    sender_contact_id: Option<String>,
    body: Option<String>,
    sent_at: i64,
) -> ProcessOutcome {
    if state
        .db()
        .get_contact(peer_contact_id)
        .ok()
        .flatten()
        .is_none()
    {
        return ProcessOutcome::Unprocessable;
    }
    let Ok(conversation) = state
        .db()
        .ensure_direct_conversation(peer_contact_id, now())
    else {
        return ProcessOutcome::Unprocessable;
    };
    let message = Message {
        message_id: message_id.to_string(),
        conversation_id: conversation.conversation_id,
        sender_contact_id,
        body,
        sent_at,
        received_at: Some(now()),
        expires_at: None,
        deleted_at: None,
        reply_to_message_id: None,
        edited_at: None,
    };
    match state.db().insert_message(&message) {
        Ok(()) => ProcessOutcome::Delivered,
        Err(err) => {
            tracing::warn!(%err, "receive loop: failed to insert synced message");
            ProcessOutcome::Unprocessable
        }
    }
}

fn deliver_text_message(
    state: &AppState,
    contact: &Contact,
    body: &str,
    sent_at: i64,
) -> ProcessOutcome {
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
        body: Some(body.to_string()),
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
