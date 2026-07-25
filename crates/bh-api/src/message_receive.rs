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

use bh_crypto::envelope::{ConversationRef, Envelope};
use bh_crypto::identity::{recipient_key_hash, IdentityKeyPair};
use bh_crypto::mls::MlsMember;
use bh_crypto::ratchet::{self, session_associated_data, RatchetMessage, Session, SignedPreKey};
use bh_network::sealed_sender::{self, SealedSenderEnvelope};
use bh_storage::models::{Contact, Group as StoredGroup, Message, Session as StoredSession};
use tokio::task::JoinHandle;
use x25519_dalek::StaticSecret as X25519Secret;

use crate::message_crypto::{
    ensure_own_signed_prekey, publish_own_bundle_best_effort, OutgoingEnvelope,
};
use crate::AppState;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

/// How many already-processed envelopes to remember. Each entry is a
/// 32-byte digest plus a timestamp, so this is a few tens of KB at the
/// cap — cheap enough to keep well above any realistic burst of genuine
/// traffic while still being bounded.
const REPLAY_CACHE_CAPACITY: usize = 4096;

/// How far a sender's self-declared timestamp may sit from this daemon's
/// own clock before the envelope is refused outright. `unsealed.timestamp`
/// is signed by the sender, which proves who wrote it — not that it's
/// true. Unbounded, it let a contact place messages arbitrarily far up or
/// down a conversation's ordering, and it let an envelope captured off the
/// DHT stay replayable forever. A day either way absorbs real clock skew
/// and the mailbox's own store-and-forward delay for an offline recipient
/// without leaving that window open indefinitely.
const MAX_TIMESTAMP_SKEW_SECONDS: i64 = 24 * 60 * 60;

/// How many mailbox entries from senders this profile doesn't (yet) know
/// may sit in the mailbox before the surplus is deleted rather than
/// retained. Generous for the case the retention exists for — a handful of
/// strangers trying to reach someone — while far below the point where the
/// manifest's own `MAX_MANIFEST_BYTES` cap would start rejecting real
/// pushes.
const MAX_RETAINED_UNKNOWN_SENDER_ENTRIES: usize = 64;

/// Remembers which mailbox envelopes this daemon has already processed, so
/// re-inserting one doesn't get it delivered twice.
///
/// This is needed because a mailbox entry is a plain, publicly readable
/// DHT record and `Mailbox::delete` only prunes the recipient's manifest —
/// the message record itself survives until its TTL. Anyone who watched
/// the DHT can therefore re-publish a manifest entry pointing back at an
/// envelope that was already delivered, sealed-sender signature and all.
/// `bh_crypto::ratchet::Session::decrypt` being atomic means such a replay
/// can no longer corrupt session state, but two paths would still act on
/// it: an envelope carrying an X3DH `InitialMessage` (which derives a
/// fresh session from scratch, so it decrypts again) and any
/// `Envelope::Call` offer (which would ring the user a second time).
/// Keyed on a digest of the sealed bytes rather than the mailbox message
/// id, since the id is chosen by the sender and a replayer is free to
/// invent a new one for identical content.
#[derive(Default)]
pub struct ReplayGuard {
    seen: std::sync::Mutex<std::collections::HashMap<[u8; 32], i64>>,
}

impl ReplayGuard {
    /// Records `ciphertext` as processed, returning `true` if it had
    /// already been seen. Evicts the oldest entries once past
    /// [`REPLAY_CACHE_CAPACITY`].
    fn check_and_record(&self, ciphertext: &[u8], now: i64) -> bool {
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(ciphertext).into();

        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if seen.contains_key(&digest) {
            return true;
        }
        if seen.len() >= REPLAY_CACHE_CAPACITY {
            // Drop the oldest quarter in one pass rather than one entry
            // per insert: a single `min_by_key` scan amortized over many
            // inserts, instead of one scan on every insert once full.
            let mut ages: Vec<i64> = seen.values().copied().collect();
            ages.sort_unstable();
            let cutoff = ages[ages.len() / 4];
            seen.retain(|_, seen_at| *seen_at > cutoff);
        }
        seen.insert(digest, now);
        false
    }
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
    // Not `own_identity_keypair`: a linked secondary device has no
    // account identity by design, and speaks as its own per-device one
    // instead (`device_role::acting_identity_keypair`). Using the account
    // identity here is exactly what left a real second daemon polling a
    // mailbox that did not exist.
    let Ok(identity) = crate::device_role::acting_identity_keypair(state) else {
        // No identity bootstrapped and no device link yet — routine
        // before `POST /identity`, not worth a warning every tick.
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

    let mut retained_unknown = 0usize;
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
                // Retained so a stranger's first message survives until
                // they're added as a contact (see module doc) — but only
                // up to a bound. Retaining without one made this a free
                // denial of service: entries from unknown senders were
                // never deleted and `Mailbox::pull` only prunes ones that
                // are expired or already gone, so an attacker cycling
                // throwaway identities could pin junk in the manifest
                // until it hit `MAX_MANIFEST_BYTES` and *every* legitimate
                // push to this identity started failing — for as long as
                // the attacker's chosen TTL, up to 30 days. Past the
                // bound, the surplus is deleted: losing an unread
                // first-contact message is a far smaller harm than being
                // unreachable.
                retained_unknown += 1;
                if retained_unknown > MAX_RETAINED_UNKNOWN_SENDER_ENTRIES {
                    tracing::warn!(
                        "receive loop: more than {MAX_RETAINED_UNKNOWN_SENDER_ENTRIES} \
                         unknown-sender entries in the mailbox — deleting the surplus to keep \
                         the manifest usable"
                    );
                    if let Err(err) = network
                        .mailbox()
                        .delete(&own_key_hash, &message_id_bytes)
                        .await
                    {
                        tracing::warn!(%err, "receive loop: failed to delete surplus entry");
                    }
                }
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

    // Refuse an envelope whose signed timestamp is implausible before
    // acting on it — see `MAX_TIMESTAMP_SKEW_SECONDS`. Doing this here
    // rather than at storage time also means a stale envelope recovered
    // from the DHT long after the fact can't be replayed into a live
    // conversation once it falls outside the window.
    let received_at = now();
    if (unsealed.timestamp - received_at).abs() > MAX_TIMESTAMP_SKEW_SECONDS {
        tracing::debug!(
            declared = unsealed.timestamp,
            local = received_at,
            "dropping a mailbox entry whose declared timestamp is outside the accepted window"
        );
        return ProcessOutcome::Unprocessable;
    }

    // Replay check runs *after* unsealing (so junk nobody could have sent
    // never occupies a cache slot) but *before* any session or delivery
    // work — see `ReplayGuard`.
    if state.replay_guard.check_and_record(ciphertext, received_at) {
        tracing::debug!("dropping an already-processed mailbox entry (replay)");
        return ProcessOutcome::Unprocessable;
    }

    let sender_signing_bytes = unsealed.sender_identity.to_bytes();
    // A sender that isn't a contact may still be one of this account's
    // own linked devices delegating a send (`device_delegation.rs`), or —
    // on a secondary — the primary mirroring state. Both need a
    // `contacts` row to hang a ratchet session off, materialized on first
    // use. `internal_pseudo_contact` returns `None` for a revoked device,
    // which is what makes revocation bite here rather than depending on
    // the revoked device cooperating.
    let contact = match find_contact_by_signing_key(state, &sender_signing_bytes) {
        Some(contact) => contact,
        None => match crate::device_role::internal_pseudo_contact(state, &sender_signing_bytes) {
            Some(contact) => contact,
            None => return ProcessOutcome::UnknownSender,
        },
    };

    // Blocking a contact used to stop at the UI: nothing on this path ever
    // read `Contact::blocked`, so a blocked identity's messages were still
    // inserted, its group invites still joined, and — worst of all — its
    // call offers still reached `calls::handle_incoming_call_signal`.
    // Dropped as `Unprocessable` (not `UnknownSender`) on purpose: the
    // mailbox entry is deleted rather than pinned forever, so a blocked
    // sender can't use it to fill the recipient's manifest.
    if contact.blocked {
        tracing::debug!(
            contact_id = %contact.contact_id,
            "dropping a mailbox entry from a blocked contact"
        );
        return ProcessOutcome::Unprocessable;
    }

    // Candidate sessions, in the order they're tried. The stored session
    // always comes first — including when the envelope carries an X3DH
    // `InitialMessage`.
    //
    // That ordering is the point. This used to rebuild a responder session
    // from scratch whenever an `InitialMessage` was present, unconditionally
    // discarding the live one, which made "replay the first envelope of a
    // conversation" a way to reset a peer's ratchet at will. Preferring the
    // existing session means a replayed handshake simply fails to decrypt
    // (its message key was consumed long ago) and changes nothing. The
    // freshly-derived session is still kept as a *fallback* so the genuine
    // case it exists for — a peer that lost its state and legitimately
    // re-handshakes — still recovers.
    let mut candidates: Vec<Session> = Vec::with_capacity(2);
    if let Ok(Some(row)) = state.db().get_session(&contact.contact_id) {
        if let Ok(session) = Session::from_bytes(&row.ratchet_state) {
            candidates.push(session);
        }
    }
    if let Some(initial_message) = &envelope.initial_message {
        let mut their_identity_bytes = [0u8; 64];
        their_identity_bytes[..32].copy_from_slice(&sender_signing_bytes);
        their_identity_bytes[32..]
            .copy_from_slice(initial_message.sender_identity_agreement_key.as_bytes());

        if let Ok(shared_secret) =
            ratchet::x3dh_respond(identity, signed_prekey, None, initial_message)
        {
            let associated_data =
                session_associated_data(&identity.public_identity_bytes(), &their_identity_bytes);
            candidates.push(Session::init_as_responder(
                shared_secret,
                X25519Secret::from(signed_prekey.secret.to_bytes()),
                associated_data,
            ));
        }
    }
    if candidates.is_empty() {
        return ProcessOutcome::Unprocessable;
    }

    deliver_decrypted(
        state,
        &contact,
        candidates,
        &envelope.ratchet_message,
        unsealed.timestamp,
    )
    .await
}

/// Tries each candidate session in order (see `process_one`) and delivers
/// whatever the first one that decrypts produces.
async fn deliver_decrypted(
    state: &AppState,
    contact: &Contact,
    candidates: Vec<Session>,
    ratchet_message: &RatchetMessage,
    sent_at: i64,
) -> ProcessOutcome {
    // Persisted **only** on success, and only for the session that
    // actually worked. `Session::decrypt` is atomic (see its own doc
    // comment), so a candidate that fails leaves nothing behind to undo —
    // which is what makes trying several of them safe in the first place.
    let mut winner = None;
    let mut plaintext = Vec::new();
    for mut session in candidates {
        if let Ok(decrypted) = session.decrypt(ratchet_message) {
            plaintext = decrypted;
            winner = Some(session);
            break;
        }
    }
    let Some(session) = winner else {
        return ProcessOutcome::Unprocessable;
    };

    if let Err(err) = state.db().upsert_session(&StoredSession {
        session_id: contact.contact_id.clone(),
        contact_id: contact.contact_id.clone(),
        device_id: "primary".to_string(),
        ratchet_state: session.to_bytes(),
        updated_at: now(),
    }) {
        tracing::warn!(%err, "receive loop: failed to persist session");
    }

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
            conversation,
            sender_contact_id,
            body,
            sent_at,
        }) => {
            if !crate::device_role::is_primary_sender(state, contact) {
                return ProcessOutcome::Unprocessable;
            }
            deliver_synced_message(
                state,
                &message_id,
                &conversation,
                sender_contact_id,
                body,
                sent_at,
            )
        }

        // A linked secondary device asking this daemon to send for it.
        // Gated on the sender genuinely being one of *this account's* own
        // authorized devices — without that check any contact could put
        // this envelope in the mailbox and have this daemon send messages
        // as the account. See `device_role::is_authorized_own_device`.
        Ok(Envelope::OutboundRequest {
            request_id,
            conversation,
            body,
            reply_to_message_id,
        }) => {
            if !crate::device_role::is_authorized_own_device(state, contact) {
                tracing::warn!(
                    contact_id = %contact.contact_id,
                    "ignoring a delegated-send request from a sender that is not an authorized device"
                );
                return ProcessOutcome::Unprocessable;
            }
            crate::device_delegation::handle_outbound_request(
                state,
                contact,
                request_id,
                conversation,
                body,
                reply_to_message_id,
            )
            .await;
            ProcessOutcome::Delivered
        }
        // The primary's answer to a send this device delegated.
        Ok(Envelope::OutboundResult {
            request_id, error, ..
        }) => {
            if !crate::device_role::is_primary_sender(state, contact) {
                return ProcessOutcome::Unprocessable;
            }
            crate::device_delegation::handle_outbound_result(state, &request_id, error);
            ProcessOutcome::Delivered
        }
        // Mirrored contact rows. Same authorization reasoning as above,
        // mirrored: accepting these from anyone but the primary would let
        // a contact inject identities into this device's contact book.
        Ok(Envelope::ContactSync { contacts }) => {
            if !crate::device_role::is_primary_sender(state, contact) {
                return ProcessOutcome::Unprocessable;
            }
            crate::device_sync::apply_contact_sync(state, contacts);
            ProcessOutcome::Delivered
        }
        Ok(Envelope::DeviceRevoked) => {
            if !crate::device_role::is_primary_sender(state, contact) {
                return ProcessOutcome::Unprocessable;
            }
            tracing::warn!("this device has been revoked by its primary");
            if let Err(err) = state.db().mark_linked_account_revoked(now()) {
                tracing::warn!(%err, "failed to record this device's revocation");
            }
            ProcessOutcome::Delivered
        }
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
    conversation: &ConversationRef,
    sender_contact_id: Option<String>,
    body: Option<String>,
    sent_at: i64,
) -> ProcessOutcome {
    // `true`: a mirrored group message may well be the first this device
    // hears of the group, so a placeholder `groups` row is materialized
    // for it. That row carries **no** MLS state — a secondary is never a
    // member (see `device_delegation::resolve_conversation`) — it exists
    // only to give the conversation something to reference.
    let Ok(conversation) =
        crate::device_delegation::resolve_conversation(state, conversation, true)
    else {
        // An unknown contact is the one genuinely retryable case here:
        // `Envelope::ContactSync` may simply not have arrived yet, and
        // the mailbox entry is worth keeping until it does.
        return ProcessOutcome::UnknownSender;
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
    // `insert_group_message` rather than `insert_message`: it accepts
    // every conversation kind (and re-checks the broadcast-only rule),
    // which this path now needs since mirroring covers groups and
    // self-notes too, not just `Direct`.
    match state.db().insert_group_message(&message) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_replay_guard_reports_a_repeat_of_the_same_envelope() {
        let guard = ReplayGuard::default();
        let envelope = b"a sealed sender envelope's exact bytes";

        assert!(
            !guard.check_and_record(envelope, 1_000),
            "the first sighting is not a replay"
        );
        assert!(
            guard.check_and_record(envelope, 1_050),
            "the same bytes arriving again must be reported as a replay"
        );
        assert!(
            !guard.check_and_record(b"a genuinely different envelope", 1_100),
            "a different envelope must not be mistaken for a replay"
        );
    }

    /// The guard must stay bounded — it's fed by whatever arrives in a
    /// mailbox, which an attacker can drive.
    #[test]
    fn the_replay_guard_stays_bounded_under_a_flood() {
        let guard = ReplayGuard::default();
        for i in 0..(REPLAY_CACHE_CAPACITY * 3) {
            guard.check_and_record(format!("envelope-{i}").as_bytes(), i as i64);
        }
        let held = guard
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        assert!(
            held <= REPLAY_CACHE_CAPACITY,
            "the replay cache must stay within its cap, held {held}"
        );
    }

    /// A recent entry must survive the eviction pass that a flood triggers,
    /// or the guard would stop catching the replays it exists for exactly
    /// when it's under pressure.
    #[test]
    fn eviction_drops_old_entries_and_keeps_recent_ones() {
        let guard = ReplayGuard::default();
        for i in 0..REPLAY_CACHE_CAPACITY {
            guard.check_and_record(format!("old-{i}").as_bytes(), i as i64);
        }
        let recent = b"the envelope that just arrived";
        assert!(!guard.check_and_record(recent, 1_000_000));
        // Force an eviction pass with more traffic.
        for i in 0..(REPLAY_CACHE_CAPACITY / 2) {
            guard.check_and_record(format!("newer-{i}").as_bytes(), 1_000_001 + i as i64);
        }
        assert!(
            guard.check_and_record(recent, 1_000_100),
            "a recently-seen envelope must still be recognized after eviction"
        );
    }
}
