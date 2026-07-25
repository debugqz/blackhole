//! Delegated sending: how a linked secondary device gets a message out
//! without ever holding the key material required to encrypt one.
//!
//! See `device_role.rs` for the role split this builds on, and
//! `docs/superpowers/specs/2026-07-24-multidevice-delegation-design.md`
//! for why delegation rather than per-device sessions.
//!
//! ## The round trip
//!
//! 1. The secondary's `conversations::send_message` finds a
//!    `linked_account` row and lands in [`delegate_send`]. It persists the
//!    message locally as `pending` and pushes an
//!    `Envelope::OutboundRequest` to the primary's mailbox — the account
//!    identity's mailbox, which the primary is by definition the only
//!    device reading.
//! 2. The primary's receive loop resolves the sender to one of its own
//!    `devices` rows and calls [`handle_outbound_request`], which runs the
//!    request through `conversations::send_message_inner` — the *same*
//!    function the primary's own UI uses, not a parallel implementation.
//! 3. The primary answers with an `Envelope::OutboundResult`, and
//!    [`handle_outbound_result`] promotes the secondary's pending row to
//!    `sent` or marks it `failed` with the reason.
//!
//! ## Why this is safe to retry
//!
//! The secondary's `request_id` *is* the message id the primary uses. So
//! idempotency is a database property, not an in-memory one: a repeated
//! request finds an existing message and re-reports its outcome instead of
//! sending twice, and that survives a restart on either side. A primary
//! that is simply offline isn't a failure at all — the request sits in its
//! mailbox until the TTL, exactly like any other store-and-forward
//! message.
//!
//! ## What a secondary still cannot do
//!
//! Everything that needs the account's private keys: adding a group
//! member, verifying a safety number, issuing an invite, placing a call.
//! Those routes keep requiring a real `own_identity` and keep failing on a
//! secondary, deliberately.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use bh_crypto::envelope::{ConversationRef, Envelope};
use bh_storage::delegated_sends::DelegationState;
use bh_storage::models::{Contact, Conversation, ConversationKind, Group, LinkedAccount, Message};

use crate::conversations::{SendMessageRequest, SendMessageResponse};
use crate::AppState;

/// How many pending delegated sends one retry sweep re-pushes. Bounded so
/// a long offline backlog doesn't turn a single receive tick into an
/// unbounded burst of mailbox writes (each one costs proof-of-work).
const RETRY_BATCH: i64 = 16;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

/// Names a local conversation in the device-independent terms both sides
/// agree on. `None` for a conversation that cannot be referred to across
/// devices — an ephemeral-identity conversation, whose whole point is that
/// it does *not* speak for the account (see `ephemeral_identity.rs`), so
/// delegating one would send it under the wrong identity.
pub(crate) fn conversation_ref(conversation: &Conversation) -> Option<ConversationRef> {
    if conversation.ephemeral_identity_id.is_some() {
        return None;
    }
    match conversation.kind {
        ConversationKind::Direct => conversation
            .contact_id
            .clone()
            .map(|contact_id| ConversationRef::Direct { contact_id }),
        ConversationKind::Group => conversation
            .group_id
            .clone()
            .map(|group_id| ConversationRef::Group { group_id }),
        ConversationKind::SelfNotes => Some(ConversationRef::SelfNotes),
    }
}

/// Resolves a [`ConversationRef`] to a local conversation, creating it if
/// this device hasn't seen it before.
///
/// The `Group` arm is where the hub model earns its keep: a secondary is
/// never an MLS member, so it materializes a `groups` row with **empty**
/// `mls_state` purely to satisfy the conversation's foreign key. That row
/// is a label to hang mirrored messages off, not group state — the
/// primary holds the only real MLS state, decrypts with it, and mirrors
/// plaintext. Trying to encrypt from this row would fail, which is
/// correct: on a secondary every send goes through [`delegate_send`].
pub(crate) fn resolve_conversation(
    state: &AppState,
    reference: &ConversationRef,
    create_missing_group_as_placeholder: bool,
) -> Result<Conversation, StatusCode> {
    match reference {
        ConversationRef::Direct { contact_id } => {
            // A contact this device doesn't know yet cannot be resolved:
            // `conversations.contact_id` has a foreign key, and inventing
            // a contact row here would fabricate an identity nobody
            // verified. `Envelope::ContactSync` is what fills this gap.
            if state
                .db()
                .get_contact(contact_id)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .is_none()
            {
                return Err(StatusCode::NOT_FOUND);
            }
            state
                .db()
                .ensure_direct_conversation(contact_id, now())
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
        }
        ConversationRef::Group { group_id } => {
            if let Some(conversation) = state
                .db()
                .get_conversation_for_group(group_id)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            {
                return Ok(conversation);
            }
            if !create_missing_group_as_placeholder {
                return Err(StatusCode::NOT_FOUND);
            }
            state
                .db()
                .create_group(&Group {
                    group_id: group_id.clone(),
                    name: None,
                    mls_state: Vec::new(),
                    epoch: 0,
                    created_at: now(),
                    broadcast_only: false,
                })
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let conversation_id = uuid::Uuid::new_v4().to_string();
            state
                .db()
                .create_group_conversation(&conversation_id, group_id, now())
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            state
                .db()
                .get_conversation(&conversation_id)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .ok_or(StatusCode::INTERNAL_SERVER_ERROR)
        }
        ConversationRef::SelfNotes => state
            .db()
            .ensure_self_conversation(now())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// The secondary side of a send.
///
/// Persists locally first and pushes second, on purpose: a message the
/// user typed must survive the push failing (no network yet, primary
/// unreachable, daemon killed mid-request). A failed push leaves the row
/// `pending`, which [`retry_pending_delegations`] picks up on the next
/// tick.
pub(crate) async fn delegate_send(
    state: &AppState,
    linked: &LinkedAccount,
    conversation_id: &str,
    req: SendMessageRequest,
) -> Result<SendMessageResponse, StatusCode> {
    let conversation = state
        .db()
        .get_conversation(conversation_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let reference = conversation_ref(&conversation).ok_or(StatusCode::BAD_REQUEST)?;

    // The request id doubles as the message id — see the module doc on
    // why that is what makes retrying safe.
    let request_id = uuid::Uuid::new_v4().to_string();
    let sent_at = now();
    let expires_at = state
        .db()
        .compute_message_expiry(conversation_id, sent_at)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let message = Message {
        message_id: request_id.clone(),
        conversation_id: conversation_id.to_string(),
        sender_contact_id: None,
        body: Some(req.body.clone()),
        sent_at,
        received_at: None,
        expires_at,
        deleted_at: None,
        reply_to_message_id: req.reply_to_message_id.clone(),
        edited_at: None,
    };
    state
        .db()
        .insert_group_message(&message)
        .map_err(|e| match e {
            bh_storage::StorageError::Forbidden(_) => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        })?;
    state
        .db()
        .upsert_delegated_send(&request_id, DelegationState::Pending, None, sent_at)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    push_outbound_request(
        state,
        linked,
        &request_id,
        &reference,
        &req.body,
        req.reply_to_message_id.as_deref(),
    )
    .await;

    Ok(SendMessageResponse { message })
}

/// Pushes one `OutboundRequest` to the primary's mailbox. Best-effort by
/// design — the caller has already persisted the message, so a failure
/// here is a delay, not a loss.
async fn push_outbound_request(
    state: &AppState,
    linked: &LinkedAccount,
    request_id: &str,
    reference: &ConversationRef,
    body: &str,
    reply_to_message_id: Option<&str>,
) {
    let Some(network) = state.network.as_ref() else {
        tracing::debug!(%request_id, "delegated send stored, no live network to reach the primary");
        return;
    };
    let primary = match crate::device_role::ensure_pseudo_contact(
        state,
        linked.account_public_key.clone(),
        "primary device",
    ) {
        Ok(contact) => contact,
        Err(err) => {
            tracing::warn!(
                ?err,
                "delegated send: cannot materialize the primary's contact row"
            );
            return;
        }
    };

    let envelope = Envelope::OutboundRequest {
        request_id: request_id.to_string(),
        conversation: reference.clone(),
        body: body.to_string(),
        reply_to_message_id: reply_to_message_id.map(str::to_string),
    };
    let Ok(bytes) = envelope.encode() else {
        return;
    };
    if let Err(err) = crate::message_crypto::send_encrypted_over_network(
        state, network, &primary, request_id, &bytes,
    )
    .await
    {
        tracing::warn!(?err, %request_id, "delegated send: push to the primary's mailbox failed");
    }
}

/// Re-pushes delegated sends still waiting on an answer. Called from the
/// secondary's receive tick, so "the primary came back online" is enough
/// to drain a backlog with no user action.
pub async fn retry_pending_delegations(state: &AppState, linked: &LinkedAccount) {
    let Ok(pending) = state.db().list_pending_delegated_sends(RETRY_BATCH) else {
        return;
    };
    for entry in pending {
        let Ok(Some(message)) = state.db().get_message(&entry.message_id) else {
            continue;
        };
        let Ok(Some(conversation)) = state.db().get_conversation(&message.conversation_id) else {
            continue;
        };
        let Some(reference) = conversation_ref(&conversation) else {
            continue;
        };
        push_outbound_request(
            state,
            linked,
            &entry.message_id,
            &reference,
            message.body.as_deref().unwrap_or_default(),
            message.reply_to_message_id.as_deref(),
        )
        .await;
    }
}

/// The primary side of a delegated send.
///
/// `device_contact` is the pseudo-contact for the secondary that asked
/// (`device_role::own_device_pseudo_contact`), which is also where the
/// answer is sent. Never propagates an error to its caller: the receive
/// loop must keep draining the mailbox, and a refusal is reported to the
/// secondary as an `OutboundResult` rather than dropped.
pub(crate) async fn handle_outbound_request(
    state: &AppState,
    device_contact: &Contact,
    request_id: String,
    reference: ConversationRef,
    body: String,
    reply_to_message_id: Option<String>,
) {
    // Idempotency, checked against the database rather than memory: a
    // request whose message already exists was already carried out, so
    // re-answer instead of sending a duplicate.
    if let Ok(Some(_)) = state.db().get_message(&request_id) {
        answer(
            state,
            device_contact,
            &request_id,
            Some(request_id.clone()),
            None,
        )
        .await;
        return;
    }

    match perform_delegated_send(state, &request_id, reference, body, reply_to_message_id).await {
        Ok(message_id) => answer(state, device_contact, &request_id, Some(message_id), None).await,
        // Transient: this device is online enough to have read the
        // request but could not reach the network to carry it out (a DHT
        // lookup that hasn't converged, the recipient's prekey bundle not
        // published yet). Deliberately *not* answered — an
        // `OutboundResult` carrying an error is final, and reporting a
        // permanent failure for something that will work in ten seconds
        // would strand a message the user actually sent. Staying silent
        // leaves the secondary's row `pending`, and its retry sweep
        // re-pushes the same `request_id`, which the idempotency check
        // above makes safe to process again.
        Err(StatusCode::SERVICE_UNAVAILABLE) => {
            tracing::debug!(
                %request_id,
                "delegated send could not reach the network yet; leaving it for the device to retry"
            );
        }
        Err(status) => {
            let reason = describe_refusal(status);
            tracing::info!(%request_id, %reason, "refused a delegated send from a linked device");
            answer(state, device_contact, &request_id, None, Some(reason)).await
        }
    }
}

async fn perform_delegated_send(
    state: &AppState,
    request_id: &str,
    reference: ConversationRef,
    body: String,
    reply_to_message_id: Option<String>,
) -> Result<String, StatusCode> {
    // `create_missing_group_as_placeholder: false` — a primary asked to
    // post to a group it has no conversation for is a genuine refusal
    // (it was removed, or never joined), not something to paper over by
    // inventing a stateless group row.
    let conversation = resolve_conversation(state, &reference, false)?;

    // A quote-reply id is meaningful across devices only because message
    // ids are mirrored verbatim — but the secondary may still name a
    // message this device purged (a disappearing-message timer fired
    // here first). Dropping the reference beats failing the whole send on
    // a foreign key.
    let reply_to_message_id =
        reply_to_message_id.filter(|id| matches!(state.db().get_message(id), Ok(Some(_))));

    let response = crate::conversations::send_message_inner(
        state,
        &conversation.conversation_id,
        SendMessageRequest {
            body,
            reply_to_message_id,
            sender_contact_id: None,
        },
        Some(request_id.to_string()),
    )
    .await?;
    Ok(response.message.message_id)
}

/// Turns the refusal into something a human reads on the other device.
/// Deliberately coarse: the secondary is the user's own device, but the
/// text still crosses the network, so it names the rule that was hit and
/// nothing about who else is involved.
fn describe_refusal(status: StatusCode) -> String {
    match status {
        StatusCode::NOT_FOUND => "conversation not available on the primary device".to_string(),
        StatusCode::FORBIDDEN => "not allowed to post in this conversation".to_string(),
        other => format!("the primary device could not send this ({other})"),
    }
}

async fn answer(
    state: &AppState,
    device_contact: &Contact,
    request_id: &str,
    message_id: Option<String>,
    error: Option<String>,
) {
    let Some(network) = state.network.as_ref() else {
        return;
    };
    let envelope = Envelope::OutboundResult {
        request_id: request_id.to_string(),
        message_id,
        error,
    };
    let Ok(bytes) = envelope.encode() else {
        return;
    };
    // A distinct mailbox entry id from the request's, or this push would
    // collide with the request the secondary already stored under
    // `request_id`.
    let entry_id = format!("{request_id}-result");
    if let Err(err) = crate::message_crypto::send_encrypted_over_network(
        state,
        network,
        device_contact,
        &entry_id,
        &bytes,
    )
    .await
    {
        tracing::warn!(?err, %request_id, "failed to answer a delegated send");
    }
}

/// The secondary side of the answer: promote the pending row, or mark it
/// failed with the primary's reason.
pub(crate) fn handle_outbound_result(state: &AppState, request_id: &str, error: Option<String>) {
    let (delegation_state, reason) = match &error {
        None => (DelegationState::Sent, None),
        Some(reason) => (DelegationState::Failed, Some(reason.as_str())),
    };
    if let Err(err) = state
        .db()
        .upsert_delegated_send(request_id, delegation_state, reason, now())
    {
        tracing::warn!(%err, %request_id, "failed to record a delegated send's outcome");
    }
}
