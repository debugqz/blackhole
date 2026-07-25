//! Which side of the primary/secondary split this daemon is on, and the
//! bookkeeping that follows from it.
//!
//! `device_link.rs` runs the linking *ceremony*; this module is what makes
//! its outcome durable. Before it existed, `finish_link` negotiated a real
//! per-device identity, returned it in an HTTP response, and dropped the
//! in-memory session — so a genuinely separate "new device" daemon
//! finished linking holding no trace of it. It had no `own_identity` (by
//! design — installing the account's would collide its `recipient_key_
//! hash` with the primary's), but also no identity of its own and no way
//! to address the primary, and `message_receive.rs` polls the mailbox of
//! `own_identity`, so that daemon listened to nothing at all.
//!
//! ## The role split
//!
//! A profile is **either**:
//!
//! - a **primary** — has `own_identity`, holds the account's real identity
//!   key, is the only device that ever runs a Double Ratchet session with
//!   a contact or touches MLS group state; or
//! - a **secondary** — has `linked_account` (`bh-storage::linked_account`),
//!   holds only its own per-device identity, and delegates every outbound
//!   message to the primary (`device_delegation.rs`).
//!
//! Never both, enforced in `Database::set_linked_account` rather than
//! merely documented here.
//!
//! ## Why a secondary can't just encrypt for itself
//!
//! Because the Double Ratchet is monotonic mutable state. `bh_crypto::
//! ratchet::Session` advances `sending_chain_key`/`send_count` on every
//! encrypt, and that state lives in one `sessions` row on one device. Two
//! devices sharing an account identity would each advance their own copy
//! and reuse message keys — a cryptographic break, not a synchronization
//! inconvenience. Keeping exactly one device in possession of that state
//! is the entire point of the hub model. See
//! `docs/superpowers/specs/2026-07-24-multidevice-delegation-design.md`.
//!
//! ## Addressing
//!
//! Nothing new had to be invented in either direction:
//!
//! - **secondary → primary**: the account identity *is* the primary's
//!   address, because the primary is the only device holding it. The
//!   secondary already receives that public key at `finish_link`, and the
//!   primary already publishes a prekey bundle for it.
//! - **primary → secondary**: `device_sync.rs` already addresses a linked
//!   device by `Device.public_key || Device.identity_agreement_key`, the
//!   same 64-byte layout `Contact.identity_public_key` uses.
//!
//! What both directions *do* need is a `contacts` row to hang a ratchet
//! session off (`sessions.contact_id` is `NOT NULL REFERENCES contacts`),
//! which is why this module materializes pseudo-contacts — the same trick
//! `device_sync.rs` already uses, applied symmetrically.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use bh_crypto::identity::IdentityKeyPair;
use bh_storage::models::{Contact, DeviceOwner, LinkedAccount};
use serde::{Deserialize, Serialize};

use crate::AppState;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

/// This daemon's linked-secondary record, if it has one.
pub(crate) fn linked_account(state: &AppState) -> Option<LinkedAccount> {
    state.db().get_linked_account().ok().flatten()
}

/// As [`linked_account`], but `None` once the primary has revoked this
/// device — every caller that is about to *act* as a secondary (delegate
/// a send, accept mirrored state) wants this one, not the raw row.
pub(crate) fn active_linked_account(state: &AppState) -> Option<LinkedAccount> {
    linked_account(state).filter(|l| l.revoked_at.is_none())
}

/// The identity this daemon actually speaks as on the network: the
/// account identity on a primary, this device's own identity on a
/// secondary.
///
/// Deliberately separate from `message_crypto::own_identity_keypair`
/// rather than replacing it. Most routes (identity bootstrap, safety
/// numbers, invites, group membership) are meaningful *only* for a
/// primary and should keep failing loudly on a secondary; only the two
/// call sites that are genuinely about "put bytes on the wire as whoever
/// I am" — the mailbox receive loop and `send_encrypted_over_network` —
/// use this.
pub(crate) fn acting_identity_keypair(state: &AppState) -> Result<IdentityKeyPair, StatusCode> {
    if let Ok(identity) = crate::message_crypto::own_identity_keypair(state) {
        return Ok(identity);
    }
    let linked = linked_account(state).ok_or(StatusCode::PRECONDITION_FAILED)?;
    let bytes: [u8; 64] = linked
        .device_private_key
        .as_slice()
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    IdentityKeyPair::import_bytes(&bytes).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// The `contacts.contact_id` used for a pseudo-contact standing in for an
/// identity known only by its public key — the hex of the signing half,
/// matching `device_link::accept_link`'s own `device_id` convention so
/// both devices derive the same string without exchanging it.
pub(crate) fn pseudo_contact_id(identity_public_key: &[u8]) -> String {
    hex::encode(&identity_public_key[..32.min(identity_public_key.len())])
}

/// Inserts a `contacts` row for an identity this profile needs a ratchet
/// session with but that isn't a real contact — the account (on a
/// secondary) or one of this account's own devices (on a primary).
///
/// Idempotent, and never overwrites an existing row: a real contact that
/// happened to share this id is impossible in practice (the id is a hex
/// public key, a disjoint namespace from the UUIDs `contacts.rs` mints),
/// but "insert only if missing" costs nothing and makes that reasoning
/// unnecessary. Marked with a bracketed display name so it is visibly not
/// a person if it ever surfaces in a contact list.
pub(crate) fn ensure_pseudo_contact(
    state: &AppState,
    identity_public_key: Vec<u8>,
    label: &str,
) -> Result<Contact, StatusCode> {
    let contact_id = pseudo_contact_id(&identity_public_key);
    if let Ok(Some(existing)) = state.db().get_contact(&contact_id) {
        return Ok(existing);
    }
    let contact = Contact {
        contact_id,
        identity_public_key,
        display_name: Some(format!("[{label}]")),
        verified: false,
        blocked: false,
        added_at: now(),
    };
    state
        .db()
        .upsert_contact(&contact)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(contact)
}

/// Records this daemon as a secondary of `account_public_key` and
/// materializes the pseudo-contact its inbound envelopes from the primary
/// will resolve against.
///
/// A no-op (logged, not an error) when this profile already has an
/// `own_identity`: that is the pre-existing same-daemon linking demo,
/// which drives both ceremony roles against one `AppState` and must keep
/// behaving exactly as it did instead of converting the profile into a
/// secondary of itself.
pub(crate) fn persist_secondary_role(
    state: &AppState,
    device_identity: &IdentityKeyPair,
    account_public_key: [u8; 64],
) -> Result<(), StatusCode> {
    if state
        .db()
        .get_own_identity()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .is_some()
    {
        tracing::debug!(
            "finish_link on a profile that already has its own identity — \
             same-daemon linking demo, not recording a secondary role"
        );
        return Ok(());
    }

    let device_public_key = device_identity.public_identity_bytes();
    let linked = LinkedAccount {
        device_id: hex::encode(&device_public_key[..32]),
        device_public_key: device_public_key.to_vec(),
        device_private_key: device_identity.export_bytes().to_vec(),
        account_public_key: account_public_key.to_vec(),
        linked_at: now(),
        revoked_at: None,
    };
    state
        .db()
        .set_linked_account(&linked)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // The primary reaches this device through the ordinary sealed-sender
    // path, so its envelopes arrive attributed to the *account's* signing
    // key. Without a row for it, `message_receive::process_one` would
    // classify every one of them as an unknown sender and pin them in the
    // mailbox forever.
    ensure_pseudo_contact(state, account_public_key.to_vec(), "primary device")?;
    Ok(())
}

/// Resolves a sealed-sender signing key to a pseudo-contact for one of
/// *this account's own* linked devices, materializing the row on first
/// use. Used by the primary's receive loop so a delegated send from a
/// secondary isn't treated as mail from a stranger.
///
/// Returns `None` for a device that has been revoked, which is what makes
/// revocation effective without depending on the revoked device
/// cooperating: `Envelope::DeviceRevoked` is a courtesy notification, not
/// the enforcement point.
/// Resolves a sealed-sender signing key to whichever pseudo-contact this
/// daemon needs internally: one of the account's own linked devices (on a
/// primary) or the account itself (on a secondary).
///
/// Materializing on demand rather than only at link time is deliberate. A
/// secondary whose `linked_account` row exists but whose pseudo-contact
/// row somehow doesn't — a partially-applied restore, a link recorded by
/// an older build, a database restored from backup — would otherwise
/// classify every envelope from its own primary as an unknown sender and
/// stay permanently deaf, with nothing in the UI to explain it. Deriving
/// the row from state already on disk makes that self-healing.
pub(crate) fn internal_pseudo_contact(
    state: &AppState,
    sender_signing_key: &[u8; 32],
) -> Option<Contact> {
    own_device_pseudo_contact(state, sender_signing_key)
        .or_else(|| primary_pseudo_contact(state, sender_signing_key))
}

/// The account this daemon is a secondary of, if `sender_signing_key` is
/// it. Matching on the *stored* account key is what makes this safe: an
/// arbitrary sender cannot become "the primary" by claiming to be.
fn primary_pseudo_contact(state: &AppState, sender_signing_key: &[u8; 32]) -> Option<Contact> {
    let linked = linked_account(state)?;
    if linked.account_public_key.len() < 32
        || &linked.account_public_key[..32] != sender_signing_key.as_slice()
    {
        return None;
    }
    ensure_pseudo_contact(state, linked.account_public_key.clone(), "primary device").ok()
}

pub(crate) fn own_device_pseudo_contact(
    state: &AppState,
    sender_signing_key: &[u8; 32],
) -> Option<Contact> {
    let device = state
        .db()
        .list_own_devices()
        .ok()?
        .into_iter()
        .filter(|d| d.owner == DeviceOwner::Own && d.revoked_at.is_none())
        .find(|d| d.public_key.as_slice() == sender_signing_key.as_slice())?;
    let agreement = device.identity_agreement_key?;
    let identity_public_key = [device.public_key.clone(), agreement].concat();
    ensure_pseudo_contact(
        state,
        identity_public_key,
        &format!("device {}", device.name.as_deref().unwrap_or("linked")),
    )
    .ok()
}

/// Whether `contact` is a pseudo-contact standing in for one of *this
/// account's own* linked devices that is still authorized.
///
/// This is the authorization gate for delegated sending, and it matters:
/// `Envelope::OutboundRequest` asks this daemon to encrypt and send under
/// the account's identity. Without this check any ordinary contact could
/// put that envelope in your mailbox and have your daemon send messages as
/// you. Being a known contact is emphatically not enough.
///
/// It is also where revocation actually takes effect. A revoked device
/// stops being able to delegate the moment its `devices` row is marked,
/// with no cooperation required from that device — `Envelope::
/// DeviceRevoked` merely lets it explain itself, and a revoked device that
/// never comes online still cannot act.
pub(crate) fn is_authorized_own_device(state: &AppState, contact: &Contact) -> bool {
    state
        .db()
        .list_own_devices()
        .map(|devices| {
            devices.iter().any(|d| {
                d.owner == DeviceOwner::Own
                    && d.revoked_at.is_none()
                    && contact.identity_public_key.len() >= 32
                    && d.public_key == contact.identity_public_key[..32]
            })
        })
        .unwrap_or(false)
}

/// Whether `contact` is the account's primary, as seen from a secondary.
///
/// The mirror image of [`is_authorized_own_device`], and needed for the
/// same reason: mirrored state (`ContactSync`, `DeviceSyncMessage`,
/// `DeviceRevoked`) is written into this device's database more or less
/// verbatim, so accepting it from anyone but the primary would let a
/// contact inject contacts, plant messages in arbitrary conversations, or
/// silence the device by faking a revocation.
pub(crate) fn is_primary_sender(state: &AppState, contact: &Contact) -> bool {
    linked_account(state)
        .is_some_and(|linked| linked.account_public_key == contact.identity_public_key)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceRoleResponse {
    /// `"primary"`, `"secondary"`, or `"unprovisioned"` (neither an
    /// identity nor a link yet — a freshly-created profile).
    pub role: String,
    /// Set for a secondary: the id the primary knows this device by.
    pub device_id: Option<String>,
    pub linked_at: Option<i64>,
    /// Set once the primary has revoked this device. A revoked secondary
    /// keeps its row (and this field) rather than silently reverting to a
    /// blank profile, so the client can explain why it stopped syncing.
    pub revoked_at: Option<i64>,
}

pub async fn get_role(State(state): State<Arc<AppState>>) -> Json<DeviceRoleResponse> {
    let has_identity = state.db().get_own_identity().ok().flatten().is_some();
    let linked = linked_account(&state);
    let role = match (has_identity, &linked) {
        (true, _) => "primary",
        (false, Some(_)) => "secondary",
        (false, None) => "unprovisioned",
    };
    Json(DeviceRoleResponse {
        role: role.to_string(),
        device_id: linked.as_ref().map(|l| l.device_id.clone()),
        linked_at: linked.as_ref().map(|l| l.linked_at),
        revoked_at: linked.as_ref().and_then(|l| l.revoked_at),
    })
}

/// Drops this device's secondary role from its own side.
///
/// Distinct from being revoked *by* the primary: that keeps the row so the
/// UI can explain the silence, whereas this is the user deliberately
/// returning the profile to a blank, re-linkable state. It does not (and
/// cannot) tell the primary to forget the device — the primary's own
/// `POST /devices/:id/revoke` is the authority on that side.
pub async fn unlink_self(State(state): State<Arc<AppState>>) -> Result<StatusCode, StatusCode> {
    if linked_account(&state).is_none() {
        return Err(StatusCode::PRECONDITION_FAILED);
    }
    state
        .db()
        .clear_linked_account()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}
