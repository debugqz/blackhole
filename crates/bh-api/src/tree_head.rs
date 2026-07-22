//! Publishes this profile's own Key Transparency tree head
//! (`docs/THREAT_MODEL.md` §3.1) whenever there's a live network to
//! publish it to. Blackhole identities don't rotate their signing key
//! today (SPEC.md — one long-term identity key, generated once at
//! bootstrap), so the "log" for any one identity is always exactly one
//! leaf: this module computes that single-leaf tree head on the fly from
//! `OwnIdentity` rather than maintaining a separate persisted leaf log
//! that would only ever hold one row.
//!
//! Best-effort throughout: no live network, no identity yet, or a
//! transient DHT failure all just mean "nothing published this time,
//! try again next tick" — never a hard error surfaced to an HTTP caller.
//! Same posture as `message_crypto.rs`'s network calls degrading to
//! local-storage-only behavior when `state.network` is `None`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bh_crypto::identity::IdentityKeyPair;
use bh_crypto::key_transparency::{entry_hash, sign_tree_head, tree_hash, verify_tree_head};
use bh_network::supervised::SupervisedNetwork;
use bh_network::tree_head::{fetch_tree_head, publish_tree_head};

use crate::AppState;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

/// Publishes the currently-active profile's own tree head, if this daemon
/// has both an identity and a live network attached. Logs and returns on
/// any failure rather than propagating one — see the module doc.
pub async fn publish_own_tree_head(state: &Arc<AppState>, network: &SupervisedNetwork) {
    let own_identity = match state.db().get_own_identity() {
        Ok(Some(identity)) => identity,
        Ok(None) => return,
        Err(err) => {
            tracing::debug!(%err, "tree_head: failed to read own identity, skipping this publish");
            return;
        }
    };
    let private_bytes: [u8; 64] = match own_identity.identity_private_key.as_slice().try_into() {
        Ok(bytes) => bytes,
        Err(_) => {
            tracing::warn!("tree_head: stored identity private key has the wrong length");
            return;
        }
    };
    let identity = match IdentityKeyPair::import_bytes(&private_bytes) {
        Ok(identity) => identity,
        Err(err) => {
            tracing::warn!(%err, "tree_head: failed to reconstruct identity keypair");
            return;
        }
    };

    let leaf = entry_hash(
        &own_identity.identity_public_key,
        &own_identity.identity_public_key,
        0,
    );
    let root = tree_hash(&[leaf]);
    let sth = sign_tree_head(&identity, 1, root, now());

    if let Err(err) = publish_tree_head(&network.dht(), &sth).await {
        tracing::debug!(%err, "tree_head: publish failed, will retry next tick");
    }
}

/// Best-effort corroboration for a contact's claimed identity key,
/// alongside (never instead of) manual safety-number comparison
/// (`safety_number.rs`). `contact_identity_public_key` is the packed
/// `signing(32) || agreement(32)` bytes `contacts::add_contact` already
/// expects.
///
/// `None` means "couldn't check" — no network attached, the contact has
/// never published a tree head, or a transient fetch failure — which is
/// just today's manual-verification-only status quo, not a red flag.
/// `Some(false)` means the fetched, *validly signed* tree head does not
/// match what this contact's own key would produce — a genuine signal
/// worth surfacing, since it means either this contact published a
/// different key than the one the caller has on file, or something
/// tampered with what got fetched.
pub async fn fetch_and_verify_contact(
    network: &SupervisedNetwork,
    contact_identity_public_key: &[u8],
) -> Option<bool> {
    if contact_identity_public_key.len() != 64 {
        return None;
    }
    let signing_pub = &contact_identity_public_key[..32];

    let sth = fetch_tree_head(&network.dht(), signing_pub).await.ok()??;
    if !verify_tree_head(&sth) || sth.signer_public_key.as_slice() != signing_pub {
        return Some(false);
    }

    let expected_leaf = entry_hash(contact_identity_public_key, contact_identity_public_key, 0);
    let expected_root = tree_hash(&[expected_leaf]);
    Some(sth.size == 1 && sth.root == expected_root)
}
