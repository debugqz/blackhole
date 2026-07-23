//! Own MLS key-package bootstrap/publish (SPEC.md §5.4) — the group-
//! membership counterpart to `message_crypto.rs`'s own-prekey-bundle
//! handling. See `bh_storage::models::OwnMlsKeyPackage`'s doc comment and
//! `bh_network::key_package_directory`'s module doc for why this is a
//! **single-use** record that must be *replaced*, not just periodically
//! refreshed, every time it's actually consumed by a real `join_group`
//! this identity performs (`message_receive.rs`'s `Envelope::GroupInvite`
//! handling calls [`regenerate_and_publish_own_key_package`] right after).

use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use bh_crypto::identity::recipient_key_hash;
use bh_crypto::mls::MlsMember;
use bh_network::key_package_directory;
use bh_network::supervised::SupervisedNetwork;
use bh_storage::models::OwnMlsKeyPackage;

use crate::AppState;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

/// Generates a brand-new key package (a fresh `MlsMember`/signer — any
/// previous one is abandoned, matching the single-use semantics the module
/// doc describes), persists it, and publishes it to the DHT.
pub(crate) async fn regenerate_and_publish_own_key_package(
    state: &AppState,
    network: &SupervisedNetwork,
) -> Result<(), StatusCode> {
    let own = state
        .db()
        .get_own_identity()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::PRECONDITION_FAILED)?;
    let provider = state
        .mls_provider()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let member = MlsMember::new_persistent(&own.identity_public_key, provider)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let key_package_bytes = member
        .generate_key_package()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .db()
        .set_own_mls_key_package(&OwnMlsKeyPackage {
            signer_public_key: member.signature_public_key(),
            key_package_bytes: key_package_bytes.clone(),
            created_at: now(),
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let key_hash = recipient_key_hash(&own.identity_public_key);
    key_package_directory::publish_own_key_package(&network.dht(), &key_hash, key_package_bytes)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(())
}

/// Best-effort: republishes whatever key package is already on record, or
/// bootstraps a fresh one if none exists yet — same "Kademlia records
/// expire, a long-lived daemon needs to periodically republish" reasoning
/// `message_crypto::publish_own_bundle_best_effort` already documents.
/// Failures are logged, not propagated — a transient DHT hiccup here
/// shouldn't fail whatever the caller (the receive loop's periodic tick)
/// was actually doing.
pub(crate) async fn publish_own_key_package_best_effort(
    state: &AppState,
    network: &SupervisedNetwork,
) {
    let existing = state.db().get_own_mls_key_package().ok().flatten();
    match existing {
        Some(kp) => {
            let Ok(Some(own)) = state.db().get_own_identity() else {
                return;
            };
            let key_hash = recipient_key_hash(&own.identity_public_key);
            if let Err(err) = key_package_directory::publish_own_key_package(
                &network.dht(),
                &key_hash,
                kp.key_package_bytes,
            )
            .await
            {
                tracing::warn!(%err, "failed to republish own MLS key package");
            }
        }
        None => {
            if let Err(err) = regenerate_and_publish_own_key_package(state, network).await {
                tracing::warn!(?err, "failed to bootstrap own MLS key package");
            }
        }
    }
}
