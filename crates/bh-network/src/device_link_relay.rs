//! One-shot bootstrap relay for real cross-process device linking
//! (SPEC.md §4) — single-value DHT publish/lookup, structurally like
//! `prekey_directory.rs`, but for the two ciphertexts
//! `bh_crypto::device_link`'s 4-step ceremony exchanges before either side
//! has an established session to route through (there's no X3DH session
//! yet — that's exactly what this ceremony bootstraps). Two independent
//! key namespaces, since the two ciphertexts are addressed differently:
//!
//! - The new device's [`ProvisioningRequest`](bh_crypto::device_link::ProvisioningRequest)
//!   is addressed to the **primary's** long-term identity
//!   (`bh_crypto::identity::recipient_key_hash` over the primary's real
//!   `identity_public_key`, embedded in the link/QR the primary shows —
//!   see `bh_crypto::device_link::LinkingSession::link`'s doc comment).
//! - The primary's response is addressed to the **new device's ephemeral
//!   linking key** (`recipient_key_hash` over the raw 32-byte X25519
//!   public key from `LinkingSession::begin`/`NewDevice::scan` — the only
//!   identifier the new device has before the account identity is
//!   transferred).
//!
//! **Unauthenticated by identity, by construction** — accepted residual,
//! not an oversight: whoever publishes a request at a given primary's key
//! hash is trusted exactly as much as whoever scans that primary's QR
//! code in the real, in-person ceremony this digitizes. The AEAD
//! encryption on both ciphertexts (keyed by the ECDH shared secret
//! between the primary's session-ephemeral key and the new device's own
//! ephemeral key) is what actually gates trust here, the same as it does
//! in the pre-existing same-daemon simulation — this module only moves
//! opaque bytes, exactly like `prekey_directory`/`key_package_directory`.

use crate::dht::Dht;
use crate::NetworkError;

fn request_key(primary_key_hash: &[u8]) -> Vec<u8> {
    let mut k = b"bh-device-link-request:".to_vec();
    k.extend_from_slice(primary_key_hash);
    k
}

fn response_key(new_device_ephemeral_key_hash: &[u8]) -> Vec<u8> {
    let mut k = b"bh-device-link-response:".to_vec();
    k.extend_from_slice(new_device_ephemeral_key_hash);
    k
}

/// The new device publishes its `ProvisioningRequest` bytes here, keyed by
/// the primary's identity (decoded from the scanned link).
pub async fn publish_request(
    dht: &Dht,
    primary_key_hash: &[u8],
    request_bytes: Vec<u8>,
) -> Result<(), NetworkError> {
    dht.publish(&request_key(primary_key_hash), request_bytes)
        .await
}

/// The primary polls this, keyed by its own identity, to find a real
/// device's provisioning request.
pub async fn fetch_request(
    dht: &Dht,
    primary_key_hash: &[u8],
) -> Result<Option<Vec<u8>>, NetworkError> {
    dht.lookup(&request_key(primary_key_hash)).await
}

/// The primary publishes its response ciphertext here, keyed by the new
/// device's ephemeral linking key.
pub async fn publish_response(
    dht: &Dht,
    new_device_ephemeral_key_hash: &[u8],
    response_bytes: Vec<u8>,
) -> Result<(), NetworkError> {
    dht.publish(&response_key(new_device_ephemeral_key_hash), response_bytes)
        .await
}

/// The new device polls this, keyed by its own ephemeral linking key, to
/// find the primary's response completing the link.
pub async fn fetch_response(
    dht: &Dht,
    new_device_ephemeral_key_hash: &[u8],
) -> Result<Option<Vec<u8>>, NetworkError> {
    dht.lookup(&response_key(new_device_ephemeral_key_hash))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Node;
    use std::time::Duration;

    async fn connected_pair() -> (Dht, Dht) {
        let node_a = Node::spawn("/ip4/127.0.0.1/tcp/0").await.unwrap();
        let node_b = Node::spawn("/ip4/127.0.0.1/tcp/0").await.unwrap();
        let addr_a = node_a
            .listen_addrs()
            .await
            .into_iter()
            .next()
            .unwrap()
            .with_p2p(node_a.peer_id())
            .unwrap();
        node_b.dial(addr_a).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        (Dht::new(node_a), Dht::new(node_b))
    }

    #[tokio::test]
    async fn a_fetcher_sees_a_request_published_by_someone_else() {
        let (publisher_dht, fetcher_dht) = connected_pair().await;
        let primary_key_hash = b"some-primary-identity-hash";

        publish_request(&publisher_dht, primary_key_hash, b"fake request".to_vec())
            .await
            .unwrap();

        let fetched = fetch_request(&fetcher_dht, primary_key_hash).await.unwrap();
        assert_eq!(fetched, Some(b"fake request".to_vec()));
    }

    #[tokio::test]
    async fn a_fetcher_sees_a_response_published_by_someone_else() {
        let (publisher_dht, fetcher_dht) = connected_pair().await;
        let device_ephemeral_hash = b"some-device-ephemeral-hash";

        publish_response(
            &publisher_dht,
            device_ephemeral_hash,
            b"fake response".to_vec(),
        )
        .await
        .unwrap();

        let fetched = fetch_response(&fetcher_dht, device_ephemeral_hash)
            .await
            .unwrap();
        assert_eq!(fetched, Some(b"fake response".to_vec()));
    }

    #[tokio::test]
    async fn requests_and_responses_occupy_independent_namespaces() {
        let (publisher_dht, fetcher_dht) = connected_pair().await;
        let same_bytes_key = b"shared-key-bytes";

        publish_request(&publisher_dht, same_bytes_key, b"request payload".to_vec())
            .await
            .unwrap();
        publish_response(&publisher_dht, same_bytes_key, b"response payload".to_vec())
            .await
            .unwrap();

        assert_eq!(
            fetch_request(&fetcher_dht, same_bytes_key).await.unwrap(),
            Some(b"request payload".to_vec())
        );
        assert_eq!(
            fetch_response(&fetcher_dht, same_bytes_key).await.unwrap(),
            Some(b"response payload".to_vec())
        );
    }
}
