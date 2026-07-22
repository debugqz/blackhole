//! Publishes/fetches X3DH prekey bundles via the DHT, keyed by the same
//! recipient-key-hash convention [`Mailbox`](crate::mailbox::Mailbox) uses
//! for messages (SHA-256 over an identity's `signing_key || agreement_key`
//! bytes — see `bh_crypto::identity::recipient_key_hash`). This is exactly
//! what `bh_crypto::ratchet::PreKeyBundle`'s own doc comment already
//! anticipates (SPEC.md §5.3): "the network is where this actually gets
//! published/fetched."
//!
//! Deliberately agnostic of `PreKeyBundle`'s structure — this module just
//! moves opaque bytes in and out of a DHT record; encoding/decoding and
//! signature verification are `bh-crypto::ratchet`'s job (`to_bytes`/
//! `from_bytes`/`x3dh_initiate`'s internal `verify_signed_prekey`).

use crate::dht::Dht;
use crate::NetworkError;

fn bundle_key(recipient_key_hash: &[u8]) -> Vec<u8> {
    let mut k = b"bh-prekey-bundle:".to_vec();
    k.extend_from_slice(recipient_key_hash);
    k
}

/// Publishes (or replaces) the caller's own serialized `PreKeyBundle` so a
/// contact can fetch it to start a session, including after this identity
/// has been offline since a previous publish (Kademlia records expire —
/// callers on a long-lived daemon should call this periodically, not just
/// once at startup; see the daemon's own call site for the interval).
pub async fn publish_own_bundle(
    dht: &Dht,
    recipient_key_hash: &[u8],
    bundle_bytes: Vec<u8>,
) -> Result<(), NetworkError> {
    dht.publish(&bundle_key(recipient_key_hash), bundle_bytes)
        .await
}

/// Fetches a contact's published bundle bytes, if any node currently holds
/// one for their `recipient_key_hash`.
pub async fn fetch_bundle(
    dht: &Dht,
    recipient_key_hash: &[u8],
) -> Result<Option<Vec<u8>>, NetworkError> {
    dht.lookup(&bundle_key(recipient_key_hash)).await
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
    async fn a_fetcher_sees_a_bundle_published_by_someone_else() {
        let (publisher_dht, fetcher_dht) = connected_pair().await;
        let recipient_key = b"some-identity-key-hash";

        publish_own_bundle(&publisher_dht, recipient_key, b"fake bundle bytes".to_vec())
            .await
            .unwrap();

        let fetched = fetch_bundle(&fetcher_dht, recipient_key).await.unwrap();
        assert_eq!(fetched, Some(b"fake bundle bytes".to_vec()));
    }

    #[tokio::test]
    async fn fetching_an_unpublished_key_returns_none() {
        let (_publisher_dht, fetcher_dht) = connected_pair().await;
        let fetched = fetch_bundle(&fetcher_dht, b"nobody-published-this")
            .await
            .unwrap();
        assert_eq!(fetched, None);
    }
}
