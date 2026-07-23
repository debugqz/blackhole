//! Publishes/fetches a `bh_crypto::push_relay::PushRelayRecord`'s bytes via
//! the DHT, keyed by the same recipient-key-hash convention
//! [`Mailbox`](crate::mailbox::Mailbox)/[`prekey_directory`](crate::prekey_directory)
//! use. The counterpart directory to `prekey_directory` for SPEC.md §5.6's
//! opt-in push-relay wake notifications: `bh-api`'s message-send path
//! fetches a recipient's record here (if any) after a successful mailbox
//! push, to learn where/how to call `POST {relay_url}/wake/{token}`.
//!
//! Deliberately agnostic of the record's structure — same "opaque bytes in,
//! opaque bytes out" split `prekey_directory` already establishes;
//! encoding/decoding and signature verification are
//! `bh_crypto::push_relay::PushRelayRecord`'s job.
//!
//! Reusable/updatable, not single-use, like `prekey_directory` (contrast
//! `key_package_directory`'s single-use model) — publishing again simply
//! replaces the previous record. Kademlia records expire, so a long-lived
//! daemon should republish periodically, not just once at startup (see the
//! daemon's own call site for the interval).

use crate::dht::Dht;
use crate::NetworkError;

fn registration_key(recipient_key_hash: &[u8]) -> Vec<u8> {
    let mut k = b"bh-push-relay:".to_vec();
    k.extend_from_slice(recipient_key_hash);
    k
}

/// Publishes (or replaces) the caller's own serialized `PushRelayRecord` so
/// a contact can fetch it to learn how to wake this identity up.
pub async fn publish_own_registration(
    dht: &Dht,
    recipient_key_hash: &[u8],
    record_bytes: Vec<u8>,
) -> Result<(), NetworkError> {
    dht.publish(&registration_key(recipient_key_hash), record_bytes)
        .await
}

/// Fetches a contact's published push-relay record bytes, if any node
/// currently holds one for their `recipient_key_hash`.
pub async fn fetch_registration(
    dht: &Dht,
    recipient_key_hash: &[u8],
) -> Result<Option<Vec<u8>>, NetworkError> {
    dht.lookup(&registration_key(recipient_key_hash)).await
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
    async fn a_fetcher_sees_a_registration_published_by_someone_else() {
        let (publisher_dht, fetcher_dht) = connected_pair().await;
        let recipient_key = b"some-identity-key-hash";

        publish_own_registration(&publisher_dht, recipient_key, b"fake record bytes".to_vec())
            .await
            .unwrap();

        let fetched = fetch_registration(&fetcher_dht, recipient_key)
            .await
            .unwrap();
        assert_eq!(fetched, Some(b"fake record bytes".to_vec()));
    }

    #[tokio::test]
    async fn fetching_an_unpublished_key_returns_none() {
        let (_publisher_dht, fetcher_dht) = connected_pair().await;
        let fetched = fetch_registration(&fetcher_dht, b"nobody-published-this")
            .await
            .unwrap();
        assert_eq!(fetched, None);
    }

    #[tokio::test]
    async fn republishing_replaces_the_previous_registration() {
        let (publisher_dht, fetcher_dht) = connected_pair().await;
        let recipient_key = b"some-identity-key-hash";

        publish_own_registration(&publisher_dht, recipient_key, b"first".to_vec())
            .await
            .unwrap();
        publish_own_registration(&publisher_dht, recipient_key, b"second".to_vec())
            .await
            .unwrap();

        let fetched = fetch_registration(&fetcher_dht, recipient_key)
            .await
            .unwrap();
        assert_eq!(fetched, Some(b"second".to_vec()));
    }
}
