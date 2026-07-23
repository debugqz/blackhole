//! Publishes/fetches this identity's MLS key package via the DHT, keyed by
//! the same recipient-key-hash convention [`Mailbox`](crate::mailbox::Mailbox)
//! and [`prekey_directory`](crate::prekey_directory) already use (SHA-256
//! over `signing_key || agreement_key` — `bh_crypto::identity::
//! recipient_key_hash`). Structurally a copy of `prekey_directory.rs`: a
//! single-value DHT publish/lookup, deliberately agnostic of the key
//! package's own byte format.
//!
//! **A published key package is single-use, and the caller must republish
//! immediately after it's consumed, not just periodically.** Unlike an
//! X3DH signed prekey (safely reusable across many sessions — see
//! `own_prekey.rs`), `openmls` deletes/invalidates a key package's local
//! HPKE private material the moment it's used to join a group
//! (`bh_crypto::mls`'s `a_consumed_key_package_cannot_be_reused_to_join_a_
//! second_group` test documents exactly this). So this is a "one
//! available key at a time" directory, not a "last-resort key" in
//! `PreKeyBundle`'s reusable sense — a real deployment would want each
//! `add_member` to consume a distinct one-time key package (typically via
//! a key-package *server* handing out tickets), which this DHT-record
//! approach doesn't provide: if two `add_member` calls for two different
//! groups fetch the same currently-published record before the owner
//! republishes a fresh one, only the first `join_group` succeeds — the
//! second fails outright (not just "stale"). Documented, accepted residual
//! for v1, same spirit as `own_prekey.rs`'s "no one-time prekeys" trade.

use crate::dht::Dht;
use crate::NetworkError;

fn key_package_key(recipient_key_hash: &[u8]) -> Vec<u8> {
    let mut k = b"bh-mls-keypackage:".to_vec();
    k.extend_from_slice(recipient_key_hash);
    k
}

/// Publishes (or replaces) the caller's own serialized MLS key package.
/// Callers must call this again after every successful `join_group` this
/// identity performs (the just-published record was just consumed) — see
/// module doc.
pub async fn publish_own_key_package(
    dht: &Dht,
    recipient_key_hash: &[u8],
    key_package_bytes: Vec<u8>,
) -> Result<(), NetworkError> {
    dht.publish(&key_package_key(recipient_key_hash), key_package_bytes)
        .await
}

/// Fetches a contact's currently-published key package bytes, if any node
/// currently holds one for their `recipient_key_hash`.
pub async fn fetch_key_package(
    dht: &Dht,
    recipient_key_hash: &[u8],
) -> Result<Option<Vec<u8>>, NetworkError> {
    dht.lookup(&key_package_key(recipient_key_hash)).await
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
    async fn a_fetcher_sees_a_key_package_published_by_someone_else() {
        let (publisher_dht, fetcher_dht) = connected_pair().await;
        let recipient_key = b"some-identity-key-hash";

        publish_own_key_package(
            &publisher_dht,
            recipient_key,
            b"fake key package bytes".to_vec(),
        )
        .await
        .unwrap();

        let fetched = fetch_key_package(&fetcher_dht, recipient_key)
            .await
            .unwrap();
        assert_eq!(fetched, Some(b"fake key package bytes".to_vec()));
    }

    #[tokio::test]
    async fn fetching_an_unpublished_key_returns_none() {
        let (_publisher_dht, fetcher_dht) = connected_pair().await;
        let fetched = fetch_key_package(&fetcher_dht, b"nobody-published-this")
            .await
            .unwrap();
        assert_eq!(fetched, None);
    }

    #[tokio::test]
    async fn republishing_replaces_the_previous_key_package() {
        let (publisher_dht, fetcher_dht) = connected_pair().await;
        let recipient_key = b"rotating-identity";

        publish_own_key_package(&publisher_dht, recipient_key, b"first".to_vec())
            .await
            .unwrap();
        publish_own_key_package(&publisher_dht, recipient_key, b"second".to_vec())
            .await
            .unwrap();

        let fetched = fetch_key_package(&fetcher_dht, recipient_key)
            .await
            .unwrap();
        assert_eq!(fetched, Some(b"second".to_vec()));
    }
}
