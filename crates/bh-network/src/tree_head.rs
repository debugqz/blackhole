//! Publishes/fetches an identity's own signed Key Transparency tree head
//! via the DHT (`docs/THREAT_MODEL.md` §3.1) — closes the "no deployed
//! gossip" gap `bh_crypto::key_transparency`'s own module doc names.
//! Same shape as `prekey_directory.rs`: publish/replace your own value
//! under a well-known key derived from your identity, others fetch it.
//! No read-merge-write retry needed here (unlike `mailbox.rs`'s
//! manifests) — only the identity that owns a tree head ever publishes
//! to its key, so there's no concurrent-writer race to guard against,
//! just last-write-wins on a single writer's own record.

use bh_crypto::key_transparency::SignedTreeHead;

use crate::dht::Dht;
use crate::NetworkError;

fn tree_head_key(identity_public_key: &[u8]) -> Vec<u8> {
    let mut k = b"bh-tree-head:".to_vec();
    k.extend_from_slice(identity_public_key);
    k
}

// `signature` travels as `Vec<u8>` rather than `[u8; 64]` — `serde`'s
// built-in array support doesn't cover arrays this large, same reason
// `bh_network::sealed_sender::SealedContent` stores its signature as
// `Vec<u8>` rather than a fixed array.
#[derive(serde::Serialize, serde::Deserialize)]
struct WireSignedTreeHead {
    size: u64,
    root: [u8; 32],
    timestamp: i64,
    signer_public_key: [u8; 32],
    signature: Vec<u8>,
}

impl From<&SignedTreeHead> for WireSignedTreeHead {
    fn from(sth: &SignedTreeHead) -> Self {
        Self {
            size: sth.size,
            root: sth.root,
            timestamp: sth.timestamp,
            signer_public_key: sth.signer_public_key,
            signature: sth.signature.to_vec(),
        }
    }
}

impl TryFrom<WireSignedTreeHead> for SignedTreeHead {
    type Error = NetworkError;

    fn try_from(w: WireSignedTreeHead) -> Result<Self, NetworkError> {
        let signature: [u8; 64] = w.signature.try_into().map_err(|_| {
            NetworkError::Query("tree_head: signature has the wrong length".to_string())
        })?;
        Ok(Self {
            size: w.size,
            root: w.root,
            timestamp: w.timestamp,
            signer_public_key: w.signer_public_key,
            signature,
        })
    }
}

/// Publishes (or replaces) `sth` under its own signer's well-known DHT
/// key. Callers should re-publish periodically (Kademlia records expire —
/// same caveat `prekey_directory::publish_own_bundle`'s doc comment
/// already states) and only when the tree head actually advanced, to
/// avoid a redundant write every tick.
pub async fn publish_tree_head(dht: &Dht, sth: &SignedTreeHead) -> Result<(), NetworkError> {
    let bytes = serde_json::to_vec(&WireSignedTreeHead::from(sth))?;
    dht.publish(&tree_head_key(&sth.signer_public_key), bytes)
        .await
}

/// Fetches the tree head an identity most recently published, if any.
/// Does **not** verify the signature — that's the caller's job
/// (`bh_crypto::key_transparency::verify_tree_head`), since this module
/// only moves bytes in and out of a DHT record, same division of labor as
/// `prekey_directory.rs`.
pub async fn fetch_tree_head(
    dht: &Dht,
    identity_public_key: &[u8],
) -> Result<Option<SignedTreeHead>, NetworkError> {
    let Some(bytes) = dht.lookup(&tree_head_key(identity_public_key)).await? else {
        return Ok(None);
    };
    let wire: WireSignedTreeHead = serde_json::from_slice(&bytes)?;
    Ok(Some(wire.try_into()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bh_crypto::identity::IdentityKeyPair;
    use bh_crypto::key_transparency::{sign_tree_head, verify_tree_head};
    use std::time::Duration;

    use crate::transport::Node;

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
    async fn a_fetcher_sees_and_can_verify_a_tree_head_published_by_someone_else() {
        let (publisher_dht, fetcher_dht) = connected_pair().await;
        let identity = IdentityKeyPair::generate().unwrap();
        let sth = sign_tree_head(&identity, 3, [7u8; 32], 1_700_000_000);

        publish_tree_head(&publisher_dht, &sth).await.unwrap();

        let fetched = fetch_tree_head(&fetcher_dht, &sth.signer_public_key)
            .await
            .unwrap()
            .expect("tree head should have been published");
        assert_eq!(fetched, sth);
        assert!(verify_tree_head(&fetched));
    }

    #[tokio::test]
    async fn fetching_an_identity_that_never_published_returns_none() {
        let (_publisher_dht, fetcher_dht) = connected_pair().await;
        let fetched = fetch_tree_head(&fetcher_dht, b"nobody-published-this-key-000000")
            .await
            .unwrap();
        assert_eq!(fetched, None);
    }

    #[tokio::test]
    async fn republishing_a_newer_tree_head_replaces_the_old_one() {
        let (publisher_dht, fetcher_dht) = connected_pair().await;
        let identity = IdentityKeyPair::generate().unwrap();
        let first = sign_tree_head(&identity, 3, [1u8; 32], 1_700_000_000);
        let second = sign_tree_head(&identity, 5, [2u8; 32], 1_700_000_100);

        publish_tree_head(&publisher_dht, &first).await.unwrap();
        publish_tree_head(&publisher_dht, &second).await.unwrap();

        let fetched = fetch_tree_head(&fetcher_dht, &identity.public_signing_key().to_bytes())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched, second);
    }
}
