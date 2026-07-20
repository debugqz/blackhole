//! Store-and-forward offline messaging. Encrypted mailboxes on network
//! nodes, indexed by a hash of the recipient's public key (the node never
//! sees the real identity — that's the caller's job to hash, this module
//! just takes bytes). TTL-bounded with automatic expiry. The local daemon
//! pulls on reconnect, decrypts locally, and requests deletion of the
//! node's copy. Group sends fan out once to the group's key rather than
//! pushing individually per member — every member just pulls from the same
//! place. See `docs/SPEC.md` §5.3-5.4.
//!
//! **Known limitation**: this is built on the plain Kademlia
//! get/put-record primitives in `dht.rs`, which are single-writer,
//! last-write-wins per key. The per-recipient manifest here is
//! read-modify-written, so two sends to the same recipient racing at the
//! DHT level can lose one manifest update (the message record itself is
//! never lost, just possibly missing from the list that says to fetch it).
//! A real deployment needs either a CRDT-style mergeable manifest or a
//! dedicated mailbox-node protocol instead of raw DHT records — tracked as
//! a follow-up, not fixed here.

use serde::{Deserialize, Serialize};

use crate::dht::Dht;
use crate::NetworkError;

#[derive(Debug, Default, Serialize, Deserialize)]
struct Manifest {
    message_ids: Vec<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredMessage {
    ciphertext: Vec<u8>,
    expires_at: i64,
}

fn manifest_key(recipient_key_hash: &[u8]) -> Vec<u8> {
    let mut k = b"bh-mailbox:manifest:".to_vec();
    k.extend_from_slice(recipient_key_hash);
    k
}

fn message_key(recipient_key_hash: &[u8], message_id: &[u8]) -> Vec<u8> {
    let mut k = b"bh-mailbox:msg:".to_vec();
    k.extend_from_slice(recipient_key_hash);
    k.push(b':');
    k.extend_from_slice(message_id);
    k
}

pub struct Mailbox {
    dht: Dht,
}

impl Mailbox {
    pub fn new(dht: Dht) -> Self {
        Self { dht }
    }

    async fn fetch_manifest(&self, recipient_key_hash: &[u8]) -> Result<Manifest, NetworkError> {
        match self.dht.lookup(&manifest_key(recipient_key_hash)).await? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(Manifest::default()),
        }
    }

    /// Stores `ciphertext` for `recipient_key_hash`, expiring `ttl_seconds`
    /// after `now` (unix seconds — caller-supplied so this is testable
    /// without waiting in real time).
    pub async fn push(
        &self,
        recipient_key_hash: &[u8],
        message_id: &[u8],
        ciphertext: Vec<u8>,
        ttl_seconds: i64,
        now: i64,
    ) -> Result<(), NetworkError> {
        let stored = StoredMessage {
            ciphertext,
            expires_at: now + ttl_seconds,
        };
        self.dht
            .publish(
                &message_key(recipient_key_hash, message_id),
                serde_json::to_vec(&stored)?,
            )
            .await?;

        let mut manifest = self.fetch_manifest(recipient_key_hash).await?;
        if !manifest.message_ids.iter().any(|id| id == message_id) {
            manifest.message_ids.push(message_id.to_vec());
            self.dht
                .publish(
                    &manifest_key(recipient_key_hash),
                    serde_json::to_vec(&manifest)?,
                )
                .await?;
        }
        Ok(())
    }

    /// Pulls every non-expired message currently in the mailbox, as
    /// `(message_id, ciphertext)` pairs. Expired entries are silently
    /// skipped, not deleted — deletion is an explicit, separate step so a
    /// caller can decrypt first and only then request removal.
    pub async fn pull(
        &self,
        recipient_key_hash: &[u8],
        now: i64,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, NetworkError> {
        let manifest = self.fetch_manifest(recipient_key_hash).await?;
        let mut out = Vec::new();
        for id in &manifest.message_ids {
            if let Some(bytes) = self
                .dht
                .lookup(&message_key(recipient_key_hash, id))
                .await?
            {
                let stored: StoredMessage = serde_json::from_slice(&bytes)?;
                if stored.expires_at > now {
                    out.push((id.clone(), stored.ciphertext));
                }
            }
        }
        Ok(out)
    }

    /// Requests deletion of one message: removes it from the manifest so
    /// future pulls skip it. See the module-level note — this does not
    /// (and with plain Kademlia records, cannot) force other holders of
    /// the record to purge their copy; that needs a real mailbox-node
    /// delete RPC.
    pub async fn delete(
        &self,
        recipient_key_hash: &[u8],
        message_id: &[u8],
    ) -> Result<(), NetworkError> {
        let mut manifest = self.fetch_manifest(recipient_key_hash).await?;
        manifest.message_ids.retain(|id| id != message_id);
        self.dht
            .publish(
                &manifest_key(recipient_key_hash),
                serde_json::to_vec(&manifest)?,
            )
            .await
    }

    /// Publishes once to `group_id` rather than once per member (SPEC.md
    /// §5.4) — every group member just calls [`pull`](Self::pull) with the
    /// same `group_id` as the recipient key.
    pub async fn fan_out(
        &self,
        group_id: &[u8],
        message_id: &[u8],
        ciphertext: Vec<u8>,
        ttl_seconds: i64,
        now: i64,
    ) -> Result<(), NetworkError> {
        self.push(group_id, message_id, ciphertext, ttl_seconds, now)
            .await
    }
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

    async fn publish_with_retry(
        mailbox: &Mailbox,
        recipient: &[u8],
        id: &[u8],
        ct: Vec<u8>,
        ttl: i64,
        now: i64,
    ) {
        for attempt in 0..20 {
            match mailbox.push(recipient, id, ct.clone(), ttl, now).await {
                Ok(()) => return,
                Err(_) if attempt < 19 => tokio::time::sleep(Duration::from_millis(200)).await,
                Err(e) => panic!("push failed after retries: {e}"),
            }
        }
    }

    #[tokio::test]
    async fn recipient_pulls_a_message_pushed_by_someone_else() {
        let (sender_dht, recipient_dht) = connected_pair().await;
        let sender_mailbox = Mailbox::new(sender_dht);
        let recipient_mailbox = Mailbox::new(recipient_dht);
        let recipient_key = b"recipient-key-hash";

        publish_with_retry(
            &sender_mailbox,
            recipient_key,
            b"msg-1",
            b"encrypted contents".to_vec(),
            86_400,
            1_000,
        )
        .await;

        let messages = recipient_mailbox.pull(recipient_key, 1_000).await.unwrap();
        assert_eq!(
            messages,
            vec![(b"msg-1".to_vec(), b"encrypted contents".to_vec())]
        );
    }

    #[tokio::test]
    async fn expired_messages_are_skipped_on_pull() {
        let (sender_dht, recipient_dht) = connected_pair().await;
        let sender_mailbox = Mailbox::new(sender_dht);
        let recipient_mailbox = Mailbox::new(recipient_dht);
        let recipient_key = b"recipient-key-hash-2";

        // TTL of 10s starting at t=1000 -> expires at 1010.
        publish_with_retry(
            &sender_mailbox,
            recipient_key,
            b"msg-1",
            b"old news".to_vec(),
            10,
            1_000,
        )
        .await;

        let messages = recipient_mailbox.pull(recipient_key, 2_000).await.unwrap();
        assert!(
            messages.is_empty(),
            "message past its TTL must not be returned"
        );
    }

    #[tokio::test]
    async fn delete_removes_a_message_from_future_pulls() {
        let (sender_dht, recipient_dht) = connected_pair().await;
        let sender_mailbox = Mailbox::new(sender_dht);
        let recipient_mailbox = Mailbox::new(recipient_dht);
        let recipient_key = b"recipient-key-hash-3";

        publish_with_retry(
            &sender_mailbox,
            recipient_key,
            b"msg-1",
            b"delete me".to_vec(),
            86_400,
            1_000,
        )
        .await;
        assert_eq!(
            recipient_mailbox
                .pull(recipient_key, 1_000)
                .await
                .unwrap()
                .len(),
            1
        );

        recipient_mailbox
            .delete(recipient_key, b"msg-1")
            .await
            .unwrap();
        assert!(recipient_mailbox
            .pull(recipient_key, 1_000)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn fan_out_lets_every_member_pull_the_same_group_message() {
        let (sender_dht, member_dht) = connected_pair().await;
        let sender_mailbox = Mailbox::new(sender_dht);
        let member_a_mailbox = Mailbox::new(member_dht.clone());
        let member_b_mailbox = Mailbox::new(member_dht);
        let group_id = b"group-42";

        for attempt in 0..20 {
            match sender_mailbox
                .fan_out(
                    group_id,
                    b"group-msg-1",
                    b"meeting at noon".to_vec(),
                    86_400,
                    1_000,
                )
                .await
            {
                Ok(()) => break,
                Err(_) if attempt < 19 => tokio::time::sleep(Duration::from_millis(200)).await,
                Err(e) => panic!("fan_out failed after retries: {e}"),
            }
        }

        let a_messages = member_a_mailbox.pull(group_id, 1_000).await.unwrap();
        let b_messages = member_b_mailbox.pull(group_id, 1_000).await.unwrap();
        assert_eq!(a_messages, b_messages);
        assert_eq!(a_messages[0].1, b"meeting at noon");
    }
}
