//! Kademlia DHT for serverless peer/mailbox/username discovery. See
//! `docs/SPEC.md` §5.2, §3. Thin, domain-named wrapper around
//! [`crate::transport::Node`]'s raw Kademlia get/put — the swarm and its
//! event loop live there since they're one piece of state.
//!
//! Node selection must use verifiable randomness rather than pure
//! nearest-neighbor lookup, and enforce subnet/operator diversity per onion
//! circuit, to mitigate Eclipse/Sybil attacks — see `eclipse_resistance.rs`
//! for that (SPEC.md §5.2).

use crate::transport::Node;
use crate::NetworkError;

#[derive(Clone)]
pub struct Dht {
    node: Node,
}

impl Dht {
    pub fn new(node: Node) -> Self {
        Self { node }
    }

    pub async fn lookup(&self, key: &[u8]) -> Result<Option<Vec<u8>>, NetworkError> {
        self.node.get_record(key.to_vec()).await
    }

    pub async fn publish(&self, key: &[u8], value: Vec<u8>) -> Result<(), NetworkError> {
        self.node.put_record(key.to_vec(), value).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_then_lookup_round_trips() {
        let a = Dht::new(Node::spawn("/ip4/127.0.0.1/tcp/0").await.unwrap());
        let b_node = Node::spawn("/ip4/127.0.0.1/tcp/0").await.unwrap();

        let a_addr = a
            .node
            .listen_addrs()
            .await
            .into_iter()
            .next()
            .unwrap()
            .with_p2p(a.node.peer_id())
            .unwrap();
        b_node.dial(a_addr).await.unwrap();
        let b = Dht::new(b_node);

        for attempt in 0..20 {
            match a
                .publish(b"username:alice", b"peer-record-bytes".to_vec())
                .await
            {
                Ok(()) => break,
                Err(_) if attempt < 19 => {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await
                }
                Err(e) => panic!("publish failed after retries: {e}"),
            }
        }

        let value = b.lookup(b"username:alice").await.unwrap();
        assert_eq!(value, Some(b"peer-record-bytes".to_vec()));
    }
}
