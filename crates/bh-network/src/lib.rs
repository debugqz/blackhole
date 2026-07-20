//! P2P networking: libp2p transport, Kademlia DHT, onion routing,
//! store-and-forward mailboxes, group fan-out, and cover traffic.
//! See `docs/SPEC.md` §5.

pub mod cover_traffic;
pub mod dht;
pub mod eclipse_resistance;
pub mod mailbox;
pub mod onion;
pub mod pow;
pub mod sealed_sender;
pub mod transport;

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),
    #[error("swarm setup failed: {0}")]
    Setup(String),
    #[error("dial failed: {0}")]
    Dial(String),
    #[error("DHT query failed: {0}")]
    Query(String),
    #[error("network node has shut down")]
    NodeShutDown,
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}
