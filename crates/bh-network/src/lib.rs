//! P2P networking: libp2p transport, Kademlia DHT, onion routing,
//! store-and-forward mailboxes, group fan-out, and cover traffic.
//! See `docs/SPEC.md` §5.

pub mod cover_traffic;
pub mod device_link_relay;
pub mod dht;
pub mod eclipse_resistance;
pub mod key_package_directory;
pub mod mailbox;
pub mod onion;
pub mod pow;
pub mod prekey_directory;
pub mod push_relay_directory;
pub mod routing_admission;
pub mod sealed_sender;
pub mod supervised;
pub mod transport;
pub mod tree_head;

/// Re-exported for the same reason as [`Multiaddr`] above — `daemon`'s
/// `BLACKHOLE_PERSISTENT_NETWORK_IDENTITY` handling needs to name
/// `identity::Keypair` (load/generate/persist it via the platform
/// keystore) without a direct `libp2p` dependency of its own.
pub use libp2p::identity;
/// Re-exported so downstream crates (e.g. `daemon`, for parsing
/// `BLACKHOLE_BOOTSTRAP_PEERS`) don't need their own direct `libp2p`
/// dependency just to name this type.
pub use libp2p::Multiaddr;

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
