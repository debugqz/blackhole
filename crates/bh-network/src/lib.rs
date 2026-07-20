//! P2P networking: libp2p transport, Kademlia DHT, onion routing,
//! store-and-forward mailboxes, group fan-out, and cover traffic.
//! See `docs/SPEC.md` §5.

pub mod cover_traffic;
pub mod dht;
pub mod mailbox;
pub mod onion;
pub mod transport;

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),
}
