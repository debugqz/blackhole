//! Multi-hop onion routing (3+ hops, Tor/Session-style) over the DHT.
//! Prioritizes traffic-analysis resistance over latency by explicit design
//! choice. Same sealed-sender logic applies to call signaling, so the entry
//! node never learns who called whom. See `docs/SPEC.md` §2.3, §5.2.

use crate::NetworkError;

pub const MIN_HOPS: usize = 3;

pub struct Circuit;

impl Circuit {
    pub async fn build(_hops: usize) -> Result<Self, NetworkError> {
        todo!("wire up onion circuit construction — see docs/SPEC.md §5.2")
    }

    pub async fn send(&self, _payload: &[u8]) -> Result<(), NetworkError> {
        todo!("wire up layered onion encryption/relay")
    }
}
