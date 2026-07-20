//! Kademlia DHT for serverless peer/mailbox/username discovery. See
//! `docs/SPEC.md` §5.2, §3.
//!
//! Node selection must use verifiable randomness rather than pure
//! nearest-neighbor lookup, and enforce subnet/operator diversity per onion
//! circuit, to mitigate Eclipse/Sybil attacks (SPEC.md §5.2).

use crate::NetworkError;

pub struct Dht;

impl Dht {
    pub async fn lookup(_key: &[u8]) -> Result<Vec<u8>, NetworkError> {
        todo!("wire up Kademlia DHT lookup — see docs/SPEC.md §5.2")
    }

    /// Selects DHT nodes for an onion circuit with verifiable randomness and
    /// forced subnet/operator diversity across hops (SPEC.md §5.2).
    pub async fn select_circuit_nodes(_hop_count: usize) -> Result<Vec<String>, NetworkError> {
        todo!("wire up Eclipse/Sybil-resistant node selection — see docs/SPEC.md §5.2")
    }
}
