//! libp2p transport setup: STUN-based hole punching with TURN relay
//! fallback for the ~10-20% of cases direct connection fails. See
//! `docs/SPEC.md` §5.1. The TURN relay only ever forwards already-encrypted
//! packets — it cannot read them.

use crate::NetworkError;

pub struct Transport;

impl Transport {
    pub async fn dial(_peer_id: &str) -> Result<Self, NetworkError> {
        todo!("wire up libp2p transport with STUN/TURN — see docs/SPEC.md §5.1")
    }
}
