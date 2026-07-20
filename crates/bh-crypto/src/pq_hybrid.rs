//! Hybrid post-quantum key exchange: classical X25519 combined with a
//! post-quantum KEM (Kyber/ML-KEM), used from day one rather than bolted on
//! later, to mitigate harvest-now-decrypt-later attacks. See `docs/SPEC.md`
//! §2.1.
//!
//! This is a hybrid, not a replacement: the classical X25519 leg must always
//! be present, so a break in the PQ leg alone never fully breaks the
//! handshake.

use crate::CryptoError;

pub struct HybridKeyExchange;

impl HybridKeyExchange {
    /// Performs the combined X25519 + ML-KEM handshake and derives a shared
    /// secret from both legs.
    pub fn handshake() -> Result<Vec<u8>, CryptoError> {
        todo!("wire up X25519 + ML-KEM hybrid handshake — see docs/SPEC.md §2.1")
    }
}
