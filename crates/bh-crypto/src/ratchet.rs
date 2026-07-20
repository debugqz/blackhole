//! Signal Protocol for 1:1 sessions: X3DH key agreement + Double Ratchet.
//! See `docs/SPEC.md` §2.1. Intended to wrap `libsignal-protocol` rather
//! than reimplement the ratchet.

use crate::CryptoError;

/// An established 1:1 session between two identities.
pub struct Session;

impl Session {
    /// Runs X3DH to establish a new session with a peer's prekey bundle.
    pub fn establish() -> Result<Self, CryptoError> {
        todo!("wire up libsignal X3DH — see docs/SPEC.md §2.1")
    }

    /// Encrypts a message, advancing the sending ratchet.
    pub fn encrypt(&mut self, _plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        todo!("wire up libsignal Double Ratchet encrypt")
    }

    /// Decrypts a message, advancing the receiving ratchet.
    pub fn decrypt(&mut self, _ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        todo!("wire up libsignal Double Ratchet decrypt")
    }
}
