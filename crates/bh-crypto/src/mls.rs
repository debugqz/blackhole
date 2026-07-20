//! Group messaging via MLS (RFC 9420). See `docs/SPEC.md` §2.1. Intended to
//! wrap `openmls` rather than reimplement the group ratchet tree.

use crate::CryptoError;

/// An MLS group state (the ratchet tree + group context).
pub struct Group;

impl Group {
    pub fn create() -> Result<Self, CryptoError> {
        todo!("wire up openmls group creation — see docs/SPEC.md §2.1")
    }

    pub fn add_member(&mut self) -> Result<(), CryptoError> {
        todo!("wire up openmls Add proposal + Commit")
    }

    pub fn encrypt(&mut self, _plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        todo!("wire up openmls application message encryption")
    }

    pub fn decrypt(&mut self, _ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        todo!("wire up openmls application message decryption")
    }
}
