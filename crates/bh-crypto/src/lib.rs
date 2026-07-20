//! Cryptographic core: Signal Protocol for 1:1 sessions, MLS for groups, and
//! a hybrid post-quantum handshake. See `docs/SPEC.md` §2.
//!
//! Every primitive here wraps an already-audited library (libsignal, openmls,
//! libsodium). This crate does not and must not implement its own
//! cryptographic primitives — see `docs/SPEC.md` §2.2 for why that's a
//! hard boundary, not a style preference.

pub mod auth;
pub mod backup;
pub mod device_link;
pub mod identity;
pub mod invite;
pub mod mls;
pub mod pq_hybrid;
pub mod ratchet;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),
    #[error("random number generator failure")]
    Rng,
    #[error("key derivation failure")]
    KeyDerivation,
    #[error("invalid or corrupt recovery seed phrase")]
    InvalidSeedPhrase,
    #[error("encryption failure")]
    Encrypt,
    #[error("decryption failure (wrong key, tampered ciphertext, or out-of-order message)")]
    Decrypt,
    #[error("no matching session")]
    NoSession,
    #[error("signature verification failed")]
    InvalidSignature,
}
