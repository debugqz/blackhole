//! Cryptographic core: Signal Protocol for 1:1 sessions, MLS for groups, and
//! a hybrid post-quantum handshake. See `docs/SPEC.md` §2.
//!
//! Every primitive here wraps an already-audited library (libsignal, openmls,
//! libsodium). This crate does not and must not implement its own
//! cryptographic primitives — see `docs/SPEC.md` §2.2 for why that's a
//! hard boundary, not a style preference.

pub mod auth;
pub mod backup;
pub mod call_keys;
pub mod device_link;
pub mod envelope;
pub mod identity;
pub mod invite;
pub mod key_transparency;
pub mod mls;
pub mod mls_storage;
pub mod payment_address;
pub mod pq_hybrid;
pub mod push_relay;
pub mod qr;
pub mod ratchet;
pub mod safety_number;
pub mod webhook;

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
    #[error("malformed serialized data: {0}")]
    Malformed(&'static str),
}
