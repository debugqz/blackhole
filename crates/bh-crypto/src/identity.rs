//! Long-term identity key pairs and the seed-phrase recovery model.
//! See `docs/SPEC.md` §3-4.

use crate::CryptoError;

/// A user's long-term identity key pair, generated once at account creation
/// and backing the security-number / QR verification flow (SPEC.md §3).
pub struct IdentityKeyPair;

impl IdentityKeyPair {
    /// Generates a new identity key pair via an audited libsodium binding.
    pub fn generate() -> Result<Self, CryptoError> {
        todo!("wire up libsodium keypair generation — see docs/SPEC.md §2.1")
    }
}

/// A BIP39-style 12-24 word recovery seed. Losing this and all linked
/// devices means the account is unrecoverable by design (SPEC.md §4) —
/// there is deliberately no backdoor recovery path.
pub struct SeedPhrase;

impl SeedPhrase {
    pub fn generate() -> Result<Self, CryptoError> {
        todo!("generate a BIP39-style seed phrase — see docs/SPEC.md §4")
    }
}
