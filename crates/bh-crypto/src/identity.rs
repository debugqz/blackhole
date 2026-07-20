//! Long-term identity: a signing key pair (safety-number attestations,
//! signed prekeys) plus an X25519 agreement key pair (X3DH), and the
//! BIP39 seed phrase both can be deterministically re-derived from.
//! See `docs/SPEC.md` §3-4.
//!
//! Signal's actual identity key is a single Curve25519 key used for both
//! signing (via XEdDSA) and agreement. We use two separate audited key
//! types instead (Ed25519 for signing, X25519 for agreement) rather than
//! reimplementing XEdDSA ourselves — functionally equivalent, simpler, and
//! still zero custom primitives.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha512;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use zeroize::Zeroizing;

use crate::CryptoError;

const HKDF_INFO_AGREEMENT: &[u8] = b"blackhole-identity-agreement-key-v1";
const HKDF_INFO_SIGNING: &[u8] = b"blackhole-identity-signing-key-v1";

pub struct IdentityKeyPair {
    signing: SigningKey,
    agreement: X25519Secret,
}

impl IdentityKeyPair {
    /// Generates a fresh, non-recoverable-from-seed identity. Prefer
    /// [`IdentityKeyPair::from_seed_phrase`] when the caller wants the
    /// identity to be reconstructible from the recovery phrase.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut signing_bytes = [0u8; 32];
        getrandom::fill(&mut signing_bytes).map_err(|_| CryptoError::Rng)?;
        let signing = SigningKey::from_bytes(&signing_bytes);

        let mut agreement_bytes = [0u8; 32];
        getrandom::fill(&mut agreement_bytes).map_err(|_| CryptoError::Rng)?;
        let agreement = X25519Secret::from(agreement_bytes);

        Ok(Self { signing, agreement })
    }

    /// Deterministically derives both keys from a BIP39 seed (SPEC.md §4):
    /// losing every device but keeping the seed phrase must be enough to
    /// recover the same identity.
    pub fn from_seed_phrase(seed: &SeedPhrase) -> Result<Self, CryptoError> {
        let seed_bytes = seed.to_seed();
        let hkdf = Hkdf::<Sha512>::new(None, &seed_bytes);

        let mut signing_bytes = [0u8; 32];
        hkdf.expand(HKDF_INFO_SIGNING, &mut signing_bytes)
            .map_err(|_| CryptoError::KeyDerivation)?;
        let signing = SigningKey::from_bytes(&signing_bytes);

        let mut agreement_bytes = [0u8; 32];
        hkdf.expand(HKDF_INFO_AGREEMENT, &mut agreement_bytes)
            .map_err(|_| CryptoError::KeyDerivation)?;
        let agreement = X25519Secret::from(agreement_bytes);

        Ok(Self { signing, agreement })
    }

    pub fn public_signing_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn public_agreement_key(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.agreement)
    }

    pub fn agreement_secret(&self) -> &X25519Secret {
        &self.agreement
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing.sign(message)
    }

    pub fn verify(public_key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
        public_key.verify(message, signature).is_ok()
    }

    /// Raw private key material (signing || agreement, 64 bytes) — used
    /// only to transfer an identity to a newly-linked device over an
    /// already-encrypted channel (SPEC.md §4: multi-device sync never
    /// uploads private keys in the clear to any server). The caller owns
    /// encrypting/zeroizing this; it is not persisted here.
    pub fn export_bytes(&self) -> Zeroizing<[u8; 64]> {
        let mut out = Zeroizing::new([0u8; 64]);
        out[..32].copy_from_slice(self.signing.to_bytes().as_slice());
        out[32..].copy_from_slice(self.agreement.to_bytes().as_slice());
        out
    }

    pub fn import_bytes(bytes: &[u8; 64]) -> Result<Self, CryptoError> {
        let signing = SigningKey::from_bytes(bytes[..32].try_into().unwrap());
        let agreement = X25519Secret::from(<[u8; 32]>::try_from(&bytes[32..]).unwrap());
        Ok(Self { signing, agreement })
    }
}

/// A BIP39 12-24 word recovery seed. Losing this and all linked devices
/// means the account is unrecoverable by design (SPEC.md §4) — there is
/// deliberately no backdoor recovery path.
pub struct SeedPhrase {
    mnemonic: bip39::Mnemonic,
}

impl SeedPhrase {
    /// Generates a new 24-word (256-bit entropy) seed phrase.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        getrandom::fill(entropy.as_mut()).map_err(|_| CryptoError::Rng)?;
        let mnemonic = bip39::Mnemonic::from_entropy(entropy.as_ref())
            .map_err(|_| CryptoError::InvalidSeedPhrase)?;
        Ok(Self { mnemonic })
    }

    /// Parses and validates a phrase the user typed back in during
    /// recovery (checksum included, per BIP39).
    pub fn from_words(phrase: &str) -> Result<Self, CryptoError> {
        let mnemonic = phrase
            .parse::<bip39::Mnemonic>()
            .map_err(|_| CryptoError::InvalidSeedPhrase)?;
        Ok(Self { mnemonic })
    }

    /// The words to show the user once, at account creation, for them to
    /// write down offline.
    pub fn words(&self) -> String {
        self.mnemonic.to_string()
    }

    /// The 64-byte BIP39 seed (PBKDF2-HMAC-SHA512 over the mnemonic), used
    /// as HKDF input for identity key derivation. No BIP39 passphrase is
    /// used — the spec's recovery model is "seed phrase alone recovers the
    /// account," not "seed phrase + a second secret."
    pub fn to_seed(&self) -> [u8; 64] {
        self.mnemonic.to_seed("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_usable_keys() {
        let id = IdentityKeyPair::generate().unwrap();
        let msg = b"hello blackhole";
        let sig = id.sign(msg);
        assert!(IdentityKeyPair::verify(&id.public_signing_key(), msg, &sig));
    }

    #[test]
    fn seed_phrase_roundtrips_through_words() {
        let seed = SeedPhrase::generate().unwrap();
        let words = seed.words();
        assert_eq!(words.split_whitespace().count(), 24);

        let reparsed = SeedPhrase::from_words(&words).unwrap();
        assert_eq!(seed.to_seed(), reparsed.to_seed());
    }

    #[test]
    fn identity_from_seed_phrase_is_deterministic() {
        let seed = SeedPhrase::generate().unwrap();
        let id_a = IdentityKeyPair::from_seed_phrase(&seed).unwrap();

        let words = seed.words();
        let seed_again = SeedPhrase::from_words(&words).unwrap();
        let id_b = IdentityKeyPair::from_seed_phrase(&seed_again).unwrap();

        assert_eq!(
            id_a.public_signing_key().to_bytes(),
            id_b.public_signing_key().to_bytes()
        );
        assert_eq!(
            id_a.public_agreement_key().to_bytes(),
            id_b.public_agreement_key().to_bytes()
        );
    }

    #[test]
    fn different_seed_phrases_give_different_identities() {
        let id_a = IdentityKeyPair::from_seed_phrase(&SeedPhrase::generate().unwrap()).unwrap();
        let id_b = IdentityKeyPair::from_seed_phrase(&SeedPhrase::generate().unwrap()).unwrap();
        assert_ne!(
            id_a.public_signing_key().to_bytes(),
            id_b.public_signing_key().to_bytes()
        );
    }

    #[test]
    fn garbage_recovery_phrase_is_rejected() {
        assert!(SeedPhrase::from_words("not a valid bip39 phrase at all").is_err());
    }
}
