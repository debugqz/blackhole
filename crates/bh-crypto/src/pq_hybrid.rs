//! Hybrid post-quantum key exchange: classical X25519 combined with
//! ML-KEM-768 (FIPS 203), used from day one rather than bolted on later, to
//! mitigate harvest-now-decrypt-later attacks. See `docs/SPEC.md` §2.1.
//!
//! This is a hybrid, not a replacement: the classical X25519 leg is always
//! present, so a break in the PQ leg alone (ML-KEM is much younger and less
//! battle-tested than Curve25519) never fully breaks the handshake — the
//! combiner only produces a weak shared secret if *both* legs are broken.

use hkdf::Hkdf;
use ml_kem::{
    Decapsulate, DecapsulationKey768, Encapsulate, EncapsulationKey768, Kem, KeyExport, MlKem768,
};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use zeroize::Zeroizing;

use crate::CryptoError;

fn combine(x25519_shared: &[u8; 32], ml_kem_shared: &[u8]) -> [u8; 32] {
    // Heap-allocated and holds both raw shared secrets concatenated —
    // wrapped so it's wiped on drop rather than left in freed heap memory.
    let mut ikm: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(32 + ml_kem_shared.len()));
    ikm.extend_from_slice(x25519_shared);
    ikm.extend_from_slice(ml_kem_shared);
    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut out = [0u8; 32];
    hkdf.expand(b"blackhole-pq-hybrid-v1", &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// The long-term (or per-session, depending on how the caller uses it)
/// hybrid keypair. In an X3DH-style handshake this plays the same role a
/// signed prekey does — see `ratchet.rs`.
pub struct HybridSecretKey {
    x25519_secret: X25519Secret,
    ml_kem_decap: DecapsulationKey768,
}

/// The public half, published so a peer can run [`hybrid_encapsulate`]
/// against it.
#[derive(Clone)]
pub struct HybridPublicKey {
    pub x25519_public: X25519PublicKey,
    pub ml_kem_encap: EncapsulationKey768,
}

impl HybridPublicKey {
    /// Raw bytes suitable for signing or wire transmission: the X25519
    /// public key followed by the encoded ML-KEM encapsulation key.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 1184);
        out.extend_from_slice(self.x25519_public.as_bytes());
        out.extend_from_slice(self.ml_kem_encap.to_bytes().as_slice());
        out
    }

    /// Inverse of [`to_bytes`](Self::to_bytes) — reconstructs a peer's
    /// published hybrid public key from wire bytes (e.g. a `PreKeyBundle`
    /// fetched from a mailbox/DHT record).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let x25519_bytes = bytes
            .get(..32)
            .ok_or(CryptoError::Malformed("hybrid public key: truncated"))?;
        let x25519_public =
            X25519PublicKey::from(<[u8; 32]>::try_from(x25519_bytes).expect("checked length"));
        let ek_bytes = bytes
            .get(32..)
            .ok_or(CryptoError::Malformed("hybrid public key: truncated"))?;
        let arr: ml_kem::Key<EncapsulationKey768> = ek_bytes
            .try_into()
            .map_err(|_| CryptoError::Malformed("hybrid public key: bad ml-kem key length"))?;
        let ml_kem_encap = EncapsulationKey768::new(&arr)
            .map_err(|_| CryptoError::Malformed("hybrid public key: invalid ml-kem key"))?;
        Ok(Self {
            x25519_public,
            ml_kem_encap,
        })
    }
}

/// What the initiator sends to the responder: their ephemeral X25519
/// public key plus the ML-KEM ciphertext. The responder needs both to
/// derive the same shared secret.
pub struct HybridCiphertext {
    pub x25519_ephemeral_public: X25519PublicKey,
    pub ml_kem_ciphertext: Vec<u8>,
}

impl HybridCiphertext {
    /// Wire bytes: the ephemeral X25519 public key, then the ML-KEM
    /// ciphertext length-prefixed (ML-KEM's ciphertext size is fixed per
    /// parameter set, but length-prefixing avoids hardcoding that constant
    /// here).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + self.ml_kem_ciphertext.len());
        out.extend_from_slice(self.x25519_ephemeral_public.as_bytes());
        out.extend_from_slice(&(self.ml_kem_ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.ml_kem_ciphertext);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let x25519_bytes = bytes
            .get(..32)
            .ok_or(CryptoError::Malformed("hybrid ciphertext: truncated"))?;
        let x25519_ephemeral_public =
            X25519PublicKey::from(<[u8; 32]>::try_from(x25519_bytes).expect("checked length"));
        let len_bytes = bytes
            .get(32..36)
            .ok_or(CryptoError::Malformed("hybrid ciphertext: truncated"))?;
        let len = u32::from_be_bytes(len_bytes.try_into().expect("checked length")) as usize;
        let ml_kem_ciphertext = bytes
            .get(36..36 + len)
            .ok_or(CryptoError::Malformed("hybrid ciphertext: truncated"))?
            .to_vec();
        Ok(Self {
            x25519_ephemeral_public,
            ml_kem_ciphertext,
        })
    }
}

impl HybridSecretKey {
    pub fn generate() -> Self {
        let x25519_secret = X25519Secret::random();
        let (ml_kem_decap, _ml_kem_encap) = MlKem768::generate_keypair();
        Self {
            x25519_secret,
            ml_kem_decap,
        }
    }

    /// Generates a fresh key together with the compact 96-byte seed it was
    /// derived from (32 bytes for the X25519 secret, 64 for ML-KEM's own
    /// seed form — `DecapsulationKey::from_seed`), for callers that need
    /// to *persist* this key (e.g. a long-term signed prekey surviving a
    /// daemon restart) without storing ML-KEM's much larger (~2400-byte)
    /// fully-expanded private key encoding. Use [`Self::from_seed_bytes`]
    /// to rebuild the identical key from the returned seed later.
    pub fn generate_with_seed() -> ([u8; 96], Self) {
        let mut seed = [0u8; 96];
        getrandom::fill(&mut seed).expect("getrandom failure");
        (seed, Self::from_seed_bytes(&seed))
    }

    /// Inverse of [`Self::generate_with_seed`].
    pub fn from_seed_bytes(seed: &[u8; 96]) -> Self {
        let x25519_secret =
            X25519Secret::from(<[u8; 32]>::try_from(&seed[..32]).expect("checked length"));
        let ml_kem_seed: ml_kem::Seed =
            ml_kem::array::Array::from(<[u8; 64]>::try_from(&seed[32..]).expect("checked length"));
        let ml_kem_decap = DecapsulationKey768::from_seed(ml_kem_seed);
        Self {
            x25519_secret,
            ml_kem_decap,
        }
    }

    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            x25519_public: X25519PublicKey::from(&self.x25519_secret),
            ml_kem_encap: self.ml_kem_decap.encapsulation_key().clone(),
        }
    }
}

/// The initiator's side: encapsulate against the responder's published
/// hybrid public key, producing both the shared secret and the ciphertext
/// to send them.
pub fn hybrid_encapsulate(
    their_public: &HybridPublicKey,
) -> Result<([u8; 32], HybridCiphertext), CryptoError> {
    let ephemeral = X25519Secret::random();
    let ephemeral_public = X25519PublicKey::from(&ephemeral);
    let x25519_shared = ephemeral.diffie_hellman(&their_public.x25519_public);

    let (ml_kem_ciphertext, ml_kem_shared) = their_public.ml_kem_encap.encapsulate();

    let shared_secret = combine(x25519_shared.as_bytes(), ml_kem_shared.as_slice());

    Ok((
        shared_secret,
        HybridCiphertext {
            x25519_ephemeral_public: ephemeral_public,
            ml_kem_ciphertext: ml_kem_ciphertext.to_vec(),
        },
    ))
}

/// The responder's side: reconstruct the same shared secret from the
/// initiator's [`HybridCiphertext`] and our own (still-private) hybrid
/// secret key.
pub fn hybrid_decapsulate(
    my_secret: &HybridSecretKey,
    ciphertext: &HybridCiphertext,
) -> Result<[u8; 32], CryptoError> {
    let x25519_shared = my_secret
        .x25519_secret
        .diffie_hellman(&ciphertext.x25519_ephemeral_public);

    // ML-KEM decapsulation is infallible by design (FIPS 203 implicit
    // rejection): a tampered ciphertext doesn't error, it just silently
    // yields an unpredictable, wrong shared secret.
    let ml_kem_shared = my_secret
        .ml_kem_decap
        .decapsulate_slice(&ciphertext.ml_kem_ciphertext)
        .map_err(|_| CryptoError::Decrypt)?;

    Ok(combine(x25519_shared.as_bytes(), ml_kem_shared.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initiator_and_responder_derive_the_same_hybrid_secret() {
        let responder_key = HybridSecretKey::generate();
        let responder_public = responder_key.public_key();

        let (initiator_secret, ciphertext) = hybrid_encapsulate(&responder_public).unwrap();
        let responder_secret = hybrid_decapsulate(&responder_key, &ciphertext).unwrap();

        assert_eq!(initiator_secret, responder_secret);
    }

    #[test]
    fn different_responders_yield_different_secrets() {
        let responder_a = HybridSecretKey::generate();
        let responder_b = HybridSecretKey::generate();

        let (secret_a, _) = hybrid_encapsulate(&responder_a.public_key()).unwrap();
        let (secret_b, _) = hybrid_encapsulate(&responder_b.public_key()).unwrap();

        assert_ne!(secret_a, secret_b);
    }

    #[test]
    fn tampered_ml_kem_ciphertext_breaks_agreement() {
        let responder_key = HybridSecretKey::generate();
        let (initiator_secret, mut ciphertext) =
            hybrid_encapsulate(&responder_key.public_key()).unwrap();
        let last = ciphertext.ml_kem_ciphertext.len() - 1;
        ciphertext.ml_kem_ciphertext[last] ^= 0xFF;

        let responder_secret = hybrid_decapsulate(&responder_key, &ciphertext).unwrap();
        assert_ne!(initiator_secret, responder_secret);
    }

    #[test]
    fn hybrid_public_key_roundtrips_through_bytes() {
        let secret = HybridSecretKey::generate();
        let public = secret.public_key();
        let decoded = HybridPublicKey::from_bytes(&public.to_bytes()).unwrap();
        assert_eq!(decoded.to_bytes(), public.to_bytes());
    }

    #[test]
    fn hybrid_ciphertext_roundtrips_through_bytes() {
        let responder_key = HybridSecretKey::generate();
        let (secret, ciphertext) = hybrid_encapsulate(&responder_key.public_key()).unwrap();
        let decoded = HybridCiphertext::from_bytes(&ciphertext.to_bytes()).unwrap();
        let decoded_secret = hybrid_decapsulate(&responder_key, &decoded).unwrap();
        assert_eq!(secret, decoded_secret);
    }

    #[test]
    fn hybrid_secret_key_rebuilt_from_seed_bytes_behaves_identically() {
        let (seed, original) = HybridSecretKey::generate_with_seed();
        let rebuilt = HybridSecretKey::from_seed_bytes(&seed);

        // Same public key...
        assert_eq!(
            original.public_key().to_bytes(),
            rebuilt.public_key().to_bytes()
        );

        // ...and the rebuilt key can decapsulate a ciphertext produced
        // against the original's public key, proving it's really the same
        // private key, not just a coincidentally-matching public half.
        let (secret, ciphertext) = hybrid_encapsulate(&original.public_key()).unwrap();
        let decapsulated = hybrid_decapsulate(&rebuilt, &ciphertext).unwrap();
        assert_eq!(secret, decapsulated);
    }
}
