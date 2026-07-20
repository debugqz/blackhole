//! Hybrid post-quantum key exchange: classical X25519 combined with
//! ML-KEM-768 (FIPS 203), used from day one rather than bolted on later, to
//! mitigate harvest-now-decrypt-later attacks. See `docs/SPEC.md` §2.1.
//!
//! This is a hybrid, not a replacement: the classical X25519 leg is always
//! present, so a break in the PQ leg alone (ML-KEM is much younger and less
//! battle-tested than Curve25519) never fully breaks the handshake — the
//! combiner only produces a weak shared secret if *both* legs are broken.

use hkdf::Hkdf;
use ml_kem::{Decapsulate, DecapsulationKey768, Encapsulate, EncapsulationKey768, Kem, MlKem768};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

use crate::CryptoError;

fn combine(x25519_shared: &[u8; 32], ml_kem_shared: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(32 + ml_kem_shared.len());
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
pub struct HybridPublicKey {
    pub x25519_public: X25519PublicKey,
    pub ml_kem_encap: EncapsulationKey768,
}

/// What the initiator sends to the responder: their ephemeral X25519
/// public key plus the ML-KEM ciphertext. The responder needs both to
/// derive the same shared secret.
pub struct HybridCiphertext {
    pub x25519_ephemeral_public: X25519PublicKey,
    pub ml_kem_ciphertext: Vec<u8>,
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
}
