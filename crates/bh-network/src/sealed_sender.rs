//! Sealed sender: the mailbox/entry node that stores or relays an envelope
//! learns only the recipient (needed to route/store it), never the sender.
//! Same construction applies to call signaling (SPEC.md §2.3) — whatever
//! carries the envelope just needs a recipient key, never a sender
//! identity, to do its job.
//!
//! The sender's identity and signature live *inside* the encryption to the
//! recipient's key, so only the recipient — who decrypts it — ever learns
//! who actually sent the message. There's no central certificate
//! authority attesting sender identity (unlike Signal's actual sealed
//! sender, which relies on the server issuing sender certificates): trust
//! here comes from the recipient already knowing the sender's identity key
//! via prior contact verification (SPEC.md §3), consistent with the rest
//! of this project's zero-trusted-server design.

use bh_crypto::identity::IdentityKeyPair;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

use crate::NetworkError;

/// What the entry/mailbox node actually sees: a recipient-routable
/// envelope with no sender information anywhere in it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedSenderEnvelope {
    pub ephemeral_public: [u8; 32],
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SealedContent {
    sender_identity_public: [u8; 32],
    sender_signature: Vec<u8>,
    timestamp: i64,
    inner_message: Vec<u8>,
}

fn derive_key(shared: &[u8; 32]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, shared);
    let mut key = [0u8; 32];
    hkdf.expand(b"blackhole-sealed-sender-v1", &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

fn signed_bytes(timestamp: i64, inner_message: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + inner_message.len());
    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf.extend_from_slice(inner_message);
    buf
}

/// The sender's side: wraps `inner_message` (itself already Double
/// Ratchet/MLS ciphertext — this layer doesn't care) so that only
/// `recipient_public` can learn who sent it.
pub fn seal(
    sender_identity: &IdentityKeyPair,
    recipient_public: &X25519PublicKey,
    inner_message: Vec<u8>,
    timestamp: i64,
) -> Result<SealedSenderEnvelope, NetworkError> {
    let signature = sender_identity.sign(&signed_bytes(timestamp, &inner_message));
    let content = SealedContent {
        sender_identity_public: sender_identity.public_signing_key().to_bytes(),
        sender_signature: signature.to_bytes().to_vec(),
        timestamp,
        inner_message,
    };
    let plaintext = serde_json::to_vec(&content).map_err(|e| NetworkError::Setup(e.to_string()))?;

    let ephemeral_secret = X25519Secret::random();
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(recipient_public);
    let key = derive_key(shared.as_bytes());

    let cipher = ChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(&Nonce::default(), plaintext.as_slice())
        .map_err(|_| NetworkError::Setup("sealed_sender: encryption failed".to_string()))?;

    Ok(SealedSenderEnvelope {
        ephemeral_public: ephemeral_public.to_bytes(),
        ciphertext,
    })
}

/// What unsealing reveals — available only to the recipient.
pub struct UnsealedMessage {
    pub sender_identity: VerifyingKey,
    pub timestamp: i64,
    pub inner_message: Vec<u8>,
}

/// The recipient's side. Fails if the envelope wasn't actually addressed
/// to `recipient_secret`, or if the revealed sender signature doesn't
/// match the revealed sender identity (someone tampered with the sealed
/// content, or it's simply corrupt).
pub fn unseal(
    recipient_secret: &X25519Secret,
    envelope: &SealedSenderEnvelope,
) -> Result<UnsealedMessage, NetworkError> {
    let their_ephemeral = X25519PublicKey::from(envelope.ephemeral_public);
    let shared = recipient_secret.diffie_hellman(&their_ephemeral);
    let key = derive_key(shared.as_bytes());

    let cipher = ChaCha20Poly1305::new((&key).into());
    let plaintext = cipher
        .decrypt(&Nonce::default(), envelope.ciphertext.as_slice())
        .map_err(|_| NetworkError::Query("sealed_sender: decryption failed".to_string()))?;

    let content: SealedContent =
        serde_json::from_slice(&plaintext).map_err(|e| NetworkError::Query(e.to_string()))?;

    let sender_identity = VerifyingKey::from_bytes(&content.sender_identity_public)
        .map_err(|_| NetworkError::Query("sealed_sender: bad sender identity key".to_string()))?;
    let signature_bytes: [u8; 64] = content
        .sender_signature
        .as_slice()
        .try_into()
        .map_err(|_| NetworkError::Query("sealed_sender: bad signature length".to_string()))?;
    let signature = Signature::from_bytes(&signature_bytes);
    sender_identity
        .verify(
            &signed_bytes(content.timestamp, &content.inner_message),
            &signature,
        )
        .map_err(|_| NetworkError::Query("sealed_sender: sender signature invalid".to_string()))?;

    Ok(UnsealedMessage {
        sender_identity,
        timestamp: content.timestamp,
        inner_message: content.inner_message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_learns_sender_identity_and_message() {
        let sender = IdentityKeyPair::generate().unwrap();
        let recipient_secret = X25519Secret::random();
        let recipient_public = X25519PublicKey::from(&recipient_secret);

        let envelope = seal(
            &sender,
            &recipient_public,
            b"hi there".to_vec(),
            1_700_000_000,
        )
        .unwrap();
        let unsealed = unseal(&recipient_secret, &envelope).unwrap();

        assert_eq!(unsealed.inner_message, b"hi there");
        assert_eq!(
            unsealed.sender_identity.to_bytes(),
            sender.public_signing_key().to_bytes()
        );
        assert_eq!(unsealed.timestamp, 1_700_000_000);
    }

    #[test]
    fn envelope_carries_no_sender_information_in_the_clear() {
        let sender = IdentityKeyPair::generate().unwrap();
        let recipient_secret = X25519Secret::random();
        let recipient_public = X25519PublicKey::from(&recipient_secret);

        let envelope = seal(&sender, &recipient_public, b"secret plan".to_vec(), 1000).unwrap();
        let serialized = serde_json::to_vec(&envelope).unwrap();

        let sender_key_bytes = sender.public_signing_key().to_bytes();
        assert!(
            !serialized
                .windows(sender_key_bytes.len())
                .any(|w| w == sender_key_bytes),
            "sender's identity key must not appear anywhere in the envelope"
        );
    }

    #[test]
    fn wrong_recipient_cannot_unseal() {
        let sender = IdentityKeyPair::generate().unwrap();
        let recipient_public = X25519PublicKey::from(&X25519Secret::random());
        let envelope = seal(
            &sender,
            &recipient_public,
            b"for your eyes only".to_vec(),
            1000,
        )
        .unwrap();

        let impostor_secret = X25519Secret::random();
        assert!(unseal(&impostor_secret, &envelope).is_err());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let sender = IdentityKeyPair::generate().unwrap();
        let recipient_secret = X25519Secret::random();
        let recipient_public = X25519PublicKey::from(&recipient_secret);
        let mut envelope = seal(&sender, &recipient_public, b"message".to_vec(), 1000).unwrap();

        let last = envelope.ciphertext.len() - 1;
        envelope.ciphertext[last] ^= 0xFF;
        assert!(unseal(&recipient_secret, &envelope).is_err());
    }
}
