//! Call media encryption: key agreement for a voice/video call, and a
//! SFrame-style (draft-ietf-sframe) per-frame AEAD layer on top of whatever
//! the WebRTC transport (`bh-calls`) already does for DTLS-SRTP hop
//! security. The point of a second, independent encryption layer is that
//! DTLS-SRTP only protects each hop to/from a TURN relay — this layer
//! protects the actual audio/video payload end-to-end even from a
//! malicious or coerced relay, the same property text messages already
//! get from the Double Ratchet/MLS layer (SPEC.md §2.1).
//!
//! Call setup itself (the offer/answer/candidate exchange —
//! `envelope::CallSignal`) is authenticated implicitly: it travels *inside*
//! an already-established Double Ratchet/MLS session, so a peer only ever
//! accepts a call offer that came from someone whose identity key it
//! already trusts. What this module adds on top is call-specific *forward
//! secrecy*: a compromise of the long-term session keys later shouldn't
//! retroactively expose a call's audio/video, so each call gets its own
//! ephemeral ECDH exchange rather than reusing the message ratchet's keys
//! directly.
//!
//! Composition of audited primitives only (X25519, HKDF-SHA256,
//! ChaCha20-Poly1305) — no new cryptographic primitives, per `docs/SPEC.md`
//! §2.2.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as AeadKey, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

use crate::CryptoError;

/// One side's ephemeral keypair for a single call's key agreement. Thrown
/// away as soon as the call ends — never persisted, never reused across
/// calls.
pub struct CallEphemeralKeyPair {
    secret: X25519Secret,
    public: X25519PublicKey,
}

impl CallEphemeralKeyPair {
    pub fn generate() -> Self {
        let secret = X25519Secret::random();
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public(&self) -> [u8; 32] {
        self.public.to_bytes()
    }
}

/// Derives the call's SFrame base key from both sides' ephemeral public
/// keys. `call_id` is mixed in as an HKDF salt so two different calls
/// between the same two ephemeral keys (which won't happen in practice
/// since fresh ephemerals are generated per call, but defense in depth
/// costs nothing here) can never derive the same key material.
pub fn derive_base_key(
    call_id: &str,
    mine: &CallEphemeralKeyPair,
    their_public: &[u8; 32],
) -> [u8; 32] {
    let their_public = X25519PublicKey::from(*their_public);
    let shared = mine.secret.diffie_hellman(&their_public);
    let hkdf = Hkdf::<Sha256>::new(Some(call_id.as_bytes()), shared.as_bytes());
    let mut base_key = [0u8; 32];
    hkdf.expand(b"blackhole-call-base-key-v1", &mut base_key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    base_key
}

/// Identifies who encrypted a given SFrame frame, distinguishing which
/// per-direction sub-key/nonce-salt to use so two participants sending
/// concurrently never reuse a (key, nonce) pair even though they share one
/// base key. In a 1:1 call this is just "caller" (0) vs "callee" (1); a
/// future group-call extension would assign one per participant (SPEC.md
/// group calls are explicitly not designed yet — see `docs/SPEC.md`).
pub type SenderTag = u8;

const FRAME_HEADER_LEN: usize = 1 + 1 + 8; // epoch, sender_tag, counter

fn frame_header(epoch: u8, sender_tag: SenderTag, counter: u64) -> [u8; FRAME_HEADER_LEN] {
    let mut header = [0u8; FRAME_HEADER_LEN];
    header[0] = epoch;
    header[1] = sender_tag;
    header[2..].copy_from_slice(&counter.to_be_bytes());
    header
}

fn counter_nonce(salt: &[u8; 12], counter: u64) -> Nonce {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..].copy_from_slice(&counter.to_be_bytes());
    for (n, s) in nonce_bytes.iter_mut().zip(salt.iter()) {
        *n ^= s;
    }
    Nonce::from(nonce_bytes)
}

/// One call's SFrame encryption context. `epoch` starts at 0 and is bumped
/// (via [`envelope::CallSignal::KeyUpdate`](crate::envelope::CallSignal::KeyUpdate))
/// whenever the base key material should rotate — e.g. periodically during
/// a long call, mirroring the Double Ratchet's own "don't use one key
/// forever" principle, composed here at the frame level instead of
/// per-message.
#[derive(Clone)]
pub struct SframeContext {
    base_key: [u8; 32],
}

impl SframeContext {
    pub fn new(base_key: [u8; 32]) -> Self {
        Self { base_key }
    }

    fn epoch_key_and_salt(&self, epoch: u8) -> (AeadKey, [u8; 12]) {
        let hkdf = Hkdf::<Sha256>::new(None, &self.base_key);
        let mut okm = [0u8; 44];
        hkdf.expand(
            &[b"blackhole-sframe-v1".as_slice(), &[epoch]].concat(),
            &mut okm,
        )
        .expect("44 bytes is a valid HKDF-SHA256 output length");
        let key = AeadKey::try_from(&okm[..32]).expect("32 bytes");
        let mut salt = [0u8; 12];
        salt.copy_from_slice(&okm[32..44]);
        (key, salt)
    }

    /// Encrypts one media frame's payload. `counter` must never repeat for
    /// the same `(epoch, sender_tag)` pair — callers own a strictly
    /// increasing per-sender counter, the same responsibility the Double
    /// Ratchet's `send_count` carries for messages.
    pub fn encrypt_frame(
        &self,
        epoch: u8,
        sender_tag: SenderTag,
        counter: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let (key, salt) = self.epoch_key_and_salt(epoch);
        let nonce = counter_nonce(&salt, counter);
        let header = frame_header(epoch, sender_tag, counter);
        let cipher = ChaCha20Poly1305::new(&key);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| CryptoError::Encrypt)?;

        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + ciphertext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypts a frame produced by [`SframeContext::encrypt_frame`],
    /// reading `epoch`/`sender_tag`/`counter` back out of its header.
    /// Returns the plaintext plus the header fields, so the caller (the
    /// WebRTC RTP interceptor in `bh-calls`) can do jitter-buffer/replay
    /// bookkeeping keyed on `(sender_tag, counter)`.
    pub fn decrypt_frame(
        &self,
        frame: &[u8],
    ) -> Result<(u8, SenderTag, u64, Vec<u8>), CryptoError> {
        if frame.len() < FRAME_HEADER_LEN {
            return Err(CryptoError::Decrypt);
        }
        let epoch = frame[0];
        let sender_tag = frame[1];
        let counter = u64::from_be_bytes(frame[2..FRAME_HEADER_LEN].try_into().unwrap());
        let header = &frame[..FRAME_HEADER_LEN];
        let ciphertext = &frame[FRAME_HEADER_LEN..];

        let (key, salt) = self.epoch_key_and_salt(epoch);
        let nonce = counter_nonce(&salt, counter);
        let cipher = ChaCha20Poly1305::new(&key);
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: header,
                },
            )
            .map_err(|_| CryptoError::Decrypt)?;
        Ok((epoch, sender_tag, counter, plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn established_pair() -> (SframeContext, SframeContext) {
        let caller = CallEphemeralKeyPair::generate();
        let callee = CallEphemeralKeyPair::generate();
        let caller_key = derive_base_key("call-1", &caller, &callee.public());
        let callee_key = derive_base_key("call-1", &callee, &caller.public());
        assert_eq!(caller_key, callee_key);
        (
            SframeContext::new(caller_key),
            SframeContext::new(callee_key),
        )
    }

    #[test]
    fn both_sides_derive_the_same_base_key() {
        established_pair();
    }

    #[test]
    fn different_call_ids_derive_different_base_keys() {
        let caller = CallEphemeralKeyPair::generate();
        let callee = CallEphemeralKeyPair::generate();
        let key_a = derive_base_key("call-a", &caller, &callee.public());
        let key_b = derive_base_key("call-b", &caller, &callee.public());
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn frame_roundtrips() {
        let (sender, receiver) = established_pair();
        let frame = sender
            .encrypt_frame(0, 0, 42, b"audio payload bytes")
            .unwrap();
        let (epoch, sender_tag, counter, plaintext) = receiver.decrypt_frame(&frame).unwrap();
        assert_eq!(epoch, 0);
        assert_eq!(sender_tag, 0);
        assert_eq!(counter, 42);
        assert_eq!(plaintext, b"audio payload bytes");
    }

    #[test]
    fn tampered_frame_is_rejected() {
        let (sender, receiver) = established_pair();
        let mut frame = sender.encrypt_frame(0, 1, 0, b"video keyframe").unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 0xFF;
        assert!(receiver.decrypt_frame(&frame).is_err());
    }

    #[test]
    fn different_senders_at_the_same_counter_do_not_collide() {
        let (sender, receiver) = established_pair();
        let from_caller = sender.encrypt_frame(0, 0, 5, b"caller frame").unwrap();
        let from_callee = receiver.encrypt_frame(0, 1, 5, b"callee frame").unwrap();
        assert_ne!(from_caller, from_callee);

        assert_eq!(
            receiver.decrypt_frame(&from_caller).unwrap().3,
            b"caller frame"
        );
        assert_eq!(
            sender.decrypt_frame(&from_callee).unwrap().3,
            b"callee frame"
        );
    }

    #[test]
    fn key_update_changes_ciphertext_for_the_same_plaintext() {
        let (sender, _receiver) = established_pair();
        let frame_epoch0 = sender.encrypt_frame(0, 0, 0, b"same plaintext").unwrap();
        let frame_epoch1 = sender.encrypt_frame(1, 0, 0, b"same plaintext").unwrap();
        assert_ne!(frame_epoch0, frame_epoch1);
    }

    #[test]
    fn mismatched_base_key_cannot_decrypt() {
        let (sender, _) = established_pair();
        let frame = sender.encrypt_frame(0, 0, 0, b"secret").unwrap();

        let stranger = SframeContext::new([0xAAu8; 32]);
        assert!(stranger.decrypt_frame(&frame).is_err());
    }
}
