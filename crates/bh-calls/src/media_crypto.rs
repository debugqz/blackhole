//! Thin ergonomic wrapper around `bh_crypto::call_keys::SframeContext`:
//! callers hand it encoded media samples (Opus/VP8 bytes) in and out, and
//! it owns the monotonic per-sender frame counter and current key epoch so
//! `audio.rs`/`video.rs`/`transport.rs` don't each have to reimplement
//! that bookkeeping (and can't accidentally reuse a counter value, which
//! would be a nonce-reuse bug at the crypto layer).

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use bh_crypto::call_keys::SframeContext;

use crate::CallError;

/// Encrypts this side's outgoing media frames.
pub struct FrameEncryptor {
    ctx: SframeContext,
    sender_tag: u8,
    epoch: AtomicU8,
    counter: AtomicU64,
}

impl FrameEncryptor {
    pub fn new(ctx: SframeContext, sender_tag: u8) -> Self {
        Self {
            ctx,
            sender_tag,
            epoch: AtomicU8::new(0),
            counter: AtomicU64::new(0),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CallError> {
        let counter = self.counter.fetch_add(1, Ordering::SeqCst);
        let epoch = self.epoch.load(Ordering::SeqCst);
        self.ctx
            .encrypt_frame(epoch, self.sender_tag, counter, plaintext)
            .map_err(CallError::from)
    }

    /// Rotates to a new key epoch (see
    /// `bh_crypto::envelope::CallSignal::KeyUpdate`) and resets this
    /// sender's frame counter — a new epoch means a fresh nonce space, so
    /// counters may safely restart from zero.
    pub fn rotate_epoch(&self, new_epoch: u8) {
        self.epoch.store(new_epoch, Ordering::SeqCst);
        self.counter.store(0, Ordering::SeqCst);
    }
}

/// Decrypts the peer's incoming media frames.
pub struct FrameDecryptor {
    ctx: SframeContext,
}

impl FrameDecryptor {
    pub fn new(ctx: SframeContext) -> Self {
        Self { ctx }
    }

    /// Decrypts one frame, returning its plaintext plus the header fields
    /// (epoch, sender tag, counter) so the caller can do jitter-buffer or
    /// replay bookkeeping keyed on `(sender_tag, counter)`.
    pub fn decrypt(&self, frame: &[u8]) -> Result<(u8, u8, u64, Vec<u8>), CallError> {
        self.ctx.decrypt_frame(frame).map_err(CallError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signaling::{CALLEE_SENDER_TAG, CALLER_SENDER_TAG};
    use bh_crypto::call_keys::{derive_base_key, CallEphemeralKeyPair};

    fn shared_contexts() -> (SframeContext, SframeContext) {
        let caller = CallEphemeralKeyPair::generate();
        let callee = CallEphemeralKeyPair::generate();
        let key = derive_base_key("call-1", &caller, &callee.public());
        let key2 = derive_base_key("call-1", &callee, &caller.public());
        (SframeContext::new(key), SframeContext::new(key2))
    }

    #[test]
    fn encryptor_counter_auto_increments_and_never_repeats() {
        let (caller_ctx, callee_ctx) = shared_contexts();
        let encryptor = FrameEncryptor::new(caller_ctx, CALLER_SENDER_TAG);
        let decryptor = FrameDecryptor::new(callee_ctx);

        let frame1 = encryptor.encrypt(b"frame one").unwrap();
        let frame2 = encryptor.encrypt(b"frame two").unwrap();
        assert_ne!(frame1, frame2);

        let (_, _, counter1, plaintext1) = decryptor.decrypt(&frame1).unwrap();
        let (_, _, counter2, plaintext2) = decryptor.decrypt(&frame2).unwrap();
        assert_eq!(counter1, 0);
        assert_eq!(counter2, 1);
        assert_eq!(plaintext1, b"frame one");
        assert_eq!(plaintext2, b"frame two");
    }

    #[test]
    fn rotating_epoch_resets_counter_and_changes_ciphertext() {
        let (caller_ctx, callee_ctx) = shared_contexts();
        let encryptor = FrameEncryptor::new(caller_ctx, CALLEE_SENDER_TAG);
        let decryptor = FrameDecryptor::new(callee_ctx);

        let before = encryptor.encrypt(b"same plaintext").unwrap();
        encryptor.rotate_epoch(1);
        let after = encryptor.encrypt(b"same plaintext").unwrap();
        assert_ne!(before, after);

        let (epoch, _, counter, _) = decryptor.decrypt(&after).unwrap();
        assert_eq!(epoch, 1);
        assert_eq!(counter, 0);
    }
}
