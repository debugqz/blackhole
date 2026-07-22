//! Voice/video calls. See `docs/SPEC.md` calls section and
//! `docs/THREAT_MODEL.md` for the security model this crate implements:
//!
//! - **Signaling** (`signaling.rs`): offer/answer/candidate exchange and
//!   the call's ephemeral key agreement, both built on
//!   `bh_crypto::{envelope, call_keys}`. Transport-agnostic — knows nothing
//!   about WebRTC.
//! - **Transport** (`transport.rs`): a real WebRTC (ICE/DTLS/SRTP) peer
//!   connection via `webrtc-rs`, giving hop security "for free" from an
//!   audited implementation.
//! - **Media crypto** (`media_crypto.rs`): wraps `bh_crypto::call_keys`'s
//!   SFrame layer with a per-sender monotonic counter, so callers don't
//!   have to manage frame counters themselves. This is what actually makes
//!   the call end-to-end encrypted — DTLS-SRTP alone only protects each
//!   hop to/from a relay.
//! - **Codecs** (`audio.rs`, `video.rs`): Opus capture/encode/decode/
//!   playback and camera capture/VP8 encode/decode. These touch real
//!   hardware (microphone/speakers/camera) and are accordingly the least
//!   exercised by this crate's own test suite — see each module's doc
//!   comment for exactly what is and isn't covered without physical
//!   devices.
//! - **Session** (`session.rs`): ties the above together into one call.
//!
//! Consistent with the rest of this workspace's honesty about scope: the
//! signaling/key-agreement/media-crypto/transport path is real and tested
//! against actual local WebRTC peer connections (see `transport.rs` tests).
//! What is *not* yet exercised by an automated test is a call running
//! against real, physically-present audio/video hardware, or against a
//! WebRTC peer across a real NAT/Internet path — no STUN/TURN is wired in
//! yet (mirrors `bh-network`'s own current state).

pub mod audio;
pub mod group;
pub mod media_crypto;
pub mod screen;
pub mod session;
pub mod signaling;
pub mod transport;
pub mod video;

#[derive(Debug, thiserror::Error)]
pub enum CallError {
    #[error("signaling message was not the expected variant")]
    UnexpectedSignal,
    #[error("call id in signal did not match this call")]
    CallIdMismatch,
    #[error("call media/frame encryption failed")]
    Crypto(#[from] bh_crypto::CryptoError),
    #[error("webrtc transport error: {0}")]
    Transport(String),
    #[error("audio device error: {0}")]
    Audio(String),
    #[error("video device error: {0}")]
    Video(String),
    #[error("codec error: {0}")]
    Codec(String),
}
