//! Ties signaling (`signaling.rs`), transport (`transport.rs`), and media
//! crypto (`media_crypto.rs`) together into the facade a daemon would
//! actually drive to place/answer a call. See `transport.rs`'s own test
//! for a fully worked, lower-level example of every step this wraps.
//!
//! Scope note: [`CallSession`]'s receive side wires up audio only (Opus).
//! Video capture/encode/encrypt/send is implemented (`video.rs`) and can
//! be sent over a session's peer connection the same way audio is, but
//! receive-side video (depacketize + hand off to the client for decode —
//! see `video.rs`'s scope note on why decoding isn't implemented here) and
//! mixed audio+video track routing are not yet wired into this facade.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use webrtc::media::io::sample_builder::SampleBuilder;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::rtp::codecs::opus::OpusPacket;
use webrtc::rtp_transceiver::rtp_receiver::RTCRtpReceiver;
use webrtc::rtp_transceiver::RTCRtpTransceiver;
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;
use webrtc::track::track_local::TrackLocal;
use webrtc::track::track_remote::TrackRemote;

use bh_crypto::envelope::CallSignal;

use crate::media_crypto::{FrameDecryptor, FrameEncryptor};
use crate::signaling::{IncomingCall, OutgoingCall, CALLEE_SENDER_TAG, CALLER_SENDER_TAG};
use crate::{transport, CallError};

const OPUS_CLOCK_RATE: u32 = 48_000;
/// How many out-of-order RTP packets the receive-side jitter buffer will
/// wait for before giving up on a sample — see `SampleBuilder::new`.
const SAMPLE_BUILDER_MAX_LATE: u16 = 50;

fn to_call_error(err: impl std::fmt::Display) -> CallError {
    CallError::Transport(err.to_string())
}

fn sdp_from_bytes(bytes: Vec<u8>) -> Result<String, CallError> {
    String::from_utf8(bytes).map_err(|e| CallError::Transport(e.to_string()))
}

/// A live, connected call: signaling and the WebRTC handshake are done,
/// and both sides have derived the same SFrame context.
pub struct CallSession {
    pub call_id: String,
    pc: Arc<RTCPeerConnection>,
    audio_track: Arc<TrackLocalStaticSample>,
    encryptor: FrameEncryptor,
}

impl CallSession {
    fn new(
        call_id: String,
        pc: Arc<RTCPeerConnection>,
        audio_track: Arc<TrackLocalStaticSample>,
        sframe: bh_crypto::call_keys::SframeContext,
        sender_tag: u8,
    ) -> Self {
        Self {
            call_id,
            pc,
            audio_track,
            encryptor: FrameEncryptor::new(sframe, sender_tag),
        }
    }

    /// Encrypts and sends one already-Opus-encoded audio frame.
    pub async fn send_audio_frame(
        &self,
        opus_frame: &[u8],
        duration: Duration,
    ) -> Result<(), CallError> {
        let encrypted = self.encryptor.encrypt(opus_frame)?;
        transport::write_encrypted_sample(&self.audio_track, encrypted, duration).await
    }

    /// Registers a handler that decrypts and forwards decoded-ready Opus
    /// packets from whatever remote track arrives first. `sframe` is the
    /// *same* context this session was built with — the caller passes it
    /// in again because `CallSession` doesn't keep a second copy around
    /// for the receive side (only one `FrameEncryptor` is stored above);
    /// this keeps the encrypt/decrypt key material each in exactly one
    /// place rather than duplicated.
    pub fn on_remote_audio_frame(
        &self,
        sframe: bh_crypto::call_keys::SframeContext,
        remote_sender_tag: u8,
        on_frame: impl FnMut(Vec<u8>) + Send + 'static,
    ) {
        let decryptor = Arc::new(FrameDecryptor::new(sframe));
        // `on_track`'s handler type must be `Sync` (it's stored behind an
        // `ArcSwapOption` and invoked from `tokio::spawn`), but an
        // arbitrary `FnMut` isn't automatically `Sync` — a `Mutex` gives us
        // that for free since only one task ever drives one track's
        // handler at a time anyway.
        let on_frame = Arc::new(Mutex::new(on_frame));
        self.pc.on_track(Box::new(
            move |track: Arc<TrackRemote>,
                  _receiver: Arc<RTCRtpReceiver>,
                  _transceiver: Arc<RTCRtpTransceiver>| {
                let decryptor = decryptor.clone();
                let on_frame = on_frame.clone();
                Box::pin(async move {
                    let sample_builder = Arc::new(Mutex::new(SampleBuilder::new(
                        SAMPLE_BUILDER_MAX_LATE,
                        OpusPacket,
                        OPUS_CLOCK_RATE,
                    )));
                    let mut buf = vec![0u8; 1500];
                    while let Ok((packet, _attrs)) = track.read(&mut buf).await {
                        let mut builder = sample_builder.lock().await;
                        builder.push(packet);
                        while let Some(sample) = builder.pop() {
                            if let Ok((_, tag, _, plaintext)) = decryptor.decrypt(&sample.data) {
                                if tag == remote_sender_tag {
                                    // Note: `on_frame` runs inline in this
                                    // task, not spawned — callers doing
                                    // real decode/playback should keep it
                                    // fast or hand off to their own queue.
                                    let mut on_frame = on_frame.lock().await;
                                    (*on_frame)(plaintext);
                                }
                            }
                        }
                    }
                })
            },
        ));
    }

    pub async fn hangup(&self) -> Result<(), CallError> {
        self.pc.close().await.map_err(to_call_error)
    }
}

/// An outgoing call whose offer has been sent but not yet answered.
pub struct PendingOutgoingCall {
    pc: Arc<RTCPeerConnection>,
    audio_track: Arc<TrackLocalStaticSample>,
    outgoing: OutgoingCall,
}

impl PendingOutgoingCall {
    /// Sets up local transport and produces the offer signal to send the
    /// callee.
    pub async fn start(
        call_id: impl Into<String>,
        video: bool,
    ) -> Result<(Self, CallSignal), CallError> {
        let call_id = call_id.into();
        let pc = transport::new_peer_connection(vec![]).await?;
        let audio_track = transport::new_audio_track(&call_id);
        pc.add_track(audio_track.clone() as Arc<dyn TrackLocal + Send + Sync>)
            .await
            .map_err(to_call_error)?;

        let outgoing = OutgoingCall::new(call_id, video);
        let offer_sdp = transport::create_local_offer(&pc).await?;
        let offer_signal = outgoing.offer(offer_sdp.into_bytes());

        Ok((
            Self {
                pc,
                audio_track,
                outgoing,
            },
            offer_signal,
        ))
    }

    /// Consumes the callee's answer, completing the WebRTC handshake and
    /// returning a live [`CallSession`] plus the SFrame context (handed
    /// back so the caller can also wire up
    /// [`CallSession::on_remote_audio_frame`], which needs it too).
    pub async fn complete(
        self,
        answer: &CallSignal,
    ) -> Result<(CallSession, bh_crypto::call_keys::SframeContext), CallError> {
        let (sframe, answer_sdp) = self.outgoing.accept_answer(answer)?;
        transport::apply_remote_answer(&self.pc, sdp_from_bytes(answer_sdp)?).await?;

        let session = CallSession::new(
            self.outgoing.call_id.clone(),
            self.pc,
            self.audio_track,
            sframe.clone(),
            CALLER_SENDER_TAG,
        );
        Ok((session, sframe))
    }
}

/// Accepts an incoming call offer, completing the handshake immediately
/// (unlike the outgoing side, the callee doesn't need to wait for
/// anything further before the session is live).
pub async fn accept_incoming_call(
    offer: &CallSignal,
) -> Result<(CallSession, bh_crypto::call_keys::SframeContext, CallSignal), CallError> {
    let incoming = IncomingCall::from_offer(offer)?;
    let pc = transport::new_peer_connection(vec![]).await?;
    let audio_track = transport::new_audio_track(&incoming.call_id);
    pc.add_track(audio_track.clone() as Arc<dyn TrackLocal + Send + Sync>)
        .await
        .map_err(to_call_error)?;

    let answer_sdp = transport::create_local_answer(
        &pc,
        sdp_from_bytes(incoming.transport_description.clone())?,
    )
    .await?;
    let (answer_signal, sframe) = incoming.answer(answer_sdp.into_bytes());

    let session = CallSession::new(
        incoming.call_id.clone(),
        pc,
        audio_track,
        sframe.clone(),
        CALLEE_SENDER_TAG,
    );
    Ok((session, sframe, answer_signal))
}
