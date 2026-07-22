//! Ties signaling (`signaling.rs`), transport (`transport.rs`), and media
//! crypto (`media_crypto.rs`) together into the facade a daemon would
//! actually drive to place/answer a call. See `transport.rs`'s own test
//! for a fully worked, lower-level example of every step this wraps.
//!
//! Scope note: [`CallSession`]'s receive side wires up audio only (Opus).
//! Camera video capture/encode/encrypt/send is implemented (`video.rs`)
//! and can be sent over a session's peer connection the same way audio is,
//! but receive-side video (depacketize + hand off to the client for decode
//! — see `video.rs`'s scope note on why decoding isn't implemented here)
//! and mixed audio+video track routing are not yet wired into this
//! facade. Screen sharing (this module's `start_screen_share`/
//! `stop_screen_share`) is the one exception on the *send* side: it's
//! fully wired end to end (capture -> encode -> encrypt -> track), reusing
//! `video.rs`'s encoder and this session's own `FrameEncryptor` rather
//! than adding a second pipeline — see `screen.rs`.

use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{oneshot, Mutex};
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
use crate::screen::ScreenCapture;
use crate::signaling::{IncomingCall, OutgoingCall, CALLEE_SENDER_TAG, CALLER_SENDER_TAG};
use crate::video::VideoEncoder;
use crate::{transport, CallError};

const OPUS_CLOCK_RATE: u32 = 48_000;
/// How many out-of-order RTP packets the receive-side jitter buffer will
/// wait for before giving up on a sample — see `SampleBuilder::new`.
const SAMPLE_BUILDER_MAX_LATE: u16 = 50;

/// Default screen-share capture rate. Screen content is mostly static
/// between user actions, so this is deliberately lower than a camera's
/// typical 30fps — plenty for readable shared content while keeping the
/// VP8 encoder's per-frame CPU cost down.
pub const DEFAULT_SCREEN_SHARE_FPS: u32 = 12;
/// Screen content compresses very differently from camera video (large
/// flat regions, occasional big deltas on scroll/redraw) — this bitrate is
/// tuned for readability of shared text/UI rather than motion smoothness.
const SCREEN_SHARE_BITRATE_KBPS: u32 = 1_500;

fn to_call_error(err: impl std::fmt::Display) -> CallError {
    CallError::Transport(err.to_string())
}

fn sdp_from_bytes(bytes: Vec<u8>) -> Result<String, CallError> {
    String::from_utf8(bytes).map_err(|e| CallError::Transport(e.to_string()))
}

/// A screen-share capture/encode loop in progress, plus what's needed to
/// stop it cleanly. `ScreenCapture`/`VideoEncoder` themselves never leave
/// the blocking thread they're constructed on (see `start_screen_share`) —
/// both wrap `!Send` FFI/platform handles (libvpx's codec context, the
/// platform capturer), so this handle only holds `Send` coordination
/// primitives.
struct ScreenShareHandle {
    stop: Arc<AtomicBool>,
    capture_task: tokio::task::JoinHandle<()>,
    forward_task: tokio::task::JoinHandle<()>,
}

/// A live, connected call: signaling and the WebRTC handshake are done,
/// and both sides have derived the same SFrame context.
pub struct CallSession {
    pub call_id: String,
    pc: Arc<RTCPeerConnection>,
    audio_track: Arc<TrackLocalStaticSample>,
    /// Added to the peer connection eagerly at call setup (see
    /// `PendingOutgoingCall::start`/`accept_incoming_call`), same as
    /// `audio_track`, but only actually carries samples once
    /// `start_screen_share` is running — this facade doesn't yet support
    /// mid-call SDP renegotiation to add a track lazily, so the track
    /// exists from the start and simply stays idle until shared.
    screen_track: Arc<TrackLocalStaticSample>,
    screen_share: Mutex<Option<ScreenShareHandle>>,
    encryptor: FrameEncryptor,
}

impl CallSession {
    fn new(
        call_id: String,
        pc: Arc<RTCPeerConnection>,
        audio_track: Arc<TrackLocalStaticSample>,
        screen_track: Arc<TrackLocalStaticSample>,
        sframe: bh_crypto::call_keys::SframeContext,
        sender_tag: u8,
    ) -> Self {
        Self {
            call_id,
            pc,
            audio_track,
            screen_track,
            screen_share: Mutex::new(None),
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

    /// Encrypts and sends one already-VP8-encoded screen-share frame. Used
    /// internally by [`Self::start_screen_share`]'s forwarding task; also
    /// exposed directly for tests/callers that already have encoded
    /// frames from elsewhere.
    pub async fn send_screen_share_frame(
        &self,
        vp8_frame: &[u8],
        duration: Duration,
    ) -> Result<(), CallError> {
        let encrypted = self.encryptor.encrypt(vp8_frame)?;
        transport::write_encrypted_sample(&self.screen_track, encrypted, duration).await
    }

    /// Starts screen sharing: opens the platform screen capturer, and
    /// pumps frames through the *same* VP8 encoder (`video.rs`) and SFrame
    /// encryptor (`self.encryptor`, the same one audio frames use) camera
    /// video would use — there's no separate encode or encryption path for
    /// screen sharing, just a second track carrying it.
    ///
    /// `ScreenCapture` and `VideoEncoder` both wrap `!Send` FFI/platform
    /// handles, so they're constructed *and* driven entirely inside a
    /// single `spawn_blocking` thread (capture is a blocking call anyway)
    /// rather than being moved in from here; a `oneshot` reports back
    /// whether opening the capturer succeeded (e.g. permission denied)
    /// before this call returns, so failures surface synchronously to the
    /// caller instead of only showing up later in logs. Encoded frames
    /// cross into normal async code over an unbounded channel to a second
    /// task that actually encrypts+sends them (`write_sample` is async).
    ///
    /// Idempotent: calling this while already sharing is a no-op.
    pub async fn start_screen_share(self: Arc<Self>, fps: u32) -> Result<(), CallError> {
        let mut guard = self.screen_share.lock().await;
        if guard.is_some() {
            return Ok(());
        }

        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_capture = stop.clone();
        let (opened_tx, opened_rx) = oneshot::channel::<Result<(), CallError>>();
        let (frame_tx, mut frame_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        let capture_task = tokio::task::spawn_blocking(move || {
            let mut capture = match ScreenCapture::open_default(fps) {
                Ok(capture) => capture,
                Err(err) => {
                    let _ = opened_tx.send(Err(err));
                    return;
                }
            };
            let (width, height) = capture.resolution();
            let mut encoder = match VideoEncoder::new(width, height, SCREEN_SHARE_BITRATE_KBPS) {
                Ok(encoder) => encoder,
                Err(err) => {
                    let _ = opened_tx.send(Err(err));
                    return;
                }
            };
            if opened_tx.send(Ok(())).is_err() {
                // Caller stopped waiting (e.g. dropped/timed out) — nothing
                // downstream can consume frames either way.
                return;
            }

            let frame_period_ms = (1000 / fps.max(1)) as i64;
            let mut pts_ms: i64 = 0;
            while !stop_for_capture.load(AtomicOrdering::SeqCst) {
                let i420 = match capture.capture_i420_frame() {
                    Ok(frame) => frame,
                    Err(err) => {
                        tracing::warn!(%err, "screen capture failed; stopping screen share");
                        break;
                    }
                };
                match encoder.encode_frame(pts_ms, &i420) {
                    Ok(packets) => {
                        for packet in packets {
                            if frame_tx.send(packet.data).is_err() {
                                return;
                            }
                        }
                    }
                    Err(err) => {
                        tracing::warn!(%err, "screen frame encode failed; stopping screen share");
                        break;
                    }
                }
                pts_ms += frame_period_ms;
            }
        });

        match opened_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                let _ = capture_task.await;
                return Err(err);
            }
            Err(_) => {
                let _ = capture_task.await;
                return Err(CallError::Video(
                    "screen capture thread exited before reporting status".into(),
                ));
            }
        }

        let session = self.clone();
        let frame_duration = Duration::from_millis((1000 / fps.max(1)) as u64);
        let forward_task = tokio::spawn(async move {
            while let Some(vp8_frame) = frame_rx.recv().await {
                if let Err(err) = session
                    .send_screen_share_frame(&vp8_frame, frame_duration)
                    .await
                {
                    tracing::warn!(%err, "failed to send screen-share frame; stopping forwarder");
                    break;
                }
            }
        });

        *guard = Some(ScreenShareHandle {
            stop,
            capture_task,
            forward_task,
        });
        Ok(())
    }

    /// Stops screen sharing started by [`Self::start_screen_share`], if
    /// any (idempotent otherwise). Signals the capture thread and waits
    /// for it to notice — bounded by roughly one frame period, since the
    /// thread only checks the stop flag between frames, not while blocked
    /// capturing the current one.
    pub async fn stop_screen_share(&self) {
        let handle = self.screen_share.lock().await.take();
        if let Some(handle) = handle {
            handle.stop.store(true, AtomicOrdering::SeqCst);
            let _ = handle.capture_task.await;
            let _ = handle.forward_task.await;
        }
    }

    pub async fn hangup(&self) -> Result<(), CallError> {
        self.stop_screen_share().await;
        self.pc.close().await.map_err(to_call_error)
    }
}

/// An outgoing call whose offer has been sent but not yet answered.
pub struct PendingOutgoingCall {
    pc: Arc<RTCPeerConnection>,
    audio_track: Arc<TrackLocalStaticSample>,
    screen_track: Arc<TrackLocalStaticSample>,
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
        // Added eagerly alongside audio (see `CallSession::screen_track`'s
        // doc comment) so screen sharing can start mid-call without SDP
        // renegotiation support this facade doesn't have yet.
        let screen_track = transport::new_screen_share_track(&call_id);
        pc.add_track(screen_track.clone() as Arc<dyn TrackLocal + Send + Sync>)
            .await
            .map_err(to_call_error)?;

        let outgoing = OutgoingCall::new(call_id, video);
        let offer_sdp = transport::create_local_offer(&pc).await?;
        let offer_signal = outgoing.offer(offer_sdp.into_bytes());

        Ok((
            Self {
                pc,
                audio_track,
                screen_track,
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
            self.screen_track,
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
    let screen_track = transport::new_screen_share_track(&incoming.call_id);
    pc.add_track(screen_track.clone() as Arc<dyn TrackLocal + Send + Sync>)
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
        screen_track,
        sframe.clone(),
        CALLEE_SENDER_TAG,
    );
    Ok((session, sframe, answer_signal))
}
