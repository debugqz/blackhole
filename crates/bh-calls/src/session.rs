//! Ties signaling (`signaling.rs`), transport (`transport.rs`), and media
//! crypto (`media_crypto.rs`) together into the facade a daemon would
//! actually drive to place/answer a call. See `transport.rs`'s own test
//! for a fully worked, lower-level example of every step this wraps.
//!
//! Camera video (`start_camera`/`stop_camera`) and screen sharing
//! (`start_screen_share`/`stop_screen_share`) share the same capture ->
//! encode -> SFrame-encrypt -> track pipeline (`start_capture_loop`), just
//! pointed at different capture backends (`video::CameraCapture` vs
//! `screen::ScreenCapture`) and tracks — there is no separate pipeline for
//! either. Receive-side audio/video/screen frames are all delivered
//! through the one [`CallSession::on_remote_media`] registration: WebRTC
//! only supports a single `on_track` handler per peer connection (see its
//! own doc comment), so this dispatches by `TrackRemote::id()`
//! ("audio"/"video"/"screen") to the right depacketizer/decryptor/
//! callback internally rather than composing three independent
//! registrations. Decoding the *video* bitstream itself (VP8) is
//! deliberately left to the caller (see `video.rs`'s module doc: no
//! audited safe-Rust VP8 decoder exists) — `on_remote_media`'s video/
//! screen callbacks receive the still-encoded, already-decrypted
//! bitstream, same as `video.rs`'s scope note has long described.

use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{oneshot, Mutex};
use webrtc::media::io::sample_builder::SampleBuilder;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::rtp::codecs::opus::OpusPacket;
use webrtc::rtp::codecs::vp8::Vp8Packet;
use webrtc::rtp_transceiver::rtp_receiver::RTCRtpReceiver;
use webrtc::rtp_transceiver::RTCRtpTransceiver;
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;
use webrtc::track::track_local::TrackLocal;
use webrtc::track::track_remote::TrackRemote;

use bh_crypto::envelope::CallSignal;

use crate::media_crypto::{FrameDecryptor, FrameEncryptor};
use crate::screen::ScreenCapture;
use crate::signaling::{IncomingCall, OutgoingCall, CALLEE_SENDER_TAG, CALLER_SENDER_TAG};
use crate::video::{CameraCapture, VideoEncoder};
use crate::{transport, CallError};

const OPUS_CLOCK_RATE: u32 = 48_000;
const VP8_CLOCK_RATE: u32 = 90_000;
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

/// Default camera capture rate — standard webcam smoothness for a video
/// call, distinct from screen sharing's much lower rate.
pub const DEFAULT_CAMERA_FPS: u32 = 24;
/// Tuned for motion (talking-head video), not text readability — lower
/// than screen sharing's bitrate since camera content at call resolution
/// needs less of a bit budget.
const CAMERA_BITRATE_KBPS: u32 = 800;

/// A boxed, shareable frame callback — `on_remote_media`'s three callback
/// parameters (arbitrary, differently-typed closures at each call site)
/// all end up stored this way so [`run_depacketize_loop`] can be one
/// non-generic-over-closure-type function shared by every track kind.
type FrameCallback = Arc<Mutex<Box<dyn FnMut(Vec<u8>) + Send>>>;

fn to_call_error(err: impl std::fmt::Display) -> CallError {
    CallError::Transport(err.to_string())
}

fn sdp_from_bytes(bytes: Vec<u8>) -> Result<String, CallError> {
    String::from_utf8(bytes).map_err(|e| CallError::Transport(e.to_string()))
}

/// A capture backend that can be polled for I420 frames, one call at a
/// time, from whichever blocking thread `start_capture_loop` drives it
/// on. Implemented by both [`CameraCapture`] and [`ScreenCapture`] — see
/// this module's doc comment for why one capture/encode loop can serve
/// both.
trait FrameSource {
    fn capture_i420_frame(&mut self) -> Result<Vec<u8>, CallError>;
}

impl FrameSource for CameraCapture {
    fn capture_i420_frame(&mut self) -> Result<Vec<u8>, CallError> {
        CameraCapture::capture_i420_frame(self)
    }
}

impl FrameSource for ScreenCapture {
    fn capture_i420_frame(&mut self) -> Result<Vec<u8>, CallError> {
        ScreenCapture::capture_i420_frame(self)
    }
}

/// A capture/encode loop in progress, plus what's needed to stop it
/// cleanly. The `FrameSource`/`VideoEncoder` pair driving it never leaves
/// the blocking thread they're constructed on (see `start_capture_loop`)
/// — both wrap `!Send` FFI/platform handles (libvpx's codec context, the
/// platform capturer/camera), so this handle only holds `Send`
/// coordination primitives.
struct CaptureHandle {
    stop: Arc<AtomicBool>,
    capture_task: tokio::task::JoinHandle<()>,
    forward_task: tokio::task::JoinHandle<()>,
}

impl CaptureHandle {
    /// Signals the capture thread and waits for both tasks to notice —
    /// bounded by roughly one frame period, since the capture thread only
    /// checks the stop flag between frames, not while blocked capturing
    /// the current one.
    async fn stop_and_join(self) {
        self.stop.store(true, AtomicOrdering::SeqCst);
        let _ = self.capture_task.await;
        let _ = self.forward_task.await;
    }
}

/// A live, connected call: signaling and the WebRTC handshake are done,
/// and both sides have derived the same SFrame context.
pub struct CallSession {
    pub call_id: String,
    pc: Arc<RTCPeerConnection>,
    audio_track: Arc<TrackLocalStaticSample>,
    video_track: Arc<TrackLocalStaticSample>,
    /// Added to the peer connection eagerly at call setup (see
    /// `PendingOutgoingCall::start`/`accept_incoming_call`), same as
    /// `audio_track`/`video_track`, but only actually carries samples
    /// once `start_screen_share`/`start_camera` is running — this facade
    /// doesn't yet support mid-call SDP renegotiation to add a track
    /// lazily, so every track exists from the start and simply stays idle
    /// until its capture loop starts.
    screen_track: Arc<TrackLocalStaticSample>,
    screen_share: Mutex<Option<CaptureHandle>>,
    camera: Mutex<Option<CaptureHandle>>,
    encryptor: FrameEncryptor,
}

impl CallSession {
    fn new(
        call_id: String,
        pc: Arc<RTCPeerConnection>,
        audio_track: Arc<TrackLocalStaticSample>,
        video_track: Arc<TrackLocalStaticSample>,
        screen_track: Arc<TrackLocalStaticSample>,
        sframe: bh_crypto::call_keys::SframeContext,
        sender_tag: u8,
    ) -> Self {
        Self {
            call_id,
            pc,
            audio_track,
            video_track,
            screen_track,
            screen_share: Mutex::new(None),
            camera: Mutex::new(None),
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

    /// Encrypts and sends one already-VP8-encoded camera-video frame.
    /// Used internally by [`Self::start_camera`]'s forwarding task; also
    /// exposed directly for tests/callers that already have encoded
    /// frames from elsewhere.
    pub async fn send_video_frame(
        &self,
        vp8_frame: &[u8],
        duration: Duration,
    ) -> Result<(), CallError> {
        let encrypted = self.encryptor.encrypt(vp8_frame)?;
        transport::write_encrypted_sample(&self.video_track, encrypted, duration).await
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

    /// Registers the *single* handler this call's remote media (audio,
    /// camera video, and screen share) is delivered through — see this
    /// module's doc comment for why one registration has to cover all
    /// three rather than composing independent ones. `sframe` is the
    /// *same* context this session was built with — the caller passes it
    /// in again because `CallSession` doesn't keep a second copy around
    /// for the receive side (only one `FrameEncryptor` is stored above);
    /// this keeps the encrypt/decrypt key material each in exactly one
    /// place rather than duplicated. Video/screen callbacks receive
    /// still-VP8-encoded, already-decrypted bytes — decoding is the
    /// caller's job (see module doc).
    pub fn on_remote_media(
        &self,
        sframe: bh_crypto::call_keys::SframeContext,
        remote_sender_tag: u8,
        on_audio_frame: impl FnMut(Vec<u8>) + Send + 'static,
        on_video_frame: impl FnMut(Vec<u8>) + Send + 'static,
        on_screen_frame: impl FnMut(Vec<u8>) + Send + 'static,
    ) {
        let decryptor = Arc::new(FrameDecryptor::new(sframe));
        let on_audio_frame: FrameCallback = Arc::new(Mutex::new(Box::new(on_audio_frame)));
        let on_video_frame: FrameCallback = Arc::new(Mutex::new(Box::new(on_video_frame)));
        let on_screen_frame: FrameCallback = Arc::new(Mutex::new(Box::new(on_screen_frame)));

        self.pc.on_track(Box::new(
            move |track: Arc<TrackRemote>,
                  _receiver: Arc<RTCRtpReceiver>,
                  _transceiver: Arc<RTCRtpTransceiver>| {
                let decryptor = decryptor.clone();
                eprintln!(
                    "[DEBUG on_track] id={:?} stream_id={:?} kind={:?} ssrc={:?} payload_type={:?}",
                    track.id(),
                    track.stream_id(),
                    track.kind(),
                    track.ssrc(),
                    track.payload_type(),
                );
                match track.id().as_str() {
                    "audio" => Box::pin(run_depacketize_loop(
                        track,
                        decryptor,
                        remote_sender_tag,
                        on_audio_frame.clone(),
                        OpusPacket,
                        OPUS_CLOCK_RATE,
                    )),
                    "video" => Box::pin(run_depacketize_loop(
                        track,
                        decryptor,
                        remote_sender_tag,
                        on_video_frame.clone(),
                        Vp8Packet::default(),
                        VP8_CLOCK_RATE,
                    )),
                    "screen" => Box::pin(run_depacketize_loop(
                        track,
                        decryptor,
                        remote_sender_tag,
                        on_screen_frame.clone(),
                        Vp8Packet::default(),
                        VP8_CLOCK_RATE,
                    )),
                    _ => Box::pin(async {}),
                }
            },
        ));
    }

    /// Shared machinery behind [`Self::start_camera`]/
    /// [`Self::start_screen_share`]: opens a capture+encoder pair (via
    /// `open`, constructed entirely on the blocking thread this spawns,
    /// since both wrap `!Send` FFI/platform handles) and pumps encoded VP8
    /// frames to `track` at `fps`. A `oneshot` reports back whether
    /// opening the capturer succeeded (e.g. permission denied) before this
    /// returns, so failures surface synchronously to the caller instead of
    /// only showing up later in logs.
    async fn start_capture_loop(
        self: &Arc<Self>,
        fps: u32,
        track: Arc<TrackLocalStaticSample>,
        mut on_local_frame: impl FnMut(Vec<u8>) + Send + 'static,
        open: impl FnOnce() -> Result<(Box<dyn FrameSource>, u32, u32, u32), CallError> + Send + 'static,
    ) -> Result<CaptureHandle, CallError> {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_capture = stop.clone();
        let (opened_tx, opened_rx) = oneshot::channel::<Result<(), CallError>>();
        let (frame_tx, mut frame_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        let capture_task = tokio::task::spawn_blocking(move || {
            let (mut source, width, height, bitrate_kbps) = match open() {
                Ok(v) => v,
                Err(err) => {
                    let _ = opened_tx.send(Err(err));
                    return;
                }
            };
            let mut encoder = match VideoEncoder::new(width, height, bitrate_kbps) {
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
                let i420 = match source.capture_i420_frame() {
                    Ok(frame) => frame,
                    Err(err) => {
                        tracing::warn!(%err, "capture failed; stopping capture loop");
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
                        tracing::warn!(%err, "frame encode failed; stopping capture loop");
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
                    "capture thread exited before reporting status".into(),
                ));
            }
        }

        let session = self.clone();
        let frame_duration = Duration::from_millis((1000 / fps.max(1)) as u64);
        let forward_task = tokio::spawn(async move {
            while let Some(vp8_frame) = frame_rx.recv().await {
                // Local self-preview: the caller sees exactly the encoded
                // bytes about to be sent, before encryption — same VP8
                // bitstream a remote peer will eventually decrypt and
                // decode, so preview and "what the other side sees" never
                // diverge. See this module's/`CLAUDE.md`'s note on why
                // this loopback avoids opening the camera a second time.
                on_local_frame(vp8_frame.clone());
                let encrypted = match session.encryptor.encrypt(&vp8_frame) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        tracing::warn!(%err, "failed to encrypt frame; stopping forwarder");
                        break;
                    }
                };
                if let Err(err) =
                    transport::write_encrypted_sample(&track, encrypted, frame_duration).await
                {
                    tracing::warn!(%err, "failed to send frame; stopping forwarder");
                    break;
                }
            }
        });

        Ok(CaptureHandle {
            stop,
            capture_task,
            forward_task,
        })
    }

    /// Starts sending camera video: opens the system's default camera and
    /// pumps frames through the VP8 encoder + SFrame encryption path
    /// (`self.encryptor`, the same one audio/screen-share frames use) onto
    /// this session's dedicated video track. `on_local_frame` is called
    /// with each encoded (pre-encryption) frame for local self-preview —
    /// see `start_capture_loop`'s doc comment. Idempotent: calling this
    /// while already sending camera video is a no-op.
    pub async fn start_camera(
        self: Arc<Self>,
        fps: u32,
        on_local_frame: impl FnMut(Vec<u8>) + Send + 'static,
    ) -> Result<(), CallError> {
        let mut guard = self.camera.lock().await;
        if guard.is_some() {
            return Ok(());
        }
        let track = self.video_track.clone();
        let handle = self
            .start_capture_loop(fps, track, on_local_frame, move || {
                let capture = CameraCapture::open_default()?;
                let (width, height) = capture.resolution();
                Ok((
                    Box::new(capture) as Box<dyn FrameSource>,
                    width,
                    height,
                    CAMERA_BITRATE_KBPS,
                ))
            })
            .await?;
        *guard = Some(handle);
        Ok(())
    }

    /// Stops camera video started by [`Self::start_camera`], if any
    /// (idempotent otherwise).
    pub async fn stop_camera(&self) {
        if let Some(handle) = self.camera.lock().await.take() {
            handle.stop_and_join().await;
        }
    }

    /// Starts screen sharing: opens the platform screen capturer, and
    /// pumps frames through the *same* VP8 encoder (`video.rs`) and SFrame
    /// encryptor (`self.encryptor`, the same one audio/camera frames use)
    /// camera video uses — there's no separate encode or encryption path
    /// for screen sharing, just a second track carrying it. `on_local_frame`
    /// mirrors `start_camera`'s — local self-preview of what's being shared.
    ///
    /// Idempotent: calling this while already sharing is a no-op.
    pub async fn start_screen_share(
        self: Arc<Self>,
        fps: u32,
        on_local_frame: impl FnMut(Vec<u8>) + Send + 'static,
    ) -> Result<(), CallError> {
        let mut guard = self.screen_share.lock().await;
        if guard.is_some() {
            return Ok(());
        }
        let track = self.screen_track.clone();
        let handle = self
            .start_capture_loop(fps, track, on_local_frame, move || {
                let capture = ScreenCapture::open_default(fps)?;
                let (width, height) = capture.resolution();
                Ok((
                    Box::new(capture) as Box<dyn FrameSource>,
                    width,
                    height,
                    SCREEN_SHARE_BITRATE_KBPS,
                ))
            })
            .await?;
        *guard = Some(handle);
        Ok(())
    }

    /// Stops screen sharing started by [`Self::start_screen_share`], if
    /// any (idempotent otherwise).
    pub async fn stop_screen_share(&self) {
        if let Some(handle) = self.screen_share.lock().await.take() {
            handle.stop_and_join().await;
        }
    }

    pub async fn hangup(&self) -> Result<(), CallError> {
        self.stop_camera().await;
        self.stop_screen_share().await;
        self.pc.close().await.map_err(to_call_error)
    }
}

/// Depacketizes+reassembles one remote track's RTP stream into samples,
/// decrypts each with `decryptor`, and forwards plaintext bytes for
/// samples tagged `remote_sender_tag` to `on_frame`. Shared by every
/// track kind `on_remote_media` handles — audio (Opus) and video/screen
/// (VP8) differ only in which `Depacketizer`/clock rate they're built
/// with.
async fn run_depacketize_loop<D>(
    track: Arc<TrackRemote>,
    decryptor: Arc<FrameDecryptor>,
    remote_sender_tag: u8,
    on_frame: FrameCallback,
    depacketizer: D,
    clock_rate: u32,
) where
    D: webrtc::rtp::packetizer::Depacketizer + Send + Sync + 'static,
{
    let sample_builder = Arc::new(Mutex::new(SampleBuilder::new(
        SAMPLE_BUILDER_MAX_LATE,
        depacketizer,
        clock_rate,
    )));
    let track_id = track.id();
    eprintln!("[DEBUG depacketize_loop] starting for track id={track_id:?}");
    let mut buf = vec![0u8; 1500];
    while let Ok((packet, _attrs)) = track.read(&mut buf).await {
        eprintln!(
            "[DEBUG depacketize_loop] id={track_id:?} read packet seq={} ts={} payload_len={}",
            packet.header.sequence_number,
            packet.header.timestamp,
            packet.payload.len()
        );
        let mut builder = sample_builder.lock().await;
        builder.push(packet);
        while let Some(sample) = builder.pop() {
            eprintln!(
                "[DEBUG depacketize_loop] id={track_id:?} sample_builder popped {} bytes",
                sample.data.len()
            );
            if let Ok((_, tag, _, plaintext)) = decryptor.decrypt(&sample.data) {
                eprintln!(
                    "[DEBUG depacketize_loop] id={track_id:?} decrypt ok tag={tag} \
                     remote_sender_tag={remote_sender_tag}"
                );
                if tag == remote_sender_tag {
                    // Note: `on_frame` runs inline in this task, not
                    // spawned — callers doing real decode/playback should
                    // keep it fast or hand off to their own queue.
                    let mut on_frame = on_frame.lock().await;
                    (*on_frame)(plaintext);
                }
            }
        }
    }
    eprintln!("[DEBUG depacketize_loop] id={track_id:?} track.read loop ended (EOF/error)");
}

/// An outgoing call whose offer has been sent but not yet answered.
pub struct PendingOutgoingCall {
    pc: Arc<RTCPeerConnection>,
    audio_track: Arc<TrackLocalStaticSample>,
    video_track: Arc<TrackLocalStaticSample>,
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
        let pc = transport::new_peer_connection(transport::default_ice_servers()).await?;
        let audio_track = transport::new_audio_track(&call_id);
        pc.add_track(audio_track.clone() as Arc<dyn TrackLocal + Send + Sync>)
            .await
            .map_err(to_call_error)?;
        // Video and screen-share tracks are added eagerly alongside audio
        // (see `CallSession::screen_track`'s doc comment) so either can
        // start mid-call without SDP renegotiation support this facade
        // doesn't have yet.
        let video_track = transport::new_video_track(&call_id);
        pc.add_track(video_track.clone() as Arc<dyn TrackLocal + Send + Sync>)
            .await
            .map_err(to_call_error)?;
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
                video_track,
                screen_track,
                outgoing,
            },
            offer_signal,
        ))
    }

    /// Consumes the callee's answer, completing the WebRTC handshake and
    /// returning a live [`CallSession`] plus the SFrame context (handed
    /// back so the caller can also wire up
    /// [`CallSession::on_remote_media`], which needs it too).
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
            self.video_track,
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
    let pc = transport::new_peer_connection(transport::default_ice_servers()).await?;
    let audio_track = transport::new_audio_track(&incoming.call_id);
    pc.add_track(audio_track.clone() as Arc<dyn TrackLocal + Send + Sync>)
        .await
        .map_err(to_call_error)?;
    let video_track = transport::new_video_track(&incoming.call_id);
    pc.add_track(video_track.clone() as Arc<dyn TrackLocal + Send + Sync>)
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
        video_track,
        screen_track,
        sframe.clone(),
        CALLEE_SENDER_TAG,
    );
    Ok((session, sframe, answer_signal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration as StdDuration;

    /// End-to-end: a full `PendingOutgoingCall::start` /
    /// `accept_incoming_call` / `complete` handshake (audio + video +
    /// screen tracks all added, matching real call setup) between two real
    /// local peer connections, then the caller sends one frame on each of
    /// its three tracks and the callee's *single* `on_remote_media`
    /// registration must route each to the right callback — proof that
    /// dispatching by `TrackRemote::id()` inside one `on_track` handler
    /// actually works, not just that three independent registrations
    /// would (which WebRTC doesn't support — see module doc).
    #[tokio::test]
    async fn on_remote_media_routes_each_track_to_its_own_callback() {
        let (pending, offer) = PendingOutgoingCall::start("session-test-call", true)
            .await
            .unwrap();
        let (callee_session, callee_sframe, answer) = accept_incoming_call(&offer).await.unwrap();
        let (caller_session, _caller_sframe) = pending.complete(&answer).await.unwrap();

        wait_connected(&session_pc(&caller_session)).await;
        wait_connected(&session_pc(&callee_session)).await;

        let audio_frames: Arc<StdMutex<Vec<Vec<u8>>>> = Arc::new(StdMutex::new(Vec::new()));
        let video_frames: Arc<StdMutex<Vec<Vec<u8>>>> = Arc::new(StdMutex::new(Vec::new()));
        let screen_frames: Arc<StdMutex<Vec<Vec<u8>>>> = Arc::new(StdMutex::new(Vec::new()));
        let (a, v, s) = (
            audio_frames.clone(),
            video_frames.clone(),
            screen_frames.clone(),
        );
        callee_session.on_remote_media(
            callee_sframe,
            CALLER_SENDER_TAG,
            move |frame| a.lock().unwrap().push(frame),
            move |frame| v.lock().unwrap().push(frame),
            move |frame| s.lock().unwrap().push(frame),
        );

        // A handful of frames per track, tagged with their index.
        for i in 0..3 {
            caller_session
                .send_audio_frame(
                    format!("audio-{i}").as_bytes(),
                    StdDuration::from_millis(20),
                )
                .await
                .unwrap();
            caller_session
                .send_video_frame(
                    format!("video-{i}").as_bytes(),
                    StdDuration::from_millis(33),
                )
                .await
                .unwrap();
            caller_session
                .send_screen_share_frame(
                    format!("screen-{i}").as_bytes(),
                    StdDuration::from_millis(100),
                )
                .await
                .unwrap();
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }

        // Keep nudging every track with a flush frame (the receive side's
        // `SampleBuilder` needs a later-timestamped packet before it
        // releases the previous one — same technique `transport.rs`'s own
        // tests use) until every callback has caught up or the deadline
        // hits, instead of a fixed burst of 3 up front: this is real UDP
        // over the loopback interface, and a CI runner under resource
        // contention can drop a packet — a one-shot flush burst then
        // strands that track's last real frame in its jitter buffer
        // forever (nothing else arrives to release it), where continuous
        // retries just cost a little more wall time.
        let deadline = tokio::time::Instant::now() + StdDuration::from_secs(15);
        while (audio_frames.lock().unwrap().len() < 3
            || video_frames.lock().unwrap().len() < 3
            || screen_frames.lock().unwrap().len() < 3)
            && tokio::time::Instant::now() < deadline
        {
            caller_session
                .send_audio_frame(b"__flush__", StdDuration::from_millis(20))
                .await
                .unwrap();
            caller_session
                .send_video_frame(b"__flush__", StdDuration::from_millis(33))
                .await
                .unwrap();
            caller_session
                .send_screen_share_frame(b"__flush__", StdDuration::from_millis(100))
                .await
                .unwrap();
            tokio::time::sleep(StdDuration::from_millis(50)).await;
        }

        // Compare only the first 3 frames of each: the wait loop above races
        // the still-running depacketize loops, which may have already
        // pushed one or more `__flush__` frames past the length-3 threshold
        // by the time this grabs the lock again — that's expected, not a
        // routing bug, so it shouldn't fail the assertion.
        assert_eq!(
            audio_frames.lock().unwrap()[..3].to_vec(),
            vec![
                b"audio-0".to_vec(),
                b"audio-1".to_vec(),
                b"audio-2".to_vec()
            ],
            "audio callback must only ever see audio frames, in order"
        );
        assert_eq!(
            video_frames.lock().unwrap()[..3].to_vec(),
            vec![
                b"video-0".to_vec(),
                b"video-1".to_vec(),
                b"video-2".to_vec()
            ],
            "video callback must only ever see video frames, in order"
        );
        assert_eq!(
            screen_frames.lock().unwrap()[..3].to_vec(),
            vec![
                b"screen-0".to_vec(),
                b"screen-1".to_vec(),
                b"screen-2".to_vec()
            ],
            "screen callback must only ever see screen-share frames, in order"
        );
    }

    async fn wait_connected(pc: &Arc<RTCPeerConnection>) {
        use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
        let tx = Arc::new(tx);
        pc.on_peer_connection_state_change(Box::new(move |state| {
            if state == RTCPeerConnectionState::Connected {
                let tx = tx.clone();
                return Box::pin(async move {
                    let _ = tx.send(()).await;
                });
            }
            Box::pin(async {})
        }));
        if pc.connection_state() == RTCPeerConnectionState::Connected {
            return;
        }
        tokio::time::timeout(StdDuration::from_secs(30), rx.recv())
            .await
            .expect("peer connection did not reach Connected in time")
            .expect("state-change channel closed");
    }

    fn session_pc(session: &CallSession) -> Arc<RTCPeerConnection> {
        session.pc.clone()
    }
}
