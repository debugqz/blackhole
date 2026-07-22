//! Real-time call state + media streaming from the daemon to the UI —
//! the piece `calls.rs`'s REST endpoints alone can't provide (signaling
//! is request/response; ringing/connected/participant-joined notifications
//! and video frames need the daemon to push, not just answer). One
//! `GET /calls/:call_id/ws` WebSocket per call bridges a
//! `tokio::sync::broadcast` channel (fed by `calls.rs` as the call
//! progresses) to the client: JSON text frames for [`CallEvent`], binary
//! frames (a one-byte [`FrameKind`] tag + raw VP8 bytes) for video.
//!
//! **Audio never travels this channel at all.** `bh-calls::audio`
//! implements real microphone capture and speaker playback natively via
//! `cpal`; `calls.rs` wires a call's `CallSession::send_audio_frame`/
//! `on_remote_media` audio callback straight to that hardware in the
//! daemon process, so call audio just plays on the machine's own speakers
//! — there's nothing for the UI to render or decode. Video is different
//! only because decoding VP8 is deliberately left to the client (no
//! audited safe-Rust decoder — see `bh-calls::video`'s module doc): the
//! daemon forwards the already-decrypted bitstream here, and the client
//! decodes it locally (e.g. via the browser's `WebCodecs` API).

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::Serialize;
use tokio::sync::broadcast;

use crate::AppState;

/// How many messages a lagging WebSocket client can fall behind before
/// older ones are dropped for it specifically (`broadcast::Receiver`'s own
/// backpressure model) — generous enough to absorb a brief stall without
/// either blocking the sender (video capture must never wait on a slow
/// UI) or growing unboundedly.
pub const CALL_STREAM_CHANNEL_CAPACITY: usize = 256;

/// Out-of-band call state, pushed as JSON text WebSocket frames.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CallEvent {
    /// The call's WebRTC transport reached `Connected` — both sides can
    /// now exchange media, not just signaling.
    Connected,
    /// A group call gained a participant (including shadow ones — see
    /// `calls.rs`'s module doc on why group calls' *other* participants
    /// are locally simulated today).
    ParticipantJoined {
        tag: u8,
    },
    ParticipantLeft {
        tag: u8,
    },
    /// The call ended — either side hung up, or the connection dropped.
    Hangup,
}

/// Which track a binary WebSocket frame's payload came from. `Local*`
/// variants are this daemon's own outgoing (pre-encryption) frames, looped
/// back for self-preview — see `bh-calls::session`'s `start_camera`/
/// `start_screen_share` doc comments for why that avoids opening the
/// camera/capturer a second time.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum FrameKind {
    RemoteVideo = 0,
    RemoteScreen = 1,
    LocalVideo = 2,
    LocalScreen = 3,
}

/// One message on a call's stream: either state (`CallEvent`, sent as
/// JSON text) or a video/screen-share frame (sent as a tagged binary
/// blob). `Arc<[u8]>` rather than `Vec<u8>` for the frame payload — a
/// `broadcast` channel clones every message once per receiver, and this
/// keeps that clone a cheap refcount bump instead of copying the whole
/// (potentially several-KB) frame per connected client.
#[derive(Debug, Clone)]
pub enum CallStreamMessage {
    Event(CallEvent),
    Frame { kind: FrameKind, bytes: Arc<[u8]> },
}

impl CallStreamMessage {
    pub fn frame(kind: FrameKind, bytes: Vec<u8>) -> Self {
        Self::Frame {
            kind,
            bytes: Arc::from(bytes),
        }
    }
}

/// Publishes to a call's stream if anyone's listening; silently a no-op
/// (not an error) if nothing has subscribed yet or the call already
/// ended — a dropped video frame or missed "connected" event because the
/// UI hadn't opened the WebSocket yet is expected, not exceptional.
pub fn publish(sender: &broadcast::Sender<CallStreamMessage>, message: CallStreamMessage) {
    let _ = sender.send(message);
}

/// Upgrades to a WebSocket streaming `call_id`'s events/video frames as
/// they happen. `404` if the call doesn't exist (or already ended) —
/// there is deliberately no "connect early and wait for the call to
/// start" mode; the client creates the call (`POST /calls`) or accepts
/// one (`POST /calls/incoming`) first, same ordering `calls.rs`'s other
/// endpoints already require.
pub async fn call_ws(
    State(state): State<Arc<AppState>>,
    Path(call_id): Path<String>,
    ws: WebSocketUpgrade,
) -> Result<Response, StatusCode> {
    let (rx, current) = state
        .calls
        .subscribe_with_current_state(&call_id)
        .await
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(ws.on_upgrade(move |socket| handle_socket(socket, rx, current)))
}

/// `current` is the call's last-recorded event (if any) at subscribe time —
/// sent first, before live updates, so a client that connects after
/// `accept_call`/`complete_call`/`start_group_call` already published their
/// first event (a real race: those handlers record it synchronously, before
/// the client could possibly have opened this WebSocket yet) still learns
/// the call reached e.g. `Connected` instead of waiting forever for an
/// event that already happened. See `CallRegistry::record_event`'s doc.
async fn handle_socket(
    mut socket: WebSocket,
    mut rx: broadcast::Receiver<CallStreamMessage>,
    current: Option<CallEvent>,
) {
    if let Some(event) = current {
        if let Ok(json) = serde_json::to_string(&event) {
            if socket.send(Message::Text(json)).await.is_err() {
                return;
            }
        }
    }
    loop {
        tokio::select! {
            outgoing = rx.recv() => {
                let message = match outgoing {
                    Ok(CallStreamMessage::Event(event)) => {
                        match serde_json::to_string(&event) {
                            Ok(json) => Message::Text(json),
                            Err(_) => continue,
                        }
                    }
                    Ok(CallStreamMessage::Frame { kind, bytes }) => {
                        let mut framed = Vec::with_capacity(1 + bytes.len());
                        framed.push(kind as u8);
                        framed.extend_from_slice(&bytes);
                        Message::Binary(framed)
                    }
                    // A slow client fell behind the channel capacity —
                    // some frames/events were dropped for it specifically
                    // (other receivers are unaffected); just keep going
                    // from wherever the channel is now rather than
                    // disconnecting over a transient stall.
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                if socket.send(message).await.is_err() {
                    break;
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    None | Some(Ok(Message::Close(_))) | Some(Err(_)) => break,
                    // This is a server-push channel — the client isn't
                    // expected to send anything, but draining pings/
                    // whatever it does send keeps the socket healthy
                    // instead of accumulating unread frames.
                    Some(Ok(_)) => {}
                }
            }
        }
    }
}
