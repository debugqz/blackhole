//! Voice/video call endpoints, backed by `bh-calls` (real WebRTC transport
//! plus SFrame end-to-end media encryption — see that crate's docs).
//!
//! **1:1 call signaling now travels over the real network** the same way
//! `Direct` messages do (`message_crypto.rs`/`message_receive.rs`):
//! [`start_call`] with a `contact_id` pushes the resulting
//! `CallSignal::Offer` straight to that contact's mailbox
//! (`send_call_signal`), wrapped in `Envelope::Call` inside the same
//! authenticated X3DH/Double Ratchet session text messages use — a
//! mailbox operator sees identical-looking ciphertext either way (see
//! `envelope.rs`'s module doc). The receiving daemon's own
//! `message_receive.rs` loop decrypts it and dispatches into
//! [`handle_incoming_call_signal`], which answers automatically and
//! pushes the `Answer` back the same way; a `Hangup` signal travels the
//! same path from either side. `POST /calls`'s `contact_id` is optional —
//! omitting it (or no live `state.network`) keeps the older
//! same-daemon/manual-ferry behavior (`accept_call`/`complete_call`
//! consuming a signal a client copied over HTTP itself), which the
//! existing same-daemon test still exercises unchanged.
//!
//! **Deliberately out of scope for this pass** (same spirit as
//! `message_crypto.rs`'s v1 scoping): group-call signaling
//! (`GroupOffer`/`GroupAnswer`) and `IceCandidate`/`KeyUpdate` — today's
//! WebRTC transport gathers ICE fully before returning an SDP blob (no
//! separate trickle-ICE messages exist to route yet), so `Offer`/
//! `Answer`/`Hangup` are sufficient for full 1:1 feature parity with what
//! this API already did locally. The desktop client (`client/desktop`)
//! doesn't pass `contact_id` yet either — it still exercises the
//! same-daemon demo path; wiring the UI to place a real call to a real
//! contact (including handling an unprompted incoming offer, which has no
//! client-side notification affordance today) is a separate follow-up.
//!
//! Call state lives in `AppState` only for the lifetime of the daemon
//! process (in-memory, keyed by call id) — calls aren't persisted, unlike
//! messages, since there's nothing meaningful to restore mid-call after a
//! restart.
//!
//! **Once a call is live, this module wires it to real hardware and a
//! real client stream** (`call_stream.rs`): [`wire_live_audio`] decodes
//! incoming Opus and plays it on the system's speakers, and encodes/sends
//! the system's microphone, entirely inside the daemon process — call
//! audio never needs to reach the UI at all. Camera video and screen
//! sharing are different only because decoding VP8 is deliberately left
//! to the client (`bh-calls::video`'s module doc: no audited safe-Rust
//! decoder exists): [`start_camera`]/[`start_screen_share`] forward the
//! still-encoded, already-decrypted bitstream (both remote frames and a
//! local self-preview loopback) over `GET /calls/:call_id/ws`.
//!
//! Group calls (`start_group_call`/`hangup_group_call`, backed by
//! `bh_calls::group`) go one step further than 1:1's "you ferry the
//! signal yourself": since neither `bh-network` nor a real second daemon
//! is wired in, and this crate has no group-membership/MLS wiring yet
//! (unlike a real deployment, where the call's participants would already
//! share an MLS group from `crates/bh-crypto/src/mls.rs`), the other
//! participants here are locally-generated MLS "shadow" members — the
//! same honest-about-scope pattern this workspace uses elsewhere for
//! multi-party flows it can't yet exercise against real remote peers. The
//! MLS group they form and the full-mesh WebRTC/SFrame handshake it drives
//! are both completely real; only the *identity* of the other
//! participants is simulated. **Scope note**: group-call audio here is
//! decoded and queued to the shared speaker output *per participant, in
//! arrival order* (`wire_group_audio`), not true simultaneous mixing —
//! real N-way PCM summing is a separate DSP problem, not attempted in this
//! pass. Camera video/screen sharing aren't wired for group calls at all
//! (`bh_calls::group::GroupCallSession` has no video/screen track yet,
//! unlike 1:1's `CallSession`).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use bh_calls::audio::{AudioDecoder, AudioEncoder};
use bh_calls::group::{GroupCallSession, ParticipantTag, MAX_GROUP_CALL_PARTICIPANTS};
use bh_calls::session::{self, CallSession, PendingOutgoingCall, DEFAULT_CAMERA_FPS};
use bh_crypto::call_keys::SframeContext;
use bh_crypto::envelope::{CallSignal, Envelope};
use bh_crypto::mls::{Group as MlsGroup, MlsMember};
use bh_network::supervised::SupervisedNetwork;
use bh_storage::models::Contact;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex};

use crate::call_audio;
use crate::call_stream::{self, CallStreamMessage, FrameKind, CALL_STREAM_CHANNEL_CAPACITY};
use crate::AppState;

/// One call's live broadcast channel, paired with the last state event
/// recorded on it (if any) — see the `call_streams` field doc for why the
/// pairing exists.
type CallStreamEntry = (
    broadcast::Sender<CallStreamMessage>,
    Option<call_stream::CallEvent>,
);

/// Keeps a call's native mic/speaker I/O alive for the call's duration:
/// `_stop_handle` (`call_audio::AudioStopHandle`) owns the signal that
/// stops the dedicated thread holding the non-`Send` `cpal::Stream`s (see
/// that module) — dropping it stops both capture and playback.
/// `capture_task` (the mic-encode-send loop) is aborted on hangup rather
/// than left running against a closed session.
struct AudioHandle {
    _stop_handle: call_audio::AudioStopHandle,
    capture_task: tokio::task::JoinHandle<()>,
}

/// Calls currently being placed or in progress. Separate from
/// `bh_storage`-backed state on purpose (see module doc) — this isn't
/// part of `AppState`'s per-profile database at all, since it must survive
/// independently of which profile happens to be active (hanging up on
/// profile switch would be a strange surprise) and has no encrypted-at-
/// rest requirement of its own (no content is stored, only live handles).
#[derive(Default)]
pub struct CallRegistry {
    pending_outgoing: Mutex<HashMap<String, PendingOutgoingCall>>,
    active: Mutex<HashMap<String, Arc<CallSession>>>,
    /// Every participant's [`GroupCallSession`] for a given group call,
    /// keyed by `call_id` — kept together (rather than just the local
    /// tag-0 session) so `hangup_group_call` can tear down the whole
    /// simulated mesh, including the shadow participants, in one call.
    group_active: Mutex<HashMap<String, Vec<GroupCallSession>>>,
    /// One broadcast channel per live call (1:1 or group), feeding
    /// `GET /calls/:call_id/ws` — see `call_stream.rs`. Paired with the
    /// most recently published [`call_stream::CallEvent`] (if any): a
    /// `broadcast::Sender::send` reaches only receivers that already
    /// existed at that moment, but a client can't know a call exists (and
    /// so has nothing to subscribe *to*) until the same HTTP response
    /// that triggers e.g. `CallEvent::Connected` returns — meaning the
    /// very first event a call ever publishes would otherwise always be
    /// missed by every real client. `subscribe_with_current_state`
    /// replays this cached value as each new subscriber's first message.
    call_streams: Mutex<HashMap<String, CallStreamEntry>>,
    audio_handles: Mutex<HashMap<String, AudioHandle>>,
    /// The remote contact a given 1:1 call's signaling is exchanged with
    /// over `bh-network`'s mailbox (`send_call_signal`/
    /// `handle_incoming_call_signal`) — absent for calls only ever
    /// ferried locally (no `contact_id` given to [`start_call`], or
    /// accepted via `POST /calls/incoming` directly). [`hangup_call`]
    /// uses this to know who to notify, without threading a `Contact`
    /// through every handler.
    network_peers: Mutex<HashMap<String, Contact>>,
}

impl CallRegistry {
    /// The stream sender for `call_id`, if it's currently live — every
    /// place in this module that publishes a *frame* (video/screen; state
    /// events go through [`Self::record_event`] instead, so they're
    /// cached for late subscribers too) uses this to reach subscribers.
    pub async fn stream_sender(
        &self,
        call_id: &str,
    ) -> Option<broadcast::Sender<CallStreamMessage>> {
        self.call_streams
            .lock()
            .await
            .get(call_id)
            .map(|(tx, _)| tx.clone())
    }

    async fn create_stream(&self, call_id: &str) -> broadcast::Sender<CallStreamMessage> {
        let (tx, _rx) = broadcast::channel(CALL_STREAM_CHANNEL_CAPACITY);
        self.call_streams
            .lock()
            .await
            .insert(call_id.to_string(), (tx.clone(), None));
        tx
    }

    /// Publishes a state event and remembers it as `call_id`'s current
    /// state (see the field doc on why) — the counterpart to
    /// [`Self::subscribe_with_current_state`].
    async fn record_event(&self, call_id: &str, event: call_stream::CallEvent) {
        let mut guard = self.call_streams.lock().await;
        if let Some((tx, last)) = guard.get_mut(call_id) {
            *last = Some(event.clone());
            let _ = tx.send(CallStreamMessage::Event(event));
        }
    }

    /// For `call_stream::call_ws`: a live receiver (subscribed *before*
    /// reading the cached state, so a state change racing this call can
    /// only ever produce a harmless duplicate, never a gap) plus whatever
    /// event was last recorded, if any.
    pub async fn subscribe_with_current_state(
        &self,
        call_id: &str,
    ) -> Option<(
        broadcast::Receiver<CallStreamMessage>,
        Option<call_stream::CallEvent>,
    )> {
        let guard = self.call_streams.lock().await;
        let (tx, last) = guard.get(call_id)?;
        Some((tx.subscribe(), last.clone()))
    }

    async fn teardown_call(&self, call_id: &str) {
        self.call_streams.lock().await.remove(call_id);
        if let Some(handle) = self.audio_handles.lock().await.remove(call_id) {
            handle.capture_task.abort();
        }
    }
}

fn to_status(err: bh_calls::CallError) -> StatusCode {
    tracing::warn!(%err, "call operation failed");
    StatusCode::INTERNAL_SERVER_ERROR
}

/// Wires a live 1:1 call's remote media, and — best-effort — native audio
/// hardware: mic capture -> Opus encode -> `session.send_audio_frame` on
/// its own task, and native Opus decode -> speaker playback for whatever
/// `session.on_remote_media` delivers, with no audio ever crossing into
/// `bh-api`'s HTTP/WebSocket surface. Video/screen-share *receive* frames
/// (still-encoded VP8, decoding is the client's job — see module doc) are
/// always wired onto `tx` regardless of audio hardware availability.
///
/// **Audio hardware failure never fails the call.** A machine with no
/// microphone/speaker (every CI/sandboxed test environment, some real
/// desktops) still gets a fully working call — signaling, video, and
/// screen-share all work without audio — logging a warning and returning
/// `None` instead of an error. Camera/screen-share failures stay
/// synchronous errors (`CallSession::start_camera`/`start_screen_share`)
/// because those are explicit, separate opt-in actions the user just
/// took; audio is implicit to every call, so silently degrading instead
/// of refusing the call entirely is the more useful failure mode.
fn wire_live_media(
    session: &Arc<CallSession>,
    sframe: SframeContext,
    remote_tag: u8,
    tx: broadcast::Sender<CallStreamMessage>,
) -> Option<AudioHandle> {
    let tx_video = tx.clone();
    let tx_screen = tx;

    let audio_io = call_audio::spawn_audio_io_thread().and_then(|(frames, pcm_tx, stop)| {
        AudioDecoder::new().map(|decoder| (frames, pcm_tx, stop, decoder))
    });

    match audio_io {
        Ok((captured_frames, pcm_tx, stop_handle, mut decoder)) => {
            session.on_remote_media(
                sframe,
                remote_tag,
                move |opus_bytes| {
                    if let Ok(pcm) = decoder.decode_frame(Some(&opus_bytes)) {
                        let _ = pcm_tx.send(pcm);
                    }
                },
                move |vp8_bytes| {
                    call_stream::publish(
                        &tx_video,
                        CallStreamMessage::frame(FrameKind::RemoteVideo, vp8_bytes),
                    );
                },
                move |vp8_bytes| {
                    call_stream::publish(
                        &tx_screen,
                        CallStreamMessage::frame(FrameKind::RemoteScreen, vp8_bytes),
                    );
                },
            );

            // Opus-encoding a 20ms frame is cheap enough to do inline in a
            // normal async task, no `spawn_blocking` needed —
            // `captured_frames` is already a Tokio channel
            // (`call_audio::spawn_audio_io_thread` did the blocking-channel
            // bridging).
            let mut captured_frames = captured_frames;
            let encode_session = session.clone();
            let capture_task = tokio::spawn(async move {
                let encoder = match AudioEncoder::new() {
                    Ok(e) => e,
                    Err(err) => {
                        tracing::warn!(%err, "failed to start audio encoder; mic will not be sent");
                        return;
                    }
                };
                while let Some(pcm) = captured_frames.recv().await {
                    match encoder.encode_frame(&pcm) {
                        Ok(encoded) => {
                            if encode_session
                                .send_audio_frame(&encoded, Duration::from_millis(20))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(err) => {
                            tracing::warn!(%err, "failed to encode a mic frame, dropping it")
                        }
                    }
                }
            });

            Some(AudioHandle {
                _stop_handle: stop_handle,
                capture_task,
            })
        }
        Err(err) => {
            tracing::warn!(
                %err,
                "no audio hardware available; call continues without native audio \
                 (video/screen-share are unaffected)"
            );
            session.on_remote_media(
                sframe,
                remote_tag,
                |_opus_bytes| {},
                move |vp8_bytes| {
                    call_stream::publish(
                        &tx_video,
                        CallStreamMessage::frame(FrameKind::RemoteVideo, vp8_bytes),
                    );
                },
                move |vp8_bytes| {
                    call_stream::publish(
                        &tx_screen,
                        CallStreamMessage::frame(FrameKind::RemoteScreen, vp8_bytes),
                    );
                },
            );
            None
        }
    }
}

#[derive(Deserialize)]
pub struct StartCallRequest {
    pub call_id: String,
    pub video: bool,
    /// When present and a live network is attached, the resulting offer
    /// is also pushed straight to this contact's mailbox
    /// (`send_call_signal`) instead of leaving delivery entirely to the
    /// caller — see module doc. `None` keeps the older manual-ferry
    /// behavior (client copies the returned `signal` itself), which the
    /// same-daemon test still exercises.
    #[serde(default)]
    pub contact_id: Option<String>,
}

#[derive(Serialize)]
pub struct CallSignalResponse {
    pub signal: CallSignal,
}

/// Wraps `signal` in `Envelope::Call` and pushes it through `contact`'s
/// real X3DH/Double-Ratchet-encrypted mailbox — the same channel
/// `message_crypto::send_encrypted_over_network` uses for chat text, just
/// with a different envelope variant on top (see module doc for why that
/// matters for metadata resistance).
async fn send_call_signal(
    state: &AppState,
    network: &SupervisedNetwork,
    contact: &Contact,
    signal: CallSignal,
) -> Result<(), StatusCode> {
    let plaintext = Envelope::Call(signal)
        .encode()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let message_id = uuid::Uuid::new_v4().to_string();
    crate::message_crypto::send_encrypted_over_network(
        state,
        network,
        contact,
        &message_id,
        &plaintext,
    )
    .await
}

/// Places an outgoing call: sets up local WebRTC transport and returns the
/// offer signal. When `contact_id` is given and a live network is
/// attached, also pushes that offer to the contact's mailbox — see module
/// doc.
pub async fn start_call(
    State(state): State<Arc<AppState>>,
    Json(req): Json<StartCallRequest>,
) -> Result<Json<CallSignalResponse>, StatusCode> {
    let (pending, offer) = PendingOutgoingCall::start(req.call_id.clone(), req.video)
        .await
        .map_err(to_status)?;

    if let Some(contact_id) = &req.contact_id {
        let network = state
            .network
            .as_ref()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let contact = state
            .db()
            .get_contact(contact_id)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::NOT_FOUND)?;
        send_call_signal(&state, network, &contact, offer.clone()).await?;
        state
            .calls
            .network_peers
            .lock()
            .await
            .insert(req.call_id.clone(), contact);
    }

    state
        .calls
        .pending_outgoing
        .lock()
        .await
        .insert(req.call_id, pending);
    Ok(Json(CallSignalResponse { signal: offer }))
}

/// Dispatches a `CallSignal` that arrived over `bh-network`'s mailbox
/// (`message_receive.rs`, once the enclosing `Envelope::Call` has been
/// decrypted) — the receive-side counterpart to [`start_call`]/
/// [`hangup_call`] pushing signals out. `contact` is whoever the
/// mailbox's sealed-sender unsealing already proved sent this signal, so
/// an `Offer` here is answered without any additional trust decision: the
/// underlying session it travelled inside already gates that (see
/// `bh_crypto::call_keys`'s doc comment on why call setup is implicitly
/// authenticated by riding an already-trusted session).
pub(crate) async fn handle_incoming_call_signal(
    state: &AppState,
    contact: &Contact,
    signal: CallSignal,
) {
    match &signal {
        CallSignal::Offer { .. } => {
            let (session, sframe, answer) = match session::accept_incoming_call(&signal).await {
                Ok(result) => result,
                Err(err) => {
                    tracing::warn!(%err, "failed to accept an incoming network call offer");
                    return;
                }
            };
            let session = Arc::new(session);
            let call_id = session.call_id.clone();

            let tx = state.calls.create_stream(&call_id).await;
            let audio_handle =
                wire_live_media(&session, sframe, bh_calls::signaling::CALLER_SENDER_TAG, tx);
            if let Some(audio_handle) = audio_handle {
                state
                    .calls
                    .audio_handles
                    .lock()
                    .await
                    .insert(call_id.clone(), audio_handle);
            }
            state
                .calls
                .record_event(&call_id, call_stream::CallEvent::Connected)
                .await;
            state
                .calls
                .active
                .lock()
                .await
                .insert(call_id.clone(), session);
            state
                .calls
                .network_peers
                .lock()
                .await
                .insert(call_id, contact.clone());

            if let Some(network) = state.network.as_ref() {
                if let Err(err) = send_call_signal(state, network, contact, answer).await {
                    tracing::warn!(?err, "failed to send call answer back over the network");
                }
            }
        }
        CallSignal::Answer { call_id, .. } => {
            let call_id = call_id.clone();
            let Some(pending) = state.calls.pending_outgoing.lock().await.remove(&call_id) else {
                tracing::warn!(%call_id, "received a network call answer for a call we didn't start");
                return;
            };
            let (session, sframe) = match pending.complete(&signal).await {
                Ok(result) => result,
                Err(err) => {
                    tracing::warn!(%err, "failed to complete an outgoing call from a network answer");
                    return;
                }
            };
            let session = Arc::new(session);

            let tx = state.calls.create_stream(&call_id).await;
            let audio_handle =
                wire_live_media(&session, sframe, bh_calls::signaling::CALLEE_SENDER_TAG, tx);
            if let Some(audio_handle) = audio_handle {
                state
                    .calls
                    .audio_handles
                    .lock()
                    .await
                    .insert(call_id.clone(), audio_handle);
            }
            state
                .calls
                .record_event(&call_id, call_stream::CallEvent::Connected)
                .await;
            state.calls.active.lock().await.insert(call_id, session);
        }
        CallSignal::Hangup { call_id } => {
            let call_id = call_id.clone();
            if let Some(session) = state.calls.active.lock().await.remove(&call_id) {
                state
                    .calls
                    .record_event(&call_id, call_stream::CallEvent::Hangup)
                    .await;
                state.calls.teardown_call(&call_id).await;
                if let Err(err) = session.hangup().await {
                    tracing::warn!(%err, "failed to tear down call after a network hangup signal");
                }
            }
            state.calls.pending_outgoing.lock().await.remove(&call_id);
            state.calls.network_peers.lock().await.remove(&call_id);
        }
        CallSignal::GroupOffer { .. }
        | CallSignal::GroupAnswer { .. }
        | CallSignal::IceCandidate { .. }
        | CallSignal::KeyUpdate { .. } => {
            tracing::debug!(
                "ignoring group/ICE/key-update call signal over the network — not wired \
                 for 1:1 calls in this pass (see module doc)"
            );
        }
    }
}

#[derive(Serialize)]
pub struct CallStatusResponse {
    pub status: &'static str,
}

/// Cheap polling alternative to `GET /calls/:call_id/ws` for "has this
/// call connected yet" — used by real-network callers on either side
/// (including this crate's own two-daemon integration test) that just
/// need a yes/no rather than a live event stream.
pub async fn call_status(
    State(state): State<Arc<AppState>>,
    Path(call_id): Path<String>,
) -> Json<CallStatusResponse> {
    let status = if state.calls.active.lock().await.contains_key(&call_id) {
        "active"
    } else if state
        .calls
        .pending_outgoing
        .lock()
        .await
        .contains_key(&call_id)
    {
        "pending"
    } else {
        "unknown"
    };
    Json(CallStatusResponse { status })
}

#[derive(Serialize)]
pub struct NetworkCallSummary {
    pub call_id: String,
    pub contact_id: String,
}

/// Every currently-active call that has a real network peer attached
/// (`network_peers` — populated for both an outgoing `start_call` with a
/// `contact_id` and an incoming `Offer` handled by
/// `handle_incoming_call_signal`). There's no separate "ringing, not yet
/// answered" state today — `handle_incoming_call_signal` auto-accepts an
/// incoming offer immediately (see its own doc comment) — so this is
/// deliberately minimal: a client polls it to notice "a call with this
/// contact just went live" and surface *some* visibility, not a full
/// pre-accept ringing UI. A client that already knows about a given
/// `call_id` (e.g. one it placed itself) just ignores that entry.
pub async fn list_network_calls(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<NetworkCallSummary>> {
    let active = state.calls.active.lock().await;
    let peers = state.calls.network_peers.lock().await;
    let calls = peers
        .iter()
        .filter(|(call_id, _)| active.contains_key(*call_id))
        .map(|(call_id, contact)| NetworkCallSummary {
            call_id: call_id.clone(),
            contact_id: contact.contact_id.clone(),
        })
        .collect();
    Json(calls)
}

#[derive(Deserialize)]
pub struct IncomingCallRequest {
    pub offer: CallSignal,
}

/// Accepts an incoming call offer, completing the WebRTC handshake
/// immediately and returning the answer signal to send back. The session
/// is live from this point, so audio/video wiring (`wire_live_audio`)
/// starts here too.
pub async fn accept_call(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IncomingCallRequest>,
) -> Result<Json<CallSignalResponse>, StatusCode> {
    let (session, sframe, answer) = session::accept_incoming_call(&req.offer)
        .await
        .map_err(to_status)?;
    let session = Arc::new(session);
    let call_id = session.call_id.clone();

    let tx = state.calls.create_stream(&call_id).await;
    let audio_handle = wire_live_media(
        &session,
        sframe,
        bh_calls::signaling::CALLER_SENDER_TAG,
        tx.clone(),
    );
    if let Some(audio_handle) = audio_handle {
        state
            .calls
            .audio_handles
            .lock()
            .await
            .insert(call_id.clone(), audio_handle);
    }
    state
        .calls
        .record_event(&call_id, call_stream::CallEvent::Connected)
        .await;

    state.calls.active.lock().await.insert(call_id, session);
    Ok(Json(CallSignalResponse { signal: answer }))
}

#[derive(Deserialize)]
pub struct CompleteCallRequest {
    pub answer: CallSignal,
}

/// Consumes the callee's answer for a call previously started with
/// [`start_call`], completing the handshake and wiring audio/video the
/// same as [`accept_call`] does for the callee side.
pub async fn complete_call(
    State(state): State<Arc<AppState>>,
    Path(call_id): Path<String>,
    Json(req): Json<CompleteCallRequest>,
) -> Result<StatusCode, StatusCode> {
    let pending = state
        .calls
        .pending_outgoing
        .lock()
        .await
        .remove(&call_id)
        .ok_or(StatusCode::NOT_FOUND)?;
    let (session, sframe) = pending.complete(&req.answer).await.map_err(to_status)?;
    let session = Arc::new(session);

    let tx = state.calls.create_stream(&call_id).await;
    let audio_handle = wire_live_media(
        &session,
        sframe,
        bh_calls::signaling::CALLEE_SENDER_TAG,
        tx.clone(),
    );
    if let Some(audio_handle) = audio_handle {
        state
            .calls
            .audio_handles
            .lock()
            .await
            .insert(call_id.clone(), audio_handle);
    }
    state
        .calls
        .record_event(&call_id, call_stream::CallEvent::Connected)
        .await;

    state.calls.active.lock().await.insert(call_id, session);
    Ok(StatusCode::OK)
}

/// Hangs up a 1:1 call, whether it's already `active` or still
/// `pending_outgoing` (rung but not yet answered). If this call's
/// signaling was exchanged over the real network (`network_peers` has an
/// entry), also pushes a `CallSignal::Hangup` to that contact so the
/// other daemon tears its own side down too, rather than waiting to
/// notice a dead connection.
pub async fn hangup_call(
    State(state): State<Arc<AppState>>,
    Path(call_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let session = state.calls.active.lock().await.remove(&call_id);
    let was_pending = state
        .calls
        .pending_outgoing
        .lock()
        .await
        .remove(&call_id)
        .is_some();
    let peer = state.calls.network_peers.lock().await.remove(&call_id);

    if session.is_none() && !was_pending {
        return Err(StatusCode::NOT_FOUND);
    }

    if let Some(session) = session {
        state
            .calls
            .record_event(&call_id, call_stream::CallEvent::Hangup)
            .await;
        state.calls.teardown_call(&call_id).await;
        session.hangup().await.map_err(to_status)?;
    }

    if let (Some(contact), Some(network)) = (peer, state.network.as_ref()) {
        if let Err(err) = send_call_signal(
            &state,
            network,
            &contact,
            CallSignal::Hangup {
                call_id: call_id.clone(),
            },
        )
        .await
        {
            tracing::warn!(?err, "failed to notify peer of hangup over the network");
        }
    }

    Ok(StatusCode::OK)
}

fn default_camera_fps() -> u32 {
    DEFAULT_CAMERA_FPS
}

#[derive(Deserialize)]
pub struct StartCameraRequest {
    #[serde(default = "default_camera_fps")]
    pub fps: u32,
}

/// Starts sending camera video on an already-active call: opens the
/// system's default camera and streams frames out on the call's dedicated
/// video track, through the SFrame encryption path
/// (`bh_calls::session::CallSession::start_camera`). Every encoded frame
/// is also looped back to this call's own WebSocket stream
/// (`FrameKind::LocalVideo`) for self-preview, without opening the camera
/// a second time. Fails synchronously if the camera can't be opened (no
/// permission, already in use, none present).
pub async fn start_camera(
    State(state): State<Arc<AppState>>,
    Path(call_id): Path<String>,
    Json(req): Json<StartCameraRequest>,
) -> Result<StatusCode, StatusCode> {
    let session = state
        .calls
        .active
        .lock()
        .await
        .get(&call_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    let tx = state
        .calls
        .stream_sender(&call_id)
        .await
        .ok_or(StatusCode::NOT_FOUND)?;
    session
        .start_camera(req.fps, move |frame| {
            call_stream::publish(&tx, CallStreamMessage::frame(FrameKind::LocalVideo, frame));
        })
        .await
        .map_err(to_status)?;
    Ok(StatusCode::OK)
}

/// Stops camera video previously started with [`start_camera`] on this
/// call. Idempotent: stopping when no camera is active succeeds with no
/// effect, as long as the call itself is still active.
pub async fn stop_camera(
    State(state): State<Arc<AppState>>,
    Path(call_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let session = state
        .calls
        .active
        .lock()
        .await
        .get(&call_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    session.stop_camera().await;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct StartGroupCallRequest {
    pub call_id: String,
    pub video: bool,
    /// Number of *other* participants to include besides the local caller
    /// (who is always tag 0) — see this module's doc for why they're
    /// locally generated "shadow" MLS members rather than real remote
    /// peers, and `bh_calls::group` for the participant cap this is
    /// validated against.
    pub participant_count: u8,
}

#[derive(Serialize)]
pub struct GroupCallStartedResponse {
    pub call_id: String,
    pub local_tag: ParticipantTag,
    /// The other participants' tags — always `1..=participant_count`,
    /// since the caller is always tag 0.
    pub participant_tags: Vec<ParticipantTag>,
}

/// Starts a group call: builds a local MLS group of `participant_count`
/// shadow members plus the caller, derives the call's shared SFrame base
/// key from it (`bh_crypto::mls::Group::export_call_base_key`), and drives
/// a real full-mesh WebRTC/SFrame handshake between all of them. Every
/// resulting session (the caller's and every shadow's) is kept alive in
/// the registry so [`hangup_group_call`] can close the whole mesh. Wires
/// the local participant's real mic/speaker (`wire_group_audio`) — see
/// module doc for the "queued, not mixed" scope note on multi-party audio.
pub async fn start_group_call(
    State(state): State<Arc<AppState>>,
    Json(req): Json<StartGroupCallRequest>,
) -> Result<Json<GroupCallStartedResponse>, StatusCode> {
    if req.participant_count == 0
        || (req.participant_count as usize) + 1 > MAX_GROUP_CALL_PARTICIPANTS
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut sessions = build_local_group_call_mesh(&req.call_id, req.video, req.participant_count)
        .await
        .map_err(to_status)?;
    let participant_tags: Vec<ParticipantTag> = (1..=req.participant_count).collect();

    state.calls.create_stream(&req.call_id).await;
    let audio_setup = wire_group_audio(&mut sessions[0]);

    // The mesh must be in the registry *before* the mic-send task starts
    // looking it up — inserted first, then the task spawned against the
    // now-locatable `call_id`, same ordering `hangup_group_call` relies on
    // to find (and later remove) it.
    state
        .calls
        .group_active
        .lock()
        .await
        .insert(req.call_id.clone(), sessions);

    if let Some((stop_handle, mic_frames)) = audio_setup {
        let capture_task = spawn_group_mic_sender(state.clone(), req.call_id.clone(), mic_frames);
        state.calls.audio_handles.lock().await.insert(
            req.call_id.clone(),
            AudioHandle {
                _stop_handle: stop_handle,
                capture_task,
            },
        );
    }

    state
        .calls
        .record_event(&req.call_id, call_stream::CallEvent::Connected)
        .await;
    for &tag in &participant_tags {
        state
            .calls
            .record_event(
                &req.call_id,
                call_stream::CallEvent::ParticipantJoined { tag },
            )
            .await;
    }

    Ok(Json(GroupCallStartedResponse {
        call_id: req.call_id,
        local_tag: 0,
        participant_tags,
    }))
}

/// Hangs up a group call started with [`start_group_call`], closing every
/// participant's (including every shadow's) mesh edges.
pub async fn hangup_group_call(
    State(state): State<Arc<AppState>>,
    Path(call_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let sessions = state.calls.group_active.lock().await.remove(&call_id);
    match sessions {
        Some(sessions) => {
            state
                .calls
                .record_event(&call_id, call_stream::CallEvent::Hangup)
                .await;
            state.calls.teardown_call(&call_id).await;
            for session in &sessions {
                session.hangup().await.map_err(to_status)?;
            }
            Ok(StatusCode::OK)
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Wires the local participant's (tag 0) real speaker into a group call:
/// every other participant's decoded PCM is queued onto the *same* shared
/// playback stream as it arrives, one `AudioDecoder` per remote tag (Opus
/// decoding is stateful per stream). **This is sequential queuing, not
/// simultaneous mixing** — two participants talking at once will play
/// back one after the other rather than overlapping, unlike a real
/// conference mixer. A real fix needs summing decoded PCM samples across
/// participants on a fixed tick, a separate DSP problem from what this
/// pass attempts (see module doc).
///
/// Also starts mic *capture* (bridged onto the returned channel), but
/// deliberately does not encode/send it: `GroupCallSession::
/// send_audio_frame` needs `&self` on the specific session instance living
/// in the registry's `Vec<GroupCallSession>`, which this function — called
/// before that `Vec` is inserted — doesn't have access to yet. The caller
/// ([`start_group_call`]) spawns [`spawn_group_mic_sender`] against the
/// registry afterward to actually consume the returned receiver.
///
/// **`None` (no audio hardware) never fails the group call** — same
/// reasoning as [`wire_live_media`]. The mesh's own inbound frame channel
/// (`GroupCallSession::take_frame_receiver`) is always drained regardless,
/// so a missing speaker doesn't leave it growing unboundedly for the
/// call's duration.
fn wire_group_audio(
    session: &mut GroupCallSession,
) -> Option<(
    call_audio::AudioStopHandle,
    tokio::sync::mpsc::UnboundedReceiver<Vec<i16>>,
)> {
    let mut receiver = session
        .take_frame_receiver()
        .expect("freshly-constructed GroupCallSession always has its frame receiver available");

    match call_audio::spawn_audio_io_thread() {
        Ok((captured_frames, pcm_tx, stop_handle)) => {
            let mut decoders: HashMap<ParticipantTag, AudioDecoder> = HashMap::new();
            tokio::spawn(async move {
                while let Some((tag, opus_bytes)) = receiver.recv().await {
                    let decoder = match decoders.entry(tag) {
                        std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                        std::collections::hash_map::Entry::Vacant(e) => match AudioDecoder::new() {
                            Ok(d) => e.insert(d),
                            Err(err) => {
                                tracing::warn!(%err, tag, "failed to start decoder for group-call participant");
                                continue;
                            }
                        },
                    };
                    if let Ok(pcm) = decoder.decode_frame(Some(&opus_bytes)) {
                        let _ = pcm_tx.send(pcm);
                    }
                }
            });
            Some((stop_handle, captured_frames))
        }
        Err(err) => {
            tracing::warn!(
                %err,
                "no audio hardware available; group call continues without native audio"
            );
            tokio::spawn(async move { while receiver.recv().await.is_some() {} });
            None
        }
    }
}

/// Encodes and sends the local participant's mic audio for a group call,
/// looking up `sessions[0]` (always the local participant — see module
/// doc) from the registry on every frame rather than holding a direct
/// handle, since `GroupCallSession`'s `&mut self`-shaped API doesn't fit
/// being moved into a long-lived task any other way. Exits quietly once
/// the call is torn down (`group_active` no longer has this `call_id`) or
/// the mic capture bridge closes.
fn spawn_group_mic_sender(
    state: Arc<AppState>,
    call_id: String,
    mut mic_frames: tokio::sync::mpsc::UnboundedReceiver<Vec<i16>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let encoder = match AudioEncoder::new() {
            Ok(e) => e,
            Err(err) => {
                tracing::warn!(%err, "failed to start group-call audio encoder; mic will not be sent");
                return;
            }
        };
        while let Some(pcm) = mic_frames.recv().await {
            let encoded = match encoder.encode_frame(&pcm) {
                Ok(bytes) => bytes,
                Err(err) => {
                    tracing::warn!(%err, "failed to encode a group-call mic frame, dropping it");
                    continue;
                }
            };
            let sessions = state.calls.group_active.lock().await;
            let Some(sessions) = sessions.get(&call_id) else {
                break; // call already hung up
            };
            let Some(local) = sessions.first() else {
                break;
            };
            if local
                .send_audio_frame(&encoded, Duration::from_millis(20))
                .await
                .is_err()
            {
                break;
            }
        }
    })
}

/// Builds a `participant_count + 1`-member MLS group (the caller, tag 0,
/// plus `participant_count` locally-generated shadow members, tags
/// `1..=participant_count`) purely to derive the call's shared SFrame base
/// key from real, audited MLS group-key-schedule machinery (see this
/// module's doc for why the *participants* are simulated but the *crypto*
/// is not), then constructs one [`GroupCallSession`] per tag and drives a
/// real full-mesh WebRTC handshake between all of them.
async fn build_local_group_call_mesh(
    call_id: &str,
    video: bool,
    participant_count: u8,
) -> Result<Vec<GroupCallSession>, bh_calls::CallError> {
    let local = MlsMember::new(b"group-call-local")?;
    let mut local_group = local.create_group()?;

    // Every already-joined shadow member's own `MlsMember`/`Group` handle,
    // in join order — each existing shadow must process every subsequent
    // `add_member` commit to stay in sync with `local_group`'s epoch, the
    // same requirement `bh_crypto::mls`'s own multi-member tests exercise.
    let mut shadows: Vec<(MlsMember<OpenMlsRustCrypto>, MlsGroup)> = Vec::new();

    for i in 1..=participant_count {
        let shadow = MlsMember::new(format!("group-call-shadow-{i}").as_bytes())?;
        let key_package = shadow.generate_key_package()?;
        let added = local_group.add_member(&local, &key_package)?;
        for (member, group) in shadows.iter_mut() {
            group.decrypt(member, &added.commit)?;
        }
        let shadow_group = shadow.join_group(&added.welcome, &added.ratchet_tree)?;
        shadows.push((shadow, shadow_group));
    }

    let local_key = local_group.export_call_base_key(&local, call_id)?;

    let mut sessions: Vec<GroupCallSession> = Vec::with_capacity(shadows.len() + 1);
    sessions.push(GroupCallSession::new(
        call_id.to_string(),
        0,
        SframeContext::new(local_key),
    ));
    for (tag, (member, group)) in shadows.iter().enumerate() {
        let shadow_key = group.export_call_base_key(member, call_id)?;
        debug_assert_eq!(
            shadow_key, local_key,
            "every member of the same MLS group/epoch must export the same call base key"
        );
        sessions.push(GroupCallSession::new(
            call_id.to_string(),
            (tag + 1) as ParticipantTag,
            SframeContext::new(shadow_key),
        ));
    }

    // Full mesh: every unordered pair (i, j) with i < j gets one edge.
    let n = sessions.len();
    for i in 0..n {
        for j in (i + 1)..n {
            let offer = sessions[i].offer_to(j as ParticipantTag, video).await?;
            let answer = sessions[j].accept_offer(&offer).await?;
            sessions[i].complete_edge(&answer).await?;
        }
    }

    Ok(sessions)
}

fn default_screen_share_fps() -> u32 {
    bh_calls::session::DEFAULT_SCREEN_SHARE_FPS
}

#[derive(Deserialize)]
pub struct StartScreenShareRequest {
    #[serde(default = "default_screen_share_fps")]
    pub fps: u32,
}

/// Starts screen sharing on an already-active call: opens the platform
/// screen capturer and streams frames out on the call's dedicated
/// screen-share track, through the *same* VP8 encoder and SFrame
/// encryption path camera video uses (see `bh_calls::session::CallSession
/// ::start_screen_share`) — not a separate pipeline. Every encoded frame
/// is also looped back to this call's own WebSocket stream
/// (`FrameKind::LocalScreen`) for local self-preview of what's being
/// shared. Fails synchronously (rather than only in logs) if the capturer
/// can't be opened, e.g. no screen-recording permission granted to the
/// daemon process.
pub async fn start_screen_share(
    State(state): State<Arc<AppState>>,
    Path(call_id): Path<String>,
    Json(req): Json<StartScreenShareRequest>,
) -> Result<StatusCode, StatusCode> {
    let session = state
        .calls
        .active
        .lock()
        .await
        .get(&call_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    let tx = state
        .calls
        .stream_sender(&call_id)
        .await
        .ok_or(StatusCode::NOT_FOUND)?;
    session
        .start_screen_share(req.fps, move |frame| {
            call_stream::publish(&tx, CallStreamMessage::frame(FrameKind::LocalScreen, frame));
        })
        .await
        .map_err(to_status)?;
    Ok(StatusCode::OK)
}

/// Stops screen sharing previously started with [`start_screen_share`] on
/// this call. Idempotent: stopping when nothing is being shared succeeds
/// with no effect, as long as the call itself is still active.
pub async fn stop_screen_share(
    State(state): State<Arc<AppState>>,
    Path(call_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let session = state
        .calls
        .active
        .lock()
        .await
        .get(&call_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    session.stop_screen_share().await;
    Ok(StatusCode::OK)
}
