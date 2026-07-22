//! Voice/video call endpoints, backed by `bh-calls` (real WebRTC transport
//! plus SFrame end-to-end media encryption — see that crate's docs). As
//! with messages (`conversations.rs`), actual delivery of the signaling
//! payloads this produces (`bh_crypto::envelope::CallSignal`, serialized
//! as JSON here) over the network waits on `bh-network` being wired into
//! the daemon — a client today gets a real offer/answer/SFrame-context
//! call session out of this API, but is responsible for ferrying the
//! signal JSON to the other party itself until that wiring exists.
//!
//! Call state lives in `AppState` only for the lifetime of the daemon
//! process (in-memory, keyed by call id) — calls aren't persisted, unlike
//! messages, since there's nothing meaningful to restore mid-call after a
//! restart.
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
//! participants is simulated.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use bh_calls::group::{GroupCallSession, ParticipantTag, MAX_GROUP_CALL_PARTICIPANTS};
use bh_calls::session::{self, CallSession, PendingOutgoingCall};
use bh_crypto::call_keys::SframeContext;
use bh_crypto::envelope::CallSignal;
use bh_crypto::mls::{Group as MlsGroup, MlsMember};
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::AppState;

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
}

fn to_status(err: bh_calls::CallError) -> StatusCode {
    tracing::warn!(%err, "call operation failed");
    StatusCode::INTERNAL_SERVER_ERROR
}

#[derive(Deserialize)]
pub struct StartCallRequest {
    pub call_id: String,
    pub video: bool,
}

#[derive(Serialize)]
pub struct CallSignalResponse {
    pub signal: CallSignal,
}

/// Places an outgoing call: sets up local WebRTC transport and returns the
/// offer signal for the client to deliver to the callee.
pub async fn start_call(
    State(state): State<Arc<AppState>>,
    Json(req): Json<StartCallRequest>,
) -> Result<Json<CallSignalResponse>, StatusCode> {
    let (pending, offer) = PendingOutgoingCall::start(req.call_id.clone(), req.video)
        .await
        .map_err(to_status)?;
    state
        .calls
        .pending_outgoing
        .lock()
        .await
        .insert(req.call_id, pending);
    Ok(Json(CallSignalResponse { signal: offer }))
}

#[derive(Deserialize)]
pub struct IncomingCallRequest {
    pub offer: CallSignal,
}

/// Accepts an incoming call offer, completing the WebRTC handshake
/// immediately and returning the answer signal to send back.
pub async fn accept_call(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IncomingCallRequest>,
) -> Result<Json<CallSignalResponse>, StatusCode> {
    let (session, _sframe, answer) = session::accept_incoming_call(&req.offer)
        .await
        .map_err(to_status)?;
    state
        .calls
        .active
        .lock()
        .await
        .insert(session.call_id.clone(), Arc::new(session));
    Ok(Json(CallSignalResponse { signal: answer }))
}

#[derive(Deserialize)]
pub struct CompleteCallRequest {
    pub answer: CallSignal,
}

/// Consumes the callee's answer for a call previously started with
/// [`start_call`], completing the handshake.
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
    let (session, _sframe) = pending.complete(&req.answer).await.map_err(to_status)?;
    state
        .calls
        .active
        .lock()
        .await
        .insert(call_id, Arc::new(session));
    Ok(StatusCode::OK)
}

pub async fn hangup_call(
    State(state): State<Arc<AppState>>,
    Path(call_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let session = state.calls.active.lock().await.remove(&call_id);
    match session {
        Some(session) => {
            session.hangup().await.map_err(to_status)?;
            Ok(StatusCode::OK)
        }
        None => Err(StatusCode::NOT_FOUND),
    }
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
/// the registry so [`hangup_group_call`] can close the whole mesh.
pub async fn start_group_call(
    State(state): State<Arc<AppState>>,
    Json(req): Json<StartGroupCallRequest>,
) -> Result<Json<GroupCallStartedResponse>, StatusCode> {
    if req.participant_count == 0
        || (req.participant_count as usize) + 1 > MAX_GROUP_CALL_PARTICIPANTS
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let sessions = build_local_group_call_mesh(&req.call_id, req.video, req.participant_count)
        .await
        .map_err(to_status)?;
    let participant_tags: Vec<ParticipantTag> = (1..=req.participant_count).collect();

    state
        .calls
        .group_active
        .lock()
        .await
        .insert(req.call_id.clone(), sessions);

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
            for session in &sessions {
                session.hangup().await.map_err(to_status)?;
            }
            Ok(StatusCode::OK)
        }
        None => Err(StatusCode::NOT_FOUND),
    }
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
/// ::start_screen_share`) — not a separate pipeline. Fails synchronously
/// (rather than only in logs) if the capturer can't be opened, e.g. no
/// screen-recording permission granted to the daemon process.
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
    session
        .start_screen_share(req.fps)
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
