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

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use bh_calls::session::{self, CallSession, PendingOutgoingCall};
use bh_crypto::envelope::CallSignal;
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
