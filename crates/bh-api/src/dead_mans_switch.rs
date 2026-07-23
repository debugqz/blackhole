//! "Dead man's switch": if the user doesn't check in for a configured
//! number of days, a predefined set of text-only messages is released to
//! predefined contacts, once. Delivery reuses the exact same
//! Direct-conversation send path every other message uses
//! ([`conversations::send_message`], X3DH + Double Ratchet over
//! `bh-network` when a network is attached, local-storage-only fallback
//! otherwise) — this module adds no new crypto or transport, only
//! scheduling and a release list. Text-only by design: attachments have no
//! real network delivery path yet in this codebase (see
//! `files::upload_attachment`'s doc comment), so this feature never offers
//! one rather than silently failing to deliver a file.
//!
//! Two check-in paths reset the countdown: automatically whenever this
//! profile becomes active ([`crate::state::AppState::new`]/
//! [`crate::state::AppState::switch_active`]), and explicitly via
//! [`check_in`]. Once fired, the switch latches (`triggered_at`) and only
//! re-arms if the user disables and re-enables it ([`set_dead_mans_switch`]
//! with `enabled: true`) — see `bh_storage::dead_mans_switch`'s module doc
//! for the storage-level guarantee this rests on.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use bh_storage::models::{DeadMansSwitchConfig, DeadMansSwitchReleaseView};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::conversations::{self, SendMessageRequest};
use crate::AppState;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

// ---------------- HTTP handlers ----------------

#[derive(Serialize)]
pub struct DeadMansSwitchStatus {
    pub enabled: bool,
    pub cadence_days: i64,
    pub last_check_in_at: i64,
    /// `last_check_in_at + cadence_days*86400` — `None` if there's no
    /// switch configured at all (never configured = never due).
    pub next_deadline_at: Option<i64>,
    pub triggered_at: Option<i64>,
}

fn to_status(config: Option<DeadMansSwitchConfig>) -> DeadMansSwitchStatus {
    match config {
        Some(c) => DeadMansSwitchStatus {
            enabled: c.enabled,
            cadence_days: c.cadence_days,
            last_check_in_at: c.last_check_in_at,
            next_deadline_at: Some(c.last_check_in_at + c.cadence_days * 86_400),
            triggered_at: c.triggered_at,
        },
        None => DeadMansSwitchStatus {
            enabled: false,
            cadence_days: 0,
            last_check_in_at: 0,
            next_deadline_at: None,
            triggered_at: None,
        },
    }
}

pub async fn get_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<DeadMansSwitchStatus>, StatusCode> {
    let config = state
        .db()
        .get_dead_mans_switch()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(to_status(config)))
}

#[derive(Deserialize)]
pub struct SetDeadMansSwitchRequest {
    pub enabled: bool,
    /// Required when `enabled: true`; ignored when disabling. Must be
    /// `>= 1` — rejected with `400` otherwise (a 0- or negative-day
    /// cadence would fire immediately or nonsensically).
    #[serde(default)]
    pub cadence_days: Option<i64>,
}

/// Activates/updates or deactivates the switch in one endpoint, mirroring
/// `push::set_push_registration`'s enabled-flag-driven shape.
pub async fn set_dead_mans_switch(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SetDeadMansSwitchRequest>,
) -> Result<Json<DeadMansSwitchStatus>, StatusCode> {
    if req.enabled {
        let cadence_days = req.cadence_days.ok_or(StatusCode::BAD_REQUEST)?;
        if cadence_days < 1 {
            return Err(StatusCode::BAD_REQUEST);
        }
        let config = state
            .db()
            .activate_dead_mans_switch(cadence_days, now())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(Json(to_status(Some(config))))
    } else {
        state
            .db()
            .deactivate_dead_mans_switch(now())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let config = state
            .db()
            .get_dead_mans_switch()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(Json(to_status(config)))
    }
}

/// Explicit "check in now" — the second of the two check-in paths (the
/// first being automatic on profile activation, see `state.rs`). A safe
/// no-op (`200 OK`, unchanged status) if no switch is configured or it's
/// disabled — see `Database::record_dead_mans_switch_check_in`.
pub async fn check_in(
    State(state): State<Arc<AppState>>,
) -> Result<Json<DeadMansSwitchStatus>, StatusCode> {
    state
        .db()
        .record_dead_mans_switch_check_in(now())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let config = state
        .db()
        .get_dead_mans_switch()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(to_status(config)))
}

#[derive(Serialize)]
pub struct ListReleasesResponse {
    pub releases: Vec<DeadMansSwitchReleaseView>,
}

pub async fn list_releases(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ListReleasesResponse>, StatusCode> {
    state
        .db()
        .list_dead_mans_switch_releases()
        .map(|releases| Json(ListReleasesResponse { releases }))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Deserialize)]
pub struct AddReleaseRequest {
    pub contact_id: String,
    pub body: String,
}

pub async fn add_release(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddReleaseRequest>,
) -> Result<Json<DeadMansSwitchReleaseView>, StatusCode> {
    if req.body.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    // Validates the contact exists up front — a clearer `404` than letting
    // the FK constraint reject it at insert time.
    let contact = state
        .db()
        .get_contact(&req.contact_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let release = state
        .db()
        .add_dead_mans_switch_release(&req.contact_id, &req.body, now())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(DeadMansSwitchReleaseView {
        id: release.id,
        contact_id: release.contact_id,
        contact_display_name: contact.display_name,
        body: release.body,
        created_at: release.created_at,
    }))
}

pub async fn remove_release(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> StatusCode {
    match state.db().remove_dead_mans_switch_release(id) {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

// ---------------- sweeper ----------------

/// Spawns the checkin sweeper; follows `message_receive::spawn_receive_loop`'s
/// shape (reads `state.db()` fresh every tick), so — same as that loop — it
/// never needs restarting across `AppState::switch_active`, unlike the
/// expiry sweeper.
pub fn spawn_checkin_sweeper(state: Arc<AppState>, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            checkin_tick(state.clone(), now).await;
        }
    })
}

/// `now` is injected (not just read from the system clock inline) so tests
/// can drive it deterministically — same rationale as
/// `bh_storage::expiry::spawn_expiry_sweeper`'s `now: impl Fn() -> i64`.
/// Takes `state` by value (not `&AppState`) since firing a release calls
/// [`conversations::send_message`], whose `State` extractor needs to own an
/// `Arc<AppState>` — a cheap clone per tick.
pub async fn checkin_tick(state: Arc<AppState>, now: impl Fn() -> i64 + Clone) {
    let due = match state.db().dead_mans_switch_is_due(now()) {
        Ok(due) => due,
        Err(err) => {
            tracing::warn!(%err, "dead man's switch: failed to check due-ness");
            return;
        }
    };
    if !due {
        return;
    }

    let releases = match state.db().list_dead_mans_switch_releases_raw() {
        Ok(releases) => releases,
        Err(err) => {
            tracing::warn!(%err, "dead man's switch: failed to load release list");
            // Still mark triggered below — see the doc comment further
            // down on why a failure here shouldn't leave the switch
            // re-checking (and potentially double-sending) forever.
            Vec::new()
        }
    };

    for release in &releases {
        let conversation = match state
            .db()
            .ensure_direct_conversation(&release.contact_id, now())
        {
            Ok(c) => c,
            Err(err) => {
                tracing::warn!(
                    %err, contact_id = %release.contact_id,
                    "dead man's switch: failed to resolve conversation for release entry"
                );
                continue;
            }
        };
        // Calling `send_message` directly (not over HTTP) — its params are
        // plain axum extractor wrapper structs, so this is the same
        // in-process call `bh-api`'s own test suite uses via
        // `tower::ServiceExt::oneshot`, just skipping the HTTP layer
        // entirely. Internally it takes the real X3DH/Double-Ratchet path
        // when `state.network` is attached and falls back to
        // local-storage-only otherwise — exactly the desired behavior.
        let result = conversations::send_message(
            State(state.clone()),
            Path(conversation.conversation_id.clone()),
            Json(SendMessageRequest {
                body: release.body.clone(),
                reply_to_message_id: None,
                sender_contact_id: None,
            }),
        )
        .await;
        if let Err(status) = result {
            tracing::warn!(
                ?status, contact_id = %release.contact_id,
                "dead man's switch: failed to send release message to one contact — \
                 continuing with the remaining releases"
            );
            // Deliberately not `return`ed: one contact's send failure
            // (e.g. no session yet, network hiccup) must not silently
            // suppress delivery to every *other* contact on the list —
            // each release entry is independent.
        }
    }

    // Marked triggered even if some/all sends failed above: the
    // requirement is "must not re-fire repeatedly," and retrying forever
    // on every tick for a contact whose send will deterministically keep
    // failing (e.g. a since-blocked/removed contact) is worse than a
    // best-effort single attempt. A future pass could add a
    // `dead_mans_switch_release.delivery_status` column if "guaranteed
    // eventual delivery, retried indefinitely" becomes a real requirement,
    // but that's out of scope for v1.
    if let Err(err) = state.db().mark_dead_mans_switch_triggered(now()) {
        tracing::warn!(%err, "dead man's switch: failed to mark triggered");
    }
}
