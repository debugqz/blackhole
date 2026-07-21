//! Multi-account endpoints: list/create/switch/delete profiles, each one a
//! fully isolated SQLCipher database + platform-keystore service
//! (`bh_storage::profiles::ProfileManager`). Switching the active profile
//! swaps what every other endpoint in this crate sees — there is
//! deliberately no way to reach a non-active profile's data through any
//! other route, mirroring the isolation SPEC.md §12 requires between
//! payments and messaging, applied here between identities instead.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use bh_storage::keystore::DB_KEY_LABEL;
use bh_storage::profiles::ProfileMeta;
use bh_storage::Database;
use serde::{Deserialize, Serialize};

use crate::state::ProfileSession;
use crate::AppState;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

pub async fn list_profiles(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ProfileMeta>>, StatusCode> {
    state
        .manager
        .list_profiles()
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Serialize)]
pub struct ActiveProfile {
    pub profile_id: String,
}

pub async fn active_profile(State(state): State<Arc<AppState>>) -> Json<ActiveProfile> {
    Json(ActiveProfile {
        profile_id: state.active_profile_id(),
    })
}

#[derive(Deserialize)]
pub struct CreateProfileRequest {
    pub display_name: String,
}

/// Creates a new, empty profile and provisions its SQLCipher encryption
/// key in its own keystore entry — but does **not** switch to it. The
/// caller (typically the UI, right after this) calls
/// [`activate_profile`] to make it current.
pub async fn create_profile(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateProfileRequest>,
) -> Result<Json<ProfileMeta>, StatusCode> {
    let meta = state
        .manager
        .create_profile(req.display_name, now())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let keystore = state.manager.keystore_for(&meta.id);
    let mut db_key = [0u8; 32];
    getrandom::fill(&mut db_key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    keystore
        .store_key(DB_KEY_LABEL, &db_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(meta))
}

/// Switches the daemon's active profile. Every other endpoint reads/writes
/// through `AppState::db()`/`AppState::keystore()`, so this is the only
/// place that decides which profile's encrypted database subsequent
/// requests actually touch.
pub async fn activate_profile(
    State(state): State<Arc<AppState>>,
    Path(profile_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    state
        .manager
        .get_profile(&profile_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let keystore = state.manager.keystore_for(&profile_id);
    let db_key = keystore
        .load_key(DB_KEY_LABEL)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::PRECONDITION_FAILED)?;
    let db_key: [u8; 32] = db_key
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let db = Database::open(state.manager.profile_db_path(&profile_id), &db_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state.switch_active(ProfileSession {
        profile_id: profile_id.clone(),
        db,
        keystore,
        data_dir: state.manager.profile_data_dir(&profile_id),
    });
    Ok(StatusCode::OK)
}

/// Irreversibly deletes a profile's keys and database. Refuses to delete
/// the currently-active profile — the caller must switch to a different
/// one first, so `AppState` is never left pointing at a database that was
/// just wiped out from under it.
pub async fn delete_profile(
    State(state): State<Arc<AppState>>,
    Path(profile_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    if state.active_profile_id() == profile_id {
        return Err(StatusCode::CONFLICT);
    }
    state
        .manager
        .delete_profile(&profile_id)
        .map(|()| StatusCode::OK)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
