//! Multi-device linking (SPEC.md §4), backed by `bh-crypto::device_link`.
//!
//! There is exactly one daemon/one database in this repo today — no real
//! second physical device exists to hand a QR scan to. This module exposes
//! the real 4-step protocol (`begin` on the already-trusted device, then
//! `scan`, `accept`, and `finish` completing the handoff) as granular
//! endpoints, with the daemon playing both roles against the same
//! `AppState`. The client UI must label this a **local simulation** — it
//! genuinely exercises the ECDH/HKDF/AEAD path and adds a real second row
//! to the `devices` table, but it does not model a second process, and it
//! never transfers the SQLCipher database key (only the shared *account*
//! identity, exactly as the real protocol does between two real devices).
//!
//! Ceremony state (the in-progress `LinkingSession`/`NewDevice` handles)
//! lives only in memory for the daemon's process lifetime, same convention
//! as `calls::CallRegistry` — there is nothing meaningful to resume after a
//! restart mid-link, so nothing here is persisted until `accept`/`finish`
//! actually complete.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bh_crypto::device_link::{LinkingSession, NewDevice, ProvisioningRequest};
use bh_crypto::identity::IdentityKeyPair;
use bh_storage::models::{Device, DeviceOwner};
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::AppState;

#[derive(Default)]
pub struct DeviceLinkRegistry {
    primary_sessions: Mutex<HashMap<String, LinkingSession>>,
    new_device_sessions: Mutex<HashMap<String, NewDevice>>,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

fn own_identity_keypair(state: &AppState) -> Result<IdentityKeyPair, StatusCode> {
    let own = state
        .db()
        .get_own_identity()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::PRECONDITION_FAILED)?;
    let bytes: [u8; 64] = own
        .identity_private_key
        .as_slice()
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    IdentityKeyPair::import_bytes(&bytes).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// What clients see for a device — `public_key` is hex-encoded rather than
/// the storage row's raw `Vec<u8>`, which `serde_json` would otherwise
/// render as a JSON array of numbers (matching every other public-key-
/// shaped field the API returns as a hex string, e.g. `identity.rs`).
#[derive(Serialize)]
pub struct DevicePublic {
    pub device_id: String,
    pub owner: DeviceOwner,
    pub contact_id: Option<String>,
    pub name: Option<String>,
    pub public_key: String,
    pub linked_at: i64,
    pub last_seen_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

impl From<Device> for DevicePublic {
    fn from(d: Device) -> Self {
        DevicePublic {
            device_id: d.device_id,
            owner: d.owner,
            contact_id: d.contact_id,
            name: d.name,
            public_key: hex::encode(d.public_key),
            linked_at: d.linked_at,
            last_seen_at: d.last_seen_at,
            revoked_at: d.revoked_at,
        }
    }
}

pub async fn list_devices(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<DevicePublic>>, StatusCode> {
    state
        .db()
        .list_own_devices()
        .map(|devices| Json(devices.into_iter().map(Into::into).collect()))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn revoke_device(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
) -> StatusCode {
    match state.db().revoke_device(&device_id, now()) {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[derive(Serialize)]
pub struct BeginLinkResponse {
    pub session_id: String,
    pub link: String,
    pub qr_svg: String,
}

/// The already-trusted device's side: shows a QR/link for the "new device"
/// to scan.
pub async fn begin_link(
    State(state): State<Arc<AppState>>,
) -> Result<Json<BeginLinkResponse>, StatusCode> {
    let session = LinkingSession::begin();
    let link = session.link();
    let qr_svg = bh_crypto::qr::to_svg(&link).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let session_id = uuid::Uuid::new_v4().to_string();
    state
        .device_link
        .primary_sessions
        .lock()
        .expect("device_link registry lock poisoned")
        .insert(session_id.clone(), session);
    Ok(Json(BeginLinkResponse {
        session_id,
        link,
        qr_svg,
    }))
}

#[derive(Deserialize)]
pub struct ScanLinkRequest {
    pub link: String,
}

#[derive(Serialize)]
pub struct ScanLinkResponse {
    pub new_device_session_id: String,
    pub provisioning_request_b64: String,
}

/// The "new device"'s side: scans the link shown by `begin_link` and
/// produces a provisioning request to hand back.
pub async fn scan_link(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ScanLinkRequest>,
) -> Result<Json<ScanLinkResponse>, StatusCode> {
    let new_device = NewDevice::scan(&req.link).map_err(|_| StatusCode::BAD_REQUEST)?;
    let request = new_device.provisioning_request();

    let mut blob = request.new_device_ephemeral_public.as_bytes().to_vec();
    blob.extend_from_slice(&request.ciphertext);
    let provisioning_request_b64 = BASE64.encode(blob);

    let new_device_session_id = uuid::Uuid::new_v4().to_string();
    state
        .device_link
        .new_device_sessions
        .lock()
        .expect("device_link registry lock poisoned")
        .insert(new_device_session_id.clone(), new_device);

    Ok(Json(ScanLinkResponse {
        new_device_session_id,
        provisioning_request_b64,
    }))
}

#[derive(Deserialize)]
pub struct AcceptLinkRequest {
    pub provisioning_request_b64: String,
    pub device_name: Option<String>,
}

#[derive(Serialize)]
pub struct AcceptLinkResponse {
    pub response_ciphertext_b64: String,
    pub device: DevicePublic,
}

/// The already-trusted device accepts the scanned request, hands over the
/// shared account identity, and records the new device.
pub async fn accept_link(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(req): Json<AcceptLinkRequest>,
) -> Result<Json<AcceptLinkResponse>, StatusCode> {
    let session = state
        .device_link
        .primary_sessions
        .lock()
        .expect("device_link registry lock poisoned")
        .remove(&session_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let blob = BASE64
        .decode(&req.provisioning_request_b64)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if blob.len() < 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (pubkey_bytes, ciphertext) = blob.split_at(32);
    let pubkey_arr: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let request = ProvisioningRequest {
        new_device_ephemeral_public: X25519PublicKey::from(pubkey_arr),
        ciphertext: ciphertext.to_vec(),
    };

    let identity = own_identity_keypair(&state)?;
    let (device_signing_key, response) = session
        .accept(&request, &identity)
        .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;

    let device = Device {
        device_id: hex::encode(device_signing_key.to_bytes()),
        owner: DeviceOwner::Own,
        contact_id: None,
        name: req.device_name,
        public_key: device_signing_key.to_bytes().to_vec(),
        linked_at: now(),
        last_seen_at: None,
        revoked_at: None,
    };
    state
        .db()
        .upsert_device(&device)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(AcceptLinkResponse {
        response_ciphertext_b64: BASE64.encode(response),
        device: device.into(),
    }))
}

#[derive(Deserialize)]
pub struct FinishLinkRequest {
    pub response_ciphertext_b64: String,
}

#[derive(Serialize)]
pub struct FinishLinkResponse {
    pub confirmed: bool,
    pub device_signing_key_hex: String,
}

/// The "new device" decrypts the response, completing the link — confirmed
/// by checking the transferred identity matches this daemon's own (since
/// both roles run against the same profile here).
pub async fn finish_link(
    State(state): State<Arc<AppState>>,
    Path(new_device_session_id): Path<String>,
    Json(req): Json<FinishLinkRequest>,
) -> Result<Json<FinishLinkResponse>, StatusCode> {
    let new_device = state
        .device_link
        .new_device_sessions
        .lock()
        .expect("device_link registry lock poisoned")
        .remove(&new_device_session_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let ciphertext = BASE64
        .decode(&req.response_ciphertext_b64)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let linked_identity = new_device
        .accept_response(&ciphertext)
        .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;

    let own_identity = own_identity_keypair(&state)?;
    let confirmed = linked_identity.public_signing_key().to_bytes()
        == own_identity.public_signing_key().to_bytes()
        && linked_identity.public_agreement_key().as_bytes()
            == own_identity.public_agreement_key().as_bytes();

    Ok(Json(FinishLinkResponse {
        confirmed,
        device_signing_key_hex: hex::encode(
            new_device.device_signing_key.verifying_key().to_bytes(),
        ),
    }))
}
