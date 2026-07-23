//! Multi-device linking (SPEC.md §4), backed by `bh-crypto::device_link`.
//!
//! **Real cross-process linking now exists** when `state.network` is
//! attached: `scan_link` (the new device) publishes its
//! `ProvisioningRequest` to `bh_network::device_link_relay` instead of
//! only returning it in the HTTP response, keyed by the primary's real
//! identity (`bh_crypto::device_link::LinkingSession::begin`'s doc
//! comment on why the link itself now embeds that); `accept_link` (the
//! primary) fetches it from the relay when the caller doesn't supply
//! `provisioning_request_b64` directly, and — symmetrically — publishes
//! its response to the relay keyed by the new device's ephemeral linking
//! key; `finish_link` (the new device) fetches that response the same
//! way when not given `response_ciphertext_b64` directly. Every endpoint
//! still accepts the ciphertext inline too — the pre-existing same-daemon
//! demo (both roles against the same `AppState`, no live network needed)
//! keeps working completely unchanged.
//!
//! **Deliberately still out of scope**: this only proves the *ceremony*
//! travels the real network — a real new device's `finish_link` does
//! *not* install the transferred account identity as its own
//! `own_identity` (would make its `recipient_key_hash` collide with the
//! primary's, and this codebase's `Direct`-message mailbox is
//! delete-on-read/single-consumer, unlike `Group`'s `Mailbox::fan_out` —
//! two daemons racing to pull-and-delete the same account's incoming
//! mailbox would silently drop messages for whichever loses the race).
//! Making a real second device a fully-synced peer for ordinary messaging
//! is `device_sync.rs`'s job, which already works over the real network
//! independently (see that module's doc comment) — it doesn't need this
//! module's identity transfer at all, only a `Device` row with a real
//! `identity_agreement_key`, which `accept_link` already writes here.
//! Resolving the mailbox-sharing question for *general* multi-device
//! messaging (not just sync pushes) is a real follow-up, not attempted in
//! this pass.
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
    let identity = own_identity_keypair(&state)?;
    let own_key_hash = bh_crypto::identity::recipient_key_hash(&identity.public_identity_bytes());
    let session = LinkingSession::begin(own_key_hash);
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
/// produces a provisioning request to hand back — and, if a live network
/// is attached, also publishes it to the relay so a genuinely separate
/// primary daemon can find it (see module doc).
pub async fn scan_link(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ScanLinkRequest>,
) -> Result<Json<ScanLinkResponse>, StatusCode> {
    let new_device = NewDevice::scan(&req.link).map_err(|_| StatusCode::BAD_REQUEST)?;
    let request = new_device.provisioning_request();

    let mut blob = request.new_device_ephemeral_public.as_bytes().to_vec();
    blob.extend_from_slice(&request.ciphertext);
    let provisioning_request_b64 = BASE64.encode(&blob);

    if let Some(network) = state.network.as_ref() {
        if let Err(err) = bh_network::device_link_relay::publish_request(
            &network.dht(),
            &new_device.primary_key_hash,
            blob.clone(),
        )
        .await
        {
            tracing::warn!(%err, "failed to publish device-link request to the relay");
        }
    }

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
    /// `None` means: fetch the request from the real network relay
    /// instead (see module doc) — only valid when `state.network` is
    /// attached.
    #[serde(default)]
    pub provisioning_request_b64: Option<String>,
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

    let identity = own_identity_keypair(&state)?;

    let blob = match req.provisioning_request_b64 {
        Some(b64) => BASE64.decode(&b64).map_err(|_| StatusCode::BAD_REQUEST)?,
        None => {
            let own_key_hash =
                bh_crypto::identity::recipient_key_hash(&identity.public_identity_bytes());
            let network = state
                .network
                .as_ref()
                .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
            bh_network::device_link_relay::fetch_request(&network.dht(), &own_key_hash)
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
                .ok_or(StatusCode::NOT_FOUND)?
        }
    };
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

    let (device_identity_public, response) = session
        .accept(&request, &identity)
        .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;
    let (device_signing_bytes, device_agreement_bytes) = device_identity_public.split_at(32);

    let device = Device {
        device_id: hex::encode(device_signing_bytes),
        owner: DeviceOwner::Own,
        contact_id: None,
        name: req.device_name,
        public_key: device_signing_bytes.to_vec(),
        identity_agreement_key: Some(device_agreement_bytes.to_vec()),
        linked_at: now(),
        last_seen_at: None,
        revoked_at: None,
    };
    state
        .db()
        .upsert_device(&device)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some(network) = state.network.as_ref() {
        let device_ephemeral_key_hash =
            bh_crypto::identity::recipient_key_hash(request.new_device_ephemeral_public.as_bytes());
        if let Err(err) = bh_network::device_link_relay::publish_response(
            &network.dht(),
            &device_ephemeral_key_hash,
            response.clone(),
        )
        .await
        {
            tracing::warn!(%err, "failed to publish device-link response to the relay");
        }
    }

    Ok(Json(AcceptLinkResponse {
        response_ciphertext_b64: BASE64.encode(response),
        device: device.into(),
    }))
}

#[derive(Deserialize)]
pub struct FinishLinkRequest {
    /// `None` means: fetch the response from the real network relay
    /// instead (see module doc) — only valid when `state.network` is
    /// attached.
    #[serde(default)]
    pub response_ciphertext_b64: Option<String>,
}

#[derive(Serialize)]
pub struct FinishLinkResponse {
    pub confirmed: bool,
    pub device_signing_key_hex: String,
    /// The transferred account identity's own public keys — present
    /// whenever `confirmed` is `true`, letting a genuinely separate new
    /// device (with no `own_identity` of its own yet to compare against
    /// — see module doc on why this daemon doesn't install it) verify the
    /// ceremony recovered the *expected* primary identity, by comparing
    /// against whatever it already knows out-of-band (e.g. the primary's
    /// own `GET /identity` response).
    pub linked_signing_key_hex: String,
    pub linked_agreement_key_hex: String,
}

/// The "new device" decrypts the response, completing the link. On the
/// same-daemon demo path (both roles sharing a profile — `own_identity`
/// already set), `confirmed` re-checks the transferred identity matches
/// this daemon's own. On a genuinely separate new device (no
/// `own_identity` yet), there's nothing local to compare against — see
/// module doc for why this daemon deliberately doesn't install the
/// transferred identity as its own — so `confirmed` there just means
/// "decryption succeeded," and the caller compares
/// `linked_signing_key_hex`/`linked_agreement_key_hex` against the
/// primary's known identity itself.
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

    let ciphertext = match req.response_ciphertext_b64 {
        Some(b64) => BASE64.decode(&b64).map_err(|_| StatusCode::BAD_REQUEST)?,
        None => {
            let device_ephemeral_key_hash =
                bh_crypto::identity::recipient_key_hash(new_device.ephemeral_public().as_bytes());
            let network = state
                .network
                .as_ref()
                .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
            bh_network::device_link_relay::fetch_response(
                &network.dht(),
                &device_ephemeral_key_hash,
            )
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .ok_or(StatusCode::NOT_FOUND)?
        }
    };
    let linked_identity = new_device
        .accept_response(&ciphertext)
        .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;

    let confirmed = match own_identity_keypair(&state) {
        Ok(own_identity) => {
            linked_identity.public_signing_key().to_bytes()
                == own_identity.public_signing_key().to_bytes()
                && linked_identity.public_agreement_key().as_bytes()
                    == own_identity.public_agreement_key().as_bytes()
        }
        // No `own_identity` on this daemon yet — a genuinely separate new
        // device, not the same-daemon demo. Decryption already succeeded
        // above (an `UNPROCESSABLE_ENTITY` would have short-circuited
        // otherwise), which is the real proof for this case.
        Err(StatusCode::PRECONDITION_FAILED) => true,
        Err(other) => return Err(other),
    };

    Ok(Json(FinishLinkResponse {
        confirmed,
        device_signing_key_hex: hex::encode(
            new_device.device_identity.public_signing_key().to_bytes(),
        ),
        linked_signing_key_hex: hex::encode(linked_identity.public_signing_key().to_bytes()),
        linked_agreement_key_hex: hex::encode(linked_identity.public_agreement_key().as_bytes()),
    }))
}
