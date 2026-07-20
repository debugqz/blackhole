//! Local identity bootstrap. The seed phrase is generated here and
//! returned in the HTTP response body exactly once — it is never stored
//! anywhere, by design (SPEC.md §4): if the caller doesn't write it down
//! now, it's gone.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use bh_crypto::identity::{IdentityKeyPair, SeedPhrase};
use bh_storage::models::OwnIdentity;
use serde::Serialize;

use crate::AppState;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

fn split_public(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    if bytes.len() != 64 {
        return None;
    }
    Some((&bytes[..32], &bytes[32..]))
}

#[derive(Serialize)]
pub struct IdentityStatus {
    pub initialized: bool,
    pub public_signing_key: Option<String>,
    pub public_agreement_key: Option<String>,
}

pub async fn get_identity(
    State(state): State<Arc<AppState>>,
) -> Result<Json<IdentityStatus>, StatusCode> {
    let stored = state
        .db
        .get_own_identity()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(match stored {
        Some(identity) => {
            let (signing_pub, agreement_pub) = split_public(&identity.identity_public_key)
                .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
            IdentityStatus {
                initialized: true,
                public_signing_key: Some(hex::encode(signing_pub)),
                public_agreement_key: Some(hex::encode(agreement_pub)),
            }
        }
        None => IdentityStatus {
            initialized: false,
            public_signing_key: None,
            public_agreement_key: None,
        },
    }))
}

#[derive(Serialize)]
pub struct CreateIdentityResponse {
    pub public_signing_key: String,
    pub public_agreement_key: String,
    /// Shown exactly once. Write it down offline — Blackhole cannot
    /// recover a lost account without it (SPEC.md §4).
    pub seed_phrase: String,
}

pub async fn create_identity(
    State(state): State<Arc<AppState>>,
) -> Result<Json<CreateIdentityResponse>, StatusCode> {
    let already_exists = state
        .db
        .get_own_identity()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .is_some();
    if already_exists {
        return Err(StatusCode::CONFLICT);
    }

    let seed = SeedPhrase::generate().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let identity =
        IdentityKeyPair::from_seed_phrase(&seed).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut public_bytes = Vec::with_capacity(64);
    public_bytes.extend_from_slice(&identity.public_signing_key().to_bytes());
    public_bytes.extend_from_slice(identity.public_agreement_key().as_bytes());

    state
        .db
        .set_own_identity(&OwnIdentity {
            identity_public_key: public_bytes.clone(),
            identity_private_key: identity.export_bytes().to_vec(),
            created_at: now(),
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let (signing_pub, agreement_pub) =
        split_public(&public_bytes).ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(CreateIdentityResponse {
        public_signing_key: hex::encode(signing_pub),
        public_agreement_key: hex::encode(agreement_pub),
        seed_phrase: seed.words(),
    }))
}
