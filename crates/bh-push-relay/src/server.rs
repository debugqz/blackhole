use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::GovernorLayer;

use crate::RelayState;

/// Sanity bounds on the opaque token — not a format requirement (the relay
/// doesn't know or care what encoding a client used), just a crude guard
/// against someone trying to smuggle an oversized payload through the one
/// string field this API accepts.
const MIN_TOKEN_LEN: usize = 16;
const MAX_TOKEN_LEN: usize = 512;

/// The entire request body this relay is capable of accepting for
/// registration. There is no field here (and never should be) for message
/// content, a sender identity, or a conversation id — see the crate docs.
#[derive(Deserialize)]
pub struct RegisterRequest {
    pub token: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub registered: bool,
}

fn valid_token(token: &str) -> bool {
    (MIN_TOKEN_LEN..=MAX_TOKEN_LEN).contains(&token.len())
}

async fn register(
    State(state): State<Arc<RelayState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    if !valid_token(&req.token) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !state.register(req.token) {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(Json(RegisterResponse { registered: true }))
}

// TODO(real-push): wire to APNs/FCM here. That needs an Apple Push
// Notification service key/certificate or a Firebase Cloud Messaging
// service account — platform credentials this task cannot provision. When
// it lands: look up whatever platform-specific push handle is associated
// with `token` (today, this relay never persists such an association —
// that lookup itself is new work, kept out of scope here on purpose) and
// send a single content-free wake payload through the platform's push
// gateway. UnifiedPush (SPEC.md §5.6) is the Android alternative to FCM
// and would plug in at this same seam.
fn forward_to_push_provider(_token: &str) {
    tracing::debug!("wake signal handed to downstream push provider (stub, see TODO(real-push))");
}

async fn wake(State(state): State<Arc<RelayState>>, Path(token): Path<String>) -> StatusCode {
    if !state.is_registered(&token) {
        return StatusCode::NOT_FOUND;
    }
    forward_to_push_provider(&token);
    StatusCode::ACCEPTED
}

/// The relay's HTTP server. Unlike `bh-api::ApiServer` (loopback-only —
/// see that crate's doc comment), this binds to all interfaces by default:
/// it has to be reachable from wherever daemons and/or APNs/FCM live, not
/// just localhost.
pub struct RelayServer {
    addr: SocketAddr,
    state: Arc<RelayState>,
}

impl RelayServer {
    /// `port = 0` lets the OS pick a free port.
    pub fn new(port: u16, state: Arc<RelayState>) -> Self {
        Self {
            addr: SocketAddr::from(([0, 0, 0, 0], port)),
            state,
        }
    }

    /// Exposed at `pub` visibility so integration tests can drive the
    /// whole route table in-process via `tower::ServiceExt::oneshot`,
    /// mirroring `bh-api`'s test setup (`crates/bh-api/tests/api_smoke.rs`)
    /// — no real TCP listener needed to prove the register/wake contract.
    ///
    /// Rate-limited per source IP (`GovernorLayer`, `PeerIpKeyExtractor`)
    /// — this is the one genuinely internet-facing surface in the repo
    /// (binds all interfaces, unlike `bh-api`'s loopback-only daemon), so
    /// unlike `bh-api` it needs a real, if deliberately loose, throttle
    /// against automated abuse of `/register`/`/wake/:token`.
    /// `PeerIpKeyExtractor` reads connection info from request
    /// extensions, which only a real `axum::serve(...,
    /// into_make_service_with_connect_info::<SocketAddr>())` populates —
    /// tests that drive this router directly via `oneshot` must insert a
    /// `ConnectInfo<SocketAddr>` extension on their requests themselves.
    pub fn router(state: Arc<RelayState>) -> Router {
        let governor_config = Arc::new(
            GovernorConfigBuilder::default()
                .finish()
                .expect("default governor config is always valid"),
        );
        Router::new()
            .route("/register", post(register))
            .route("/wake/:token", post(wake))
            .layer(GovernorLayer {
                config: governor_config,
            })
            .with_state(state)
    }

    pub async fn run(self) -> std::io::Result<()> {
        let listener = tokio::net::TcpListener::bind(self.addr).await?;
        tracing::info!(addr = %listener.local_addr()?, "push relay listening");
        axum::serve(
            listener,
            Self::router(self.state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    }
}
