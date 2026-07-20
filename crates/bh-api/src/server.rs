use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;

use crate::{contacts, conversations, identity, moderation, panic_wipe, ApiError, AppState};

#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
}

async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// The daemon's localhost API server. Binds only to loopback — this must
/// never be reachable from the network (SPEC.md §6).
pub struct ApiServer {
    addr: SocketAddr,
    state: Arc<AppState>,
}

impl ApiServer {
    /// `port = 0` lets the OS pick a free port.
    pub fn new(port: u16, state: Arc<AppState>) -> Self {
        Self {
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
            state,
        }
    }

    fn router(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/health", get(health))
            .route(
                "/identity",
                get(identity::get_identity).post(identity::create_identity),
            )
            .route("/panic-wipe", post(panic_wipe::panic_wipe))
            .route(
                "/contacts",
                get(contacts::list_contacts).post(contacts::add_contact),
            )
            .route("/contacts/:id/block", post(contacts::block_contact))
            .route("/contacts/:id/unblock", post(moderation::unblock_contact))
            .route("/conversations", get(conversations::list_conversations))
            .route(
                "/conversations/:id/messages",
                get(conversations::list_messages),
            )
            .route("/message-requests", get(moderation::list_message_requests))
            .route(
                "/message-requests/:contact_id/accept",
                post(moderation::accept_message_request),
            )
            .route(
                "/message-requests/:contact_id/decline",
                post(moderation::decline_message_request),
            )
            .route("/reports", post(moderation::create_report))
            .with_state(state)
    }

    pub async fn run(self) -> Result<(), ApiError> {
        let listener = tokio::net::TcpListener::bind(self.addr).await?;
        tracing::info!(addr = %listener.local_addr()?, "daemon API listening on loopback");
        axum::serve(listener, Self::router(self.state)).await?;
        Ok(())
    }
}
