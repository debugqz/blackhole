use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Serialize;

use crate::{
    calls, contacts, conversations, export, identity, invites, moderation, panic_wipe, profiles,
    reactions, receipts, safety_number, ApiError, AppState,
};

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

    /// Exposed at `pub` visibility (rather than crate-private) so
    /// integration tests in `tests/` can drive the whole route table
    /// in-process via `tower::ServiceExt::oneshot`, without binding a real
    /// TCP listener.
    pub fn router(state: Arc<AppState>) -> Router {
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
            .route(
                "/conversations",
                get(conversations::list_conversations)
                    .post(conversations::create_direct_conversation),
            )
            .route(
                "/conversations/:id/messages",
                get(conversations::list_messages).post(conversations::send_message),
            )
            .route(
                "/conversations/:id/disappearing-timer",
                post(conversations::set_disappearing_timer),
            )
            .route(
                "/conversations/:id/export",
                post(export::export_conversation),
            )
            .route("/conversations/import", post(export::import_conversation))
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
            .route(
                "/messages/:id/reactions",
                get(reactions::list_reactions).post(reactions::add_reaction),
            )
            .route(
                "/messages/:id/reactions/:emoji",
                delete(reactions::remove_reaction),
            )
            .route(
                "/messages/:id/receipts",
                get(receipts::list_receipts).post(receipts::record_receipt),
            )
            .route(
                "/contacts/:id/safety-number",
                get(safety_number::get_safety_number),
            )
            .route("/contacts/:id/verify", post(safety_number::set_verified))
            .route("/invites", post(invites::create_invite))
            .route("/invites/decode", post(invites::decode_invite))
            .route("/invites/:token/consume", post(invites::consume_invite))
            .route("/invites/:token/revoke", post(invites::revoke_invite))
            .route(
                "/profiles",
                get(profiles::list_profiles).post(profiles::create_profile),
            )
            .route("/profiles/active", get(profiles::active_profile))
            .route("/profiles/:id/activate", post(profiles::activate_profile))
            .route("/profiles/:id", delete(profiles::delete_profile))
            .route("/calls", post(calls::start_call))
            .route("/calls/incoming", post(calls::accept_call))
            .route("/calls/:call_id/complete", post(calls::complete_call))
            .route("/calls/:call_id/hangup", post(calls::hangup_call))
            .with_state(state)
    }

    pub async fn run(self) -> Result<(), ApiError> {
        let listener = tokio::net::TcpListener::bind(self.addr).await?;
        tracing::info!(addr = %listener.local_addr()?, "daemon API listening on loopback");
        axum::serve(listener, Self::router(self.state)).await?;
        Ok(())
    }
}
