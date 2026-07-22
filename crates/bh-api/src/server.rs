use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde::Serialize;

use crate::{
    calls, contacts, conversations, cosmetics, device_link, device_sync, export, files, groups,
    identity, invites, local_auth, moderation, network, panic_wipe, payment_requests, presence,
    profiles, push, reactions, receipts, safety_number, search, security, stickers, ApiError,
    AppState,
};

/// Rejects any request carrying a browser-set `Origin` header.
///
/// This API is meant to be reachable only from the Tauri desktop client's
/// own Rust-side HTTP bridge (`daemon_call`), which talks raw loopback TCP
/// and never sets `Origin`. A malicious web page open in the user's actual
/// browser can still reach `127.0.0.1:<port>` and, for state-changing
/// routes like `/panic-wipe`, that request qualifies as a CORS "simple
/// request" — the browser sends it and only *reading the response* is
/// blocked, which is not what we need here. Browsers always attach
/// `Origin` on cross-origin state-changing requests, so any request that
/// has one did not come from our own bridge and is rejected outright.
async fn reject_browser_origin(req: Request, next: Next) -> Result<Response, StatusCode> {
    if req.headers().contains_key(header::ORIGIN) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(req).await)
}

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
        // `files::MAX_ATTACHMENT_BYTES` (25 MiB) is the plaintext cap, but
        // the wire body is base64 (≈1.33x inflation) plus JSON framing —
        // the default 2 MiB body limit axum applies to every `Json`
        // extractor would reject any attachment above ~1.4 MB plaintext
        // long before that check ever ran. Scope a raised limit to just
        // this route rather than raising it globally.
        let attachment_routes = Router::new()
            .route(
                "/conversations/:id/attachments",
                get(files::list_attachments).post(files::upload_attachment),
            )
            .layer(DefaultBodyLimit::max(files::MAX_UPLOAD_BODY_BYTES));

        Router::new()
            .merge(attachment_routes)
            .route("/health", get(health))
            .route(
                "/identity",
                get(identity::get_identity).post(identity::create_identity),
            )
            .route("/panic-wipe", post(panic_wipe::panic_wipe))
            .route(
                "/security/db-pin",
                get(security::db_pin_status).post(security::set_db_pin),
            )
            .route("/security/db-pin/clear", post(security::clear_db_pin))
            .route("/network/status", get(network::status))
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
                "/conversations/:id/messages/:message_id",
                patch(conversations::edit_message),
            )
            .route(
                "/conversations/:id/messages/:message_id/edits",
                get(conversations::list_message_edits),
            )
            .route(
                "/conversations/:id/payment-requests",
                post(payment_requests::create_payment_request),
            )
            .route(
                "/messages/:id/payment-request",
                get(payment_requests::get_payment_request),
            )
            .route(
                "/messages/:id/payment-request/paid",
                post(payment_requests::mark_payment_request_paid)
                    .delete(payment_requests::unmark_payment_request_paid),
            )
            .route(
                "/conversations/:id/export",
                post(export::export_conversation),
            )
            .route("/conversations/import", post(export::import_conversation))
            .route(
                "/attachments/:content_hash/download",
                get(files::download_attachment),
            )
            .route(
                "/attachments/:content_hash",
                delete(files::delete_attachment),
            )
            .route(
                "/groups",
                get(groups::list_groups).post(groups::create_group),
            )
            .route("/groups/:id", get(groups::get_group))
            .route("/groups/:id/members", post(groups::add_member))
            .route(
                "/groups/:id/members/:contact_id",
                delete(groups::remove_member),
            )
            .route("/groups/:id/mls-self-test", post(groups::mls_self_test))
            .route("/devices", get(device_link::list_devices))
            .route("/devices/:id/revoke", post(device_link::revoke_device))
            .route("/devices/:id/sync", get(device_sync::sync_device))
            .route("/devices/:id/sync/status", get(device_sync::sync_status))
            .route("/devices/link/begin", post(device_link::begin_link))
            .route("/devices/link/scan", post(device_link::scan_link))
            .route(
                "/devices/link/:session_id/accept",
                post(device_link::accept_link),
            )
            .route(
                "/devices/link/:new_device_session_id/finish",
                post(device_link::finish_link),
            )
            .route("/local-auth/status", get(local_auth::status))
            .route(
                "/local-auth/passkey/register/start",
                post(local_auth::passkey_register_start),
            )
            .route(
                "/local-auth/passkey/register/finish",
                post(local_auth::passkey_register_finish),
            )
            .route(
                "/local-auth/passkey/auth/start",
                post(local_auth::passkey_auth_start),
            )
            .route(
                "/local-auth/passkey/auth/finish",
                post(local_auth::passkey_auth_finish),
            )
            .route("/local-auth/passkey", get(local_auth::passkey_list))
            .route(
                "/local-auth/passkey/:credential_id",
                delete(local_auth::passkey_delete),
            )
            .route(
                "/local-auth/totp/enroll/start",
                post(local_auth::totp_enroll_start),
            )
            .route(
                "/local-auth/totp/enroll/confirm",
                post(local_auth::totp_enroll_confirm),
            )
            .route("/local-auth/totp/verify", post(local_auth::totp_verify))
            .route("/local-auth/totp", delete(local_auth::totp_delete))
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
            .route("/cosmetics/catalog", get(cosmetics::list_catalog))
            .route("/cosmetics/inventory", get(cosmetics::list_inventory))
            .route("/cosmetics/equipped", get(cosmetics::list_equipped))
            .route("/cosmetics/equip", post(cosmetics::equip))
            .route("/cosmetics/equipped/:kind", delete(cosmetics::unequip))
            .route("/cosmetics/purchases", post(cosmetics::create_purchase))
            .route(
                "/cosmetics/purchases/:id/paid",
                post(cosmetics::mark_purchase_paid),
            )
            .route(
                "/cosmetics/sticker-packs",
                get(cosmetics::list_sticker_packs),
            )
            .route("/conversations/:id/stickers", post(stickers::send_sticker))
            .route("/messages/:id/sticker", get(stickers::get_message_sticker))
            .route(
                "/settings/typing-indicators",
                get(presence::get_typing_indicator_setting)
                    .post(presence::set_typing_indicator_setting),
            )
            .route(
                "/conversations/:id/typing",
                get(presence::get_typing_status).post(presence::send_typing_ping),
            )
            .route(
                "/push/register",
                get(push::get_push_registration).post(push::set_push_registration),
            )
            .route("/search", get(search::search_messages))
            .route("/calls", post(calls::start_call))
            .route("/calls/incoming", post(calls::accept_call))
            .route("/calls/:call_id/complete", post(calls::complete_call))
            .route("/calls/:call_id/hangup", post(calls::hangup_call))
            .route(
                "/calls/:call_id/screen-share/start",
                post(calls::start_screen_share),
            )
            .route(
                "/calls/:call_id/screen-share/stop",
                post(calls::stop_screen_share),
            )
            .route("/calls/group/start", post(calls::start_group_call))
            .route(
                "/calls/group/:call_id/hangup",
                post(calls::hangup_group_call),
            )
            .layer(middleware::from_fn(reject_browser_origin))
            .with_state(state)
    }

    pub async fn run(self) -> Result<(), ApiError> {
        let listener = tokio::net::TcpListener::bind(self.addr).await?;
        tracing::info!(addr = %listener.local_addr()?, "daemon API listening on loopback");
        axum::serve(listener, Self::router(self.state)).await?;
        Ok(())
    }
}
