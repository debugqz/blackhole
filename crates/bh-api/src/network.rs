//! Diagnostic HTTP surface over `bh_network::supervised::SupervisedNetwork`
//! (`docs/SPEC.md` §5/§6). Deliberately read-only and small: this pass
//! wires the network stack into the daemon (spawned, supervised, reachable
//! from `AppState`) so it's actually running and observable — it does not
//! yet rewire `bh-api::conversations`' message send/list handlers to go
//! over `bh-network::mailbox` instead of the local database directly. That
//! (real network delivery replacing today's DB-only messaging) is a
//! separate, larger follow-up.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use crate::AppState;

#[derive(Serialize)]
pub struct NetworkStatus {
    /// `false` if this daemon wasn't started with a network stack
    /// attached (`AppState::with_network`) — every field below is a
    /// default/empty placeholder in that case, not a real report.
    pub enabled: bool,
    pub peer_id: Option<String>,
    pub alive: bool,
    pub listen_addrs: Vec<String>,
}

pub async fn status(State(state): State<Arc<AppState>>) -> Json<NetworkStatus> {
    let Some(net) = &state.network else {
        return Json(NetworkStatus {
            enabled: false,
            peer_id: None,
            alive: false,
            listen_addrs: Vec::new(),
        });
    };
    Json(NetworkStatus {
        enabled: true,
        peer_id: Some(net.peer_id().to_string()),
        alive: net.is_alive(),
        listen_addrs: net
            .listen_addrs()
            .await
            .into_iter()
            .map(|a| a.to_string())
            .collect(),
    })
}
