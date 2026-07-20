use std::net::SocketAddr;

use axum::{routing::get, Json, Router};
use serde::Serialize;

use crate::ApiError;

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
}

impl ApiServer {
    /// `port = 0` lets the OS pick a free port.
    pub fn new(port: u16) -> Self {
        Self {
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }

    fn router() -> Router {
        Router::new().route("/health", get(health))
    }

    pub async fn run(self) -> Result<(), ApiError> {
        let listener = tokio::net::TcpListener::bind(self.addr).await?;
        tracing::info!(addr = %listener.local_addr()?, "daemon API listening on loopback");
        axum::serve(listener, Self::router()).await?;
        Ok(())
    }
}
