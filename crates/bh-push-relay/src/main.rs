//! Standalone push relay binary. See the `bh_push_relay` crate docs
//! (`src/lib.rs`) for the full design write-up — what this deliberately
//! does and does not do.

use std::sync::Arc;

use bh_push_relay::{RelayServer, RelayState};

const DEFAULT_PORT: u16 = 47_900;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let port = std::env::var("BLACKHOLE_PUSH_RELAY_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let state = Arc::new(RelayState::new());
    tracing::info!("bh-push-relay starting (opaque wake relay — see crate docs for the design)");
    if let Err(err) = RelayServer::new(port, state).run().await {
        tracing::error!(%err, "push relay exited with an error");
        std::process::exit(1);
    }
}
