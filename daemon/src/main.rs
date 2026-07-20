//! The Blackhole daemon: runs on localhost, owns all cryptographic keys and
//! the connection to the P2P network. UI clients talk only to this daemon's
//! localhost API, never directly to the network. See `docs/SPEC.md` §6.
//!
//! `bh-crypto`, `bh-network`, and `bh-storage` are wired in here once each
//! has real protocol logic behind its stubs — this binary is currently just
//! the localhost API surface (`bh-api`).

const DEFAULT_PORT: u16 = 47_853;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let port = std::env::var("BLACKHOLE_DAEMON_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    tracing::info!("blackhole daemon starting (see docs/SPEC.md §6)");

    if let Err(err) = bh_api::ApiServer::new(port).run().await {
        tracing::error!(%err, "daemon API server exited with an error");
        std::process::exit(1);
    }
}
