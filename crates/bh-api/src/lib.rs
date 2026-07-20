//! The localhost-only RPC surface between the daemon and UI clients. The UI
//! never talks to the P2P network directly — only to this daemon, over
//! localhost. See `docs/SPEC.md` §6.

pub mod server;

pub use server::ApiServer;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("server error: {0}")]
    Server(#[from] std::io::Error),
}
