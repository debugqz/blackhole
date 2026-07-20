//! The localhost-only RPC surface between the daemon and UI clients. The UI
//! never talks to the P2P network directly — only to this daemon, over
//! localhost. See `docs/SPEC.md` §6.

pub mod contacts;
pub mod conversations;
pub mod identity;
pub mod moderation;
pub mod panic_wipe;
pub mod server;
pub mod state;

pub use server::ApiServer;
pub use state::AppState;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("server error: {0}")]
    Server(#[from] std::io::Error),
}
