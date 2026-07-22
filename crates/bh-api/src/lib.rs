//! The localhost-only RPC surface between the daemon and UI clients. The UI
//! never talks to the P2P network directly — only to this daemon, over
//! localhost. See `docs/SPEC.md` §6.

pub mod call_audio;
pub mod call_stream;
pub mod calls;
pub mod contacts;
pub mod conversations;
pub mod cosmetics;
pub mod device_link;
pub mod device_sync;
pub mod export;
pub mod files;
pub mod groups;
pub mod identity;
pub mod invites;
pub mod local_auth;
pub mod message_crypto;
pub mod message_receive;
pub mod moderation;
pub mod network;
pub mod panic_wipe;
pub mod payment_requests;
pub mod presence;
pub mod profiles;
pub mod push;
pub mod reactions;
pub mod receipts;
pub mod safety_number;
pub mod search;
pub mod security;
pub mod server;
pub mod state;
pub mod stickers;
pub mod tree_head;

pub use server::ApiServer;
pub use state::AppState;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("server error: {0}")]
    Server(#[from] std::io::Error),
}
