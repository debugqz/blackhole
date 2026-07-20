//! Row types for every table in `schema.rs`. Timestamps are unix seconds.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnIdentity {
    pub identity_public_key: Vec<u8>,
    pub identity_private_key: Vec<u8>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceOwner {
    #[serde(rename = "self")]
    Own,
    Contact,
}

impl DeviceOwner {
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceOwner::Own => "self",
            DeviceOwner::Contact => "contact",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "self" => DeviceOwner::Own,
            _ => DeviceOwner::Contact,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub device_id: String,
    pub owner: DeviceOwner,
    pub contact_id: Option<String>,
    pub name: Option<String>,
    pub public_key: Vec<u8>,
    pub linked_at: i64,
    pub last_seen_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub contact_id: String,
    pub identity_public_key: Vec<u8>,
    pub display_name: Option<String>,
    pub verified: bool,
    pub blocked: bool,
    pub added_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageRequestStatus {
    Pending,
    Accepted,
    Declined,
}

impl MessageRequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            MessageRequestStatus::Pending => "pending",
            MessageRequestStatus::Accepted => "accepted",
            MessageRequestStatus::Declined => "declined",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageRequest {
    pub contact_id: String,
    pub received_at: i64,
    pub status: MessageRequestStatus,
}

/// Opaque serialized Double Ratchet state for one contact device. See
/// `bh-crypto::ratchet`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub contact_id: String,
    pub device_id: String,
    pub ratchet_state: Vec<u8>,
    pub updated_at: i64,
}

/// Opaque serialized MLS group state. See `bh-crypto::mls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub group_id: String,
    pub name: Option<String>,
    pub mls_state: Vec<u8>,
    pub epoch: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub group_id: String,
    pub contact_id: String,
    pub joined_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConversationKind {
    Direct,
    Group,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub conversation_id: String,
    pub kind: ConversationKind,
    pub contact_id: Option<String>,
    pub group_id: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub message_id: String,
    pub conversation_id: String,
    /// `None` means the message was sent by the local user.
    pub sender_contact_id: Option<String>,
    pub body: Option<String>,
    pub sent_at: i64,
    pub received_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub deleted_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DownloadState {
    Pending,
    Partial,
    Complete,
}

impl DownloadState {
    pub fn as_str(self) -> &'static str {
        match self {
            DownloadState::Pending => "pending",
            DownloadState::Partial => "partial",
            DownloadState::Complete => "complete",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMeta {
    pub content_hash: String,
    pub message_id: Option<String>,
    pub file_name: Option<String>,
    pub mime_type: Option<String>,
    pub size_bytes: i64,
    pub chunk_count: i64,
    pub local_path: Option<String>,
    pub download_state: DownloadState,
}
