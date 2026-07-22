//! Row types for every table in `schema.rs`. Timestamps are unix seconds.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnIdentity {
    pub identity_public_key: Vec<u8>,
    pub identity_private_key: Vec<u8>,
    pub created_at: i64,
}

/// This identity's own long-term X3DH prekey material — see `schema.rs`'s
/// `SCHEMA_V15` doc comment for the v1 scoping (one non-rotating signed
/// prekey, no one-time prekeys). `bh-crypto::ratchet::SignedPreKey`/
/// `bh_crypto::pq_hybrid::HybridSecretKey` are rebuilt from these bytes on
/// demand (`signed_prekey_secret` via `X25519Secret::from`,
/// `pq_prekey_seed` via `HybridSecretKey::from_seed_bytes`) rather than
/// this crate depending on `bh-crypto`'s types directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnPrekey {
    pub signed_prekey_id: i64,
    pub signed_prekey_secret: Vec<u8>,
    pub signed_prekey_signature: Vec<u8>,
    pub pq_prekey_seed: Vec<u8>,
    pub pq_prekey_signature: Vec<u8>,
    pub created_at: i64,
}

/// Local record of this profile's opt-in "wake push" registration (SPEC.md
/// §5.6, `crates/bh-push-relay`) — an opaque, locally-generated token and
/// whether the feature is currently on. Never message content, never a
/// contact or conversation id, and the token is not derived from (and
/// cannot be linked back to) the identity key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushRegistration {
    pub token: String,
    pub enabled: bool,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceOwner {
    #[serde(rename = "self")]
    Own,
    #[serde(rename = "contact")]
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
    /// A broadcast channel: only the owner may post (enforced at the API
    /// level in `bh-api::conversations::send_message`, not a crypto-level
    /// restriction — the underlying MLS group works exactly as it does for
    /// a regular group). `false` for every ordinary group.
    pub broadcast_only: bool,
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
    /// The single local-only "Notes to self" conversation: no counterparty,
    /// so no `contact_id`/`group_id` and no encryption session/ratchet —
    /// see `bh_storage::conversations::ensure_self_conversation`. Still
    /// stored inside the same SQLCipher-encrypted database as everything
    /// else, just without a Double Ratchet/MLS layer on top, since that
    /// layer exists to protect messages *in transit* between two parties
    /// and there is no transit here.
    #[serde(rename = "self")]
    SelfNotes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub conversation_id: String,
    pub kind: ConversationKind,
    pub contact_id: Option<String>,
    pub group_id: Option<String>,
    pub created_at: i64,
    /// Disappearing-messages timer for this conversation, in seconds —
    /// `None` means off. Applied to new outgoing messages at send time
    /// (`sent_at + timer` becomes `expires_at`); see `expiry.rs` for the
    /// sweeper that actually purges them.
    pub disappearing_timer_secs: Option<i64>,
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
    /// Quote-reply target, if this message is a reply to another one.
    pub reply_to_message_id: Option<String>,
    /// When this message was last edited (unix seconds of the most
    /// subsequent edit) — `None` means never edited. Editing never
    /// silently overwrites: the previous body is preserved in
    /// `message_edits` before `body` is updated, so `edited_at.is_some()`
    /// is a reliable, always-visible signal to the recipient that history
    /// exists to inspect.
    pub edited_at: Option<i64>,
}

/// One prior version of a message's body, kept so an edit is visible and
/// auditable instead of a silent overwrite. Populated by
/// `Database::edit_message` immediately before the live `messages.body` is
/// updated, so this always holds what the recipient originally saw (or an
/// earlier edit of it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEdit {
    pub id: i64,
    pub message_id: String,
    pub body: Option<String>,
    pub edited_at: i64,
}

/// One reaction on a message. `contact_id: None` means the local user
/// reacted (mirrors `Message::sender_contact_id`'s convention).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reaction {
    pub message_id: String,
    pub contact_id: Option<String>,
    pub emoji: String,
    pub reacted_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReceiptStatus {
    Delivered,
    Read,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ReceiptStatus::Delivered => "delivered",
            ReceiptStatus::Read => "read",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "read" => ReceiptStatus::Read,
            _ => ReceiptStatus::Delivered,
        }
    }
}

/// Per-recipient delivery/read status for a message we sent. Populated
/// from the encrypted receipt envelopes described in `bh-crypto::envelope`
/// — nothing here is ever visible to anything but the two conversation
/// participants (SPEC.md §2.3: no operator-visible metadata).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageReceipt {
    pub message_id: String,
    pub contact_id: String,
    pub status: ReceiptStatus,
    pub updated_at: i64,
}

/// A locally-issued invite link/QR this identity created, tracked so
/// expiry and single/limited-use redemption can be enforced without a
/// server (SPEC.md §3): the *issuer* is the only party who can meaningfully
/// enforce "this link only works once," since there's no central authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedInvite {
    pub token: Vec<u8>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub max_uses: Option<i64>,
    pub use_count: i64,
    pub revoked: bool,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PaymentAsset {
    Xmr,
    Btc,
    Eth,
}

impl PaymentAsset {
    pub fn as_str(self) -> &'static str {
        match self {
            PaymentAsset::Xmr => "XMR",
            PaymentAsset::Btc => "BTC",
            PaymentAsset::Eth => "ETH",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "BTC" => PaymentAsset::Btc,
            "ETH" => PaymentAsset::Eth,
            _ => PaymentAsset::Xmr,
        }
    }

    /// URI scheme used for the "open in wallet" deep link. Deliberately
    /// address-only (no embedded amount) — see
    /// `crates/bh-api/src/payment_requests.rs` for why.
    pub fn uri_scheme(self) -> &'static str {
        match self {
            PaymentAsset::Xmr => "monero",
            PaymentAsset::Btc => "bitcoin",
            PaymentAsset::Eth => "ethereum",
        }
    }

    /// Matches the honesty-in-UI requirement from SPEC.md §12: Monero is
    /// private by design, BTC/ETH are public and traceable on-chain.
    pub fn privacy_label(self) -> &'static str {
        match self {
            PaymentAsset::Xmr => "private by design",
            PaymentAsset::Btc | PaymentAsset::Eth => "public on-chain",
        }
    }
}

/// A request to pay a crypto address, attached to a chat message. This is
/// *only* an encrypted address/amount/memo exchange — Blackhole never
/// custodies funds and never watches the blockchain for payment; settlement
/// happens wallet-to-wallet, entirely outside the app. `paid_at` reflects a
/// manual "mark as paid" action by a local user, not an on-chain
/// confirmation (SPEC.md §12 keeps the payments/messaging data boundary by
/// having this feature never touch payment infrastructure at all).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequest {
    pub message_id: String,
    pub asset: PaymentAsset,
    pub address: String,
    pub amount: Option<String>,
    pub memo: Option<String>,
    pub paid_at: Option<i64>,
}

/// A profile-customization slot (SPEC.md §12). Shared vocabulary between
/// the messaging database (`cosmetic_inventory`/`cosmetic_equipped`) and
/// the separate payments database (`cosmetic_catalog`) — defining it once
/// here is just avoiding a duplicate enum, not a data link between the two
/// databases; no row ever crosses between them, only the opaque
/// entitlement token handled in `payments.rs`/`cosmetics.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CosmeticKind {
    Banner,
    Theme,
    Badge,
    #[serde(rename = "sticker_pack")]
    StickerPack,
}

impl CosmeticKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CosmeticKind::Banner => "banner",
            CosmeticKind::Theme => "theme",
            CosmeticKind::Badge => "badge",
            CosmeticKind::StickerPack => "sticker_pack",
        }
    }

    /// Trusted-input decode for rows already accepted by the `CHECK`
    /// constraint on `kind` — falls back to `Badge` rather than failing,
    /// since an invalid value here can only mean a schema/data bug, not
    /// attacker-controlled input.
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "banner" => CosmeticKind::Banner,
            "theme" => CosmeticKind::Theme,
            "sticker_pack" => CosmeticKind::StickerPack,
            _ => CosmeticKind::Badge,
        }
    }

    /// Strict decode for untrusted input (e.g. an API path segment) —
    /// `None` on anything that isn't exactly one of the four slots,
    /// unlike `from_db_str`'s lossy fallback.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "banner" => Some(CosmeticKind::Banner),
            "theme" => Some(CosmeticKind::Theme),
            "badge" => Some(CosmeticKind::Badge),
            "sticker_pack" => Some(CosmeticKind::StickerPack),
            _ => None,
        }
    }
}

/// One cosmetic this profile owns, granted by redeeming an opaque
/// entitlement token minted by the payments database once a purchase is
/// confirmed (SPEC.md §12) — this row never carries an invoice id, a
/// price, or any other payment detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosmeticInventoryItem {
    pub entitlement_token: String,
    pub item_id: String,
    pub kind: CosmeticKind,
    pub granted_at: i64,
}

/// The single item currently equipped in a given slot. `kind` is the
/// primary key in `cosmetic_equipped` — one active item per slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquippedCosmetic {
    pub kind: CosmeticKind,
    pub item_id: String,
    pub equipped_at: i64,
}

/// The sticker a message carries, if any — one row per message
/// (`message_stickers`), gated on ownership at send time by
/// `crates/bh-api/src/stickers.rs`, never at read time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageSticker {
    pub message_id: String,
    pub pack_item_id: String,
    pub sticker_id: String,
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
    /// The 32-byte `bh_files` file key. SQLCipher-at-rest is this column's
    /// only protection — same trust boundary as `sessions.ratchet_state`/
    /// `groups.mls_state` — so it must never round-trip into an HTTP
    /// response (see `crates/bh-api/src/files.rs`'s stripped response DTO).
    pub file_key: Vec<u8>,
    /// JSON-serialized `bh_files::chunking::Manifest` (chunk hashes +
    /// plaintext lengths) — needed to reassemble the file from the
    /// per-chunk ciphertext this daemon wrote to disk under `data_dir`.
    pub manifest_json: String,
    pub attachment_kind: AttachmentKind,
    /// Recording length in seconds — only meaningful (`Some`) for
    /// `AttachmentKind::Voice`.
    pub duration_secs: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttachmentKind {
    File,
    Voice,
}

impl AttachmentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AttachmentKind::File => "file",
            AttachmentKind::Voice => "voice",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "voice" => AttachmentKind::Voice,
            _ => AttachmentKind::File,
        }
    }
}

/// A locally-enrolled TOTP secret gating the Tauri client's local-unlock
/// screen (SPEC.md §3). Single-row table — one daemon, one local-auth
/// identity. See `bh-crypto::auth::TotpSecret`. **Does not** gate SQLCipher
/// DB decryption (THREAT_MODEL.md §3.7) — this is a client-UX-level gate
/// only, checked after the DB is already open.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSecretRow {
    pub base32_secret: String,
    pub enrolled_at: i64,
}

/// A locally-enrolled WebAuthn/passkey credential gating the Tauri
/// client's local-unlock screen (SPEC.md §3). `passkey_blob` is
/// `serde_json`-serialized `webauthn_rs::prelude::Passkey`, opaque to
/// `bh-storage`. See `bh-crypto::auth::PasskeyManager`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub credential_id: String,
    pub passkey_blob: Vec<u8>,
    pub label: Option<String>,
    pub enrolled_at: i64,
}
