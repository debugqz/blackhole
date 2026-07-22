//! File/media attachments, backed by `bh-files` (chunking + per-chunk
//! E2EE) and `bh-storage::files` (metadata). `bh-files` is deliberately
//! transport/storage-agnostic — this module is the daemon-side glue: chunk
//! ciphertext lives on disk under `data_dir/files/<content_hash>/`, and
//! `bh-storage`'s `files` row tracks the metadata plus the file key and
//! serialized manifest needed to reassemble it.
//!
//! Transport is base64-in-JSON (matches `export.rs`'s existing
//! `sealed_base64` precedent), not `axum::extract::Multipart` — not worth
//! the added complexity for a localhost-only daemon at this phase.
//! Uploads are capped at [`MAX_ATTACHMENT_BYTES`].
//!
//! Uploads are also fully synchronous today (no real network fetch to
//! interrupt), so `bh_files::download::DownloadState`/`missing_chunks()`
//! stay exercised only by that crate's own unit tests — nothing here has
//! anything to resume from yet. Attachments *are* swept by the
//! disappearing-message timer: `bh-storage`'s expiry sweeper reports which
//! `content_hash`es it just orphaned from the `files` table, and
//! `state.rs`'s `restart_expiry_sweeper` uses this module's [`chunk_dir`]
//! (kept `pub(crate)` for exactly that call site) to remove the matching
//! `data_dir/files/<content_hash>/` directory from disk — see
//! THREAT_MODEL.md for the history of this gap.

use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bh_files::chunking::{ChunkRef, Manifest};
use bh_storage::models::{FileMeta, Message};
use serde::{Deserialize, Serialize};

use crate::AppState;

/// 25 MiB — a pragmatic MVP limit tied directly to the base64-in-JSON
/// transport choice; a real chunked/streaming upload path would lift this.
const MAX_ATTACHMENT_BYTES: usize = 25 * 1024 * 1024;

/// Body-size limit for the upload route's `Json` extractor. The wire body
/// is base64 (≈1.33x inflation over `MAX_ATTACHMENT_BYTES`) plus JSON
/// framing, so this must stay comfortably above `MAX_ATTACHMENT_BYTES` or
/// legitimate uploads near the cap get rejected by the extractor before
/// the handler's own size check ever runs — see `server.rs`, which wires
/// this into a route-scoped `DefaultBodyLimit`.
pub const MAX_UPLOAD_BODY_BYTES: usize = 34 * 1024 * 1024;

/// A `blake3` content hash rendered as lowercase hex: exactly 64 hex
/// digits. Any path built from a `content_hash` path parameter must be
/// validated against this first — it is otherwise attacker-controlled
/// input reaching the filesystem directly (see `delete_attachment`).
fn is_valid_content_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

pub(crate) fn chunk_dir(data_dir: &FsPath, content_hash: &str) -> PathBuf {
    data_dir.join("files").join(content_hash)
}

/// JSON-serializable mirror of `bh_files::chunking::Manifest`/`ChunkRef` —
/// kept local to this module rather than adding `serde` to `bh-files`,
/// which is deliberately dependency-light and storage-agnostic.
#[derive(Serialize, Deserialize)]
struct ManifestDto {
    total_size: u64,
    chunks: Vec<ChunkRefDto>,
}

#[derive(Serialize, Deserialize)]
struct ChunkRefDto {
    content_hash_hex: String,
    plaintext_len: u32,
}

impl From<&Manifest> for ManifestDto {
    fn from(m: &Manifest) -> Self {
        ManifestDto {
            total_size: m.total_size,
            chunks: m
                .chunks
                .iter()
                .map(|c| ChunkRefDto {
                    content_hash_hex: hex::encode(c.content_hash),
                    plaintext_len: c.plaintext_len,
                })
                .collect(),
        }
    }
}

impl TryFrom<&ManifestDto> for Manifest {
    type Error = ();
    fn try_from(dto: &ManifestDto) -> Result<Self, ()> {
        let chunks = dto
            .chunks
            .iter()
            .map(|c| {
                let bytes = hex::decode(&c.content_hash_hex).map_err(|_| ())?;
                let content_hash: [u8; 32] = bytes.try_into().map_err(|_| ())?;
                Ok(ChunkRef {
                    content_hash,
                    plaintext_len: c.plaintext_len,
                })
            })
            .collect::<Result<Vec<_>, ()>>()?;
        Ok(Manifest {
            total_size: dto.total_size,
            chunks,
        })
    }
}

/// What clients ever see for a file — deliberately omits `file_key`. Key
/// material should never round-trip into an HTTP response body, even on
/// loopback.
#[derive(Serialize)]
pub struct FileMetaPublic {
    pub content_hash: String,
    pub message_id: Option<String>,
    pub file_name: Option<String>,
    pub mime_type: Option<String>,
    pub size_bytes: i64,
    pub chunk_count: i64,
    pub attachment_kind: bh_storage::models::AttachmentKind,
    pub duration_secs: Option<i64>,
}

impl From<FileMeta> for FileMetaPublic {
    fn from(f: FileMeta) -> Self {
        FileMetaPublic {
            content_hash: f.content_hash,
            message_id: f.message_id,
            file_name: f.file_name,
            mime_type: f.mime_type,
            size_bytes: f.size_bytes,
            chunk_count: f.chunk_count,
            attachment_kind: f.attachment_kind,
            duration_secs: f.duration_secs,
        }
    }
}

#[derive(Deserialize)]
pub struct UploadAttachmentRequest {
    pub file_name: Option<String>,
    pub mime_type: Option<String>,
    pub data_base64: String,
    pub reply_to_message_id: Option<String>,
    /// Presence of this field is what distinguishes a voice message from
    /// an ordinary attachment (`AttachmentKind::Voice` vs `File`) — a
    /// recording necessarily has a length, an arbitrary file doesn't.
    #[serde(default)]
    pub duration_secs: Option<i64>,
}

#[derive(Serialize)]
pub struct UploadAttachmentResponse {
    pub message: Message,
    pub file: FileMetaPublic,
}

pub async fn upload_attachment(
    State(state): State<Arc<AppState>>,
    Path(conversation_id): Path<String>,
    Json(req): Json<UploadAttachmentRequest>,
) -> Result<Json<UploadAttachmentResponse>, StatusCode> {
    let plaintext = BASE64
        .decode(&req.data_base64)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if plaintext.len() > MAX_ATTACHMENT_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    if plaintext.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    // A recording length outside sane bounds is malformed input, not a
    // real voice message — reject before any chunking/disk work.
    if req.duration_secs.is_some_and(|d| !(1..=600).contains(&d)) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let content_hash = hex::encode(blake3::hash(&plaintext).as_bytes());
    let mut file_key = [0u8; 32];
    getrandom::fill(&mut file_key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let (manifest, chunks) = bh_files::chunk_and_encrypt(&plaintext, &file_key);

    let dir = chunk_dir(&state.data_dir(), &content_hash);
    std::fs::create_dir_all(&dir).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    for (index, chunk) in chunks.iter().enumerate() {
        std::fs::write(dir.join(format!("{index}.chunk")), &chunk.ciphertext)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    let sent_at = now();
    let expires_at = state
        .db()
        .compute_message_expiry(&conversation_id, sent_at)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let display_name = req.file_name.clone().unwrap_or_else(|| "file".to_string());
    // A voice message carries no body — like a sticker, the client
    // recognizes it by fetching this attachment for a `body: null`
    // message rather than by parsing an emoji-prefixed label.
    let body = if req.duration_secs.is_some() {
        None
    } else {
        Some(format!("\u{1F4CE} {display_name}"))
    };
    let message = Message {
        message_id: uuid::Uuid::new_v4().to_string(),
        conversation_id,
        sender_contact_id: None,
        body,
        sent_at,
        received_at: None,
        expires_at,
        deleted_at: None,
        reply_to_message_id: req.reply_to_message_id,
        edited_at: None,
    };
    state
        .db()
        .insert_message(&message)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let manifest_json = serde_json::to_string(&ManifestDto::from(&manifest))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let file = FileMeta {
        content_hash: content_hash.clone(),
        message_id: Some(message.message_id.clone()),
        file_name: req.file_name,
        mime_type: req.mime_type,
        size_bytes: plaintext.len() as i64,
        chunk_count: manifest.chunks.len() as i64,
        local_path: None,
        // The sender already holds every chunk locally the instant this
        // returns — there is no real transfer step yet (module doc).
        download_state: bh_storage::models::DownloadState::Complete,
        file_key: file_key.to_vec(),
        manifest_json,
        attachment_kind: if req.duration_secs.is_some() {
            bh_storage::models::AttachmentKind::Voice
        } else {
            bh_storage::models::AttachmentKind::File
        },
        duration_secs: req.duration_secs,
    };
    state
        .db()
        .upsert_file_meta(&file)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(UploadAttachmentResponse {
        message,
        file: file.into(),
    }))
}

pub async fn list_attachments(
    State(state): State<Arc<AppState>>,
    Path(conversation_id): Path<String>,
) -> Result<Json<Vec<FileMetaPublic>>, StatusCode> {
    state
        .db()
        .list_files_for_conversation(&conversation_id)
        .map(|files| Json(files.into_iter().map(Into::into).collect()))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Serialize)]
pub struct DownloadAttachmentResponse {
    pub data_base64: String,
    pub file_name: Option<String>,
    pub mime_type: Option<String>,
}

pub async fn download_attachment(
    State(state): State<Arc<AppState>>,
    Path(content_hash): Path<String>,
) -> Result<Json<DownloadAttachmentResponse>, StatusCode> {
    let meta = state
        .db()
        .get_file_meta(&content_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let manifest_dto: ManifestDto =
        serde_json::from_str(&meta.manifest_json).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let manifest: Manifest = (&manifest_dto)
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let file_key: [u8; 32] = meta
        .file_key
        .as_slice()
        .try_into()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let dir = chunk_dir(&state.data_dir(), &content_hash);
    let mut available = std::collections::HashMap::new();
    for (index, chunk_ref) in manifest.chunks.iter().enumerate() {
        let bytes = std::fs::read(dir.join(format!("{index}.chunk")))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        available.insert(chunk_ref.content_hash, bytes);
    }

    let plaintext = bh_files::reassemble(&manifest, &available, &file_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(DownloadAttachmentResponse {
        data_base64: BASE64.encode(plaintext),
        file_name: meta.file_name,
        mime_type: meta.mime_type,
    }))
}

pub async fn delete_attachment(
    State(state): State<Arc<AppState>>,
    Path(content_hash): Path<String>,
) -> StatusCode {
    if !is_valid_content_hash(&content_hash) {
        return StatusCode::BAD_REQUEST;
    }
    // Only touch the filesystem for a hash that actually has a metadata
    // row — otherwise this is attacker-controlled input reaching
    // `remove_dir_all` with no proof it ever referred to a real chunk dir.
    match state.db().get_file_meta(&content_hash) {
        Ok(Some(_)) => {}
        Ok(None) => return StatusCode::NOT_FOUND,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    }

    let dir = chunk_dir(&state.data_dir(), &content_hash);
    let _ = std::fs::remove_dir_all(&dir);
    match state.db().delete_file_meta(&content_hash) {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
