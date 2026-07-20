//! Schema definition and migration runner. Migrations are additive and
//! idempotent (`CREATE TABLE IF NOT EXISTS`); schema version is tracked via
//! `PRAGMA user_version` so future breaking changes have somewhere to hook
//! real `ALTER TABLE` migrations.

use rusqlite::Connection;

use crate::StorageError;

pub const CURRENT_VERSION: i64 = 1;

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS own_identity (
    id                    INTEGER PRIMARY KEY CHECK (id = 1),
    identity_public_key   BLOB NOT NULL,
    identity_private_key  BLOB NOT NULL,
    created_at            INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
    contact_id           TEXT PRIMARY KEY,
    identity_public_key  BLOB NOT NULL,
    display_name         TEXT,
    verified              INTEGER NOT NULL DEFAULT 0,
    blocked                INTEGER NOT NULL DEFAULT 0,
    added_at               INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    device_id     TEXT PRIMARY KEY,
    owner         TEXT NOT NULL CHECK (owner IN ('self', 'contact')),
    contact_id    TEXT REFERENCES contacts(contact_id) ON DELETE CASCADE,
    name          TEXT,
    public_key    BLOB NOT NULL,
    linked_at     INTEGER NOT NULL,
    last_seen_at  INTEGER,
    revoked_at    INTEGER
);

CREATE TABLE IF NOT EXISTS message_requests (
    contact_id   TEXT PRIMARY KEY REFERENCES contacts(contact_id) ON DELETE CASCADE,
    received_at  INTEGER NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('pending','accepted','declined')) DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id     TEXT PRIMARY KEY,
    contact_id     TEXT NOT NULL REFERENCES contacts(contact_id) ON DELETE CASCADE,
    device_id      TEXT NOT NULL,
    ratchet_state  BLOB NOT NULL,
    updated_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS groups (
    group_id    TEXT PRIMARY KEY,
    name        TEXT,
    mls_state   BLOB NOT NULL,
    epoch       INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id    TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
    contact_id  TEXT NOT NULL REFERENCES contacts(contact_id) ON DELETE CASCADE,
    joined_at   INTEGER NOT NULL,
    PRIMARY KEY (group_id, contact_id)
);

CREATE TABLE IF NOT EXISTS conversations (
    conversation_id  TEXT PRIMARY KEY,
    kind             TEXT NOT NULL CHECK (kind IN ('direct','group')),
    contact_id       TEXT REFERENCES contacts(contact_id) ON DELETE CASCADE,
    group_id         TEXT REFERENCES groups(group_id) ON DELETE CASCADE,
    created_at       INTEGER NOT NULL,
    CHECK ((kind = 'direct' AND contact_id IS NOT NULL AND group_id IS NULL)
        OR (kind = 'group'  AND group_id  IS NOT NULL AND contact_id IS NULL))
);

CREATE TABLE IF NOT EXISTS messages (
    message_id         TEXT PRIMARY KEY,
    conversation_id    TEXT NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,
    sender_contact_id  TEXT REFERENCES contacts(contact_id),
    body               TEXT,
    sent_at            INTEGER NOT NULL,
    received_at        INTEGER,
    expires_at         INTEGER,
    deleted_at         INTEGER
);
CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, sent_at);

CREATE TABLE IF NOT EXISTS files (
    content_hash    TEXT PRIMARY KEY,
    message_id      TEXT REFERENCES messages(message_id) ON DELETE CASCADE,
    file_name       TEXT,
    mime_type       TEXT,
    size_bytes      INTEGER NOT NULL,
    chunk_count     INTEGER NOT NULL,
    local_path      TEXT,
    download_state  TEXT NOT NULL CHECK (download_state IN ('pending','partial','complete')) DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
"#;

pub fn migrate(conn: &Connection) -> Result<(), StorageError> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 1 {
        conn.execute_batch(SCHEMA_V1)?;
        conn.execute_batch(&format!("PRAGMA user_version = {CURRENT_VERSION}"))?;
    }
    Ok(())
}
