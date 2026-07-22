//! Schema definition and migration runner. Migrations are additive and
//! idempotent (`CREATE TABLE IF NOT EXISTS`); schema version is tracked via
//! `PRAGMA user_version` so future breaking changes have somewhere to hook
//! real `ALTER TABLE` migrations.

use rusqlite::Connection;

use crate::StorageError;

pub const CURRENT_VERSION: i64 = 14;

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

// v2 adds: quote-reply + reactions on messages, a per-conversation
// disappearing-messages timer, delivery/read receipts, and a local record
// of invite links this identity has issued (for expiry/single-use
// enforcement — SPEC.md §3). `ALTER TABLE ... ADD COLUMN` is idempotent
// enough for our purposes: SQLite errors if the column already exists, so
// each statement is wrapped and any "duplicate column" error is swallowed
// by `migrate` below rather than gated behind a second idempotency check.
const SCHEMA_V2: &str = r#"
ALTER TABLE messages ADD COLUMN reply_to_message_id TEXT REFERENCES messages(message_id);

ALTER TABLE conversations ADD COLUMN disappearing_timer_secs INTEGER;

CREATE TABLE IF NOT EXISTS reactions (
    message_id  TEXT NOT NULL REFERENCES messages(message_id) ON DELETE CASCADE,
    contact_id  TEXT REFERENCES contacts(contact_id) ON DELETE CASCADE,
    emoji       TEXT NOT NULL,
    reacted_at  INTEGER NOT NULL,
    PRIMARY KEY (message_id, contact_id, emoji)
);

CREATE TABLE IF NOT EXISTS message_receipts (
    message_id  TEXT NOT NULL REFERENCES messages(message_id) ON DELETE CASCADE,
    contact_id  TEXT NOT NULL REFERENCES contacts(contact_id) ON DELETE CASCADE,
    status      TEXT NOT NULL CHECK (status IN ('delivered','read')),
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (message_id, contact_id)
);

CREATE TABLE IF NOT EXISTS issued_invites (
    token        BLOB PRIMARY KEY,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER,
    max_uses     INTEGER,
    use_count    INTEGER NOT NULL DEFAULT 0,
    revoked      INTEGER NOT NULL DEFAULT 0
);
"#;

// v3 adds in-chat crypto payment requests (SPEC.md §15): a message can
// carry a request to pay a given address, but Blackhole never custodies
// funds or watches the chain for it — one sibling table keyed by
// `message_id`, same shape as `files`/`reactions`, and `paid_at` is only
// ever set by an explicit local "mark as paid" action (see
// `crates/bh-api/src/payment_requests.rs`), never inferred automatically.
const SCHEMA_V3: &str = r#"
CREATE TABLE IF NOT EXISTS payment_requests (
    message_id  TEXT PRIMARY KEY REFERENCES messages(message_id) ON DELETE CASCADE,
    asset       TEXT NOT NULL CHECK (asset IN ('XMR','BTC','ETH')),
    address     TEXT NOT NULL,
    amount      TEXT,
    memo        TEXT,
    paid_at     INTEGER
);
"#;

// v4 adds local cosmetic inventory/equip state (SPEC.md §12): which
// profile-customization items (banners, themes, badges) this profile owns
// and has equipped. Ownership is only ever granted by redeeming an opaque
// entitlement token minted by the separate payments database
// (`payments_schema.rs`) — see `cosmetics.rs::grant_cosmetic`. Nothing here
// stores an invoice id, a price, or any other payment detail, so this
// table alone can never link message history to a purchase
// (CLAUDE.md non-negotiable: payments/messaging data stay isolated).
const SCHEMA_V4: &str = r#"
CREATE TABLE IF NOT EXISTS cosmetic_inventory (
    entitlement_token  TEXT PRIMARY KEY,
    item_id             TEXT NOT NULL,
    kind                TEXT NOT NULL CHECK (kind IN ('banner','theme','badge')),
    granted_at          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS cosmetic_equipped (
    kind         TEXT PRIMARY KEY CHECK (kind IN ('banner','theme','badge')),
    item_id      TEXT NOT NULL,
    equipped_at  INTEGER NOT NULL
);
"#;

// v5 adds: local-auth (passkey/TOTP) credential storage for the daemon's
// own client-side unlock gate (SPEC.md §3 — does not gate SQLCipher DB
// decryption itself, see THREAT_MODEL.md §3.7), and the file-attachment
// crypto material (`file_key` + serialized chunk manifest) needed to
// actually chunk/encrypt/reassemble attachments end to end via
// `bh-files` — see `crates/bh-api/src/files.rs`.
const SCHEMA_V5: &str = r#"
ALTER TABLE files ADD COLUMN file_key BLOB;
ALTER TABLE files ADD COLUMN manifest_json TEXT;

CREATE TABLE IF NOT EXISTS totp_secrets (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    base32_secret  TEXT NOT NULL,
    enrolled_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS passkey_credentials (
    credential_id  TEXT PRIMARY KEY,
    passkey_blob   BLOB NOT NULL,
    label          TEXT,
    enrolled_at    INTEGER NOT NULL
);
"#;

// v6 adds a message<->attachment join table. `files` stays keyed by
// `content_hash` (one row per unique file blob, so identical content
// shares chunk ciphertext), but a single file can legitimately be
// attached to more than one message — e.g. the same photo sent into two
// different conversations. Before this table existed, `files.message_id`
// could only ever point at one message, so re-attaching identical content
// to a second message silently reassigned the row and made it vanish
// from the first conversation's attachment list.
const SCHEMA_V6: &str = r#"
CREATE TABLE IF NOT EXISTS message_attachments (
    message_id    TEXT NOT NULL REFERENCES messages(message_id) ON DELETE CASCADE,
    content_hash  TEXT NOT NULL REFERENCES files(content_hash) ON DELETE CASCADE,
    PRIMARY KEY (message_id, content_hash)
);

INSERT OR IGNORE INTO message_attachments (message_id, content_hash)
    SELECT message_id, content_hash FROM files WHERE message_id IS NOT NULL;
"#;

// v7 adds a per-linked-device message-sync delivery cursor (SPEC.md §4),
// complementing device linking (`crates/bh-api/src/device_link.rs`) with
// actually keeping already-linked devices' visible history up to date. A
// linked "own" device doesn't share the primary's SQLCipher database or
// its in-memory Double Ratchet session state (see
// `crates/bh-api/src/device_sync.rs` module doc for why the ratchet
// session itself is *not* stored here, mirroring how `groups.rs` keeps
// live MLS state in-memory only), so this table is the only piece of sync
// progress that survives a daemon restart: how far — by `sent_at`, tie-
// broken by `message_id` for determinism within the same second — a given
// device has pulled via `GET /devices/:id/sync`.
const SCHEMA_V7: &str = r#"
CREATE TABLE IF NOT EXISTS device_sync_cursor (
    device_id          TEXT PRIMARY KEY REFERENCES devices(device_id) ON DELETE CASCADE,
    cursor_sent_at      INTEGER NOT NULL DEFAULT 0,
    cursor_message_id   TEXT,
    updated_at           INTEGER NOT NULL
);
"#;

// v8 adds sticker packs as a new cosmetic kind (SPEC.md §12/§15) and a
// sibling table recording which sticker a message carries. SQLite `CHECK`
// constraints can't be widened with `ALTER TABLE`, so `cosmetic_inventory`
// and `cosmetic_equipped` are recreated with `sticker_pack` added to their
// allowed `kind` values and their existing rows copied across — nothing
// else references either table via a foreign key, so this is safe without
// touching `PRAGMA foreign_keys` (contrast `payments_schema.rs`'s v2,
// where `purchases` *does* reference `cosmetic_catalog` and the pragma
// toggle is required). `message_stickers` mirrors `payment_requests`'
// shape: one row per message, `ON DELETE CASCADE` for the (rare) hard
// delete, with `messages.rs::delete_dependent_rows` handling the normal
// soft-delete path explicitly, same as it already does for
// `payment_requests`.
const SCHEMA_V8: &str = r#"
CREATE TABLE IF NOT EXISTS cosmetic_inventory_v8 (
    entitlement_token  TEXT PRIMARY KEY,
    item_id             TEXT NOT NULL,
    kind                TEXT NOT NULL CHECK (kind IN ('banner','theme','badge','sticker_pack')),
    granted_at          INTEGER NOT NULL
);
INSERT OR IGNORE INTO cosmetic_inventory_v8
    SELECT entitlement_token, item_id, kind, granted_at FROM cosmetic_inventory;
DROP TABLE cosmetic_inventory;
ALTER TABLE cosmetic_inventory_v8 RENAME TO cosmetic_inventory;

CREATE TABLE IF NOT EXISTS cosmetic_equipped_v8 (
    kind         TEXT PRIMARY KEY CHECK (kind IN ('banner','theme','badge','sticker_pack')),
    item_id      TEXT NOT NULL,
    equipped_at  INTEGER NOT NULL
);
INSERT OR IGNORE INTO cosmetic_equipped_v8
    SELECT kind, item_id, equipped_at FROM cosmetic_equipped;
DROP TABLE cosmetic_equipped;
ALTER TABLE cosmetic_equipped_v8 RENAME TO cosmetic_equipped;

CREATE TABLE IF NOT EXISTS message_stickers (
    message_id    TEXT PRIMARY KEY REFERENCES messages(message_id) ON DELETE CASCADE,
    pack_item_id  TEXT NOT NULL,
    sticker_id    TEXT NOT NULL
);
"#;

// v9 adds a third conversation kind, `self`, for the single local-only
// "Notes to self" conversation (SPEC.md §15) — no counterparty, so no
// `contact_id`/`group_id` and no Double Ratchet/MLS session. SQLite `CHECK`
// constraints can't be widened with `ALTER TABLE`, so `conversations` is
// recreated with `self` added to its `kind` CHECK (and to the multi-column
// CHECK below it) and its rows copied across. Unlike `schema.rs`'s v8
// (widening `cosmetic_inventory`/`cosmetic_equipped`, which nothing
// references via a foreign key), `messages.conversation_id` *does*
// reference `conversations`, and — critically — SQLite's docs specify that
// with `PRAGMA foreign_keys = ON` (always true here, see `db.rs`), `DROP
// TABLE` on a table other rows reference performs an *implicit cascading
// delete* of those referencing rows first, exactly as if `ON DELETE
// CASCADE` had fired. Without turning the pragma off first, dropping the
// old `conversations` table would silently wipe every message in the
// database mid-migration. See `payments_schema.rs`'s v2 for the same
// pattern applied to `cosmetic_catalog`/`purchases`.
const SCHEMA_V9: &str = r#"
CREATE TABLE conversations_v9 (
    conversation_id  TEXT PRIMARY KEY,
    kind             TEXT NOT NULL CHECK (kind IN ('direct','group','self')),
    contact_id       TEXT REFERENCES contacts(contact_id) ON DELETE CASCADE,
    group_id         TEXT REFERENCES groups(group_id) ON DELETE CASCADE,
    created_at       INTEGER NOT NULL,
    disappearing_timer_secs INTEGER,
    CHECK ((kind = 'direct' AND contact_id IS NOT NULL AND group_id IS NULL)
        OR (kind = 'group'  AND group_id  IS NOT NULL AND contact_id IS NULL)
        OR (kind = 'self'   AND contact_id IS NULL AND group_id IS NULL))
);
INSERT INTO conversations_v9
    (conversation_id, kind, contact_id, group_id, created_at, disappearing_timer_secs)
    SELECT conversation_id, kind, contact_id, group_id, created_at, disappearing_timer_secs
    FROM conversations;
DROP TABLE conversations;
ALTER TABLE conversations_v9 RENAME TO conversations;
"#;

// v10 adds message editing: an `edited_at` marker on the message row
// itself (so "was this edited" is a cheap, always-visible fact — never a
// silent overwrite) plus a `message_edits` table holding every prior
// version of the body, so a recipient can inspect edit history instead of
// just being told an edit happened. This travels over the same E2EE send
// path as a normal message (see `bh-api::conversations::edit_message`) —
// no new crypto mechanism, just another mutation referencing an existing
// `message_id`, the same shape reactions/receipts already use.
const SCHEMA_V10: &str = r#"
ALTER TABLE messages ADD COLUMN edited_at INTEGER;

CREATE TABLE IF NOT EXISTS message_edits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id  TEXT NOT NULL REFERENCES messages(message_id) ON DELETE CASCADE,
    body        TEXT,
    edited_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_message_edits_message ON message_edits(message_id, id);
"#;

// v11 adds broadcast channels (one-to-many groups where only the owner may
// post) as a `broadcast_only` flag on `groups` — not a new crypto
// primitive: it just gates *posting* at the API level
// (`bh-api::conversations::send_message`) on top of the same MLS group
// machinery every other group already uses.
const SCHEMA_V11: &str = r#"
ALTER TABLE groups ADD COLUMN broadcast_only INTEGER NOT NULL DEFAULT 0;
"#;

// v12 adds a local record of this profile's opt-in "wake push"
// registration (SPEC.md §5.6, `crates/bh-push-relay`) — an opaque,
// locally-generated token and whether the feature is on. Single-row, same
// pattern as `own_identity`: there is exactly one "is push on for this
// profile" state at a time. Deliberately identity-adjacent rather than
// identity-derived: the token carries no contact/conversation reference
// and isn't derived from the identity key.
const SCHEMA_V12: &str = r#"
CREATE TABLE IF NOT EXISTS push_registration (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    token       TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 0,
    updated_at  INTEGER NOT NULL
);
"#;

// v13 adds voice messages: short recorded audio clips reusing the exact
// same `bh-files` chunk-and-encrypt attachment path as a regular file
// (SPEC.md §5.5), distinguished by `attachment_kind` and carrying a
// recording length. No new crypto or storage mechanism — just two columns
// on the existing `files` table.
const SCHEMA_V13: &str = r#"
ALTER TABLE files ADD COLUMN attachment_kind TEXT NOT NULL DEFAULT 'file';
ALTER TABLE files ADD COLUMN duration_secs INTEGER;
"#;

// v14 adds local full-text search over message bodies (SPEC.md-style local
// feature: this is pure local convenience over content the daemon already
// holds decrypted in this SQLCipher-encrypted database — never anything
// transiting the network or visible to the operator — this indexes exactly
// the same plaintext `messages.body` already sitting here, so it inherits
// the same at-rest encryption). `messages.message_id` is a TEXT primary
// key, not an `INTEGER PRIMARY KEY` rowid alias, so FTS5's "external
// content table" mode (which requires an integer `content_rowid`) doesn't
// fit cleanly here; instead `messages_fts` is a normal (if independently
// rowid'd) FTS5 table kept in sync via triggers, storing `message_id`/
// `conversation_id` as `UNINDEXED` lookup columns alongside the indexed
// `body` text. A deleted or self-destructed message clears `body` via
// `UPDATE ... SET body = NULL` (see `messages.rs`), which fires the `AU`
// trigger below and removes it from the index — nothing about a
// disappeared message stays searchable.
const SCHEMA_V14: &str = r#"
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    message_id UNINDEXED,
    conversation_id UNINDEXED,
    body
);

INSERT INTO messages_fts (message_id, conversation_id, body)
    SELECT message_id, conversation_id, body FROM messages WHERE body IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS messages_fts_ai AFTER INSERT ON messages
WHEN NEW.body IS NOT NULL
BEGIN
    INSERT INTO messages_fts (message_id, conversation_id, body)
    VALUES (NEW.message_id, NEW.conversation_id, NEW.body);
END;

CREATE TRIGGER IF NOT EXISTS messages_fts_ad AFTER DELETE ON messages
BEGIN
    DELETE FROM messages_fts WHERE message_id = OLD.message_id;
END;

CREATE TRIGGER IF NOT EXISTS messages_fts_au AFTER UPDATE ON messages
BEGIN
    DELETE FROM messages_fts WHERE message_id = OLD.message_id;
    INSERT INTO messages_fts (message_id, conversation_id, body)
        SELECT NEW.message_id, NEW.conversation_id, NEW.body
        WHERE NEW.body IS NOT NULL;
END;
"#;

/// Each step's DDL runs together with `PRAGMA user_version = N` for that
/// same step. `SCHEMA_V2`/`SCHEMA_V5` contain `ALTER TABLE ... ADD COLUMN`,
/// which is *not* idempotent (SQLite errors on a column that already
/// exists) — bundling the version bump into the same transaction as the
/// DDL means a crash/power-loss mid-step rolls the whole step back rather
/// than leaving `user_version` behind a half-applied schema. The next
/// `migrate` call then safely retries the entire step from scratch instead
/// of re-running `ADD COLUMN` against an already-altered table and
/// permanently failing to open (the previous bare `execute_batch` + single
/// trailing version bump did not have this property).
/// `(target_version, ddl, needs_foreign_keys_toggle)` — see `SCHEMA_V9`'s
/// doc comment for why a step that drops a table other rows reference
/// needs the toggle (mirrors `payments_schema.rs`'s identical mechanism).
const STEPS: &[(i64, &str, bool)] = &[
    (1, SCHEMA_V1, false),
    (2, SCHEMA_V2, false),
    (3, SCHEMA_V3, false),
    (4, SCHEMA_V4, false),
    (5, SCHEMA_V5, false),
    (6, SCHEMA_V6, false),
    (7, SCHEMA_V7, false),
    (8, SCHEMA_V8, false),
    (9, SCHEMA_V9, true),
    (10, SCHEMA_V10, false),
    (11, SCHEMA_V11, false),
    (12, SCHEMA_V12, false),
    (13, SCHEMA_V13, false),
    (14, SCHEMA_V14, false),
];

pub fn migrate(conn: &Connection) -> Result<(), StorageError> {
    debug_assert_eq!(STEPS.last().map(|(v, _, _)| *v), Some(CURRENT_VERSION));
    for (target_version, ddl, needs_fk_toggle) in STEPS {
        let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version >= *target_version {
            continue;
        }
        if *needs_fk_toggle {
            // No-ops if issued inside a transaction, so this must run
            // before `BEGIN` — see `SCHEMA_V9`'s doc comment.
            conn.execute_batch("PRAGMA foreign_keys = OFF;")?;
        }
        conn.execute_batch(&format!(
            "BEGIN; {ddl} PRAGMA user_version = {target_version}; COMMIT;"
        ))?;
        if *needs_fk_toggle {
            conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_twice_in_a_row_is_a_harmless_no_op() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        migrate(&conn).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, CURRENT_VERSION);
    }

    /// Regression test for the crash-mid-migration bug: before this fix, a
    /// single bare `execute_batch(ddl)` per step plus one trailing version
    /// bump at the very end meant a crash between a step's DDL and the
    /// next step (or the final bump) left `user_version` behind an
    /// already-applied `ALTER TABLE ADD COLUMN`. The next `migrate()` call
    /// would then replay that same non-idempotent `ADD COLUMN` and fail
    /// with "duplicate column name" forever — the database could never be
    /// opened again. Simulate the crash directly: run step 5's DDL inside
    /// a transaction and roll it back instead of committing (exactly what
    /// happens if the process dies before `COMMIT`), then confirm
    /// `migrate()` can still safely retry the whole step from scratch.
    #[test]
    fn an_interrupted_ddl_step_rolls_back_so_migrate_can_safely_retry() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch(SCHEMA_V2).unwrap();
        conn.execute_batch(SCHEMA_V3).unwrap();
        conn.execute_batch(SCHEMA_V4).unwrap();
        conn.execute_batch("PRAGMA user_version = 4;").unwrap();

        conn.execute_batch("BEGIN;").unwrap();
        conn.execute_batch(SCHEMA_V5).unwrap();
        // ...the process dies here, before "PRAGMA user_version = 5; COMMIT;"...
        conn.execute_batch("ROLLBACK;").unwrap();

        // Because the whole step rolled back, `file_key` doesn't exist yet
        // and `user_version` is still 4 — migrate() must retry step 5 in
        // full rather than hitting "duplicate column name".
        migrate(&conn).unwrap();

        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, CURRENT_VERSION);
        conn.execute_batch("SELECT file_key FROM files LIMIT 0;")
            .expect("file_key should exist after the retried migration");
    }
}
