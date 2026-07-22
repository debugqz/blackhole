//! Local full-text search over the user's own already-decrypted message
//! history. Everything here queries `messages_fts` (see `schema.rs`'s
//! SQLite FTS5 virtual table, kept in sync with `messages` via triggers) —
//! a pure local SQLCipher-encrypted-at-rest database query. Nothing about a
//! search term or its results ever leaves this daemon process, let alone
//! reaches a relay or the operator: this is the user searching their own
//! mailbox after the daemon has already decrypted it, not "content
//! scanning" in the CLAUDE.md-forbidden sense.

use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::{Database, StorageError};

/// One matching message, plus a short excerpt of the body around the
/// match. `snippet` brackets matched terms with `[`/`]` (FTS5's `snippet()`
/// built-in, given `[`/`]` as the highlight markers) rather than HTML, so
/// the UI can highlight matches without ever needing to trust/sanitize
/// injected markup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageSearchResult {
    pub message_id: String,
    pub conversation_id: String,
    pub sent_at: i64,
    pub snippet: String,
}

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;

impl Database {
    /// Full-text searches this profile's own local message history for
    /// `query`. `conversation_id`, if given, scopes results to a single
    /// conversation. Deleted/self-destructed messages (`body IS NULL`)
    /// never match — their row is removed from `messages_fts` the moment
    /// `body` is cleared (see the `messages_fts_au` trigger in
    /// `schema.rs`). Results are ordered most-recent-first, same
    /// convention as `list_messages`.
    pub fn search_messages(
        &self,
        query: &str,
        conversation_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<MessageSearchResult>, StorageError> {
        let query = query.trim();
        if query.is_empty() {
            return Ok(Vec::new());
        }
        let limit = match limit {
            l if l <= 0 => DEFAULT_LIMIT,
            l if l > MAX_LIMIT => MAX_LIMIT,
            l => l,
        };
        let fts_query = sanitize_fts_query(query);
        if fts_query.is_empty() {
            return Ok(Vec::new());
        }

        let conn = self.conn()?;
        let sql = "SELECT m.message_id, m.conversation_id, m.sent_at,
                          snippet(messages_fts, 2, '[', ']', '…', 8) AS snippet
                   FROM messages_fts
                   JOIN messages m ON m.message_id = messages_fts.message_id
                   WHERE messages_fts MATCH ?1
                     AND m.deleted_at IS NULL
                     AND (?2 IS NULL OR m.conversation_id = ?2)
                   ORDER BY m.sent_at DESC
                   LIMIT ?3";
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map(params![fts_query, conversation_id, limit], |row| {
            Ok(MessageSearchResult {
                message_id: row.get(0)?,
                conversation_id: row.get(1)?,
                sent_at: row.get(2)?,
                snippet: row.get(3)?,
            })
        })?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }
}

/// FTS5's `MATCH` argument is a small expression language of its own
/// (`AND`/`OR`/`NOT`, `"phrase"` grouping, `col:` filters, `*` prefix
/// wildcards, …) — feeding arbitrary user-typed text into it unescaped
/// means a search that merely contains a stray `"`, `-`, `:`, or the word
/// `NOT` can throw a syntax error, or silently opt into wildcard/boolean
/// behavior the person typing it never intended. Quoting every
/// whitespace-separated token as an FTS5 string literal (doubling any
/// embedded `"`) and ANDing them together gives plain "all these words,
/// in any order" substring-ish search semantics regardless of what
/// punctuation shows up in the query.
fn sanitize_fts_query(input: &str) -> String {
    input
        .split_whitespace()
        .map(|token| format!("\"{}\"", token.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" AND ")
}

#[cfg(test)]
mod tests {
    use super::sanitize_fts_query;

    #[test]
    fn quotes_and_ands_whitespace_separated_tokens() {
        assert_eq!(sanitize_fts_query("hello world"), "\"hello\" AND \"world\"");
    }

    #[test]
    fn escapes_embedded_quotes_and_neutralizes_fts5_operators() {
        // A bare `-`/`NOT`/`:`/`*` would otherwise be interpreted as FTS5
        // query syntax rather than literal text.
        assert_eq!(
            sanitize_fts_query("say \"hi\" -x OR y:*"),
            "\"say\" AND \"\"\"hi\"\"\" AND \"-x\" AND \"OR\" AND \"y:*\""
        );
    }

    #[test]
    fn empty_or_whitespace_only_input_sanitizes_to_empty() {
        assert_eq!(sanitize_fts_query(""), "");
        assert_eq!(sanitize_fts_query("   "), "");
    }
}
