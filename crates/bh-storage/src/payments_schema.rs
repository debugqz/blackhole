//! Schema for the payments/subscriptions database — physically separate
//! from `schema.rs` (the messaging database), per CLAUDE.md's non-
//! negotiable that payments and messaging data are never linked directly.
//! See `payments_db.rs` for why this is a distinct SQLCipher file rather
//! than a second set of tables in the same one.

use rusqlite::Connection;

use crate::StorageError;

pub const CURRENT_VERSION: i64 = 2;

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS cosmetic_catalog (
    item_id       TEXT PRIMARY KEY,
    kind          TEXT NOT NULL CHECK (kind IN ('banner','theme','badge')),
    name          TEXT NOT NULL,
    description   TEXT,
    asset_ref     TEXT NOT NULL,
    price_asset   TEXT NOT NULL CHECK (price_asset IN ('XMR','BTC')),
    price_amount  TEXT NOT NULL,
    active        INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS purchases (
    purchase_id        TEXT PRIMARY KEY,
    item_id             TEXT NOT NULL REFERENCES cosmetic_catalog(item_id),
    invoice_id          TEXT NOT NULL,
    asset                TEXT NOT NULL CHECK (asset IN ('XMR','BTC')),
    amount                TEXT NOT NULL,
    status                TEXT NOT NULL CHECK (status IN ('pending','paid','expired')) DEFAULT 'pending',
    entitlement_token    TEXT UNIQUE,
    created_at            INTEGER NOT NULL,
    paid_at               INTEGER
);
"#;

// v2 adds `sticker_pack` to the set of purchasable cosmetic kinds (SPEC.md
// §12/§15). SQLite `CHECK` constraints can't be widened with `ALTER TABLE`,
// so `cosmetic_catalog` is recreated with the wider list and its rows
// copied across. Unlike `schema.rs`'s v7 (which does the same thing for
// `cosmetic_inventory`/`cosmetic_equipped`), `purchases.item_id` has a real
// foreign key into `cosmetic_catalog`, and SQLite refuses to `DROP TABLE` a
// table something else still references while `PRAGMA foreign_keys` is on
// — so this step turns it off, does the swap, and turns it back on. Both
// pragma calls must run *outside* the `BEGIN...COMMIT` — SQLite silently
// no-ops `PRAGMA foreign_keys` inside an active transaction — hence this
// step gets its own bespoke wrapping in `migrate` below rather than
// sharing the plain `BEGIN; {ddl} COMMIT;` every other step uses.
const SCHEMA_V2: &str = r#"
CREATE TABLE IF NOT EXISTS cosmetic_catalog_v2 (
    item_id       TEXT PRIMARY KEY,
    kind          TEXT NOT NULL CHECK (kind IN ('banner','theme','badge','sticker_pack')),
    name          TEXT NOT NULL,
    description   TEXT,
    asset_ref     TEXT NOT NULL,
    price_asset   TEXT NOT NULL CHECK (price_asset IN ('XMR','BTC')),
    price_amount  TEXT NOT NULL,
    active        INTEGER NOT NULL DEFAULT 1
);
INSERT OR IGNORE INTO cosmetic_catalog_v2
    SELECT item_id, kind, name, description, asset_ref, price_asset, price_amount, active
    FROM cosmetic_catalog;
DROP TABLE cosmetic_catalog;
ALTER TABLE cosmetic_catalog_v2 RENAME TO cosmetic_catalog;
"#;

/// `(target_version, ddl, needs_foreign_keys_toggle)`.
const STEPS: &[(i64, &str, bool)] = &[(1, SCHEMA_V1, false), (2, SCHEMA_V2, true)];

pub fn migrate(conn: &Connection) -> Result<(), StorageError> {
    debug_assert_eq!(STEPS.last().map(|(v, _, _)| *v), Some(CURRENT_VERSION));
    for (target_version, ddl, needs_fk_toggle) in STEPS {
        let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version >= *target_version {
            continue;
        }
        if *needs_fk_toggle {
            // No-ops if issued inside a transaction, so this must run
            // before `BEGIN` — see the SCHEMA_V2 doc comment above.
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
