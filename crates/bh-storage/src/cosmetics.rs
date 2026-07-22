//! Local cosmetic inventory/equip state for this profile — banners,
//! themes, and badges (SPEC.md §12). Ownership is granted only through
//! `grant_cosmetic`'s opaque entitlement token, minted by the separate
//! payments database (`payments.rs`) once a purchase clears; nothing here
//! ever sees an invoice, a price, or a BTCPay identifier.

use rusqlite::params;

use crate::models::{CosmeticInventoryItem, CosmeticKind, EquippedCosmetic};
use crate::{Database, StorageError};

fn row_to_inventory_item(row: &rusqlite::Row) -> rusqlite::Result<CosmeticInventoryItem> {
    let kind: String = row.get(2)?;
    Ok(CosmeticInventoryItem {
        entitlement_token: row.get(0)?,
        item_id: row.get(1)?,
        kind: CosmeticKind::from_db_str(&kind),
        granted_at: row.get(3)?,
    })
}

fn row_to_equipped(row: &rusqlite::Row) -> rusqlite::Result<EquippedCosmetic> {
    let kind: String = row.get(0)?;
    Ok(EquippedCosmetic {
        kind: CosmeticKind::from_db_str(&kind),
        item_id: row.get(1)?,
        equipped_at: row.get(2)?,
    })
}

impl Database {
    /// Redeems an entitlement token minted by the payments database,
    /// adding the cosmetic it represents to this profile's inventory.
    /// Idempotent on `entitlement_token` — replaying the same token (e.g.
    /// after a crash between mint and redeem) just no-ops instead of
    /// erroring, since a token is unique per purchase by construction.
    pub fn grant_cosmetic(
        &self,
        entitlement_token: &str,
        item_id: &str,
        kind: CosmeticKind,
        granted_at: i64,
    ) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO cosmetic_inventory (entitlement_token, item_id, kind, granted_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(entitlement_token) DO NOTHING",
            params![entitlement_token, item_id, kind.as_str(), granted_at],
        )?;
        Ok(())
    }

    pub fn list_inventory(&self) -> Result<Vec<CosmeticInventoryItem>, StorageError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT entitlement_token, item_id, kind, granted_at
             FROM cosmetic_inventory ORDER BY granted_at",
        )?;
        let rows = stmt.query_map([], row_to_inventory_item)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    /// Whether this profile's inventory owns `item_id` in slot `kind`.
    /// This is the *only* accessor `bh-api` should use to gate anything on
    /// ownership (equipping, and — per `crates/bh-api/src/stickers.rs` —
    /// sending a sticker from a purchased pack): it reads exclusively from
    /// the messaging database's `cosmetic_inventory` table, which only ever
    /// gains rows via `grant_cosmetic`'s opaque entitlement token. Callers
    /// must never re-derive ownership by querying the payments database's
    /// `cosmetic_catalog`/`purchases` tables instead — that would cross the
    /// payments/messaging isolation boundary CLAUDE.md requires.
    pub fn is_cosmetic_owned(
        &self,
        kind: CosmeticKind,
        item_id: &str,
    ) -> Result<bool, StorageError> {
        self.conn()?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM cosmetic_inventory WHERE item_id = ?1 AND kind = ?2)",
                params![item_id, kind.as_str()],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    /// Equips `item_id` in the given slot (`kind`), replacing whatever was
    /// equipped there before. Fails with `StorageError::NotFound` if this
    /// profile's inventory doesn't contain an item with that
    /// `(item_id, kind)` pair — equipping is never a way to grant
    /// ownership, only `grant_cosmetic` is.
    pub fn equip_cosmetic(
        &self,
        kind: CosmeticKind,
        item_id: &str,
        equipped_at: i64,
    ) -> Result<(), StorageError> {
        let conn = self.conn()?;
        let owned: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM cosmetic_inventory WHERE item_id = ?1 AND kind = ?2)",
            params![item_id, kind.as_str()],
            |row| row.get(0),
        )?;
        if !owned {
            return Err(StorageError::NotFound);
        }
        conn.execute(
            "INSERT INTO cosmetic_equipped (kind, item_id, equipped_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(kind) DO UPDATE SET
                item_id = excluded.item_id,
                equipped_at = excluded.equipped_at",
            params![kind.as_str(), item_id, equipped_at],
        )?;
        Ok(())
    }

    pub fn unequip_cosmetic(&self, kind: CosmeticKind) -> Result<(), StorageError> {
        self.conn()?.execute(
            "DELETE FROM cosmetic_equipped WHERE kind = ?1",
            params![kind.as_str()],
        )?;
        Ok(())
    }

    pub fn get_equipped(
        &self,
        kind: CosmeticKind,
    ) -> Result<Option<EquippedCosmetic>, StorageError> {
        self.conn()?
            .query_row(
                "SELECT kind, item_id, equipped_at FROM cosmetic_equipped WHERE kind = ?1",
                params![kind.as_str()],
                row_to_equipped,
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    pub fn list_equipped(&self) -> Result<Vec<EquippedCosmetic>, StorageError> {
        let conn = self.conn()?;
        let mut stmt =
            conn.prepare("SELECT kind, item_id, equipped_at FROM cosmetic_equipped ORDER BY kind")?;
        let rows = stmt.query_map([], row_to_equipped)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn granting_cosmetic_adds_it_to_inventory() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.grant_cosmetic("tok-1", "banner-1", CosmeticKind::Banner, 100)
            .unwrap();

        let inventory = db.list_inventory().unwrap();
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].item_id, "banner-1");
        assert_eq!(inventory[0].kind, CosmeticKind::Banner);
    }

    #[test]
    fn granting_same_token_twice_does_not_duplicate() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        for _ in 0..2 {
            db.grant_cosmetic("tok-1", "banner-1", CosmeticKind::Banner, 100)
                .unwrap();
        }
        assert_eq!(db.list_inventory().unwrap().len(), 1);
    }

    #[test]
    fn is_cosmetic_owned_reflects_inventory_only() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        assert!(!db
            .is_cosmetic_owned(CosmeticKind::StickerPack, "sticker-pack-nebula")
            .unwrap());

        db.grant_cosmetic(
            "tok-1",
            "sticker-pack-nebula",
            CosmeticKind::StickerPack,
            100,
        )
        .unwrap();
        assert!(db
            .is_cosmetic_owned(CosmeticKind::StickerPack, "sticker-pack-nebula")
            .unwrap());
        // Same item id, different kind: not owned under that kind.
        assert!(!db
            .is_cosmetic_owned(CosmeticKind::Banner, "sticker-pack-nebula")
            .unwrap());
    }

    #[test]
    fn equipping_unowned_item_fails() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        let result = db.equip_cosmetic(CosmeticKind::Banner, "banner-1", 100);
        assert!(matches!(result, Err(StorageError::NotFound)));
    }

    #[test]
    fn equip_and_reequip_same_slot() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.grant_cosmetic("tok-1", "banner-1", CosmeticKind::Banner, 100)
            .unwrap();
        db.grant_cosmetic("tok-2", "banner-2", CosmeticKind::Banner, 101)
            .unwrap();

        db.equip_cosmetic(CosmeticKind::Banner, "banner-1", 200)
            .unwrap();
        assert_eq!(
            db.get_equipped(CosmeticKind::Banner)
                .unwrap()
                .unwrap()
                .item_id,
            "banner-1"
        );

        db.equip_cosmetic(CosmeticKind::Banner, "banner-2", 300)
            .unwrap();
        let equipped = db.get_equipped(CosmeticKind::Banner).unwrap().unwrap();
        assert_eq!(equipped.item_id, "banner-2");
        assert_eq!(equipped.equipped_at, 300);
    }

    #[test]
    fn different_slots_are_independent() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.grant_cosmetic("tok-1", "banner-1", CosmeticKind::Banner, 100)
            .unwrap();
        db.grant_cosmetic("tok-2", "theme-1", CosmeticKind::Theme, 100)
            .unwrap();
        db.equip_cosmetic(CosmeticKind::Banner, "banner-1", 200)
            .unwrap();
        db.equip_cosmetic(CosmeticKind::Theme, "theme-1", 200)
            .unwrap();

        assert_eq!(db.list_equipped().unwrap().len(), 2);
        assert!(db.get_equipped(CosmeticKind::Badge).unwrap().is_none());
    }

    #[test]
    fn unequip_clears_the_slot() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.grant_cosmetic("tok-1", "banner-1", CosmeticKind::Banner, 100)
            .unwrap();
        db.equip_cosmetic(CosmeticKind::Banner, "banner-1", 200)
            .unwrap();

        db.unequip_cosmetic(CosmeticKind::Banner).unwrap();
        assert!(db.get_equipped(CosmeticKind::Banner).unwrap().is_none());
    }
}
