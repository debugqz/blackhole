//! Catalog and purchase lifecycle for the payments database. Nothing here
//! ever touches the messaging database — see `payments_db.rs`. Creating
//! and confirming invoices against BTCPay (and its Monero plugin) is not
//! wired in yet: `create_purchase` records an invoice BTCPay has already
//! issued, and `mark_purchase_paid` is meant to be called once BTCPay's
//! webhook confirms it — that HTTP integration is a separate piece of
//! work, not part of this storage layer.

use rusqlite::params;
use uuid::Uuid;

use crate::models::CosmeticKind;
use crate::payments_models::{CosmeticCatalogItem, CryptoAsset, Purchase, PurchaseStatus};
use crate::{PaymentsDatabase, StorageError};

fn row_to_catalog_item(row: &rusqlite::Row) -> rusqlite::Result<CosmeticCatalogItem> {
    let kind: String = row.get(1)?;
    let price_asset: String = row.get(5)?;
    Ok(CosmeticCatalogItem {
        item_id: row.get(0)?,
        kind: CosmeticKind::from_db_str(&kind),
        name: row.get(2)?,
        description: row.get(3)?,
        asset_ref: row.get(4)?,
        price_asset: CryptoAsset::from_db_str(&price_asset),
        price_amount: row.get(6)?,
        active: row.get::<_, i64>(7)? != 0,
    })
}

const CATALOG_COLUMNS: &str =
    "item_id, kind, name, description, asset_ref, price_asset, price_amount, active";

fn row_to_purchase(row: &rusqlite::Row) -> rusqlite::Result<Purchase> {
    let asset: String = row.get(3)?;
    let status: String = row.get(5)?;
    Ok(Purchase {
        purchase_id: row.get(0)?,
        item_id: row.get(1)?,
        invoice_id: row.get(2)?,
        asset: CryptoAsset::from_db_str(&asset),
        amount: row.get(4)?,
        status: PurchaseStatus::from_db_str(&status),
        entitlement_token: row.get(6)?,
        created_at: row.get(7)?,
        paid_at: row.get(8)?,
    })
}

const PURCHASE_COLUMNS: &str = "purchase_id, item_id, invoice_id, asset, amount, status, \
    entitlement_token, created_at, paid_at";

impl PaymentsDatabase {
    pub fn upsert_catalog_item(&self, item: &CosmeticCatalogItem) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO cosmetic_catalog
                (item_id, kind, name, description, asset_ref, price_asset, price_amount, active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(item_id) DO UPDATE SET
                kind = excluded.kind,
                name = excluded.name,
                description = excluded.description,
                asset_ref = excluded.asset_ref,
                price_asset = excluded.price_asset,
                price_amount = excluded.price_amount,
                active = excluded.active",
            params![
                item.item_id,
                item.kind.as_str(),
                item.name,
                item.description,
                item.asset_ref,
                item.price_asset.as_str(),
                item.price_amount,
                item.active as i64,
            ],
        )?;
        Ok(())
    }

    pub fn list_catalog(
        &self,
        active_only: bool,
    ) -> Result<Vec<CosmeticCatalogItem>, StorageError> {
        let conn = self.conn()?;
        let sql = if active_only {
            format!(
                "SELECT {CATALOG_COLUMNS} FROM cosmetic_catalog WHERE active = 1 ORDER BY item_id"
            )
        } else {
            format!("SELECT {CATALOG_COLUMNS} FROM cosmetic_catalog ORDER BY item_id")
        };
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_catalog_item)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    pub fn get_catalog_item(
        &self,
        item_id: &str,
    ) -> Result<Option<CosmeticCatalogItem>, StorageError> {
        let conn = self.conn()?;
        let sql = format!("SELECT {CATALOG_COLUMNS} FROM cosmetic_catalog WHERE item_id = ?1");
        conn.query_row(&sql, params![item_id], row_to_catalog_item)
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    /// Records a purchase against an invoice BTCPay has already issued.
    /// Starts life `pending`; call `mark_purchase_paid` once BTCPay
    /// confirms it.
    pub fn create_purchase(
        &self,
        item_id: &str,
        invoice_id: &str,
        asset: CryptoAsset,
        amount: &str,
        created_at: i64,
    ) -> Result<Purchase, StorageError> {
        let purchase = Purchase {
            purchase_id: Uuid::new_v4().to_string(),
            item_id: item_id.to_string(),
            invoice_id: invoice_id.to_string(),
            asset,
            amount: amount.to_string(),
            status: PurchaseStatus::Pending,
            entitlement_token: None,
            created_at,
            paid_at: None,
        };
        self.conn()?.execute(
            "INSERT INTO purchases
                (purchase_id, item_id, invoice_id, asset, amount, status, entitlement_token, created_at, paid_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, NULL)",
            params![
                purchase.purchase_id,
                purchase.item_id,
                purchase.invoice_id,
                purchase.asset.as_str(),
                purchase.amount,
                purchase.status.as_str(),
                purchase.created_at,
            ],
        )?;
        Ok(purchase)
    }

    /// Mints the opaque entitlement token for a confirmed purchase and
    /// returns it. This token — never the invoice id, amount, or address —
    /// is the only thing the caller hands to `Database::grant_cosmetic` on
    /// the messaging side (SPEC.md §12). Only takes effect from `pending`;
    /// returns `StorageError::NotFound` for an unknown or already-settled
    /// purchase id, so callers can't accidentally mint a second token for
    /// the same purchase.
    pub fn mark_purchase_paid(
        &self,
        purchase_id: &str,
        paid_at: i64,
    ) -> Result<String, StorageError> {
        let token = Uuid::new_v4().to_string();
        let updated = self.conn()?.execute(
            "UPDATE purchases SET status = 'paid', entitlement_token = ?1, paid_at = ?2
             WHERE purchase_id = ?3 AND status = 'pending'",
            params![token, paid_at, purchase_id],
        )?;
        if updated == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(token)
    }

    pub fn get_purchase(&self, purchase_id: &str) -> Result<Option<Purchase>, StorageError> {
        let conn = self.conn()?;
        let sql = format!("SELECT {PURCHASE_COLUMNS} FROM purchases WHERE purchase_id = ?1");
        conn.query_row(&sql, params![purchase_id], row_to_purchase)
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    pub fn list_purchases(&self) -> Result<Vec<Purchase>, StorageError> {
        let conn = self.conn()?;
        let sql = format!("SELECT {PURCHASE_COLUMNS} FROM purchases ORDER BY created_at");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_purchase)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str) -> CosmeticCatalogItem {
        CosmeticCatalogItem {
            item_id: id.to_string(),
            kind: CosmeticKind::Banner,
            name: "Event Horizon".into(),
            description: Some("monochrome banner".into()),
            asset_ref: "banners/event-horizon.svg".into(),
            price_asset: CryptoAsset::Xmr,
            price_amount: "0.01".into(),
            active: true,
        }
    }

    #[test]
    fn catalog_upsert_and_list() {
        let db = PaymentsDatabase::open_in_memory(&[1u8; 32]).unwrap();
        db.upsert_catalog_item(&item("banner-1")).unwrap();

        let listed = db.list_catalog(true).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "Event Horizon");

        let fetched = db.get_catalog_item("banner-1").unwrap().unwrap();
        assert_eq!(fetched.price_amount, "0.01");
    }

    #[test]
    fn upsert_updates_existing_item_in_place() {
        let db = PaymentsDatabase::open_in_memory(&[1u8; 32]).unwrap();
        db.upsert_catalog_item(&item("banner-1")).unwrap();

        let mut updated = item("banner-1");
        updated.name = "Event Horizon (v2)".into();
        db.upsert_catalog_item(&updated).unwrap();

        assert_eq!(db.list_catalog(true).unwrap().len(), 1);
        assert_eq!(
            db.get_catalog_item("banner-1").unwrap().unwrap().name,
            "Event Horizon (v2)"
        );
    }

    #[test]
    fn inactive_items_excluded_from_active_only_listing() {
        let db = PaymentsDatabase::open_in_memory(&[1u8; 32]).unwrap();
        let mut inactive = item("banner-2");
        inactive.active = false;
        db.upsert_catalog_item(&inactive).unwrap();

        assert!(db.list_catalog(true).unwrap().is_empty());
        assert_eq!(db.list_catalog(false).unwrap().len(), 1);
    }

    #[test]
    fn purchase_lifecycle_mints_entitlement_token_on_payment() {
        let db = PaymentsDatabase::open_in_memory(&[1u8; 32]).unwrap();
        db.upsert_catalog_item(&item("banner-1")).unwrap();

        let purchase = db
            .create_purchase("banner-1", "invoice-abc", CryptoAsset::Xmr, "0.01", 100)
            .unwrap();
        assert_eq!(purchase.status, PurchaseStatus::Pending);
        assert!(purchase.entitlement_token.is_none());

        let token = db.mark_purchase_paid(&purchase.purchase_id, 200).unwrap();
        assert!(!token.is_empty());

        let reloaded = db.get_purchase(&purchase.purchase_id).unwrap().unwrap();
        assert_eq!(reloaded.status, PurchaseStatus::Paid);
        assert_eq!(reloaded.entitlement_token, Some(token));
        assert_eq!(reloaded.paid_at, Some(200));
    }

    #[test]
    fn marking_unknown_purchase_paid_fails() {
        let db = PaymentsDatabase::open_in_memory(&[1u8; 32]).unwrap();
        let result = db.mark_purchase_paid("does-not-exist", 1);
        assert!(matches!(result, Err(StorageError::NotFound)));
    }

    #[test]
    fn marking_already_paid_purchase_paid_again_fails() {
        let db = PaymentsDatabase::open_in_memory(&[1u8; 32]).unwrap();
        db.upsert_catalog_item(&item("banner-1")).unwrap();
        let purchase = db
            .create_purchase("banner-1", "invoice-abc", CryptoAsset::Xmr, "0.01", 100)
            .unwrap();
        db.mark_purchase_paid(&purchase.purchase_id, 200).unwrap();

        let result = db.mark_purchase_paid(&purchase.purchase_id, 300);
        assert!(matches!(result, Err(StorageError::NotFound)));
    }

    #[test]
    fn list_purchases_returns_all_regardless_of_status() {
        let db = PaymentsDatabase::open_in_memory(&[1u8; 32]).unwrap();
        db.upsert_catalog_item(&item("banner-1")).unwrap();
        db.create_purchase("banner-1", "invoice-a", CryptoAsset::Xmr, "0.01", 1)
            .unwrap();
        let p2 = db
            .create_purchase("banner-1", "invoice-b", CryptoAsset::Btc, "0.0005", 2)
            .unwrap();
        db.mark_purchase_paid(&p2.purchase_id, 3).unwrap();

        assert_eq!(db.list_purchases().unwrap().len(), 2);
    }
}
