//! Row types for every table in `payments_schema.rs`.

use serde::{Deserialize, Serialize};

use crate::models::CosmeticKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CryptoAsset {
    Xmr,
    Btc,
}

impl CryptoAsset {
    pub fn as_str(self) -> &'static str {
        match self {
            CryptoAsset::Xmr => "XMR",
            CryptoAsset::Btc => "BTC",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "BTC" => CryptoAsset::Btc,
            _ => CryptoAsset::Xmr,
        }
    }
}

/// One purchasable cosmetic. Public catalog data — no more sensitive than
/// a storefront listing — but still lives in the payments database, not
/// the messaging one: browsing/purchasing never requires opening the
/// messaging database at all.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosmeticCatalogItem {
    pub item_id: String,
    pub kind: CosmeticKind,
    pub name: String,
    pub description: Option<String>,
    pub asset_ref: String,
    pub price_asset: CryptoAsset,
    pub price_amount: String,
    pub active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PurchaseStatus {
    Pending,
    Paid,
    Expired,
}

impl PurchaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            PurchaseStatus::Pending => "pending",
            PurchaseStatus::Paid => "paid",
            PurchaseStatus::Expired => "expired",
        }
    }

    pub fn from_db_str(s: &str) -> Self {
        match s {
            "paid" => PurchaseStatus::Paid,
            "expired" => PurchaseStatus::Expired,
            _ => PurchaseStatus::Pending,
        }
    }
}

/// One purchase attempt against a BTCPay-issued invoice for a catalog
/// item. `entitlement_token` is `None` until `PaymentsDatabase::
/// mark_purchase_paid` mints it — that token, never this row, is the only
/// thing that reaches the messaging database (SPEC.md §12).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Purchase {
    pub purchase_id: String,
    pub item_id: String,
    pub invoice_id: String,
    pub asset: CryptoAsset,
    pub amount: String,
    pub status: PurchaseStatus,
    pub entitlement_token: Option<String>,
    pub created_at: i64,
    pub paid_at: Option<i64>,
}
