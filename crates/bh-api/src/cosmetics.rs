//! Cosmetic-store endpoints (SPEC.md §12): browse the catalog, see what
//! this profile owns/has equipped, and the mint-token-then-grant step that
//! bridges the payments database into the messaging database's inventory
//! (`bh_storage::cosmetics::grant_cosmetic`). See `bh_storage::payments`
//! and `bh_storage::cosmetics` for the storage layer this wraps.
//!
//! What's still missing: the actual BTCPay/Monero-plugin HTTP integration
//! — invoice creation. `create_purchase` records an invoice id the caller
//! supplies, because nothing here talks to BTCPay yet; a real integration
//! would create that invoice itself instead of trusting one handed to it.
//!
//! `mark_purchase_paid` is a stand-in for BTCPay's payment-confirmed
//! webhook. It's gated behind an HMAC-SHA256 signature
//! (`bh_crypto::webhook`) over the `purchase_id`, keyed by a per-profile
//! secret generated on first use and held only in the platform keystore
//! (`bh_storage::keystore::COSMETICS_WEBHOOK_SECRET_LABEL`) — so reaching
//! this route over the localhost API is no longer sufficient on its own to
//! grant a cosmetic for free; the caller also needs the secret, which today
//! only something reading the keystore directly (an operator, or eventually
//! a real BTCPay webhook config) can produce. See docs/THREAT_MODEL.md.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use bh_storage::keystore::COSMETICS_WEBHOOK_SECRET_LABEL;
use bh_storage::models::{CosmeticInventoryItem, CosmeticKind, EquippedCosmetic};
use bh_storage::payments_models::{CosmeticCatalogItem, CryptoAsset, Purchase};
use bh_storage::{PaymentsDatabase, StorageError};
use serde::{Deserialize, Serialize};

use crate::AppState;

/// Header carrying the hex-encoded HMAC-SHA256 signature over the
/// `purchase_id` path segment — see the module doc and [`verify_webhook_signature`].
const WEBHOOK_SIGNATURE_HEADER: &str = "x-blackhole-webhook-signature";

/// Loads this profile's cosmetics-webhook HMAC secret, generating and
/// storing a fresh 32-byte one in the platform keystore on first use.
/// Mirrors `daemon::load_or_create_db_key`'s pattern, minus the
/// PIN-protection concept, since this secret never gates database
/// decryption — it only proves a caller knows the shared webhook secret.
pub fn load_or_create_webhook_secret(state: &AppState) -> Result<[u8; 32], StatusCode> {
    let keystore = state.keystore();
    if let Some(existing) = keystore
        .load_key(COSMETICS_WEBHOOK_SECRET_LABEL)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        return existing
            .as_slice()
            .try_into()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
    }
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    keystore
        .store_key(COSMETICS_WEBHOOK_SECRET_LABEL, &key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(key)
}

/// Extracts and verifies the [`WEBHOOK_SIGNATURE_HEADER`] against
/// `purchase_id`, rejecting with `401` if it's missing, malformed, or
/// doesn't match.
fn verify_webhook_signature(
    state: &AppState,
    headers: &HeaderMap,
    purchase_id: &str,
) -> Result<(), StatusCode> {
    let secret = load_or_create_webhook_secret(state)?;
    let signature = headers
        .get(WEBHOOK_SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|hex_sig| hex::decode(hex_sig).ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if bh_crypto::webhook::verify(&secret, purchase_id.as_bytes(), &signature) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

fn status_for(err: StorageError) -> StatusCode {
    match err {
        StorageError::NotFound => StatusCode::NOT_FOUND,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Seeds the "Event Horizon" launch catalog if it isn't already there.
/// Idempotent (`upsert_catalog_item` keys on `item_id`), so calling this on
/// every daemon startup/profile activation is safe.
pub fn seed_default_catalog(payments_db: &PaymentsDatabase) -> Result<(), StorageError> {
    let items = [
        CosmeticCatalogItem {
            item_id: "banner-event-horizon".into(),
            kind: CosmeticKind::Banner,
            name: "Event Horizon".into(),
            description: Some("The default monochrome banner, in case you ever unequip it.".into()),
            asset_ref: "banners/event-horizon.svg".into(),
            price_asset: CryptoAsset::Xmr,
            price_amount: "0.005".into(),
            active: true,
        },
        CosmeticCatalogItem {
            item_id: "theme-void".into(),
            kind: CosmeticKind::Theme,
            name: "Void".into(),
            description: Some("Deeper blacks, no accent color.".into()),
            asset_ref: "themes/void.json".into(),
            price_asset: CryptoAsset::Xmr,
            price_amount: "0.01".into(),
            active: true,
        },
        CosmeticCatalogItem {
            item_id: "badge-early-orbit".into(),
            kind: CosmeticKind::Badge,
            name: "Early Orbit".into(),
            description: Some("Shown next to your name in conversations.".into()),
            asset_ref: "badges/early-orbit.svg".into(),
            price_asset: CryptoAsset::Btc,
            price_amount: "0.00015".into(),
            active: true,
        },
        CosmeticCatalogItem {
            item_id: "theme-solar-flare".into(),
            kind: CosmeticKind::Theme,
            name: "Solar Flare".into(),
            description: Some("A warm amber-on-black variant of the default theme.".into()),
            asset_ref: "themes/solar-flare.json".into(),
            price_asset: CryptoAsset::Xmr,
            price_amount: "0.01".into(),
            active: true,
        },
        CosmeticCatalogItem {
            item_id: STICKER_PACK_NEBULA.into(),
            kind: CosmeticKind::StickerPack,
            name: "Nebula Stickers".into(),
            description: Some("A small pack of nebula-themed stickers for chat.".into()),
            asset_ref: "stickers/nebula/pack.json".into(),
            price_asset: CryptoAsset::Xmr,
            price_amount: "0.004".into(),
            active: true,
        },
        CosmeticCatalogItem {
            item_id: STICKER_PACK_ORBIT.into(),
            kind: CosmeticKind::StickerPack,
            name: "Orbit Stickers".into(),
            description: Some("A small pack of orbit-themed stickers for chat.".into()),
            asset_ref: "stickers/orbit/pack.json".into(),
            price_asset: CryptoAsset::Btc,
            price_amount: "0.00008".into(),
            active: true,
        },
    ];
    for item in items {
        payments_db.upsert_catalog_item(&item)?;
    }
    Ok(())
}

/// Catalog `item_id`s for the two launch sticker packs — shared between
/// `seed_default_catalog` (so they exist as purchasable
/// `CosmeticKind::StickerPack` items) and `STICKER_PACKS` below (so their
/// contents can be validated/listed) without repeating the string.
const STICKER_PACK_NEBULA: &str = "sticker-pack-nebula";
const STICKER_PACK_ORBIT: &str = "sticker-pack-orbit";

/// Static definition of which sticker ids exist inside each purchasable
/// sticker-pack catalog item, plus a short human label for each. This is
/// asset metadata, not stored in either database — there is no real
/// sticker-asset pipeline yet, so it lives in code, same spirit as the
/// catalog seed above.
const STICKER_PACKS: &[(&str, &[(&str, &str)])] = &[
    (
        STICKER_PACK_NEBULA,
        &[
            ("nebula-wave", "Nebula Wave"),
            ("nebula-heart", "Nebula Heart"),
            ("nebula-spark", "Nebula Spark"),
        ],
    ),
    (
        STICKER_PACK_ORBIT,
        &[
            ("orbit-thumbsup", "Orbit Thumbs Up"),
            ("orbit-wave", "Orbit Wave"),
        ],
    ),
];

/// Looks up which pack (if any) a given `sticker_id` belongs to. Used by
/// `crates/bh-api/src/stickers.rs` to validate that a sticker a client
/// wants to send is a real sticker inside a real pack — never trusted as a
/// bare string from the request — before checking whether this profile
/// owns that pack.
pub fn pack_for_sticker(sticker_id: &str) -> Option<&'static str> {
    STICKER_PACKS.iter().find_map(|(pack_item_id, stickers)| {
        stickers
            .iter()
            .any(|(id, _)| *id == sticker_id)
            .then_some(*pack_item_id)
    })
}

#[derive(Serialize)]
pub struct StickerDef {
    pub sticker_id: &'static str,
    pub label: &'static str,
}

#[derive(Serialize)]
pub struct StickerPackDef {
    pub pack_item_id: &'static str,
    pub stickers: Vec<StickerDef>,
}

/// Lists every known sticker pack's contents (id + label per sticker),
/// regardless of catalog `active` status or ownership — the composer's
/// sticker picker cross-references this against `GET /cosmetics/inventory`
/// itself to decide which packs to actually show as sendable.
pub async fn list_sticker_packs() -> Json<Vec<StickerPackDef>> {
    Json(
        STICKER_PACKS
            .iter()
            .map(|(pack_item_id, stickers)| StickerPackDef {
                pack_item_id,
                stickers: stickers
                    .iter()
                    .map(|(sticker_id, label)| StickerDef { sticker_id, label })
                    .collect(),
            })
            .collect(),
    )
}

pub async fn list_catalog(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<CosmeticCatalogItem>>, StatusCode> {
    state
        .payments_db()
        .list_catalog(true)
        .map(Json)
        .map_err(status_for)
}

pub async fn list_inventory(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<CosmeticInventoryItem>>, StatusCode> {
    state.db().list_inventory().map(Json).map_err(status_for)
}

pub async fn list_equipped(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<EquippedCosmetic>>, StatusCode> {
    state.db().list_equipped().map(Json).map_err(status_for)
}

#[derive(Deserialize)]
pub struct EquipRequest {
    pub kind: CosmeticKind,
    pub item_id: String,
}

/// Fails with 404 if this profile's inventory doesn't own `item_id` in
/// that slot — see `bh_storage::cosmetics::equip_cosmetic`.
pub async fn equip(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EquipRequest>,
) -> StatusCode {
    match state.db().equip_cosmetic(req.kind, &req.item_id, now()) {
        Ok(()) => StatusCode::OK,
        Err(err) => status_for(err),
    }
}

pub async fn unequip(
    State(state): State<Arc<AppState>>,
    Path(kind): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let kind = CosmeticKind::parse(&kind).ok_or(StatusCode::BAD_REQUEST)?;
    state
        .db()
        .unequip_cosmetic(kind)
        .map(|()| StatusCode::OK)
        .map_err(status_for)
}

#[derive(Deserialize)]
pub struct CreatePurchaseRequest {
    pub item_id: String,
    /// The invoice BTCPay issued for this purchase — supplied by the
    /// caller today only because the BTCPay HTTP client isn't wired in
    /// yet; see the module doc.
    pub invoice_id: String,
}

/// Price/asset are always read from the catalog, never trusted from the
/// request — the caller only gets to say *what* it wants to buy and *which*
/// invoice it's paying against, not *how much* that costs.
pub async fn create_purchase(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreatePurchaseRequest>,
) -> Result<Json<Purchase>, StatusCode> {
    let payments_db = state.payments_db();
    let item = payments_db
        .get_catalog_item(&req.item_id)
        .map_err(status_for)?
        .filter(|item| item.active)
        .ok_or(StatusCode::NOT_FOUND)?;

    payments_db
        .create_purchase(
            &item.item_id,
            &req.invoice_id,
            item.price_asset,
            &item.price_amount,
            now(),
        )
        .map(Json)
        .map_err(status_for)
}

#[derive(Serialize)]
pub struct MarkPaidResponse {
    pub purchase: Purchase,
    pub entitlement_token: String,
}

/// Stand-in for BTCPay's payment-confirmed webhook — see the module doc.
/// Requires a valid [`WEBHOOK_SIGNATURE_HEADER`]; anonymous localhost
/// access alone is no longer enough to grant a cosmetic.
/// Safe to call more than once for the same `purchase_id`: if it was
/// already marked paid (e.g. a previous call minted the token but crashed
/// before granting it), this reuses the existing token rather than trying
/// to mint a second one, and `grant_cosmetic` is itself idempotent on that
/// token — so replaying this after a partial failure never double-credits.
pub async fn mark_purchase_paid(
    State(state): State<Arc<AppState>>,
    Path(purchase_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<MarkPaidResponse>, StatusCode> {
    verify_webhook_signature(&state, &headers, &purchase_id)?;

    let payments_db = state.payments_db();
    let purchase = payments_db
        .get_purchase(&purchase_id)
        .map_err(status_for)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let item = payments_db
        .get_catalog_item(&purchase.item_id)
        .map_err(status_for)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let entitlement_token = match purchase.entitlement_token {
        Some(token) => token,
        None => payments_db
            .mark_purchase_paid(&purchase_id, now())
            .map_err(status_for)?,
    };

    state
        .db()
        .grant_cosmetic(&entitlement_token, &item.item_id, item.kind, now())
        .map_err(status_for)?;

    let purchase = payments_db
        .get_purchase(&purchase_id)
        .map_err(status_for)?
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(MarkPaidResponse {
        purchase,
        entitlement_token,
    }))
}
