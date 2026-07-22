//! In-chat crypto payment requests (SPEC.md §12/§15, "option A"): the app
//! only exchanges an address/amount/memo as an encrypted chat message.
//! There is no custody and no blockchain watching anywhere in this module
//! — settlement happens wallet-to-wallet, entirely outside Blackhole, and
//! "paid" is only ever a manual local flag. This is what keeps the feature
//! outside SPEC.md §12's payments/messaging database isolation requirement:
//! it never touches payment infrastructure in the first place.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use bh_storage::models::{Message, PaymentAsset, PaymentRequest};
use serde::{Deserialize, Serialize};

use crate::AppState;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

fn to_crypto_asset(asset: PaymentAsset) -> bh_crypto::payment_address::Asset {
    match asset {
        PaymentAsset::Xmr => bh_crypto::payment_address::Asset::Xmr,
        PaymentAsset::Btc => bh_crypto::payment_address::Asset::Btc,
        PaymentAsset::Eth => bh_crypto::payment_address::Asset::Eth,
    }
}

/// The API-facing view of a payment request: the stored row plus a
/// derived, address-only "open in wallet" QR — never persisted, computed
/// fresh from `address`/`asset` each time, same pattern as
/// `invites`/`safety_number`'s `qr_svg` fields.
#[derive(Serialize)]
pub struct PaymentRequestView {
    #[serde(flatten)]
    pub payment_request: PaymentRequest,
    pub privacy_label: &'static str,
    pub qr_svg: String,
}

fn to_view(payment_request: PaymentRequest) -> Result<PaymentRequestView, StatusCode> {
    let uri = format!(
        "{}:{}",
        payment_request.asset.uri_scheme(),
        payment_request.address
    );
    let qr_svg = bh_crypto::qr::to_svg(&uri).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(PaymentRequestView {
        privacy_label: payment_request.asset.privacy_label(),
        payment_request,
        qr_svg,
    })
}

#[derive(Deserialize)]
pub struct CreatePaymentRequestRequest {
    pub asset: PaymentAsset,
    pub address: String,
    /// Informational only — never encoded into the wallet deep link, so a
    /// unit-conversion bug here can't silently misstate what's owed.
    pub amount: Option<String>,
    pub memo: Option<String>,
}

#[derive(Serialize)]
pub struct CreatePaymentRequestResponse {
    pub message: Message,
    pub payment_request: PaymentRequestView,
}

pub async fn create_payment_request(
    State(state): State<Arc<AppState>>,
    Path(conversation_id): Path<String>,
    Json(req): Json<CreatePaymentRequestRequest>,
) -> Result<Json<CreatePaymentRequestResponse>, StatusCode> {
    bh_crypto::payment_address::validate_address(to_crypto_asset(req.asset), &req.address)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if let Some(amount) = &req.amount {
        bh_crypto::payment_address::validate_amount(amount).map_err(|_| StatusCode::BAD_REQUEST)?;
    }

    let sent_at = now();
    let expires_at = state
        .db()
        .compute_message_expiry(&conversation_id, sent_at)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let message = Message {
        message_id: uuid::Uuid::new_v4().to_string(),
        conversation_id,
        sender_contact_id: None,
        body: req.memo.clone(),
        sent_at,
        received_at: None,
        expires_at,
        deleted_at: None,
        reply_to_message_id: None,
        edited_at: None,
    };
    state
        .db()
        .insert_message(&message)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let payment_request = PaymentRequest {
        message_id: message.message_id.clone(),
        asset: req.asset,
        address: req.address,
        amount: req.amount,
        memo: req.memo,
        paid_at: None,
    };
    state
        .db()
        .insert_payment_request(&payment_request)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(CreatePaymentRequestResponse {
        message,
        payment_request: to_view(payment_request)?,
    }))
}

pub async fn get_payment_request(
    State(state): State<Arc<AppState>>,
    Path(message_id): Path<String>,
) -> Result<Json<PaymentRequestView>, StatusCode> {
    let payment_request = state
        .db()
        .get_payment_request(&message_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(to_view(payment_request)?))
}

/// Requires an explicit out-of-band confirmation before marking a payment
/// request paid: the server refuses to flip the flag on a bare POST, so a
/// direct API caller can't bypass the confirmation step the UI presents
/// (THREAT_MODEL.md §3.11/§4 item 13). This does not verify the payment in
/// any way — see the module doc comment — it only ensures the local "paid"
/// flag can't be set without the caller affirmatively asserting they
/// checked the address out of band.
#[derive(Deserialize)]
pub struct ConfirmPaymentPaidRequest {
    pub confirmed_out_of_band: bool,
}

pub async fn mark_payment_request_paid(
    State(state): State<Arc<AppState>>,
    Path(message_id): Path<String>,
    Json(req): Json<ConfirmPaymentPaidRequest>,
) -> StatusCode {
    if !req.confirmed_out_of_band {
        return StatusCode::PRECONDITION_FAILED;
    }
    match state
        .db()
        .set_payment_request_paid(&message_id, Some(now()))
    {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

pub async fn unmark_payment_request_paid(
    State(state): State<Arc<AppState>>,
    Path(message_id): Path<String>,
) -> StatusCode {
    match state.db().set_payment_request_paid(&message_id, None) {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
