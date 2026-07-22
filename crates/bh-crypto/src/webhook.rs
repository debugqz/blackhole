//! Generic HMAC-SHA256 signing/verification for webhook-style callbacks —
//! used today to gate `bh-api::cosmetics::mark_purchase_paid` (a stand-in
//! for BTCPay's payment-confirmed webhook) behind proof the caller holds a
//! shared secret, not just localhost network access. See
//! docs/THREAT_MODEL.md.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Computes an HMAC-SHA256 signature over `payload` using `secret`.
pub fn sign(secret: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(payload);
    mac.finalize().into_bytes().to_vec()
}

/// Verifies `signature` against `payload` under `secret`. Uses
/// `Mac::verify_slice`, which compares in constant time rather than a
/// manual `==` that would leak timing information about how many leading
/// bytes matched.
pub fn verify(secret: &[u8], payload: &[u8], signature: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(payload);
    mac.verify_slice(signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_accepts_a_correct_signature() {
        let secret = b"shared-secret";
        let payload = b"purchase-123";
        let sig = sign(secret, payload);
        assert!(verify(secret, payload, &sig));
    }

    #[test]
    fn verify_rejects_a_tampered_payload() {
        let secret = b"shared-secret";
        let sig = sign(secret, b"purchase-123");
        assert!(!verify(secret, b"purchase-456", &sig));
    }

    #[test]
    fn verify_rejects_the_wrong_secret() {
        let payload = b"purchase-123";
        let sig = sign(b"secret-a", payload);
        assert!(!verify(b"secret-b", payload, &sig));
    }

    #[test]
    fn verify_rejects_a_truncated_signature() {
        let secret = b"shared-secret";
        let payload = b"purchase-123";
        let sig = sign(secret, payload);
        assert!(!verify(secret, payload, &sig[..sig.len() - 1]));
    }
}
