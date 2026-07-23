//! Signed record an identity publishes (via `bh-network`'s
//! `push_relay_directory`, keyed by `recipient_key_hash` like a
//! [`crate::ratchet::PreKeyBundle`]) so a contact's daemon can learn *this*
//! identity's opt-in push-relay base URL and opaque wake token, and call
//! `POST {relay_url}/wake/{token}` after successfully delivering a message
//! to this identity's mailbox (`docs/SPEC.md` §5.6, `crates/bh-push-relay`).
//!
//! Unlike a `PreKeyBundle`, a bare DHT record here would have no built-in
//! authenticity: any node answering the `get_record` lookup could otherwise
//! substitute an attacker-chosen `relay_url`, making the *fetching* peer's
//! daemon issue an HTTP request to a URL it never actually agreed to (a real
//! SSRF surface, not just a theoretical one). Signing with the publishing
//! identity's own signing key — the same key a contact already trusts via
//! X3DH/safety numbers — and verifying against it on fetch closes that gap
//! without any new trust bootstrap.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::identity::IdentityKeyPair;
use crate::CryptoError;

/// Signed pointer to this identity's push-relay registration. See module
/// doc for why the signature exists at all.
pub struct PushRelayRecord {
    pub relay_url: String,
    pub token: String,
    pub signature: Signature,
}

/// Length-prefixes `relay_url` and `token` before concatenating them, so
/// the signed message is unambiguous — a bare concatenation would let
/// `("ab", "c")` and `("a", "bc")` sign identically.
fn signed_message(relay_url: &str, token: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + relay_url.len() + 4 + token.len());
    out.extend_from_slice(&(relay_url.len() as u32).to_be_bytes());
    out.extend_from_slice(relay_url.as_bytes());
    out.extend_from_slice(&(token.len() as u32).to_be_bytes());
    out.extend_from_slice(token.as_bytes());
    out
}

fn read_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, CryptoError> {
    let slice = bytes
        .get(*offset..*offset + 4)
        .ok_or(CryptoError::Malformed(
            "push-relay record: truncated length",
        ))?;
    *offset += 4;
    Ok(u32::from_be_bytes(
        slice.try_into().expect("checked length"),
    ))
}

fn read_string(bytes: &[u8], offset: &mut usize) -> Result<String, CryptoError> {
    let len = read_u32(bytes, offset)? as usize;
    let slice = bytes
        .get(*offset..*offset + len)
        .ok_or(CryptoError::Malformed(
            "push-relay record: truncated string",
        ))?;
    *offset += len;
    String::from_utf8(slice.to_vec())
        .map_err(|_| CryptoError::Malformed("push-relay record: invalid utf-8"))
}

impl PushRelayRecord {
    pub fn sign(identity: &IdentityKeyPair, relay_url: String, token: String) -> Self {
        let signature = identity.sign(&signed_message(&relay_url, &token));
        Self {
            relay_url,
            token,
            signature,
        }
    }

    /// Verifies this record's signature against `signing_key` — the
    /// signing-key half of the already-locally-trusted
    /// `Contact::identity_public_key` this record's publisher is claimed
    /// to be. Returns `false` for a tampered `relay_url`/`token`, or one
    /// signed by a different identity.
    pub fn verify(&self, signing_key: &VerifyingKey) -> bool {
        IdentityKeyPair::verify(
            signing_key,
            &signed_message(&self.relay_url, &self.token),
            &self.signature,
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = signed_message(&self.relay_url, &self.token);
        out.extend_from_slice(&self.signature.to_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut offset = 0;
        let relay_url = read_string(bytes, &mut offset)?;
        let token = read_string(bytes, &mut offset)?;
        let sig_bytes = bytes
            .get(offset..offset + 64)
            .ok_or(CryptoError::Malformed(
                "push-relay record: truncated signature",
            ))?;
        let signature = Signature::from_bytes(&sig_bytes.try_into().expect("checked length"));
        Ok(Self {
            relay_url,
            token,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_signed_by_an_identity_verifies_against_its_own_public_key() {
        let identity = IdentityKeyPair::generate().unwrap();
        let record = PushRelayRecord::sign(
            &identity,
            "https://relay.example".to_string(),
            "deadbeef".to_string(),
        );
        assert!(record.verify(&identity.public_signing_key()));
    }

    #[test]
    fn a_record_signed_by_a_different_identity_fails_to_verify() {
        let identity = IdentityKeyPair::generate().unwrap();
        let other = IdentityKeyPair::generate().unwrap();
        let record = PushRelayRecord::sign(
            &identity,
            "https://relay.example".to_string(),
            "deadbeef".to_string(),
        );
        assert!(!record.verify(&other.public_signing_key()));
    }

    #[test]
    fn a_tampered_relay_url_fails_to_verify_after_a_round_trip() {
        let identity = IdentityKeyPair::generate().unwrap();
        let record = PushRelayRecord::sign(
            &identity,
            "https://relay.example".to_string(),
            "deadbeef".to_string(),
        );
        let mut tampered = PushRelayRecord::from_bytes(&record.to_bytes()).unwrap();
        tampered.relay_url = "https://evil.example".to_string();
        assert!(!tampered.verify(&identity.public_signing_key()));
    }

    #[test]
    fn a_tampered_token_fails_to_verify_after_a_round_trip() {
        let identity = IdentityKeyPair::generate().unwrap();
        let record = PushRelayRecord::sign(
            &identity,
            "https://relay.example".to_string(),
            "deadbeef".to_string(),
        );
        let mut tampered = PushRelayRecord::from_bytes(&record.to_bytes()).unwrap();
        tampered.token = "cafebabe".to_string();
        assert!(!tampered.verify(&identity.public_signing_key()));
    }

    #[test]
    fn round_trips_through_bytes() {
        let identity = IdentityKeyPair::generate().unwrap();
        let record = PushRelayRecord::sign(
            &identity,
            "https://relay.example".to_string(),
            "deadbeef".to_string(),
        );
        let decoded = PushRelayRecord::from_bytes(&record.to_bytes()).unwrap();
        assert_eq!(decoded.relay_url, record.relay_url);
        assert_eq!(decoded.token, record.token);
        assert!(decoded.verify(&identity.public_signing_key()));
    }
}
