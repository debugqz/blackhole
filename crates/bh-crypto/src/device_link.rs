//! Multi-device linking (SPEC.md §4): scan a QR shown on an already-trusted
//! device, and transfer the account identity to the new device over a
//! channel encrypted end-to-end by an ephemeral ECDH key agreement — the
//! private key material never touches any server, encrypted or not.
//!
//! The new device also generates its own full [`IdentityKeyPair`] (not
//! just a signing key — see `device_identity`'s field doc), recorded (its
//! public half) in `bh-storage`'s `devices` table, so the "active
//! devices" panel and instant revocation (SPEC.md §4) have something to
//! actually distinguish and revoke — revoking a device stops trusting that
//! per-device identity, it does not (and cannot, since both devices hold
//! the same account identity) invalidate the shared identity key itself.
//! The *agreement* half of that same per-device identity is also what
//! lets a linked device be addressed on the real network at all
//! (`recipient_key_hash`/`prekey_directory`, same convention a `Contact`
//! already uses) — see `bh-api::device_sync`'s module doc.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::VerifyingKey;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

use crate::identity::IdentityKeyPair;
use crate::CryptoError;

const LINK_SCHEME_PREFIX: &str = "blackhole://link-device?k=";
const INFO_REQUEST: &[u8] = b"blackhole-device-link-request-v1";
const INFO_RESPONSE: &[u8] = b"blackhole-device-link-response-v1";

fn derive_key(shared: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, shared);
    let mut out = [0u8; 32];
    hkdf.expand(info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

fn aead_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    // A fixed nonce is safe here: `key` is single-use, derived fresh per
    // linking session via HKDF and never reused for a second message.
    cipher
        .encrypt(&Nonce::default(), plaintext)
        .expect("encryption with a freshly-derived key cannot fail")
}

fn aead_decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(&Nonce::default(), ciphertext)
        .map_err(|_| CryptoError::Decrypt)
}

/// The already-trusted device's side: shows a QR/link containing an
/// ephemeral public key for the new device to scan.
pub struct LinkingSession {
    ephemeral_secret: X25519Secret,
    ephemeral_public: X25519PublicKey,
    /// This primary's real `recipient_key_hash` — embedded in [`link`]
    /// so a genuinely separate daemon that scans the QR knows where to
    /// publish its `ProvisioningRequest`
    /// (`bh_network::device_link_relay::publish_request`) without any
    /// other out-of-band channel. Same-daemon callers that never touch
    /// the network don't need this to be *correct*, only present — see
    /// [`begin`](Self::begin)'s doc comment.
    primary_key_hash: [u8; 32],
}

impl LinkingSession {
    /// `primary_key_hash` is `bh_crypto::identity::recipient_key_hash`
    /// over this primary's real `identity_public_key` — the caller
    /// already has this identity loaded (it needs it moments later for
    /// [`accept`](Self::accept) too), so it's taken here rather than this
    /// module reaching into storage itself.
    pub fn begin(primary_key_hash: [u8; 32]) -> Self {
        let ephemeral_secret = X25519Secret::random();
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
        Self {
            ephemeral_secret,
            ephemeral_public,
            primary_key_hash,
        }
    }

    pub fn link(&self) -> String {
        let mut payload = self.ephemeral_public.as_bytes().to_vec();
        payload.extend_from_slice(&self.primary_key_hash);
        format!("{LINK_SCHEME_PREFIX}{}", URL_SAFE_NO_PAD.encode(payload))
    }

    /// Having received a [`ProvisioningRequest`] from the new device (out
    /// of band — e.g. relayed through the daemon once it scans the QR),
    /// derive the shared secret, decrypt it, and prepare the response that
    /// hands over the account identity. Returns the new device's own
    /// public identity bytes (`IdentityKeyPair::public_identity_bytes`'s
    /// 64-byte `signing || agreement` layout — not the shared account
    /// identity, its own per-device one) so the caller can record both
    /// halves, not just the signing key `Device.public_key` used to hold
    /// alone.
    pub fn accept(
        &self,
        request: &ProvisioningRequest,
        identity: &IdentityKeyPair,
    ) -> Result<([u8; 64], Vec<u8>), CryptoError> {
        let shared = self
            .ephemeral_secret
            .diffie_hellman(&request.new_device_ephemeral_public);
        let request_key = derive_key(shared.as_bytes(), INFO_REQUEST);
        let plaintext = aead_decrypt(&request_key, &request.ciphertext)?;
        let device_identity_public: [u8; 64] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::NotImplemented("device_link: malformed request"))?;
        // Validate the signing half really is a well-formed Ed25519 point
        // before trusting it as this device's identity.
        VerifyingKey::from_bytes(device_identity_public[..32].try_into().unwrap())
            .map_err(|_| CryptoError::InvalidSignature)?;

        let response_key = derive_key(shared.as_bytes(), INFO_RESPONSE);
        let response = aead_encrypt(&response_key, identity.export_bytes().as_slice());

        Ok((device_identity_public, response))
    }
}

/// Decodes a linking link into the primary's ephemeral public key and its
/// real `recipient_key_hash` (see [`LinkingSession::begin`]'s doc comment
/// on the latter).
pub fn parse_linking_link(link: &str) -> Result<(X25519PublicKey, [u8; 32]), CryptoError> {
    let encoded = link
        .strip_prefix(LINK_SCHEME_PREFIX)
        .ok_or(CryptoError::NotImplemented(
            "device_link: not a linking link",
        ))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| CryptoError::NotImplemented("device_link: bad base64"))?;
    if bytes.len() != 64 {
        return Err(CryptoError::NotImplemented("device_link: bad key length"));
    }
    let ephemeral_arr: [u8; 32] = bytes[..32].try_into().unwrap();
    let primary_key_hash: [u8; 32] = bytes[32..].try_into().unwrap();
    Ok((X25519PublicKey::from(ephemeral_arr), primary_key_hash))
}

/// What the new device sends back after scanning the primary's QR.
pub struct ProvisioningRequest {
    pub new_device_ephemeral_public: X25519PublicKey,
    pub ciphertext: Vec<u8>,
}

/// The new device's side of the exchange.
pub struct NewDevice {
    ephemeral_secret: X25519Secret,
    ephemeral_public: X25519PublicKey,
    /// This device's own long-term per-device identity — distinct from the
    /// shared account identity: the signing half is what gets recorded in
    /// `bh-storage`'s `devices` table as `Device.public_key` (unchanged
    /// from before this identity was widened past just a signing key), and
    /// the agreement half is new — it's what lets this device be addressed
    /// on the real network at all once linking completes (see module doc).
    pub device_identity: IdentityKeyPair,
    primary_ephemeral_public: X25519PublicKey,
    /// The primary's real identity key hash, decoded from the scanned
    /// link — where a genuinely separate daemon publishes its
    /// `ProvisioningRequest` (`bh_network::device_link_relay::
    /// publish_request`). See [`LinkingSession::begin`]'s doc comment.
    pub primary_key_hash: [u8; 32],
}

impl NewDevice {
    pub fn scan(primary_link: &str) -> Result<Self, CryptoError> {
        let (primary_ephemeral_public, primary_key_hash) = parse_linking_link(primary_link)?;
        let ephemeral_secret = X25519Secret::random();
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

        Ok(Self {
            ephemeral_secret,
            ephemeral_public,
            device_identity: IdentityKeyPair::generate()?,
            primary_ephemeral_public,
            primary_key_hash,
        })
    }

    /// This device's own ephemeral linking key — `recipient_key_hash`
    /// over these bytes is where the primary's response gets published
    /// (`bh_network::device_link_relay::publish_response`/
    /// `fetch_response`).
    pub fn ephemeral_public(&self) -> X25519PublicKey {
        self.ephemeral_public
    }

    pub fn provisioning_request(&self) -> ProvisioningRequest {
        let shared = self
            .ephemeral_secret
            .diffie_hellman(&self.primary_ephemeral_public);
        let request_key = derive_key(shared.as_bytes(), INFO_REQUEST);
        let ciphertext = aead_encrypt(&request_key, &self.device_identity.public_identity_bytes());
        ProvisioningRequest {
            new_device_ephemeral_public: self.ephemeral_public,
            ciphertext,
        }
    }

    /// Decrypts the primary device's response into the shared account
    /// identity, completing the link.
    pub fn accept_response(
        &self,
        response_ciphertext: &[u8],
    ) -> Result<IdentityKeyPair, CryptoError> {
        let shared = self
            .ephemeral_secret
            .diffie_hellman(&self.primary_ephemeral_public);
        let response_key = derive_key(shared.as_bytes(), INFO_RESPONSE);
        let plaintext = aead_decrypt(&response_key, response_ciphertext)?;
        let bytes: [u8; 64] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::NotImplemented("device_link: malformed identity payload"))?;
        IdentityKeyPair::import_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_linking_flow_transfers_the_shared_identity() {
        let primary_identity = IdentityKeyPair::generate().unwrap();
        let session = LinkingSession::begin(crate::identity::recipient_key_hash(
            &primary_identity.public_identity_bytes(),
        ));
        let link = session.link();

        let new_device = NewDevice::scan(&link).unwrap();
        let request = new_device.provisioning_request();

        let (registered_device_identity, response) =
            session.accept(&request, &primary_identity).unwrap();
        assert_eq!(
            registered_device_identity,
            new_device.device_identity.public_identity_bytes()
        );

        let linked_identity = new_device.accept_response(&response).unwrap();
        assert_eq!(
            linked_identity.public_agreement_key().as_bytes(),
            primary_identity.public_agreement_key().as_bytes()
        );
        assert_eq!(
            linked_identity.public_signing_key().to_bytes(),
            primary_identity.public_signing_key().to_bytes()
        );
    }

    #[test]
    fn rejects_a_response_decrypted_with_the_wrong_session() {
        let primary_identity = IdentityKeyPair::generate().unwrap();
        let session = LinkingSession::begin(crate::identity::recipient_key_hash(
            &primary_identity.public_identity_bytes(),
        ));
        let new_device = NewDevice::scan(&session.link()).unwrap();
        let request = new_device.provisioning_request();
        let (_key, response) = session.accept(&request, &primary_identity).unwrap();

        let unrelated_session = LinkingSession::begin(crate::identity::recipient_key_hash(
            &IdentityKeyPair::generate().unwrap().public_identity_bytes(),
        ));
        let unrelated_device = NewDevice::scan(&unrelated_session.link()).unwrap();
        assert!(unrelated_device.accept_response(&response).is_err());
    }

    #[test]
    fn rejects_malformed_linking_links() {
        assert!(parse_linking_link("not-a-link").is_err());
        assert!(parse_linking_link("blackhole://link-device?k=not-base64!!").is_err());
    }
}
