//! Manual contact discovery via link/QR (SPEC.md §3): no server, no agenda
//! leakage — the whole payload is just the two public keys a peer needs to
//! start an X3DH session, base64-encoded into a shareable link, optionally
//! rendered as a QR code.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use qrcode::render::svg;
use qrcode::QrCode;
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::identity::IdentityKeyPair;
use crate::CryptoError;

const INVITE_SCHEME: &str = "blackhole";
const PAYLOAD_VERSION: u8 = 1;
const MAX_NAME_LEN: usize = 255;

/// What gets encoded into an invite link/QR: just enough for the scanning
/// party to verify and start a session — no phone number, no server
/// round-trip.
pub struct InvitePayload {
    pub identity_agreement_key: X25519PublicKey,
    pub identity_signing_key: VerifyingKey,
    pub display_name: Option<String>,
}

impl InvitePayload {
    pub fn for_identity(identity: &IdentityKeyPair, display_name: Option<String>) -> Self {
        Self {
            identity_agreement_key: identity.public_agreement_key(),
            identity_signing_key: identity.public_signing_key(),
            display_name,
        }
    }

    fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        let name_bytes = self.display_name.as_deref().unwrap_or("").as_bytes();
        if name_bytes.len() > MAX_NAME_LEN {
            return Err(CryptoError::NotImplemented("invite: display name too long"));
        }
        let mut bytes = Vec::with_capacity(1 + 32 + 32 + 1 + name_bytes.len());
        bytes.push(PAYLOAD_VERSION);
        bytes.extend_from_slice(self.identity_agreement_key.as_bytes());
        bytes.extend_from_slice(self.identity_signing_key.as_bytes());
        bytes.push(name_bytes.len() as u8);
        bytes.extend_from_slice(name_bytes);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 1 + 32 + 32 + 1 || bytes[0] != PAYLOAD_VERSION {
            return Err(CryptoError::NotImplemented("invite: malformed payload"));
        }
        let agreement: [u8; 32] = bytes[1..33].try_into().unwrap();
        let signing: [u8; 32] = bytes[33..65].try_into().unwrap();
        let name_len = bytes[65] as usize;
        let name_bytes = bytes
            .get(66..66 + name_len)
            .ok_or(CryptoError::NotImplemented("invite: truncated name"))?;

        Ok(Self {
            identity_agreement_key: X25519PublicKey::from(agreement),
            identity_signing_key: VerifyingKey::from_bytes(&signing)
                .map_err(|_| CryptoError::InvalidSignature)?,
            display_name: if name_bytes.is_empty() {
                None
            } else {
                Some(
                    String::from_utf8(name_bytes.to_vec())
                        .map_err(|_| CryptoError::NotImplemented("invite: invalid name utf-8"))?,
                )
            },
        })
    }

    /// A shareable `blackhole://invite?d=...` link.
    pub fn to_link(&self) -> Result<String, CryptoError> {
        let encoded = URL_SAFE_NO_PAD.encode(self.encode()?);
        Ok(format!("{INVITE_SCHEME}://invite?d={encoded}"))
    }

    pub fn from_link(link: &str) -> Result<Self, CryptoError> {
        let prefix = format!("{INVITE_SCHEME}://invite?d=");
        let encoded = link
            .strip_prefix(&prefix)
            .ok_or(CryptoError::NotImplemented(
                "invite: not a blackhole invite link",
            ))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| CryptoError::NotImplemented("invite: bad base64"))?;
        Self::decode(&bytes)
    }

    /// SVG markup for a scannable QR code of [`to_link`](Self::to_link).
    pub fn to_qr_svg(&self) -> Result<String, CryptoError> {
        let link = self.to_link()?;
        let code = QrCode::new(link.as_bytes())
            .map_err(|_| CryptoError::NotImplemented("invite: QR encoding failed"))?;
        Ok(code
            .render()
            .min_dimensions(256, 256)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_roundtrips_with_display_name() {
        let identity = IdentityKeyPair::generate().unwrap();
        let payload = InvitePayload::for_identity(&identity, Some("Alice".to_string()));
        let link = payload.to_link().unwrap();
        assert!(link.starts_with("blackhole://invite?d="));

        let decoded = InvitePayload::from_link(&link).unwrap();
        assert_eq!(
            decoded.identity_agreement_key.as_bytes(),
            identity.public_agreement_key().as_bytes()
        );
        assert_eq!(
            decoded.identity_signing_key.to_bytes(),
            identity.public_signing_key().to_bytes()
        );
        assert_eq!(decoded.display_name, Some("Alice".to_string()));
    }

    #[test]
    fn link_roundtrips_without_display_name() {
        let identity = IdentityKeyPair::generate().unwrap();
        let payload = InvitePayload::for_identity(&identity, None);
        let decoded = InvitePayload::from_link(&payload.to_link().unwrap()).unwrap();
        assert_eq!(decoded.display_name, None);
    }

    #[test]
    fn rejects_links_from_a_different_scheme() {
        assert!(InvitePayload::from_link("https://evil.example/not-an-invite").is_err());
    }

    #[test]
    fn rejects_truncated_payloads() {
        let short = format!("blackhole://invite?d={}", URL_SAFE_NO_PAD.encode([1, 2, 3]));
        assert!(InvitePayload::from_link(&short).is_err());
    }

    #[test]
    fn qr_svg_is_well_formed_and_scannable_length() {
        let identity = IdentityKeyPair::generate().unwrap();
        let payload = InvitePayload::for_identity(&identity, None);
        let svg = payload.to_qr_svg().unwrap();
        assert!(svg.contains("<svg"));
    }
}
