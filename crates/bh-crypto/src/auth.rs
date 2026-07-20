//! Local authentication gating access to the daemon itself: passkeys/FIDO2
//! as the primary method, TOTP as fallback, deliberately no SMS (SPEC.md
//! §3). There is no account server here — the daemon is its own relying
//! party for WebAuthn, and TOTP has no server component at all.

use totp_rs::{Algorithm, Secret, TOTP};
use webauthn_rs::prelude::*;

use crate::CryptoError;

impl From<WebauthnError> for CryptoError {
    fn from(_: WebauthnError) -> Self {
        CryptoError::InvalidSignature
    }
}

// ---------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------

/// A TOTP secret bound to one account. Entirely local — RFC 6238, no
/// server round-trip.
pub struct TotpSecret {
    totp: TOTP,
}

impl TotpSecret {
    /// Generates a fresh random secret for enrollment.
    pub fn generate(account_name: &str, issuer: &str) -> Result<Self, CryptoError> {
        let secret = Secret::generate_secret();
        Self::from_secret(secret, account_name, issuer)
    }

    /// Reconstructs a `TotpSecret` from a previously stored base32 secret
    /// (e.g. loaded back out of `bh-storage`).
    pub fn from_base32(
        base32_secret: &str,
        account_name: &str,
        issuer: &str,
    ) -> Result<Self, CryptoError> {
        Self::from_secret(
            Secret::Encoded(base32_secret.to_string()),
            account_name,
            issuer,
        )
    }

    fn from_secret(secret: Secret, account_name: &str, issuer: &str) -> Result<Self, CryptoError> {
        let totp = TOTP::new(
            Algorithm::SHA1, // widest authenticator-app compatibility
            6,
            1,
            30,
            secret.to_bytes().map_err(|_| CryptoError::KeyDerivation)?,
            Some(issuer.to_string()),
            account_name.to_string(),
        )
        .map_err(|_| CryptoError::KeyDerivation)?;
        Ok(Self { totp })
    }

    /// The base32 secret to persist (SQLCipher-encrypted at rest via
    /// `bh-storage` — never shown again after enrollment except as a QR).
    pub fn base32_secret(&self) -> String {
        self.totp.get_secret_base32()
    }

    /// `otpauth://` URI for rendering an enrollment QR code.
    pub fn provisioning_uri(&self) -> String {
        self.totp.get_url()
    }

    /// Verifies a 6-digit code against the current time step (and, per
    /// `totp-rs` defaults, one step of clock skew tolerance either side).
    pub fn verify(&self, code: &str) -> bool {
        self.totp.check_current(code).unwrap_or(false)
    }
}

// ---------------------------------------------------------------------
// Passkeys / FIDO2
// ---------------------------------------------------------------------

/// Wraps a `webauthn-rs` relying party for the local daemon. The actual
/// authenticator ceremony (Touch ID / Windows Hello / a FIDO2 security
/// key) is driven by the *real* WebAuthn API in the Tauri webview — modern
/// WKWebView/WebView2 implement `navigator.credentials.create()/get()`
/// natively — the resulting attestation/assertion JSON is what gets passed
/// into `finish_registration`/`finish_authentication` here.
///
/// `rp_id`/`rp_origin` must match whatever origin the Tauri webview
/// actually reports to WebAuthn, which is platform-dependent (verified
/// manually on a real device, not something this crate can confirm).
pub struct PasskeyManager {
    webauthn: Webauthn,
}

impl PasskeyManager {
    pub fn new(rp_id: &str, rp_origin: &Url) -> Result<Self, CryptoError> {
        let webauthn = WebauthnBuilder::new(rp_id, rp_origin)
            .map_err(|_| CryptoError::KeyDerivation)?
            .build()
            .map_err(|_| CryptoError::KeyDerivation)?;
        Ok(Self { webauthn })
    }

    pub fn start_registration(
        &self,
        user_id: Uuid,
        username: &str,
        display_name: &str,
        exclude_credentials: Option<Vec<CredentialID>>,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), CryptoError> {
        self.webauthn
            .start_passkey_registration(user_id, username, display_name, exclude_credentials)
            .map_err(Into::into)
    }

    pub fn finish_registration(
        &self,
        response: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> Result<Passkey, CryptoError> {
        self.webauthn
            .finish_passkey_registration(response, state)
            .map_err(Into::into)
    }

    pub fn start_authentication(
        &self,
        known_credentials: &[Passkey],
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication), CryptoError> {
        self.webauthn
            .start_passkey_authentication(known_credentials)
            .map_err(Into::into)
    }

    pub fn finish_authentication(
        &self,
        response: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> Result<AuthenticationResult, CryptoError> {
        self.webauthn
            .finish_passkey_authentication(response, state)
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_generated_code_verifies() {
        let secret = TotpSecret::generate("alice", "Blackhole").unwrap();
        let code = secret.totp.generate_current().unwrap();
        assert!(secret.verify(&code));
    }

    #[test]
    fn totp_roundtrips_through_base32() {
        let original = TotpSecret::generate("alice", "Blackhole").unwrap();
        let code = original.totp.generate_current().unwrap();

        let restored =
            TotpSecret::from_base32(&original.base32_secret(), "alice", "Blackhole").unwrap();
        assert!(restored.verify(&code));
    }

    #[test]
    fn totp_provisioning_uri_is_well_formed() {
        let secret = TotpSecret::generate("alice", "Blackhole").unwrap();
        let uri = secret.provisioning_uri();
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("Blackhole"));
    }

    #[test]
    fn wrong_totp_code_is_rejected() {
        let secret = TotpSecret::generate("alice", "Blackhole").unwrap();
        // A fixed wrong code will only ever collide with the real one by
        // chance (1 in a million); good enough for a unit test.
        assert!(!secret.verify("019283"));
    }

    #[test]
    fn passkey_manager_builds_and_starts_a_registration_challenge() {
        // This exercises everything that doesn't require a real
        // authenticator: RP configuration and challenge generation. Full
        // registration/authentication round-trips need a real platform
        // authenticator (Touch ID/Windows Hello/security key) driving the
        // Tauri webview's WebAuthn API and can't be faked in a headless
        // test — that path needs manual verification on real hardware.
        let rp_origin = Url::parse("http://localhost:47853").unwrap();
        let mgr = PasskeyManager::new("localhost", &rp_origin).unwrap();

        let (challenge, _state) = mgr
            .start_registration(Uuid::new_v4(), "alice", "Alice", None)
            .unwrap();
        assert_eq!(challenge.public_key.rp.id, "localhost");
    }
}
