//! Safety-number verification: a human-comparable fingerprint of a
//! contact's identity keys, so two people can confirm out-of-band (in
//! person, over a trusted channel) that no one is impersonating either
//! side of a session — the standard mitigation for "the recipient already
//! knowing the sender's identity key via prior contact verification" that
//! `bh-network::sealed_sender` and X3DH otherwise just assume (SPEC.md §3).
//!
//! This is the same style of construction Signal's own safety numbers use
//! (iterated SHA-512 over each identity's public keys, combined and sorted
//! so both sides compute an identical number regardless of who's "Alice"),
//! reimplemented here from the published algorithm rather than pulled in as
//! a dependency — composition of an audited primitive (SHA-512), not new
//! cryptography, per `docs/SPEC.md` §2.2.

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha512};
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::CryptoError;

const FINGERPRINT_VERSION: u8 = 1;
const ITERATIONS: u32 = 5200;
const DIGITS_PER_IDENTITY: usize = 30;

/// Both public keys that make up one identity, concatenated — agreement
/// key first, then signing key, matching the order they're normally passed
/// around together (e.g. `invite::InvitePayload`).
fn identity_bytes(agreement: &X25519PublicKey, signing: &VerifyingKey) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(agreement.as_bytes());
    bytes[32..].copy_from_slice(signing.as_bytes());
    bytes
}

fn iterated_digest(identity: &[u8; 64]) -> [u8; 64] {
    let mut state: [u8; 64] = {
        let mut hasher = Sha512::new();
        hasher.update([FINGERPRINT_VERSION]);
        hasher.update(identity);
        hasher.finalize().into()
    };
    for _ in 0..ITERATIONS {
        let mut hasher = Sha512::new();
        hasher.update(state);
        hasher.update(identity);
        state = hasher.finalize().into();
    }
    state
}

/// Renders a 64-byte digest as a 30-digit decimal string: six 5-byte
/// chunks, each reduced mod 100000 and zero-padded to 5 digits.
fn digest_to_digits(digest: &[u8; 64]) -> String {
    let mut out = String::with_capacity(DIGITS_PER_IDENTITY);
    for chunk in digest[..30].chunks(5) {
        let mut buf = [0u8; 8];
        buf[3..8].copy_from_slice(chunk);
        let value = u64::from_be_bytes(buf) % 100_000;
        out.push_str(&format!("{value:05}"));
    }
    out
}

/// One identity's own 30-digit fingerprint, before combining with a peer's.
pub fn fingerprint_digits(agreement: &X25519PublicKey, signing: &VerifyingKey) -> String {
    digest_to_digits(&iterated_digest(&identity_bytes(agreement, signing)))
}

/// The 60-digit combined safety number for a pair of identities, displayed
/// as 12 groups of 5 digits. Sorting the two 30-digit halves before
/// concatenating means both participants compute the same string regardless
/// of which one calls this "self" vs "peer" — there's no fixed Alice/Bob
/// ordering to get wrong.
pub fn safety_number(
    my_agreement: &X25519PublicKey,
    my_signing: &VerifyingKey,
    their_agreement: &X25519PublicKey,
    their_signing: &VerifyingKey,
) -> String {
    let mut halves = [
        fingerprint_digits(my_agreement, my_signing),
        fingerprint_digits(their_agreement, their_signing),
    ];
    halves.sort();
    halves.concat()
}

/// Splits a 60-digit safety number into 12 groups of 5 for display, e.g.
/// `"12345 67890 ..."`.
pub fn format_grouped(digits: &str) -> String {
    digits
        .as_bytes()
        .chunks(5)
        .map(|c| std::str::from_utf8(c).expect("ascii digits"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// SVG QR code of the raw 60-digit safety number, for scan-to-compare
/// verification instead of manually reading digits aloud.
pub fn to_qr_svg(digits: &str) -> Result<String, CryptoError> {
    let code = qrcode::QrCode::new(digits.as_bytes())
        .map_err(|_| CryptoError::NotImplemented("safety_number: QR encoding failed"))?;
    Ok(code
        .render()
        .min_dimensions(256, 256)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKeyPair;

    #[test]
    fn safety_number_is_deterministic() {
        let alice = IdentityKeyPair::generate().unwrap();
        let bob = IdentityKeyPair::generate().unwrap();

        let a = safety_number(
            &alice.public_agreement_key(),
            &alice.public_signing_key(),
            &bob.public_agreement_key(),
            &bob.public_signing_key(),
        );
        let b = safety_number(
            &alice.public_agreement_key(),
            &alice.public_signing_key(),
            &bob.public_agreement_key(),
            &bob.public_signing_key(),
        );
        assert_eq!(a, b);
        assert_eq!(a.len(), 60);
    }

    #[test]
    fn safety_number_is_order_independent() {
        let alice = IdentityKeyPair::generate().unwrap();
        let bob = IdentityKeyPair::generate().unwrap();

        let from_alice_side = safety_number(
            &alice.public_agreement_key(),
            &alice.public_signing_key(),
            &bob.public_agreement_key(),
            &bob.public_signing_key(),
        );
        let from_bob_side = safety_number(
            &bob.public_agreement_key(),
            &bob.public_signing_key(),
            &alice.public_agreement_key(),
            &alice.public_signing_key(),
        );
        assert_eq!(from_alice_side, from_bob_side);
    }

    #[test]
    fn different_identities_give_different_numbers() {
        let alice = IdentityKeyPair::generate().unwrap();
        let bob = IdentityKeyPair::generate().unwrap();
        let mallory = IdentityKeyPair::generate().unwrap();

        let real = safety_number(
            &alice.public_agreement_key(),
            &alice.public_signing_key(),
            &bob.public_agreement_key(),
            &bob.public_signing_key(),
        );
        let impersonated = safety_number(
            &alice.public_agreement_key(),
            &alice.public_signing_key(),
            &mallory.public_agreement_key(),
            &mallory.public_signing_key(),
        );
        assert_ne!(real, impersonated);
    }

    #[test]
    fn grouped_formatting_splits_into_twelve_groups_of_five() {
        let alice = IdentityKeyPair::generate().unwrap();
        let bob = IdentityKeyPair::generate().unwrap();
        let digits = safety_number(
            &alice.public_agreement_key(),
            &alice.public_signing_key(),
            &bob.public_agreement_key(),
            &bob.public_signing_key(),
        );
        let grouped = format_grouped(&digits);
        assert_eq!(grouped.split(' ').count(), 12);
    }

    #[test]
    fn qr_svg_is_well_formed() {
        let alice = IdentityKeyPair::generate().unwrap();
        let bob = IdentityKeyPair::generate().unwrap();
        let digits = safety_number(
            &alice.public_agreement_key(),
            &alice.public_signing_key(),
            &bob.public_agreement_key(),
            &bob.public_signing_key(),
        );
        assert!(to_qr_svg(&digits).unwrap().contains("<svg"));
    }
}
