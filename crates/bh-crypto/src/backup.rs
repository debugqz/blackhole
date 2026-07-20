//! Encrypted local backups (SPEC.md §4): a passphrase only the user knows
//! derives the encryption key via Argon2id — nobody who obtains the backup
//! file, including us, can open it without that passphrase. What actually
//! goes *into* the plaintext payload (which contacts, sessions, etc. to
//! include) is a `bh-storage`/daemon concern layered on top; this module
//! only seals/opens an opaque byte blob.

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use crate::CryptoError;

const FORMAT_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

fn derive_key(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<[u8; 32], CryptoError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(key)
}

/// Encrypts `plaintext` under a key derived from `passphrase`. Layout:
/// `version(1) || salt(16) || nonce(12) || ciphertext`. A fresh random
/// salt and nonce are generated per call, so backing up the same data
/// twice with the same passphrase produces unlinkable ciphertexts.
pub fn seal(passphrase: &str, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| CryptoError::Rng)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|_| CryptoError::Rng)?;

    let key = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(
            &Nonce::try_from(nonce_bytes.as_slice()).expect("12 bytes"),
            plaintext,
        )
        .map_err(|_| CryptoError::Encrypt)?;

    let mut out = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + ciphertext.len());
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts a blob produced by [`seal`]. Wrong passphrase and any
/// tampering both surface as [`CryptoError::Decrypt`] — Argon2id makes
/// this deliberately slow to discourage offline brute-forcing.
pub fn open(passphrase: &str, sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < 1 + SALT_LEN + NONCE_LEN || sealed[0] != FORMAT_VERSION {
        return Err(CryptoError::NotImplemented(
            "backup: malformed or unsupported format",
        ));
    }
    let salt: [u8; SALT_LEN] = sealed[1..1 + SALT_LEN].try_into().unwrap();
    let nonce_start = 1 + SALT_LEN;
    let nonce_bytes = &sealed[nonce_start..nonce_start + NONCE_LEN];
    let ciphertext = &sealed[nonce_start + NONCE_LEN..];

    let key = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    cipher
        .decrypt(&Nonce::try_from(nonce_bytes).expect("12 bytes"), ciphertext)
        .map_err(|_| CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_and_open_roundtrip() {
        let sealed = seal("correct horse battery staple", b"my precious backup data").unwrap();
        let opened = open("correct horse battery staple", &sealed).unwrap();
        assert_eq!(opened, b"my precious backup data");
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let sealed = seal("right passphrase", b"secret contents").unwrap();
        assert!(open("wrong passphrase", &sealed).is_err());
    }

    #[test]
    fn tampered_backup_is_rejected() {
        let mut sealed = seal("a passphrase", b"secret contents").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(open("a passphrase", &sealed).is_err());
    }

    #[test]
    fn two_backups_of_the_same_data_are_unlinkable() {
        let a = seal("same passphrase", b"same data").unwrap();
        let b = seal("same passphrase", b"same data").unwrap();
        assert_ne!(a, b, "salt/nonce must be fresh per backup");
    }

    #[test]
    fn garbage_input_is_rejected_not_panicked_on() {
        assert!(open("whatever", b"too short").is_err());
    }
}
