//! Signal Protocol for 1:1 sessions: X3DH key agreement + Double Ratchet,
//! composed from audited primitives (x25519-dalek, ed25519-dalek, hkdf,
//! hmac, chacha20poly1305) per `docs/SPEC.md` §2.1 — see `lib.rs` for why
//! this isn't a dependency on Signal's own `libsignal`.
//!
//! References: Signal's public X3DH
//! (<https://signal.org/docs/specifications/x3dh/>) and Double Ratchet
//! (<https://signal.org/docs/specifications/doubleratchet/>)
//! specifications.

use std::collections::HashMap;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as AeadKey, Nonce};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

use crate::identity::IdentityKeyPair;
use crate::CryptoError;

/// Bound on how many out-of-order message keys we'll cache per session
/// before refusing to skip further ahead — mirrors Signal's own MAX_SKIP,
/// preventing a malicious peer from forcing unbounded memory growth.
const MAX_SKIP: u32 = 1000;

// ---------------------------------------------------------------------
// X3DH: prekeys and the initial handshake
// ---------------------------------------------------------------------

/// One of Bob's medium-term signed prekeys, plus the identity signature
/// over it that lets Alice verify it really came from Bob.
pub struct SignedPreKey {
    pub id: u32,
    pub secret: X25519Secret,
    pub public: X25519PublicKey,
    pub signature: Signature,
}

impl SignedPreKey {
    pub fn generate(identity: &IdentityKeyPair, id: u32) -> Self {
        let secret = X25519Secret::random();
        let public = X25519PublicKey::from(&secret);
        let signature = identity.sign(public.as_bytes());
        Self {
            id,
            secret,
            public,
            signature,
        }
    }
}

/// A one-time prekey — consumed after a single use, then discarded.
pub struct OneTimePreKey {
    pub id: u32,
    pub secret: X25519Secret,
    pub public: X25519PublicKey,
}

pub fn generate_one_time_prekeys(start_id: u32, count: u32) -> Vec<OneTimePreKey> {
    (start_id..start_id + count)
        .map(|id| {
            let secret = X25519Secret::random();
            let public = X25519PublicKey::from(&secret);
            OneTimePreKey { id, secret, public }
        })
        .collect()
}

/// What a peer publishes to the network so others can start a session with
/// them while they're offline (SPEC.md §5.3 mailboxes are where this
/// actually gets published/fetched — this struct is the payload).
pub struct PreKeyBundle {
    pub identity_agreement_key: X25519PublicKey,
    pub identity_signing_key: VerifyingKey,
    pub signed_prekey_id: u32,
    pub signed_prekey: X25519PublicKey,
    pub signed_prekey_signature: Signature,
    pub one_time_prekey_id: Option<u32>,
    pub one_time_prekey: Option<X25519PublicKey>,
}

impl PreKeyBundle {
    fn verify_signed_prekey(&self) -> Result<(), CryptoError> {
        self.identity_signing_key
            .verify(self.signed_prekey.as_bytes(), &self.signed_prekey_signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

fn hkdf_sk(input_key_material: &[u8]) -> [u8; 32] {
    // X3DH §2.2: prepend 32 0xFF bytes so the KDF input can't collide with
    // a valid Curve25519 point, then HKDF-extract+expand to the session key.
    let mut ikm = vec![0xFFu8; 32];
    ikm.extend_from_slice(input_key_material);
    let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ikm);
    let mut sk = [0u8; 32];
    hkdf.expand(b"blackhole-x3dh-v1", &mut sk)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    sk
}

/// The message Alice sends to start a session — Bob needs this (plus his
/// own private prekeys) to derive the same shared secret via
/// [`x3dh_respond`].
pub struct InitialMessage {
    pub sender_identity_agreement_key: X25519PublicKey,
    pub sender_ephemeral_key: X25519PublicKey,
    pub used_signed_prekey_id: u32,
    pub used_one_time_prekey_id: Option<u32>,
}

/// Alice's side of X3DH: given Bob's published prekey bundle, derive the
/// shared secret and the message that lets Bob derive the same one.
pub fn x3dh_initiate(
    my_identity: &IdentityKeyPair,
    their_bundle: &PreKeyBundle,
) -> Result<([u8; 32], InitialMessage), CryptoError> {
    their_bundle.verify_signed_prekey()?;

    let ephemeral = X25519Secret::random();
    let ephemeral_public = X25519PublicKey::from(&ephemeral);

    let dh1 = my_identity
        .agreement_secret()
        .diffie_hellman(&their_bundle.signed_prekey);
    let dh2 = ephemeral.diffie_hellman(&their_bundle.identity_agreement_key);
    let dh3 = ephemeral.diffie_hellman(&their_bundle.signed_prekey);

    let mut ikm = Vec::with_capacity(32 * 4);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    if let Some(opk) = &their_bundle.one_time_prekey {
        let dh4 = ephemeral.diffie_hellman(opk);
        ikm.extend_from_slice(dh4.as_bytes());
    }

    let sk = hkdf_sk(&ikm);

    Ok((
        sk,
        InitialMessage {
            sender_identity_agreement_key: my_identity.public_agreement_key(),
            sender_ephemeral_key: ephemeral_public,
            used_signed_prekey_id: their_bundle.signed_prekey_id,
            used_one_time_prekey_id: their_bundle.one_time_prekey.as_ref().map(|_| {
                their_bundle
                    .one_time_prekey_id
                    .expect("one_time_prekey_id set whenever one_time_prekey is")
            }),
        },
    ))
}

/// Bob's side of X3DH: reconstruct the same shared secret from Alice's
/// [`InitialMessage`] and his own (still-private) prekeys. `one_time_prekey`
/// must be the specific OPK named in the message, if any — and the caller
/// is responsible for deleting it afterwards (SPEC.md §2: OPKs are
/// single-use).
pub fn x3dh_respond(
    my_identity: &IdentityKeyPair,
    my_signed_prekey: &SignedPreKey,
    my_one_time_prekey: Option<&OneTimePreKey>,
    msg: &InitialMessage,
) -> Result<[u8; 32], CryptoError> {
    let dh1 = my_signed_prekey
        .secret
        .diffie_hellman(&msg.sender_identity_agreement_key);
    let dh2 = my_identity
        .agreement_secret()
        .diffie_hellman(&msg.sender_ephemeral_key);
    let dh3 = my_signed_prekey
        .secret
        .diffie_hellman(&msg.sender_ephemeral_key);

    let mut ikm = Vec::with_capacity(32 * 4);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    if let Some(opk) = my_one_time_prekey {
        let dh4 = opk.secret.diffie_hellman(&msg.sender_ephemeral_key);
        ikm.extend_from_slice(dh4.as_bytes());
    }

    Ok(hkdf_sk(&ikm))
}

// ---------------------------------------------------------------------
// Double Ratchet
// ---------------------------------------------------------------------

type HmacSha256 = Hmac<Sha256>;

fn kdf_root(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hkdf = Hkdf::<Sha256>::new(Some(root_key), dh_output);
    let mut output = [0u8; 64];
    hkdf.expand(b"blackhole-double-ratchet-root-v1", &mut output)
        .expect("64 bytes is a valid HKDF-SHA256 output length");
    let mut new_root = [0u8; 32];
    let mut new_chain = [0u8; 32];
    new_root.copy_from_slice(&output[..32]);
    new_chain.copy_from_slice(&output[32..]);
    (new_root, new_chain)
}

fn kdf_chain(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut mac = HmacSha256::new_from_slice(chain_key).expect("HMAC accepts any key length");
    mac.update(&[0x01]);
    let message_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(chain_key).expect("HMAC accepts any key length");
    mac.update(&[0x02]);
    let next_chain_key = mac.finalize().into_bytes();

    let mut mk = [0u8; 32];
    let mut ck = [0u8; 32];
    mk.copy_from_slice(&message_key);
    ck.copy_from_slice(&next_chain_key);
    (ck, mk)
}

/// Derives the actual AEAD key+nonce from a per-message key. Each message
/// key is used for exactly one message ever, so — unlike a normal AEAD key
/// reused across calls — a fixed derivation is safe; we still separate key
/// material from the message key via HKDF rather than using it directly.
fn message_key_to_aead(message_key: &[u8; 32]) -> (AeadKey, Nonce) {
    let hkdf = Hkdf::<Sha256>::new(None, message_key);
    let mut output = [0u8; 44];
    hkdf.expand(b"blackhole-double-ratchet-msg-v1", &mut output)
        .expect("44 bytes is a valid HKDF-SHA256 output length");
    let key = AeadKey::try_from(&output[..32]).expect("32 bytes");
    let nonce = Nonce::try_from(&output[32..44]).expect("12 bytes");
    (key, nonce)
}

fn header_bytes(dh_public: &X25519PublicKey, prev_chain_len: u32, counter: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + 4 + 4);
    bytes.extend_from_slice(dh_public.as_bytes());
    bytes.extend_from_slice(&prev_chain_len.to_be_bytes());
    bytes.extend_from_slice(&counter.to_be_bytes());
    bytes
}

/// A single encrypted Double Ratchet message.
#[derive(Debug, Clone)]
pub struct RatchetMessage {
    pub dh_public: [u8; 32],
    pub prev_chain_len: u32,
    pub counter: u32,
    pub ciphertext: Vec<u8>,
}

/// An established 1:1 session between two identities — the persistent
/// state that `bh-storage::sessions` stores as an opaque blob.
pub struct Session {
    associated_data: Vec<u8>,
    root_key: [u8; 32],
    dh_self_secret: X25519Secret,
    dh_self_public: X25519PublicKey,
    dh_remote_public: Option<X25519PublicKey>,
    sending_chain_key: Option<[u8; 32]>,
    receiving_chain_key: Option<[u8; 32]>,
    send_count: u32,
    recv_count: u32,
    prev_chain_len: u32,
    skipped_keys: HashMap<([u8; 32], u32), [u8; 32]>,
}

impl Session {
    /// Alice's side: called right after `x3dh_initiate`, using Bob's
    /// signed prekey as his first ratchet public key.
    pub fn init_as_initiator(
        shared_secret: [u8; 32],
        their_signed_prekey: X25519PublicKey,
        associated_data: Vec<u8>,
    ) -> Self {
        let dh_self_secret = X25519Secret::random();
        let dh_self_public = X25519PublicKey::from(&dh_self_secret);
        let dh_output = dh_self_secret.diffie_hellman(&their_signed_prekey);
        let (root_key, sending_chain_key) = kdf_root(&shared_secret, dh_output.as_bytes());

        Self {
            associated_data,
            root_key,
            dh_self_secret,
            dh_self_public,
            dh_remote_public: Some(their_signed_prekey),
            sending_chain_key: Some(sending_chain_key),
            receiving_chain_key: None,
            send_count: 0,
            recv_count: 0,
            prev_chain_len: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Bob's side: called right after `x3dh_respond`, reusing his signed
    /// prekey pair as the first ratchet keypair.
    pub fn init_as_responder(
        shared_secret: [u8; 32],
        my_signed_prekey_secret: X25519Secret,
        associated_data: Vec<u8>,
    ) -> Self {
        let dh_self_public = X25519PublicKey::from(&my_signed_prekey_secret);
        Self {
            associated_data,
            root_key: shared_secret,
            dh_self_secret: my_signed_prekey_secret,
            dh_self_public,
            dh_remote_public: None,
            sending_chain_key: None,
            receiving_chain_key: None,
            send_count: 0,
            recv_count: 0,
            prev_chain_len: 0,
            skipped_keys: HashMap::new(),
        }
    }

    fn dh_ratchet(&mut self, their_new_public: X25519PublicKey) {
        self.prev_chain_len = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;
        self.dh_remote_public = Some(their_new_public);

        let dh_output = self.dh_self_secret.diffie_hellman(&their_new_public);
        let (root_key, receiving_chain_key) = kdf_root(&self.root_key, dh_output.as_bytes());
        self.root_key = root_key;
        self.receiving_chain_key = Some(receiving_chain_key);

        self.dh_self_secret = X25519Secret::random();
        self.dh_self_public = X25519PublicKey::from(&self.dh_self_secret);
        let dh_output = self.dh_self_secret.diffie_hellman(&their_new_public);
        let (root_key, sending_chain_key) = kdf_root(&self.root_key, dh_output.as_bytes());
        self.root_key = root_key;
        self.sending_chain_key = Some(sending_chain_key);
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage, CryptoError> {
        let chain_key = self.sending_chain_key.ok_or(CryptoError::NoSession)?;
        let (next_chain_key, message_key) = kdf_chain(&chain_key);
        self.sending_chain_key = Some(next_chain_key);

        let counter = self.send_count;
        self.send_count += 1;

        let header = header_bytes(&self.dh_self_public, self.prev_chain_len, counter);
        let mut aad = self.associated_data.clone();
        aad.extend_from_slice(&header);

        let (key, nonce) = message_key_to_aead(&message_key);
        let cipher = ChaCha20Poly1305::new(&key);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Encrypt)?;

        Ok(RatchetMessage {
            dh_public: self.dh_self_public.to_bytes(),
            prev_chain_len: self.prev_chain_len,
            counter,
            ciphertext,
        })
    }

    fn try_skipped(&mut self, msg: &RatchetMessage) -> Option<[u8; 32]> {
        self.skipped_keys.remove(&(msg.dh_public, msg.counter))
    }

    fn skip_receiving_keys(&mut self, until: u32) -> Result<(), CryptoError> {
        let Some(chain_key) = self.receiving_chain_key else {
            return Ok(());
        };
        if until.saturating_sub(self.recv_count) > MAX_SKIP {
            return Err(CryptoError::Decrypt);
        }
        let mut chain_key = chain_key;
        let remote = self
            .dh_remote_public
            .ok_or(CryptoError::NoSession)?
            .to_bytes();
        while self.recv_count < until {
            let (next_chain_key, message_key) = kdf_chain(&chain_key);
            self.skipped_keys
                .insert((remote, self.recv_count), message_key);
            chain_key = next_chain_key;
            self.recv_count += 1;
        }
        self.receiving_chain_key = Some(chain_key);
        Ok(())
    }

    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>, CryptoError> {
        let message_key = if let Some(mk) = self.try_skipped(msg) {
            mk
        } else {
            let incoming_dh = X25519PublicKey::from(msg.dh_public);
            if self.dh_remote_public.map(|k| k.to_bytes()) != Some(msg.dh_public) {
                self.skip_receiving_keys(msg.prev_chain_len)?;
                self.dh_ratchet(incoming_dh);
            }
            self.skip_receiving_keys(msg.counter)?;
            let chain_key = self.receiving_chain_key.ok_or(CryptoError::NoSession)?;
            let (next_chain_key, message_key) = kdf_chain(&chain_key);
            self.receiving_chain_key = Some(next_chain_key);
            self.recv_count += 1;
            message_key
        };

        let header = header_bytes(
            &X25519PublicKey::from(msg.dh_public),
            msg.prev_chain_len,
            msg.counter,
        );
        let mut aad = self.associated_data.clone();
        aad.extend_from_slice(&header);

        let (key, nonce) = message_key_to_aead(&message_key);
        let cipher = ChaCha20Poly1305::new(&key);
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &msg.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bob_bundle(
        bob_identity: &IdentityKeyPair,
        signed_prekey: &SignedPreKey,
        otk: Option<&OneTimePreKey>,
    ) -> PreKeyBundle {
        PreKeyBundle {
            identity_agreement_key: bob_identity.public_agreement_key(),
            identity_signing_key: bob_identity.public_signing_key(),
            signed_prekey_id: signed_prekey.id,
            signed_prekey: signed_prekey.public,
            signed_prekey_signature: signed_prekey.signature,
            one_time_prekey_id: otk.map(|k| k.id),
            one_time_prekey: otk.map(|k| k.public),
        }
    }

    #[test]
    fn x3dh_alice_and_bob_derive_the_same_secret_with_one_time_prekey() {
        let alice_id = IdentityKeyPair::generate().unwrap();
        let bob_id = IdentityKeyPair::generate().unwrap();
        let bob_spk = SignedPreKey::generate(&bob_id, 1);
        let bob_otk = &generate_one_time_prekeys(1, 1)[0];

        let bundle = bob_bundle(&bob_id, &bob_spk, Some(bob_otk));
        let (alice_sk, initial_msg) = x3dh_initiate(&alice_id, &bundle).unwrap();

        let bob_sk = x3dh_respond(&bob_id, &bob_spk, Some(bob_otk), &initial_msg).unwrap();

        assert_eq!(alice_sk, bob_sk);
    }

    #[test]
    fn x3dh_works_without_a_one_time_prekey() {
        let alice_id = IdentityKeyPair::generate().unwrap();
        let bob_id = IdentityKeyPair::generate().unwrap();
        let bob_spk = SignedPreKey::generate(&bob_id, 1);

        let bundle = bob_bundle(&bob_id, &bob_spk, None);
        let (alice_sk, initial_msg) = x3dh_initiate(&alice_id, &bundle).unwrap();
        let bob_sk = x3dh_respond(&bob_id, &bob_spk, None, &initial_msg).unwrap();

        assert_eq!(alice_sk, bob_sk);
    }

    #[test]
    fn x3dh_rejects_a_tampered_signed_prekey_signature() {
        let alice_id = IdentityKeyPair::generate().unwrap();
        let bob_id = IdentityKeyPair::generate().unwrap();
        let bob_spk = SignedPreKey::generate(&bob_id, 1);
        let mut bundle = bob_bundle(&bob_id, &bob_spk, None);
        // Substitute a signature that was made over different data.
        let other_spk = SignedPreKey::generate(&bob_id, 2);
        bundle.signed_prekey_signature = other_spk.signature;

        assert!(x3dh_initiate(&alice_id, &bundle).is_err());
    }

    fn establish_session_pair() -> (Session, Session) {
        let alice_id = IdentityKeyPair::generate().unwrap();
        let bob_id = IdentityKeyPair::generate().unwrap();
        let bob_spk = SignedPreKey::generate(&bob_id, 1);
        let bundle = bob_bundle(&bob_id, &bob_spk, None);

        let (alice_sk, initial_msg) = x3dh_initiate(&alice_id, &bundle).unwrap();
        let bob_sk = x3dh_respond(&bob_id, &bob_spk, None, &initial_msg).unwrap();

        let ad = b"alice-bob-associated-data".to_vec();
        let alice_session = Session::init_as_initiator(alice_sk, bob_spk.public, ad.clone());
        let bob_session = Session::init_as_responder(bob_sk, bob_spk.secret, ad);
        (alice_session, bob_session)
    }

    #[test]
    fn double_ratchet_basic_message_roundtrip() {
        let (mut alice, mut bob) = establish_session_pair();
        let msg = alice.encrypt(b"hello bob").unwrap();
        let plaintext = bob.decrypt(&msg).unwrap();
        assert_eq!(plaintext, b"hello bob");
    }

    #[test]
    fn double_ratchet_handles_a_full_back_and_forth_conversation() {
        let (mut alice, mut bob) = establish_session_pair();

        let m1 = alice.encrypt(b"hi bob").unwrap();
        assert_eq!(bob.decrypt(&m1).unwrap(), b"hi bob");

        let m2 = bob.encrypt(b"hi alice").unwrap();
        assert_eq!(alice.decrypt(&m2).unwrap(), b"hi alice");

        let m3 = alice.encrypt(b"how are you").unwrap();
        let m4 = alice.encrypt(b"still there?").unwrap();
        assert_eq!(bob.decrypt(&m3).unwrap(), b"how are you");
        assert_eq!(bob.decrypt(&m4).unwrap(), b"still there?");
    }

    #[test]
    fn double_ratchet_handles_out_of_order_delivery() {
        let (mut alice, mut bob) = establish_session_pair();

        let m1 = alice.encrypt(b"one").unwrap();
        let m2 = alice.encrypt(b"two").unwrap();
        let m3 = alice.encrypt(b"three").unwrap();

        // Bob receives them out of order.
        assert_eq!(bob.decrypt(&m3).unwrap(), b"three");
        assert_eq!(bob.decrypt(&m1).unwrap(), b"one");
        assert_eq!(bob.decrypt(&m2).unwrap(), b"two");
    }

    #[test]
    fn double_ratchet_survives_many_dh_ratchet_steps() {
        let (mut alice, mut bob) = establish_session_pair();
        for i in 0..10 {
            let from_alice = format!("alice says {i}");
            let m = alice.encrypt(from_alice.as_bytes()).unwrap();
            assert_eq!(bob.decrypt(&m).unwrap(), from_alice.as_bytes());

            let from_bob = format!("bob says {i}");
            let m = bob.encrypt(from_bob.as_bytes()).unwrap();
            assert_eq!(alice.decrypt(&m).unwrap(), from_bob.as_bytes());
        }
    }

    #[test]
    fn double_ratchet_rejects_tampered_ciphertext() {
        let (mut alice, mut bob) = establish_session_pair();
        let mut msg = alice.encrypt(b"hello").unwrap();
        let last = msg.ciphertext.len() - 1;
        msg.ciphertext[last] ^= 0xFF;
        assert!(bob.decrypt(&msg).is_err());
    }

    #[test]
    fn double_ratchet_rejects_wrong_associated_data() {
        let alice_id = IdentityKeyPair::generate().unwrap();
        let bob_id = IdentityKeyPair::generate().unwrap();
        let bob_spk = SignedPreKey::generate(&bob_id, 1);
        let bundle = bob_bundle(&bob_id, &bob_spk, None);
        let (alice_sk, initial_msg) = x3dh_initiate(&alice_id, &bundle).unwrap();
        let bob_sk = x3dh_respond(&bob_id, &bob_spk, None, &initial_msg).unwrap();

        let mut alice_session =
            Session::init_as_initiator(alice_sk, bob_spk.public, b"correct-ad".to_vec());
        let mut bob_session =
            Session::init_as_responder(bob_sk, bob_spk.secret, b"wrong-ad".to_vec());

        let msg = alice_session.encrypt(b"hello").unwrap();
        assert!(bob_session.decrypt(&msg).is_err());
    }
}
