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
use zeroize::Zeroizing;

use crate::identity::IdentityKeyPair;
use crate::pq_hybrid::{self, HybridCiphertext, HybridPublicKey, HybridSecretKey};
use crate::CryptoError;

/// Bound on how many out-of-order message keys we'll cache per session
/// before refusing to skip further ahead — mirrors Signal's own MAX_SKIP,
/// preventing a malicious peer from forcing unbounded memory growth.
const MAX_SKIP: u32 = 1000;

// ---------------------------------------------------------------------
// X3DH: prekeys and the initial handshake
// ---------------------------------------------------------------------

/// One of Bob's medium-term signed prekeys, plus the identity signature
/// over it that lets Alice verify it really came from Bob. Bundles a
/// post-quantum hybrid prekey alongside the classical one (SPEC.md §2.1:
/// PQ hybrid from day one, not bolted on later) — every session actually
/// gets both legs, not just whichever `bh-crypto::pq_hybrid` demonstrates
/// standalone.
pub struct SignedPreKey {
    pub id: u32,
    pub secret: X25519Secret,
    pub public: X25519PublicKey,
    pub signature: Signature,
    pub pq_prekey: HybridSecretKey,
    pub pq_prekey_signature: Signature,
}

impl SignedPreKey {
    pub fn generate(identity: &IdentityKeyPair, id: u32) -> Self {
        let secret = X25519Secret::random();
        let public = X25519PublicKey::from(&secret);
        let signature = identity.sign(public.as_bytes());

        let pq_prekey = HybridSecretKey::generate();
        let pq_prekey_signature = identity.sign(&pq_prekey.public_key().to_bytes());

        Self {
            id,
            secret,
            public,
            signature,
            pq_prekey,
            pq_prekey_signature,
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
    pub pq_prekey: HybridPublicKey,
    pub pq_prekey_signature: Signature,
    pub one_time_prekey_id: Option<u32>,
    pub one_time_prekey: Option<X25519PublicKey>,
}

impl PreKeyBundle {
    fn verify_signed_prekey(&self) -> Result<(), CryptoError> {
        self.identity_signing_key
            .verify(self.signed_prekey.as_bytes(), &self.signed_prekey_signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        self.identity_signing_key
            .verify(&self.pq_prekey.to_bytes(), &self.pq_prekey_signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    /// Wire bytes for publishing this (public-only) bundle somewhere a
    /// peer can fetch it (SPEC.md §5.3: a mailbox/DHT record keyed by this
    /// identity's own recipient-key-hash). Signature verification against
    /// `identity_signing_key` still happens in [`x3dh_initiate`] on the
    /// fetching side — this is just the encoding, not a trust boundary.
    pub fn to_bytes(&self) -> Vec<u8> {
        let pq_prekey_bytes = self.pq_prekey.to_bytes();
        let mut out =
            Vec::with_capacity(32 + 32 + 4 + 32 + 64 + 4 + pq_prekey_bytes.len() + 64 + 1 + 4 + 32);
        out.extend_from_slice(self.identity_agreement_key.as_bytes());
        out.extend_from_slice(self.identity_signing_key.as_bytes());
        out.extend_from_slice(&self.signed_prekey_id.to_be_bytes());
        out.extend_from_slice(self.signed_prekey.as_bytes());
        out.extend_from_slice(&self.signed_prekey_signature.to_bytes());
        out.extend_from_slice(&(pq_prekey_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&pq_prekey_bytes);
        out.extend_from_slice(&self.pq_prekey_signature.to_bytes());
        match (self.one_time_prekey_id, &self.one_time_prekey) {
            (Some(id), Some(public)) => {
                out.push(1);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(public.as_bytes());
            }
            _ => out.push(0),
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut offset = 0;
        let identity_agreement_key = X25519PublicKey::from(read_array32(bytes, &mut offset)?);
        let identity_signing_key = VerifyingKey::from_bytes(&read_array32(bytes, &mut offset)?)
            .map_err(|_| CryptoError::Malformed("prekey bundle: bad identity signing key"))?;
        let signed_prekey_id = read_u32(bytes, &mut offset)?;
        let signed_prekey = X25519PublicKey::from(read_array32(bytes, &mut offset)?);
        let signed_prekey_signature = Signature::from_bytes(&{
            let arr: [u8; 64] = read_exact(bytes, &mut offset, 64)?
                .try_into()
                .expect("checked length");
            arr
        });
        let pq_prekey_len = read_u32(bytes, &mut offset)? as usize;
        let pq_prekey =
            HybridPublicKey::from_bytes(read_exact(bytes, &mut offset, pq_prekey_len)?)?;
        let pq_prekey_signature = Signature::from_bytes(&{
            let arr: [u8; 64] = read_exact(bytes, &mut offset, 64)?
                .try_into()
                .expect("checked length");
            arr
        });
        let has_otk = *read_exact(bytes, &mut offset, 1)?
            .first()
            .expect("checked length");
        let (one_time_prekey_id, one_time_prekey) = match has_otk {
            0 => (None, None),
            1 => {
                let id = read_u32(bytes, &mut offset)?;
                let public = X25519PublicKey::from(read_array32(bytes, &mut offset)?);
                (Some(id), Some(public))
            }
            _ => return Err(CryptoError::Malformed("prekey bundle: bad otk flag")),
        };
        Ok(Self {
            identity_agreement_key,
            identity_signing_key,
            signed_prekey_id,
            signed_prekey,
            signed_prekey_signature,
            pq_prekey,
            pq_prekey_signature,
            one_time_prekey_id,
            one_time_prekey,
        })
    }
}

fn hkdf_sk(input_key_material: &[u8]) -> [u8; 32] {
    // X3DH §2.2: prepend 32 0xFF bytes so the KDF input can't collide with
    // a valid Curve25519 point, then HKDF-extract+expand to the session key.
    // `ikm` is heap-allocated and holds the raw DH outputs concatenated —
    // wrapped so it's wiped on drop rather than left in freed heap memory.
    let mut ikm: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0xFFu8; 32]);
    ikm.extend_from_slice(input_key_material);
    let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ikm);
    let mut sk = [0u8; 32];
    hkdf.expand(b"blackhole-x3dh-v1", &mut sk)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    sk
}

/// Combines the classical X3DH secret with the post-quantum hybrid KEM
/// secret into the final session key. Defense in depth by construction,
/// same as `pq_hybrid::combine`: breaking the PQ leg alone still leaves an
/// attacker facing the full classical X3DH secret, and vice versa.
fn combine_classical_and_pq(classical_sk: &[u8; 32], pq_secret: &[u8; 32]) -> [u8; 32] {
    let mut ikm: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(classical_sk);
    ikm.extend_from_slice(pq_secret);
    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut out = [0u8; 32];
    hkdf.expand(b"blackhole-x3dh-pq-hybrid-v1", &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// The message Alice sends to start a session — Bob needs this (plus his
/// own private prekeys) to derive the same shared secret via
/// [`x3dh_respond`].
pub struct InitialMessage {
    pub sender_identity_agreement_key: X25519PublicKey,
    pub sender_ephemeral_key: X25519PublicKey,
    pub used_signed_prekey_id: u32,
    pub used_one_time_prekey_id: Option<u32>,
    pub pq_ciphertext: HybridCiphertext,
}

impl InitialMessage {
    /// Wire bytes for the X3DH handshake message a first-contact envelope
    /// carries alongside the first Double Ratchet ciphertext — the
    /// recipient needs this to derive the same shared secret via
    /// [`x3dh_respond`] before it can decrypt anything.
    pub fn to_bytes(&self) -> Vec<u8> {
        let pq_bytes = self.pq_ciphertext.to_bytes();
        let mut out = Vec::with_capacity(32 + 32 + 4 + 1 + 4 + pq_bytes.len());
        out.extend_from_slice(self.sender_identity_agreement_key.as_bytes());
        out.extend_from_slice(self.sender_ephemeral_key.as_bytes());
        out.extend_from_slice(&self.used_signed_prekey_id.to_be_bytes());
        match self.used_one_time_prekey_id {
            Some(id) => {
                out.push(1);
                out.extend_from_slice(&id.to_be_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&pq_bytes);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut offset = 0;
        let sender_identity_agreement_key =
            X25519PublicKey::from(read_array32(bytes, &mut offset)?);
        let sender_ephemeral_key = X25519PublicKey::from(read_array32(bytes, &mut offset)?);
        let used_signed_prekey_id = read_u32(bytes, &mut offset)?;
        let has_otk = *read_exact(bytes, &mut offset, 1)?
            .first()
            .expect("checked length");
        let used_one_time_prekey_id = match has_otk {
            0 => None,
            1 => Some(read_u32(bytes, &mut offset)?),
            _ => return Err(CryptoError::Malformed("initial message: bad otk flag")),
        };
        let pq_ciphertext = HybridCiphertext::from_bytes(
            bytes
                .get(offset..)
                .ok_or(CryptoError::Malformed("initial message: truncated"))?,
        )?;
        Ok(Self {
            sender_identity_agreement_key,
            sender_ephemeral_key,
            used_signed_prekey_id,
            used_one_time_prekey_id,
            pq_ciphertext,
        })
    }
}

/// Alice's side of X3DH: given Bob's published prekey bundle, derive the
/// shared secret and the message that lets Bob derive the same one. The
/// returned secret is a classical-X3DH/PQ-hybrid combination (SPEC.md
/// §2.1) — not just the classical X3DH output.
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

    let classical_sk = hkdf_sk(&ikm);
    let (pq_secret, pq_ciphertext) = pq_hybrid::hybrid_encapsulate(&their_bundle.pq_prekey)?;
    let sk = combine_classical_and_pq(&classical_sk, &pq_secret);

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
            pq_ciphertext,
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

    let classical_sk = hkdf_sk(&ikm);
    let pq_secret = pq_hybrid::hybrid_decapsulate(&my_signed_prekey.pq_prekey, &msg.pq_ciphertext)?;
    Ok(combine_classical_and_pq(&classical_sk, &pq_secret))
}

/// The Double Ratchet's `associated_data` must be byte-for-byte identical
/// on both ends of a session (it's mixed into every message's AEAD AAD —
/// see [`Session::encrypt`]/[`Session::decrypt`]), but the two parties
/// don't agree in advance on who's "Alice" and who's "Bob": the initiator
/// only knows "my identity, their identity" and the responder only knows
/// "my identity, their identity" — same two values, opposite labels.
/// Canonically ordering the two 64-byte identity blobs (`signing_key ||
/// agreement_key`, see `bh_crypto::identity::IdentityKeyPair::
/// public_identity_bytes`/`Contact::identity_public_key`) by byte value
/// before concatenating them means both sides compute the exact same
/// bytes regardless of which side they're on — the same idea as Signal's
/// own `Encode(IKA) || Encode(IKB)` X3DH associated data.
pub fn session_associated_data(identity_a: &[u8], identity_b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(identity_a.len() + identity_b.len());
    if identity_a <= identity_b {
        out.extend_from_slice(identity_a);
        out.extend_from_slice(identity_b);
    } else {
        out.extend_from_slice(identity_b);
        out.extend_from_slice(identity_a);
    }
    out
}

// ---------------------------------------------------------------------
// Double Ratchet
// ---------------------------------------------------------------------

type HmacSha256 = Hmac<Sha256>;

fn kdf_root(
    root_key: &[u8; 32],
    dh_output: &[u8; 32],
) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let hkdf = Hkdf::<Sha256>::new(Some(root_key), dh_output);
    let mut output: Zeroizing<[u8; 64]> = Zeroizing::new([0u8; 64]);
    hkdf.expand(b"blackhole-double-ratchet-root-v1", &mut *output)
        .expect("64 bytes is a valid HKDF-SHA256 output length");
    let mut new_root = Zeroizing::new([0u8; 32]);
    let mut new_chain = Zeroizing::new([0u8; 32]);
    new_root.copy_from_slice(&output[..32]);
    new_chain.copy_from_slice(&output[32..]);
    (new_root, new_chain)
}

/// Returns `(next_chain_key, message_key)`, both wrapped so the chain key
/// stored back into the session and the one-time message key handed to
/// `message_key_to_aead` are wiped as soon as they go out of scope instead
/// of lingering in freed memory for the rest of the session's lifetime.
fn kdf_chain(chain_key: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mut mac = HmacSha256::new_from_slice(chain_key).expect("HMAC accepts any key length");
    mac.update(&[0x01]);
    let message_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(chain_key).expect("HMAC accepts any key length");
    mac.update(&[0x02]);
    let next_chain_key = mac.finalize().into_bytes();

    let mut mk = Zeroizing::new([0u8; 32]);
    let mut ck = Zeroizing::new([0u8; 32]);
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
    let mut output: Zeroizing<[u8; 44]> = Zeroizing::new([0u8; 44]);
    hkdf.expand(b"blackhole-double-ratchet-msg-v1", &mut *output)
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

// ---------------------------------------------------------------------
// Wire/persistence serialization. Deliberately hand-rolled, not `serde` —
// several of the types serialized here (`X25519Secret`, `Session`'s
// `Zeroizing` fields) either don't implement it or shouldn't have their
// exact in-memory representation treated as a stable wire format, so this
// mirrors the existing `IdentityKeyPair::export_bytes`/`import_bytes` and
// `sealed_sender.rs` framing style: explicit, auditable byte layout, no
// derive magic. Every multi-byte integer is big-endian.
// ---------------------------------------------------------------------

fn read_exact<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'a [u8], CryptoError> {
    let end = offset
        .checked_add(len)
        .ok_or(CryptoError::Malformed("length overflow"))?;
    let slice = bytes
        .get(*offset..end)
        .ok_or(CryptoError::Malformed("truncated"))?;
    *offset = end;
    Ok(slice)
}

fn read_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, CryptoError> {
    let slice = read_exact(bytes, offset, 4)?;
    Ok(u32::from_be_bytes(
        slice.try_into().expect("checked length"),
    ))
}

fn read_array32(bytes: &[u8], offset: &mut usize) -> Result<[u8; 32], CryptoError> {
    let slice = read_exact(bytes, offset, 32)?;
    Ok(slice.try_into().expect("checked length"))
}

impl RatchetMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + 4 + 4 + self.ciphertext.len());
        out.extend_from_slice(&self.dh_public);
        out.extend_from_slice(&self.prev_chain_len.to_be_bytes());
        out.extend_from_slice(&self.counter.to_be_bytes());
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut offset = 0;
        let dh_public = read_array32(bytes, &mut offset)?;
        let prev_chain_len = read_u32(bytes, &mut offset)?;
        let counter = read_u32(bytes, &mut offset)?;
        let ciphertext_len = read_u32(bytes, &mut offset)? as usize;
        let ciphertext = read_exact(bytes, &mut offset, ciphertext_len)?.to_vec();
        Ok(Self {
            dh_public,
            prev_chain_len,
            counter,
            ciphertext,
        })
    }
}

/// An established 1:1 session between two identities — the persistent
/// state that `bh-storage::sessions` stores as an opaque blob.
///
/// `root_key`/`sending_chain_key`/`receiving_chain_key`/`skipped_keys`'
/// values are `Zeroizing` — this state lives for the session's entire
/// lifetime (potentially a whole conversation), so it's the highest-value
/// target for a memory-disclosure read; wrapping it means every one of
/// those fields is wiped the moment it's replaced or the `Session` drops,
/// rather than left sitting in freed memory.
pub struct Session {
    associated_data: Vec<u8>,
    root_key: Zeroizing<[u8; 32]>,
    dh_self_secret: X25519Secret,
    dh_self_public: X25519PublicKey,
    dh_remote_public: Option<X25519PublicKey>,
    sending_chain_key: Option<Zeroizing<[u8; 32]>>,
    receiving_chain_key: Option<Zeroizing<[u8; 32]>>,
    send_count: u32,
    recv_count: u32,
    prev_chain_len: u32,
    skipped_keys: HashMap<([u8; 32], u32), Zeroizing<[u8; 32]>>,
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
            root_key: Zeroizing::new(shared_secret),
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
        // `.take()` rather than a Copy-out: `Zeroizing<[u8; 32]>` is
        // intentionally not `Copy`, and the old chain key is fully
        // consumed here (replaced below), so taking it lets it zeroize on
        // drop at the end of this scope instead of lingering.
        let chain_key = self
            .sending_chain_key
            .take()
            .ok_or(CryptoError::NoSession)?;
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

    fn try_skipped(&mut self, msg: &RatchetMessage) -> Option<Zeroizing<[u8; 32]>> {
        self.skipped_keys.remove(&(msg.dh_public, msg.counter))
    }

    fn skip_receiving_keys(&mut self, until: u32) -> Result<(), CryptoError> {
        // Cloned rather than taken: an early return below (over-skip,
        // over-cap) must leave `self.receiving_chain_key` untouched, so the
        // session isn't left without a receiving chain key after a
        // rejected call.
        let Some(mut chain_key) = self.receiving_chain_key.clone() else {
            return Ok(());
        };
        let new_keys = until.saturating_sub(self.recv_count);
        if new_keys > MAX_SKIP {
            return Err(CryptoError::Decrypt);
        }
        // `recv_count` resets to 0 on every `dh_ratchet`, so bounding only
        // this call's `new_keys` against it caps growth per DH epoch, not
        // per session — a peer that keeps ratcheting could otherwise add
        // up to MAX_SKIP entries on every epoch forever. Cap the *total*
        // cached count across the session's lifetime instead, matching
        // what MAX_SKIP's own doc comment (and THREAT_MODEL.md §3.1)
        // actually claims it bounds.
        if self.skipped_keys.len() as u32 + new_keys > MAX_SKIP {
            return Err(CryptoError::Decrypt);
        }
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
            let chain_key = self
                .receiving_chain_key
                .take()
                .ok_or(CryptoError::NoSession)?;
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

    /// Serializes this session's full ratchet state — the opaque blob
    /// `bh-storage::sessions.ratchet_state` persists (see that model's own
    /// doc comment). Contains long-term-sensitive key material; the caller
    /// is responsible for keeping the resulting bytes inside an
    /// already-encrypted store (SQLCipher here), same trust boundary as
    /// everything else this crate hands to `bh-storage`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&(self.associated_data.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.associated_data);
        out.extend_from_slice(&*self.root_key);
        out.extend_from_slice(&self.dh_self_secret.to_bytes());
        match &self.dh_remote_public {
            Some(k) => {
                out.push(1);
                out.extend_from_slice(k.as_bytes());
            }
            None => out.push(0),
        }
        match &self.sending_chain_key {
            Some(k) => {
                out.push(1);
                out.extend_from_slice(&**k);
            }
            None => out.push(0),
        }
        match &self.receiving_chain_key {
            Some(k) => {
                out.push(1);
                out.extend_from_slice(&**k);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.send_count.to_be_bytes());
        out.extend_from_slice(&self.recv_count.to_be_bytes());
        out.extend_from_slice(&self.prev_chain_len.to_be_bytes());
        out.extend_from_slice(&(self.skipped_keys.len() as u32).to_be_bytes());
        for ((dh, counter), key) in &self.skipped_keys {
            out.extend_from_slice(dh);
            out.extend_from_slice(&counter.to_be_bytes());
            out.extend_from_slice(&**key);
        }
        out
    }

    /// Inverse of [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut offset = 0;
        let ad_len = read_u32(bytes, &mut offset)? as usize;
        let associated_data = read_exact(bytes, &mut offset, ad_len)?.to_vec();
        let root_key = Zeroizing::new(read_array32(bytes, &mut offset)?);
        let dh_self_secret = X25519Secret::from(read_array32(bytes, &mut offset)?);
        let dh_self_public = X25519PublicKey::from(&dh_self_secret);

        let has_remote = *read_exact(bytes, &mut offset, 1)?
            .first()
            .expect("checked length");
        let dh_remote_public = match has_remote {
            0 => None,
            1 => Some(X25519PublicKey::from(read_array32(bytes, &mut offset)?)),
            _ => return Err(CryptoError::Malformed("session: bad remote-key flag")),
        };

        let has_sending = *read_exact(bytes, &mut offset, 1)?
            .first()
            .expect("checked length");
        let sending_chain_key = match has_sending {
            0 => None,
            1 => Some(Zeroizing::new(read_array32(bytes, &mut offset)?)),
            _ => return Err(CryptoError::Malformed("session: bad sending-chain flag")),
        };

        let has_receiving = *read_exact(bytes, &mut offset, 1)?
            .first()
            .expect("checked length");
        let receiving_chain_key = match has_receiving {
            0 => None,
            1 => Some(Zeroizing::new(read_array32(bytes, &mut offset)?)),
            _ => return Err(CryptoError::Malformed("session: bad receiving-chain flag")),
        };

        let send_count = read_u32(bytes, &mut offset)?;
        let recv_count = read_u32(bytes, &mut offset)?;
        let prev_chain_len = read_u32(bytes, &mut offset)?;

        let skipped_count = read_u32(bytes, &mut offset)?;
        let mut skipped_keys = HashMap::with_capacity(skipped_count as usize);
        for _ in 0..skipped_count {
            let dh = read_array32(bytes, &mut offset)?;
            let counter = read_u32(bytes, &mut offset)?;
            let key = Zeroizing::new(read_array32(bytes, &mut offset)?);
            skipped_keys.insert((dh, counter), key);
        }

        Ok(Self {
            associated_data,
            root_key,
            dh_self_secret,
            dh_self_public,
            dh_remote_public,
            sending_chain_key,
            receiving_chain_key,
            send_count,
            recv_count,
            prev_chain_len,
            skipped_keys,
        })
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
            pq_prekey: signed_prekey.pq_prekey.public_key(),
            pq_prekey_signature: signed_prekey.pq_prekey_signature,
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

    #[test]
    fn x3dh_rejects_a_tampered_pq_prekey_signature() {
        let alice_id = IdentityKeyPair::generate().unwrap();
        let bob_id = IdentityKeyPair::generate().unwrap();
        let bob_spk = SignedPreKey::generate(&bob_id, 1);
        let mut bundle = bob_bundle(&bob_id, &bob_spk, None);
        let other_spk = SignedPreKey::generate(&bob_id, 2);
        bundle.pq_prekey_signature = other_spk.pq_prekey_signature;

        assert!(x3dh_initiate(&alice_id, &bundle).is_err());
    }

    /// Proves the PQ leg isn't decorative: a session derived with a
    /// tampered post-quantum ciphertext ends up with a *different* key on
    /// each side, so the final session key genuinely depends on both legs
    /// (SPEC.md §2.1 hybrid-from-day-one), not just the classical X3DH
    /// output.
    #[test]
    fn tampering_with_the_pq_ciphertext_changes_the_derived_key() {
        let alice_id = IdentityKeyPair::generate().unwrap();
        let bob_id = IdentityKeyPair::generate().unwrap();
        let bob_spk = SignedPreKey::generate(&bob_id, 1);
        let bundle = bob_bundle(&bob_id, &bob_spk, None);

        let (alice_sk, mut initial_msg) = x3dh_initiate(&alice_id, &bundle).unwrap();
        let last = initial_msg.pq_ciphertext.ml_kem_ciphertext.len() - 1;
        initial_msg.pq_ciphertext.ml_kem_ciphertext[last] ^= 0xFF;

        let bob_sk = x3dh_respond(&bob_id, &bob_spk, None, &initial_msg).unwrap();
        assert_ne!(
            alice_sk, bob_sk,
            "a tampered PQ ciphertext must change the derived session key"
        );
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

    /// Regression test for the unbounded-growth bug: `recv_count` resets to
    /// 0 on every `dh_ratchet`, so bounding a single `skip_receiving_keys`
    /// call against only `recv_count` capped growth per DH epoch, not per
    /// session — a peer could ratchet repeatedly and add up to `MAX_SKIP`
    /// entries each time, forever. Drive several "epochs" (each
    /// individually well under `MAX_SKIP`) and confirm the *cumulative*
    /// cache size is what gets capped.
    #[test]
    fn skipped_key_cache_is_capped_across_the_whole_session_not_just_per_epoch() {
        let (_, mut bob) = establish_session_pair();

        for epoch in 0..2u8 {
            bob.dh_remote_public = Some(X25519PublicKey::from([epoch; 32]));
            bob.receiving_chain_key = Some(Zeroizing::new([epoch; 32]));
            bob.recv_count = 0;
            bob.skip_receiving_keys(400).unwrap();
        }
        assert_eq!(bob.skipped_keys.len(), 800);

        // A third epoch that's individually under MAX_SKIP (1000) would
        // have succeeded under the old per-epoch-only check, even though
        // the total cache would then hold 1200 entries.
        bob.dh_remote_public = Some(X25519PublicKey::from([2u8; 32]));
        bob.receiving_chain_key = Some(Zeroizing::new([2u8; 32]));
        bob.recv_count = 0;
        assert!(bob.skip_receiving_keys(400).is_err());
        assert_eq!(
            bob.skipped_keys.len(),
            800,
            "a rejected skip must not partially insert keys"
        );
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

    #[test]
    fn session_associated_data_is_order_independent() {
        let a = b"alice-identity-bytes";
        let b = b"bob-identity-bytes";
        assert_eq!(session_associated_data(a, b), session_associated_data(b, a));
        assert_ne!(session_associated_data(a, b), a.to_vec());
    }

    #[test]
    fn ratchet_message_roundtrips_through_bytes() {
        let msg = RatchetMessage {
            dh_public: [7u8; 32],
            prev_chain_len: 3,
            counter: 42,
            ciphertext: b"some ciphertext bytes".to_vec(),
        };
        let decoded = RatchetMessage::from_bytes(&msg.to_bytes()).unwrap();
        assert_eq!(decoded.dh_public, msg.dh_public);
        assert_eq!(decoded.prev_chain_len, msg.prev_chain_len);
        assert_eq!(decoded.counter, msg.counter);
        assert_eq!(decoded.ciphertext, msg.ciphertext);
    }

    #[test]
    fn initial_message_roundtrips_through_bytes_with_and_without_otk() {
        let alice_id = IdentityKeyPair::generate().unwrap();
        let bob_id = IdentityKeyPair::generate().unwrap();
        let bob_spk = SignedPreKey::generate(&bob_id, 1);

        for otk in [None, Some(generate_one_time_prekeys(1, 1).remove(0))] {
            let bundle = bob_bundle(&bob_id, &bob_spk, otk.as_ref());
            let (_sk, initial_msg) = x3dh_initiate(&alice_id, &bundle).unwrap();
            let decoded = InitialMessage::from_bytes(&initial_msg.to_bytes()).unwrap();
            assert_eq!(
                decoded.sender_identity_agreement_key.to_bytes(),
                initial_msg.sender_identity_agreement_key.to_bytes()
            );
            assert_eq!(
                decoded.sender_ephemeral_key.to_bytes(),
                initial_msg.sender_ephemeral_key.to_bytes()
            );
            assert_eq!(
                decoded.used_signed_prekey_id,
                initial_msg.used_signed_prekey_id
            );
            assert_eq!(
                decoded.used_one_time_prekey_id,
                initial_msg.used_one_time_prekey_id
            );

            // The round-tripped `InitialMessage` must still let Bob derive
            // the exact same shared secret `x3dh_initiate` produced — not
            // just structurally equal fields.
            let bob_sk = x3dh_respond(&bob_id, &bob_spk, otk.as_ref(), &decoded).unwrap();
            let alice_sk = x3dh_respond(&bob_id, &bob_spk, otk.as_ref(), &initial_msg).unwrap();
            assert_eq!(bob_sk, alice_sk);
        }
    }

    #[test]
    fn prekey_bundle_roundtrips_through_bytes_and_stays_verifiable() {
        let bob_id = IdentityKeyPair::generate().unwrap();
        let bob_spk = SignedPreKey::generate(&bob_id, 1);
        let otk = generate_one_time_prekeys(5, 1).remove(0);
        let bundle = bob_bundle(&bob_id, &bob_spk, Some(&otk));

        let decoded = PreKeyBundle::from_bytes(&bundle.to_bytes()).unwrap();
        assert_eq!(
            decoded.identity_agreement_key.to_bytes(),
            bundle.identity_agreement_key.to_bytes()
        );
        assert_eq!(
            decoded.identity_signing_key.to_bytes(),
            bundle.identity_signing_key.to_bytes()
        );
        assert_eq!(decoded.signed_prekey_id, bundle.signed_prekey_id);
        assert_eq!(decoded.one_time_prekey_id, bundle.one_time_prekey_id);

        // A decoded bundle must still pass the same signature check a
        // real `x3dh_initiate` call runs against it — proves the encoding
        // didn't silently corrupt anything the signature covers.
        let alice_id = IdentityKeyPair::generate().unwrap();
        assert!(x3dh_initiate(&alice_id, &decoded).is_ok());
    }

    #[test]
    fn session_roundtrips_through_bytes_mid_conversation() {
        let (mut alice, mut bob) = establish_session_pair();

        // Advance the ratchet a bit in both directions before snapshotting,
        // so the round-trip actually exercises chain keys/counters/DH
        // state, not just the freshly-initialized case.
        let m1 = alice.encrypt(b"hi bob").unwrap();
        assert_eq!(bob.decrypt(&m1).unwrap(), b"hi bob");
        let m2 = bob.encrypt(b"hi alice").unwrap();
        assert_eq!(alice.decrypt(&m2).unwrap(), b"hi alice");

        let alice_bytes = alice.to_bytes();
        let mut alice_restored = Session::from_bytes(&alice_bytes).unwrap();

        // The restored session must produce a message the *original* live
        // `bob` session (continuing independently) can still decrypt —
        // proving the restored state is really live ratchet state, not
        // just structurally similar bytes.
        let m3 = alice_restored.encrypt(b"still me").unwrap();
        assert_eq!(bob.decrypt(&m3).unwrap(), b"still me");
    }
}
