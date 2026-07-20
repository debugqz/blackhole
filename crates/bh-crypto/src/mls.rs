//! Group messaging via MLS (RFC 9420), using `openmls` — the reference
//! implementation — rather than reimplementing the group ratchet tree.
//! See `docs/SPEC.md` §2.1.
//!
//! Each member holds their own [`MlsMember`] (credential, signature key,
//! and an `openmls` crypto/storage provider) and a [`Group`] per group
//! they're in. `openmls`'s storage provider here is the in-memory
//! reference implementation (`OpenMlsRustCrypto`) — persisting MLS group
//! state into `bh-storage`'s `groups` table across daemon restarts means
//! implementing `openmls_traits::storage::StorageProvider` against
//! `bh_storage::Database`, which is a real follow-up integration, not done
//! here.

use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

use crate::CryptoError;

/// MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 — X25519-based, matching
/// the curve we already use for 1:1 sessions (SPEC.md §2.1).
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

fn map_err<E: std::fmt::Display>(e: E) -> CryptoError {
    tracing_like_log(&e);
    CryptoError::NotImplemented("mls")
}

// Kept tiny and dependency-free: we don't want to pull in a logging crate
// just for this. In the daemon this would go through `tracing`.
fn tracing_like_log<E: std::fmt::Display>(_e: &E) {}

/// One participant's durable MLS identity: a credential + signature
/// keypair, and the provider that stores this member's per-group secrets.
pub struct MlsMember {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
}

impl MlsMember {
    /// `identity` is an opaque, application-chosen identifier (e.g. the
    /// contact_id from `bh-storage`) — MLS doesn't interpret it.
    pub fn new(identity: &[u8]) -> Result<Self, CryptoError> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(map_err)?;
        signer.store(provider.storage()).map_err(map_err)?;

        let credential = BasicCredential::new(identity.to_vec());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };

        Ok(Self {
            provider,
            signer,
            credential_with_key,
        })
    }

    /// Publishes a key package so others can add this member to a group
    /// while they're offline (fetched via the same mailbox mechanism as
    /// X3DH prekey bundles — SPEC.md §5.3).
    pub fn generate_key_package(&self) -> Result<Vec<u8>, CryptoError> {
        let bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential_with_key.clone(),
            )
            .map_err(map_err)?;
        bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(map_err)
    }

    pub fn create_group(&self) -> Result<Group, CryptoError> {
        let inner = MlsGroup::new(
            &self.provider,
            &self.signer,
            &MlsGroupCreateConfig::default(),
            self.credential_with_key.clone(),
        )
        .map_err(map_err)?;
        Ok(Group { inner })
    }

    /// Joins a group from a `Welcome` message (received out-of-band, e.g.
    /// via the recipient's mailbox) plus the group's public ratchet tree.
    pub fn join_group(
        &self,
        welcome_bytes: &[u8],
        ratchet_tree_bytes: &[u8],
    ) -> Result<Group, CryptoError> {
        let welcome_msg =
            MlsMessageIn::tls_deserialize(&mut &welcome_bytes[..]).map_err(map_err)?;
        let welcome = match welcome_msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => {
                return Err(CryptoError::NotImplemented(
                    "mls: expected a Welcome message",
                ))
            }
        };
        let ratchet_tree =
            RatchetTreeIn::tls_deserialize(&mut &ratchet_tree_bytes[..]).map_err(map_err)?;

        let staged = StagedWelcome::new_from_welcome(
            &self.provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            Some(ratchet_tree),
        )
        .map_err(map_err)?;
        let inner = staged.into_group(&self.provider).map_err(map_err)?;
        Ok(Group { inner })
    }
}

/// An MLS group as seen by one member — wraps `openmls::group::MlsGroup`
/// plus the borrowed member state needed to drive it.
pub struct Group {
    inner: MlsGroup,
}

/// What `add_member` produces: the commit (broadcast to existing members)
/// and the welcome (sent to the new member only), both already serialized
/// for the wire.
pub struct AddMemberResult {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
    pub ratchet_tree: Vec<u8>,
}

impl Group {
    pub fn group_id(&self) -> Vec<u8> {
        self.inner.group_id().as_slice().to_vec()
    }

    pub fn epoch(&self) -> u64 {
        self.inner.epoch().as_u64()
    }

    pub fn member_count(&self) -> usize {
        self.inner.members().count()
    }

    /// Adds a member (via their published key package) and immediately
    /// merges the resulting commit into our own state. The commit still
    /// needs to be fanned out to existing members (SPEC.md §5.4) and the
    /// welcome delivered to the new member.
    pub fn add_member(
        &mut self,
        member: &MlsMember,
        their_key_package_bytes: &[u8],
    ) -> Result<AddMemberResult, CryptoError> {
        let key_package_in =
            KeyPackageIn::tls_deserialize(&mut &their_key_package_bytes[..]).map_err(map_err)?;
        let key_package = key_package_in
            .validate(member.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(map_err)?;

        let (commit, welcome_out, _group_info) = self
            .inner
            .add_members(&member.provider, &member.signer, &[key_package])
            .map_err(map_err)?;

        self.inner
            .merge_pending_commit(&member.provider)
            .map_err(map_err)?;

        let ratchet_tree = self.inner.export_ratchet_tree();

        Ok(AddMemberResult {
            commit: commit.tls_serialize_detached().map_err(map_err)?,
            welcome: welcome_out.tls_serialize_detached().map_err(map_err)?,
            ratchet_tree: ratchet_tree.tls_serialize_detached().map_err(map_err)?,
        })
    }

    /// Removes a member by leaf index (as seen in `members()`), producing a
    /// commit that must be fanned out the same way as `add_member`'s.
    pub fn remove_member(
        &mut self,
        member: &MlsMember,
        leaf_index: u32,
    ) -> Result<Vec<u8>, CryptoError> {
        let (commit, _welcome, _group_info) = self
            .inner
            .remove_members(
                &member.provider,
                &member.signer,
                &[LeafNodeIndex::new(leaf_index)],
            )
            .map_err(map_err)?;
        self.inner
            .merge_pending_commit(&member.provider)
            .map_err(map_err)?;
        commit.tls_serialize_detached().map_err(map_err)
    }

    pub fn encrypt(
        &mut self,
        member: &MlsMember,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let out = self
            .inner
            .create_message(&member.provider, &member.signer, plaintext)
            .map_err(map_err)?;
        out.tls_serialize_detached().map_err(map_err)
    }

    /// Processes an incoming MLS message. Application messages return
    /// `Some(plaintext)`; commits (membership changes) are merged into the
    /// group state and return `None`.
    pub fn decrypt(
        &mut self,
        member: &MlsMember,
        message_bytes: &[u8],
    ) -> Result<Option<Vec<u8>>, CryptoError> {
        let msg_in = MlsMessageIn::tls_deserialize(&mut &message_bytes[..]).map_err(map_err)?;
        let protocol_message: ProtocolMessage = match msg_in.extract() {
            MlsMessageBodyIn::PrivateMessage(m) => m.into(),
            MlsMessageBodyIn::PublicMessage(m) => m.into(),
            _ => return Err(CryptoError::NotImplemented("mls: unexpected message type")),
        };

        let processed = self
            .inner
            .process_message(&member.provider, protocol_message)
            .map_err(map_err)?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => Ok(Some(app_msg.into_bytes())),
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                self.inner
                    .merge_staged_commit(&member.provider, *staged_commit)
                    .map_err(map_err)?;
                Ok(None)
            }
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_members_exchange_a_group_message() {
        let alice = MlsMember::new(b"alice").unwrap();
        let bob = MlsMember::new(b"bob").unwrap();

        let mut alice_group = alice.create_group().unwrap();
        assert_eq!(alice_group.member_count(), 1);

        let bob_kp = bob.generate_key_package().unwrap();
        let added = alice_group.add_member(&alice, &bob_kp).unwrap();
        assert_eq!(alice_group.member_count(), 2);

        let mut bob_group = bob.join_group(&added.welcome, &added.ratchet_tree).unwrap();
        assert_eq!(bob_group.group_id(), alice_group.group_id());
        assert_eq!(bob_group.epoch(), alice_group.epoch());

        let ciphertext = alice_group.encrypt(&alice, b"hello group").unwrap();
        let plaintext = bob_group.decrypt(&bob, &ciphertext).unwrap();
        assert_eq!(plaintext, Some(b"hello group".to_vec()));

        let reply = bob_group.encrypt(&bob, b"hi alice").unwrap();
        let plaintext = alice_group.decrypt(&alice, &reply).unwrap();
        assert_eq!(plaintext, Some(b"hi alice".to_vec()));
    }

    #[test]
    fn adding_a_third_member_advances_the_epoch_for_everyone() {
        let alice = MlsMember::new(b"alice").unwrap();
        let bob = MlsMember::new(b"bob").unwrap();
        let carol = MlsMember::new(b"carol").unwrap();

        let mut alice_group = alice.create_group().unwrap();
        let added = alice_group
            .add_member(&alice, &bob.generate_key_package().unwrap())
            .unwrap();
        let mut bob_group = bob.join_group(&added.welcome, &added.ratchet_tree).unwrap();

        let added2 = alice_group
            .add_member(&alice, &carol.generate_key_package().unwrap())
            .unwrap();

        // Bob must process Alice's commit to stay in sync before Carol can
        // be considered joined from his point of view.
        bob_group.decrypt(&bob, &added2.commit).unwrap();

        let carol_group = carol
            .join_group(&added2.welcome, &added2.ratchet_tree)
            .unwrap();

        assert_eq!(alice_group.epoch(), bob_group.epoch());
        assert_eq!(alice_group.epoch(), carol_group.epoch());
        assert_eq!(alice_group.member_count(), 3);
    }

    #[test]
    fn removed_member_can_no_longer_be_reasoned_about_as_current() {
        let alice = MlsMember::new(b"alice").unwrap();
        let bob = MlsMember::new(b"bob").unwrap();

        let mut alice_group = alice.create_group().unwrap();
        alice_group
            .add_member(&alice, &bob.generate_key_package().unwrap())
            .unwrap();
        assert_eq!(alice_group.member_count(), 2);

        let bob_leaf_index = alice_group
            .inner
            .members()
            .find(|m| m.credential.serialized_content() == b"bob")
            .unwrap()
            .index
            .u32();

        alice_group.remove_member(&alice, bob_leaf_index).unwrap();
        assert_eq!(alice_group.member_count(), 1);
    }
}
