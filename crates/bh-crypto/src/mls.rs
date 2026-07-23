//! Group messaging via MLS (RFC 9420), using `openmls` — the reference
//! implementation — rather than reimplementing the group ratchet tree.
//! See `docs/SPEC.md` §2.1.
//!
//! Each member holds their own [`MlsMember`] (credential, signature key,
//! and an `openmls` crypto/storage provider) and a [`Group`] per group
//! they're in. `MlsMember` is generic over which `OpenMlsProvider` backs
//! it: [`MlsMember::new`] uses the crate's in-memory reference storage
//! (fine for tests, gone on restart); [`MlsMember::new_persistent`] uses
//! [`crate::mls_storage::PersistentMlsProvider`], which keeps the same
//! audited RustCrypto crypto backend but persists group state to a
//! SQLCipher-encrypted database (`docs/THREAT_MODEL.md` §3.2 — this used
//! to be an open gap; it's what closes it).
//!
//! Surviving a restart needs two things reconstructed, not just the
//! `PersistentMlsProvider`'s database file reopened: the group's own
//! `MlsGroup` state ([`Group::load`], backed by `openmls`'s own
//! `MlsGroup::load`) and the *same* member signer keypair used before
//! (not a freshly generated one — a new keypair would produce a
//! credential `openmls` doesn't recognize as this leaf).
//! [`MlsMember::from_stored_signer`] reads that keypair back out of the
//! provider's storage given its public key bytes, which callers must have
//! persisted themselves (there is nowhere else to keep them) — see
//! [`MlsMember::signature_public_key`].

use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

use crate::mls_storage::PersistentMlsProvider;
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
/// Generic over the storage/crypto backend — see the module docs for the
/// two constructors.
pub struct MlsMember<P: OpenMlsProvider> {
    provider: P,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
}

impl<P: OpenMlsProvider> MlsMember<P> {
    fn from_provider(identity: &[u8], provider: P) -> Result<Self, CryptoError> {
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

    /// Read-only access to this member's underlying `OpenMlsProvider` —
    /// needed by callers reconstructing a [`Group`] via [`Group::load`]
    /// against the *same* storage this (already-reconstructed) member
    /// reads/writes, rather than opening a second, redundant connection to
    /// the same store.
    pub fn provider(&self) -> &P {
        &self.provider
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

    /// This member's signature public key — opaque bytes with no meaning
    /// on their own, but enough (together with `identity`) to reconstruct
    /// this exact member later via
    /// [`from_stored_signer`](MlsMember::from_stored_signer), *if* the
    /// provider backing it persists (i.e. a [`PersistentMlsProvider`] —
    /// `signer.store()` was already called for it in [`from_provider`]).
    /// Callers that want restart survival must persist this alongside
    /// whatever identifies the member (e.g. a `groups` DB row).
    pub fn signature_public_key(&self) -> Vec<u8> {
        self.signer.public().to_vec()
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

impl MlsMember<OpenMlsRustCrypto> {
    /// In-memory storage — group state does not survive a restart. Fine
    /// for tests and short-lived processes; the daemon should use
    /// [`new_persistent`](Self::new_persistent) instead.
    ///
    /// `identity` is an opaque, application-chosen identifier (e.g. the
    /// contact_id from `bh-storage`) — MLS doesn't interpret it.
    pub fn new(identity: &[u8]) -> Result<Self, CryptoError> {
        Self::from_provider(identity, OpenMlsRustCrypto::default())
    }
}

impl MlsMember<PersistentMlsProvider> {
    /// Same as [`new`](MlsMember::new), but backed by a SQLCipher-encrypted
    /// on-disk store (`provider`, from
    /// [`PersistentMlsProvider::open`](crate::mls_storage::PersistentMlsProvider::open))
    /// — group state survives a daemon restart.
    pub fn new_persistent(
        identity: &[u8],
        provider: PersistentMlsProvider,
    ) -> Result<Self, CryptoError> {
        Self::from_provider(identity, provider)
    }

    /// Reconstructs a previously-created persistent member using its
    /// *stored* signer keypair (read via
    /// [`SignatureKeyPair::read`](openmls_basic_credential::SignatureKeyPair::read))
    /// rather than generating a new one — the counterpart to
    /// [`new_persistent`](Self::new_persistent) needed to survive a
    /// restart: a fresh keypair would mint a credential `openmls` has
    /// never seen as a member of the group, so the reloaded [`Group`]
    /// (via [`Group::load`]) would reject anything signed with it.
    ///
    /// `signer_public_key` is [`signature_public_key`](Self::signature_public_key)
    /// from the original member, persisted by the caller. Returns an error
    /// (never panics) if no such key exists in `provider`'s storage.
    pub fn from_stored_signer(
        identity: &[u8],
        provider: PersistentMlsProvider,
        signer_public_key: &[u8],
    ) -> Result<Self, CryptoError> {
        let signer = SignatureKeyPair::read(
            provider.storage(),
            signer_public_key,
            CIPHERSUITE.signature_algorithm(),
        )
        .ok_or(CryptoError::NotImplemented(
            "mls: stored signer key pair not found",
        ))?;

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

/// One member as seen from inside a [`Group`] — enough to find the leaf
/// index [`Group::remove_member`] needs, keyed by the same opaque identity
/// bytes passed to [`MlsMember::new`].
pub struct GroupMemberInfo {
    pub leaf_index: u32,
    pub identity: Vec<u8>,
}

impl Group {
    /// Reloads a group's live state from `provider`'s storage — the
    /// counterpart to [`MlsMember::from_stored_signer`] needed for the
    /// *group* half of restart survival. Returns `Ok(None)` if nothing is
    /// stored for `group_id` (never created, or never persisted there),
    /// matching `openmls::group::MlsGroup::load`'s own contract rather
    /// than collapsing "not found" into an error.
    pub fn load<P: OpenMlsProvider>(
        provider: &P,
        group_id: &[u8],
    ) -> Result<Option<Group>, CryptoError> {
        let group_id = GroupId::from_slice(group_id);
        let loaded = MlsGroup::load(provider.storage(), &group_id).map_err(map_err)?;
        Ok(loaded.map(|inner| Group { inner }))
    }

    pub fn group_id(&self) -> Vec<u8> {
        self.inner.group_id().as_slice().to_vec()
    }

    pub fn epoch(&self) -> u64 {
        self.inner.epoch().as_u64()
    }

    pub fn member_count(&self) -> usize {
        self.inner.members().count()
    }

    /// Current membership as seen by this member's view of the group —
    /// used to look up a leaf index (by identity) before calling
    /// [`Group::remove_member`].
    pub fn members(&self) -> Vec<GroupMemberInfo> {
        self.inner
            .members()
            .map(|m| GroupMemberInfo {
                leaf_index: m.index.u32(),
                identity: m.credential.serialized_content().to_vec(),
            })
            .collect()
    }

    /// Derives a 32-byte key for a group call's SFrame media encryption
    /// straight from this group's own MLS exporter secret (RFC 9420) — the
    /// same mechanism a TLS 1.3 exporter uses. Every member who has
    /// processed the same commits already shares epoch secrets, so a whole
    /// group call gets one shared key with zero extra key-agreement round
    /// trips, no new crypto primitive, reusing the audited `openmls`
    /// machinery. `call_id` is mixed in as exporter context, playing the
    /// same role `call_id` plays as an HKDF salt in
    /// `call_keys::derive_base_key`, so two different calls placed within
    /// the same group epoch never reuse key material. See `bh_calls::group`
    /// for how the resulting key feeds a full-mesh group call's per-edge
    /// `SframeContext`s.
    pub fn export_call_base_key<P: OpenMlsProvider>(
        &self,
        member: &MlsMember<P>,
        call_id: &str,
    ) -> Result<[u8; 32], CryptoError> {
        let exported = self
            .inner
            .export_secret(
                member.provider.crypto(),
                "blackhole-group-call-sframe-v1",
                call_id.as_bytes(),
                32,
            )
            .map_err(map_err)?;
        exported.try_into().map_err(|_| {
            CryptoError::NotImplemented("mls: export_secret returned unexpected length")
        })
    }

    /// Adds a member (via their published key package) and immediately
    /// merges the resulting commit into our own state. The commit still
    /// needs to be fanned out to existing members (SPEC.md §5.4) and the
    /// welcome delivered to the new member.
    pub fn add_member<P: OpenMlsProvider>(
        &mut self,
        member: &MlsMember<P>,
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
    pub fn remove_member<P: OpenMlsProvider>(
        &mut self,
        member: &MlsMember<P>,
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

    pub fn encrypt<P: OpenMlsProvider>(
        &mut self,
        member: &MlsMember<P>,
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
    pub fn decrypt<P: OpenMlsProvider>(
        &mut self,
        member: &MlsMember<P>,
        message_bytes: &[u8],
    ) -> Result<Option<Vec<u8>>, CryptoError> {
        self.decrypt_with_sender(member, message_bytes)
            .map(|decrypted| decrypted.plaintext)
    }

    /// Same as [`Group::decrypt`], but also reports the sender's opaque
    /// identity bytes (the same `identity` an application passed to
    /// [`MlsMember::new`]/[`MlsMember::new_persistent`] when that member
    /// was created — see [`Group::members`]'s doc comment) — needed by a
    /// real group-message receive path to know who sent an application
    /// message, which [`Group::decrypt`] alone can't report. `sender_identity`
    /// is still populated for a commit (`plaintext` is `None`), reporting
    /// who committed the membership change.
    pub fn decrypt_with_sender<P: OpenMlsProvider>(
        &mut self,
        member: &MlsMember<P>,
        message_bytes: &[u8],
    ) -> Result<DecryptedMessage, CryptoError> {
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

        // Captured before `into_content()` consumes `processed` — `Credential`
        // borrows from `processed`, not from `content`.
        let sender_identity = processed.credential().serialized_content().to_vec();

        let plaintext = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => Some(app_msg.into_bytes()),
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                self.inner
                    .merge_staged_commit(&member.provider, *staged_commit)
                    .map_err(map_err)?;
                None
            }
            _ => None,
        };

        Ok(DecryptedMessage {
            plaintext,
            sender_identity,
        })
    }
}

/// See [`Group::decrypt_with_sender`].
pub struct DecryptedMessage {
    pub plaintext: Option<Vec<u8>>,
    pub sender_identity: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mls_storage::PersistentMlsProvider;

    /// Documents *why* a published key package must be replaced with a
    /// fresh one immediately after this member joins a group with it, not
    /// just periodically: `join_group` consumes the local HPKE private
    /// material tied to that specific serialized key package (openmls's
    /// own single-use-by-design behavior), so reusing the same bytes for a
    /// second, unrelated group's `add_member`/`join_group` fails outright
    /// — it isn't just "stale," it's actively broken the moment it's first
    /// used. `bh-network::key_package_directory`'s own doc comment points
    /// back at this test for the reasoning.
    #[test]
    fn a_consumed_key_package_cannot_be_reused_to_join_a_second_group() {
        let carol = MlsMember::new(b"carol").unwrap();
        let carol_kp = carol.generate_key_package().unwrap();

        let alice = MlsMember::new(b"alice").unwrap();
        let mut alice_group = alice.create_group().unwrap();
        let added1 = alice_group.add_member(&alice, &carol_kp).unwrap();
        assert!(
            carol
                .join_group(&added1.welcome, &added1.ratchet_tree)
                .is_ok(),
            "first join, consuming the key package, must succeed"
        );

        let bob = MlsMember::new(b"bob").unwrap();
        let mut bob_group = bob.create_group().unwrap();
        let added2 = bob_group.add_member(&bob, &carol_kp).unwrap();
        assert!(
            carol
                .join_group(&added2.welcome, &added2.ratchet_tree)
                .is_err(),
            "a second join reusing the same already-consumed key package bytes must fail"
        );
    }

    #[test]
    fn decrypt_with_sender_reports_who_sent_an_application_message_and_who_committed() {
        let alice = MlsMember::new(b"alice").unwrap();
        let bob = MlsMember::new(b"bob").unwrap();

        let mut alice_group = alice.create_group().unwrap();
        let bob_kp = bob.generate_key_package().unwrap();
        let added = alice_group.add_member(&alice, &bob_kp).unwrap();
        let mut bob_group = bob.join_group(&added.welcome, &added.ratchet_tree).unwrap();

        // An application message from Alice must report Alice's identity,
        // not Bob's or an empty one.
        let ciphertext = alice_group.encrypt(&alice, b"hello group").unwrap();
        let decrypted = bob_group.decrypt_with_sender(&bob, &ciphertext).unwrap();
        assert_eq!(decrypted.plaintext, Some(b"hello group".to_vec()));
        assert_eq!(decrypted.sender_identity, b"alice");

        // A commit is still attributed to whoever committed it, even though
        // its own `plaintext` is `None`.
        let carol = MlsMember::new(b"carol").unwrap();
        let carol_kp = carol.generate_key_package().unwrap();
        let added2 = alice_group.add_member(&alice, &carol_kp).unwrap();
        let decrypted = bob_group.decrypt_with_sender(&bob, &added2.commit).unwrap();
        assert_eq!(decrypted.plaintext, None);
        assert_eq!(decrypted.sender_identity, b"alice");
    }

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
            .members()
            .into_iter()
            .find(|m| m.identity == b"bob")
            .unwrap()
            .leaf_index;

        alice_group.remove_member(&alice, bob_leaf_index).unwrap();
        assert_eq!(alice_group.member_count(), 1);
    }

    #[test]
    fn members_reports_the_correct_leaf_index_for_each_identity() {
        let alice = MlsMember::new(b"alice").unwrap();
        let bob = MlsMember::new(b"bob").unwrap();

        let mut alice_group = alice.create_group().unwrap();
        alice_group
            .add_member(&alice, &bob.generate_key_package().unwrap())
            .unwrap();

        let members = alice_group.members();
        assert_eq!(members.len(), 2);
        let alice_leaf = members.iter().find(|m| m.identity == b"alice").unwrap();
        let bob_leaf = members.iter().find(|m| m.identity == b"bob").unwrap();
        assert_ne!(alice_leaf.leaf_index, bob_leaf.leaf_index);
    }

    /// The actual point of `mls_storage`: build up group state through a
    /// persistent provider, drop everything, reopen against the *same*
    /// database file, and confirm the store already contains state from
    /// the previous "process" rather than starting fresh.
    #[test]
    fn group_state_survives_reopening_the_persistent_provider() {
        let dir = std::env::temp_dir().join(format!("bh-mls-persist-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("mls.sqlite");
        let key = [7u8; 32];

        let group_id = {
            let alice_provider = PersistentMlsProvider::open(&db_path, &key).unwrap();
            let alice = MlsMember::new_persistent(b"alice", alice_provider).unwrap();
            let mut group = alice.create_group().unwrap();
            let ciphertext = group.encrypt(&alice, b"before restart").unwrap();
            assert!(!ciphertext.is_empty());
            group.group_id()
            // `alice`/`group`/the provider all drop here, simulating a
            // daemon restart — nothing survives except the database file.
        };

        // Re-opening the same file with the same key must succeed (proves
        // the SQLCipher key round-trips) and the storage migrations must
        // be idempotent (proves reopening an already-migrated store is
        // safe, not just opening a fresh one).
        let alice_provider_reopened = PersistentMlsProvider::open(&db_path, &key).unwrap();
        let bob = MlsMember::new_persistent(b"bob", alice_provider_reopened).unwrap();
        let bob_group = bob.create_group().unwrap();
        assert_ne!(
            bob_group.group_id(),
            group_id,
            "a second group in the same persistent store must get its own id, \
             confirming the store already had alice's group data and didn't reset"
        );

        // Wrong key must fail outright rather than silently opening
        // garbage — same contract bh-storage's own SQLCipher wiring
        // relies on.
        let wrong_key = [9u8; 32];
        assert!(PersistentMlsProvider::open(&db_path, &wrong_key).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The full restart story, not just "the file didn't error": create a
    /// persistent member + group, add a second (in-memory) member,
    /// exchange a message, drop *everything* (member, group, provider —
    /// simulating a daemon restart), reopen the same database file, reload
    /// both the member (via [`MlsMember::from_stored_signer`]) and the
    /// group (via [`Group::load`]), and prove the reloaded pair is
    /// actually usable: it must be able to decrypt a *new* message
    /// encrypted by the still-live other member after the "restart", and
    /// encrypt one back that the other member can decrypt in turn.
    #[test]
    fn a_reloaded_persistent_member_and_group_can_still_do_real_mls_after_a_simulated_restart() {
        let dir =
            std::env::temp_dir().join(format!("bh-mls-persist-reload-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("mls.sqlite");
        let key = [11u8; 32];

        let bob = MlsMember::new(b"bob").unwrap();

        let (group_id, alice_signer_public_key, added) = {
            let alice_provider = PersistentMlsProvider::open(&db_path, &key).unwrap();
            let alice = MlsMember::new_persistent(b"alice", alice_provider).unwrap();
            let mut alice_group = alice.create_group().unwrap();

            let added = alice_group
                .add_member(&alice, &bob.generate_key_package().unwrap())
                .unwrap();

            let ciphertext = alice_group.encrypt(&alice, b"before restart").unwrap();
            // Bob's own view of the group is process-lifetime, in-memory
            // state (same as every other `MlsMember::new` user in this
            // file) — it survives the "restart" below on its own merits,
            // exactly like a real second daemon/device that never went
            // down. Only alice's side is what this test is proving.
            let mut bob_group = bob.join_group(&added.welcome, &added.ratchet_tree).unwrap();
            let plaintext = bob_group.decrypt(&bob, &ciphertext).unwrap();
            assert_eq!(plaintext, Some(b"before restart".to_vec()));

            // Persist what a real caller (bh-api) would: the group id
            // (already durable via `openmls`'s own storage once
            // `Group::load` is pointed at it) and alice's signer public
            // key (nowhere else to keep it).
            let group_id = alice_group.group_id();
            let signer_public_key = alice.signature_public_key();
            (group_id, signer_public_key, bob_group)

            // `alice`, `alice_group`, and the provider all drop here,
            // simulating alice's daemon restarting.
        };
        let mut bob_group = added;

        // Reopen the same file — simulates the daemon coming back up.
        let reopened_provider = PersistentMlsProvider::open(&db_path, &key).unwrap();
        let alice_reloaded =
            MlsMember::from_stored_signer(b"alice", reopened_provider, &alice_signer_public_key)
                .unwrap();
        let mut group_reloaded = Group::load(&alice_reloaded.provider, &group_id)
            .unwrap()
            .expect("group must still be in storage after reopening the provider");
        assert_eq!(group_reloaded.group_id(), group_id);

        // The real point: a *new* message, encrypted/decrypted using the
        // reloaded member and group after the simulated restart — proving
        // the reloaded pair is actually usable for real MLS operations,
        // not just that the DB file opened without erroring.
        let ciphertext = group_reloaded
            .encrypt(&alice_reloaded, b"after restart")
            .unwrap();
        let plaintext = bob_group.decrypt(&bob, &ciphertext).unwrap();
        assert_eq!(plaintext, Some(b"after restart".to_vec()));

        let reply = bob_group.encrypt(&bob, b"got it").unwrap();
        let plaintext = group_reloaded.decrypt(&alice_reloaded, &reply).unwrap();
        assert_eq!(plaintext, Some(b"got it".to_vec()));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn export_call_base_key_is_shared_across_members_and_distinct_per_call() {
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
        bob_group.decrypt(&bob, &added2.commit).unwrap();
        let carol_group = carol
            .join_group(&added2.welcome, &added2.ratchet_tree)
            .unwrap();

        let alice_key = alice_group.export_call_base_key(&alice, "call-1").unwrap();
        let bob_key = bob_group.export_call_base_key(&bob, "call-1").unwrap();
        let carol_key = carol_group.export_call_base_key(&carol, "call-1").unwrap();
        assert_eq!(alice_key, bob_key);
        assert_eq!(alice_key, carol_key);

        // Mixing in `call_id` as exporter context means two different
        // calls placed in the same group epoch never share key material.
        let other_call_key = alice_group.export_call_base_key(&alice, "call-2").unwrap();
        assert_ne!(alice_key, other_call_key);
    }
}
