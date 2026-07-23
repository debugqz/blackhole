//! Groups (MLS, RFC 9420), backed by `bh-crypto::mls`. Message send/list
//! for a group conversation needs **no new code at all** —
//! `conversations::send_message`/`list_messages` already work on any
//! `conversation_id`, and `create_group_conversation` (already exercised
//! by `export.rs`'s import path) sets `kind='group'` — only group
//! creation/membership is new here.
//!
//! **Real membership over the network now exists**: when `state.network`
//! is attached, `add_member`/`create_group` fetch the target contact's
//! real, DHT-published MLS key package
//! (`bh_network::key_package_directory`, populated by
//! `mls_key_package.rs`'s own bootstrap/republish logic — see
//! `fetch_real_key_package`), commit the add for real
//! (`commit_real_member_add`), fan the resulting commit out to the group's
//! shared mailbox for already-joined real members
//! (`deliver_real_member_add`), and deliver the `Welcome` to the new
//! member over their existing 1:1 mailbox as a real
//! `Envelope::GroupInvite` (`message_receive.rs`'s handling of it —
//! `handle_group_invite` — is the mirror image of this file's own
//! `create_group`: it joins, persists the own-member/`groups`/
//! `conversations` rows, and caches the live state, then rotates this
//! identity's own now-consumed key package). Proven by a genuine
//! three-daemon test, not a same-process shadow session — see
//! `bh-api/tests/api_smoke.rs`'s
//! `group_membership_and_messages_travel_a_real_network_between_three_daemons`.
//!
//! **Falls back to the pre-existing local simulation** whenever there's no
//! live network, no `Contact` row for the target, or no key package
//! currently published for them (`fetch_real_key_package` returning
//! `None` covers all three uniformly) — this daemon locally generates one
//! persistent "shadow" [`MlsMember`] per contact, scoped to this process,
//! purely to exercise `generate_key_package`/`add_member`/`join_group`/
//! `decrypt` for real. This keeps every existing single-process demo/test
//! working unchanged; it is not part of the persistence story below.
//!
//! MLS state persistence (THREAT_MODEL.md §3.2, ranked #8) is real now:
//! the *own* member for each group is backed by
//! `bh_crypto::mls_storage::PersistentMlsProvider` — a SQLCipher-encrypted
//! database, separate from the messaging/payments databases, opened via
//! `AppState::mls_provider` — instead of `openmls`'s in-memory reference
//! storage. `groups.mls_state` persists that own member's signature public
//! key (the only thing needed to reconstruct the exact same member later
//! via `MlsMember::from_stored_signer`; the group's own ratchet-tree/epoch
//! state is durable on its own in the `PersistentMlsProvider` database,
//! reloaded via `bh_crypto::mls::Group::load`). [`GroupRegistry`] still
//! caches live `Group`/`MlsMember` handles in-process for as long as the
//! daemon keeps running — repeating the reconstruction on every request
//! would be wasteful, not incorrect — but `add_member`/`remove_member`/
//! `mls_self_test` no longer unconditionally 410 after a restart: see
//! [`ensure_live_group_state`], which reconstructs a registry miss from
//! storage before falling through to the in-memory lookup, and only
//! surfaces `GONE` if that reconstruction is itself impossible.
//! `GroupRegistry` is profile-scoped (`AppState::groups`/`ProfileSession
//! ::groups`), resetting on every profile switch the same way `db`/
//! `payments_db` do, so one profile's in-flight group ceremonies can never
//! leak into another's.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use bh_crypto::mls::{Group as MlsGroup, MlsMember};
use bh_crypto::mls_storage::PersistentMlsProvider;
use bh_storage::models::{Conversation, Group as StoredGroup, GroupMember};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};

use crate::AppState;

/// What clients see for a group — deliberately omits `mls_state`, mirroring
/// `files.rs::FileMetaPublic`'s "never round-trip key material into an
/// HTTP response, even on loopback" convention. `mls_state` now holds the
/// group's own-member signature public key (see module doc) — not secret
/// on its own, but there's no reason to round-trip it into an HTTP
/// response either, so it stays out of this DTO exactly as the old
/// placeholder value did.
#[derive(Serialize)]
pub struct GroupPublic {
    pub group_id: String,
    pub name: Option<String>,
    pub epoch: i64,
    pub created_at: i64,
    pub broadcast_only: bool,
}

impl From<StoredGroup> for GroupPublic {
    fn from(g: StoredGroup) -> Self {
        GroupPublic {
            group_id: g.group_id,
            name: g.name,
            epoch: g.epoch,
            created_at: g.created_at,
            broadcast_only: g.broadcast_only,
        }
    }
}

#[derive(Default)]
pub struct GroupRegistry {
    own_members: Mutex<HashMap<String, MlsMember<PersistentMlsProvider>>>,
    live_groups: Mutex<HashMap<String, MlsGroup>>,
    shadow_members: Mutex<HashMap<String, MlsMember<OpenMlsRustCrypto>>>,
    shadow_groups: Mutex<HashMap<(String, String), MlsGroup>>,
    /// Group-mailbox entries (`message_receive.rs`'s group-fan-out polling
    /// phase) already attempted at least once this process's lifetime, so
    /// a message that's never deleted from its shared group mailbox (see
    /// that module's doc comment on why deleting would race other members
    /// still pulling it) isn't re-decrypted every single tick until it
    /// finally TTL-expires. Safe to lose on restart — a stale entry just
    /// gets re-attempted once and (for anything already processed) fails
    /// harmlessly against `openmls`'s own per-epoch/per-generation replay
    /// protection, the same as it would mid-session.
    seen_group_mailbox_ids: Mutex<HashMap<String, std::collections::HashSet<Vec<u8>>>>,
}

impl GroupRegistry {
    /// `true` if `message_id` was already attempted for `group_id` this
    /// process's lifetime — see the field doc above.
    pub(crate) fn already_attempted_group_message(
        &self,
        group_id: &str,
        message_id: &[u8],
    ) -> bool {
        self.seen_group_mailbox_ids
            .lock()
            .expect(LOCK_POISON_MSG)
            .get(group_id)
            .is_some_and(|seen| seen.contains(message_id))
    }

    pub(crate) fn mark_group_message_attempted(&self, group_id: &str, message_id: Vec<u8>) {
        self.seen_group_mailbox_ids
            .lock()
            .expect(LOCK_POISON_MSG)
            .entry(group_id.to_string())
            .or_default()
            .insert(message_id);
    }

    /// Caches a just-joined group's own member/live state in-process —
    /// used by `message_receive.rs`'s real `GroupInvite` handling right
    /// after persisting it, mirroring what `create_group` does for its own
    /// in-process cache-insert on the inviter's side. Without this, the
    /// very first `send_message`/`add_member`/`mls_self_test` call against
    /// this group would still work (`ensure_live_group_state` reconstructs
    /// a cache miss from storage), just via an avoidable extra reload.
    pub(crate) fn cache_own_member_and_group(
        &self,
        group_id: &str,
        own_member: MlsMember<PersistentMlsProvider>,
        group: MlsGroup,
    ) {
        self.own_members
            .lock()
            .expect(LOCK_POISON_MSG)
            .insert(group_id.to_string(), own_member);
        self.live_groups
            .lock()
            .expect(LOCK_POISON_MSG)
            .insert(group_id.to_string(), group);
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

const LOCK_POISON_MSG: &str = "groups registry lock poisoned";

/// Ensures a shadow `MlsMember` exists for this contact, scoped to this
/// process — see module doc for why this stands in for a real remote
/// member. Every `MlsMember` method only needs `&self`, so (unlike
/// `Group`, which needs `&mut self` to advance) shadow members can stay in
/// the registry the whole time — no take/restore dance needed.
fn ensure_shadow_member(state: &AppState, contact_id: &str) -> Result<(), StatusCode> {
    let registry = state.groups();
    let mut shadow_members = registry.shadow_members.lock().expect(LOCK_POISON_MSG);
    if !shadow_members.contains_key(contact_id) {
        let member =
            MlsMember::new(contact_id.as_bytes()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        shadow_members.insert(contact_id.to_string(), member);
    }
    Ok(())
}

/// If `group_id`'s own live member + group state isn't already cached in
/// this process's [`GroupRegistry`], reconstructs it from persistent
/// storage: the group's own-member signer key (persisted in the `groups`
/// DB row's `mls_state` column) plus the group's own ratchet-tree/epoch
/// state (persisted independently by `openmls` itself in the
/// `PersistentMlsProvider` database, reloaded via
/// `bh_crypto::mls::Group::load`). This is what used to be an
/// unconditional `410 GONE` before this process had re-created the group's
/// live state at least once (THREAT_MODEL.md §3.2) — now it's only `GONE`
/// if reconstruction is genuinely impossible: no own identity, the group
/// doesn't exist, or its own-member signer key was never persisted.
fn ensure_live_group_state(state: &AppState, group_id: &str) -> Result<(), StatusCode> {
    {
        let registry = state.groups();
        let own_members = registry.own_members.lock().expect(LOCK_POISON_MSG);
        let live_groups = registry.live_groups.lock().expect(LOCK_POISON_MSG);
        if own_members.contains_key(group_id) && live_groups.contains_key(group_id) {
            return Ok(());
        }
    }

    let own = state
        .db()
        .get_own_identity()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::GONE)?;
    let stored_group = state
        .db()
        .get_group(group_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::GONE)?;
    if stored_group.mls_state.is_empty() {
        // Nothing was ever persisted for this group's own member — there
        // is genuinely nothing to reconstruct from.
        return Err(StatusCode::GONE);
    }
    let group_id_bytes = hex::decode(group_id).map_err(|_| StatusCode::GONE)?;

    let provider = state.mls_provider().map_err(|_| StatusCode::GONE)?;
    let own_member =
        MlsMember::from_stored_signer(&own.identity_public_key, provider, &stored_group.mls_state)
            .map_err(|_| StatusCode::GONE)?;
    let group = MlsGroup::load(own_member.provider(), &group_id_bytes)
        .map_err(|_| StatusCode::GONE)?
        .ok_or(StatusCode::GONE)?;

    let registry = state.groups();
    registry
        .own_members
        .lock()
        .expect(LOCK_POISON_MSG)
        .insert(group_id.to_string(), own_member);
    registry
        .live_groups
        .lock()
        .expect(LOCK_POISON_MSG)
        .insert(group_id.to_string(), group);
    Ok(())
}

/// Encrypts `plaintext` as this profile's own member of `group_id`'s live
/// group state (reconstructing it from storage first if needed — see
/// [`ensure_live_group_state`]). Used by `conversations::send_message`'s
/// `Group` arm to produce real MLS ciphertext before fanning it out over
/// the network via `Mailbox::fan_out`.
pub(crate) fn encrypt_group_message(
    state: &AppState,
    group_id: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, StatusCode> {
    ensure_live_group_state(state, group_id)?;
    let registry = state.groups();
    let own_members = registry.own_members.lock().expect(LOCK_POISON_MSG);
    let mut live_groups = registry.live_groups.lock().expect(LOCK_POISON_MSG);
    let own_member = own_members.get(group_id).ok_or(StatusCode::GONE)?;
    let group = live_groups.get_mut(group_id).ok_or(StatusCode::GONE)?;
    group
        .encrypt(own_member, plaintext)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Decrypts an incoming MLS message (application message or commit) for
/// `group_id`'s live group state, reporting the sender's identity bytes
/// alongside the plaintext (`None` for a merged commit — see
/// `bh_crypto::mls::Group::decrypt_with_sender`). Used by
/// `message_receive.rs`'s group-mailbox polling phase.
pub(crate) fn decrypt_group_message(
    state: &AppState,
    group_id: &str,
    message_bytes: &[u8],
) -> Result<bh_crypto::mls::DecryptedMessage, StatusCode> {
    ensure_live_group_state(state, group_id)?;
    let registry = state.groups();
    let own_members = registry.own_members.lock().expect(LOCK_POISON_MSG);
    let mut live_groups = registry.live_groups.lock().expect(LOCK_POISON_MSG);
    let own_member = own_members.get(group_id).ok_or(StatusCode::GONE)?;
    let group = live_groups.get_mut(group_id).ok_or(StatusCode::GONE)?;
    group
        .decrypt_with_sender(own_member, message_bytes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Looks up whether `contact_id` can be added over the real network right
/// now: a live `state.network`, a known `Contact` row, and a currently-
/// published MLS key package for them. Deliberately takes **no**
/// `MlsGroup`/`MlsMember` reference — those types hold non-`Sync` internals
/// (`PersistentMlsProvider`'s SQLCipher connection), and every `axum`
/// handler's future must be `Send`; a shared reference to a non-`Sync` type
/// held across an `.await` breaks that. Keeping this lookup entirely
/// separate from the group/member state (which the *caller* holds as
/// owned, not borrowed, locals — see `create_group`/`add_member`) is what
/// keeps the callers' futures Send-safe. Returns `None` (meaning: use the
/// local shadow-member simulation, see module doc) for any of "no live
/// network," "not a contact," or "no key package published" — the caller
/// doesn't need to distinguish which.
async fn fetch_real_key_package(
    state: &AppState,
    contact_id: &str,
) -> Option<(bh_storage::models::Contact, Vec<u8>)> {
    let network = state.network.as_ref()?;
    let contact = state.db().get_contact(contact_id).ok().flatten()?;
    let key_hash = bh_crypto::identity::recipient_key_hash(&contact.identity_public_key);
    let key_package_bytes =
        bh_network::key_package_directory::fetch_key_package(&network.dht(), &key_hash)
            .await
            .ok()
            .flatten()?;
    Some((contact, key_package_bytes))
}

/// Adds one contact to a live group: the real-network path if `real` (from
/// [`fetch_real_key_package`], already awaited by the caller) has one,
/// otherwise the local "shadow member" simulation (see module doc). A
/// macro, not a function, because the real path's MLS commit
/// ([`commit_real_member_add`]) must stay synchronous while its delivery
/// ([`deliver_real_member_add`]) is async — see
/// [`commit_real_member_add`]'s doc comment for why no function taking
/// `&mut MlsGroup`/`&MlsMember<P>` can itself be `async` here, which rules
/// out wrapping this whole match in one ordinary function.
macro_rules! add_contact_to_live_group {
    ($state:expr, $group_id:expr, $group:expr, $own_member:expr, $contact_id:expr, $real:expr) => {
        match $real {
            Some((contact, key_package_bytes)) => {
                let network = $state
                    .network
                    .as_ref()
                    .expect("fetch_real_key_package only returns Some when state.network is Some")
                    .clone();
                match commit_real_member_add($group, $own_member, &key_package_bytes) {
                    Ok((added, own_signer_public_key, new_epoch)) => {
                        deliver_real_member_add(
                            $state,
                            &network,
                            $group_id,
                            &contact,
                            added,
                            own_signer_public_key,
                            new_epoch,
                        )
                        .await
                    }
                    Err(err) => Err(err),
                }
            }
            None => add_shadow_contact_to_live_group(
                $state,
                $group_id,
                $group,
                $own_member,
                $contact_id,
            ),
        }
    };
}

/// The synchronous half of the real-network add path: commits the add on
/// `group` using `contact`'s real, DHT-fetched key package, returning
/// everything the async delivery half needs as owned values. **Must stay
/// synchronous — no `.await` anywhere in this function or anything it
/// calls.** `MlsGroup`/`MlsMember<PersistentMlsProvider>` hold non-`Sync`
/// internals (`PersistentMlsProvider`'s SQLCipher connection uses
/// `RefCell`), and rustc's async-fn lowering captures a borrowed parameter
/// as part of an `async fn`'s returned future *unconditionally* — not just
/// when a liveness analysis proves it's still needed across some later
/// `.await` — because the future's own type must be valid for the entire
/// borrow's lifetime by construction. So `&mut MlsGroup`/`&MlsMember<P>`
/// can never appear in the signature of any `async fn` reachable from an
/// `axum` handler (whose future must be `Send`) even if that function's
/// body never actually holds them across its own internal await points.
/// This is why the add is split into this sync half and
/// [`deliver_real_member_add`] (no MLS types in its signature at all)
/// rather than being one `async fn` the way the shadow path's
/// [`add_shadow_contact_to_live_group`] can afford to be.
fn commit_real_member_add<P: OpenMlsProvider>(
    group: &mut MlsGroup,
    own_member: &MlsMember<P>,
    key_package_bytes: &[u8],
) -> Result<(bh_crypto::mls::AddMemberResult, Vec<u8>, i64), StatusCode> {
    let added = group
        .add_member(own_member, key_package_bytes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let own_signer_public_key = own_member.signature_public_key();
    let new_epoch = group.epoch() as i64;
    Ok((added, own_signer_public_key, new_epoch))
}

/// The async half of the real-network add path (see
/// [`commit_real_member_add`]'s doc comment for why the split is
/// necessary): fans the commit out to the group's shared mailbox (so every
/// other already-joined *real* member converges —
/// `message_receive.rs`'s group-mailbox polling phase), delivers the
/// `Welcome` to `contact` over their existing 1:1 mailbox
/// (`Envelope::GroupInvite`, riding the same X3DH/Double-Ratchet session
/// `message_crypto::send_encrypted_over_network` already establishes for
/// Direct messages — adding someone to a group presupposes they're already
/// a contact), and persists local state exactly like the shadow path does.
#[allow(clippy::too_many_arguments)]
async fn deliver_real_member_add(
    state: &AppState,
    network: &bh_network::supervised::SupervisedNetwork,
    group_id: &str,
    contact: &bh_storage::models::Contact,
    added: bh_crypto::mls::AddMemberResult,
    own_signer_public_key: Vec<u8>,
    new_epoch: i64,
) -> Result<(), StatusCode> {
    let group_id_bytes = hex::decode(group_id).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let sent_at = now();
    let commit_message_id = uuid::Uuid::new_v4().to_string();
    let pow = bh_network::mailbox::Mailbox::solve_pow(
        &group_id_bytes,
        commit_message_id.as_bytes(),
        &added.commit,
        sent_at,
    );
    network
        .mailbox()
        .fan_out(
            &group_id_bytes,
            commit_message_id.as_bytes(),
            added.commit.clone(),
            crate::message_crypto::MAILBOX_TTL_SECONDS,
            sent_at,
            &pow,
        )
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    let stored_group = state
        .db()
        .get_group(group_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let invite_message_id = uuid::Uuid::new_v4().to_string();
    let invite_bytes = bh_crypto::envelope::Envelope::GroupInvite {
        group_id: group_id.to_string(),
        name: stored_group.name.clone(),
        welcome: added.welcome,
        ratchet_tree: added.ratchet_tree,
        broadcast_only: stored_group.broadcast_only,
    }
    .encode()
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    crate::message_crypto::send_encrypted_over_network(
        state,
        network,
        contact,
        &invite_message_id,
        &invite_bytes,
    )
    .await?;

    state
        .db()
        .add_group_member(group_id, &contact.contact_id, now())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .db()
        .update_group_state(group_id, &own_signer_public_key, new_epoch)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(())
}

/// The pre-existing local simulation (see module doc): publishes a shadow
/// key package, commits the add on `group`, fans that commit out to every
/// already-joined shadow member (so they stay in sync — mirrors
/// `bh-crypto::mls`'s own `adding_a_third_member_advances_the_epoch_for_
/// everyone` test), and has the new shadow member join from the resulting
/// welcome. Persists the own member's signature public key as `mls_state`
/// — see module doc for why that (not any group secret) is what needs to
/// round-trip through storage.
fn add_shadow_contact_to_live_group<P: OpenMlsProvider>(
    state: &AppState,
    group_id: &str,
    group: &mut MlsGroup,
    own_member: &MlsMember<P>,
    contact_id: &str,
) -> Result<(), StatusCode> {
    ensure_shadow_member(state, contact_id)?;
    let registry = state.groups();

    let key_package = {
        let shadow_members = registry.shadow_members.lock().expect(LOCK_POISON_MSG);
        shadow_members
            .get(contact_id)
            .expect("just ensured")
            .generate_key_package()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    };

    let added = group
        .add_member(own_member, &key_package)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    {
        let shadow_members = registry.shadow_members.lock().expect(LOCK_POISON_MSG);
        let mut shadow_groups = registry.shadow_groups.lock().expect(LOCK_POISON_MSG);
        for ((gid, cid), shadow_group) in shadow_groups.iter_mut() {
            if gid != group_id || cid == contact_id {
                continue;
            }
            if let Some(shadow_member) = shadow_members.get(cid) {
                // Best-effort: a member that's somehow already desynced
                // stays desynced (surfaced by mls_self_test), not a hard
                // failure for the member actually being added here.
                let _ = shadow_group.decrypt(shadow_member, &added.commit);
            }
        }
    }

    let joined = {
        let shadow_members = registry.shadow_members.lock().expect(LOCK_POISON_MSG);
        shadow_members
            .get(contact_id)
            .expect("just ensured")
            .join_group(&added.welcome, &added.ratchet_tree)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    };
    registry
        .shadow_groups
        .lock()
        .expect(LOCK_POISON_MSG)
        .insert((group_id.to_string(), contact_id.to_string()), joined);

    state
        .db()
        .add_group_member(group_id, contact_id, now())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .db()
        .update_group_state(
            group_id,
            &own_member.signature_public_key(),
            group.epoch() as i64,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(())
}

pub async fn list_groups(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<GroupPublic>>, StatusCode> {
    state
        .db()
        .list_groups()
        .map(|groups| Json(groups.into_iter().map(Into::into).collect()))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    pub name: Option<String>,
    pub member_contact_ids: Vec<String>,
    /// `"group"` (default) or `"broadcast"` — a broadcast channel is the
    /// same MLS group with posting restricted to its owner (this daemon,
    /// since it's always the creator). Unrecognized values are rejected
    /// rather than silently treated as `"group"`.
    #[serde(default)]
    pub kind: Option<String>,
}

#[derive(Serialize)]
pub struct CreateGroupResponse {
    pub conversation: Conversation,
    pub group: GroupPublic,
    pub members: Vec<GroupMember>,
}

pub async fn create_group(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<CreateGroupResponse>, StatusCode> {
    let broadcast_only = match req.kind.as_deref() {
        None | Some("group") => false,
        Some("broadcast") => true,
        Some(_) => return Err(StatusCode::BAD_REQUEST),
    };

    let own = state
        .db()
        .get_own_identity()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::PRECONDITION_FAILED)?;
    let provider = state
        .mls_provider()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let own_member = MlsMember::new_persistent(&own.identity_public_key, provider)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let signer_public_key = own_member.signature_public_key();
    let mut group = own_member
        .create_group()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let group_id = hex::encode(group.group_id());
    let conversation_id = uuid::Uuid::new_v4().to_string();
    let created_at = now();

    state
        .db()
        .create_group(&StoredGroup {
            group_id: group_id.clone(),
            name: req.name.clone(),
            mls_state: signer_public_key,
            epoch: group.epoch() as i64,
            created_at,
            broadcast_only,
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .db()
        .create_group_conversation(&conversation_id, &group_id, created_at)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    for contact_id in &req.member_contact_ids {
        let real = fetch_real_key_package(&state, contact_id).await;
        add_contact_to_live_group!(&state, &group_id, &mut group, &own_member, contact_id, real)?;
    }

    state
        .groups()
        .own_members
        .lock()
        .expect(LOCK_POISON_MSG)
        .insert(group_id.clone(), own_member);
    state
        .groups()
        .live_groups
        .lock()
        .expect(LOCK_POISON_MSG)
        .insert(group_id.clone(), group);

    let conversation = state
        .db()
        .get_conversation(&conversation_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let stored_group = state
        .db()
        .get_group(&group_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let members = state
        .db()
        .list_group_members(&group_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(CreateGroupResponse {
        conversation,
        group: stored_group.into(),
        members,
    }))
}

#[derive(Serialize)]
pub struct GroupDetail {
    pub group: GroupPublic,
    pub members: Vec<GroupMember>,
}

pub async fn get_group(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<String>,
) -> Result<Json<GroupDetail>, StatusCode> {
    let group = state
        .db()
        .get_group(&group_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let members = state
        .db()
        .list_group_members(&group_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(GroupDetail {
        group: group.into(),
        members,
    }))
}

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub contact_id: String,
}

pub async fn add_member(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> Result<StatusCode, StatusCode> {
    ensure_live_group_state(&state, &group_id)?;

    // Taken out of the registry (not just locked) for the duration of the
    // real-network `.await` inside `add_contact_to_live_group` below —
    // holding a `std::sync::MutexGuard` across an await point is both a
    // compile error (the guard isn't `Send`) and, even if it weren't,
    // would block every other request touching this group registry for
    // the length of a network round trip. Always restored afterward
    // (success or failure) so a failed add doesn't strand the group's live
    // state — the next request would otherwise see a spurious `410 GONE`
    // for a group that's actually still fine.
    let real = fetch_real_key_package(&state, &req.contact_id).await;

    let registry = state.groups();
    let (own_member, mut group) = {
        let mut own_members = registry.own_members.lock().expect(LOCK_POISON_MSG);
        let mut live_groups = registry.live_groups.lock().expect(LOCK_POISON_MSG);
        let own_member = own_members.remove(&group_id).ok_or(StatusCode::GONE)?;
        let group = live_groups.remove(&group_id).ok_or(StatusCode::GONE)?;
        (own_member, group)
    };

    let result = add_contact_to_live_group!(
        &state,
        &group_id,
        &mut group,
        &own_member,
        &req.contact_id,
        real
    );

    registry
        .own_members
        .lock()
        .expect(LOCK_POISON_MSG)
        .insert(group_id.clone(), own_member);
    registry
        .live_groups
        .lock()
        .expect(LOCK_POISON_MSG)
        .insert(group_id, group);

    result?;
    Ok(StatusCode::OK)
}

pub async fn remove_member(
    State(state): State<Arc<AppState>>,
    Path((group_id, contact_id)): Path<(String, String)>,
) -> Result<StatusCode, StatusCode> {
    ensure_live_group_state(&state, &group_id)?;

    let registry = state.groups();
    let own_members = registry.own_members.lock().expect(LOCK_POISON_MSG);
    let mut live_groups = registry.live_groups.lock().expect(LOCK_POISON_MSG);
    let own_member = own_members.get(&group_id).ok_or(StatusCode::GONE)?;
    let group = live_groups.get_mut(&group_id).ok_or(StatusCode::GONE)?;

    let leaf_index = group
        .members()
        .into_iter()
        .find(|m| m.identity == contact_id.as_bytes())
        .map(|m| m.leaf_index)
        .ok_or(StatusCode::NOT_FOUND)?;
    let commit = group
        .remove_member(own_member, leaf_index)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .db()
        .remove_group_member(&group_id, &contact_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .db()
        .update_group_state(
            &group_id,
            &own_member.signature_public_key(),
            group.epoch() as i64,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // The remaining members must process the removal commit to stay in
    // sync (same reasoning as the add path in `add_contact_to_live_group`)
    // before the removed contact's own shadow group view is dropped.
    {
        let registry = state.groups();
        let shadow_members = registry.shadow_members.lock().expect(LOCK_POISON_MSG);
        let mut shadow_groups = registry.shadow_groups.lock().expect(LOCK_POISON_MSG);
        for ((gid, cid), shadow_group) in shadow_groups.iter_mut() {
            if gid != &group_id || cid == &contact_id {
                continue;
            }
            if let Some(shadow_member) = shadow_members.get(cid) {
                let _ = shadow_group.decrypt(shadow_member, &commit);
            }
        }
        shadow_groups.remove(&(group_id.clone(), contact_id));
    }

    Ok(StatusCode::OK)
}

#[derive(Serialize)]
pub struct MlsSelfTestResponse {
    pub roundtrip_ok: bool,
    pub confirmed_members: Vec<String>,
}

/// Encrypts a fixed ping as the local member and decrypts it as every
/// shadow member currently joined to this group — an explicit proof that
/// the real MLS crypto path works for the group's current membership,
/// decoupled from normal (still-plaintext, DB-only) message send exactly
/// like 1:1 messaging never exercises the Double Ratchet today.
pub async fn mls_self_test(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<String>,
) -> Result<Json<MlsSelfTestResponse>, StatusCode> {
    const PING: &[u8] = b"mls-self-test-ping";

    ensure_live_group_state(&state, &group_id)?;

    let registry = state.groups();
    let own_members = registry.own_members.lock().expect(LOCK_POISON_MSG);
    let mut live_groups = registry.live_groups.lock().expect(LOCK_POISON_MSG);
    let own_member = own_members.get(&group_id).ok_or(StatusCode::GONE)?;
    let group = live_groups.get_mut(&group_id).ok_or(StatusCode::GONE)?;

    let ciphertext = group
        .encrypt(own_member, PING)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let shadow_members = registry.shadow_members.lock().expect(LOCK_POISON_MSG);
    let mut shadow_groups = registry.shadow_groups.lock().expect(LOCK_POISON_MSG);

    let member_ids: Vec<String> = shadow_groups
        .keys()
        .filter(|(gid, _)| gid == &group_id)
        .map(|(_, cid)| cid.clone())
        .collect();

    let mut confirmed_members = Vec::new();
    for contact_id in &member_ids {
        let key = (group_id.clone(), contact_id.clone());
        let (Some(shadow_group), Some(shadow_member)) =
            (shadow_groups.get_mut(&key), shadow_members.get(contact_id))
        else {
            continue;
        };
        if let Ok(Some(plaintext)) = shadow_group.decrypt(shadow_member, &ciphertext) {
            if plaintext == PING {
                confirmed_members.push(contact_id.clone());
            }
        }
    }

    let roundtrip_ok = !member_ids.is_empty() && confirmed_members.len() == member_ids.len();
    Ok(Json(MlsSelfTestResponse {
        roundtrip_ok,
        confirmed_members,
    }))
}
