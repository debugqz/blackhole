# Blackhole Threat Model

This turns `SPEC.md` §1's prose threat model into something concrete enough
to check implementation against: what we're protecting, who we're
protecting it from, and — per subsystem — what could go wrong (STRIDE:
Spoofing, Tampering, Repudiation, Information disclosure, Denial of
service, Elevation of privilege) and whether it's mitigated, partially
mitigated, or an open risk today.

This document describes the **current implementation**, not just the
design intent — where something is a known gap, it says so explicitly
rather than describing the aspirational end state.

---

## 1. Assets

What an attacker might want, roughly in order of severity if compromised:

- **Message/file plaintext** — the actual content of conversations.
- **Long-term identity private keys** — compromise lets an attacker
  impersonate the user indefinitely, including retroactively decrypting
  anything protected only by identity-bound handshakes.
- **Seed phrase** — full account takeover, and it's the *only* recovery
  path (SPEC.md §4), so its loss is also a first-class risk (unrecoverable
  account) not just a disclosure risk.
- **Sender/recipient metadata** — who talks to whom, when, how often, even
  without content.
- **Group membership** — who's in a group, independent of message content.
- **Local device state** — session ratchet state, MLS group state, contact
  list, message history at rest on disk.
- **SQLCipher database key / device signing key** — held in the platform
  keystore (`bh-storage::keystore`); compromise unlocks everything the
  database key protects.

## 2. Adversaries and trust boundaries

| Adversary | Capability assumed | Trusted with |
|---|---|---|
| Passive network observer | Sees encrypted traffic in transit, not endpoints | Nothing |
| Malicious/compromised relay or mailbox node | Runs actual Blackhole node software; can log, delay, drop, or attempt to correlate traffic it handles | Ciphertext + connection metadata *it directly touches* — never sender identity (sealed sender) or plaintext |
| Malicious contact | A real, authenticated conversation partner | Whatever the user chooses to send them — not more |
| Compromised device (post-unlock) | Full access to a device the user has already unlocked | Everything on that device — explicitly **out of scope** per SPEC.md §1 |
| The Blackhole operator/maintainers | Can publish malicious code, but code is open source and (aspirationally, SPEC.md §9) reproducibly built | Nothing, by design — that's the zero-knowledge premise |

**Explicitly out of scope** (SPEC.md §1): an attacker with sustained
physical/root control of an already-unlocked device — OS-level keyloggers,
preinstalled malware, forensic device imaging. No messaging app can
meaningfully defend against that; claiming otherwise would be a false
guarantee.

## 3. Per-subsystem analysis

### 3.1 Identity & 1:1 sessions (`bh-crypto::identity`, `bh-crypto::ratchet`)

- **Spoofing**: an identity key is just a keypair; anyone can generate one
  claiming any display name. Mitigated the same way Signal is: safety
  number / QR verification between contacts (SPEC.md §3) is the actual
  trust anchor, not the display name. **Partially mitigated — Key
  Transparency primitive now exists, not yet deployed**: `bh_crypto::
  key_transparency` implements RFC 6962's Merkle tree hash, inclusion
  proofs, and consistency proofs from scratch (domain-separated leaf/node
  hashing, exhaustively tested across tree sizes 1-32 and all valid
  leaf/size-pair combinations, plus negative cases for tampered proofs,
  wrong leaves, wrong roots, and rewritten/reordered history). What's
  still missing is the network side: a service that actually gossips
  signed tree heads and lets a client fetch/verify a contact's current key
  against them. Until that exists, this module is a tested building block,
  not a deployed defense — MITM detection in practice is still
  manual-verification-only.
- **Tampering**: X3DH's signed prekey is Ed25519-signed by the identity key
  and verified before use (`ratchet.rs::PreKeyBundle::verify_signed_prekey`,
  tested). Double Ratchet messages are AEAD-authenticated
  (ChaCha20-Poly1305) with the ratchet header as associated data — tested
  against tampering and wrong-AD in `ratchet.rs` tests.
- **Information disclosure**: forward secrecy via the ratchet (each message
  key used once, chain keys deleted after use) and post-compromise security
  via DH ratchet steps — both are inherent to a correct Double Ratchet
  implementation and covered by the "survives many ratchet steps" test.
- **Denial of service**: `MAX_SKIP` bounds how many out-of-order message
  keys get cached per session, so a peer can't force unbounded memory
  growth by sending a message with a huge counter gap.
- **Known gap**: this is a from-scratch implementation of the public X3DH/
  Double Ratchet algorithms (not Signal's own `libsignal`), composed from
  audited primitives — see `bh-crypto/Cargo.toml` for why. It has not had
  independent cryptographic review. Treat it as "implements the right
  algorithm, unreviewed" rather than "as trusted as libsignal."

### 3.2 Groups (`bh-crypto::mls`)

- Uses `openmls`, the reference MLS (RFC 9420) implementation, rather than
  a custom group ratchet — the highest-confidence piece of the crypto
  stack precisely because it's an integration, not new protocol code.
- **Elevation of privilege**: removed members can no longer decrypt new
  epochs (MLS's core property) — covered by
  `mls.rs::removed_member_can_no_longer_be_reasoned_about_as_current`.
- **Mitigated — MLS group state now survives a daemon restart**:
  `MlsMember` is generic over its `openmls_traits::OpenMlsProvider`
  (`MlsMember<P>`), and `bh_crypto::mls_storage::PersistentMlsProvider` is
  a second, real backend — same audited `openmls_rust_crypto` crypto/RNG
  as before, but storage via `openmls_sqlite_storage::SqliteStorageProvider`
  over a SQLCipher-keyed `rusqlite::Connection` (own database file/key,
  isolated from `bh-storage`'s messaging DB, same pattern as the payments
  DB). `bh-api::groups.rs`'s `GroupRegistry` now constructs
  `MlsMember<PersistentMlsProvider>` for the daemon's own member in every
  group, and persists that member's signature public key as
  `groups.mls_state` — not a secret, just enough to reconstruct the exact
  same member later (`MlsMember::from_stored_signer` reads the stored
  signer keypair rather than generating a fresh one, since a fresh keypair
  would produce a credential `openmls` wouldn't recognize as the existing
  leaf); the group's own ratchet-tree/epoch state is durable on its own
  inside `PersistentMlsProvider`'s storage, reloaded via
  `bh_crypto::mls::Group::load` (wrapping `openmls`'s own `MlsGroup::load`).
  On a `GroupRegistry` cache miss, `ensure_live_group_state` reconstructs
  both pieces from storage before falling through to the in-memory lookup,
  so `add_member`/`remove_member`/`mls-self-test` no longer return `410
  GONE` after an actual daemon restart. Tested at two levels:
  `bh-crypto::mls::tests::
  a_reloaded_persistent_member_and_group_can_still_do_real_mls_after_a_simulated_restart`
  proves the crypto primitives themselves round-trip (create a persistent
  member + group, add a member, encrypt, drop everything, reopen the same
  database file, reload, and encrypt/decrypt a *new* message); `bh-api`'s
  `groups_survive_a_daemon_restart_via_the_http_api` proves the same thing
  through the HTTP API, rebuilding a whole second `AppState`/router against
  the same on-disk profile directory. The shadow-member/shadow-group local
  single-daemon peer simulation (below) is intentionally unaffected — it
  remains process-lifetime-only test scaffolding, not part of what needed
  persisting.
- **Tampering (membership sync)**: `bh-api::groups::add_contact_to_live_group`
  and `remove_member` explicitly fan the resulting MLS commit out to every
  other already-joined member's local view before considering the
  operation complete — an earlier version of this code didn't, and a
  member added/removed after others had already joined silently went
  epoch-desynced and stopped being able to decrypt (caught by
  `groups_round_trip_create_add_remove_and_self_test` in
  `crates/bh-api/tests/api_smoke.rs`, which is exactly why
  `mls-self-test` exists as an explicit, callable proof rather than an
  assumption).
- **Elevation of privilege (no real remote membership yet)**: `bh-api`'s
  group endpoints locally generate one "shadow" `MlsMember` per contact,
  scoped to the daemon process, to exercise `add_member`/`join_group`/
  `decrypt` end to end without a live `bh-network` to fetch a real peer's
  key package from (see `groups.rs` module doc). This proves the crypto
  path works, not that any real remote device has actually joined
  anything — it must be reworked once real key-package exchange over
  `bh-network` exists, and should not be read as "groups are
  network-ready."

### 3.3 Post-quantum hybrid (`bh-crypto::pq_hybrid`)

- Defense in depth by construction: the shared secret is HKDF-combined
  from *both* the X25519 and ML-KEM-768 legs, so a break in ML-KEM alone
  degrades to "as secure as X25519 alone," not full compromise.
  `tampered_ml_kem_ciphertext_breaks_agreement` confirms ML-KEM's
  implicit-rejection behavior (a tampered ciphertext silently yields a
  wrong secret rather than erroring) doesn't break the combiner.
- **Mitigated — now integrated into the live X3DH flow**: `SignedPreKey`/
  `PreKeyBundle` carry a second, ML-KEM-768 prekey alongside the classical
  X25519 one (both Ed25519-signed and both verified before use), and
  `x3dh_initiate`/`x3dh_respond` combine the classical DH output with the
  PQ leg via HKDF (`combine_classical_and_pq`) — real 1:1 sessions now get
  the hybrid protection, not just the standalone `pq_hybrid` module.
  Tested for tampering on *both* legs independently
  (`x3dh_rejects_a_tampered_pq_prekey_signature`,
  `tampering_with_the_pq_ciphertext_changes_the_derived_key`), confirming
  a break in either leg alone doesn't silently succeed.

### 3.4 Onion routing (`bh-network::onion`)

- **Information disclosure — partially mitigated, was the most significant
  open risk in this codebase.** Packets are now length-prefixed and padded
  up to the nearest of a fixed set of size buckets
  (`SIZE_BUCKETS`/`bucket_len`) before encoding at every hop, so most
  payloads of different real sizes become indistinguishable on the wire —
  confirmed by
  `same_bucket_payloads_produce_identically_sized_packets_at_every_hop` and
  `packet_sizes_are_bucketed_not_exact`. This is a real, tested
  improvement, but **not** full Sphinx-style constant-size padding: two
  payloads straddling a bucket boundary (or one payload larger than every
  bucket) are still distinguishable by size, and the module doc comment
  says so explicitly. Position-in-circuit inference from packet size is
  reduced, not eliminated.
- **Spoofing/tampering between hops**: each layer is authenticated
  (ChaCha20-Poly1305, per-layer key from one-time ECDH) — a relay cannot
  forge or modify a layer without detection, confirmed by
  `wrong_relay_key_fails_to_peel`.
- **Information disclosure between hops**: confirmed by
  `intermediate_hops_cannot_read_final_payload` — an intermediate hop
  provably cannot see the exit payload in either the packet it receives or
  the packet it forwards.
- This is, overall, the least-precedented piece of the protocol stack —
  see `docs/SPEC.md` §2.2/§9: nothing here should be trusted in production
  without independent cryptographic review, and this module most of all.

### 3.5 DHT & node selection (`bh-network::transport`, `dht`, `eclipse_resistance`)

- **Spoofing (Sybil)**: mitigated for circuit-hop selection specifically —
  `eclipse_resistance::select_circuit_nodes` ranks candidates by an
  HMAC-keyed score (not DHT closeness, which is gameable) and enforces
  subnet diversity, tested against a scenario with 3 Sybil nodes on one
  subnet plus 2 honest nodes.
- **Known gap**: this only covers *circuit hop selection*. It does not
  cover Kademlia routing-table poisoning in general (an attacker flooding
  the DHT with nodes to bias ordinary `get_record`/`put_record` lookups)
  — that's a broader S/Kademlia-style hardening effort not undertaken here.
  Also, "subnet diversity" here is whatever grouping key the caller
  supplies; there's no real IP→ASN database wired in (that's closer to
  infrastructure than code — see the project's earlier scoping decision to
  defer anything requiring deployed infrastructure).
- **Denial of service**: Kademlia's own protocol-level bounds (bucket
  sizes, query concurrency limits) apply as shipped by `rust-libp2p`;
  nothing Blackhole-specific has been added or reviewed here.

### 3.6 Mailboxes & sealed sender (`bh-network::mailbox`, `sealed_sender`)

- **Information disclosure (sender identity)**: `sealed_sender` puts the
  sender's identity and signature *inside* the encryption to the
  recipient's key — confirmed by
  `envelope_carries_no_sender_information_in_the_clear`, which asserts the
  sender's public key literally does not appear in the serialized
  envelope bytes. A mailbox node holding an envelope learns only the
  routing key (recipient), never the sender.
- **Tampering / repudiation**: the sealed content's signature is verified
  against the *revealed* sender identity on unseal
  (`tampered_ciphertext_is_rejected`), so a mailbox node can't forge a
  message's apparent sender — but see the module doc: there's no
  certificate authority, so "sender identity" here means "whichever
  identity key the recipient's client is shown," which is only meaningful
  if the recipient has separately verified that key belongs to who they
  think it does (same caveat as §3.1).
- **Mitigated (not eliminated) — concurrency**: `push`/`delete` now
  read-merge-write the per-recipient manifest against the Kademlia record
  with verify-and-retry (up to `MAX_MANIFEST_MERGE_ATTEMPTS`): read the
  current record, merge in the new message ID, write, then read back to
  confirm the write actually landed (not clobbered by a racing writer) —
  retrying the whole cycle on mismatch. Confirmed with a real concurrency
  test (`two_concurrent_pushes_to_the_same_recipient_both_survive`, using
  `tokio::join!` on two genuinely simultaneous pushes, not a mocked race).
  Still not a CRDT — it's retry-based conflict *avoidance*, not
  conflict-free merging — so it doesn't scale to many simultaneous writers
  as gracefully as a real mergeable structure would, but the specific
  "two sends race, one silently disappears" failure this section used to
  describe is now closed.
- **Mitigated — denial of service**: PoW is now verified server-side.
  `Mailbox::push`/`fan_out` take a `pow_solution: &Solution` parameter and
  reject the push if it doesn't verify
  (`push_without_valid_pow_is_rejected`) before doing any storage work —
  `pow.rs`'s primitive (§3.8) is no longer just defined-and-tested in
  isolation, it's the actual gate. TTL-bounded storage still keeps
  abandoned mailboxes from growing forever on top of that.

### 3.7 Local storage (`bh-storage`)

- **Information disclosure at rest**: SQLCipher encryption confirmed with
  a real negative test — `wrong_key_fails_to_open_existing_database`
  opens a real on-disk database with the wrong key and asserts it fails,
  not just "would fail in theory."
- **Key management**: the database key and device signing key live in the
  OS credential store (Keychain/Credential Manager/Secret Service via
  `keystore.rs`), never on disk in plaintext next to the database.
- **Elevation of privilege / DoS mitigation**: `panic_wipe` gives a tested,
  irreversible emergency destruction path
  (`panic_wipe_removes_keys_and_data_dir`), confirmed end-to-end through
  the daemon (`POST /panic-wipe` actually deletes the data directory and
  exits the process).
- **Mitigated — optional PIN/passphrase layer in front of the DB key now
  exists**: the SQLCipher key is still generated with the system RNG, but
  `bh_storage::db_key_lock` can now wrap that same key under a
  user-chosen PIN — `backup::seal`'s existing Argon2id (deliberately slow)
  + ChaCha20Poly1305 primitive (SPEC.md §4's backup passphrase KDF),
  reused rather than reinvented. The keystore entry then holds a sealed
  blob instead of the raw key; telling the two apart needs no extra flag
  (a raw key is always exactly 32 bytes, a sealed blob is always longer).
  `POST /security/db-pin` (set, from an already-unlocked daemon) /
  `POST /security/db-pin/clear` (requires the current PIN) are the HTTP
  surface (`bh-api::security`); `daemon/src/main.rs::
  load_or_create_db_key` enforces it at startup via `BLACKHOLE_DB_PIN`,
  refusing to start (rather than silently minting a fresh key or starting
  unprotected) if a PIN is set but not supplied. `POST /profiles/:id/
  activate` is PIN-aware too (`db_pin` field), so switching *into* a
  PIN-protected profile requires it — confirmed by
  `switching_into_a_pin_protected_profile_requires_the_pin`, which also
  checks a rejected switch doesn't partially apply. **Opt-in, per
  profile, and not on by default**: a fresh profile is unprotected exactly
  as before until its owner explicitly sets a PIN, so this closes the
  "no such layer exists at all" gap without changing default behavior for
  anyone who doesn't use it. `bh-api::local_auth`'s passkey/TOTP tables
  remain a separate, client-UX-only unlock screen (§3.11) — this entry is
  specifically about the DB key itself, which is what's now actually
  gated.

### 3.8 Anti-spam PoW (`bh-network::pow`)

- **Denial of service (spam)**: the PoW challenge is bound to the specific
  message (recipient + ciphertext + timestamp) via SHA-256, confirmed by
  `solution_does_not_transfer_to_a_different_message` — a solved PoW can't
  be replayed to cover a different or repeated send.
- **Mitigated — now verified server-side**: mailbox nodes check it before
  accepting a push (see §3.6) — the primitive is no longer just real and
  tested in isolation, it's the actual enforcement point.

### 3.9 Daemon API surface (`bh-api`)

- **Elevation of privilege**: the API binds to `127.0.0.1` only
  (`ApiServer::new`/`server.rs`) — never reachable from the network, so
  the UI/daemon boundary can't be attacked remotely as designed. This
  isn't yet defended by an additional auth token between the local UI
  process and the daemon (SPEC.md §6 doesn't call for one, since both are
  meant to run as the same local user, but a second local process could
  currently also reach it — no worse than the general trust level of
  "this device's other processes," which is out of scope per §2).
- **Repudiation**: `POST /identity` refuses to overwrite an existing
  identity (`409 Conflict`, verified live in the smoke test) — an
  accidental or malicious re-init can't silently replace a user's identity
  through this endpoint.

### 3.10 Third-party dependency vulnerabilities (GitHub Dependabot)

Reviewed 2026-07-20. GitHub's dependency graph scans `Cargo.lock`
statically — it flags every locked package regardless of whether that
package is actually reachable from compiled code, so each alert below was
individually checked with `cargo tree` (and `cargo tree --target all`,
since some entries are target-gated) to see whether it's live or dormant.

- **`yamux` 0.12.1 — GHSA-vxx9-2994-q338 / CVE-2026-32314, high, LIVE, and
  now actually running.** A crafted inbound Yamux `Data` frame with `SYN`
  set and an oversized body (> `DEFAULT_CREDIT`) panics the connection
  state machine (`remove(...).expect("stream not found")`) — remotely
  triggerable by any peer that can open a Yamux stream, no authentication
  required. This *is* compiled into `bh-network`'s transport
  (`libp2p-yamux` depends on it directly, confirmed via `cargo tree -i
  yamux@0.12.1` with no `--target`/feature gate needed). Fixed upstream in
  `yamux` 0.13.10 — but `libp2p-yamux` 0.47.0 (the version pulled by
  `libp2p` 0.56.0, currently latest) depends on *both* 0.12.1 and 0.13.10
  for what looks like wire-protocol-version negotiation between two yamux
  generations, and hasn't bumped the 0.12 slot yet. No fix is available by
  changing anything in this repo — it's blocked on a `rust-libp2p` release.
  **Exposure changed**: `daemon/src/main.rs` now spawns and listens with
  `bh_network::supervised::SupervisedNetwork`, binding
  `BLACKHOLE_NETWORK_LISTEN_ADDR` (default `/ip4/0.0.0.0/tcp/0` — all
  interfaces, unlike the HTTP API's loopback-only bind) — so this is no
  longer a theoretical "once it's wired in" concern, it's live in a
  process actually accepting inbound connections. **Blast radius is now
  contained, not eliminated**: the event loop already ran as its own
  `tokio::spawn`ed task, so a panic there was never able to crash the
  whole daemon process (no `panic = "abort"` set anywhere in this
  workspace, confirmed) — but until now it *did* silently and permanently
  kill that node's networking, with no automatic recovery.
  `bh_network::supervised::SupervisedNetwork` closes that: it polls
  `Node::is_alive()` (cheap, checks whether the event loop's command
  channel receiver is still there) every `NETWORK_HEALTH_CHECK_INTERVAL`
  and respawns a fresh `Node` on death, tested by directly constructing a
  dead handle and confirming the supervisor detects and replaces it with a
  working one (`supervisor_detects_a_dead_node_and_respawns_a_working_one`).
  A successful attack is now "networking blips and self-heals" rather than
  "networking silently dies until someone notices and restarts the whole
  daemon" — real containment, but **not a fix for the underlying bug**: an
  attacker who can keep reconnecting can keep re-triggering it, and a
  respawned node gets a fresh random libp2p identity each time (peer
  identity isn't persisted across respawns — noted in `supervised.rs`'s
  own doc comment), so this is not free from the rest of the network's
  point of view. Genuinely fixing this still requires the upstream
  `rust-libp2p` release; that dependency hasn't changed.
- **`hickory-proto` ≤0.25.2 / ≤0.26.0 — GHSA-3v94-mw7p-v465,
  GHSA-q2qq-hmj6-3wpp, dormant.** Pulled transitively via
  `libp2p-mdns → hickory-resolver → hickory-proto`. `libp2p`'s `mdns`
  feature (LAN peer discovery) is not enabled anywhere in this workspace —
  confirmed via `cargo tree -i libp2p-mdns` (and `--target all`), which
  resolves to nothing. Locked in `Cargo.lock` because Cargo reserves a
  compatible version for every optional dependency any crate in the graph
  *could* activate, not just the ones actually turned on. Becomes live the
  moment `mdns` is enabled — worth fixing at that point, not before.
- **`libcrux-chacha20poly1305` <0.0.8 — GHSA-hc3c-63hc-2r9f, dormant.**
  Pulled via `hpke-rs`'s optional `libcrux` backend, which `openmls_rust_crypto`
  (the backend this repo actually uses — see `bh-crypto::mls`) does not
  request. `cargo tree -i hpke-rs-libcrux --target all` resolves to
  nothing.
- **`glib` <0.20.0 — GHSA-wrw7-89jp-8q8g, dormant on the platforms built/tested
  so far.** Part of Tauri's Linux GTK backend (`gtk`/`webkit2gtk` →
  `glib`), gated to `target_os = "linux"`. Doesn't appear in `cargo tree`
  for the macOS host target used during development. Linux is an explicit
  distribution target for the desktop client (SPEC.md §10), so this
  **will** need a fix before a Linux build ships — tracked in §4, not
  ignorable indefinitely the way the other two dormant entries are.

### 3.11 Post-v0.1 features (`bh-crypto::{envelope,safety_number,call_keys,payment_address}`, `bh-storage::{reactions,receipts,invites,profiles,payment_requests,local_auth}`, `bh-api::{device_link,files}`, `bh-calls`)

Reviewed 2026-07-20, covering everything added in SPEC.md §15.

- **Mitigated (partially) — ciphertext-length side channel**: `Envelope`'s
  variants (text/reaction/receipt/call-signal) are different sizes before
  encryption, so an observer who can measure ciphertext length across many
  messages could statistically distinguish "this looks like a receipt"
  from "this looks like a long text message" — the same class of leak as
  the onion packet-size gap (§3.4), not a new category of risk, but a new
  instance of it. Now closed the same way: `encode`/`decode` length-prefix
  and pad to a fixed set of size buckets before the ratchet/MLS layer ever
  sees the bytes, confirmed by
  `different_small_variants_pad_to_the_same_bucket` (a `Reaction` and a
  multi-message `Receipt` land in the same bucket) and
  `encoded_length_is_always_a_known_bucket_size`. Same caveat as §3.4:
  bucket, not perfectly-constant, size — payloads near a bucket boundary
  or larger than the biggest bucket are still distinguishable.
- **Repudiation (safety numbers)**: `bh_crypto::safety_number` computes a
  fingerprint from *whatever* public keys are handed to it — it has no way
  to know the caller resolved the correct contact. `Contact.verified` only
  ever gets set by an explicit `POST /contacts/:id/verify` after a human
  comparison; the crate itself makes no trust claim.
- **Elevation of privilege (invite tokens are issuer-side-only)**: nothing
  stops a scanning party from trying an expired/revoked token anyway —
  `bh_storage::invites::consume_invite` is what actually blocks it, and
  only the *issuer's* daemon ever calls it. A client that skips calling
  `consume_invite` before completing a handshake would silently accept an
  invite it shouldn't — this is a contract on whatever eventually wires
  `bh-network` handshakes to invites, not yet enforced by a type system.
- **Denial of service (profile keystore cache is unbounded)**:
  `ProfileManager` caches one `Keystore` per profile for the daemon's
  lifetime (`keystore_for`) and never evicts entries for profiles that
  still exist — bounded in practice by how many profiles a user creates
  through the UI, not attacker-controlled, but worth noting if profile
  creation is ever exposed to less-trusted callers.
- **Fixed — disappearing-timer sweeper now follows profile switches**: the
  expiry sweeper (§3.7) used to be spawned once in `daemon/src/main.rs`
  against whichever profile was active at startup and never moved.
  Ownership moved into `AppState` (`restart_expiry_sweeper`, called from
  both `AppState::new` and `switch_active`): it aborts whatever sweeper
  was running and respawns one against the newly-active profile's `db`,
  so exactly one sweeper is ever running and it always tracks whichever
  profile is actually active. Confirmed by
  `expiry_sweeper_follows_profile_switches` — an expired message on the
  starting profile gets purged, then after switching to a second profile,
  an expired message *there* gets purged too, without a restart.
- **Calls — no STUN/TURN (`bh-calls::transport`)**: mirrors §3.4/general
  network state — only peers that can reach each other directly connect
  today. Unlike the messaging path, there's also no onion routing over
  call signaling or media; `Envelope::Call` gets the same sealed-sender-
  via-session protection as any other envelope, but the WebRTC media
  itself flows directly between the two endpoints once connected (by
  design — SFrame end-to-end encryption, not anonymity, is the property
  calls get; see SPEC.md §15).
- **Calls — VP8 decode intentionally unimplemented (`bh-calls::video`)**:
  by design (SPEC.md §15) rather than an oversight — no audited safe-Rust
  VP8 decoder exists on crates.io, and hand-rolling one against libvpx's
  raw FFI was judged higher-risk than deferring decode/render to the
  client's webview. Tracked here so it doesn't get mistaken for a gap that
  "just needs plumbing" — it needs either a new audited dependency or a
  client-side implementation.
- **Calls — no group-call support**: `call_keys::SframeContext`'s
  `sender_tag` is a single byte distinguishing exactly two parties
  (caller/callee). Extending to N participants needs a per-participant
  tag and key-distribution scheme that doesn't exist yet — noted in
  `call_keys.rs`'s own doc comments.
- **Payment requests — no defense against a compromised endpoint
  (`bh_crypto::payment_address`, `bh-storage::payment_requests`)**: the
  E2EE session (§3.1) guarantees the address arrives unmodified from
  whatever the *sender's device* actually encrypted — it says nothing
  about whether that device's own display/clipboard was already showing a
  swapped address before encryption (malware, a compromised OS clipboard
  manager, a malicious browser extension in a webview context). This is
  the same "endpoint security is out of scope for E2EE" boundary §7
  already draws for message content generally, but it's worth calling out
  specifically here because the consequence for a payment request is
  irreversible fund loss rather than a privacy leak. `validate_address`
  only catches structurally malformed addresses (typos, wrong network,
  bad checksum) — it cannot and does not attempt to verify that an
  address belongs to the person who appears to have sent it. No
  mitigation beyond what already exists (safety-number verification of
  the channel itself, §3.1) is implemented; the client now forces an
  explicit out-of-band-confirmation step before "Mark as paid" can be
  clicked (`renderPaymentBlock` in `client/desktop/src/main.ts` swaps in an
  inline checkbox-gated confirm panel showing the address again), and the
  server enforces this itself — `mark_payment_request_paid`
  (`crates/bh-api/src/payment_requests.rs`) requires a
  `confirmed_out_of_band: true` field in the request body and returns
  `412 Precondition Failed` without touching the DB otherwise, so a direct
  API caller can't skip the UI's nudge. This closes the "no confirmation
  step exists at all" gap, not the underlying endpoint-compromise
  boundary above: nothing stops a user from checking the box without
  actually verifying the address against a second channel, since that's
  inherent to any such consent-gate UI rather than something software can
  enforce.
- **Device linking is a single-daemon simulation (`bh-api::device_link`)**:
  there is exactly one daemon/database in this repo — `begin`/`scan`/
  `accept`/`finish` run against the *same* `AppState`, with the daemon
  playing both the already-trusted and the new device's role. The real
  ECDH/HKDF/AEAD path from `bh-crypto::device_link` runs for real and a
  genuine second row lands in `devices`, but nothing here models a second
  physical device, transfers the SQLCipher DB key, or exercises any
  cross-process behavior. The client UI must keep labeling this a local
  simulation rather than implying real multi-device support exists.
- **Local unlock is client-UX-only, not a DB-key gate
  (`bh-api::local_auth`)**: see §3.7 — repeating here because it's easy to
  misread "passkey/TOTP enrollment" as closing that gap when it doesn't.
- **File attachments — no resumability (expiry sweep now closed)
  (`bh-api::files`, `bh-files`)**: uploads are fully synchronous today (no
  real network fetch to interrupt), so `bh_files::download::DownloadState`/
  `missing_chunks()` stay exercised only by that crate's own unit tests —
  nothing in the daemon has anything to resume from without a live
  `bh-network` peer to fetch missing chunks from. Attachments **are** now
  swept by the disappearing-message timer (`bh_storage::expiry`): the
  sweeper's `ExpirySweepResult` reports which `content_hash`es it just
  orphaned from the `files` table, and `bh-api`'s `AppState::
  restart_expiry_sweeper` removes the matching `data_dir/files/
  <content_hash>/` chunk directory from disk in the same pass — a parent
  message expiring no longer leaves its chunk files behind. Transport is
  base64-in-JSON capped at 25 MiB (`crates/bh-api/src/
  files.rs::MAX_ATTACHMENT_BYTES`), not `axum::extract::Multipart` — fine
  for a localhost daemon today, a real limitation once large-file transfer
  over a live network matters.
- **Payment requests — "paid" is a trust-nothing local flag**: `paid_at`
  is set only by an explicit local action (`POST
  /messages/:id/payment-request/paid`) and is never confirmed against a
  blockchain by design (SPEC.md §15) — the sender marking their own
  request paid, the recipient marking it paid, and reality can all
  diverge, and nothing in this system detects that. This is an accepted
  tradeoff, not an oversight: the alternative (the daemon querying a
  block explorer/node) would leak which addresses a user is watching to
  whatever backend answers that query, in direct tension with the
  zero-knowledge design principle (CLAUDE.md non-negotiables).

### 3.12 Second post-v0.1 batch (`bh-api::{device_sync,cosmetics,stickers,presence,push,search,groups,conversations}`, `bh-storage::{push,search,cosmetics,message_stickers}`, `crates/bh-push-relay`, `bh-calls::{group,screen}`, `bh-crypto::mls::export_call_base_key`, `client/desktop/src-tauri/src/link_preview.rs`)

Reviewed 2026-07-21, covering everything added in SPEC.md §16.

- **Spoofing (device sync's shadow crypto)**: `device_sync.rs` runs a real
  X3DH + Double Ratchet handshake, but — same caveat as groups' shadow
  members (§3.2) — the "device" side of that handshake is a
  locally-generated throwaway identity, not the linked device's real
  signing key from `device_link.rs`. This proves the ratchet machinery
  works end to end; it does not prove any real second device has actually
  received anything. Must be reworked once `bh-network` delivery exists.
- **Elevation of privilege (broadcast channels are a policy check, not a
  crypto one)**: `groups.broadcast_only` gates posting entirely in
  `bh-api::conversations::send_message` (rejects a non-owner
  `sender_contact_id` with `403`) — the underlying MLS group has no
  concept of read-only members, so any code path that reaches
  `insert_message` directly (bypassing the HTTP handler) would not be
  stopped by anything at the crypto layer. This mirrors invite tokens
  (§3.11): the enforcement point is a single, specific function, not a
  structural guarantee.
- **Spoofing (message-sender attribution more broadly)**: `send_message`'s
  `sender_contact_id` field is honored *only* for `Group`-kind
  conversations (needed for the broadcast-channel non-owner-post test and
  for shadow-member simulation generally) and is silently forced to the
  real local user for `Direct`/`SelfNotes` conversations. This was a
  deliberate tightening during integration: honoring an
  attacker-controlled `sender_contact_id` on a 1:1 conversation would let
  a compromised webview (the same XSS-bridge concern `daemon_call`'s own
  doc comment already flags, §3.9) forge messages that appear to come
  from a verified contact. The `Group`-only carve-out is still broader
  than strictly necessary — it trusts the caller not to impersonate a
  fellow *group* member either, bounded today only by the fact that
  `bh-api` has no concept of "which member is making this HTTP request" in
  the first place (single local daemon, single local user).
- **Information disclosure (link previews are the one client-side network
  call that isn't sealed-sender/onion-routed)**: `fetch_link_preview`
  (`client/desktop/src-tauri/src/link_preview.rs`) deliberately never
  goes through the daemon or `bh-network` — it's a direct HTTP GET from
  the user's own device straight to whatever site is linked. This is the
  single largest voluntary metadata leak surface in the client today:
  enabling the feature tells the linked site's operator the user's IP,
  approximate timing, and that they opened that specific link. Mitigated
  as much as a feature like this can be without an anonymizing proxy in
  front of it: off by default, with the tradeoff stated in the toggle's
  own copy rather than buried in a settings submenu, plus a best-effort
  SSRF guard (`is_blocked_host`/`is_non_public_ip`) rejecting literal
  loopback/private/link-local addresses and `localhost`. **Known gap**:
  the guard doesn't resolve the hostname itself, so a public domain that
  resolves to an internal address (DNS rebinding) isn't caught — accepted
  because the URL is always something the user chose to paste/receive,
  not attacker-reachable input, but this code must not be reused anywhere
  the URL *is* attacker-controlled without adding resolve-then-pin-the-IP.
- **Information disclosure (opaque push relay)**: `crates/bh-push-relay`
  is designed to leak the least metadata a wake-push mechanism can — no
  message content, no sender/recipient identity, no conversation id, just
  an opaque token. Residual leak, inherent to the concept of push
  notifications and not fixable by this design: the relay (and by
  extension whatever real APNs/FCM/UnifiedPush backend eventually sits
  behind `forward_to_push_provider`, still a stub) necessarily learns
  "this opaque token's owner wants to be woken, roughly now" — a coarse
  online/timing signal, which is exactly why the feature defaults off in
  both the relay's own design and the client's opt-in toggle. No
  authentication ties a registration to an identity (by design — an
  authenticated token would itself be a stronger identity-linkage risk),
  which means **denial of service**: nothing stops a party who obtains
  someone else's opaque token (e.g. by observing daemon-to-relay traffic,
  since that channel isn't specified/secured here) from waking their
  device repeatedly. Low severity (a wake is content-free and rate-limited
  only by whatever the real push provider enforces) but worth noting as
  unmitigated.
- **Denial of service (local search has no query-cost bound beyond FTS5's
  own)**: `search_messages` caps result count (`MAX_LIMIT = 200`) but not
  match-set size before that cap applies — a pathological query against a
  very large local history could still be slow. Low severity: this is a
  query against the user's *own* local database, so the only party who can
  trigger it is the user themselves (or, per §3.9, another local process
  on the same machine — the same trust level already out of scope).
- **Tampering (FTS5 query-injection) — mitigated**: `sanitize_fts_query`
  quotes every whitespace-separated token as an FTS5 string literal
  (doubling embedded `"`) before it ever reaches `MATCH`, confirmed by
  `escapes_embedded_quotes_and_neutralizes_fts5_operators` — a search
  containing `NOT`, `-`, `:`, or `*` is treated as literal text, not
  reinterpreted as FTS5 boolean/prefix syntax.
- **Elevation of privilege (voice messages reuse the attachment path's
  existing trust boundary)**: no new gap introduced — `duration_secs` is
  validated (`1..=600` seconds) before any chunking/disk work, same
  spirit as the existing `MAX_ATTACHMENT_BYTES` check, so a malformed
  duration is rejected as a `400` rather than silently accepted or
  crashing the chunker.
- **Elevation of privilege (group calls/screen sharing inherit calls'
  existing gaps)**: no new category of risk — `bh-calls::group` and
  `bh-calls::screen` sit on top of the same WebRTC transport and SFrame
  media encryption §3.11 already covers, so "no STUN/TURN" and "media
  flows directly between endpoints once connected, not onion-routed"
  apply identically here, now also to a full mesh of connections and to
  the screen-share track specifically. Screen sharing adds one new
  concern of its own: **information disclosure via the capture surface
  itself** — screen sharing is, definitionally, "give the other party
  live pixels of your screen," and nothing in `bh_calls::screen` (or
  could, at this layer) prevents a user from sharing a window/region that
  contains something they didn't mean to show. This is a UX/consent
  concern (the client should make crystal clear *what* is being shared
  before/while it's shared), not something the transport or encryption
  layer can mitigate — noted here because it's easy to only think about
  "is the pixel data encrypted" (yes) and miss "should this pixel data
  have been sent at all" (a human judgment call every time).
- **Group call participant cap enforced at both layers**: `bh-calls::
  group::MAX_GROUP_CALL_PARTICIPANTS` is checked inside
  `GroupCallSession::offer_to`/`accept_offer` *and* independently at the
  HTTP boundary (`bh-api::calls::start_group_call` rejects an
  over-cap `participant_count` with `400` before doing any MLS/WebRTC
  work) — a request that would exceed the mesh's practical limit is
  rejected outright rather than partially built and left inconsistent,
  confirmed by `group_call_over_the_participant_cap_is_rejected`.
- **Repudiation (message editing preserves history, doesn't erase it)**:
  `Database::edit_message` archives the previous body into
  `message_edits` before overwriting the live row — an edited message is
  never presented as if it always read that way. Only the local user's
  own outgoing messages can be edited (`sender_contact_id.is_some()` is
  rejected with `403`), and an already-deleted/self-destructed message
  can't be "resurrected" via edit (rejected with `404` — there is nothing
  sensible to edit once `body` has been wiped).
- **Cosmetics store isolation extended, not weakened, by sticker packs**:
  `stickers.rs`'s ownership check (`Database::is_cosmetic_owned`) queries
  exclusively the messaging database's `cosmetic_inventory` table — the
  same accessor every other cosmetic-gated action already uses — and
  never touches `state.payments_db()`, preserving CLAUDE.md's payments/
  messaging isolation non-negotiable (SPEC.md §12) for the new cosmetic
  kind exactly as strictly as for the original three.
- **"Notes to self" has no counterparty, so no session to compromise**:
  worth stating explicitly rather than assuming — a self-conversation's
  messages get no Double Ratchet/MLS layer at all (there being no second
  party to protect the message *in transit* from), so their only
  protection is the same SQLCipher-at-rest guarantee (§3.7) as every
  other row in the database, including the local PIN layer if the profile
  has one set. This is by design, not an oversight, but it means a
  self-note is exactly as exposed as, say, a contact's display name — not
  independently hardened the way a real 1:1 message is.



Numbering is kept stable across revisions (rather than renumbered as items
close) so cross-references elsewhere in this document keep pointing at the
same item — a **MITIGATED**/**FIXED** tag means the item's own subsection
now describes what closed it, not that the number was removed.

1. **MITIGATED — onion routing packet-size leak** (§3.4). Bucket-size
   padding closes the "exact size leaks hop position" version of this;
   still not full Sphinx constant-size (see §3.4).
2. **PARTIALLY MITIGATED — `yamux` remote panic, CVE-2026-32314** (§3.10).
   The underlying bug is still open and upstream-blocked, and `bh-network`
   is now actually wired into the daemon and listening — but a panic there
   no longer permanently kills the node's networking:
   `bh_network::supervised::SupervisedNetwork` detects the dead event loop
   and respawns automatically. Contained, not fixed; still requires an
   upstream `rust-libp2p` release for the actual panic to stop happening.
3. **MITIGATED — mailbox manifest race condition under concurrent
   writers** (§3.6). Read-merge-write-verify retry, confirmed with a real
   concurrent-`tokio::join!` test; not a full CRDT, but the specific
   silent-loss failure is closed.
4. **PARTIALLY MITIGATED — no Key Transparency deployment** (§3.1). The
   RFC 6962 client-side primitive (tree hash, inclusion/consistency
   proofs) now exists and is exhaustively tested, but nothing gossips
   signed tree heads yet — MITM detection in practice is still
   manual-verification-only.
5. **FIXED — PQ hybrid integrated into the live X3DH flow** (§3.3). Real
   1:1 sessions now derive their shared secret from both the X25519 and
   ML-KEM-768 legs via HKDF, tested including tamper-detection on each leg
   independently.
6. **FIXED — PoW now enforced** (§3.8). Mailbox nodes verify it
   server-side before accepting a push.
7. **FIXED — PIN/passphrase layer in front of the DB key** (§3.7). Opt-in,
   per profile; `POST /security/db-pin` sets/clears it, daemon startup and
   profile-switch enforce it.
8. **FIXED — MLS group state now survives a daemon restart** (§3.2).
   `mls_storage::PersistentMlsProvider` + generic `MlsMember<P>` are wired
   all the way through `bh-api::groups.rs`: the own member's signer key is
   persisted (`groups.mls_state`) and the group itself is reloaded via
   `bh_crypto::mls::Group::load` on a `GroupRegistry` cache miss, so
   `add_member`/`remove_member`/`mls-self-test` now work after an actual
   daemon restart instead of returning `410 GONE`. Confirmed by a
   `bh-crypto` unit test that reloads and reuses real MLS state after
   dropping everything and reopening the database file, and a `bh-api` HTTP
   test that rebuilds a whole second `AppState`/router against the same
   on-disk profile.
9. **`glib` GTK vulnerability** (§3.10) — still open, dormant until a
   Linux build ships, needs upstream Tauri/gtk-rs-core to bump first.
10. **Calls have no STUN/TURN and no anonymity properties** (§3.11) — still
    open, same class of gap as #1/#2, now also applicable to call media,
    not just messaging.
11. **MITIGATED — envelope ciphertext-length side channel** (§3.11). Same
    bucket-padding fix as #1, applied to `Envelope::encode`/`decode`;
    same "buckets, not perfectly constant" caveat applies.
12. **FIXED — disappearing-timer sweeper now follows profile switches**
    (§3.11). Sweeper ownership moved into `AppState`, restarted against
    the newly-active profile on every `switch_active`, confirmed by a
    test that switches profiles and checks both sides actually get swept.
13. **MITIGATED — payment requests now require an explicit out-of-band
    address confirmation prompt** (§3.11). `renderPaymentBlock`
    (`client/desktop/src/main.ts`) swaps "Mark as paid" for an inline,
    checkbox-gated confirm panel that repeats the address in full before
    the click can fire; `mark_payment_request_paid`
    (`crates/bh-api/src/payment_requests.rs`) itself now rejects the
    request with `412 Precondition Failed` unless the body carries
    `confirmed_out_of_band: true`, so this isn't just a UI nudge a direct
    API caller could bypass. Not tagged FIXED: the consequence (irreversible
    fund loss) still requires an already-compromised endpoint to matter,
    same as before, and nothing stops a user from checking the box without
    actually verifying the address against a second channel — that residual
    is inherent to any consent-gate UI, not something this change (or any
    software fix) can close.
14. **Device linking is a same-daemon simulation, not real multi-device**
    (§3.11) — proves the crypto path, not cross-process/cross-device
    behavior; must be reworked once a second physical device can actually
    be reached.
15. **PARTIALLY MITIGATED — file attachments now swept by the
    disappearing-message timer, still have no resumability** (§3.11). The
    orphaned-chunk-files-on-disk gap is closed: `bh-storage`'s expiry
    sweeper reports which `content_hash`es it just dropped from `files`,
    and `bh-api`'s `AppState::restart_expiry_sweeper` deletes the matching
    `data_dir/files/<content_hash>/` directory in the same pass, confirmed
    by an integration test that expires an attachment and checks the chunk
    directory is actually gone. Resumability is unchanged and still absent:
    uploads remain fully synchronous with nothing to resume from without a
    live `bh-network` peer to fetch missing chunks — a lower-severity data
    hygiene gap, separate from the network-level gaps ranked above.
16. **Link previews are a voluntary, unmitigated-by-design metadata leak
    when enabled** (§3.12). The single largest deliberate exception to
    "nothing leaves the daemon/network stack without going through
    sealed-sender + onion routing" in the whole client — off by default,
    with the tradeoff stated plainly in the opt-in toggle's own copy, but
    once turned on, every link a message contains is fetched directly
    from the user's own IP with no anonymization. Not fixable without
    proxying the fetch through the P2P network itself (not attempted —
    would need `bh-network` wired in first, and even then would need
    careful design to not just relocate the leak to whichever node proxies
    it).
17. **Opaque push relay leaks coarse online/timing metadata by design, and
    registration isn't authenticated** (§3.12). Inherent to the concept of
    a wake-push mechanism, not a bug: the relay learns "this token's owner
    wants to be woken, roughly now." Off by default in both the relay's
    own design and the client. Unauthenticated registration means anyone
    who obtains a user's opaque token could trigger repeated wakes for
    them (low severity — content-free, no privacy loss beyond "device
    woke up") — no mitigation implemented yet.
18. **Device sync's crypto is real, its peer is not** (§3.12) — same class
    of gap as #14 (device linking) and groups' shadow members (§3.2): the
    X3DH + Double Ratchet handshake `device_sync.rs` runs is genuine, but
    the "linked device" side is a locally-generated shadow identity, not
    the real device's own signing key. Must be reworked once `bh-network`
    delivery and real cross-process device sync exist.
19. **Broadcast-channel posting restriction is enforced at exactly one
    function, not structurally** (§3.12) — same pattern already accepted
    for invite-token consumption (#14's neighbor in §3.11): the MLS group
    backing a broadcast channel has no crypto-level concept of read-only
    membership, so `bh-api::conversations::send_message`'s `403` check is
    the entire enforcement. Any future code path that reaches
    `insert_message` directly bypasses it. Low severity today (there is
    exactly one way to send a message, through this one function) but
    worth tracking before this code is refactored.
20. **Group calls and screen sharing inherit calls' no-STUN/TURN and
    no-anonymity gaps** (§3.12, same underlying issue as #10) — now also
    applicable to a full mesh of connections and to shared-screen pixel
    data specifically, plus a new, layer-independent concern: nothing
    technical stops a user from screen-sharing something they didn't mean
    to show. That's a client UX/consent responsibility, not something
    transport or media encryption can address.

Two entries deliberately excluded from this list: the `hickory-proto`
alerts (§3.10) are dormant with no path to becoming live short of
enabling a feature (`mdns`) nothing in this repo turns on — re-evaluate
if/when that changes, not before.

None of these are secret — each is called out in the relevant module's own
doc comments. This section exists to make the aggregate picture visible in
one place rather than scattered across the codebase.
