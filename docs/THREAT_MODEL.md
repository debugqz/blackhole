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
  trust anchor, not the display name. **Gap**: Key Transparency (SPEC.md
  §2.4) — a way to detect the *network* handing different clients different
  keys for the same contact — is not implemented. Until then, MITM
  detection depends entirely on users doing manual verification.
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
- **Known gap**: `openmls`'s state currently lives in its in-memory
  reference storage provider, not persisted through `bh-storage`. A daemon
  restart today loses in-progress group state — wiring `openmls_traits::
  storage::StorageProvider` against `bh_storage::Database` is a real
  follow-up, not done yet (see `mls.rs` module docs).

### 3.3 Post-quantum hybrid (`bh-crypto::pq_hybrid`)

- Defense in depth by construction: the shared secret is HKDF-combined
  from *both* the X25519 and ML-KEM-768 legs, so a break in ML-KEM alone
  degrades to "as secure as X25519 alone," not full compromise.
  `tampered_ml_kem_ciphertext_breaks_agreement` confirms ML-KEM's
  implicit-rejection behavior (a tampered ciphertext silently yields a
  wrong secret rather than erroring) doesn't break the combiner.
- **Known gap**: this hybrid handshake is not yet wired into the X3DH
  flow in `ratchet.rs` — the two exist as separate, independently-tested
  primitives. Integrating them (so real sessions actually get PQ
  protection, not just the standalone module) is unfinished.

### 3.4 Onion routing (`bh-network::onion`)

- **Information disclosure — the significant open risk in this codebase.**
  The module doc comment is explicit about this: packet size shrinks by a
  fixed amount at every hop (unlike Sphinx, which keeps packets constant-
  size end to end), which leaks a relay's position in the circuit to
  anyone who can observe packet sizes on the wire. This is a real,
  currently-unmitigated traffic-analysis weakness.
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
- **Known gap — concurrency**: the mailbox module doc is explicit that the
  per-recipient manifest (list of message IDs) is read-modify-written
  against a plain Kademlia record, which is last-write-wins. Two sends to
  the same recipient racing at the DHT level can lose one manifest update
  — the message itself isn't lost, but it can end up unreferenced. A CRDT-
  style mergeable manifest or a dedicated mailbox-node protocol is the
  real fix, not implemented here.
- **Denial of service**: TTL-bounded storage (`push`'s `ttl_seconds`) keeps
  abandoned mailboxes from growing forever, but there is currently no rate
  limiting on how many messages one sender can push to one mailbox —
  that's what `pow.rs` (§3.8) is *supposed* to gate at the network layer,
  but PoW enforcement on the mailbox-node side isn't wired in yet either.

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
- **Known gap**: the SQLCipher key itself is currently generated with the
  system RNG and stored directly in the keystore — there is no additional
  PIN/passphrase-derived layer in front of it yet (SPEC.md §7 describes
  "clave derivada del PIN/passcode del usuario," which isn't wired in).
  Today, keystore compromise alone (without a device PIN) is sufficient to
  unlock the database.

### 3.8 Anti-spam PoW (`bh-network::pow`)

- **Denial of service (spam)**: the PoW challenge is bound to the specific
  message (recipient + ciphertext + timestamp) via SHA-256, confirmed by
  `solution_does_not_transfer_to_a_different_message` — a solved PoW can't
  be replayed to cover a different or repeated send.
- **Known gap**: nothing currently *verifies* PoW server-side (mailbox
  nodes don't check it before accepting a push — see §3.6). The primitive
  is real and tested; the enforcement point isn't wired in.

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

- **`yamux` 0.12.1 — GHSA-vxx9-2994-q338 / CVE-2026-32314, high, LIVE.**
  A crafted inbound Yamux `Data` frame with `SYN` set and an oversized body
  (> `DEFAULT_CREDIT`) panics the connection state machine
  (`remove(...).expect("stream not found")`) — remotely triggerable by any
  peer that can open a Yamux stream, no authentication required. This *is*
  compiled into `bh-network`'s transport (`libp2p-yamux` depends on it
  directly, confirmed via `cargo tree -i yamux@0.12.1` with no
  `--target`/feature gate needed). Fixed upstream in `yamux` 0.13.10 — but
  `libp2p-yamux` 0.47.0 (the version pulled by `libp2p` 0.56.0, currently
  latest) depends on *both* 0.12.1 and 0.13.10 for what looks like
  wire-protocol-version negotiation between two yamux generations, and
  hasn't bumped the 0.12 slot yet. No fix is available by changing anything
  in this repo — it's blocked on a `rust-libp2p` release. Not practically
  exploitable today (no live network deployment — see the Status table),
  but this **must be resolved before `bh-network` is wired into the daemon
  and exposed to real peers** (tracked in §4 below).
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

## 4. Summary: open risks, ranked

1. **Onion routing packet-size leak** (§3.4) — the most consequential
   design gap; position-in-circuit is inferable from packet size today.
2. **`yamux` remote panic, CVE-2026-32314** (§3.10) — live in the compiled
   transport, upstream-blocked, must be resolved before `bh-network` is
   wired into the daemon and exposed to real peers.
3. **Mailbox manifest race condition under concurrent writers** (§3.6).
4. **No Key Transparency** (§3.1) — MITM detection is manual-verification-
   only.
5. **PQ hybrid not integrated into the live X3DH flow** (§3.3) — exists and
   is tested standalone, doesn't protect real sessions yet.
6. **PoW not enforced anywhere** (§3.8) — primitive exists, no enforcement
   point wired in.
7. **No PIN/passphrase layer in front of the DB key** (§3.7).
8. **MLS state not persisted** (§3.2) — functional but not durable across
   restarts.
9. **`glib` GTK vulnerability** (§3.10) — dormant until a Linux build ships,
   needs upstream Tauri/gtk-rs-core to bump first.

Two entries deliberately excluded from this list: the `hickory-proto`
alerts (§3.10) are dormant with no path to becoming live short of
enabling a feature (`mdns`) nothing in this repo turns on — re-evaluate
if/when that changes, not before.

None of these are secret — each is called out in the relevant module's own
doc comments. This section exists to make the aggregate picture visible in
one place rather than scattered across the codebase.
