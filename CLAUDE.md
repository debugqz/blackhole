# Blackhole

P2P E2EE messaging platform. Zero-knowledge by design: the operator cannot read
content or reconstruct who talks to whom. No content moderation, ever — that's
a design principle, not a policy. Monetization is cosmetic-only (profile
gifts/themes), paid in crypto (Monero primary), never "more privacy" as an
upsell.

Full architecture, rationale, and open questions: **[docs/SPEC.md](docs/SPEC.md)**.
Per-subsystem attack surface and known open risks:
**[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)**. Read both before making
protocol, crypto, or networking decisions — most "why is it built this way"
and "what could go wrong here" questions are already answered there.

## Non-negotiables (do not casually change)

- No custom crypto primitives. Signal Protocol (X3DH + Double Ratchet) for 1:1,
  MLS (RFC 9420) for groups, hybrid post-quantum (X25519 + ML-KEM) from day
  one. A homegrown cryptosystem is explicitly deferred and gated on
  professional cryptographers + formal verification — see SPEC.md §2.2.
  Do not implement one. (Note: `bh-crypto`'s X3DH/Double Ratchet is a
  from-scratch composition of audited primitives, not a dependency on
  Signal's own `libsignal` — see `bh-crypto/Cargo.toml` for why. This is
  "protocol composition from audited primitives," not "custom crypto" in
  the forbidden sense, but it also means that code specifically has not had
  independent review — see THREAT_MODEL.md §3.1.)
- No content scanning/reading, under any circumstance (SPEC.md §8).
- No mandatory phone number, no SMS-as-2FA, no third-party analytics/crash SDKs
  (SPEC.md §3, §7).
- Payments and messaging data are strictly isolated — never link the two
  databases directly (SPEC.md §12).

## Stack decisions made at scaffold time (not fixed in SPEC.md v0.1)

- **Daemon: Rust.** Aligns with `libsignal` (Rust), `openmls` (RFC 9420 ref
  impl, Rust), `rust-libp2p`.
- **Initial client: desktop only, via Tauri** (shares Rust crates with the
  daemon). Mobile/web deferred. iOS distribution is still an open question
  (SPEC.md §14) — resolve it before starting the iOS client.

## Repo layout

- `daemon/` — Rust binary; owns the SQLCipher database and platform
  keystore, runs the self-destruct sweeper, and exposes the localhost API
  the UI talks to (SPEC.md §6). `bh-network` (DHT/onion/mailboxes) *is*
  spawned and listening here via `bh_network::supervised::SupervisedNetwork`
  (binding all interfaces via `BLACKHOLE_NETWORK_LISTEN_ADDR`, unlike the
  HTTP API's loopback-only bind — THREAT_MODEL.md §3.10), reachable
  read-only via `GET /network/status`, and — for `Direct` conversations
  specifically — is now genuinely wired into message send/receive:
  `bh-api::conversations::send_message` runs a real X3DH + Double Ratchet
  handshake and pushes the ciphertext to the recipient's mailbox
  (`crates/bh-api/src/message_crypto.rs`) when a network is attached,
  falling back to today's local-storage-only behavior when it isn't (no
  live daemon network, or a test that never attaches one); a background
  loop (`crates/bh-api/src/message_receive.rs::spawn_receive_loop`) pulls
  this identity's own mailbox, decrypts, and delivers. Proven end-to-end
  by a real two-daemon integration test, not a same-process shadow
  session — see `bh-api/tests/api_smoke.rs`'s
  `direct_message_travels_a_real_network_between_two_daemons_and_decrypts`.
  **`Group` conversations are now wired too**: `conversations::send_message`'s
  `Group` arm encrypts with real MLS (`bh_crypto::mls::Group::encrypt`) and
  fans the ciphertext out over `Mailbox::fan_out`, keyed by the group id
  rather than a per-recipient mailbox; `message_receive.rs`'s loop grew a
  second per-tick phase that polls every locally-known group's shared
  mailbox, decrypts with `Group::decrypt_with_sender`, and delivers —
  deliberately never deleting a processed entry (it's shared by every
  member) and instead tracking already-attempted message ids in-process
  (`GroupRegistry::already_attempted_group_message`) so a daemon doesn't
  re-decrypt the same backlog every tick. Real membership travels the
  network too, not just messages: `groups::add_member`/`create_group` now
  fetch a real member's real, DHT-published MLS key package
  (`bh_network::key_package_directory`, `bh-api::mls_key_package` owning
  this identity's own single-use key package — republished after every
  consumption, not just periodically, since an MLS key package's private
  material is consumed by `join_group`, unlike an X3DH signed prekey)
  before falling back to the previous locally-simulated "shadow member" (no
  live network, no key package published yet, or no `Contact` row).
  The resulting `Welcome` travels to the new member over the existing 1:1
  mailbox as a new `Envelope::GroupInvite`, and the resulting commit fans
  out over the group mailbox to already-joined real members. Proven
  end-to-end by a genuine three-daemon integration test — see
  `bh-api/tests/api_smoke.rs`'s
  `group_membership_and_messages_travel_a_real_network_between_three_daemons`.
- `crates/bh-crypto` — identity + seed phrase, passkeys/TOTP, X3DH + Double
  Ratchet, MLS, PQ hybrid, invite QR/links, device linking, encrypted
  backups (SPEC.md §2-4). All real, tested implementations. Also:
  `key_transparency.rs` (RFC 6962 Merkle tree hash/inclusion/consistency
  proofs — a tested client-side primitive, not yet a deployed gossiped
  log, THREAT_MODEL.md §3.1), `mls_storage.rs`
  (`PersistentMlsProvider` — SQLCipher-backed `openmls` storage so group
  state survives a daemon restart; its connection now also sets `PRAGMA
  secure_delete = ON`, same as `bh-storage::db`'s main profile database,
  so a removed member's now-inaccessible epoch secrets are actually
  zeroed on disk rather than merely unlinked — THREAT_MODEL.md §3.7),
  `payment_address.rs` (address-format
  validation for XMR/BTC/ETH payment requests), `qr.rs` (shared QR
  rendering for invites/device-linking/safety-numbers), `webhook.rs`
  (HMAC-SHA256 signing/verification gating the cosmetics-store
  payment-confirmed webhook), `push_relay.rs` (`read_u32`/`read_string`
  now use `checked_add` instead of raw `+` when parsing a
  `PushRelayRecord`'s declared length — this parses DHT-sourced bytes
  from an untrusted peer *before* signature verification, so an
  attacker-chosen length near `u32::MAX` must fail cleanly rather than
  panic/wrap — THREAT_MODEL.md §3.12).
- `crates/bh-network` — libp2p transport + Kademlia DHT, onion routing,
  Eclipse/Sybil-resistant node selection, cover traffic, mailboxes, sealed
  sender, anti-spam PoW (SPEC.md §5). Real and tested against local
  multi-node scenarios (including a genuine two-daemon test in
  `bh-api`'s own test suite, not just this crate's own unit tests); not
  yet deployed against a real network, and see THREAT_MODEL.md §3.4/§3.6
  for the two biggest known (now hardened, not eliminated) gaps: onion
  packet-size leak — a finer, further-extended `SIZE_BUCKETS` ladder plus
  a smaller oversized-payload fallback stride — and mailbox manifest race
  — jittered retry backoff (`manifest_retry_backoff`) on top of the
  existing read-merge-write-verify loop. `mailbox.rs` also now caps a
  manifest's serialized size (`MAX_MANIFEST_BYTES`, 96 KiB, conservative
  headroom under the DHT's 128 KiB record cap) and rejects a `push` once a
  recipient's/group's manifest is already at that cap — closes a cheap
  denial-of-service where an attacker who knows a target's
  `recipient_key_hash` could solve trivially-difficult PoW in bulk and
  grow their manifest past the DHT's own size limit, silently breaking
  every future legitimate push to that recipient until the next lazy
  prune (THREAT_MODEL.md §3.6). `prekey_directory.rs` publishes/
  fetches X3DH prekey bundles via the DHT, the mechanism
  `bh-crypto::ratchet::PreKeyBundle`'s own doc comment already pointed at.
  `supervised.rs` wraps the event loop so a panic (e.g. the live `yamux`
  CVE, THREAT_MODEL.md §3.10) respawns a fresh node instead of permanently
  killing that node's networking, and exposes `dial()` for connecting to a
  known peer directly plus `spawn_with_bootstrap()` for dialing a
  configured list on startup *and* after any respawn (a respawned node's
  routing table is always empty — see that method's own doc comment — and,
  by default, so is its libp2p identity: `Node::spawn`/`spawn_with_bootstrap`
  generate a fresh random keypair every call). `daemon/src/main.rs` reads
  the bootstrap list from `BLACKHOLE_BOOTSTRAP_PEERS` (comma-separated
  multiaddrs), empty/unset by default since no public bootstrap nodes are
  deployed for this project yet. **A stable-identity variant now exists**
  for the deployment that actually needs one — a bootstrap node, whose
  whole job is being an address other nodes' `BLACKHOLE_BOOTSTRAP_PEERS`
  can keep pointing at: `Node::spawn_with_keypair`/`SupervisedNetwork::
  spawn_with_bootstrap_and_keypair` accept a caller-supplied `Keypair` that
  survives both a process restart and a mid-life supervisor respawn alike,
  gated behind `daemon/src/main.rs`'s `BLACKHOLE_PERSISTENT_NETWORK_IDENTITY`
  opt-in (off by default — an ordinary end-user daemon has no reason to
  want a network-layer identity that outlives one run, THREAT_MODEL.md
  §3.5). `key_package_directory.rs` publishes/fetches MLS key packages via
  the DHT, the group-membership counterpart to `prekey_directory.rs` (see
  the `Group` conversations entry above) — deliberately single-use, unlike
  `prekey_directory`'s reusable bundle, since `openmls` invalidates a key
  package's local private material the moment it's consumed by a real
  `join_group`.
- `crates/bh-storage` — SQLCipher-backed data model (contacts,
  conversations, messages, groups, devices, sessions, files, settings),
  platform keystore (Keychain/Credential Manager/Secret Service via
  `keyring`), panic wipe, self-destruct message sweeper (SPEC.md §7).
  `keystore.rs` also has an opt-in headless fallback now:
  `BLACKHOLE_KEYSTORE_BACKEND=file` switches to key material stored as
  `chmod 600` files under `<data_dir>/keystore-file-backend/` instead of
  the OS keychain, for deployments (a DHT bootstrap node in a container)
  with no D-Bus Secret Service to talk to — off by default, and a genuine,
  labeled downgrade, not a free fix, see THREAT_MODEL.md §3.7.
  Also: `db_key_lock.rs` (optional PIN layer sealing the SQLCipher key,
  Argon2id + ChaCha20-Poly1305, opt-in per profile — now also reachable
  via a WebAuthn passkey's PRF-derived secret instead of a typed PIN, see
  THREAT_MODEL.md §3.7), `own_prekey.rs` (this identity's one long-term
  X3DH signed prekey + hybrid PQ prekey, generated lazily on first real
  send/receive and persisted so a restarted daemon still answers to a
  bundle it already published — schema v15), `local_auth.rs`
  (passkey/TOTP credential storage for the client-side unlock gate —
  does not gate DB decryption itself), `cosmetics.rs`/`message_stickers.rs`
  (inventory/equip state and per-message sticker attachment, SPEC.md §12),
  `push.rs` (this profile's own opt-in wake-relay registration —
  opaque token + on/off, never content or a contact/conversation id),
  `search.rs` (local FTS5 full-text search over this profile's own
  already-decrypted `messages.body` — a pure local query, never
  "content scanning" in the CLAUDE.md-forbidden sense since nothing
  leaves the daemon), `contacts.rs::message_counts_by_contact` (one
  aggregate query — non-deleted `Direct`-conversation message count per
  contact — feeding `bh-api::contacts`'s local trust-level heuristic
  below; never persisted, computed fresh per request). `keystore.rs`'s
  `Backend::File` now creates its directory/file with owner-only
  permissions (`0o700`/`0o600`) at creation time via
  `DirBuilder`/`OpenOptions`'s own `mode` argument rather than a
  follow-up `chmod`, closing a brief window where a freshly-created path
  was readable by other local users under a permissive umask —
  THREAT_MODEL.md §3.7.
- `crates/bh-files` — content-addressed file chunking, per-chunk E2EE,
  resumable download tracking (SPEC.md §5.5). Storage/transport-agnostic by
  design — the daemon wires it to disk and the network separately.
- `crates/bh-api` — localhost RPC surface between daemon and UI clients.
  Real endpoints for identity bootstrap, panic wipe, contacts, moderation
  (block/message-requests/reports), conversations/messages (including
  message editing with a preserved-history model, never a silent
  overwrite), reactions, quote-reply, disappearing-message timers,
  delivery/read receipts, safety numbers, expiring/limited-use invites,
  encrypted conversation export/import, multi-account profile management,
  call signaling/setup (1:1, group, and screen-share), device linking
  (`device_link.rs`) and device *sync* (`device_sync.rs` — keeps an
  already-linked device's message history current, distinct from linking
  itself), real `Direct`-conversation message encryption/delivery over
  `bh-network` when attached (`message_crypto.rs`'s
  `send_encrypted_over_network`/`message_receive.rs`'s
  `spawn_receive_loop` — see the `daemon/` entry above), passkey/TOTP
  local-unlock (`local_auth.rs`), groups
  (`groups.rs`, including broadcast channels — a group with
  `broadcast_only` set so only the owner may post, enforced at the API
  layer on top of the same MLS group, not a crypto-level restriction),
  file/media attachments (`files.rs`, including voice messages — the same
  attachment path tagged `attachment_kind: voice` with a duration, body
  `null` like a sticker), sticker packs (`stickers.rs`, gated by
  cosmetic-inventory ownership), the cosmetics store (`cosmetics.rs`),
  opt-in typing presence (`presence.rs`), opt-in wake-push registration
  (`push.rs`), and local full-text search (`search.rs`) — all backed by
  `bh-storage`/`bh-crypto`/`bh-calls`/`bh-files`, verified end-to-end via
  live HTTP smoke tests during development plus an in-process
  `tower::ServiceExt` integration test suite
  (`crates/bh-api/tests/api_smoke.rs`). **Device linking and device sync
  now travel the real network too**, each proven by a genuine two-daemon
  integration test with zero shared process state: device linking's
  4-step ceremony (`begin`/`scan`/`accept`/`finish`) routes its two
  bootstrap ciphertexts through a new one-shot DHT relay
  (`bh_network::device_link_relay`) when a network is attached — a
  genuinely separate "new device" daemon (no `own_identity` of its own
  yet) recovers the primary's real account identity this way
  (`device_linking_completes_a_real_ceremony_between_two_daemons_over_the_network`);
  the linked device's own per-device identity was widened from a bare
  Ed25519 signing key to a full signing+X25519-agreement pair
  (`bh_crypto::device_link::NewDevice::device_identity`) specifically so
  it can be addressed the same way a `Contact` is. Device sync then
  pushes real pending `Direct`-conversation messages to that device's real
  mailbox (`device_sync::sync_device_over_network`, reusing
  `message_crypto::send_encrypted_over_network` against a pseudo-`Contact`
  built from the `Device` row) rather than encrypting-and-immediately-
  decrypting in the same process
  (`device_sync_pushes_a_real_message_to_a_linked_device_over_the_network`).
  **Deliberately still out of scope** (see `device_link.rs`'s own module
  doc): a real linked device does not install the transferred account
  identity as its own `own_identity` — doing so would collide its
  `recipient_key_hash` with the primary's, and this codebase's `Direct`
  mailbox is delete-on-read/single-consumer (unlike `Group`'s
  `Mailbox::fan_out`), so two daemons racing to pull the same account's
  incoming mail would silently drop messages for whichever loses. Falls
  back to the pre-existing same-daemon simulation whenever there's no live
  network (or, for sync, no `identity_agreement_key` on record for that
  device yet) — same-daemon device linking exercises the real 4-step
  protocol without a second physical device; same-daemon device sync
  exercises a genuine X3DH + Double Ratchet handshake between the primary
  device's real identity and a locally-generated shadow identity for the
  linked device's endpoint (same trick groups uses for contacts). Groups
  (including broadcast channels and group calls) similarly fall back to
  per-contact/per-participant "shadow" MLS members generated locally
  whenever there's no live network or no real key package published yet
  for the target contact (see the `bh-network`/`bh-crypto` entries above
  for the real-network group-membership path) — and live MLS group state
  does survive a daemon restart
  (`bh_crypto::mls_storage::PersistentMlsProvider` backs the own member in
  every group, and `bh-api::groups.rs` reconstructs a `GroupRegistry`
  cache miss from storage — `add_member`/`remove_member`/`mls-self-test`
  no longer return `410` after a restart — THREAT_MODEL.md §3.2);
  attachments are base64-in-JSON with a 25 MiB cap, and are swept by the
  disappearing-message timer (the expiry sweeper deletes a purged
  message's orphaned chunk directory from disk, not just its DB row).
  Local search (`search.rs`) is a pure local SQLite FTS5 query over this
  profile's own already-decrypted message history — nothing about a
  search term or its results ever leaves the daemon process, so this is
  not "content scanning" in the CLAUDE.md-forbidden sense. The ordinary
  passkey/TOTP local-unlock screen gates the Tauri client's UI only — it
  does not gate SQLCipher DB decryption. A separate, dedicated passkey
  enrollment (WebAuthn's PRF extension, `client/desktop`'s "Database
  lock" setting) genuinely does, by having the Tauri shell withhold
  spawning the daemon until the PRF assertion succeeds — TOTP is
  deliberately excluded from this path (a TOTP secret has to be readable
  by the client without the database open, so it can't provide a real
  second factor here) — see THREAT_MODEL.md §3.7. **Shareable blocklists**
  (`moderation.rs`'s `export_blocklist`/`decode_blocklist`/
  `apply_blocklist`, three new routes under `/moderation/blocklist/*`): a
  courtesy export, not a moderation system — a copyable
  `blackhole://blocklist?d=...` link (plain base64 JSON, same convention
  as `bh_crypto::invite::InvitePayload::to_link`, no encryption since
  nothing in it is secret) listing the identity public keys + local
  labels of this profile's own blocked contacts. Decoding only ever
  *previews* which entries match the importer's own contact book;
  applying only ever blocks a contact the importer already has and
  explicitly selected by id — nothing here creates a contact or blocks
  anyone automatically, keeping the "no content moderation, ever"
  non-negotiable intact (every real effect is the same local
  `set_contact_blocked` call the existing block button already used).
  **Contact trust level** (`contacts.rs`'s `TrustLevel`/
  `compute_trust_level`, folded into `GET /contacts`'s response as
  `ContactView`): a purely local, never-persisted UI heuristic
  (`Blocked`/`Verified`/`Established`/`New`) computed fresh from
  `Contact.blocked`/`Contact.verified` plus
  `bh-storage::contacts::message_counts_by_contact` — `Established` means
  "≥10 non-deleted messages over ≥3 days," a much weaker signal than
  `Verified`'s real safety-number confirmation, shown only so a longtime
  unverified contact doesn't look identical to one added five minutes
  ago. `require_bearer_token` (`server.rs`) now compares the presented
  token to `state.api_token` with `subtle::ConstantTimeEq` instead of
  plain `==`, closing a timing side channel a co-located local process
  could otherwise use to narrow down the token byte-by-byte —
  THREAT_MODEL.md §3.9.
- `crates/bh-calls` — voice/video calls: real WebRTC transport (ICE/DTLS/
  SRTP via `webrtc-rs`) plus an independent SFrame-style end-to-end media
  encryption layer keyed from `bh-crypto::call_keys` (so even a coerced
  relay can't see call content). Opus audio (capture/encode/decode/
  playback) is fully real and tested; camera capture and VP8 encoding are
  real, but VP8 *decoding* is deliberately left to the client (no audited
  safe-Rust VP8 decoder exists — see SPEC.md §15/THREAT_MODEL.md §3.11).
  **Group calls** (`group.rs`): full-mesh WebRTC (every participant
  connects directly to every other one, capped at
  `MAX_GROUP_CALL_PARTICIPANTS = 6` — no SFU exists yet), with the shared
  SFrame base key derived straight from the call's MLS group via
  `bh_crypto::mls::Group::export_call_base_key` (RFC 9420's own exporter
  secret, the same mechanism a TLS 1.3 exporter uses) instead of a bespoke
  per-edge key-agreement scheme — every member already shares epoch
  secrets after processing the same commits, so no extra round trip is
  needed and no new crypto primitive was written. **Screen sharing**
  (`screen.rs`, via the cross-platform `scap` crate — ScreenCaptureKit on
  macOS, Windows.Graphics.Capture on Windows, the PipeWire portal on
  Linux): frames flow through the *exact same* VP8 encode + SFrame
  encrypt path camera video already uses, just on a second, parallel
  track (`"screen"` vs `"video"` track id) — not a separate codec or
  encryption scheme. STUN is wired in (`transport::default_ice_servers`
  — a public server by default, `BLACKHOLE_STUN_SERVERS`-configurable, used
  by every `new_peer_connection` call site including group-mesh edges), so
  ordinary-NAT peers no longer both need to be directly reachable. **TURN
  is now configurable too** — `BLACKHOLE_TURN_SERVERS` (comma-separated
  `turn:`/`turns:` URLs) plus `BLACKHOLE_TURN_USERNAME`/
  `BLACKHOLE_TURN_CREDENTIAL`, all three required together or none is added
  (`default_ice_servers` fails soft with a `tracing::warn!` rather than
  building a config `webrtc-rs` would reject at connection time) — but no
  TURN server is deployed for this project, so unless an operator sets all
  three, a symmetric NAT on either side still won't connect.
  Needs `opus`, `libvpx`, and `pkg-config` installed at build time (see
  `crates/bh-calls/Cargo.toml`); the Linux screen-capture backend
  additionally needs `libpipewire`/`libdbus` headers (see
  `.github/workflows/ci.yml`'s system-dependencies step).
- `crates/bh-push-relay` — a small, separate, internet-facing binary (not
  part of the `bh-api` loopback-only daemon) whose *only* job is relaying
  an opaque "wake up" token — never message content, sender identity, or
  conversation id. `POST /register` accepts a client's opaque token;
  `POST /wake/:token` triggers a content-free push to whatever real
  provider (APNs/FCM/UnifiedPush) is plugged in later, itself still a stub
  (`forward_to_push_provider`, `// TODO(real-push)`, needs platform
  credentials this repo can't provision). In-memory only, no database, no
  logging beyond what's operationally necessary — see the crate's own
  module doc for the full design rationale (SPEC.md §5.6).
  **The daemon side is now genuinely wired to a relay, not just a local
  token store.** `bh-api::push`'s registration state (opaque, rotating
  token + on/off, `bh-storage::push`, opt-in and off by default) grew a
  `relay_url` field (`SCHEMA_V20`); when set with a live network attached,
  enabling push actually calls the relay's real `POST /register` and
  signs-and-publishes a `bh_crypto::push_relay::PushRelayRecord` to the
  DHT (`bh-network::push_relay_directory`, the push-relay counterpart to
  `prekey_directory` — republished periodically alongside the Key
  Transparency tree head, same daemon-loop pattern,
  `push::republish_own_registration_best_effort`) *before* writing
  anything locally — both must succeed, so "push is enabled" can't drift
  from "a contact could actually reach it." The record is signed (not a
  bare DHT value) because an unsigned one would let any DHT node inject an
  attacker-chosen `relay_url`, turning the *fetching* peer's own daemon
  into an SSRF client against a URL it never agreed to; verification uses
  the same already-locally-trusted `Contact::identity_public_key` X3DH
  itself relies on, so no new trust bootstrap was needed. On the send
  side, `bh-api::message_crypto::wake_recipient_best_effort` — the actual
  landing site the old `// TODO(real-push)` marker pointed at — runs
  right after a real mailbox push succeeds: fetches the recipient's
  record, verifies it, and calls `POST {relay_url}/wake/{token}`,
  best-effort (logged, never propagated, since the message itself has
  already genuinely been delivered either way). Proven end-to-end by a
  real two-daemon test plus a genuine third, separately-listening
  `RelayServer` instance (real TCP, not `oneshot` — the daemon reaches it
  over real HTTP via `reqwest`) —
  `bh-api/tests/api_smoke.rs`'s
  `sending_a_message_wakes_the_recipients_real_push_relay`.
  **Still not deployed**: this is all code-level wiring — no actual
  `bh-push-relay` instance runs anywhere for real users yet, same as
  `bh-network`'s own bootstrap nodes and TURN above; an operator still has
  to run one and point `relay_url` at it. The desktop client's push-toggle
  UI also doesn't yet have a `relay_url` input field (still sends
  `{"enabled": true}` with no `relay_url`, which keeps working — the field
  is optional and falls back to the pre-existing local-only behavior) —
  wiring that up is a separate, explicit follow-up, same "backend wired,
  client catches up later" precedent 1:1 calls set.
- `client/desktop` — Tauri desktop client. Real product UI (monochrome
  "Event Horizon" visual direction), wired end-to-end against every
  same-profile `bh-api` route that doesn't need a live network: identity
  bootstrap with one-time seed phrase reveal, contacts/conversations/
  messages (including inline editing with a viewable edit-history
  affordance), safety number verification, invite create/decode/revoke,
  moderation (block/unblock, message requests, reports), multi-profile
  switching, message reactions, delivery/read receipt display,
  disappearing-message timer, encrypted conversation export/import, panic
  wipe, device linking (local simulation, labeled as such in the UI) plus
  device *sync* (a "Sync now" action + pending-count badge per linked
  device), passkey/TOTP local-unlock gate, groups (create/manage
  members/verify the MLS crypto path) including broadcast channels
  (a "Broadcast channel" toggle at creation, labeled `(channel)` in the
  conversation list), file/media attachments (attach, list, download)
  plus voice messages (record via `MediaRecorder`, inline playback), a
  singleton local-only "Notes to self" conversation (pinned at the top of
  the list, no encryption session since there's no counterparty), a
  cosmetics store (browse/buy/equip banners/themes/stickers — "buy"
  records a pending purchase; there is no client-side way to confirm
  payment, by design, since that's gated behind an HMAC secret only a
  real BTCPay webhook should have), a sticker picker in the composer
  (only shows owned packs), opt-in "typing…" indicators (debounced
  send-while-typing + polled status line), a contact's derived **trust
  level** shown as a badge (`bh-api::contacts`'s `Blocked`/`Verified`/
  `Established`/`New`), **shareable blocklists** (export/import panel
  wired to `moderation.rs`'s three new routes — a preview step shows
  which decoded entries match the importer's own contacts before any
  block is applied), client-only **UI preferences**
  (`src/ui_prefs.ts` — density and font-size, pure `localStorage`,
  deliberately not profile-scoped since these describe the device's
  screen, not any identity), opt-in link previews (resolved
  **client-side only**, via a dedicated Tauri command
  (`fetch_link_preview`, `src-tauri/src/link_preview.rs`) that never goes
  through `daemon_call`/the daemon at all — enabling it reveals the
  user's IP to whatever site is linked, stated explicitly in the toggle's
  copy rather than hidden), opt-in wake-push registration, and local
  message search (a search overlay with FTS5-highlighted snippets).
  Talks to the daemon only through a single generic `daemon_call` Tauri
  command (`src-tauri/src/lib.rs`) proxying raw HTTP over loopback — the
  typed request/response surface lives in `src/api.ts`. The Tauri shell
  now also owns the daemon's *process lifecycle*
  (`src-tauri/src/daemon_lifecycle.rs`): `boot()` in `main.ts` calls
  `ensure_daemon_running` itself rather than assuming a daemon is already
  up (it previously wasn't spawning one at all — this was a real gap, not
  a design choice). A "Database lock" setting
  (`src-tauri/src/prf_unlock.rs`, `main.ts`'s `enrollDatabaseUnlockGate`/
  `derivePrfSecret`) lets a profile require a WebAuthn passkey (via the
  PRF extension, hardware-derived, not TOTP — see THREAT_MODEL.md §3.7 for
  why) before the daemon even spawns, genuinely gating SQLCipher
  decryption rather than just the client's own UI. A "Network" settings
  section (`src-tauri/src/network_config.rs`) closes a real gap this
  repo's own real-network deployment work surfaced: `BLACKHOLE_
  BOOTSTRAP_PEERS`/`BLACKHOLE_TURN_*` are plain env vars `daemon/src/
  main.rs`/`bh-calls::transport` read at process start, and the Tauri
  shell used to only pick them up if whatever launched the app happened
  to have them exported — a real bootstrap/TURN connection didn't
  survive the app being closed and reopened normally. `network_config.rs`
  persists them to a local JSON file (`app_config_dir()/
  network_config.json`, `chmod 600`) that `daemon_lifecycle.rs::
  ensure_daemon_running` reads and applies as env vars on the spawned
  daemon `Command` — but only for a var not already present in this
  process's own environment, so the original ad hoc "export it yourself
  before launching" override still works unchanged for anyone who wants
  it. The same settings section also finally gives the opt-in push
  toggle a `relay_url` field (`bh-api::push::PushRegistrationResponse`
  now round-trips it) — previously only reachable via a raw API call.
  **Validated against a real deployment, not just locally**: two
  independent daemons (this client's own, and a separate standalone one)
  found each other and exchanged a real X3DH/Double-Ratchet-decrypted
  message purely through a real, independently-hosted DHT bootstrap node
  reachable over the public internet — no direct dial, no shared process
  state — and a real `POST /calls` offer against that same deployment's
  TURN relay produced a genuine `typ relay` ICE candidate (an actual
  coturn allocation, not just a configured-but-unverified env var).
  Daemon binary resolution is dev-mode only for now
  (`BLACKHOLE_DAEMON_BIN` or a monorepo-relative `cargo tauri dev`
  fallback) — packaging it as a signed Tauri sidecar for real
  distribution is a separate follow-up. Calls
  (1:1 audio/video/screen-share, group audio) now have a client UI: a
  "Call"/"Video" pair in the conversation header for direct conversations
  and a "Group call" button for groups, an in-call overlay with local
  self-preview + remote `<canvas>` elements fed by a WebCodecs
  `VideoDecoder` (`src/calls.ts`'s `Vp8CanvasRenderer` — the client-side
  half of "the daemon never decodes VP8", see `bh-calls::video`'s module
  doc), camera/screen-share toggle buttons, and an audio-only participant
  grid for group calls (no group video/screen track exists yet, matching
  `bh-api::calls`'s own scope note). The daemon's `GET
  /calls/:call_id/ws` (state events + video/screen frames, `bh-api::
  call_stream`) can't be opened by the webview directly — its WebSocket
  handshake always carries an `Origin` header, which `reject_browser_
  origin` rejects, the same reasoning `link_preview.rs` already
  established for "this networking has to happen on the Tauri Rust side"
  — so a new bridge (`src-tauri/src/call_stream_bridge.rs`, using
  `tokio-tungstenite`) dials it instead and relays events/frames to the
  webview via Tauri's event system (`call-event`/`call-frame`, binary
  frames base64-encoded in the JSON payload — the same lesson
  `message_crypto.rs`'s sealed-sender fix learned about not JSON-encoding
  raw `Vec<u8>` on the daemon side). **1:1 calls now place a real call to a
  real contact**: the "Call"/"Video" buttons (`main.ts`'s `startCall`) read
  the open conversation's real `contact_id` and pass it to `POST /calls`,
  which — per `bh-api::calls`'s own module doc — routes the offer through
  that contact's real mailbox instead of the same-daemon demo path; falls
  back to the old same-daemon demo automatically for conversations with no
  resolved `contact_id` (e.g. "Notes to self"). There's still no unprompted
  "incoming call" ringing UI — the daemon auto-answers a real incoming
  offer server-side — but the client now polls `GET /calls/network`
  (`bh-api::calls::list_network_calls`) and shows a minimal banner
  ("Call with X" + Join/Dismiss) once a call it didn't place itself goes
  live. **Group calls remain the same-daemon demo** (matching the existing
  "device linking (local simulation, labeled as such in the UI)"
  precedent): `bh-api::calls`'s own module doc explains `GroupOffer`/
  `GroupAnswer` are deliberately not routed over the network yet, so every
  group call this UI starts still plays every participant role against
  this same daemon — the WebRTC connections, media capture/encode, and
  SFrame end-to-end encryption are all genuine, only the signaling hop is
  local instead of over the network, and the UI says so. The
  passkey enroll/unlock/PRF WebAuthn glue
  (`navigator.credentials.create()/get()` in `main.ts`) can't be
  exercised headlessly — verify manually on real hardware (Touch ID/
  Windows Hello/a security key) before relying on it. (One unrelated
  latent bug found and fixed while first opening this UI in a real
  browser this session: `styles.css` had no `[hidden] { display: none
  !important; }` rule, so every `.overlay`/screen element's own
  `display: flex` silently beat the browser's default `[hidden]` styling
  at equal CSS specificity — every modal in the app, not just the new
  call one, was rendering regardless of its `hidden` attribute. This
  had apparently never been caught because the UI hadn't been opened in
  an actual browser/webview at any point earlier in this session.)
- `docs/SPEC.md` — full spec, source of truth for architecture decisions.
  §15 covers the first post-v0.1 batch (reactions, disappearing timers,
  receipts, safety numbers, expiring invites, encrypted export/import,
  multi-account, calls). §16 covers the second batch (device sync,
  sticker packs/themes, notes to self, message editing, broadcast
  channels, link previews, wake-push relay, voice messages, local search,
  group calls, screen sharing). §17 covers wiring that capability up to
  the real network/UI (real `Direct`-message delivery over `bh-network`,
  the three pragmatic hardening fixes, DHT routing admission control,
  full call-streaming UI, and the daemon/client bearer-token auth layer).
  §18 covers a fourth round: shareable blocklists, the contact trust-level
  heuristic, client-only UI preferences, and a further hardening pass
  (mailbox manifest-size DoS cap, constant-time bearer-token comparison,
  `secure_delete` parity for MLS storage, a `PushRelayRecord` parser
  overflow guard, a keystore file/directory creation race, and the TURN
  credential no longer appearing in a host process listing).
- `docs/THREAT_MODEL.md` — per-subsystem STRIDE analysis grounded in the
  actual implementation, plus a ranked list of known open risks.
- `infra/` — deploy artifacts (not application code) for the three real
  pieces of infrastructure Blackhole needs but doesn't bundle: a DHT
  bootstrap node (Dockerfile + systemd unit wrapping the ordinary
  `bh-daemon` binary with `BLACKHOLE_PERSISTENT_NETWORK_IDENTITY=1` and
  `BLACKHOLE_KEYSTORE_BACKEND=file`), the opaque wake-push relay
  (Dockerfile + systemd unit around `bh-push-relay`, fronted by Caddy for
  automatic TLS), and a TURN relay (`docker-compose.yml`'s `coturn`
  service — coturn itself, not this repo's code; static credentials only,
  see `infra/README.md`'s own limitation note). Nothing here is deployed
  to a real domain by this repo itself — `infra/README.md` is the
  step-by-step guide for an operator who wants to. **Genuinely exercised
  against a real deployment, not just written**: a real bootstrap node and
  TURN relay were stood up and used to validate two independent daemons
  finding each other over the public DHT and a real `typ relay` ICE
  candidate — see the `client/desktop` entry above.

Workspace-wide: 409 tests across `bh-crypto`/`bh-network`/`bh-storage`/
`bh-files`/`bh-api`/`bh-calls`/`bh-push-relay`/`bh-desktop` (including real
local WebRTC connection tests in `bh-calls` — 1:1, three-way group mesh, and
a screen-share track — all of which need real UDP loopback and can be flaky
under sandboxing/CI resource contention; see that crate's test comments;
and a genuine two-daemon, two-identity, real-network integration test in
`bh-api` — `direct_message_travels_a_real_network_between_two_daemons_and_decrypts`
— that sends a `Direct` message as real X3DH/Double Ratchet ciphertext over
an actual Kademlia mailbox push/pull between two independent
`SupervisedNetwork`s, not a same-process shadow session), `cargo fmt`/
`clippy -D warnings` clean, CI in `.github/workflows/ci.yml`.
Nothing here has been through independent security review — see
THREAT_MODEL.md before treating any of it as production-ready, especially
the onion routing module and the calls media path (1:1, group, and
screen-share alike).
