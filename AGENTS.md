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
  **`Group` conversations are not wired yet** — real MLS ciphertext
  fan-out via `Mailbox::fan_out` is a separate follow-up, deliberately out
  of scope for this pass (see `message_crypto.rs`'s module doc).
- `crates/bh-crypto` — identity + seed phrase, passkeys/TOTP, X3DH + Double
  Ratchet, MLS, PQ hybrid, invite QR/links, device linking, encrypted
  backups (SPEC.md §2-4). All real, tested implementations. Also:
  `key_transparency.rs` (RFC 6962 Merkle tree hash/inclusion/consistency
  proofs — a tested client-side primitive, not yet a deployed gossiped
  log, THREAT_MODEL.md §3.1), `mls_storage.rs`
  (`PersistentMlsProvider` — SQLCipher-backed `openmls` storage so group
  state survives a daemon restart), `payment_address.rs` (address-format
  validation for XMR/BTC/ETH payment requests), `qr.rs` (shared QR
  rendering for invites/device-linking/safety-numbers), `webhook.rs`
  (HMAC-SHA256 signing/verification gating the cosmetics-store
  payment-confirmed webhook).
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
  existing read-merge-write-verify loop. `prekey_directory.rs` publishes/
  fetches X3DH prekey bundles via the DHT, the mechanism
  `bh-crypto::ratchet::PreKeyBundle`'s own doc comment already pointed at.
  `supervised.rs` wraps the event loop so a panic (e.g. the live `yamux`
  CVE, THREAT_MODEL.md §3.10) respawns a fresh node instead of permanently
  killing that node's networking, and now also exposes `dial()` for
  connecting to a known peer directly (real deployments still need a
  bootstrap-node list, not implemented here).
- `crates/bh-storage` — SQLCipher-backed data model (contacts,
  conversations, messages, groups, devices, sessions, files, settings),
  platform keystore (Keychain/Credential Manager/Secret Service via
  `keyring`), panic wipe, self-destruct message sweeper (SPEC.md §7).
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
  "content scanning" in the AGENTS.md-forbidden sense since nothing
  leaves the daemon).
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
  (`crates/bh-api/tests/api_smoke.rs`). Device linking, device sync,
  groups, and file attachments are deliberately scoped to what works
  without a live `bh-network`: device linking is a single-daemon
  simulation of the real 4-step protocol (not a second physical device);
  device sync exercises a genuine X3DH + Double Ratchet handshake between
  the primary device's real identity and a locally-generated shadow
  identity for the linked device's endpoint (same trick groups uses for
  contacts) so the sync round-trip is real crypto, not a same-process
  echo; groups (including broadcast channels and group calls) use
  per-contact/per-participant "shadow" MLS members generated locally to
  exercise the real crypto path (not real remote peers); and live MLS
  group state does survive a daemon restart
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
  not "content scanning" in the AGENTS.md-forbidden sense. The ordinary
  passkey/TOTP local-unlock screen gates the Tauri client's UI only — it
  does not gate SQLCipher DB decryption. A separate, dedicated passkey
  enrollment (WebAuthn's PRF extension, `client/desktop`'s "Database
  lock" setting) genuinely does, by having the Tauri shell withhold
  spawning the daemon until the PRF assertion succeeds — TOTP is
  deliberately excluded from this path (a TOTP secret has to be readable
  by the client without the database open, so it can't provide a real
  second factor here) — see THREAT_MODEL.md §3.7.
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
  encryption scheme. No STUN/TURN yet, same current limitation as
  `bh-network`, so today's WebRTC connections (1:1, group-mesh, and
  screen-share alike) only work when peers can reach each other directly.
  Needs `opus`, `libvpx`, and `pkg-config` installed at build time (see
  `crates/bh-calls/Cargo.toml`); the Linux screen-capture backend
  additionally needs `libpipewire`/`libdbus` headers (see
  `.github/workflows/ci.yml`'s system-dependencies step).
- `crates/bh-push-relay` — a small, separate, internet-facing binary (not
  part of the `bh-api` loopback-only daemon) whose *only* job is relaying
  an opaque "wake up" token — never message content, sender identity, or
  conversation id. `POST /register` accepts a client's opaque token;
  `POST /wake/:token` (called by the daemon's mailbox code once wired —
  currently a marked `// TODO(real-push)` integration point, not built)
  triggers a content-free push to whatever real provider (APNs/FCM/
  UnifiedPush) is plugged in later, itself still a stub
  (`forward_to_push_provider`). In-memory only, no database, no logging
  beyond what's operationally necessary — see the crate's own module doc
  for the full design rationale (SPEC.md §5.6). The daemon-side
  registration state (opaque, rotating token + on/off) lives in
  `bh-storage::push`/`bh-api::push`, opt-in and off by default.
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
  send-while-typing + polled status line), opt-in link previews (resolved
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
  decryption rather than just the client's own UI. Daemon binary
  resolution is dev-mode only for now (`BLACKHOLE_DAEMON_BIN` or a
  monorepo-relative `cargo tauri dev` fallback) — packaging it as a signed
  Tauri sidecar for real distribution is a separate follow-up. Calls
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
  raw `Vec<u8>` on the daemon side). **Scope note, matching the existing
  "device linking (local simulation, labeled as such in the UI)"
  precedent**: since call-signal delivery between two separate devices
  still isn't wired into the P2P network (`bh-api::calls`'s own module
  doc), every call this UI starts plays both the caller and callee role
  against this same daemon — the WebRTC connection, media capture/encode,
  and SFrame end-to-end encryption are all genuine, only the signaling
  hop is local instead of over the network, and the UI says so. The
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
- `docs/THREAT_MODEL.md` — per-subsystem STRIDE analysis grounded in the
  actual implementation, plus a ranked list of known open risks.

Workspace-wide: 328 tests across `bh-crypto`/`bh-network`/`bh-storage`/
`bh-files`/`bh-api`/`bh-calls`/`bh-push-relay`/`bh-desktop` (including real
local WebRTC connection tests in `bh-calls` — 1:1, three-way group mesh, and
a screen-share track — all of which need real UDP loopback and can be flaky
under sandboxing/CI resource contention; see that crate's test comments;
and a genuine two-daemon, two-identity, real-network integration test in
`bh-api` — `direct_message_travels_a_real_network_between_two_daemons_and_decrypts`
— that sends a `Direct` message as real X3DH/Double Ratchet ciphertext over
an actual Kademlia mailbox push/pull between two independent
`SupervisedNetwork`s, not a same-process shadow session; **Key Transparency
gossip is now deployed**: identities publish signed tree heads over the DHT
every 10 minutes via `bh_network::tree_head`, with best-effort
corroboration alongside safety-number verification — not a replacement for
manual checks, just additional evidence), `cargo fmt`/
`clippy -D warnings` clean, CI in `.github/workflows/ci.yml`.
Nothing here has been through independent security review — see
THREAT_MODEL.md before treating any of it as production-ready, especially
the onion routing module, the calls media path (1:1, group, and
screen-share alike), and the `bh-network` integration (live for `Direct`,
not yet for `Group` conversations).
