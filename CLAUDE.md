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
  the UI talks to (SPEC.md §6). `bh-network` (DHT/onion/mailboxes) is not
  wired into the daemon yet — it's a fully tested standalone layer, not yet
  connected to a live network or to message send/receive.
- `crates/bh-crypto` — identity + seed phrase, passkeys/TOTP, X3DH + Double
  Ratchet, MLS, PQ hybrid, invite QR/links, device linking, encrypted
  backups (SPEC.md §2-4). All real, tested implementations.
- `crates/bh-network` — libp2p transport + Kademlia DHT, onion routing,
  Eclipse/Sybil-resistant node selection, cover traffic, mailboxes, sealed
  sender, anti-spam PoW (SPEC.md §5). Real and tested against local
  multi-node scenarios; not yet deployed against a real network, and see
  THREAT_MODEL.md §3.4/§3.6 for the two biggest known gaps (onion packet-
  size leak, mailbox manifest race).
- `crates/bh-storage` — SQLCipher-backed data model (contacts,
  conversations, messages, groups, devices, sessions, files, settings),
  platform keystore (Keychain/Credential Manager/Secret Service via
  `keyring`), panic wipe, self-destruct message sweeper (SPEC.md §7).
- `crates/bh-files` — content-addressed file chunking, per-chunk E2EE,
  resumable download tracking (SPEC.md §5.5). Storage/transport-agnostic by
  design — the daemon wires it to disk and the network separately.
- `crates/bh-api` — localhost RPC surface between daemon and UI clients.
  Real endpoints for identity bootstrap, panic wipe, contacts, moderation
  (block/message-requests/reports), conversations/messages, reactions,
  quote-reply, disappearing-message timers, delivery/read receipts, safety
  numbers, expiring/limited-use invites, encrypted conversation
  export/import, multi-account profile management, and call
  signaling/setup — all backed by `bh-storage`/`bh-crypto`/`bh-calls`,
  verified end-to-end via live HTTP smoke tests during development plus an
  in-process `tower::ServiceExt` integration test suite
  (`crates/bh-api/tests/api_smoke.rs`).
- `crates/bh-calls` — voice/video calls: real WebRTC transport (ICE/DTLS/
  SRTP via `webrtc-rs`) plus an independent SFrame-style end-to-end media
  encryption layer keyed from `bh-crypto::call_keys` (so even a coerced
  relay can't see call content). Opus audio (capture/encode/decode/
  playback) is fully real and tested; camera capture and VP8 encoding are
  real, but VP8 *decoding* is deliberately left to the client (no audited
  safe-Rust VP8 decoder exists — see SPEC.md §15/THREAT_MODEL.md §3.11).
  No STUN/TURN yet, same current limitation as `bh-network`. Needs `opus`,
  `libvpx`, and `pkg-config` installed at build time (see
  `crates/bh-calls/Cargo.toml`).
- `client/desktop` — Tauri desktop client. Minimal dev shell (not product
  UI) with daemon health check, panic wipe button, and window-blur content
  mitigation wired up.
- `docs/SPEC.md` — full spec, source of truth for architecture decisions.
  §15 covers everything added post-v0.1 (reactions, disappearing timers,
  receipts, safety numbers, expiring invites, encrypted export/import,
  multi-account, calls).
- `docs/THREAT_MODEL.md` — per-subsystem STRIDE analysis grounded in the
  actual implementation, plus a ranked list of known open risks.

Workspace-wide: 141 tests across `bh-crypto`/`bh-network`/`bh-storage`/
`bh-files`/`bh-api`/`bh-calls` (including a real local two-peer WebRTC
connection test in `bh-calls`), `cargo fmt`/`clippy -D warnings` clean, CI
in `.github/workflows/ci.yml`. Nothing here has been through independent
security review — see THREAT_MODEL.md before treating any of it as
production-ready, especially the onion routing module and the new calls
media path.
