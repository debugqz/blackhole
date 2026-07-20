# Blackhole

P2P E2EE messaging platform. Zero-knowledge by design: the operator cannot read
content or reconstruct who talks to whom. No content moderation, ever — that's
a design principle, not a policy. Monetization is cosmetic-only (profile
gifts/themes), paid in crypto (Monero primary), never "more privacy" as an
upsell.

Full architecture, rationale, and open questions: **[docs/SPEC.md](docs/SPEC.md)**.
Read it before making protocol, crypto, or networking decisions — most
"why is it built this way" questions are answered there.

## Non-negotiables (do not casually change)

- No custom crypto primitives. Signal Protocol (X3DH + Double Ratchet) for 1:1,
  MLS (RFC 9420) for groups, hybrid post-quantum (X25519 + ML-KEM) from day
  one. A homegrown cryptosystem is explicitly deferred and gated on
  professional cryptographers + formal verification — see SPEC.md §2.2.
  Do not implement one.
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

- `daemon/` — Rust binary; wires together the crates below and exposes the
  localhost API the UI talks to (SPEC.md §6).
- `crates/bh-crypto` — Signal Protocol / MLS / PQ hybrid, wrapping audited
  primitives only (SPEC.md §2).
- `crates/bh-network` — libp2p transport, Kademlia DHT, onion routing,
  store-and-forward mailboxes (SPEC.md §5).
- `crates/bh-storage` — encrypted-at-rest local storage (SPEC.md §7).
- `crates/bh-api` — localhost RPC surface between daemon and UI clients.
- `client/desktop` — Tauri desktop client.
- `docs/SPEC.md` — full spec, source of truth for architecture decisions.

All crates are currently skeletons (module structure + stubbed signatures,
`todo!()` where protocol logic goes) — no cryptographic or networking logic
is implemented yet.
