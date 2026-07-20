# Blackhole

Private P2P messaging with real E2EE, no central custody of data, no content
moderation. Full architecture and rationale: [docs/SPEC.md](docs/SPEC.md).
Contributor-facing summary and non-negotiables: [CLAUDE.md](CLAUDE.md).

**Status: early scaffold.** The workspace structure and the daemon↔client
localhost boundary exist and build; cryptographic and networking protocol
logic is not implemented yet.

## Layout

```
daemon/            bh-daemon binary — the localhost daemon (SPEC.md §6)
crates/
  bh-crypto/        Signal Protocol, MLS, PQ hybrid (stubs — SPEC.md §2)
  bh-network/        libp2p, DHT, onion routing, mailboxes (stubs — SPEC.md §5)
  bh-storage/        encrypted local storage, key custody (stubs — SPEC.md §7)
  bh-api/            localhost RPC surface daemon <-> clients (implemented)
client/
  desktop/           Tauri desktop client (SPEC.md §6)
docs/
  SPEC.md           full technical specification
```

## Building

Requires a stable Rust toolchain and Node.js.

```sh
# daemon + all library crates
cargo build --workspace

# run the daemon (binds 127.0.0.1:47853 by default)
cargo run -p bh-daemon

# desktop client (in a separate terminal, daemon must be running)
cd client/desktop && npm install && npm run tauri dev
```
