# Blackhole

Private P2P messaging with real E2EE, no central custody of data, no content
moderation. Full architecture and rationale: [docs/SPEC.md](docs/SPEC.md).
Contributor-facing summary and non-negotiables: [CLAUDE.md](CLAUDE.md).
Attack-surface breakdown per subsystem: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

**Status: core protocol logic implemented and tested (93 tests), no live
network deployment.** Identity, X3DH + Double Ratchet, MLS groups, the PQ
hybrid handshake, onion routing, the DHT, mailboxes, sealed sender, local
encrypted storage, and the daemon's localhost API all have real, working,
tested code behind them — not stubs. What's still ahead: mobile/web
clients, deployed network infrastructure (relay/mailbox nodes, TURN, a Key
Transparency log), and payments. See `docs/THREAT_MODEL.md` §4 for the
ranked list of known open risks in what *is* built.

## Layout

```
daemon/            bh-daemon binary — the localhost daemon (SPEC.md §6)
crates/
  bh-crypto/        Identity, X3DH + Double Ratchet, MLS, PQ hybrid,
                     passkeys/TOTP, invites, device linking, backups (SPEC.md §2-4)
  bh-network/        libp2p transport, Kademlia DHT, onion routing, sealed
                     sender, mailboxes, cover traffic, anti-spam PoW (SPEC.md §5)
  bh-storage/        SQLCipher-backed data model, platform keystore,
                     self-destruct sweeper (SPEC.md §7)
  bh-files/          content-addressed file chunking, E2EE, resumable
                     download (SPEC.md §5.5)
  bh-api/            localhost RPC surface daemon <-> clients (SPEC.md §6)
client/
  desktop/           Tauri desktop client
docs/
  SPEC.md            full technical specification
  THREAT_MODEL.md    per-subsystem attack surface and known open risks
```

## Building

Requires a stable Rust toolchain, Node.js, [pnpm](https://pnpm.io), and a
system OpenSSL (used to build SQLCipher and the WebAuthn stack). If
`cargo build` can't find it, point it at your OpenSSL install, e.g. on an
Apple Silicon Mac with Homebrew:

```sh
export OPENSSL_DIR=/opt/homebrew/opt/openssl@3
```

```sh
# daemon + all library crates
cargo build --workspace

# run the full test suite (93 tests)
cargo test --workspace

# run the daemon (binds 127.0.0.1:47853 by default)
cargo run -p bh-daemon

# desktop client (in a separate terminal, daemon must be running)
cd client/desktop && pnpm install && pnpm tauri dev
```

CI (`.github/workflows/ci.yml`) runs `cargo fmt --check`,
`cargo clippy -- -D warnings`, `cargo build`, `cargo test`, and the
desktop client's typecheck + build on every push/PR.

## License

[GNU AGPL-3.0-or-later](LICENSE) — chosen so that anyone running a modified
version of Blackhole as a network service has to share their changes too,
consistent with §9's commitment to auditable, reproducible builds. See
[GOVERNANCE.md](GOVERNANCE.md) for how project decisions get made.
