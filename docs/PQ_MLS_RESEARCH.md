# Post-quantum MLS: research findings and recommendation (2026-07-24)

Scope: whether `crates/bh-crypto/src/mls.rs` (group messaging, RFC 9420 via
`openmls`) can move from its current classical ciphersuite
(`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`) to a real, audited,
standardized post-quantum hybrid ciphersuite — the same way
`bh-crypto::ratchet` already does for 1:1 sessions via
`bh-crypto::pq_hybrid` (X25519 + ML-KEM-768, HKDF-combined).

**Outcome: no code change.** Per `CLAUDE.md`'s non-negotiable
("A homegrown cryptosystem is explicitly deferred and gated on
professional cryptographers + formal verification — see SPEC.md §2.2")
and this phase's own hard restriction, this document is the deliverable —
a from-scratch ML-KEM+MLS combination was never on the table, and the one
path that *doesn't* require hand-rolling anything still fails both the
"standardized" and "audited" bar today, for reasons specific enough to
record rather than re-derive next time this gets revisited.

## What's actually available in this workspace's dependency tree

`openmls_traits` 0.5.0 (pinned via `openmls = "0.8"` in
`crates/bh-crypto/Cargo.toml`) already reserves a ciphersuite codepoint
for a hybrid PQ construction:

```
MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 = 0x004D
```

X-Wing is a general-purpose hybrid KEM combining X25519 and ML-KEM-768
(the same ML-KEM-768 `bh_crypto::pq_hybrid` already uses for 1:1
sessions) via a published, analyzed combiner — not a from-scratch
construction, if it were usable as-is.

It isn't, on the crypto backend this repo actually depends on.
`openmls_rust_crypto` 0.5.1 — the `OpenMlsCrypto` provider
`mls.rs::MlsMember::new`/`new_persistent` wire in — stubs it out:

```rust
// openmls_rust_crypto-0.5.1/src/provider.rs
HpkeKemType::XWingKemDraft6 => {
    unimplemented!("XWingKemDraft6 is not supported by the RustCrypto provider.")
}
```

Calling into this ciphersuite with the crypto backend this codebase
actually uses would panic, not silently do the wrong thing — but it also
means the ciphersuite ID being *declared* in `openmls_traits` is not
evidence it's *usable* here.

There is a second, official `openmls`-org crate that does implement it:
`openmls_libcrux_crypto` 0.3.1 (`github.com/openmls/openmls/tree/main/
openmls_libcrux_crypto`, MIT, compatible with `openmls_traits` 0.5.0 —
same line this repo already pins), backed by Cryspen's `libcrux`:

```rust
// openmls_libcrux_crypto-0.3.1/src/crypto.rs
HpkeKemType::XWingKemDraft6 => hpke_rs_crypto::types::KemAlgorithm::XWingDraft06,
```

So the shape of "swap the crypto provider, not hand-roll a combiner" is
real and would be a small, mechanical change if the underlying pieces
cleared the bar. They don't, for two independent reasons:

## 1. X-Wing is not standardized, and neither is MLS-over-X-Wing

- `draft-connolly-cfrg-xwing-kem` (currently `-10`, dated 2026-03-02) is
  an Internet-Draft with **Informational** intended status — not on the
  standards track, and per the IETF's own boilerplate, "not endorsed by
  the IETF and has no formal standing in the IETF standards process."
- The MLS-specific ciphersuite wrapping it is *also* still draft-stage:
  `draft-mahy-mls-xwing` (registering `MLS_128_XWING_AES128GCM_SHA256_
  Ed25519`) and the broader `draft-ietf-mls-pq-ciphersuites`. Neither is
  an RFC.
- Notably, neither draft's registered value matches the `0x004D`
  codepoint `openmls_traits` actually ships (`MLS_256_XWING_
  CHACHA20POLY1305_SHA256_Ed25519`) — `openmls` picked its own
  experimental allocation ahead of IANA registration settling. Building
  against it today means building against a codepoint that could still
  change or collide before anything is final.

## 2. The one available implementation has had real, recent bugs

Cryspen's `libcrux` (specifically `libcrux-ml-kem`, what
`openmls_libcrux_crypto`'s X-Wing support is built on) is formally
verified in F*/hax for the portable and AVX2 code paths — a genuinely
strong verification story on paper. But a 2026 independent audit
("Verification Theatre: False Assurance in Formally Verified [...]",
[eprint 2026/192](https://eprint.iacr.org/2026/192.pdf)) found **13 real
vulnerabilities** across `libcrux` and `hpke-rs`, including:

- Four bugs in the *formally verified* ML-KEM specification/proof code
  itself — a wrong decompression constant, a missing inverse NTT step,
  and a proof of serialization correctness that doesn't actually hold.
- Nine more in unverified surrounding code, including a cross-backend
  endianness bug that caused **real decryption failures in Signal's own
  production post-quantum ratchet** — i.e. this isn't a theoretical
  concern about an unused corner of the library; the same class of bug
  already broke a real deployed messaging app's PQ path.

This is the concrete version of exactly what "formal verification isn't
a substitute for independent audit" means in practice, and it's squarely
inside the code path X-Wing-via-`openmls_libcrux_crypto` would depend on.

## Recommendation: wait, don't adopt yet

Do not switch `bh-crypto::mls`'s `CIPHERSUITE` to X-Wing (or any other
draft ciphersuite) now. Revisit when **both**:

1. A PQ MLS ciphersuite reaches at least IETF working-group adoption with
   a stable, IANA-registered codepoint (ideally RFC, at minimum a
   standards-track draft past the "any individual submission" stage
   `draft-connolly-cfrg-xwing-kem`/`draft-mahy-mls-xwing` are at today),
   *and*
2. The specific implementation this repo would depend on
   (`libcrux-ml-kem` today, or whatever backs the eventual codepoint) has
   a clean independent audit *after* the 2026/192 findings are fixed and
   re-reviewed — formal verification passing is necessary but, per that
   audit, demonstrably not sufficient on its own.

Until then, `bh-crypto::mls` stays on the classical
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` ciphersuite. This is a
real, currently-unclosed gap relative to `bh-crypto::ratchet`'s 1:1
sessions (which already have PQ hybrid protection via
`bh_crypto::pq_hybrid`), tracked in `docs/THREAT_MODEL.md` §3.2 — not
silently accepted as fine, just correctly sequenced behind
standardization and audit catching up.

**Escalating per `docs/SPEC.md` §2.2**: this phase's own hard
restriction requires stopping here rather than writing a from-scratch
ML-KEM+MLS combination, which is exactly the kind of homegrown
cryptosystem work `CLAUDE.md` gates on professional cryptographers and
formal verification. That gate has not been met — this is a research
finding to act on (or explicitly override, with eyes open) at your
discretion, not a decision I'm making unilaterally.
