# Governance

Blackhole follows a **benevolent dictator** model, the standard governance
pattern for large FOSS projects at this stage (same shape as Linux, Python
for most of its history, Rust before the team-based model matured). This
document exists so that shape is explicit rather than implicit.

## Decision-making

- The project maintainer(s) have final say on protocol design, roadmap, and
  what gets merged. This is a pragmatic choice for a project whose core
  premise — real zero-knowledge, no backdoors, no compromise on the
  non-negotiables in [CLAUDE.md](CLAUDE.md) — benefits from a small number
  of people accountable for holding that line under pressure (commercial,
  legal, or otherwise).
- Anyone can propose changes via issues and pull requests. Technical
  disagreements are worked out in the open, on the merits, in public
  discussion — the maintainer's final say is a tie-breaker of last resort,
  not a substitute for that discussion.
- Changes to anything in `docs/SPEC.md` §2 (cryptographic architecture) —
  and especially §2.2's rule against replacing audited protocols with a
  homegrown cryptosystem without professional cryptographic review and
  formal verification — require the same bar regardless of who proposes
  them, maintainer included.

## Why this model, for now

A small, unincorporated project doesn't have the structure (foundation,
elected technical committee, corporate sponsors balancing each other) that
makes more distributed governance models work well. Benevolent dictatorship
is the honest default until the project has the size and stability to
outgrow it — not a permanent stance.

## What's deferred

- **Economic incentives for people running network nodes** (relay/DHT/
  mailbox infrastructure): not designed yet. See `docs/SPEC.md` §13 — this
  is deliberately postponed until the network's actual operational economics
  are understood, not an oversight.
- **A formal foundation or multi-maintainer structure**: not needed at the
  project's current size. Revisit once there's a real multi-maintainer team
  and/or external funding that would benefit from more formal structure.

## Security and vulnerability reports

A dedicated disclosure process (security contact, PGP key, coordinated
disclosure timeline) is not set up yet — tracked alongside the rest of the
continuous-assurance program in `docs/SPEC.md` §13, which is explicitly
deferred rather than forgotten. Until it exists, open a regular issue for
anything that isn't sensitive, and avoid posting exploit details for
anything that is until a real channel exists.
