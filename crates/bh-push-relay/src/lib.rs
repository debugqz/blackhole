//! `bh-push-relay`: a minimal, opaque wake-up relay.
//!
//! ## What this is
//!
//! Mobile/desktop OSes suspend idle processes; a sleeping Blackhole daemon
//! can't poll its own mailbox on its own schedule. Real push infrastructure
//! (APNs on iOS, FCM on Android, and their desktop equivalents) exists to
//! solve exactly this: wake the process so *it* can go do the real work —
//! reconnect and pull from the actual mailbox/network (`bh-network`). This
//! crate is that wake-up call, and nothing else. See `docs/SPEC.md` §5.6,
//! which already calls for "APNs/FCM with empty payloads... the push
//! carries no content or readable metadata" — this crate is that piece.
//!
//! Concretely: two endpoints, both intentionally dumb.
//!
//! - `POST /register` — a client submits an opaque, rotating token it (or,
//!   in practice, its own daemon — see `bh-api::push`) generated itself.
//!   The relay remembers "this token is currently registered," full stop.
//! - `POST /wake/:token` — called by *that same identity's own* daemon
//!   (via its `bh-network` mailbox code, once that integration is wired
//!   up — see the `// TODO(real-push)` marker next to
//!   `bh_network::mailbox::Mailbox::push`) when a new mailbox item shows
//!   up for a recipient who has push enabled. If the token is registered,
//!   the relay immediately hands off a *content-free* wake signal to
//!   whatever downstream push provider is configured, and forgets the
//!   request happened. It does not queue, retry, or store anything about
//!   it.
//!
//! ## What this is emphatically not
//!
//! - **Not a mailbox.** No message content, ciphertext, or metadata about
//!   a message ever reaches this crate, and there is no code path that
//!   could even accept one — `RegisterRequest` and the `/wake/:token`
//!   path only ever carry a bare opaque string. There is deliberately no
//!   content-scanning code here to disable or bypass later, because there
//!   is nothing here capable of seeing content in the first place
//!   (CLAUDE.md: no content scanning, ever).
//! - **Not identity-aware.** The token is not, and must never become, an
//!   identity public key, a contact id, a conversation id, or anything
//!   derived from them (see `bh-api::push` for how the daemon generates
//!   it). As far as this relay is concerned, every registration is an
//!   unlabeled, unlinkable bearer string. It has no way to tell two
//!   registrations from the same person apart from two registrations from
//!   different people, and that is by design, not an oversight to fix
//!   later.
//! - **Not durable.** Registration state lives in memory only
//!   (`state::RelayState`), guarded by a mutex, and is gone on restart.
//!   Losing it just means an affected client's next wake silently no-ops
//!   until the client re-registers — a UX/liveness gap, not a
//!   confidentiality one: there was never anything sensitive in here to
//!   lose.
//! - **Not wired to a real push provider yet.** `forward_to_push_provider`
//!   in `server.rs` is a stub — see the `// TODO(real-push)` comment
//!   there. Real APNs/FCM (or UnifiedPush on Android, SPEC.md §5.6)
//!   integration needs platform credentials (an Apple push key / a
//!   Firebase service account) that this task cannot provision. When that
//!   lands, `forward_to_push_provider` is the only function that should
//!   need to change — the register/wake contract above stays the same.
//!
//! ## Logging
//!
//! Zero-knowledge (CLAUDE.md) applies to the operator of this relay, not
//! just to message content, so this crate logs only what is operationally
//! necessary to run the service — that a register/wake request happened
//! and whether it succeeded — and never the token value itself. There is
//! no request/response logging middleware wired in here, and no database
//! of any kind: `RelayState` is the entire universe of what this process
//! knows, and it is a `HashSet<String>` held in memory. If an access-log
//! or metrics layer is ever added in front of this (e.g. at a reverse
//! proxy), it must be audited against this same constraint before it
//! ships — IP addresses and request timing are themselves the kind of
//! "who talks to whom" metadata SPEC.md §2.3 already worries about.
//!
//! ## Why a separate crate/binary
//!
//! Every other new server-side surface in this repo (`bh-api`) is
//! localhost-only, running inside the user's own daemon (SPEC.md §6). This
//! is the first genuinely *public*, internet-reachable component in the
//! repo: it has to run somewhere APNs/FCM (or a daemon acting on behalf of
//! a different, sleeping machine) can actually reach, which by definition
//! is not the user's own loopback interface. Keeping it a separate
//! crate/binary — rather than, say, a route bolted onto `bh-api` — means
//! it can be deployed, scaled, and (most importantly) *audited*
//! independently, with a codebase that stays small enough to be
//! obviously-correct-by-inspection: nothing about it should ever need to
//! grow past "have I seen this opaque token before, yes or no."

pub mod server;
pub mod state;

pub use server::RelayServer;
pub use state::RelayState;
