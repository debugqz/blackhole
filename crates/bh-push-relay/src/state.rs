//! In-memory registration state for the push relay. Deliberately
//! non-persistent (see the crate-level doc comment): losing this state on
//! restart just means registered clients silently stop getting wake pings
//! until they next re-register, which is a liveness gap, not a
//! confidentiality one — there was never anything sensitive stored here.

use std::collections::HashSet;
use std::sync::Mutex;

/// Hard cap on total registrations this process will hold in memory.
/// Per-IP rate limiting (see `server.rs`'s `GovernorLayer`) bounds how
/// fast any *one* source can register tokens, but doesn't bound the total
/// across many different source IPs — this closes that separate
/// memory-exhaustion angle. Once reached, new (never-seen) tokens are
/// rejected with `503` rather than growing the set further; an
/// already-registered token re-registering (the common, idempotent case)
/// is unaffected, since that's a no-op past this cap either way.
pub const MAX_REGISTRATIONS: usize = 100_000;

/// Everything the relay knows, in total: the set of currently-registered
/// opaque wake tokens. No message content, no sender/recipient identity,
/// no conversation identifiers — see the `bh_push_relay` crate docs.
pub struct RelayState {
    tokens: Mutex<HashSet<String>>,
    max_registrations: usize,
}

impl Default for RelayState {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayState {
    pub fn new() -> Self {
        Self {
            tokens: Mutex::new(HashSet::new()),
            max_registrations: MAX_REGISTRATIONS,
        }
    }

    /// As [`new`](Self::new), but with an overridable registration cap —
    /// what tests (including `tests/relay_smoke.rs`'s HTTP-level coverage)
    /// use to exercise the cap without actually inserting
    /// [`MAX_REGISTRATIONS`] entries.
    pub fn with_max_registrations(max_registrations: usize) -> Self {
        Self {
            tokens: Mutex::new(HashSet::new()),
            max_registrations,
        }
    }

    /// Remembers `token` as registered. Idempotent — registering the same
    /// token twice (e.g. a client re-registering on a timer to keep its
    /// rotation fresh) is a no-op past the first call. Returns `false`
    /// (and does not insert) if `token` is new and the relay is already at
    /// its registration cap.
    pub fn register(&self, token: String) -> bool {
        let mut tokens = self.tokens.lock().expect("relay state lock poisoned");
        if tokens.contains(&token) {
            return true;
        }
        if tokens.len() >= self.max_registrations {
            return false;
        }
        tokens.insert(token);
        true
    }

    pub fn is_registered(&self, token: &str) -> bool {
        self.tokens
            .lock()
            .expect("relay state lock poisoned")
            .contains(token)
    }

    #[cfg(test)]
    pub fn registered_count(&self) -> usize {
        self.tokens.lock().expect("relay state lock poisoned").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_is_idempotent_and_queryable() {
        let state = RelayState::new();
        assert!(!state.is_registered("tok"));
        state.register("tok".to_string());
        state.register("tok".to_string());
        assert!(state.is_registered("tok"));
        assert_eq!(state.registered_count(), 1);
    }

    #[test]
    fn rejects_new_tokens_once_the_cap_is_reached_but_stays_idempotent_for_known_ones() {
        let state = RelayState::with_max_registrations(2);
        assert!(state.register("a".to_string()));
        assert!(state.register("b".to_string()));
        assert!(
            !state.register("c".to_string()),
            "a brand-new token past the cap must be rejected"
        );
        assert!(
            state.register("a".to_string()),
            "re-registering an already-known token must still succeed even at the cap"
        );
        assert_eq!(state.registered_count(), 2);
    }
}
