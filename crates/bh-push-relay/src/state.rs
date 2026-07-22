//! In-memory registration state for the push relay. Deliberately
//! non-persistent (see the crate-level doc comment): losing this state on
//! restart just means registered clients silently stop getting wake pings
//! until they next re-register, which is a liveness gap, not a
//! confidentiality one — there was never anything sensitive stored here.

use std::collections::HashSet;
use std::sync::Mutex;

/// Everything the relay knows, in total: the set of currently-registered
/// opaque wake tokens. No message content, no sender/recipient identity,
/// no conversation identifiers — see the `bh_push_relay` crate docs.
#[derive(Default)]
pub struct RelayState {
    tokens: Mutex<HashSet<String>>,
}

impl RelayState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remembers `token` as registered. Idempotent — registering the same
    /// token twice (e.g. a client re-registering on a timer to keep its
    /// rotation fresh) is a no-op past the first call.
    pub fn register(&self, token: String) {
        self.tokens
            .lock()
            .expect("relay state lock poisoned")
            .insert(token);
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
}
