//! `onion::peel_layer` takes bytes straight off the wire from whoever
//! handed this relay a packet — it must never panic on malformed input,
//! only return an error. Uses a fixed relay secret (the fuzzer varies the
//! packet bytes, not the key) and a fixed `now`, since neither affects
//! whether parsing panics.

#![no_main]

use bh_network::onion::peel_layer;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use x25519_dalek::StaticSecret as X25519Secret;

fn relay_secret() -> &'static X25519Secret {
    static SECRET: OnceLock<X25519Secret> = OnceLock::new();
    SECRET.get_or_init(|| X25519Secret::from([7u8; 32]))
}

fuzz_target!(|data: &[u8]| {
    let _ = peel_layer(relay_secret(), data, 1_700_000_000);
});
