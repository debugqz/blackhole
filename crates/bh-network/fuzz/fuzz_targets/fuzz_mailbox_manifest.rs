//! A mailbox manifest is fetched from a DHT record — attacker-influenceable
//! content, since any node can publish a record under a guessed/derived
//! key. `Mailbox::fetch_manifest`'s deserialization must never panic on
//! malformed bytes.

#![no_main]

use bh_network::mailbox::fuzz_only_parse_manifest_bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_only_parse_manifest_bytes(data);
});
