//! `Envelope::decode` runs on whatever bytes a Double Ratchet/MLS session
//! just decrypted — attacker-controlled in the sense that a malicious
//! *sender* the recipient already has a session with could send a
//! malformed envelope payload; it must never panic.

#![no_main]

use bh_crypto::envelope::Envelope;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Envelope::decode(data);
});
