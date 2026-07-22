//! `sealed_sender::unseal` decrypts an envelope from whoever handed us
//! one — the mailbox delivers it verbatim from an untrusted publisher.
//! Fuzzes the actual wire format (JSON-serialized `SealedSenderEnvelope`,
//! matching how it round-trips through the DHT/mailbox), not just the
//! struct fields directly, so this also exercises the deserialization
//! step, not only `unseal`'s own AEAD parsing.

#![no_main]

use bh_network::sealed_sender::{unseal, SealedSenderEnvelope};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use x25519_dalek::StaticSecret as X25519Secret;

fn recipient_secret() -> &'static X25519Secret {
    static SECRET: OnceLock<X25519Secret> = OnceLock::new();
    SECRET.get_or_init(|| X25519Secret::from([9u8; 32]))
}

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = serde_json::from_slice::<SealedSenderEnvelope>(data) {
        let _ = unseal(recipient_secret(), &envelope);
    }
});
