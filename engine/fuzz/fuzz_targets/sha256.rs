// Adapted from ClawdStrike/Arc (Apache-2.0)
//! Trust-boundary fuzz target for `swarm_crypto` SHA-256 and HMAC-SHA256.
//!
//! Hashing underpins every receipt, envelope, and Merkle leaf. It must never
//! panic, must be deterministic, and must survive a hex round-trip so digests
//! recorded in one process verify byte-identically in another.

#![no_main]

use libfuzzer_sys::fuzz_target;
use swarm_crypto::{Hash, hmac_sha256, sha256};

fuzz_target!(|data: &[u8]| {
    // SHA-256 must never panic on any input.
    let hash = sha256(data);
    assert_eq!(hash.as_bytes().len(), 32);

    // Determinism: same bytes -> same digest.
    assert_eq!(hash, sha256(data));

    // Hex round-trip (unprefixed and `0x`-prefixed) must restore the digest.
    let restored = match Hash::from_hex(&hash.to_hex()) {
        Ok(h) => h,
        Err(_) => panic!("sha256 hex output failed to decode: {}", hash.to_hex()),
    };
    assert_eq!(hash, restored);

    let restored_prefixed = match Hash::from_hex(&hash.to_hex_prefixed()) {
        Ok(h) => h,
        Err(_) => panic!("sha256 0x-hex output failed to decode"),
    };
    assert_eq!(hash, restored_prefixed);

    // HMAC: split the input into key/message halves and exercise the keyed
    // path. Must never panic and must be deterministic.
    let split = data.len() / 2;
    let (key, message) = data.split_at(split);
    let mac = hmac_sha256(key, message);
    assert_eq!(mac, hmac_sha256(key, message));
    assert_eq!(mac.as_bytes().len(), 32);
});
