// Adapted from ClawdStrike/Arc (Apache-2.0)
//! Trust-boundary fuzz target for the `swarm_guard` secret-leak guard.
//!
//! The guard scans arbitrary, attacker-controlled bytes (file writes,
//! response payloads) for credential patterns. It must never panic on any
//! input -- including invalid UTF-8 and adversarial regex-stressing strings
//! -- and its match offsets must stay within the scanned text.

#![no_main]

use libfuzzer_sys::fuzz_target;
use swarm_guard::SecretLeakGuard;

fuzz_target!(|data: &[u8]| {
    let guard = SecretLeakGuard::new();

    // Scanning must never panic, regardless of byte content or length.
    let matches = guard.scan(data);

    // Reported offsets/lengths are over the lossy-UTF-8 view of the input.
    // They must be self-consistent (offset + length does not overflow) so
    // downstream redaction/slicing cannot panic.
    let lossy_len = String::from_utf8_lossy(data).len();
    for found in &matches {
        let end = found.offset.checked_add(found.length);
        assert!(
            end.is_some_and(|e| e <= lossy_len),
            "secret match range out of bounds: offset={} length={} text_len={}",
            found.offset,
            found.length,
            lossy_len
        );
    }
});
