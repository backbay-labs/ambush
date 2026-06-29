// Adapted from ClawdStrike/Arc (Apache-2.0)
//! Trust-boundary fuzz target for the `swarm_spine` signed-envelope verify path.
//!
//! A signed spine envelope is Ambush's attestation bundle: issuer pubkey +
//! canonical-JSON hash + Ed25519 signature over the unsigned body. The verify
//! path is the load-bearing fail-closed surface -- on ANY arbitrary input it
//! must return `Err(_)` or `Ok(false)` and MUST NOT panic or abort. A crash
//! here would undermine the tamper-evident claim. We deliberately ignore the
//! `Ok(true)` branch: no arbitrary input can forge a valid Ed25519 signature.

#![no_main]

use libfuzzer_sys::{fuzz_mutator, fuzz_target};
use swarm_fuzz::canonical_json::canonical_json_mutate;
use swarm_spine::envelope::{extract_envelope_hash, verify_envelope};
use swarm_spine::{parse_issuer_pubkey_hex, verify_chain_link};

fuzz_target!(|data: &[u8]| {
    // Raw-bytes accessor: pulls `envelope_hash` out of an arbitrary payload.
    // Fail-closed = `Err` on malformed input; never a panic.
    let _ = extract_envelope_hash(data);

    // The structured verify paths operate on a parsed JSON value.
    let Ok(envelope) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };

    // Full envelope verification: hash-integrity check + signature check.
    // Any outcome other than a panic is acceptable and expected.
    let _ = verify_envelope(&envelope);

    // Chain-continuity verification with no known head (genesis check) and
    // with the envelope as its own claimed predecessor. Fail-closed.
    let _ = verify_chain_link(&envelope, None);

    // Issuer parsing is reachable from untrusted envelope fields; exercise it
    // directly with whatever string the fuzzer placed in `issuer`.
    if let Some(issuer) = envelope.get("issuer").and_then(serde_json::Value::as_str) {
        let _ = parse_issuer_pubkey_hex(issuer);
    }
});

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    canonical_json_mutate(data, size, max_size, seed)
});
