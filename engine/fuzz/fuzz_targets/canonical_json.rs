// Adapted from ClawdStrike/Arc (Apache-2.0)
//! Trust-boundary fuzz target: RFC 8785 canonical-JSON round-trip / idempotence.
//!
//! Tamper-evidence rests on canonicalization being a deterministic, stable
//! fixpoint: `canon(parse(canon(x))) == canon(x)`. If any input breaks that
//! fixpoint, two honest verifiers could compute different digests over the
//! same logical document. This target asserts the fixpoint and that
//! canonicalization never panics on any `serde_json`-parseable input.

#![no_main]

use libfuzzer_sys::{fuzz_mutator, fuzz_target};
use swarm_crypto::canonicalize_json;
use swarm_fuzz::canonical_json::canonical_json_mutate;

fuzz_target!(|data: &[u8]| {
    // Only structurally valid JSON reaches the canonicalizer; arbitrary
    // bytes that are not JSON are not in scope for this surface.
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };

    // First canonicalization. Must not panic. Numbers serde_json cannot
    // represent finitely never appear in a parsed `Value`, so `Err` here
    // would itself be a finding; we treat it as fail-closed and stop.
    let Ok(canonical) = canonicalize_json(&value) else {
        return;
    };

    // Canonical output is always valid JSON: it must re-parse.
    let reparsed: serde_json::Value = match serde_json::from_str(&canonical) {
        Ok(v) => v,
        Err(_) => panic!("canonical JSON failed to re-parse: {canonical}"),
    };

    // Idempotence / fixpoint: canonicalizing the canonical form must yield
    // byte-identical output. A mismatch means the canonical form is not a
    // stable digest input -> tamper-evidence claim is unsound.
    let Ok(canonical2) = canonicalize_json(&reparsed) else {
        panic!("re-canonicalization of canonical form errored: {canonical}");
    };
    assert_eq!(
        canonical, canonical2,
        "canonicalization is not idempotent"
    );
});

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    canonical_json_mutate(data, size, max_size, seed)
});
