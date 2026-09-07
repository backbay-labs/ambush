//! FALSIFY-02 negative-falsifiability test for
//! `SpineEnvelopeHashMismatchRejected` (docs/assurance/MAPPING.md).
//!
//! `verify_envelope` (crates/swarm-spine/src/envelope.rs:116-151) denies an
//! envelope whose recomputed SHA-256 hash over its canonical, unsigned body
//! does not equal its claimed `envelope_hash` -- any tampering with envelope
//! content after signing. `verify_envelope` is `pub`, so this test calls it
//! directly, the same way `verify_rejects_tampered_fact` in envelope.rs's
//! own `#[cfg(test)]` module already does for positive coverage.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::json;
use swarm_crypto::Keypair;
use swarm_spine::{
    SpineError, build_signed_envelope, compute_envelope_hash_hex, now_rfc3339, verify_envelope,
};

/// A deliberately broken re-implementation of `verify_envelope`'s
/// hash-integrity check (crates/swarm-spine/src/envelope.rs:142-148) with the
/// comparison removed: a claimed `envelope_hash` is trusted without ever
/// being checked against the recomputed hash of the envelope body.
fn broken_hash_check_permits(_computed_hash: &str, _claimed_hash: &str) -> bool {
    true
}

#[test]
fn negative_spine_envelope_hash_mismatch_rejected() {
    let keypair = Keypair::generate();
    let mut envelope =
        build_signed_envelope(&keypair, 1, None, json!({"ok": true}), now_rfc3339()).unwrap();
    let claimed_hash = envelope
        .get("envelope_hash")
        .and_then(serde_json::Value::as_str)
        .unwrap()
        .to_string();

    // Tamper with the signed content after signing.
    envelope["fact"] = json!({"ok": false});

    // 1. The REAL function rejects the tampered envelope.
    let real_result = verify_envelope(&envelope);
    assert!(
        matches!(real_result, Err(SpineError::HashMismatch { .. })),
        "real verify_envelope must reject a tampered envelope, got {real_result:?}"
    );

    // Recompute the hash the tampered body actually produces, the same way
    // `verify_envelope` does, so the broken variant below is handed the
    // real, genuinely-differing pair rather than an abstract stand-in.
    let mut unsigned = envelope.clone();
    if let Some(object) = unsigned.as_object_mut() {
        object.remove("envelope_hash");
        object.remove("signature");
    }
    let computed_hash = compute_envelope_hash_hex(&unsigned).unwrap();
    assert_ne!(
        computed_hash, claimed_hash,
        "fixture must actually produce a differing hash"
    );

    // 2. The broken variant accepts the same mismatched pair.
    assert!(
        broken_hash_check_permits(&computed_hash, &claimed_hash),
        "broken variant is expected to (wrongly) accept the mismatched hash"
    );
}
