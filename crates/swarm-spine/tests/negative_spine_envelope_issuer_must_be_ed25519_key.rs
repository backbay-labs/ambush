//! FALSIFY-02 negative-falsifiability test for
//! `SpineEnvelopeIssuerMustBeEd25519Key` (docs/assurance/MAPPING.md).
//!
//! `parse_issuer_pubkey_hex` (crates/swarm-spine/src/envelope.rs:25-37)
//! denies an envelope `issuer` string that is not exactly
//! `swarm:ed25519:` followed by 64 hex characters. It is `pub`, so this test
//! calls it directly, the same way `parse_issuer_rejects_bad_hex_or_length`
//! in envelope.rs's own `#[cfg(test)]` module already does for positive
//! coverage.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use swarm_spine::{SpineError, parse_issuer_pubkey_hex};

/// A deliberately broken re-implementation of `parse_issuer_pubkey_hex`
/// (crates/swarm-spine/src/envelope.rs:26-37) with the length/hex-charset
/// check removed: whatever follows the `swarm:ed25519:` prefix is accepted
/// verbatim, even when it is not a well-formed 32-byte key encoding.
fn broken_parse_issuer_pubkey_hex(issuer: &str) -> Result<String, String> {
    issuer
        .strip_prefix("swarm:ed25519:")
        .map(str::to_string)
        .ok_or_else(|| "bad prefix".to_string())
}

#[test]
fn negative_spine_envelope_issuer_must_be_ed25519_key() {
    let bad_issuer = "swarm:ed25519:not-actually-hex";

    // 1. The REAL function rejects non-hex/wrong-length key material.
    let real_result = parse_issuer_pubkey_hex(bad_issuer);
    assert!(
        matches!(real_result, Err(SpineError::InvalidIssuer(_))),
        "real parse_issuer_pubkey_hex must reject malformed key material, got {real_result:?}"
    );

    // 2. The broken variant accepts the identical malformed issuer.
    assert!(
        broken_parse_issuer_pubkey_hex(bad_issuer).is_ok(),
        "broken variant is expected to (wrongly) accept the malformed key material"
    );
}
