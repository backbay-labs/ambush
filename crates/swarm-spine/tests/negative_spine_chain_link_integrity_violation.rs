//! FALSIFY-02 negative-falsifiability test for
//! `SpineChainLinkIntegrityViolation` (docs/assurance/MAPPING.md).
//!
//! `verify_chain_link` (crates/swarm-spine/src/chain.rs:75-151) denies an
//! envelope that does not correctly continue its issuer's hash chain, which
//! surfaces as a non-`is_valid()` verdict such as `SequenceMismatch`.
//! `verify_chain_link` is `pub`, so this test calls it directly, the same
//! way `seq_gap` in chain.rs's own `#[cfg(test)]` module already does for
//! positive coverage.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::json;
use swarm_crypto::Keypair;
use swarm_spine::{
    ChainLinkVerdict, build_signed_envelope, chain_head_from_envelope, now_rfc3339,
    verify_chain_link,
};

/// A deliberately broken re-implementation of `verify_chain_link`'s
/// sequence-continuity check (crates/swarm-spine/src/chain.rs:128-138) with
/// the `seq == expected_seq` comparison removed: any sequence number is
/// accepted as a valid continuation of the known head, including one that
/// skips ahead.
fn broken_sequence_check_permits(_expected_seq: u64, _actual_seq: u64) -> bool {
    true
}

#[test]
fn negative_spine_chain_link_integrity_violation() {
    let keypair = Keypair::generate();
    let first =
        build_signed_envelope(&keypair, 1, None, json!({"type": "init"}), now_rfc3339()).unwrap();
    let head = chain_head_from_envelope(&first).unwrap();

    // The next envelope should be seq=2 to continue the chain; skip to
    // seq=3 instead (a gap).
    let third = build_signed_envelope(
        &keypair,
        3,
        Some(head.envelope_hash.clone()),
        json!({"type": "step"}),
        now_rfc3339(),
    )
    .unwrap();

    // 1. The REAL function rejects the sequence gap.
    let verdict = verify_chain_link(&third, Some(&head)).unwrap();
    assert!(
        matches!(
            verdict,
            ChainLinkVerdict::SequenceMismatch {
                expected_seq: 2,
                actual_seq: 3,
            }
        ),
        "real verify_chain_link must reject a sequence gap, got {verdict:?}"
    );
    assert!(!verdict.is_valid());

    // 2. The broken variant accepts the identical gap.
    assert!(
        broken_sequence_check_permits(2, 3),
        "broken variant is expected to (wrongly) accept the sequence gap"
    );
}
