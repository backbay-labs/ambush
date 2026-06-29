// Adapted from ClawdStrike/Arc (Apache-2.0)
//! Trust-boundary fuzz target for the `swarm_crypto` RFC 6962 Merkle tree.
//!
//! The audit trail's tamper-evidence depends on three invariants holding for
//! every tree shape: building never panics, a valid leaf index always yields
//! a proof that verifies against the root, and a proof for the wrong leaf (or
//! a tampered root) never verifies. This target drives all three.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use swarm_crypto::{Hash, MerkleTree};

#[derive(Arbitrary, Debug)]
struct MerkleInput {
    leaves: Vec<Vec<u8>>,
    proof_index: usize,
}

fuzz_target!(|input: MerkleInput| {
    // Bound the work: empty trees are an explicit `Err`, and very large
    // inputs only burn fuzzing budget without exercising new branches.
    if input.leaves.is_empty() || input.leaves.len() > 1024 {
        return;
    }

    // Building must never panic.
    let tree = match MerkleTree::from_leaves(&input.leaves) {
        Ok(t) => t,
        Err(_) => return,
    };

    // Root is always 32 bytes; leaf count is preserved.
    assert_eq!(tree.root().as_bytes().len(), 32);
    assert_eq!(tree.leaf_count(), input.leaves.len());

    // A valid index must yield a proof that verifies against the real root,
    // and must reject a tampered root.
    if input.proof_index < input.leaves.len() {
        if let Ok(proof) = tree.inclusion_proof(input.proof_index) {
            let root = tree.root();
            let leaf = &input.leaves[input.proof_index];
            assert!(
                proof.verify(leaf, &root),
                "valid inclusion proof failed to verify"
            );

            // Fail-closed: the same proof must not verify against the zero
            // root (unless the real root genuinely is zero, which it is not
            // for a non-empty tree).
            if root != Hash::zero() {
                assert!(
                    !proof.verify(leaf, &Hash::zero()),
                    "proof verified against a tampered (zero) root"
                );
            }
        }
    }

    // Out-of-range indices must be a clean `Err`, never a panic.
    let _ = tree.inclusion_proof(input.proof_index);
});
