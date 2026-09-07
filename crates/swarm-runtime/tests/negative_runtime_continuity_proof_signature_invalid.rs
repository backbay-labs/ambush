//! FALSIFY-02 negative-falsifiability test for
//! `RuntimeContinuityProofSignatureInvalid` (docs/assurance/MAPPING.md).
//!
//! `verify_continuity_proof` (crates/swarm-runtime/src/agent_identity.rs:547-589)
//! denies an agent-identity rotation continuity proof whose signature does
//! not verify against the claimed previous ed25519 public key. It is `pub`,
//! so this test calls it directly.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use swarm_core::agent::AgentRole;
use swarm_core::types::AgentId;
use swarm_runtime::agent_identity::{
    AgentIdentityContinuityPayload, AgentIdentityContinuityProof, AgentIdentityError,
    verify_continuity_proof,
};

/// A deliberately broken re-implementation of `verify_continuity_proof`
/// (crates/swarm-runtime/src/agent_identity.rs:547-589) that performs every
/// FORMAT check the real function does -- proof-id hash, key length,
/// signature length -- but OMITS the final `verifying_key.verify(...)` call
/// (agent_identity.rs:587-589), the actual cryptographic check.
fn broken_verify_continuity_proof(
    payload_bytes: &[u8],
    proof_id: &str,
    previous_public_key_hex: &str,
    signature_hex: &str,
) -> Result<(), String> {
    if swarm_crypto::sha256_hex(payload_bytes) != proof_id {
        return Err("proof_id does not match canonical payload hash".to_string());
    }
    let key_bytes = hex::decode(previous_public_key_hex).map_err(|error| error.to_string())?;
    if key_bytes.len() != 32 {
        return Err("bad previous public key length".to_string());
    }
    let signature_bytes = hex::decode(signature_hex).map_err(|error| error.to_string())?;
    if signature_bytes.len() != 64 {
        return Err("bad signature length".to_string());
    }
    // MISSING: the actual ed25519 signature verification.
    Ok(())
}

#[test]
fn negative_runtime_continuity_proof_signature_invalid() {
    let previous_key = SigningKey::generate(&mut OsRng);
    let wrong_key = SigningKey::generate(&mut OsRng);
    let next_key = SigningKey::generate(&mut OsRng);

    let payload = AgentIdentityContinuityPayload {
        schema_version: 1,
        role: AgentRole::Whisker,
        slot: "primary".to_string(),
        previous_agent_id: AgentId::from_verifying_key(&previous_key.verifying_key()),
        next_agent_id: AgentId::from_verifying_key(&next_key.verifying_key()),
        previous_public_key_hex: hex::encode(previous_key.verifying_key().to_bytes()),
        next_public_key_hex: hex::encode(next_key.verifying_key().to_bytes()),
        signed_at_ms: 1_700_000_000_000,
    };
    let payload_bytes = swarm_crypto::canonical_json_bytes(&payload).unwrap();
    let proof_id = swarm_crypto::sha256_hex(&payload_bytes);
    // Signed with the WRONG key: the proof claims `previous_key`'s public
    // key in `previous_public_key_hex`, but the signature bytes are
    // actually produced by `wrong_key`.
    let forged_signature = wrong_key.sign(&payload_bytes);
    let signature_hex = hex::encode(forged_signature.to_bytes());

    let proof = AgentIdentityContinuityProof {
        proof_id: proof_id.clone(),
        payload,
        signature_hex: signature_hex.clone(),
    };

    // 1. The REAL function rejects the forged signature.
    let real_result = verify_continuity_proof(&proof);
    assert!(
        matches!(
            real_result,
            Err(AgentIdentityError::InvalidContinuityProof { .. })
        ),
        "real verify_continuity_proof must reject a signature from the wrong key, got {real_result:?}"
    );

    // 2. The broken variant accepts the identical forged proof.
    let previous_public_key_hex = hex::encode(previous_key.verifying_key().to_bytes());
    assert!(
        broken_verify_continuity_proof(
            &payload_bytes,
            &proof_id,
            &previous_public_key_hex,
            &signature_hex,
        )
        .is_ok(),
        "broken variant is expected to (wrongly) accept the forged signature"
    );
}
