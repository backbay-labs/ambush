//! FALSIFY-02 negative-falsifiability test for
//! `RuntimeIdentityDerivedIdMismatch` (docs/assurance/MAPPING.md).
//!
//! `FileAgentIdentityRegistry::admit_persisted_identity`
//! (crates/swarm-runtime/src/agent_identity.rs:339-388) denies admitting a
//! persisted agent identity whose claimed `AgentId` does not equal the ID
//! derived from its own ed25519 signing key's public key. It is `pub`, so
//! this test calls it directly.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use swarm_core::agent::AgentRole;
use swarm_core::types::AgentId;
use swarm_runtime::agent_identity::{
    AgentIdentityError, FileAgentIdentityRegistry, PersistedAgentIdentity,
};

fn temp_root(label: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "swarm-negative-registry-identity-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&root);
    root
}

/// A deliberately broken re-implementation of `admit_persisted_identity`'s
/// derived-id check (crates/swarm-runtime/src/agent_identity.rs:344-349)
/// with the comparison removed: whatever `AgentId` the caller claims is
/// trusted without ever being checked against the identity's own signing
/// key.
fn broken_admit_checks_derived_id(_claimed_id: &AgentId, _derived_id: &AgentId) -> bool {
    true
}

#[test]
fn negative_runtime_identity_derived_id_mismatch() {
    let root = temp_root("mismatch");
    let registry = FileAgentIdentityRegistry::open(&root).unwrap();

    let signing_key = SigningKey::generate(&mut OsRng);
    let derived_id = AgentId::from_verifying_key(&signing_key.verifying_key());
    let claimed_id = AgentId("agent-that-does-not-match-the-key".to_string());
    assert_ne!(
        claimed_id, derived_id,
        "fixture must actually be mismatched"
    );

    let identity = PersistedAgentIdentity {
        id: claimed_id.clone(),
        signing_key,
    };

    // 1. The REAL function rejects the mismatched identity.
    let real_result = registry.admit_persisted_identity(
        AgentRole::Whisker,
        "primary",
        &identity,
        1_700_000_000_000,
    );
    assert!(
        matches!(
            real_result,
            Err(AgentIdentityError::DerivedIdentityMismatch { .. })
        ),
        "real admit_persisted_identity must reject a claimed id that doesn't match the signing key, got {real_result:?}"
    );

    // 2. The broken variant accepts the identical mismatched pair.
    assert!(
        broken_admit_checks_derived_id(&claimed_id, &derived_id),
        "broken variant is expected to (wrongly) accept the mismatched id"
    );

    let _ = std::fs::remove_dir_all(&root);
}
