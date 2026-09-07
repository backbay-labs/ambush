//! FALSIFY-02 negative-falsifiability test for `RuntimeKeystoreKeyIntegrity`
//! (docs/assurance/MAPPING.md).
//!
//! `FileAgentKeyStore::decode_key` (crates/swarm-runtime/src/agent_identity.rs:235-244)
//! denies loading a persisted agent signing key file whose contents are not
//! exactly 32 raw seed bytes. The function itself is private;
//! `load_or_create` (agent_identity.rs:184-206) calls it when a key file
//! already exists at the path it computes, and is the `pub` entry point
//! this test reaches it through by planting a corrupt file at that exact
//! path ahead of time.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use swarm_core::agent::AgentRole;
use swarm_runtime::agent_identity::{AgentIdentityError, FileAgentKeyStore};

fn temp_root(label: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "swarm-negative-registry-keystore-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&root);
    root
}

/// A deliberately weakened re-implementation of `FileAgentKeyStore::decode_key`
/// (crates/swarm-runtime/src/agent_identity.rs:236-244) with the exact-length
/// requirement removed: any byte length is coerced into a 32-byte seed by
/// truncating or zero-padding, instead of being refused.
fn broken_decode_key(bytes: &[u8]) -> Result<[u8; 32], String> {
    let mut seed = [0u8; 32];
    let n = bytes.len().min(32);
    seed[..n].copy_from_slice(&bytes[..n]);
    Ok(seed)
}

#[test]
fn negative_runtime_keystore_key_integrity() {
    let root = temp_root("corrupt");
    let store = FileAgentKeyStore::open(&root).unwrap();

    // The private `key_path`/`role_slug`/`sanitize_slot` helpers name this
    // file "<role_slug>-<sanitized slot>.ed25519" under the store root
    // (agent_identity.rs:226-232); "whisker"/"primary" need no sanitizing,
    // so this is the exact path `load_or_create` will read next.
    let corrupt_bytes: &[u8] = b"not-a-32-byte-seed";
    assert_ne!(
        corrupt_bytes.len(),
        32,
        "fixture must actually be the wrong length"
    );
    let key_path = root.join("whisker-primary.ed25519");
    std::fs::write(&key_path, corrupt_bytes).unwrap();

    // 1. The REAL store rejects the corrupt (non-32-byte) key file.
    let real_result = store.load_or_create(AgentRole::Whisker, "primary");
    assert!(
        matches!(real_result, Err(AgentIdentityError::InvalidKey { .. })),
        "real load_or_create must reject a corrupt key file, got {real_result:?}"
    );

    // 2. The broken variant coerces the identical bytes into a key.
    assert!(
        broken_decode_key(corrupt_bytes).is_ok(),
        "broken variant is expected to (wrongly) coerce the corrupt bytes into a key"
    );

    let _ = std::fs::remove_dir_all(&root);
}
