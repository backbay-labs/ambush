//! Checkpoint statements and witness co-signatures.

use serde_json::{Value, json};
use swarm_crypto::{Hash, Keypair, PublicKey, Signature, canonicalize_json, sha256};

use crate::envelope::{issuer_from_keypair, parse_issuer_pubkey_hex};
use crate::spine_error::{SpineError, SpineResult};

/// Schema identifier for v1 checkpoint statements.
pub const CHECKPOINT_STATEMENT_SCHEMA_V1: &str = "swarm.spine.checkpoint_statement.v1";

/// Build an unsigned checkpoint statement.
pub fn checkpoint_statement(
    log_id: &str,
    checkpoint_seq: u64,
    prev_checkpoint_hash: Option<String>,
    merkle_root: String,
    tree_size: u64,
    issued_at: String,
) -> Value {
    json!({
        "schema": CHECKPOINT_STATEMENT_SCHEMA_V1,
        "log_id": log_id,
        "checkpoint_seq": checkpoint_seq,
        "prev_checkpoint_hash": prev_checkpoint_hash,
        "merkle_root": merkle_root,
        "tree_size": tree_size,
        "issued_at": issued_at,
    })
}

/// Compute the SHA-256 hash of a canonical checkpoint statement.
pub fn checkpoint_hash(statement: &Value) -> SpineResult<Hash> {
    let canonical = canonicalize_json(statement)?;
    Ok(sha256(canonical.as_bytes()))
}

/// Build the domain-separated message that witnesses sign.
pub fn checkpoint_witness_message(checkpoint_hash: &Hash) -> Vec<u8> {
    let tag = b"SwarmCheckpointHashV1";
    let mut message = Vec::with_capacity(tag.len() + 1 + 32);
    message.extend_from_slice(tag);
    message.push(0x00);
    message.extend_from_slice(checkpoint_hash.as_bytes());
    message
}

/// Sign a checkpoint statement and return a witness signature payload.
pub fn sign_checkpoint_statement(keypair: &Keypair, statement: &Value) -> SpineResult<Value> {
    let hash = checkpoint_hash(statement)?;
    let message = checkpoint_witness_message(&hash);
    let signature = keypair.sign(&message).to_hex_prefixed();
    let witness_node_id = issuer_from_keypair(keypair);

    Ok(json!({
        "schema": "swarm.spine.witness_signature.v1",
        "witness_node_id": witness_node_id,
        "checkpoint_hash": hash.to_hex_prefixed(),
        "signature": signature,
    }))
}

/// Verify a witness signature against a checkpoint statement.
pub fn verify_witness_signature(
    statement: &Value,
    witness_node_id: &str,
    signature_hex: &str,
) -> SpineResult<bool> {
    let pubkey_hex = parse_issuer_pubkey_hex(witness_node_id)?;
    let public_key = PublicKey::from_hex(&pubkey_hex)?;
    let signature =
        Signature::from_hex(signature_hex).map_err(|_| SpineError::InvalidWitnessSignature)?;

    let hash = checkpoint_hash(statement)?;
    let message = checkpoint_witness_message(&hash);
    Ok(public_key.verify(&message, &signature))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::now_rfc3339;

    #[test]
    fn checkpoint_sign_verify() {
        let keypair = Keypair::generate();
        let root = sha256(b"some-tree-root").to_hex_prefixed();
        let statement = checkpoint_statement("log-1", 1, None, root, 42, now_rfc3339());

        let witness = sign_checkpoint_statement(&keypair, &statement).unwrap();
        let witness_id = witness
            .get("witness_node_id")
            .and_then(Value::as_str)
            .unwrap();
        let signature = witness.get("signature").and_then(Value::as_str).unwrap();

        assert!(verify_witness_signature(&statement, witness_id, signature).unwrap());
    }

    #[test]
    fn checkpoint_rejects_wrong_witness() {
        let keypair = Keypair::generate();
        let other_keypair = Keypair::generate();
        let root = sha256(b"root").to_hex_prefixed();
        let statement = checkpoint_statement("log-1", 1, None, root, 10, now_rfc3339());

        let witness = sign_checkpoint_statement(&keypair, &statement).unwrap();
        let signature = witness.get("signature").and_then(Value::as_str).unwrap();

        let wrong_id = issuer_from_keypair(&other_keypair);
        assert!(!verify_witness_signature(&statement, &wrong_id, signature).unwrap());
    }

    #[test]
    fn checkpoint_rejects_tampered_statement() {
        let keypair = Keypair::generate();
        let root = sha256(b"root").to_hex_prefixed();
        let statement = checkpoint_statement("log-1", 1, None, root, 10, now_rfc3339());

        let witness = sign_checkpoint_statement(&keypair, &statement).unwrap();
        let witness_id = witness
            .get("witness_node_id")
            .and_then(Value::as_str)
            .unwrap();
        let signature = witness.get("signature").and_then(Value::as_str).unwrap();

        let tampered =
            checkpoint_statement("log-1", 1, None, "0xbad".to_string(), 10, now_rfc3339());
        assert!(!verify_witness_signature(&tampered, witness_id, signature).unwrap());
    }

    #[test]
    fn checkpoint_hash_is_deterministic() {
        let root = sha256(b"root").to_hex_prefixed();
        let statement = checkpoint_statement(
            "log-1",
            1,
            None,
            root,
            10,
            "2026-01-01T00:00:00Z".to_string(),
        );
        let first = checkpoint_hash(&statement).unwrap();
        let second = checkpoint_hash(&statement).unwrap();

        assert_eq!(first, second);
    }
}
