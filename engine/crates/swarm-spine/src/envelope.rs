//! Signed spine envelopes backed by `swarm-crypto`.

use chrono::SecondsFormat;
use serde_json::{Value, json};
use swarm_crypto::hashing::sha256_hex as sha256_hex_prefixed;
use swarm_crypto::{Hash, Keypair, PublicKey, Signature, canonicalize_json, sha256};

use crate::spine_error::{SpineError, SpineResult};

/// Schema identifier for v1 envelopes.
pub const ENVELOPE_SCHEMA_V1: &str = "swarm.spine.envelope.v1";

/// Current UTC time as RFC 3339 string with second precision.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Derive a spine issuer identifier from a keypair.
pub fn issuer_from_keypair(keypair: &Keypair) -> String {
    format!("swarm:ed25519:{}", keypair.public_key().to_hex())
}

/// Extract the hex public key from a `swarm:ed25519:<hex>` issuer string.
pub fn parse_issuer_pubkey_hex(issuer: &str) -> SpineResult<String> {
    let prefix = "swarm:ed25519:";
    let rest = issuer
        .strip_prefix(prefix)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| SpineError::InvalidIssuer(issuer.to_string()))?;

    if rest.len() != 64 || !rest.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(SpineError::InvalidIssuer(issuer.to_string()));
    }

    Ok(rest.to_string())
}

fn canonical_json_bytes(value: &Value) -> SpineResult<Vec<u8>> {
    Ok(canonicalize_json(value)?.into_bytes())
}

/// Compute the bytes that are signed for an envelope.
pub fn envelope_signing_bytes(envelope_without_hash_and_sig: &Value) -> SpineResult<Vec<u8>> {
    canonical_json_bytes(envelope_without_hash_and_sig)
}

/// Compute the `0x`-prefixed SHA-256 hash hex string of an unsigned envelope.
pub fn compute_envelope_hash_hex(envelope_without_hash_and_sig: &Value) -> SpineResult<String> {
    let bytes = envelope_signing_bytes(envelope_without_hash_and_sig)?;
    Ok(sha256_hex_prefixed(&bytes))
}

/// Compute the SHA-256 hash of an unsigned envelope.
pub fn compute_envelope_hash(envelope_without_hash_and_sig: &Value) -> SpineResult<Hash> {
    let bytes = envelope_signing_bytes(envelope_without_hash_and_sig)?;
    Ok(sha256(&bytes))
}

/// Sign an unsigned envelope, returning `(envelope_hash_hex, signature_hex)`.
pub fn sign_envelope(
    keypair: &Keypair,
    envelope_without_hash_and_sig: &Value,
) -> SpineResult<(String, String)> {
    let bytes = envelope_signing_bytes(envelope_without_hash_and_sig)?;
    let envelope_hash = sha256_hex_prefixed(&bytes);
    let signature = keypair.sign(&bytes).to_hex_prefixed();
    Ok((envelope_hash, signature))
}

/// Build a complete signed envelope.
pub fn build_signed_envelope(
    keypair: &Keypair,
    seq: u64,
    prev_envelope_hash: Option<String>,
    fact: Value,
    issued_at: String,
) -> SpineResult<Value> {
    chrono::DateTime::parse_from_rfc3339(&issued_at).map_err(|error| {
        SpineError::InvalidTimestamp(format!(
            "issued_at is not a valid RFC 3339 timestamp: {error}"
        ))
    })?;

    let issuer = issuer_from_keypair(keypair);
    let unsigned = json!({
        "schema": ENVELOPE_SCHEMA_V1,
        "issuer": issuer,
        "seq": seq,
        "prev_envelope_hash": prev_envelope_hash,
        "issued_at": issued_at,
        "capability_token": Value::Null,
        "fact": fact,
    });

    let (envelope_hash, signature) = sign_envelope(keypair, &unsigned)?;

    let mut signed = unsigned;
    signed["envelope_hash"] = json!(envelope_hash);
    signed["signature"] = json!(signature);
    Ok(signed)
}

/// Extract the `envelope_hash` from a raw JSON payload.
pub fn extract_envelope_hash(payload: &[u8]) -> SpineResult<String> {
    let value: Value = serde_json::from_slice(payload)?;
    let hash = value
        .get("envelope_hash")
        .and_then(Value::as_str)
        .ok_or(SpineError::MissingField("envelope_hash"))?;
    Ok(hash.to_string())
}

/// Verify an envelope signature and hash integrity.
pub fn verify_envelope(envelope: &Value) -> SpineResult<bool> {
    let issuer = envelope
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or(SpineError::MissingField("issuer"))?;
    let signature_hex = envelope
        .get("signature")
        .and_then(Value::as_str)
        .ok_or(SpineError::MissingField("signature"))?;
    let claimed_hash = envelope
        .get("envelope_hash")
        .and_then(Value::as_str)
        .ok_or(SpineError::MissingField("envelope_hash"))?;

    let pubkey_hex = parse_issuer_pubkey_hex(issuer)?;
    let public_key = PublicKey::from_hex(&pubkey_hex)?;
    let signature = Signature::from_hex(signature_hex)?;

    let mut unsigned = envelope.clone();
    if let Some(object) = unsigned.as_object_mut() {
        object.remove("envelope_hash");
        object.remove("signature");
    }

    let bytes = envelope_signing_bytes(&unsigned)?;
    let computed_hash = sha256_hex_prefixed(&bytes);
    if computed_hash != claimed_hash {
        return Err(SpineError::HashMismatch {
            expected: claimed_hash.to_string(),
            computed: computed_hash,
        });
    }

    Ok(public_key.verify(&bytes, &signature))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip() {
        let keypair = Keypair::generate();
        let fact = json!({"type": "policy.update", "data": {"version": 2}});
        let envelope = build_signed_envelope(&keypair, 1, None, fact, now_rfc3339()).unwrap();

        assert_eq!(
            envelope.get("schema").and_then(Value::as_str).unwrap(),
            ENVELOPE_SCHEMA_V1
        );
        assert!(envelope.get("envelope_hash").is_some());
        assert!(envelope.get("signature").is_some());
        assert!(verify_envelope(&envelope).unwrap());
    }

    #[test]
    fn envelope_chain() {
        let keypair = Keypair::generate();
        let first =
            build_signed_envelope(&keypair, 1, None, json!({"type": "init"}), now_rfc3339())
                .unwrap();
        let first_hash = first
            .get("envelope_hash")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();

        let second = build_signed_envelope(
            &keypair,
            2,
            Some(first_hash.clone()),
            json!({"type": "step"}),
            now_rfc3339(),
        )
        .unwrap();

        assert_eq!(
            second
                .get("prev_envelope_hash")
                .and_then(Value::as_str)
                .unwrap(),
            first_hash
        );
        assert!(verify_envelope(&second).unwrap());
    }

    #[test]
    fn verify_rejects_tampered_fact() {
        let keypair = Keypair::generate();
        let mut envelope =
            build_signed_envelope(&keypair, 1, None, json!({"ok": true}), now_rfc3339()).unwrap();

        envelope["fact"] = json!({"ok": false});
        let error = verify_envelope(&envelope).unwrap_err();
        assert!(matches!(error, SpineError::HashMismatch { .. }));
    }

    #[test]
    fn issuer_roundtrip() {
        let keypair = Keypair::generate();
        let issuer = issuer_from_keypair(&keypair);
        let hex = parse_issuer_pubkey_hex(&issuer).unwrap();

        assert_eq!(hex, keypair.public_key().to_hex());
    }

    #[test]
    fn parse_issuer_rejects_bad_prefix() {
        assert!(parse_issuer_pubkey_hex("bad:prefix:abc").is_err());
        assert!(parse_issuer_pubkey_hex("swarm:ed25519:").is_err());
    }

    #[test]
    fn parse_issuer_rejects_bad_hex_or_length() {
        assert!(parse_issuer_pubkey_hex("swarm:ed25519:abcd").is_err());
        assert!(
            parse_issuer_pubkey_hex(
                "swarm:ed25519:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
            )
            .is_err()
        );
        assert!(
            parse_issuer_pubkey_hex(
                "swarm:ed25519:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd0011223300"
            )
            .is_err()
        );
    }

    #[test]
    fn extract_envelope_hash_from_json() {
        let payload = serde_json::to_vec(&json!({"envelope_hash": "0xdeadbeef"})).unwrap();
        assert_eq!(extract_envelope_hash(&payload).unwrap(), "0xdeadbeef");
    }
}
