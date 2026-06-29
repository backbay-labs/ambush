//! Digest/canonical helpers, validators, and the fail-closed key-pinning primitive.

use serde::Serialize;
use swarm_crypto::{PublicKey, canonical_json_bytes, sha256};

use crate::error::{AuthorityError, DenyReason};

/// Self-certifying issuer DID prefix; `issuer` may be `did:ambush:<hex>` or bare 64-char hex.
pub const DID_AMBUSH_PREFIX: &str = "did:ambush:";

/// 64-char lowercase sha256 over a value's canonical JSON. NB: uses `.to_hex()` (unprefixed), NOT
/// swarm-crypto's `0x`-prefixed `sha256_hex`.
pub(crate) fn digest_hex<T: Serialize>(value: &T) -> Result<String, AuthorityError> {
    let bytes = canonical_json_bytes(value).map_err(|e| AuthorityError::Canonical(e.to_string()))?;
    Ok(sha256(&bytes).to_hex())
}

/// Build the issuer DID string for a signer's public key.
pub(crate) fn issuer_did(public_key: &PublicKey) -> String {
    format!("{DID_AMBUSH_PREFIX}{}", public_key.to_hex())
}

/// Parse a self-certifying issuer string into its public key. Bare hex or `did:ambush:<hex>`.
pub(crate) fn issuer_public_key(issuer: &str) -> Result<PublicKey, DenyReason> {
    let hex = issuer.strip_prefix(DID_AMBUSH_PREFIX).unwrap_or(issuer);
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f')) {
        return Err(DenyReason::MalformedIssuer);
    }
    PublicKey::from_hex(hex).map_err(|_| DenyReason::MalformedIssuer)
}

/// Fail-closed pinning: non-empty pinned set AND the key is a member.
pub(crate) fn is_pinned(public_key: &PublicKey, trusted_keys: &[PublicKey]) -> bool {
    !trusted_keys.is_empty() && trusted_keys.iter().any(|k| k == public_key)
}

pub(crate) fn require_non_empty(value: &str, label: &str) -> Result<(), AuthorityError> {
    if value.is_empty() {
        Err(AuthorityError::Invalid(format!("{label} must not be empty")))
    } else {
        Ok(())
    }
}

pub(crate) fn require_sha256(value: &str, label: &str) -> Result<(), AuthorityError> {
    let ok = value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
    if ok {
        Ok(())
    } else {
        Err(AuthorityError::Invalid(format!("{label} must be a lowercase sha256 digest")))
    }
}

/// Serialize a signable artifact to a JSON object with `"signature"` removed (the signing body).
pub(crate) fn signature_body<T: Serialize>(
    value: &T,
    label: &str,
) -> Result<serde_json::Value, AuthorityError> {
    let mut body = serde_json::to_value(value).map_err(|e| AuthorityError::Canonical(format!("{label}: {e}")))?;
    body.as_object_mut()
        .ok_or_else(|| AuthorityError::Canonical(format!("{label}: not a JSON object")))?
        .remove("signature");
    Ok(body)
}
