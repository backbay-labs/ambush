//! Production cryptographic primitives plus compatibility helpers for existing callers.

pub mod canonical;
pub mod error;
pub mod hashing;
pub mod merkle;
pub mod receipt;
pub mod sandbox;
pub mod signing;

pub use canonical::canonicalize as canonicalize_json;
pub use error::{Error, Result};
pub use hashing::{Hash, hmac_sha256, hmac_sha256_hex, sha256};
pub use merkle::{MerkleProof, MerkleTree, leaf_hash, node_hash};
pub use receipt::{
    Provenance, Receipt, SignedReceipt, Signatures, PublicKeySet, Verdict, VerificationResult,
    ViolationRef, RECEIPT_SCHEMA_VERSION, validate_receipt_version,
};
pub use sandbox::{
    AuditEntry, CapabilitySnapshot, EnforcementLevel, FsCapSnapshot, PlatformInfo,
    ProviderApprovalStatus, ProviderAvailability, ProviderState, SandboxAttestation,
    SandboxRuntimeState, SupervisorStats, TimestampedDenial, attach_sandbox_attestation,
    read_sandbox_attestation,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub use signing::{Keypair, PublicKey, Signature, Signer, verify_signature};

/// Backward-compatible error alias used by downstream runtime modules.
pub type CryptoError = Error;

/// Detached signature metadata stored alongside one exported evidence payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetachedSignature {
    pub algorithm: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

/// Backward-compatible deterministic signer derived from secret material.
#[derive(Debug, Clone)]
pub struct Ed25519Signer {
    keypair: Keypair,
    key_id: String,
    public_key_hex: String,
}

impl Ed25519Signer {
    /// Derive a deterministic signer from local secret material.
    pub fn from_secret_material(secret_material: &str) -> Self {
        let seed = sha256(secret_material.as_bytes());
        let keypair = Keypair::from_seed(seed.as_bytes());
        let public_key_hex = keypair.public_key().to_hex();
        let key_id = sha256(keypair.public_key().as_bytes()).to_hex();

        Self {
            keypair,
            key_id,
            public_key_hex,
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    /// Sign arbitrary payload bytes and emit the legacy detached wrapper.
    pub fn sign(&self, payload: &[u8]) -> DetachedSignature {
        let signature = self.keypair.sign(payload);
        DetachedSignature {
            algorithm: "ed25519".to_string(),
            key_id: self.key_id.clone(),
            public_key_hex: self.public_key_hex.clone(),
            signature_hex: signature.to_hex(),
        }
    }
}

/// Serialize a value into canonical JSON bytes.
pub fn canonical_json_bytes<T>(value: &T) -> std::result::Result<Vec<u8>, CryptoError>
where
    T: Serialize,
{
    let normalized = serde_json::to_value(value)?;
    Ok(canonicalize_json(&normalized)?.into_bytes())
}

/// Serialize a value into canonical JSON text.
pub fn canonical_json_string<T>(value: &T) -> std::result::Result<String, CryptoError>
where
    T: Serialize,
{
    let normalized = serde_json::to_value(value)?;
    canonicalize_json(&normalized)
}

/// Parse and canonicalize raw JSON text.
pub fn normalize_canonical_json(raw: &str) -> std::result::Result<String, CryptoError> {
    let parsed: Value = serde_json::from_str(raw)?;
    canonicalize_json(&parsed)
}

/// Backward-compatible SHA-256 helper that returns unprefixed lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    sha256(bytes).to_hex()
}

/// Verify a legacy detached signature wrapper.
pub fn verify_detached_signature(
    payload: &[u8],
    signature: &DetachedSignature,
) -> std::result::Result<(), CryptoError> {
    if signature.algorithm != "ed25519" {
        return Err(Error::InvalidHex(format!(
            "unsupported signature algorithm `{}`",
            signature.algorithm
        )));
    }

    let public_key = PublicKey::from_hex(&signature.public_key_hex)?;
    if sha256(public_key.as_bytes()).to_hex() != signature.key_id {
        return Err(Error::InvalidSignature);
    }

    let signature = Signature::from_hex(&signature.signature_hex)?;
    if public_key.verify(payload, &signature) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod compat_tests {
    use super::{
        Ed25519Signer, canonical_json_string, normalize_canonical_json, sha256_hex,
        verify_detached_signature,
    };
    use serde::Serialize;

    #[derive(Debug, Serialize)]
    struct CanonicalFixture {
        name: &'static str,
        priority: u8,
    }

    #[test]
    fn canonical_json_is_compact_and_deterministic() {
        let canonical = canonical_json_string(&CanonicalFixture {
            name: "bundle",
            priority: 7,
        })
        .unwrap();
        assert_eq!(canonical, r#"{"name":"bundle","priority":7}"#);

        let normalized =
            normalize_canonical_json("{\n  \"priority\": 7,\n  \"name\": \"bundle\"\n}").unwrap();
        assert_eq!(normalized, r#"{"name":"bundle","priority":7}"#);
    }

    #[test]
    fn detached_signature_round_trips() {
        let signer = Ed25519Signer::from_secret_material("local evidence test key");
        let payload = br#"{"payload":"signed"}"#;
        let signature = signer.sign(payload);

        verify_detached_signature(payload, &signature).unwrap();
        assert_eq!(signature.key_id, signer.key_id());
        assert_eq!(signature.public_key_hex, signer.public_key_hex());
        assert_eq!(sha256_hex(payload).len(), 64);
    }

    #[test]
    fn detached_signature_fails_on_tamper() {
        let signer = Ed25519Signer::from_secret_material("local evidence test key");
        let payload = br#"{"payload":"signed"}"#;
        let signature = signer.sign(payload);
        let tampered = br#"{"payload":"tampered"}"#;

        assert!(verify_detached_signature(tampered, &signature).is_err());
    }
}
