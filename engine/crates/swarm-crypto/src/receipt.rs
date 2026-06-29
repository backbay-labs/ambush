//! Signed receipt types for attestation.
//!
//! Adapted into Ambush from the upstream `hush-core` crate (ClawdStrike, Apache-2.0):
//! the `SignedReceipt`/`Verdict`/`Provenance` model plus the fail-closed `VFY_*` verification
//! taxonomy. Mapped onto swarm-crypto's own primitives (`Hash`, `Signer`, `verify_signature`,
//! canonical JSON). Ethereum/keccak anchoring was intentionally dropped (local-first; no on-chain
//! anchoring). This is the primitive behind Ambush's "Export Attestation" and `ambush verify`.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::error::{Error, Result};
use crate::hashing::{Hash, sha256};
use crate::signing::{Keypair, PublicKey, Signature, Signer, verify_signature};

/// Current receipt schema version.
///
/// This is a schema compatibility boundary (not the crate version). Verifiers must fail closed on
/// unsupported versions to prevent silent drift.
pub const RECEIPT_SCHEMA_VERSION: &str = "1.0.0";

/// Validate that a receipt version string is supported.
pub fn validate_receipt_version(version: &str) -> Result<()> {
    if parse_semver_strict(version).is_none() {
        return Err(Error::InvalidReceiptVersion {
            version: version.to_string(),
        });
    }

    if version != RECEIPT_SCHEMA_VERSION {
        return Err(Error::UnsupportedReceiptVersion {
            found: version.to_string(),
            supported: RECEIPT_SCHEMA_VERSION.to_string(),
        });
    }

    Ok(())
}

fn parse_semver_strict(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.');
    let major = parse_semver_part(parts.next()?)?;
    let minor = parse_semver_part(parts.next()?)?;
    let patch = parse_semver_part(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }

    Some((major, minor, patch))
}

fn parse_semver_part(part: &str) -> Option<u64> {
    if part.is_empty() {
        return None;
    }
    if part.len() > 1 && part.starts_with('0') {
        return None;
    }
    if !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    part.parse().ok()
}

/// Verdict result from quality gates or guards.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verdict {
    /// Whether the check passed.
    pub passed: bool,
    /// Optional gate or guard identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate_id: Option<String>,
    /// Optional scores (guard-specific).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scores: Option<JsonValue>,
    /// Optional threshold.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
}

impl Verdict {
    /// Create a passing verdict.
    pub fn pass() -> Self {
        Self { passed: true, gate_id: None, scores: None, threshold: None }
    }

    /// Create a failing verdict.
    pub fn fail() -> Self {
        Self { passed: false, gate_id: None, scores: None, threshold: None }
    }

    /// Create a passing verdict with a gate id.
    pub fn pass_with_gate(gate_id: impl Into<String>) -> Self {
        Self { passed: true, gate_id: Some(gate_id.into()), scores: None, threshold: None }
    }

    /// Create a failing verdict with a gate id.
    pub fn fail_with_gate(gate_id: impl Into<String>) -> Self {
        Self { passed: false, gate_id: Some(gate_id.into()), scores: None, threshold: None }
    }
}

/// Violation reference from a guard.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViolationRef {
    /// Guard that detected the violation.
    pub guard: String,
    /// Severity level.
    pub severity: String,
    /// Human-readable message.
    pub message: String,
    /// Action taken (e.g., "blocked", "logged").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

/// Provenance information about the execution environment.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// Ambush Engine version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_version: Option<String>,
    /// Execution provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Policy configuration hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<Hash>,
    /// Ruleset identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ruleset: Option<String>,
    /// Any violations detected during execution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<ViolationRef>,
}

/// Receipt for an attested execution (unsigned).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    /// Receipt schema version.
    pub version: String,
    /// Unique receipt identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    /// ISO-8601 timestamp.
    pub timestamp: String,
    /// Content hash (what was executed/verified).
    pub content_hash: Hash,
    /// Overall verdict.
    pub verdict: Verdict,
    /// Execution provenance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    /// Additional metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<JsonValue>,
}

impl Receipt {
    /// Create a new receipt stamped with the current time.
    pub fn new(content_hash: Hash, verdict: Verdict) -> Self {
        Self {
            version: RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_id: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
            content_hash,
            verdict,
            provenance: None,
            metadata: None,
        }
    }

    /// Set the receipt id.
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.receipt_id = Some(id.into());
        self
    }

    /// Set provenance.
    pub fn with_provenance(mut self, provenance: Provenance) -> Self {
        self.provenance = Some(provenance);
        self
    }

    /// Set metadata.
    pub fn with_metadata(mut self, metadata: JsonValue) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Merge metadata with existing metadata using deep object merge semantics.
    ///
    /// - object + object: recursive key merge
    /// - any other source value: replaces target
    pub fn merge_metadata(mut self, metadata: JsonValue) -> Self {
        if let Some(existing) = self.metadata.as_mut() {
            merge_json_values(existing, metadata);
        } else {
            self.metadata = Some(metadata);
        }
        self
    }

    /// Validate that this receipt uses a supported schema version.
    pub fn validate_version(&self) -> Result<()> {
        validate_receipt_version(&self.version)
    }

    /// Serialize to canonical JSON (sorted keys, no extra whitespace).
    pub fn to_canonical_json(&self) -> Result<String> {
        self.validate_version()?;
        let value = serde_json::to_value(self)?;
        crate::canonical::canonicalize(&value)
    }

    /// Compute the SHA-256 hash of the canonical JSON.
    pub fn hash_sha256(&self) -> Result<Hash> {
        let canonical = self.to_canonical_json()?;
        Ok(sha256(canonical.as_bytes()))
    }
}

fn merge_json_values(target: &mut JsonValue, source: JsonValue) {
    let JsonValue::Object(source_obj) = source else {
        *target = source;
        return;
    };

    let JsonValue::Object(target_obj) = target else {
        *target = JsonValue::Object(serde_json::Map::new());
        merge_json_values(target, JsonValue::Object(source_obj));
        return;
    };

    for (key, value) in source_obj {
        match (target_obj.get_mut(&key), value) {
            (Some(existing), JsonValue::Object(new_obj)) => {
                if existing.is_object() {
                    merge_json_values(existing, JsonValue::Object(new_obj));
                } else {
                    *existing = JsonValue::Object(new_obj);
                }
            }
            (_, new_value) => {
                target_obj.insert(key, new_value);
            }
        }
    }
}

/// Signatures on a receipt.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signatures {
    /// Primary signer (required).
    pub signer: Signature,
    /// Optional co-signer (e.g., the human-gate approver).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cosigner: Option<Signature>,
}

/// A signed receipt: the underlying receipt plus its signatures.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReceipt {
    /// The underlying receipt.
    pub receipt: Receipt,
    /// Signatures.
    pub signatures: Signatures,
}

impl SignedReceipt {
    /// Sign a receipt with a keypair.
    pub fn sign(receipt: Receipt, keypair: &Keypair) -> Result<Self> {
        Self::sign_with(receipt, keypair)
    }

    /// Sign a receipt with any [`Signer`] (e.g., a hardware-backed signer).
    pub fn sign_with(receipt: Receipt, signer: &dyn Signer) -> Result<Self> {
        receipt.validate_version()?;
        let canonical = receipt.to_canonical_json()?;
        let sig = signer.sign(canonical.as_bytes())?;

        Ok(Self {
            receipt,
            signatures: Signatures { signer: sig, cosigner: None },
        })
    }

    /// Add a co-signer signature with a keypair.
    pub fn add_cosigner(&mut self, keypair: &Keypair) -> Result<()> {
        self.add_cosigner_with(keypair)
    }

    /// Add a co-signer signature with any [`Signer`] (the human-gate approval signature).
    pub fn add_cosigner_with(&mut self, signer: &dyn Signer) -> Result<()> {
        self.receipt.validate_version()?;
        let canonical = self.receipt.to_canonical_json()?;
        self.signatures.cosigner = Some(signer.sign(canonical.as_bytes())?);
        Ok(())
    }

    /// Verify all signatures. Fails closed on unsupported schema versions *before* any
    /// signature check, emitting stable `VFY_*` error codes.
    pub fn verify(&self, public_keys: &PublicKeySet) -> VerificationResult {
        fn fail_result(code: &str, message: String) -> VerificationResult {
            VerificationResult {
                valid: false,
                signer_valid: false,
                cosigner_valid: None,
                errors: vec![message],
                error_codes: vec![code.to_string()],
                policy_subcode: None,
            }
        }

        if let Err(e) = self.receipt.validate_version() {
            let code = match e {
                Error::InvalidReceiptVersion { .. } => "VFY_RECEIPT_VERSION_INVALID",
                Error::UnsupportedReceiptVersion { .. } => "VFY_RECEIPT_VERSION_UNSUPPORTED",
                _ => "VFY_INTERNAL_UNEXPECTED",
            };
            return fail_result(code, e.to_string());
        }

        let canonical = match self.receipt.to_canonical_json() {
            Ok(c) => c,
            Err(e) => {
                return fail_result(
                    "VFY_INTERNAL_UNEXPECTED",
                    format!("Failed to serialize receipt: {e}"),
                );
            }
        };
        let message = canonical.as_bytes();

        let mut result = VerificationResult {
            valid: true,
            signer_valid: false,
            cosigner_valid: None,
            errors: vec![],
            error_codes: vec![],
            policy_subcode: None,
        };

        // Verify the primary signature (required).
        result.signer_valid = verify_signature(&public_keys.signer, message, &self.signatures.signer);
        if !result.signer_valid {
            result.valid = false;
            result.errors.push("Invalid signer signature".to_string());
            result.error_codes.push("VFY_SIGNATURE_INVALID".to_string());
        }

        // Verify the co-signer signature (optional).
        if let (Some(sig), Some(pk)) = (&self.signatures.cosigner, &public_keys.cosigner) {
            let valid = verify_signature(pk, message, sig);
            result.cosigner_valid = Some(valid);
            if !valid {
                result.valid = false;
                result.errors.push("Invalid cosigner signature".to_string());
                result.error_codes.push("VFY_COSIGNATURE_INVALID".to_string());
            }
        }

        result
    }

    /// Whether this receipt attests to kernel-level (OS-sandbox) enforcement.
    ///
    /// Requires BOTH the `enforced` flag AND a kernel-backed `enforcement_level`
    /// (`kernel`/`kernel_supervised`), matching SandboxAttestation's own stricter check — a stray
    /// `enforced=true` with a non-kernel level (e.g. `degraded`) must not read as kernel-enforced.
    pub fn is_kernel_enforced(&self) -> bool {
        let sandbox = self.receipt.metadata.as_ref().and_then(|m| m.get("sandbox"));
        let enforced = sandbox
            .and_then(|s| s.get("enforced"))
            .and_then(|e| e.as_bool())
            .unwrap_or(false);
        let kernel_level = sandbox
            .and_then(|s| s.get("enforcement_level"))
            .and_then(|l| l.as_str())
            .is_some_and(|l| l == "kernel" || l == "kernel_supervised");
        enforced && kernel_level
    }

    /// The enforcement-level string from metadata, if present.
    pub fn enforcement_level(&self) -> Option<String> {
        self.receipt
            .metadata
            .as_ref()
            .and_then(|m| m.get("sandbox"))
            .and_then(|s| s.get("enforcement_level"))
            .and_then(|l| l.as_str())
            .map(String::from)
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse from JSON.
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }
}

/// Set of public keys used for verification.
#[derive(Clone, Debug)]
pub struct PublicKeySet {
    /// Primary signer public key.
    pub signer: PublicKey,
    /// Optional co-signer public key.
    pub cosigner: Option<PublicKey>,
}

impl PublicKeySet {
    /// Create with just the primary signer.
    pub fn new(signer: PublicKey) -> Self {
        Self { signer, cosigner: None }
    }

    /// Add a co-signer public key.
    pub fn with_cosigner(mut self, cosigner: PublicKey) -> Self {
        self.cosigner = Some(cosigner);
        self
    }
}

/// Result of receipt verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Overall validity.
    pub valid: bool,
    /// Whether the primary signer signature is valid.
    pub signer_valid: bool,
    /// Whether the co-signer signature is valid (if present).
    pub cosigner_valid: Option<bool>,
    /// Human-readable error messages.
    pub errors: Vec<String>,
    /// Stable verifier error codes (the `VFY_*` taxonomy).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub error_codes: Vec<String>,
    /// Optional attestation-policy subcode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_subcode: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_test_receipt() -> Receipt {
        Receipt {
            version: RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_id: Some("test-receipt-001".to_string()),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            content_hash: Hash::zero(),
            verdict: Verdict::pass_with_gate("test-gate"),
            provenance: Some(Provenance {
                engine_version: Some("0.1.0".to_string()),
                provider: Some("local".to_string()),
                policy_hash: Some(Hash::zero()),
                ruleset: Some("code-agent".to_string()),
                violations: vec![],
            }),
            metadata: None,
        }
    }

    #[test]
    fn test_sign_and_verify() {
        let receipt = make_test_receipt();
        let keypair = Keypair::generate();

        let signed = SignedReceipt::sign(receipt, &keypair).unwrap();

        let keys = PublicKeySet::new(keypair.public_key());
        let result = signed.verify(&keys);

        assert!(result.valid);
        assert!(result.signer_valid);
    }

    #[test]
    fn test_sign_with_cosigner() {
        let receipt = make_test_receipt();
        let signer_kp = Keypair::generate();
        let cosigner_kp = Keypair::generate();

        let mut signed = SignedReceipt::sign(receipt, &signer_kp).unwrap();
        signed.add_cosigner(&cosigner_kp).unwrap();

        let keys = PublicKeySet::new(signer_kp.public_key()).with_cosigner(cosigner_kp.public_key());

        let result = signed.verify(&keys);

        assert!(result.valid);
        assert!(result.signer_valid);
        assert_eq!(result.cosigner_valid, Some(true));
    }

    #[test]
    fn test_wrong_key_fails() {
        let receipt = make_test_receipt();
        let signer_kp = Keypair::generate();
        let wrong_kp = Keypair::generate();

        let signed = SignedReceipt::sign(receipt, &signer_kp).unwrap();

        let keys = PublicKeySet::new(wrong_kp.public_key()); // wrong key
        let result = signed.verify(&keys);

        assert!(!result.valid);
        assert!(!result.signer_valid);
        assert!(result.errors.contains(&"Invalid signer signature".to_string()));
        assert!(result.error_codes.contains(&"VFY_SIGNATURE_INVALID".to_string()));
    }

    #[test]
    fn test_sign_rejects_unsupported_version() {
        let mut receipt = make_test_receipt();
        receipt.version = "2.0.0".to_string();
        let signer_kp = Keypair::generate();

        let err = SignedReceipt::sign(receipt, &signer_kp).unwrap_err();
        assert!(err.to_string().contains("Unsupported receipt version"));
    }

    #[test]
    fn test_verify_fails_closed_on_unsupported_version_before_signature_check() {
        let receipt = make_test_receipt();
        let signer_kp = Keypair::generate();

        let mut signed = SignedReceipt::sign(receipt, &signer_kp).unwrap();
        signed.receipt.version = "2.0.0".to_string();

        let keys = PublicKeySet::new(signer_kp.public_key());
        let result = signed.verify(&keys);

        assert!(!result.valid);
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].contains("Unsupported receipt version"));
        assert_eq!(result.error_codes, vec!["VFY_RECEIPT_VERSION_UNSUPPORTED".to_string()]);
    }

    #[test]
    fn test_canonical_json_deterministic() {
        let receipt = make_test_receipt();
        let json1 = receipt.to_canonical_json().unwrap();
        let json2 = receipt.to_canonical_json().unwrap();
        assert_eq!(json1, json2);
    }

    #[test]
    fn test_canonical_json_sorted() {
        let receipt = make_test_receipt();
        let json = receipt.to_canonical_json().unwrap();

        // keys appear in alphabetical order: "content_hash" before "verdict"
        let content_pos = json.find("\"content_hash\"").unwrap();
        let verdict_pos = json.find("\"verdict\"").unwrap();
        assert!(content_pos < verdict_pos);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let receipt = make_test_receipt();
        let keypair = Keypair::generate();
        let signed = SignedReceipt::sign(receipt, &keypair).unwrap();

        let json = signed.to_json().unwrap();
        let restored = SignedReceipt::from_json(&json).unwrap();

        let keys = PublicKeySet::new(keypair.public_key());
        let result = restored.verify(&keys);

        assert!(result.valid);
    }

    #[test]
    fn test_receipt_metadata_merge() {
        let receipt = Receipt::new(Hash::zero(), Verdict::pass())
            .with_metadata(serde_json::json!({
                "ambush": {"extra_guards": ["a"]},
                "vault": {"command": ["echo", "hi"]},
            }))
            .merge_metadata(serde_json::json!({
                "ambush": {"posture": {"state_after": "work"}},
                "vault": {"events": "events.jsonl"},
            }));

        let metadata = receipt.metadata.expect("metadata");
        assert_eq!(metadata.pointer("/ambush/extra_guards/0"), Some(&serde_json::json!("a")));
        assert_eq!(metadata.pointer("/ambush/posture/state_after"), Some(&serde_json::json!("work")));
        assert_eq!(metadata.pointer("/vault/command/0"), Some(&serde_json::json!("echo")));
        assert_eq!(metadata.pointer("/vault/events"), Some(&serde_json::json!("events.jsonl")));
    }

    #[test]
    fn test_is_kernel_enforced() {
        let keypair = Keypair::generate();

        let receipt = make_test_receipt();
        let signed = SignedReceipt::sign(receipt, &keypair).unwrap();
        assert!(!signed.is_kernel_enforced());

        // enforced=true with a kernel-backed level -> kernel-enforced.
        let receipt = make_test_receipt()
            .with_metadata(serde_json::json!({ "sandbox": {"enforced": true, "enforcement_level": "kernel"} }));
        let signed = SignedReceipt::sign(receipt, &keypair).unwrap();
        assert!(signed.is_kernel_enforced());

        // enforced=true but a non-kernel level (degraded) must NOT read as kernel-enforced.
        let receipt = make_test_receipt()
            .with_metadata(serde_json::json!({ "sandbox": {"enforced": true, "enforcement_level": "degraded"} }));
        let signed = SignedReceipt::sign(receipt, &keypair).unwrap();
        assert!(!signed.is_kernel_enforced());

        let receipt = make_test_receipt().with_metadata(serde_json::json!({ "sandbox": {"enforced": false} }));
        let signed = SignedReceipt::sign(receipt, &keypair).unwrap();
        assert!(!signed.is_kernel_enforced());
    }
}
