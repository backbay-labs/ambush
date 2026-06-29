//! Ambush attestation bundles — the primitive behind "Export Attestation" and `ambush verify`.
//!
//! A bundle is a signed, hash-bound manifest a client verifies OFFLINE on a clean machine
//! without trusting Ambush: every artifact is bound by SHA-256, the manifest is signed with a
//! detached DSSE envelope (Ed25519), and the signer key must appear in BOTH the bundle's own
//! `trust-roots.json` AND an out-of-band, env-pinned trusted-signer set (dual fail-closed gate).
//!
//! Carved — not copied — from the Chio Proof Room (Arc/Chio, Apache-2.0) onto swarm-crypto's
//! primitives. The deep per-receipt kernel-key signature verification and the Chio-specific
//! domain artifacts (transaction passports, settlement) are intentionally out of scope; the
//! receipt-coverage check here is the structural allow/deny/failure matrix. Verification fails
//! closed and reports a stable error code + a 6-bucket process exit code.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use swarm_crypto::{PublicKey, Signature, sha256_hex};

pub const BUNDLE_SCHEMA: &str = "ambush.attestation.bundle.v1";
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.ambush.attestation-bundle+json";
pub const SIGNATURE_KIND: &str = "detached-dsse";
pub const MANIFEST_NAME: &str = "manifest.json";
pub const TRUST_ROOTS_SCHEMA: &str = "ambush.attestation.trust-roots.v1";

/// The receipt-coverage categories an audit-grade bundle must account for.
pub const REQUIRED_COVERAGE_CATEGORIES: [&str; 3] = ["allow", "denial", "failure"];

// ---------------------------------------------------------------------------
// Manifest types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationBundle {
    pub schema: String,
    pub bundle_id: String,
    pub operation: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_command: Option<String>,
    pub hash_algorithm: String,
    pub artifacts: Vec<ArtifactRef>,
    pub claims: Vec<Claim>,
    pub receipt_coverage: Vec<ReceiptCoverage>,
    #[serde(default)]
    pub negative_cases: Vec<NegativeCase>,
    pub signature: SignatureRef,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub path: String,
    pub sha256: String,
    pub schema: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClaimResult {
    Verified,
    Failed,
    Unsupported,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claim {
    pub claim_id: String,
    pub required_artifacts: Vec<String>,
    pub checker: String,
    pub result: ClaimResult,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoverageStatus {
    Covered,
    Excluded,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptCoverage {
    /// One of REQUIRED_COVERAGE_CATEGORIES (allow | denial | failure).
    pub category: String,
    pub status: CoverageStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclusion_reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NegativeCase {
    pub id: String,
    pub path: String,
    pub expected_failure_code: String,
    pub observed_failure_code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureRef {
    pub kind: String,
    pub signature_ref: String,
}

// ---------------------------------------------------------------------------
// DSSE detached signature + trust roots
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetachedDsse {
    pub payload_type: String,
    pub payload_ref: ArtifactRef,
    pub signatures: Vec<DsseSig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DsseSig {
    pub keyid: String,
    pub sig: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustRoots {
    pub roots: Vec<TrustRoot>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustRoot {
    pub key_id: String,
    pub key_digest: String,
}

/// DSSE Pre-Authentication Encoding (PAEv1): `DSSEv1 <len(type)> <type> <len(payload)> <payload>`.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"DSSEv1 ");
    encoded.extend_from_slice(payload_type.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload_type.as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload);
    encoded
}

/// Produce a detached DSSE envelope over a manifest's exact bytes, signing the PAE with `signer`.
/// Used by Export Attestation (and the tests). `signer` is any swarm-crypto [`Keypair`].
pub fn sign_manifest(manifest_bytes: &[u8], signer: &swarm_crypto::Keypair) -> DetachedDsse {
    let signing_payload = pae(DSSE_PAYLOAD_TYPE, manifest_bytes);
    let sig = signer.sign(&signing_payload);
    DetachedDsse {
        payload_type: DSSE_PAYLOAD_TYPE.to_string(),
        payload_ref: ArtifactRef {
            path: MANIFEST_NAME.to_string(),
            sha256: sha256_hex(manifest_bytes),
            schema: BUNDLE_SCHEMA.to_string(),
        },
        signatures: vec![DsseSig {
            keyid: signer.public_key().to_hex(),
            sig: sig.to_hex(),
        }],
    }
}

// ---------------------------------------------------------------------------
// Verification errors + the 6-bucket exit taxonomy
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// A required claim failed (exit 10).
    #[error("required-claim: {0}")]
    RequiredClaim(String),
    /// Hash/signature/path integrity failure (exit 20).
    #[error("integrity: {0}")]
    Integrity(String),
    /// Parse or schema error (exit 30).
    #[error("parse-schema: {0}")]
    ParseSchema(String),
    /// A declared negative case did not reproduce its expected failure (exit 40).
    #[error("negative-case: {0}")]
    NegativeCase(String),
    /// Unsupported verifier feature/version (exit 50).
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// Release-truth/coverage-completeness failure (exit 60).
    #[error("release-truth: {0}")]
    ReleaseTruth(String),
}

impl VerifyError {
    /// Stable process exit code bucket.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::RequiredClaim(_) => 10,
            Self::Integrity(_) => 20,
            Self::ParseSchema(_) => 30,
            Self::NegativeCase(_) => 40,
            Self::Unsupported(_) => 50,
            Self::ReleaseTruth(_) => 60,
        }
    }

    /// Stable machine-readable code bucket (the `VFY_*`/category prefix).
    pub fn code(&self) -> &'static str {
        match self {
            Self::RequiredClaim(_) => "VFY_REQUIRED_CLAIM",
            Self::Integrity(_) => "VFY_INTEGRITY",
            Self::ParseSchema(_) => "VFY_PARSE_SCHEMA",
            Self::NegativeCase(_) => "VFY_NEGATIVE_CASE",
            Self::Unsupported(_) => "VFY_UNSUPPORTED",
            Self::ReleaseTruth(_) => "VFY_RELEASE_TRUTH",
        }
    }
}

/// Machine-readable verification outcome (the `ambush verify` JSON contract).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyOutcome {
    pub ok: bool,
    pub exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub bundle_id: String,
    pub artifacts_verified: usize,
    pub signatures_verified: usize,
    pub claims_verified: usize,
    pub negative_cases_checked: usize,
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

fn resolve_relative(root: &Path, rel: &str) -> Result<PathBuf, VerifyError> {
    if rel.is_empty() {
        return Err(VerifyError::ParseSchema("empty bundle path".into()));
    }
    let p = Path::new(rel);
    if p.is_absolute() {
        return Err(VerifyError::Integrity(format!("absolute path rejected: {rel}")));
    }
    for comp in p.components() {
        if !matches!(comp, Component::Normal(_)) {
            return Err(VerifyError::Integrity(format!("unsafe path component in: {rel}")));
        }
    }
    Ok(root.join(p))
}

fn read_file(root: &Path, rel: &str) -> Result<Vec<u8>, VerifyError> {
    let path = resolve_relative(root, rel)?;
    std::fs::read(&path).map_err(|e| VerifyError::Integrity(format!("unreadable {rel}: {e}")))
}

/// Verify a bundle directory offline. `bundle_root` must contain `manifest.json`, the signature
/// file, and every referenced artifact at its relative path. `env_trusted_keys` is the
/// out-of-band pinned signer set (hex public keys). Returns Ok with a populated outcome, or the
/// first verification error encountered (fail-closed).
pub fn verify_bundle(
    bundle_root: &Path,
    env_trusted_keys: &BTreeSet<String>,
) -> Result<VerifyOutcome, VerifyError> {
    let manifest_bytes = read_manifest_bytes(bundle_root)?;
    let bundle: AttestationBundle = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| VerifyError::ParseSchema(format!("manifest: {e}")))?;

    if bundle.schema != BUNDLE_SCHEMA {
        return Err(VerifyError::Unsupported(format!(
            "bundle schema {} (expected {BUNDLE_SCHEMA})",
            bundle.schema
        )));
    }
    if bundle.hash_algorithm != "sha256" {
        return Err(VerifyError::Unsupported(format!(
            "hash algorithm {} (expected sha256)",
            bundle.hash_algorithm
        )));
    }

    let registered: BTreeSet<&str> = bundle.artifacts.iter().map(|a| a.path.as_str()).collect();

    verify_artifact_integrity(bundle_root, &bundle)?;
    let signatures_verified =
        verify_signature(bundle_root, &bundle, &manifest_bytes, env_trusted_keys)?;
    verify_coverage(&bundle, &registered)?;
    let claims_verified = verify_claims(&bundle, &registered)?;
    verify_negative_cases(&bundle)?;

    Ok(VerifyOutcome {
        ok: true,
        exit_code: 0,
        error_code: None,
        error: None,
        bundle_id: bundle.bundle_id,
        artifacts_verified: bundle.artifacts.len(),
        signatures_verified,
        claims_verified,
        negative_cases_checked: bundle.negative_cases.len(),
    })
}

fn read_manifest_bytes(bundle_root: &Path) -> Result<Vec<u8>, VerifyError> {
    let path = bundle_root.join(MANIFEST_NAME);
    std::fs::read(&path).map_err(|e| VerifyError::Integrity(format!("manifest unreadable: {e}")))
}

fn verify_artifact_integrity(
    bundle_root: &Path,
    bundle: &AttestationBundle,
) -> Result<(), VerifyError> {
    for artifact in &bundle.artifacts {
        if artifact.sha256.len() != 64 || !artifact.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(VerifyError::ParseSchema(format!(
                "artifact {} has malformed sha256",
                artifact.path
            )));
        }
        let bytes = read_file(bundle_root, &artifact.path)?;
        let actual = sha256_hex(&bytes);
        if actual != artifact.sha256.to_lowercase() {
            return Err(VerifyError::Integrity(format!(
                "artifact {} hash mismatch (declared {}, actual {actual})",
                artifact.path, artifact.sha256
            )));
        }
    }
    Ok(())
}

fn verify_signature(
    bundle_root: &Path,
    bundle: &AttestationBundle,
    manifest_bytes: &[u8],
    env_trusted_keys: &BTreeSet<String>,
) -> Result<usize, VerifyError> {
    if bundle.signature.kind != SIGNATURE_KIND {
        return Err(VerifyError::Unsupported(format!(
            "signature kind {} (expected {SIGNATURE_KIND})",
            bundle.signature.kind
        )));
    }
    let sig_bytes = read_file(bundle_root, &bundle.signature.signature_ref)?;
    let detached: DetachedDsse = serde_json::from_slice(&sig_bytes)
        .map_err(|e| VerifyError::ParseSchema(format!("signature envelope: {e}")))?;

    if detached.payload_type != DSSE_PAYLOAD_TYPE {
        return Err(VerifyError::Integrity("dsse payload-type mismatch".into()));
    }
    if detached.payload_ref.path != MANIFEST_NAME {
        return Err(VerifyError::Integrity("dsse payload-path mismatch".into()));
    }
    if detached.payload_ref.sha256 != sha256_hex(manifest_bytes) {
        return Err(VerifyError::Integrity("dsse payload-hash mismatch".into()));
    }
    if detached.signatures.is_empty() {
        return Err(VerifyError::Integrity("no signatures present".into()));
    }

    let declared = trusted_signer_keys(bundle_root, bundle)?;
    if env_trusted_keys.is_empty() {
        return Err(VerifyError::Integrity(
            "no env-pinned trusted signer keys supplied (set AMBUSH_TRUSTED_SIGNER_KEYS)".into(),
        ));
    }

    let signing_payload = pae(&detached.payload_type, manifest_bytes);
    let mut verified = 0_usize;
    for entry in &detached.signatures {
        if entry.keyid.is_empty() || entry.sig.is_empty() {
            return Err(VerifyError::Integrity("signature field missing".into()));
        }
        let public_key = PublicKey::from_hex(&entry.keyid)
            .map_err(|e| VerifyError::Integrity(format!("invalid signer key: {e}")))?;
        let key_id = public_key.to_hex();
        // Dual fail-closed gate: the key must be in the bundle's own trust-roots AND pinned out-of-band.
        if !declared.contains(&key_id) || !env_trusted_keys.contains(&key_id) {
            return Err(VerifyError::Integrity("signer untrusted (not in trust-roots and pinned set)".into()));
        }
        let signature = Signature::from_hex(&entry.sig)
            .map_err(|e| VerifyError::Integrity(format!("invalid signature encoding: {e}")))?;
        if !public_key.verify(&signing_payload, &signature) {
            return Err(VerifyError::Integrity("signature verification failed".into()));
        }
        verified += 1;
    }
    Ok(verified)
}

fn trusted_signer_keys(
    bundle_root: &Path,
    bundle: &AttestationBundle,
) -> Result<BTreeSet<String>, VerifyError> {
    let reference = bundle
        .artifacts
        .iter()
        .find(|a| a.schema == TRUST_ROOTS_SCHEMA)
        .ok_or_else(|| VerifyError::Integrity("trust-roots artifact missing".into()))?;
    let bytes = read_file(bundle_root, &reference.path)?;
    let roots: TrustRoots = serde_json::from_slice(&bytes)
        .map_err(|e| VerifyError::ParseSchema(format!("trust-roots: {e}")))?;
    if roots.roots.is_empty() {
        return Err(VerifyError::Integrity("trust-roots empty".into()));
    }
    let mut trusted = BTreeSet::new();
    for root in roots.roots {
        if root.key_id.is_empty() || root.key_digest.is_empty() {
            return Err(VerifyError::Integrity("trust-root field missing".into()));
        }
        if root.key_digest != sha256_hex(root.key_id.as_bytes()) {
            return Err(VerifyError::Integrity("trust-root digest mismatch".into()));
        }
        let public_key = PublicKey::from_hex(&root.key_id)
            .map_err(|e| VerifyError::Integrity(format!("invalid trust-root key: {e}")))?;
        trusted.insert(public_key.to_hex());
    }
    Ok(trusted)
}

fn verify_coverage(
    bundle: &AttestationBundle,
    registered: &BTreeSet<&str>,
) -> Result<(), VerifyError> {
    let mut seen = BTreeSet::new();
    for entry in &bundle.receipt_coverage {
        if !REQUIRED_COVERAGE_CATEGORIES.contains(&entry.category.as_str()) {
            return Err(VerifyError::ParseSchema(format!(
                "unsupported coverage category {}",
                entry.category
            )));
        }
        if !seen.insert(entry.category.clone()) {
            return Err(VerifyError::ParseSchema(format!(
                "duplicate coverage category {}",
                entry.category
            )));
        }
        match entry.status {
            CoverageStatus::Covered => {
                let path = entry.artifact_path.as_deref().ok_or_else(|| {
                    VerifyError::ReleaseTruth(format!("coverage {} missing artifact", entry.category))
                })?;
                if !registered.contains(path) {
                    return Err(VerifyError::Integrity(format!(
                        "coverage {} references unregistered artifact {path}",
                        entry.category
                    )));
                }
                let status = entry.terminal_status.as_deref().unwrap_or("");
                if !terminal_status_matches(&entry.category, status) {
                    return Err(VerifyError::ReleaseTruth(format!(
                        "coverage {} terminal_status {status} does not match category",
                        entry.category
                    )));
                }
            }
            CoverageStatus::Excluded => {
                let reason = entry.exclusion_reason.as_deref().unwrap_or("");
                if reason.is_empty() {
                    return Err(VerifyError::ReleaseTruth(format!(
                        "coverage {} excluded without a reason",
                        entry.category
                    )));
                }
            }
        }
    }
    // Audit-grade completeness: every required category must be accounted for.
    for required in REQUIRED_COVERAGE_CATEGORIES {
        if !seen.contains(required) {
            return Err(VerifyError::ReleaseTruth(format!(
                "coverage matrix incomplete: missing {required}"
            )));
        }
    }
    Ok(())
}

fn terminal_status_matches(category: &str, status: &str) -> bool {
    match category {
        "allow" => status.starts_with("allowed_"),
        "denial" => status.starts_with("denied_"),
        "failure" => status.starts_with("failed_"),
        _ => false,
    }
}

fn verify_claims(
    bundle: &AttestationBundle,
    registered: &BTreeSet<&str>,
) -> Result<usize, VerifyError> {
    let mut verified = 0_usize;
    for claim in &bundle.claims {
        if claim.required_artifacts.is_empty() {
            return Err(VerifyError::ParseSchema(format!(
                "claim {} has no required artifacts",
                claim.claim_id
            )));
        }
        for path in &claim.required_artifacts {
            if !registered.contains(path.as_str()) {
                return Err(VerifyError::ParseSchema(format!(
                    "claim {} references unregistered artifact {path}",
                    claim.claim_id
                )));
            }
        }
        match claim.result {
            ClaimResult::Verified => verified += 1,
            ClaimResult::Failed => {
                return Err(VerifyError::RequiredClaim(format!(
                    "claim {} failed",
                    claim.claim_id
                )));
            }
            ClaimResult::Unsupported => {}
        }
    }
    Ok(verified)
}

fn verify_negative_cases(bundle: &AttestationBundle) -> Result<(), VerifyError> {
    for case in &bundle.negative_cases {
        if case.expected_failure_code != case.observed_failure_code {
            return Err(VerifyError::NegativeCase(format!(
                "case {} expected {} but observed {}",
                case.id, case.expected_failure_code, case.observed_failure_code
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use swarm_crypto::Keypair;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        signer: Keypair,
        signer_hex: String,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// Build a fully valid, signed bundle in a fresh temp dir.
    fn build_valid_bundle() -> Fixture {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("swarm-attest-{}-{n}", std::process::id()));
        std::fs::create_dir_all(root.join("artifacts/authority")).unwrap();
        std::fs::create_dir_all(root.join("findings")).unwrap();

        let signer = Keypair::generate();
        let signer_hex = signer.public_key().to_hex();

        // trust-roots.json
        let trust_roots = serde_json::to_vec(&TrustRoots {
            roots: vec![TrustRoot {
                key_id: signer_hex.clone(),
                key_digest: sha256_hex(signer_hex.as_bytes()),
            }],
        })
        .unwrap();
        write(&root, "artifacts/authority/trust-roots.json", &trust_roots);

        // a finding artifact + a receipt artifact
        let finding = b"# SSRF in order lookup\nconfirmed by 3 lanes\n";
        write(&root, "findings/vec-01.md", finding);
        let receipt = b"{\"verdict\":\"DENY\",\"tool\":\"net.connect\"}";
        write(&root, "findings/receipt-allow.json", receipt);

        let artifacts = vec![
            ArtifactRef {
                path: "artifacts/authority/trust-roots.json".into(),
                sha256: sha256_hex(&trust_roots),
                schema: TRUST_ROOTS_SCHEMA.into(),
            },
            ArtifactRef {
                path: "findings/vec-01.md".into(),
                sha256: sha256_hex(finding),
                schema: "ambush.finding.v1".into(),
            },
            ArtifactRef {
                path: "findings/receipt-allow.json".into(),
                sha256: sha256_hex(receipt),
                schema: "ambush.receipt.v1".into(),
            },
        ];

        let bundle = AttestationBundle {
            schema: BUNDLE_SCHEMA.into(),
            bundle_id: "bundle-001".into(),
            operation: "Operation Nightfall".into(),
            created_at: "2026-06-28T00:00:00Z".into(),
            source_command: Some("ambush export-attestation".into()),
            hash_algorithm: "sha256".into(),
            artifacts,
            claims: vec![Claim {
                claim_id: "all-governed-writes-have-receipts".into(),
                required_artifacts: vec!["findings/receipt-allow.json".into()],
                checker: "receipt-coverage".into(),
                result: ClaimResult::Verified,
            }],
            receipt_coverage: vec![
                ReceiptCoverage {
                    category: "allow".into(),
                    status: CoverageStatus::Covered,
                    artifact_path: Some("findings/receipt-allow.json".into()),
                    terminal_status: Some("allowed_executed".into()),
                    exclusion_reason: None,
                },
                ReceiptCoverage {
                    category: "denial".into(),
                    status: CoverageStatus::Covered,
                    artifact_path: Some("findings/receipt-allow.json".into()),
                    terminal_status: Some("denied_guard_request".into()),
                    exclusion_reason: None,
                },
                ReceiptCoverage {
                    category: "failure".into(),
                    status: CoverageStatus::Excluded,
                    artifact_path: None,
                    terminal_status: None,
                    exclusion_reason: Some("no terminal failures occurred".into()),
                },
            ],
            negative_cases: vec![NegativeCase {
                id: "tampered-finding".into(),
                path: "findings/vec-01.md".into(),
                expected_failure_code: "VFY_INTEGRITY".into(),
                observed_failure_code: "VFY_INTEGRITY".into(),
            }],
            signature: SignatureRef {
                kind: SIGNATURE_KIND.into(),
                signature_ref: "signature.dsse.json".into(),
            },
        };

        // Canonical manifest bytes are what we sign and hash-bind.
        let manifest_bytes = serde_json::to_vec(&bundle).unwrap();
        write(&root, MANIFEST_NAME, &manifest_bytes);
        let detached = sign_manifest(&manifest_bytes, &signer);
        write(&root, "signature.dsse.json", &serde_json::to_vec(&detached).unwrap());

        Fixture { root, signer, signer_hex }
    }

    fn write(root: &Path, rel: &str, bytes: &[u8]) {
        std::fs::write(root.join(rel), bytes).unwrap();
    }

    fn pinned(fx: &Fixture) -> BTreeSet<String> {
        BTreeSet::from([fx.signer_hex.clone()])
    }

    #[test]
    fn valid_bundle_verifies() {
        let fx = build_valid_bundle();
        let outcome = verify_bundle(&fx.root, &pinned(&fx)).unwrap();
        assert!(outcome.ok);
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.artifacts_verified, 3);
        assert_eq!(outcome.signatures_verified, 1);
        assert_eq!(outcome.claims_verified, 1);
    }

    #[test]
    fn tampered_artifact_fails_integrity() {
        let fx = build_valid_bundle();
        // mutate a hash-bound artifact AFTER signing
        write(&fx.root, "findings/vec-01.md", b"# tampered\n");
        let err = verify_bundle(&fx.root, &pinned(&fx)).unwrap_err();
        assert_eq!(err.exit_code(), 20);
        assert_eq!(err.code(), "VFY_INTEGRITY");
    }

    #[test]
    fn tampered_manifest_fails_payload_hash() {
        let fx = build_valid_bundle();
        // rewrite the manifest so its bytes no longer match the signed payload hash
        let mut bundle: AttestationBundle =
            serde_json::from_slice(&std::fs::read(fx.root.join(MANIFEST_NAME)).unwrap()).unwrap();
        bundle.operation = "Operation Tamper".into();
        write(&fx.root, MANIFEST_NAME, &serde_json::to_vec(&bundle).unwrap());
        let err = verify_bundle(&fx.root, &pinned(&fx)).unwrap_err();
        assert_eq!(err.exit_code(), 20);
    }

    #[test]
    fn untrusted_pinned_key_fails() {
        let fx = build_valid_bundle();
        let other = BTreeSet::from([Keypair::generate().public_key().to_hex()]);
        let err = verify_bundle(&fx.root, &other).unwrap_err();
        assert_eq!(err.exit_code(), 20); // signer not in env-pinned set
    }

    #[test]
    fn empty_pinned_set_fails_closed() {
        let fx = build_valid_bundle();
        let err = verify_bundle(&fx.root, &BTreeSet::new()).unwrap_err();
        assert_eq!(err.exit_code(), 20);
    }

    #[test]
    fn failed_claim_fails_required_claim() {
        let fx = build_valid_bundle();
        let mut bundle: AttestationBundle =
            serde_json::from_slice(&std::fs::read(fx.root.join(MANIFEST_NAME)).unwrap()).unwrap();
        bundle.claims[0].result = ClaimResult::Failed;
        resign(&fx, &bundle); // re-sign so the signature stays valid; the claim itself must fail
        let err = verify_bundle(&fx.root, &pinned(&fx)).unwrap_err();
        assert_eq!(err.exit_code(), 10);
        assert_eq!(err.code(), "VFY_REQUIRED_CLAIM");
    }

    #[test]
    fn incomplete_coverage_fails_release_truth() {
        let fx = build_valid_bundle();
        let mut bundle: AttestationBundle =
            serde_json::from_slice(&std::fs::read(fx.root.join(MANIFEST_NAME)).unwrap()).unwrap();
        bundle.receipt_coverage.retain(|c| c.category != "failure");
        resign(&fx, &bundle);
        let err = verify_bundle(&fx.root, &pinned(&fx)).unwrap_err();
        assert_eq!(err.exit_code(), 60);
        assert_eq!(err.code(), "VFY_RELEASE_TRUTH");
    }

    #[test]
    fn negative_case_mismatch_fails() {
        let fx = build_valid_bundle();
        let mut bundle: AttestationBundle =
            serde_json::from_slice(&std::fs::read(fx.root.join(MANIFEST_NAME)).unwrap()).unwrap();
        bundle.negative_cases[0].observed_failure_code = "VFY_NONE".into();
        resign(&fx, &bundle);
        let err = verify_bundle(&fx.root, &pinned(&fx)).unwrap_err();
        assert_eq!(err.exit_code(), 40);
    }

    /// Re-sign the fixture's manifest with the SAME signer key after mutating `bundle`, so the
    /// signature + trust-roots stay valid and the test exercises the targeted check (not the
    /// hash/signature gate).
    fn resign(fx: &Fixture, bundle: &AttestationBundle) {
        let manifest_bytes = serde_json::to_vec(bundle).unwrap();
        write(&fx.root, MANIFEST_NAME, &manifest_bytes);
        let detached = sign_manifest(&manifest_bytes, &fx.signer);
        write(&fx.root, "signature.dsse.json", &serde_json::to_vec(&detached).unwrap());
    }
}
