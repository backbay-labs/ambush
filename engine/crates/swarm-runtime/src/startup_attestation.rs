use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::RuntimeMode;
use swarm_crypto::{
    DetachedSignature, canonical_json_bytes, sha256_hex, verify_detached_signature,
};

use crate::evasion_coverage::resolve_repo_root;

const REPO_RULESET_DIR: &str = "rulesets";
const RULESET_MANIFEST_PATH: &str = "rulesets/attestation.json";
const TRUSTED_ATTESTATION_KEY_ID: &str =
    "1ea7877323c9e3a3e30e9daeb0dd9d48c39ec15fa34de42c3705e41840bcd023";
const TRUSTED_ATTESTATION_PUBLIC_KEY_HEX: &str =
    "172e740c4a651279713f27ead2f1fb15abdf52de7b7d3f6239c455edf609e164";

#[derive(Debug, Clone, PartialEq, Eq)]
struct AttestationTrustRoot {
    key_id: String,
    public_key_hex: String,
}

impl AttestationTrustRoot {
    fn repo_owned() -> Self {
        Self {
            key_id: TRUSTED_ATTESTATION_KEY_ID.to_string(),
            public_key_hex: TRUSTED_ATTESTATION_PUBLIC_KEY_HEX.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StartupAttestationReport {
    pub ready: bool,
    pub evaluated_at_ms: i64,
    pub binary: StartupAttestationComponentReport,
    pub rulesets: StartupAttestationComponentReport,
}

impl StartupAttestationReport {
    pub fn verify(config_path: &Path) -> Self {
        let trust_root = AttestationTrustRoot::repo_owned();
        let repo_root = resolve_repo_root(config_path);
        let binary = verify_binary_component_current_exe(&trust_root);
        let rulesets = verify_ruleset_component(&repo_root, &trust_root);

        Self {
            ready: binary.ready && rulesets.ready,
            evaluated_at_ms: now_ms(),
            binary,
            rulesets,
        }
    }

    pub fn ready_for_mode(&self, mode: RuntimeMode) -> bool {
        match mode {
            RuntimeMode::DetectOnly => true,
            RuntimeMode::LiveResponse => self.ready,
        }
    }

    pub fn status(&self) -> &'static str {
        if self.ready { "verified" } else { "failed" }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StartupAttestationComponentReport {
    pub ready: bool,
    pub subject: String,
    pub statement_path: String,
    pub status: String,
    pub details: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_items: Option<usize>,
}

#[derive(Debug, thiserror::Error)]
#[error("startup attestation failed for live_response mode: {summary}")]
pub struct StartupAttestationFailure {
    summary: String,
}

impl StartupAttestationFailure {
    pub fn new(report: &StartupAttestationReport) -> Self {
        Self {
            summary: format!(
                "binary={}, rulesets={}",
                report.binary.details, report.rulesets.details
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedBinaryAttestation {
    statement: BinaryAttestationStatement,
    signature: DetachedSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BinaryAttestationStatement {
    version: u32,
    issued_at_ms: i64,
    executable_name: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedRulesetAttestation {
    statement: RulesetAttestationStatement,
    signature: DetachedSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RulesetAttestationStatement {
    version: u32,
    issued_at_ms: i64,
    root: String,
    files: Vec<RulesetAttestationFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RulesetAttestationFile {
    path: String,
    sha256: String,
}

pub fn binary_attestation_sidecar_path(executable_path: &Path) -> PathBuf {
    let file_name = executable_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "swarm_detect".to_string());
    executable_path.with_file_name(format!("{file_name}.attestation.json"))
}

fn verify_binary_component_current_exe(
    trust_root: &AttestationTrustRoot,
) -> StartupAttestationComponentReport {
    match std::env::current_exe() {
        Ok(executable_path) => verify_binary_component(
            &executable_path,
            &binary_attestation_sidecar_path(&executable_path),
            trust_root,
        ),
        Err(error) => StartupAttestationComponentReport {
            ready: false,
            subject: "current_executable".to_string(),
            statement_path: "current_executable.attestation.json".to_string(),
            status: "failed".to_string(),
            details: format!("failed to resolve running executable: {error}"),
            key_id: Some(trust_root.key_id.clone()),
            expected_sha256: None,
            observed_sha256: None,
            verified_items: None,
        },
    }
}

fn verify_binary_component(
    executable_path: &Path,
    statement_path: &Path,
    trust_root: &AttestationTrustRoot,
) -> StartupAttestationComponentReport {
    let subject = executable_path.display().to_string();
    match verify_binary_statement(executable_path, statement_path, trust_root) {
        Ok(verified) => StartupAttestationComponentReport {
            ready: true,
            subject,
            statement_path: statement_path.display().to_string(),
            status: "verified".to_string(),
            details: format!(
                "verified binary digest and size for `{}`",
                verified.executable_name
            ),
            key_id: Some(trust_root.key_id.clone()),
            expected_sha256: Some(verified.sha256.clone()),
            observed_sha256: Some(verified.sha256),
            verified_items: Some(1),
        },
        Err(error) => StartupAttestationComponentReport {
            ready: false,
            subject,
            statement_path: statement_path.display().to_string(),
            status: "failed".to_string(),
            details: error,
            key_id: Some(trust_root.key_id.clone()),
            expected_sha256: None,
            observed_sha256: None,
            verified_items: None,
        },
    }
}

fn verify_binary_statement(
    executable_path: &Path,
    statement_path: &Path,
    trust_root: &AttestationTrustRoot,
) -> Result<BinaryAttestationStatement, String> {
    let signed = read_json::<SignedBinaryAttestation>(statement_path)?;
    verify_signature(
        &signed.statement,
        &signed.signature,
        trust_root,
        statement_path,
    )?;

    let executable_name = executable_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .ok_or_else(|| {
            format!(
                "failed to derive executable name from `{}`",
                executable_path.display()
            )
        })?;
    if signed.statement.executable_name != executable_name {
        return Err(format!(
            "binary attestation subject mismatch: expected `{}`, got `{}`",
            executable_name, signed.statement.executable_name
        ));
    }

    let bytes = fs::read(executable_path).map_err(|error| {
        format!(
            "failed to read binary `{}` for startup attestation: {error}",
            executable_path.display()
        )
    })?;
    let observed_sha256 = sha256_hex(&bytes);
    let observed_size = bytes.len() as u64;
    if observed_sha256 != signed.statement.sha256 {
        return Err(format!(
            "binary digest mismatch: expected {}, observed {}",
            signed.statement.sha256, observed_sha256
        ));
    }
    if observed_size != signed.statement.size_bytes {
        return Err(format!(
            "binary size mismatch: expected {}, observed {}",
            signed.statement.size_bytes, observed_size
        ));
    }

    Ok(signed.statement)
}

fn verify_ruleset_component(
    repo_root: &Path,
    trust_root: &AttestationTrustRoot,
) -> StartupAttestationComponentReport {
    let statement_path = repo_root.join(RULESET_MANIFEST_PATH);
    let subject = repo_root.join(REPO_RULESET_DIR).display().to_string();
    match verify_ruleset_statement(repo_root, &statement_path, trust_root) {
        Ok(verified_items) => StartupAttestationComponentReport {
            ready: true,
            subject,
            statement_path: statement_path.display().to_string(),
            status: "verified".to_string(),
            details: format!("verified {} repo-owned ruleset files", verified_items),
            key_id: Some(trust_root.key_id.clone()),
            expected_sha256: None,
            observed_sha256: None,
            verified_items: Some(verified_items),
        },
        Err(error) => StartupAttestationComponentReport {
            ready: false,
            subject,
            statement_path: statement_path.display().to_string(),
            status: "failed".to_string(),
            details: error,
            key_id: Some(trust_root.key_id.clone()),
            expected_sha256: None,
            observed_sha256: None,
            verified_items: None,
        },
    }
}

fn verify_ruleset_statement(
    repo_root: &Path,
    statement_path: &Path,
    trust_root: &AttestationTrustRoot,
) -> Result<usize, String> {
    let signed = read_json::<SignedRulesetAttestation>(statement_path)?;
    verify_signature(
        &signed.statement,
        &signed.signature,
        trust_root,
        statement_path,
    )?;
    if signed.statement.root != REPO_RULESET_DIR {
        return Err(format!(
            "ruleset attestation root mismatch: expected `{REPO_RULESET_DIR}`, got `{}`",
            signed.statement.root
        ));
    }

    let observed_paths = collect_ruleset_files(repo_root)?;
    let observed_set = observed_paths.iter().cloned().collect::<BTreeSet<String>>();
    let manifest = signed
        .statement
        .files
        .into_iter()
        .map(|entry| (entry.path, entry.sha256))
        .collect::<BTreeMap<_, _>>();
    let manifest_set = manifest.keys().cloned().collect::<BTreeSet<_>>();

    let missing = manifest_set
        .difference(&observed_set)
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "ruleset attestation is missing repo files: {}",
            missing.join(", ")
        ));
    }

    let unexpected = observed_set
        .difference(&manifest_set)
        .cloned()
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        return Err(format!(
            "ruleset attestation does not cover repo files: {}",
            unexpected.join(", ")
        ));
    }

    for path in observed_paths {
        let absolute_path = repo_root.join(&path);
        let bytes = fs::read(&absolute_path).map_err(|error| {
            format!(
                "failed to read ruleset `{}` for startup attestation: {error}",
                absolute_path.display()
            )
        })?;
        let observed_sha256 = sha256_hex(&bytes);
        let expected_sha256 = manifest.get(&path).ok_or_else(|| {
            format!("ruleset attestation is missing digest for repo file `{path}`")
        })?;
        if &observed_sha256 != expected_sha256 {
            return Err(format!(
                "ruleset digest mismatch for `{path}`: expected {expected_sha256}, observed {observed_sha256}"
            ));
        }
    }

    Ok(manifest.len())
}

fn collect_ruleset_files(repo_root: &Path) -> Result<Vec<String>, String> {
    let ruleset_root = repo_root.join(REPO_RULESET_DIR);
    let mut pending = vec![ruleset_root.clone()];
    let mut files = Vec::new();

    while let Some(dir) = pending.pop() {
        let entries = fs::read_dir(&dir).map_err(|error| {
            format!(
                "failed to read ruleset directory `{}`: {error}",
                dir.display()
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                format!(
                    "failed to enumerate ruleset directory `{}`: {error}",
                    dir.display()
                )
            })?;
            let path = entry.path();
            let file_type = entry.file_type().map_err(|error| {
                format!(
                    "failed to inspect ruleset path `{}`: {error}",
                    path.display()
                )
            })?;
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let extension = path.extension().and_then(|value| value.to_str());
            if !matches!(extension, Some("yaml" | "yml")) {
                continue;
            }
            let relative = path.strip_prefix(repo_root).map_err(|error| {
                format!(
                    "failed to compute repo-relative path for `{}`: {error}",
                    path.display()
                )
            })?;
            files.push(relative.to_string_lossy().replace('\\', "/"));
        }
    }

    files.sort();
    Ok(files)
}

fn verify_signature<T: Serialize>(
    statement: &T,
    signature: &DetachedSignature,
    trust_root: &AttestationTrustRoot,
    statement_path: &Path,
) -> Result<(), String> {
    if signature.key_id != trust_root.key_id
        || signature.public_key_hex != trust_root.public_key_hex
    {
        return Err(format!(
            "attestation signature trust root mismatch for `{}`",
            statement_path.display()
        ));
    }

    let payload = canonical_json_bytes(statement).map_err(|error| {
        format!(
            "failed to canonicalize startup attestation statement `{}`: {error}",
            statement_path.display()
        )
    })?;
    verify_detached_signature(&payload, signature).map_err(|error| {
        format!(
            "startup attestation signature verification failed for `{}`: {error}",
            statement_path.display()
        )
    })
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let raw = fs::read_to_string(path).map_err(|error| {
        format!(
            "failed to read startup attestation `{}`: {error}",
            path.display()
        )
    })?;
    serde_json::from_str(&raw).map_err(|error| {
        format!(
            "failed to parse startup attestation `{}`: {error}",
            path.display()
        )
    })
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::{
        AttestationTrustRoot, BinaryAttestationStatement, RulesetAttestationFile,
        RulesetAttestationStatement, SignedBinaryAttestation, SignedRulesetAttestation,
        StartupAttestationReport, binary_attestation_sidecar_path, collect_ruleset_files,
        verify_binary_component, verify_ruleset_component,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};
    use swarm_core::config::RuntimeMode;
    use swarm_crypto::{Ed25519Signer, canonical_json_bytes, sha256_hex};

    fn temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("swarm-startup-attestation-{label}-{unique}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn signer_trust_root(secret: &str) -> (Ed25519Signer, AttestationTrustRoot) {
        let signer = Ed25519Signer::from_secret_material(secret);
        let trust_root = AttestationTrustRoot {
            key_id: signer.key_id().to_string(),
            public_key_hex: signer.public_key_hex().to_string(),
        };
        (signer, trust_root)
    }

    fn sign_statement<T: serde::Serialize>(
        statement: &T,
        signer: &Ed25519Signer,
    ) -> swarm_crypto::DetachedSignature {
        signer.sign(&canonical_json_bytes(statement).unwrap())
    }

    fn write_json<T: serde::Serialize>(path: &Path, value: &T) {
        fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    }

    #[test]
    fn repo_ruleset_attestation_matches_checked_in_files() {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap()
            .to_path_buf();
        let report = verify_ruleset_component(&repo_root, &AttestationTrustRoot::repo_owned());

        assert!(report.ready, "{}", report.details);
        assert_eq!(report.verified_items, Some(3));
    }

    #[test]
    fn binary_attestation_verifies_matching_sidecar() {
        let dir = temp_dir("binary-ok");
        let executable = dir.join("swarm_detect");
        fs::write(&executable, b"trusted-binary").unwrap();

        let (signer, trust_root) = signer_trust_root("binary-ok");
        let statement = BinaryAttestationStatement {
            version: 1,
            issued_at_ms: 1_710_000_000_000,
            executable_name: "swarm_detect".to_string(),
            sha256: sha256_hex(b"trusted-binary"),
            size_bytes: b"trusted-binary".len() as u64,
        };
        let sidecar = binary_attestation_sidecar_path(&executable);
        write_json(
            &sidecar,
            &SignedBinaryAttestation {
                signature: sign_statement(&statement, &signer),
                statement,
            },
        );

        let report = verify_binary_component(&executable, &sidecar, &trust_root);
        assert!(report.ready, "{}", report.details);
    }

    #[test]
    fn binary_attestation_rejects_tampered_binary() {
        let dir = temp_dir("binary-tampered");
        let executable = dir.join("swarm_detect");
        fs::write(&executable, b"trusted-binary").unwrap();

        let (signer, trust_root) = signer_trust_root("binary-tampered");
        let statement = BinaryAttestationStatement {
            version: 1,
            issued_at_ms: 1_710_000_000_000,
            executable_name: "swarm_detect".to_string(),
            sha256: sha256_hex(b"trusted-binary"),
            size_bytes: b"trusted-binary".len() as u64,
        };
        let sidecar = binary_attestation_sidecar_path(&executable);
        write_json(
            &sidecar,
            &SignedBinaryAttestation {
                signature: sign_statement(&statement, &signer),
                statement,
            },
        );

        fs::write(&executable, b"tampered-binary").unwrap();
        let report = verify_binary_component(&executable, &sidecar, &trust_root);
        assert!(!report.ready);
        assert!(report.details.contains("binary digest mismatch"));
    }

    #[test]
    fn ruleset_attestation_rejects_uncovered_repo_file() {
        let dir = temp_dir("rulesets-uncovered");
        fs::create_dir_all(dir.join("rulesets")).unwrap();
        fs::create_dir_all(dir.join("rulesets/safety")).unwrap();
        fs::write(dir.join("rulesets/default.yaml"), "schema_version: 1\n").unwrap();
        fs::write(
            dir.join("rulesets/safety/office-detector-admission.yaml"),
            "admit: true\n",
        )
        .unwrap();

        let (signer, trust_root) = signer_trust_root("rulesets-uncovered");
        let statement = RulesetAttestationStatement {
            version: 1,
            issued_at_ms: 1_710_000_000_000,
            root: "rulesets".to_string(),
            files: vec![RulesetAttestationFile {
                path: "rulesets/default.yaml".to_string(),
                sha256: sha256_hex(b"schema_version: 1\n"),
            }],
        };
        let statement_path = dir.join("rulesets/attestation.json");
        write_json(
            &statement_path,
            &SignedRulesetAttestation {
                signature: sign_statement(&statement, &signer),
                statement,
            },
        );

        let report = verify_ruleset_component(&dir, &trust_root);
        assert!(!report.ready);
        assert!(report.details.contains("does not cover repo files"));
    }

    #[test]
    fn startup_attestation_only_blocks_live_response_mode() {
        let report = StartupAttestationReport {
            ready: false,
            evaluated_at_ms: 1_710_000_000_000,
            binary: super::StartupAttestationComponentReport {
                ready: false,
                subject: "binary".to_string(),
                statement_path: "binary.attestation.json".to_string(),
                status: "failed".to_string(),
                details: "missing".to_string(),
                key_id: None,
                expected_sha256: None,
                observed_sha256: None,
                verified_items: None,
            },
            rulesets: super::StartupAttestationComponentReport {
                ready: true,
                subject: "rulesets".to_string(),
                statement_path: "rulesets/attestation.json".to_string(),
                status: "verified".to_string(),
                details: "ok".to_string(),
                key_id: None,
                expected_sha256: None,
                observed_sha256: None,
                verified_items: Some(1),
            },
        };

        assert!(report.ready_for_mode(RuntimeMode::DetectOnly));
        assert!(!report.ready_for_mode(RuntimeMode::LiveResponse));
    }

    #[test]
    fn collect_ruleset_files_sorts_repo_relative_paths() {
        let dir = temp_dir("collect-rulesets");
        fs::create_dir_all(dir.join("rulesets/evasion")).unwrap();
        fs::write(dir.join("rulesets/z.yaml"), "z: 1\n").unwrap();
        fs::write(dir.join("rulesets/evasion/a.yaml"), "a: 1\n").unwrap();

        let files = collect_ruleset_files(&dir).unwrap();
        assert_eq!(files, vec!["rulesets/evasion/a.yaml", "rulesets/z.yaml"]);
    }
}
