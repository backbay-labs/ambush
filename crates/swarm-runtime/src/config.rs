use crate::sequence_detector::KillChainSequenceProfile;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_yaml::Value as YamlValue;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};
use swarm_crypto::{
    DetachedSignature, canonical_json_bytes, sha256_hex, verify_detached_signature,
};
use swarm_whisker::{
    BehavioralAnomalyProfile, CredentialAccessProfile, DnsExfiltrationProfile,
    FilelessExecutionProfile, InfrastructureAnomalyProfile, LateralMovementProfile,
    NetworkConnectProfile, PersistenceProfile, ProfileValidationError, SupplyChainProfile,
    SuspiciousProcessTreeProfile, SuspiciousScriptingProfile,
};

pub use swarm_core::config::{
    CanaryConfig, CircuitBreakerConfig, CloudTrailBridgeConfig, ConfigValidationError,
    CorrelationConfig, DetectionConfig, DetectorProfilesConfig, EvolutionConfig,
    EvolutionFitnessWeightsConfig, EvolutionPathsConfig, EvolutionSafetyGateConfig,
    FieldMappingConfig, GenericJsonBridgeConfig, GenericJsonPayloadMappingConfig, HttpEdrConfig,
    IdentityConfig, InvestigationConfig, JsonFileSourceConfig, NotificationChannelConfig,
    NotificationRateLimitConfig, NotificationRoutingConfig, OperatorAuthConfig,
    OperatorSurfaceConfig, PheromoneConfig, PolicyConfig, PromotionConfig, ResponseAdapterConfig,
    RetryConfig, RoutingRule, RuntimeAntiTamperConfig, RuntimeMode, RuntimeSettings,
    SentinelBridgeConfig, SiemForwardConfig, SwarmConfig, TelemetryBridgeConfig,
    TelemetrySourceConfig, TemporalEventWindowConfig, TetragonBridgeConfig, WebhookConfig,
};

pub type RuntimeConfig = RuntimeSettings;
pub const CURRENT_SCHEMA_VERSION: u32 = 1;
const CONFIG_SIGNATURE_TRUST_KEY_ID: &str =
    "854cb2ac6a51da46daf5bdbb0d5b34d9831e5aa60290b94ea2f810f5999f2521";
const CONFIG_SIGNATURE_TRUST_PUBLIC_KEY_HEX: &str =
    "25e6e1874dbaedbf86dd50afcadeb0067d973c35e88dbf6ea3c3dc30281753f5";
#[cfg(debug_assertions)]
const DEBUG_TEST_CONFIG_SIGNING_SECRET: &str = "swarm-runtime-debug-config-signature-test-key";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigMigrationSummary {
    from_version: u32,
    to_version: u32,
    steps: Vec<&'static str>,
}

#[derive(Debug, thiserror::Error)]
pub enum SecretResolutionError {
    #[error("invalid secret reference `{reference}`: {reason}")]
    InvalidReference { reference: String, reason: String },

    #[error("failed to read secret file `{path}`: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("missing secret env var `{env_var}`")]
    MissingEnvVar { env_var: String },
}

pub trait SwarmSecretProvider: Send + Sync {
    fn resolve(&self, reference: &str) -> Result<String, SecretResolutionError>;
}

#[derive(Debug, Clone, Default)]
pub struct FileEnvSecretProvider {
    secret_dir: Option<PathBuf>,
}

impl FileEnvSecretProvider {
    pub fn new(secret_dir: Option<PathBuf>) -> Self {
        Self { secret_dir }
    }
}

impl SwarmSecretProvider for FileEnvSecretProvider {
    fn resolve(&self, reference: &str) -> Result<String, SecretResolutionError> {
        const PREFIX: &str = "@secret:";
        let Some(reference) = reference.strip_prefix(PREFIX) else {
            return Err(SecretResolutionError::InvalidReference {
                reference: reference.to_string(),
                reason: "references must start with `@secret:`".to_string(),
            });
        };

        if let Some(env_var) = reference.strip_prefix("env:") {
            let env_var = env_var.trim();
            if env_var.is_empty() {
                return Err(SecretResolutionError::InvalidReference {
                    reference: format!("{PREFIX}{reference}"),
                    reason: "environment secret name must not be empty".to_string(),
                });
            }
            let value = env::var(env_var).map_err(|_| SecretResolutionError::MissingEnvVar {
                env_var: env_var.to_string(),
            })?;
            let trimmed = value.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                return Err(SecretResolutionError::InvalidReference {
                    reference: format!("{PREFIX}{reference}"),
                    reason: "resolved environment secret must not be empty".to_string(),
                });
            }
            return Ok(trimmed.to_string());
        }

        let secret_name = reference.trim();
        if secret_name.is_empty() {
            return Err(SecretResolutionError::InvalidReference {
                reference: format!("{PREFIX}{reference}"),
                reason: "file secret name must not be empty".to_string(),
            });
        }
        validate_secret_name(secret_name, &format!("{PREFIX}{reference}"))?;
        let Some(secret_dir) = &self.secret_dir else {
            return Err(SecretResolutionError::InvalidReference {
                reference: format!("{PREFIX}{reference}"),
                reason: "runtime.secret_dir must be configured for file-backed secrets".to_string(),
            });
        };
        let path =
            canonical_secret_file_path(secret_dir, secret_name, &format!("{PREFIX}{reference}"))?;
        let value =
            fs::read_to_string(&path).map_err(|source| SecretResolutionError::ReadFile {
                path: path.clone(),
                source,
            })?;
        let trimmed = value.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            return Err(SecretResolutionError::InvalidReference {
                reference: format!("{PREFIX}{reference}"),
                reason: format!("resolved secret file `{}` is empty", path.display()),
            });
        }
        Ok(trimmed.to_string())
    }
}

fn validate_secret_name(secret_name: &str, reference: &str) -> Result<(), SecretResolutionError> {
    let path = Path::new(secret_name);
    if path.is_absolute() {
        return Err(SecretResolutionError::InvalidReference {
            reference: reference.to_string(),
            reason: "file secret name must be relative to runtime.secret_dir".to_string(),
        });
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(SecretResolutionError::InvalidReference {
            reference: reference.to_string(),
            reason: "file secret name must not contain path traversal or non-normal components"
                .to_string(),
        });
    }
    Ok(())
}

fn canonical_secret_file_path(
    secret_dir: &Path,
    secret_name: &str,
    reference: &str,
) -> Result<PathBuf, SecretResolutionError> {
    let root = fs::canonicalize(secret_dir).map_err(|source| SecretResolutionError::ReadFile {
        path: secret_dir.to_path_buf(),
        source,
    })?;
    let candidate = secret_dir.join(secret_name);
    let resolved =
        fs::canonicalize(&candidate).map_err(|source| SecretResolutionError::ReadFile {
            path: candidate.clone(),
            source,
        })?;
    if !resolved.starts_with(&root) {
        return Err(SecretResolutionError::InvalidReference {
            reference: reference.to_string(),
            reason: "resolved secret path escapes runtime.secret_dir".to_string(),
        });
    }
    Ok(resolved)
}

/// Errors raised while parsing and validating detector profile payloads.
#[derive(Debug, thiserror::Error)]
pub enum DetectorProfileError {
    #[error("failed to parse detector profile `{strategy}`: {source}")]
    Parse {
        strategy: &'static str,
        #[source]
        source: serde_json::Error,
    },

    #[error("invalid detector profile `{strategy}`: {source}")]
    Validation {
        strategy: &'static str,
        #[source]
        source: ProfileValidationError,
    },
}

/// Errors raised while loading runtime configuration from repository files.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeConfigError {
    #[error("failed to read config `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse config `{source_name}`: {source}")]
    Parse {
        source_name: String,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("invalid config `{source_name}`: {source}")]
    Validation {
        source_name: String,
        #[source]
        source: ConfigValidationError,
    },

    #[error("invalid detector profiles in `{source_name}`: {source}")]
    DetectorProfile {
        source_name: String,
        #[source]
        source: DetectorProfileError,
    },

    #[error("config signature verification failed for `{source_name}`: {source}")]
    Signature {
        source_name: String,
        #[source]
        source: ConfigSignatureError,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigSignatureError {
    #[error("missing config signature sidecar `{path}`")]
    MissingSidecar { path: PathBuf },

    #[error("failed to read config signature sidecar `{path}`: {source}")]
    ReadSidecar {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse config signature sidecar `{path}`: {source}")]
    ParseSidecar {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("config signature for `{path}` was not signed by a trusted key")]
    UntrustedSigner { path: PathBuf },

    #[error("failed to canonicalize config signature statement `{path}`: {source}")]
    Canonicalize {
        path: PathBuf,
        #[source]
        source: swarm_crypto::CryptoError,
    },

    #[error("config signature verification failed for `{path}`: {source}")]
    InvalidSignature {
        path: PathBuf,
        #[source]
        source: swarm_crypto::CryptoError,
    },

    #[error(
        "config signature subject mismatch for `{path}`: expected `{expected}`, got `{actual}`"
    )]
    SubjectMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },

    #[error(
        "config digest mismatch for `{path}`: expected {expected_sha256}, observed {observed_sha256}"
    )]
    DigestMismatch {
        path: PathBuf,
        expected_sha256: String,
        observed_sha256: String,
    },

    #[error(
        "config size mismatch for `{path}`: expected {expected_size_bytes}, observed {observed_size_bytes}"
    )]
    SizeMismatch {
        path: PathBuf,
        expected_size_bytes: u64,
        observed_size_bytes: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigSignatureTrustRoot {
    key_id: String,
    public_key_hex: String,
}

impl ConfigSignatureTrustRoot {
    fn production() -> Self {
        Self {
            key_id: CONFIG_SIGNATURE_TRUST_KEY_ID.to_string(),
            public_key_hex: CONFIG_SIGNATURE_TRUST_PUBLIC_KEY_HEX.to_string(),
        }
    }

    #[cfg(debug_assertions)]
    fn debug_test() -> Self {
        let signer =
            swarm_crypto::Ed25519Signer::from_secret_material(DEBUG_TEST_CONFIG_SIGNING_SECRET);
        Self {
            key_id: signer.key_id().to_string(),
            public_key_hex: signer.public_key_hex().to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedConfigSignature {
    statement: ConfigSignatureStatement,
    signature: DetachedSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfigSignatureStatement {
    version: u32,
    issued_at_ms: i64,
    config_file_name: String,
    sha256: String,
    size_bytes: u64,
}

/// Load a repository-owned runtime config file from disk.
pub fn load_config(path: impl AsRef<Path>) -> Result<SwarmConfig, RuntimeConfigError> {
    let path = path.as_ref();
    let raw = read_verified_config_text(path)?;

    parse_config_with_base(&raw, path.display().to_string(), Some(path))
}

/// Load a runtime config from disk without resolving `@secret:` references.
///
/// The returned config passes migration, deserialization, structural validation,
/// and detector-profile validation, but `@secret:` references remain as literal
/// string values. Use [`resolve_outbound_secrets`] to resolve them afterwards.
pub fn load_config_unresolved(path: impl AsRef<Path>) -> Result<SwarmConfig, RuntimeConfigError> {
    let path = path.as_ref();
    let raw = read_verified_config_text(path)?;

    parse_config_unresolved(&raw, path.display().to_string())
}

pub fn config_signature_sidecar_path(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    let mut sidecar = OsString::from(path.as_os_str());
    sidecar.push(".sig.json");
    PathBuf::from(sidecar)
}

pub fn verify_config_signature(
    path: impl AsRef<Path>,
    raw: &[u8],
) -> Result<(), ConfigSignatureError> {
    let path = path.as_ref();
    let sidecar_path = config_signature_sidecar_path(path);
    let signed = read_config_signature_sidecar(&sidecar_path)?;
    let payload = canonical_json_bytes(&signed.statement).map_err(|source| {
        ConfigSignatureError::Canonicalize {
            path: sidecar_path.clone(),
            source,
        }
    })?;

    let trusted = active_config_signature_trust_roots()
        .into_iter()
        .any(|root| {
            signed.signature.key_id == root.key_id
                && signed.signature.public_key_hex == root.public_key_hex
        });
    if !trusted {
        return Err(ConfigSignatureError::UntrustedSigner { path: sidecar_path });
    }

    verify_detached_signature(&payload, &signed.signature).map_err(|source| {
        ConfigSignatureError::InvalidSignature {
            path: path.to_path_buf(),
            source,
        }
    })?;

    let expected_file_name = path
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .ok_or_else(|| ConfigSignatureError::SubjectMismatch {
            path: path.to_path_buf(),
            expected: "<file-name>".to_string(),
            actual: signed.statement.config_file_name.clone(),
        })?;
    if signed.statement.config_file_name != expected_file_name {
        return Err(ConfigSignatureError::SubjectMismatch {
            path: path.to_path_buf(),
            expected: expected_file_name,
            actual: signed.statement.config_file_name,
        });
    }

    let observed_sha256 = sha256_hex(raw);
    if signed.statement.sha256 != observed_sha256 {
        return Err(ConfigSignatureError::DigestMismatch {
            path: path.to_path_buf(),
            expected_sha256: signed.statement.sha256,
            observed_sha256,
        });
    }

    let observed_size_bytes = raw.len() as u64;
    if signed.statement.size_bytes != observed_size_bytes {
        return Err(ConfigSignatureError::SizeMismatch {
            path: path.to_path_buf(),
            expected_size_bytes: signed.statement.size_bytes,
            observed_size_bytes,
        });
    }

    Ok(())
}

#[cfg(debug_assertions)]
pub fn write_debug_test_config_signature(path: impl AsRef<Path>) -> Result<(), std::io::Error> {
    let path = path.as_ref();
    let raw = fs::read(path)?;
    let signer =
        swarm_crypto::Ed25519Signer::from_secret_material(DEBUG_TEST_CONFIG_SIGNING_SECRET);
    let statement = ConfigSignatureStatement {
        version: 1,
        issued_at_ms: 1_760_000_000_000,
        config_file_name: path
            .file_name()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| "config.yaml".to_string()),
        sha256: sha256_hex(&raw),
        size_bytes: raw.len() as u64,
    };
    let payload = canonical_json_bytes(&statement).map_err(std::io::Error::other)?;
    let signed = SignedConfigSignature {
        signature: signer.sign(&payload),
        statement,
    };
    fs::write(
        config_signature_sidecar_path(path),
        serde_json::to_vec_pretty(&signed).map_err(std::io::Error::other)?,
    )
}

fn read_verified_config_text(path: &Path) -> Result<String, RuntimeConfigError> {
    let raw = fs::read_to_string(path).map_err(|source| RuntimeConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    verify_config_signature(path, raw.as_bytes()).map_err(|source| {
        RuntimeConfigError::Signature {
            source_name: path.display().to_string(),
            source,
        }
    })?;
    Ok(raw)
}

fn read_config_signature_sidecar(
    path: &Path,
) -> Result<SignedConfigSignature, ConfigSignatureError> {
    let raw = fs::read_to_string(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            ConfigSignatureError::MissingSidecar {
                path: path.to_path_buf(),
            }
        } else {
            ConfigSignatureError::ReadSidecar {
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    serde_json::from_str(&raw).map_err(|source| ConfigSignatureError::ParseSidecar {
        path: path.to_path_buf(),
        source,
    })
}

fn active_config_signature_trust_roots() -> Vec<ConfigSignatureTrustRoot> {
    let mut roots = vec![ConfigSignatureTrustRoot::production()];
    #[cfg(debug_assertions)]
    roots.push(ConfigSignatureTrustRoot::debug_test());
    roots
}

/// Parse and validate a runtime config from raw YAML.
pub fn parse_config(
    yaml: &str,
    source_name: impl Into<String>,
) -> Result<SwarmConfig, RuntimeConfigError> {
    parse_config_with_base(yaml, source_name.into(), None)
}

fn parse_config_unresolved(
    yaml: &str,
    source_name: String,
) -> Result<SwarmConfig, RuntimeConfigError> {
    let mut raw: YamlValue =
        serde_yaml::from_str(yaml).map_err(|source| RuntimeConfigError::Parse {
            source_name: source_name.clone(),
            source,
        })?;
    if let Some(summary) =
        migrate_config_value(&mut raw).map_err(|source| RuntimeConfigError::Validation {
            source_name: source_name.clone(),
            source,
        })?
    {
        tracing::info!(
            module = module_path!(),
            source_name = %source_name,
            from_schema_version = summary.from_version,
            to_schema_version = summary.to_version,
            migration_steps = ?summary.steps,
            "applied runtime config migration (unresolved)"
        );
    }

    let config: SwarmConfig =
        serde_yaml::from_value(raw).map_err(|source| RuntimeConfigError::Parse {
            source_name: source_name.clone(),
            source,
        })?;

    // Validate structural constraints. Secret references remain as literal
    // strings (e.g., `@secret:edr-token`) which pass string validation.
    // The caller resolves secrets and validates again afterwards.
    config
        .validate()
        .map_err(|source| RuntimeConfigError::Validation {
            source_name: source_name.clone(),
            source,
        })?;
    validate_detector_profiles(&config.detection).map_err(|source| {
        RuntimeConfigError::DetectorProfile {
            source_name,
            source,
        }
    })?;

    Ok(config)
}

fn parse_config_with_base(
    yaml: &str,
    source_name: String,
    config_path: Option<&Path>,
) -> Result<SwarmConfig, RuntimeConfigError> {
    let mut raw: YamlValue =
        serde_yaml::from_str(yaml).map_err(|source| RuntimeConfigError::Parse {
            source_name: source_name.clone(),
            source,
        })?;
    if let Some(summary) =
        migrate_config_value(&mut raw).map_err(|source| RuntimeConfigError::Validation {
            source_name: source_name.clone(),
            source,
        })?
    {
        tracing::info!(
            module = module_path!(),
            source_name = %source_name,
            from_schema_version = summary.from_version,
            to_schema_version = summary.to_version,
            migration_steps = ?summary.steps,
            "applied runtime config migration"
        );
    }

    let mut config: SwarmConfig =
        serde_yaml::from_value(raw).map_err(|source| RuntimeConfigError::Parse {
            source_name: source_name.clone(),
            source,
        })?;

    config
        .validate()
        .map_err(|source| RuntimeConfigError::Validation {
            source_name: source_name.clone(),
            source,
        })?;
    config = resolve_outbound_secrets(config, config_path).map_err(|source| {
        RuntimeConfigError::Validation {
            source_name: source_name.clone(),
            source,
        }
    })?;
    config
        .validate()
        .map_err(|source| RuntimeConfigError::Validation {
            source_name: source_name.clone(),
            source,
        })?;
    validate_detector_profiles(&config.detection).map_err(|source| {
        RuntimeConfigError::DetectorProfile {
            source_name,
            source,
        }
    })?;

    Ok(config)
}

fn migrate_config_value(
    value: &mut YamlValue,
) -> Result<Option<ConfigMigrationSummary>, ConfigValidationError> {
    let Some(root) = value.as_mapping_mut() else {
        return Ok(None);
    };
    let version = root
        .get(YamlValue::from("schema_version"))
        .and_then(YamlValue::as_u64)
        .map(|version| version as u32)
        .unwrap_or(0);

    if version > CURRENT_SCHEMA_VERSION {
        return Err(ConfigValidationError::InvalidField {
            field: "schema_version",
            reason: format!(
                "config schema version {version} exceeds compiled maximum {CURRENT_SCHEMA_VERSION}"
            ),
        });
    }

    match version {
        CURRENT_SCHEMA_VERSION => Ok(None),
        0 => {
            root.insert(
                YamlValue::from("schema_version"),
                YamlValue::from(CURRENT_SCHEMA_VERSION as i64),
            );
            Ok(Some(ConfigMigrationSummary {
                from_version: 0,
                to_version: CURRENT_SCHEMA_VERSION,
                steps: vec![
                    "added explicit schema_version to legacy config",
                    "legacy runtime defaults now resolve through the compiled v1 schema",
                ],
            }))
        }
        other => Err(ConfigValidationError::InvalidField {
            field: "schema_version",
            reason: format!("config schema version {other} is not recognized"),
        }),
    }
}

pub fn resolve_outbound_secrets(
    mut config: SwarmConfig,
    config_path: Option<&Path>,
) -> Result<SwarmConfig, ConfigValidationError> {
    let provider = FileEnvSecretProvider::new(resolve_secret_dir_path(
        config.runtime.secret_dir.as_deref(),
        config_path,
    ));
    match &mut config.response_adapter {
        ResponseAdapterConfig::Sandbox => {}
        ResponseAdapterConfig::HttpEdr { config: response } => {
            if is_secret_reference(&response.auth_token) {
                response.auth_token = provider.resolve(&response.auth_token).map_err(|error| {
                    ConfigValidationError::InvalidField {
                        field: "response_adapter.auth_token",
                        reason: error.to_string(),
                    }
                })?;
            }
        }
        ResponseAdapterConfig::Webhook { config: response } => {
            if let Some(auth_token) = &response.auth_token
                && is_secret_reference(auth_token)
            {
                response.auth_token = Some(provider.resolve(auth_token).map_err(|error| {
                    ConfigValidationError::InvalidField {
                        field: "response_adapter.auth_token",
                        reason: error.to_string(),
                    }
                })?);
            }
        }
    }
    if let Some(siem) = &mut config.siem_forward {
        match siem {
            SiemForwardConfig::SplunkHec { auth_token, .. }
            | SiemForwardConfig::Chronicle { auth_token, .. } => {
                if is_secret_reference(auth_token) {
                    *auth_token = provider.resolve(auth_token).map_err(|error| {
                        ConfigValidationError::InvalidField {
                            field: "siem_forward.auth_token",
                            reason: error.to_string(),
                        }
                    })?;
                }
            }
            SiemForwardConfig::ElkBulk { auth_token, .. } => {
                if let Some(auth_token) = auth_token
                    && is_secret_reference(auth_token)
                {
                    *auth_token = provider.resolve(auth_token).map_err(|error| {
                        ConfigValidationError::InvalidField {
                            field: "siem_forward.auth_token",
                            reason: error.to_string(),
                        }
                    })?;
                }
            }
        }
    }
    for channel in config.notification_channels.values_mut() {
        if let Some(auth_token) = &channel.auth_token
            && is_secret_reference(auth_token)
        {
            channel.auth_token = Some(provider.resolve(auth_token).map_err(|error| {
                ConfigValidationError::InvalidField {
                    field: "notification_channels.auth_token",
                    reason: error.to_string(),
                }
            })?);
        }
        if let Some(signature) = &mut channel.request_signature
            && is_secret_reference(&signature.secret)
        {
            signature.secret = provider.resolve(&signature.secret).map_err(|error| {
                ConfigValidationError::InvalidField {
                    field: "notification_channels.request_signature.secret",
                    reason: error.to_string(),
                }
            })?;
        }
    }
    Ok(config)
}

fn is_secret_reference(value: &str) -> bool {
    value.starts_with("@secret:")
}

pub fn resolve_secret_dir_path(
    secret_dir: Option<&str>,
    config_path: Option<&Path>,
) -> Option<PathBuf> {
    let secret_dir = secret_dir?.trim();
    if secret_dir.is_empty() {
        return None;
    }
    let path = PathBuf::from(secret_dir);
    if path.is_absolute() {
        return Some(path);
    }
    let base = config_path
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."));
    Some(base.join(path))
}

pub(crate) fn suspicious_process_tree_profile(
    config: &DetectionConfig,
) -> Result<SuspiciousProcessTreeProfile, DetectorProfileError> {
    resolve_detector_profile(
        "suspicious_process_tree",
        SuspiciousProcessTreeProfile {
            high_confidence_threshold: config.high_confidence_threshold,
            medium_confidence_threshold: config.medium_confidence_threshold,
            ..SuspiciousProcessTreeProfile::default()
        },
        config.profiles.suspicious_process_tree.as_ref(),
        SuspiciousProcessTreeProfile::validate,
    )
}

pub(crate) fn kill_chain_sequence_profile(
    config: &DetectionConfig,
) -> Result<KillChainSequenceProfile, DetectorProfileError> {
    resolve_detector_profile(
        "kill_chain_sequence",
        KillChainSequenceProfile::default(),
        config.profiles.kill_chain_sequence.as_ref(),
        KillChainSequenceProfile::validate,
    )
}

pub(crate) fn fileless_execution_profile(
    config: &DetectionConfig,
) -> Result<FilelessExecutionProfile, DetectorProfileError> {
    resolve_detector_profile(
        "fileless_execution",
        FilelessExecutionProfile {
            high_confidence_threshold: config.high_confidence_threshold,
            medium_confidence_threshold: config.medium_confidence_threshold,
            ..FilelessExecutionProfile::default()
        },
        config.profiles.fileless_execution.as_ref(),
        FilelessExecutionProfile::validate,
    )
}

pub(crate) fn behavioral_anomaly_profile(
    config: &DetectionConfig,
) -> Result<BehavioralAnomalyProfile, DetectorProfileError> {
    resolve_detector_profile(
        "behavioral_anomaly",
        BehavioralAnomalyProfile {
            high_confidence_threshold: config.high_confidence_threshold,
            medium_confidence_threshold: config.medium_confidence_threshold,
            ..BehavioralAnomalyProfile::default()
        },
        config.profiles.behavioral_anomaly.as_ref(),
        BehavioralAnomalyProfile::validate,
    )
}

pub(crate) fn dns_exfiltration_profile(
    config: &DetectionConfig,
) -> Result<DnsExfiltrationProfile, DetectorProfileError> {
    resolve_detector_profile(
        "dns_exfiltration",
        DnsExfiltrationProfile {
            high_confidence_threshold: config.high_confidence_threshold,
            medium_confidence_threshold: config.medium_confidence_threshold,
            ..DnsExfiltrationProfile::default()
        },
        config.profiles.dns_exfiltration.as_ref(),
        DnsExfiltrationProfile::validate,
    )
}

pub(crate) fn lateral_movement_profile(
    config: &DetectionConfig,
) -> Result<LateralMovementProfile, DetectorProfileError> {
    resolve_detector_profile(
        "lateral_movement",
        LateralMovementProfile {
            high_confidence_threshold: config.high_confidence_threshold,
            medium_confidence_threshold: config.medium_confidence_threshold,
            ..LateralMovementProfile::default()
        },
        config.profiles.lateral_movement.as_ref(),
        LateralMovementProfile::validate,
    )
}

pub(crate) fn credential_access_profile(
    config: &DetectionConfig,
) -> Result<CredentialAccessProfile, DetectorProfileError> {
    resolve_detector_profile(
        "credential_access",
        CredentialAccessProfile {
            high_confidence_threshold: config.high_confidence_threshold,
            medium_confidence_threshold: config.medium_confidence_threshold,
            ..CredentialAccessProfile::default()
        },
        config.profiles.credential_access.as_ref(),
        CredentialAccessProfile::validate,
    )
}

pub(crate) fn suspicious_scripting_profile(
    config: &DetectionConfig,
) -> Result<SuspiciousScriptingProfile, DetectorProfileError> {
    resolve_detector_profile(
        "suspicious_scripting",
        SuspiciousScriptingProfile {
            high_confidence_threshold: config.high_confidence_threshold,
            medium_confidence_threshold: config.medium_confidence_threshold,
            ..SuspiciousScriptingProfile::default()
        },
        config.profiles.suspicious_scripting.as_ref(),
        SuspiciousScriptingProfile::validate,
    )
}

pub(crate) fn persistence_profile(
    config: &DetectionConfig,
) -> Result<PersistenceProfile, DetectorProfileError> {
    resolve_detector_profile(
        "persistence",
        PersistenceProfile {
            high_confidence_threshold: config.high_confidence_threshold,
            medium_confidence_threshold: config.medium_confidence_threshold,
            ..PersistenceProfile::default()
        },
        config.profiles.persistence.as_ref(),
        PersistenceProfile::validate,
    )
}

pub(crate) fn supply_chain_profile(
    config: &DetectionConfig,
) -> Result<SupplyChainProfile, DetectorProfileError> {
    resolve_detector_profile(
        "supply_chain",
        SupplyChainProfile {
            high_confidence_threshold: config.high_confidence_threshold,
            medium_confidence_threshold: config.medium_confidence_threshold,
            ..SupplyChainProfile::default()
        },
        config.profiles.supply_chain.as_ref(),
        SupplyChainProfile::validate,
    )
}

pub(crate) fn network_connect_profile(
    config: &DetectionConfig,
) -> Result<NetworkConnectProfile, DetectorProfileError> {
    resolve_detector_profile(
        "network_connect",
        NetworkConnectProfile {
            high_confidence_threshold: config.high_confidence_threshold,
            medium_confidence_threshold: config.medium_confidence_threshold,
            ..NetworkConnectProfile::default()
        },
        config.profiles.network_connect.as_ref(),
        NetworkConnectProfile::validate,
    )
}

pub(crate) fn infrastructure_anomaly_profile(
    config: &DetectionConfig,
) -> Result<InfrastructureAnomalyProfile, DetectorProfileError> {
    resolve_detector_profile(
        "infrastructure_anomaly",
        InfrastructureAnomalyProfile {
            high_confidence_threshold: config.high_confidence_threshold,
            medium_confidence_threshold: config.medium_confidence_threshold,
            ..InfrastructureAnomalyProfile::default()
        },
        config.profiles.infrastructure_anomaly.as_ref(),
        InfrastructureAnomalyProfile::validate,
    )
}

pub(crate) fn validate_detector_profiles(
    config: &DetectionConfig,
) -> Result<(), DetectorProfileError> {
    if config.profiles.suspicious_process_tree.is_some() {
        suspicious_process_tree_profile(config)?;
    }
    if config.profiles.kill_chain_sequence.is_some() {
        kill_chain_sequence_profile(config)?;
    }
    if config.profiles.fileless_execution.is_some() {
        fileless_execution_profile(config)?;
    }
    if config.profiles.behavioral_anomaly.is_some() {
        behavioral_anomaly_profile(config)?;
    }
    if config.profiles.dns_exfiltration.is_some() {
        dns_exfiltration_profile(config)?;
    }
    if config.profiles.lateral_movement.is_some() {
        lateral_movement_profile(config)?;
    }
    if config.profiles.credential_access.is_some() {
        credential_access_profile(config)?;
    }
    if config.profiles.suspicious_scripting.is_some() {
        suspicious_scripting_profile(config)?;
    }
    if config.profiles.persistence.is_some() {
        persistence_profile(config)?;
    }
    if config.profiles.supply_chain.is_some() {
        supply_chain_profile(config)?;
    }
    if config.profiles.network_connect.is_some() {
        network_connect_profile(config)?;
    }
    if config.profiles.infrastructure_anomaly.is_some() {
        infrastructure_anomaly_profile(config)?;
    }
    Ok(())
}

pub(crate) fn validate_all_detector_profiles(
    config: &DetectionConfig,
) -> Result<(), DetectorProfileError> {
    for strategy in config.active_strategies() {
        match strategy.as_str() {
            "suspicious_process_tree" => {
                suspicious_process_tree_profile(config)?;
            }
            "kill_chain_sequence" => {
                kill_chain_sequence_profile(config)?;
            }
            "fileless_execution" => {
                fileless_execution_profile(config)?;
            }
            "behavioral_anomaly" => {
                behavioral_anomaly_profile(config)?;
            }
            "dns_exfiltration" => {
                dns_exfiltration_profile(config)?;
            }
            "lateral_movement" => {
                lateral_movement_profile(config)?;
            }
            "credential_access" => {
                credential_access_profile(config)?;
            }
            "suspicious_scripting" => {
                suspicious_scripting_profile(config)?;
            }
            "persistence" => {
                persistence_profile(config)?;
            }
            "supply_chain" => {
                supply_chain_profile(config)?;
            }
            "network_connect" => {
                network_connect_profile(config)?;
            }
            "infrastructure_anomaly" => {
                infrastructure_anomaly_profile(config)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn resolve_detector_profile<T>(
    strategy: &'static str,
    base_profile: T,
    overrides: Option<&Value>,
    validate: impl Fn(&T) -> Result<(), ProfileValidationError>,
) -> Result<T, DetectorProfileError>
where
    T: Serialize + DeserializeOwned,
{
    let mut merged = serde_json::to_value(base_profile)
        .map_err(|source| DetectorProfileError::Parse { strategy, source })?;
    if let Some(overrides) = overrides {
        merge_json_value(&mut merged, overrides.clone());
    }
    let profile = serde_json::from_value(merged)
        .map_err(|source| DetectorProfileError::Parse { strategy, source })?;
    validate(&profile).map_err(|source| DetectorProfileError::Validation { strategy, source })?;
    Ok(profile)
}

fn merge_json_value(target: &mut Value, overlay: Value) {
    match (target, overlay) {
        (Value::Object(target), Value::Object(overlay)) => {
            for (key, value) in overlay {
                match target.get_mut(&key) {
                    Some(existing) => merge_json_value(existing, value),
                    None => {
                        target.insert(key, value);
                    }
                }
            }
        }
        (target, overlay) => *target = overlay,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        CURRENT_SCHEMA_VERSION, GenericJsonPayloadMappingConfig, RuntimeConfigError, RuntimeMode,
        TelemetryBridgeConfig, behavioral_anomaly_profile, fileless_execution_profile,
        infrastructure_anomaly_profile, load_config, network_connect_profile, parse_config,
        suspicious_process_tree_profile, write_debug_test_config_signature,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn loads_repository_ruleset() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rulesets/default.yaml");

        let config = load_config(path).unwrap();
        assert_eq!(config.runtime.mode, RuntimeMode::DetectOnly);
        assert_eq!(config.runtime.telemetry_sources.len(), 1);
        assert!(config.runtime.require_durable_live_response);
        assert_eq!(config.runtime.governance_degraded_tick_threshold, 3);
        assert!(config.canary.enabled);
        assert!(config.promotion.enabled);
    }

    #[test]
    fn unsigned_file_backed_config_is_rejected() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "swarm-runtime-config-unsigned-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let config_path = root.join("runtime.yaml");
        fs::write(
            &config_path,
            r#"
schema_version: 1
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
"#,
        )
        .unwrap();

        let error = load_config(&config_path).unwrap_err();
        assert!(matches!(
            error,
            RuntimeConfigError::Signature {
                source_name: _,
                source: _
            }
        ));
        assert!(
            error
                .to_string()
                .contains("missing config signature sidecar")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tampered_file_backed_config_is_rejected() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "swarm-runtime-config-tampered-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let config_path = root.join("runtime.yaml");
        fs::write(
            &config_path,
            r#"
schema_version: 1
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
"#,
        )
        .unwrap();
        write_debug_test_config_signature(&config_path).unwrap();
        fs::write(
            &config_path,
            r#"
schema_version: 1
name: test
description: tampered
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
"#,
        )
        .unwrap();

        let error = load_config(&config_path).unwrap_err();
        assert!(matches!(
            error,
            RuntimeConfigError::Signature {
                source_name: _,
                source: _
            }
        ));
        assert!(error.to_string().contains("config digest mismatch"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
  extra_field: nope
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
"#;

        let error = parse_config(yaml, "inline").unwrap_err();
        match error {
            RuntimeConfigError::Parse { source_name, .. } => assert_eq!(source_name, "inline"),
            other => panic!("expected parse error, got {other:?}"),
        }
    }

    #[test]
    fn invalid_runtime_mode_is_rejected() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: live_fire
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
"#;

        let error = parse_config(yaml, "inline").unwrap_err();
        match error {
            RuntimeConfigError::Parse { source_name, .. } => assert_eq!(source_name, "inline"),
            other => panic!("expected parse error, got {other:?}"),
        }
    }

    #[test]
    fn live_response_mode_is_supported() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: live_response
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
"#;

        let config = parse_config(yaml, "inline").unwrap();
        assert_eq!(config.runtime.mode, RuntimeMode::LiveResponse);
    }

    #[test]
    fn durable_live_response_requires_durable_backend() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: live_response
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
  require_durable_live_response: true
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
  backend:
    kind: in_memory
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
audit:
  bundle_store:
    kind: memory
  recent_decisions_limit: 20
"#;

        let error = parse_config(yaml, "inline").unwrap_err();
        match error {
            RuntimeConfigError::Validation { source_name, .. } => assert_eq!(source_name, "inline"),
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn invalid_canary_rate_is_rejected() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
canary:
  enabled: true
  slot_id: canary-primary
  observation_window_events: 2
  max_candidate_only_rate: 1.5
  max_baseline_miss_rate: 0.25
  max_detect_latency_us: 10000
  max_total_detections: 4
"#;

        let error = parse_config(yaml, "inline").unwrap_err();
        match error {
            RuntimeConfigError::Validation { source_name, .. } => assert_eq!(source_name, "inline"),
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn multi_strategy_canary_scope_parses_from_yaml() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  strategies:
    - suspicious_process_tree
    - dns_exfiltration
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
canary:
  enabled: true
  slot_id: canary-primary
  strategy_id: dns_exfiltration
  observation_window_events: 2
  max_candidate_only_rate: 0.25
  max_baseline_miss_rate: 0.25
  max_detect_latency_us: 10000
  max_total_detections: 4
promotion:
  enabled: true
  window_id: production-primary
  observation_window_events: 2
  max_promoted_only_rate: 0.2
  max_fallback_recovery_rate: 0.25
  max_detect_latency_us: 10000
  max_total_detections: 4
"#;

        let config = parse_config(yaml, "inline").unwrap();
        assert_eq!(config.detection.active_strategies().len(), 2);
        assert_eq!(
            config.canary.strategy_id.as_deref(),
            Some("dns_exfiltration")
        );
        assert_eq!(config.promotion.strategy_id, None);
    }

    #[test]
    fn multi_strategy_canary_without_scope_is_rejected() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  strategies:
    - suspicious_process_tree
    - dns_exfiltration
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
canary:
  enabled: true
  slot_id: canary-primary
  observation_window_events: 2
  max_candidate_only_rate: 0.25
  max_baseline_miss_rate: 0.25
  max_detect_latency_us: 10000
  max_total_detections: 4
"#;

        let error = parse_config(yaml, "inline").unwrap_err();
        match error {
            RuntimeConfigError::Validation { source_name, .. } => assert_eq!(source_name, "inline"),
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn invalid_promotion_rate_is_rejected() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
promotion:
  enabled: true
  window_id: production-primary
  observation_window_events: 2
  max_promoted_only_rate: 1.5
  max_fallback_recovery_rate: 0.25
  max_detect_latency_us: 10000
  max_total_detections: 4
"#;

        let error = parse_config(yaml, "inline").unwrap_err();
        match error {
            RuntimeConfigError::Validation { source_name, .. } => assert_eq!(source_name, "inline"),
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn operator_surface_allows_non_loopback_bind_address() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
operator_surface:
  enabled: true
  bind_addr: "0.0.0.0:7766"
  max_list_results: 50
  auth:
    operator_id: local-operator
    token_env: SWARM_OPERATOR_TOKEN
"#;

        let config = parse_config(yaml, "inline").unwrap();
        assert_eq!(config.operator.bind_addr, "0.0.0.0:7766");
    }

    #[test]
    fn operator_surface_requires_token_env_when_enabled() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
operator_surface:
  enabled: true
  bind_addr: "127.0.0.1:7766"
  max_list_results: 50
  auth:
    operator_id: local-operator
    token_env: ""
"#;

        let error = parse_config(yaml, "inline").unwrap_err();
        match error {
            RuntimeConfigError::Validation { source_name, .. } => assert_eq!(source_name, "inline"),
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn detector_profile_overrides_inherit_top_level_thresholds() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.95
  medium_confidence_threshold: 0.85
  profiles:
    suspicious_process_tree:
      suspicious_parents: ["python"]
      suspicious_children: ["curl"]
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
"#;

        let config = parse_config(yaml, "inline").unwrap();
        let profile = suspicious_process_tree_profile(&config.detection).unwrap();
        assert_eq!(profile.suspicious_parents, vec!["python".to_string()]);
        assert_eq!(profile.suspicious_children, vec!["curl".to_string()]);
        assert_eq!(profile.high_confidence_threshold, 0.95);
        assert_eq!(profile.medium_confidence_threshold, 0.85);
    }

    #[test]
    fn fileless_execution_profile_merges_overrides() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: fileless_execution
  high_confidence_threshold: 0.94
  medium_confidence_threshold: 0.76
  profiles:
    fileless_execution:
      min_region_size_bytes: 8192
      privileged_target_processes: ["lsass", "winlogon", "spoolsv"]
      executable_protection_flags: ["page_execute_readwrite", "rwx"]
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
"#;

        let config = parse_config(yaml, "inline").unwrap();
        let profile = fileless_execution_profile(&config.detection).unwrap();
        assert_eq!(profile.min_region_size_bytes, 8192);
        assert_eq!(
            profile.privileged_target_processes,
            vec![
                "lsass".to_string(),
                "winlogon".to_string(),
                "spoolsv".to_string()
            ]
        );
        assert_eq!(
            profile.executable_protection_flags,
            vec!["page_execute_readwrite".to_string(), "rwx".to_string()]
        );
        assert_eq!(profile.high_confidence_threshold, 0.94);
        assert_eq!(profile.medium_confidence_threshold, 0.76);
    }

    #[test]
    fn behavioral_anomaly_profile_merges_overrides() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: behavioral_anomaly
  high_confidence_threshold: 0.93
  medium_confidence_threshold: 0.74
  profiles:
    behavioral_anomaly:
      min_host_observations: 6
      min_identity_observations: 4
      min_peer_group_observations: 5
      min_feature_weight: 0.4
      baseline_half_life_secs: 7200
      distribution_min_observations: 3
      distribution_stddev_floor: 0.15
      high_confidence_z_score: 2.5
      rare_role_tools: ["powershell.exe", "wmic.exe"]
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
"#;

        let config = parse_config(yaml, "inline").unwrap();
        let profile = behavioral_anomaly_profile(&config.detection).unwrap();
        assert_eq!(profile.min_host_observations, 6);
        assert_eq!(profile.min_identity_observations, 4);
        assert_eq!(profile.min_peer_group_observations, 5);
        assert!((profile.min_feature_weight - 0.4).abs() < f64::EPSILON);
        assert!((profile.baseline_half_life_secs - 7200.0).abs() < f64::EPSILON);
        assert_eq!(profile.distribution_min_observations, 3);
        assert!((profile.distribution_stddev_floor - 0.15).abs() < f64::EPSILON);
        assert!((profile.high_confidence_z_score - 2.5).abs() < f64::EPSILON);
        assert_eq!(
            profile.rare_role_tools,
            vec!["powershell.exe".to_string(), "wmic.exe".to_string()]
        );
        assert_eq!(profile.high_confidence_threshold, 0.93);
        assert_eq!(profile.medium_confidence_threshold, 0.74);
    }

    #[test]
    fn network_connect_profile_merges_overrides() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: network_connect
  high_confidence_threshold: 0.92
  medium_confidence_threshold: 0.81
  profiles:
    suspicious_process_tree:
      suspicious_parents: ["python"]
      suspicious_children: ["curl"]
    network_connect:
      suspicious_ports: [8080, 8443]
      process_port_allowlist:
        curl: [443, 8443]
      beacon_min_sample_count: 5
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
"#;

        let config = parse_config(yaml, "inline").unwrap();
        let network_profile = network_connect_profile(&config.detection).unwrap();
        assert_eq!(network_profile.suspicious_ports, vec![8080, 8443]);
        assert_eq!(
            network_profile.process_port_allowlist.get("curl"),
            Some(&vec![443, 8443])
        );
        assert_eq!(network_profile.beacon_min_sample_count, 5);
        assert_eq!(network_profile.high_confidence_threshold, 0.92);
        assert_eq!(network_profile.medium_confidence_threshold, 0.81);

        let process_tree_profile = suspicious_process_tree_profile(&config.detection).unwrap();
        assert_eq!(
            process_tree_profile.suspicious_parents,
            vec!["python".to_string()]
        );
        assert_eq!(
            process_tree_profile.suspicious_children,
            vec!["curl".to_string()]
        );
        assert_eq!(process_tree_profile.high_confidence_threshold, 0.92);
        assert_eq!(process_tree_profile.medium_confidence_threshold, 0.81);
    }

    #[test]
    fn infrastructure_anomaly_profile_merges_overrides() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: infrastructure_anomaly
  high_confidence_threshold: 0.93
  medium_confidence_threshold: 0.74
  profiles:
    infrastructure_anomaly:
      correlation_window_secs: 300
      min_sustained_high_cpu_samples: 3
      cpu_sustained_percent: 93.0
      quiet_network_tx_bytes: 4096
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
"#;

        let config = parse_config(yaml, "inline").unwrap();
        let profile = infrastructure_anomaly_profile(&config.detection).unwrap();
        assert_eq!(profile.correlation_window_secs, 300);
        assert_eq!(profile.min_sustained_high_cpu_samples, 3);
        assert_eq!(profile.cpu_sustained_percent, 93.0);
        assert_eq!(profile.quiet_network_tx_bytes, 4096);
        assert_eq!(profile.high_confidence_threshold, 0.93);
        assert_eq!(profile.medium_confidence_threshold, 0.74);
    }

    #[test]
    fn invalid_detector_profile_payload_is_rejected() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
  profiles:
    suspicious_process_tree:
      unexpected_field: true
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
"#;

        let error = parse_config(yaml, "inline").unwrap_err();
        match error {
            RuntimeConfigError::DetectorProfile { source_name, .. } => {
                assert_eq!(source_name, "inline")
            }
            other => panic!("expected detector profile error, got {other:?}"),
        }
    }

    #[test]
    fn cloudtrail_bridge_source_deserializes_without_subject() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: cloudtrail-primary
      bridge:
        kind: cloud_trail
        path: fixtures/cloudtrail.jsonl
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
"#;

        let config = parse_config(yaml, "inline").unwrap();
        match config.runtime.telemetry_sources[0].bridge.as_ref() {
            Some(TelemetryBridgeConfig::CloudTrail { config }) => {
                assert_eq!(config.source.path, "fixtures/cloudtrail.jsonl");
            }
            other => panic!("expected cloudtrail bridge config, got {other:?}"),
        }
        assert!(config.runtime.telemetry_sources[0].subject.is_empty());
    }

    #[test]
    fn tetragon_bridge_source_deserializes_from_runtime_config() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: tetragon-primary
      bridge:
        kind: tetragon
        endpoint: http://127.0.0.1:54321
        reconnect_backoff_ms: 500
        max_reconnect_backoff_ms: 4000
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
"#;

        let config = parse_config(yaml, "inline").unwrap();
        match config.runtime.telemetry_sources[0].bridge.as_ref() {
            Some(TelemetryBridgeConfig::Tetragon { config }) => {
                assert_eq!(config.endpoint, "http://127.0.0.1:54321");
                assert_eq!(config.reconnect_backoff_ms, 500);
                assert_eq!(config.max_reconnect_backoff_ms, 4_000);
            }
            other => panic!("expected tetragon bridge config, got {other:?}"),
        }
        assert!(config.runtime.telemetry_sources[0].subject.is_empty());
    }

    #[test]
    fn generic_json_bridge_mapping_deserializes_from_runtime_config() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: generic-json-primary
      bridge:
        kind: generic_json
        path: fixtures/generic.jsonl
        mapping:
          event_id_path: "/meta/id"
          timestamp_path: "/meta/timestamp"
          host_id_path: "/meta/host"
          payload:
            kind: process_start
            parent_process_path: "/proc/parent"
            process_name_path: "/proc/name"
            command_line_path: "/proc/cmd"
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
"#;

        let config = parse_config(yaml, "inline").unwrap();
        match config.runtime.telemetry_sources[0].bridge.as_ref() {
            Some(TelemetryBridgeConfig::GenericJson { config }) => {
                assert_eq!(config.source.path, "fixtures/generic.jsonl");
                assert_eq!(config.mapping.event_id_path, "/meta/id");
                assert!(matches!(
                    config.mapping.payload,
                    GenericJsonPayloadMappingConfig::ProcessStart { .. }
                ));
            }
            other => panic!("expected generic json bridge config, got {other:?}"),
        }
    }

    #[test]
    fn sentinel_bridge_source_deserializes_without_subject() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: sentinel-primary
      bridge:
        kind: sentinel
        endpoint: http://127.0.0.1:9100/metrics
        scrape_interval_ms: 500
        scrape_timeout_ms: 250
        thermal_anomaly_threshold_celsius: 65.0
        memory_exhaustion_threshold_percent: 80.0
        disk_exhaustion_threshold_percent: 88.0
        max_consecutive_failures: 3
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
"#;

        let config = parse_config(yaml, "inline").unwrap();
        match config.runtime.telemetry_sources[0].bridge.as_ref() {
            Some(TelemetryBridgeConfig::Sentinel { config }) => {
                assert_eq!(config.endpoint, "http://127.0.0.1:9100/metrics");
                assert_eq!(config.scrape_interval_ms, 500);
                assert_eq!(config.scrape_timeout_ms, 250);
                assert_eq!(config.thermal_anomaly_threshold_celsius, 65.0);
                assert_eq!(config.memory_exhaustion_threshold_percent, 80.0);
                assert_eq!(config.disk_exhaustion_threshold_percent, 88.0);
                assert_eq!(config.max_consecutive_failures, 3);
            }
            other => panic!("expected sentinel bridge config, got {other:?}"),
        }
        assert!(config.runtime.telemetry_sources[0].subject.is_empty());
    }

    #[test]
    fn invalid_generic_json_pointer_is_rejected() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: generic-json-primary
      bridge:
        kind: generic_json
        path: fixtures/generic.jsonl
        mapping:
          event_id_path: "meta/id"
          timestamp_path: "/meta/timestamp"
          payload:
            kind: process_start
            parent_process_path: "/proc/parent"
            process_name_path: "/proc/name"
            command_line_path: "/proc/cmd"
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
"#;

        let error = parse_config(yaml, "inline").unwrap_err();
        match error {
            RuntimeConfigError::Validation { source_name, .. } => assert_eq!(source_name, "inline"),
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn legacy_config_without_schema_version_is_migrated() {
        let yaml = r#"
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
"#;

        let config = parse_config(yaml, "inline").unwrap();
        assert_eq!(config.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(config.runtime.drain_timeout_ms, 30_000);
        assert_eq!(config.runtime.max_heap_pressure, 0.90);
        assert_eq!(config.runtime.secret_dir, None);
    }

    #[test]
    fn future_schema_version_is_rejected() {
        let yaml = r#"
schema_version: 99
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
"#;

        let error = parse_config(yaml, "inline").unwrap_err();
        match error {
            RuntimeConfigError::Validation {
                source_name,
                source,
            } => {
                assert_eq!(source_name, "inline");
                assert!(
                    source.to_string().contains("exceeds compiled maximum"),
                    "unexpected error: {source}"
                );
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn secret_file_reference_is_resolved_relative_to_config_path() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "swarm-runtime-config-secret-file-{}-{unique}",
            std::process::id()
        ));
        let secret_dir = root.join("secrets");
        fs::create_dir_all(&secret_dir).unwrap();
        fs::write(secret_dir.join("edr-token"), "file-secret\n").unwrap();
        let config_path = root.join("runtime.yaml");
        let yaml = r#"
schema_version: 1
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
  secret_dir: secrets
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
response_adapter:
  kind: http_edr
  endpoint: http://127.0.0.1:9000/actions
  auth_token: "@secret:edr-token"
"#;
        fs::write(&config_path, yaml).unwrap();
        write_debug_test_config_signature(&config_path).unwrap();

        let config = load_config(&config_path).unwrap();
        match config.response_adapter {
            swarm_core::config::ResponseAdapterConfig::HttpEdr { config } => {
                assert_eq!(config.auth_token, "file-secret");
            }
            other => panic!("expected http edr config, got {other:?}"),
        }

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn secret_file_reference_rejects_path_traversal() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "swarm-runtime-config-secret-traversal-{}-{unique}",
            std::process::id()
        ));
        let secret_dir = root.join("secrets");
        fs::create_dir_all(&secret_dir).unwrap();
        fs::write(root.join("outside-token"), "outside-secret\n").unwrap();
        let config_path = root.join("runtime.yaml");
        let yaml = r#"
schema_version: 1
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
  secret_dir: secrets
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
response_adapter:
  kind: http_edr
  endpoint: http://127.0.0.1:9000/actions
  auth_token: "@secret:../outside-token"
"#;
        fs::write(&config_path, yaml).unwrap();
        write_debug_test_config_signature(&config_path).unwrap();

        let error = load_config(&config_path).unwrap_err();
        assert!(matches!(
            error,
            RuntimeConfigError::Validation {
                source_name: _,
                source: _
            }
        ));
        assert!(
            error
                .to_string()
                .contains("file secret name must not contain path traversal")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn secret_file_reference_rejects_absolute_paths() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "swarm-runtime-config-secret-absolute-{}-{unique}",
            std::process::id()
        ));
        let secret_dir = root.join("secrets");
        fs::create_dir_all(&secret_dir).unwrap();
        let absolute_secret = root.join("absolute-token");
        fs::write(&absolute_secret, "absolute-secret\n").unwrap();
        let config_path = root.join("runtime.yaml");
        let yaml = format!(
            r#"
schema_version: 1
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
  secret_dir: secrets
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
response_adapter:
  kind: http_edr
  endpoint: http://127.0.0.1:9000/actions
  auth_token: "@secret:{}"
"#,
            absolute_secret.display()
        );
        fs::write(&config_path, yaml).unwrap();
        write_debug_test_config_signature(&config_path).unwrap();

        let error = load_config(&config_path).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("file secret name must be relative to runtime.secret_dir")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_reference_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "swarm-runtime-config-secret-symlink-{}-{unique}",
            std::process::id()
        ));
        let secret_dir = root.join("secrets");
        fs::create_dir_all(&secret_dir).unwrap();
        let outside = root.join("outside-token");
        fs::write(&outside, "outside-secret\n").unwrap();
        symlink(&outside, secret_dir.join("edr-token")).unwrap();
        let config_path = root.join("runtime.yaml");
        let yaml = r#"
schema_version: 1
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
  secret_dir: secrets
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
response_adapter:
  kind: http_edr
  endpoint: http://127.0.0.1:9000/actions
  auth_token: "@secret:edr-token"
"#;
        fs::write(&config_path, yaml).unwrap();
        write_debug_test_config_signature(&config_path).unwrap();

        let error = load_config(&config_path).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("resolved secret path escapes runtime.secret_dir")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn webhook_env_secret_reference_is_resolved() {
        let env_var = format!(
            "SWARM_RUNTIME_WEBHOOK_SECRET_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let yaml = format!(
            r#"
schema_version: 1
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
response_adapter:
  kind: webhook
  url: http://127.0.0.1:9000/webhook
  auth_token: "@secret:env:{env_var}"
"#
        );
        unsafe {
            std::env::set_var(&env_var, "env-secret");
        }

        let config = parse_config(&yaml, "inline").unwrap();
        match config.response_adapter {
            swarm_core::config::ResponseAdapterConfig::Webhook { config } => {
                assert_eq!(config.auth_token.as_deref(), Some("env-secret"));
            }
            other => panic!("expected webhook config, got {other:?}"),
        }

        unsafe {
            std::env::remove_var(env_var);
        }
    }

    #[test]
    fn notification_request_signature_secret_reference_is_resolved() {
        let auth_env = format!(
            "SWARM_RUNTIME_PROVIDENCE_AUTH_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let hmac_env = format!(
            "SWARM_RUNTIME_PROVIDENCE_HMAC_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let yaml = format!(
            r#"
schema_version: 1
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
operator_surface:
  runtime_base_url: http://127.0.0.1:9090
  public_base_url: http://127.0.0.1:7766
notification_channels:
  providence_webhook:
    target_url: https://providence.example/incidents
    auth_token: "@secret:env:{auth_env}"
    request_signature:
      header: X-Swarm-Signature
      secret: "@secret:env:{hmac_env}"
    timeout_ms: 5000
    dead_letter_path: ./notification-providence.jsonl
"#
        );
        unsafe {
            std::env::set_var(&auth_env, "resolved-providence-bearer");
            std::env::set_var(&hmac_env, "resolved-providence-hmac");
        }

        let config = parse_config(&yaml, "inline").unwrap();
        let channel = config
            .notification_channels
            .get("providence_webhook")
            .unwrap();
        assert_eq!(
            channel.auth_token.as_deref(),
            Some("resolved-providence-bearer")
        );
        assert_eq!(
            channel
                .request_signature
                .as_ref()
                .map(|signature| signature.secret.as_str()),
            Some("resolved-providence-hmac")
        );

        unsafe {
            std::env::remove_var(auth_env);
            std::env::remove_var(hmac_env);
        }
    }
}
