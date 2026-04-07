use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use serde_yaml::Value as YamlValue;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use swarm_whisker::{
    CredentialAccessProfile, DnsExfiltrationProfile, LateralMovementProfile, PersistenceProfile,
    ProfileValidationError, SupplyChainProfile, SuspiciousProcessTreeProfile,
    SuspiciousScriptingProfile,
};

pub use swarm_core::config::{
    CanaryConfig, CircuitBreakerConfig, CloudTrailBridgeConfig, ConfigValidationError,
    CorrelationConfig, DetectionConfig, DetectorProfilesConfig, FieldMappingConfig,
    GenericJsonBridgeConfig, GenericJsonPayloadMappingConfig, HttpEdrConfig, InvestigationConfig,
    JsonFileSourceConfig, NotificationChannelConfig, NotificationRateLimitConfig,
    NotificationRoutingConfig, OperatorAuthConfig, OperatorSurfaceConfig, PheromoneConfig,
    PolicyConfig, PromotionConfig, ResponseAdapterConfig, RetryConfig, RoutingRule, RuntimeMode,
    RuntimeSettings, SiemForwardConfig, SwarmConfig, TelemetryBridgeConfig, TelemetrySourceConfig,
    TetragonBridgeConfig, WebhookConfig,
};

pub type RuntimeConfig = RuntimeSettings;
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

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
        let Some(secret_dir) = &self.secret_dir else {
            return Err(SecretResolutionError::InvalidReference {
                reference: format!("{PREFIX}{reference}"),
                reason: "runtime.secret_dir must be configured for file-backed secrets".to_string(),
            });
        };
        let path = secret_dir.join(secret_name);
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
}

/// Load a repository-owned runtime config file from disk.
pub fn load_config(path: impl AsRef<Path>) -> Result<SwarmConfig, RuntimeConfigError> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path).map_err(|source| RuntimeConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;

    parse_config_with_base(&raw, path.display().to_string(), Some(path))
}

/// Parse and validate a runtime config from raw YAML.
pub fn parse_config(
    yaml: &str,
    source_name: impl Into<String>,
) -> Result<SwarmConfig, RuntimeConfigError> {
    parse_config_with_base(yaml, source_name.into(), None)
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

pub(crate) fn validate_detector_profiles(
    config: &DetectionConfig,
) -> Result<(), DetectorProfileError> {
    if config.profiles.suspicious_process_tree.is_some() {
        suspicious_process_tree_profile(config)?;
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
        TelemetryBridgeConfig, load_config, parse_config, suspicious_process_tree_profile,
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
        assert!(config.canary.enabled);
        assert!(config.promotion.enabled);
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
    fn operator_surface_requires_loopback_bind_address() {
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

        let error = parse_config(yaml, "inline").unwrap_err();
        match error {
            RuntimeConfigError::Validation { source_name, .. } => assert_eq!(source_name, "inline"),
            other => panic!("expected validation error, got {other:?}"),
        }
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
}
