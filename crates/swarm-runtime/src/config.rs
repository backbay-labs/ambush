use std::fs;
use std::path::{Path, PathBuf};

pub use swarm_core::config::{
    ConfigValidationError, DetectionConfig, InvestigationConfig, PheromoneConfig, PolicyConfig,
    RuntimeMode, RuntimeSettings, SwarmConfig, TelemetrySourceConfig,
};

pub type RuntimeConfig = RuntimeSettings;

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
}

/// Load a repository-owned runtime config file from disk.
pub fn load_config(path: impl AsRef<Path>) -> Result<SwarmConfig, RuntimeConfigError> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path).map_err(|source| RuntimeConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;

    parse_config(&raw, path.display().to_string())
}

/// Parse and validate a runtime config from raw YAML.
pub fn parse_config(
    yaml: &str,
    source_name: impl Into<String>,
) -> Result<SwarmConfig, RuntimeConfigError> {
    let source_name = source_name.into();
    let config: SwarmConfig =
        serde_yaml::from_str(yaml).map_err(|source| RuntimeConfigError::Parse {
            source_name: source_name.clone(),
            source,
        })?;

    config
        .validate()
        .map_err(|source| RuntimeConfigError::Validation {
            source_name,
            source,
        })?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::{RuntimeConfigError, RuntimeMode, load_config, parse_config};
    use std::path::PathBuf;

    #[test]
    fn loads_repository_ruleset() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rulesets/default.yaml");

        let config = load_config(path).unwrap();
        assert_eq!(config.runtime.mode, RuntimeMode::DetectOnly);
        assert_eq!(config.runtime.telemetry_sources.len(), 1);
        assert!(config.runtime.require_durable_live_response);
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
}
