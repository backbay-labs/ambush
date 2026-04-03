//! Canonical v1 configuration types for the Rust-first runtime.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::types::Severity;

/// Top-level repository-owned configuration for the v1 Rust runtime slice.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmConfig {
    /// Human-readable configuration name.
    pub name: String,
    /// Human-readable configuration description.
    pub description: String,
    /// Runtime settings for the critical lane.
    pub runtime: RuntimeSettings,
    /// Detector tuning for the fast path.
    pub detection: DetectionConfig,
    /// Pheromone substrate tuning.
    pub pheromone: PheromoneConfig,
    /// Deterministic live-response policy settings.
    pub policy: PolicyConfig,
    /// Audit and replay storage settings.
    #[serde(default)]
    pub audit: AuditConfig,
}

/// Whether the runtime simulates or executes live response actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    DetectOnly,
    LiveResponse,
}

/// Runtime settings for the hot path.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSettings {
    /// Whether responses execute or remain dry-run.
    pub mode: RuntimeMode,
    /// Telemetry streams or subjects to subscribe to.
    pub telemetry_sources: Vec<TelemetrySourceConfig>,
    /// Maximum concurrent response executions.
    pub max_in_flight_actions: usize,
    /// Require a durable substrate before live response can start.
    #[serde(default)]
    pub require_durable_live_response: bool,
}

/// One configured telemetry source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySourceConfig {
    pub name: String,
    pub subject: String,
}

/// Detector-specific tuning for the first concrete strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionConfig {
    pub strategy: String,
    pub high_confidence_threshold: f64,
    pub medium_confidence_threshold: f64,
}

/// Pheromone substrate tuning.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PheromoneConfig {
    /// Default half-life for pheromone decay (seconds).
    pub default_half_life_secs: f64,
    /// Strength below which pheromones are considered evaporated.
    pub evaporation_threshold: f64,
    /// Minimum distinct sources for concentration escalation.
    pub min_sources_for_escalation: usize,
    /// Strength threshold for alert mode transition.
    pub alert_threshold: f64,
    /// Strength threshold for incident mode transition.
    pub incident_threshold: f64,
    /// Backend used to store and recover deposits.
    #[serde(default)]
    pub backend: PheromoneBackendConfig,
}

/// Pheromone substrate backend selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PheromoneBackendConfig {
    #[default]
    InMemory,
    LocalJournal {
        path: String,
    },
}

/// Deterministic policy settings for live response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Severity at or above which destructive actions require human approval.
    pub human_gate_severity: Severity,
    /// Capability lease lifetime.
    pub lease_ttl_ms: i64,
}

/// Audit persistence settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Store used for replay bundles and receipt lookup.
    #[serde(default)]
    pub bundle_store: BundleStoreConfig,
    /// How many recent decision records to surface to operators by default.
    #[serde(default = "default_recent_decisions_limit")]
    pub recent_decisions_limit: usize,
}

/// Replay bundle storage backend selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BundleStoreConfig {
    #[default]
    Memory,
    LocalFiles {
        directory: String,
    },
}

/// Semantic validation errors that survive after deserialization.
#[derive(Debug, thiserror::Error)]
pub enum ConfigValidationError {
    #[error("invalid field `{field}`: {reason}")]
    InvalidField { field: &'static str, reason: String },
}

impl SwarmConfig {
    /// Validate cross-field and semantic constraints after deserialization.
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.name.trim().is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "name",
                reason: "must not be empty".to_string(),
            });
        }

        if self.runtime.telemetry_sources.is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.telemetry_sources",
                reason: "at least one telemetry source is required".to_string(),
            });
        }

        if self.runtime.max_in_flight_actions == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.max_in_flight_actions",
                reason: "must be greater than zero".to_string(),
            });
        }

        let mut source_names = BTreeSet::new();
        for source in &self.runtime.telemetry_sources {
            if source.name.trim().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "runtime.telemetry_sources.name",
                    reason: "must not be empty".to_string(),
                });
            }
            if source.subject.trim().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "runtime.telemetry_sources.subject",
                    reason: "must not be empty".to_string(),
                });
            }
            if !source_names.insert(source.name.clone()) {
                return Err(ConfigValidationError::InvalidField {
                    field: "runtime.telemetry_sources.name",
                    reason: format!("duplicate telemetry source `{}`", source.name),
                });
            }
        }

        if self.detection.strategy.trim().is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "detection.strategy",
                reason: "must not be empty".to_string(),
            });
        }
        if !(0.0..=1.0).contains(&self.detection.medium_confidence_threshold) {
            return Err(ConfigValidationError::InvalidField {
                field: "detection.medium_confidence_threshold",
                reason: "must be between 0.0 and 1.0".to_string(),
            });
        }
        if !(0.0..=1.0).contains(&self.detection.high_confidence_threshold) {
            return Err(ConfigValidationError::InvalidField {
                field: "detection.high_confidence_threshold",
                reason: "must be between 0.0 and 1.0".to_string(),
            });
        }
        if self.detection.high_confidence_threshold < self.detection.medium_confidence_threshold {
            return Err(ConfigValidationError::InvalidField {
                field: "detection.high_confidence_threshold",
                reason: "must be greater than or equal to medium_confidence_threshold".to_string(),
            });
        }

        if self.pheromone.default_half_life_secs <= 0.0 {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.default_half_life_secs",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.pheromone.evaporation_threshold <= 0.0 {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.evaporation_threshold",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.pheromone.min_sources_for_escalation == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.min_sources_for_escalation",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.pheromone.alert_threshold <= 0.0 {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.alert_threshold",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.pheromone.incident_threshold < self.pheromone.alert_threshold {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.incident_threshold",
                reason: "must be greater than or equal to alert_threshold".to_string(),
            });
        }
        match &self.pheromone.backend {
            PheromoneBackendConfig::InMemory => {
                if self.runtime.mode == RuntimeMode::LiveResponse
                    && self.runtime.require_durable_live_response
                {
                    return Err(ConfigValidationError::InvalidField {
                        field: "runtime.require_durable_live_response",
                        reason: "requires a durable pheromone backend in live_response mode"
                            .to_string(),
                    });
                }
            }
            PheromoneBackendConfig::LocalJournal { path } => {
                if path.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "pheromone.backend.path",
                        reason: "must not be empty".to_string(),
                    });
                }
            }
        }

        if self.policy.lease_ttl_ms <= 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "policy.lease_ttl_ms",
                reason: "must be greater than zero".to_string(),
            });
        }

        if self.audit.recent_decisions_limit == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "audit.recent_decisions_limit",
                reason: "must be greater than zero".to_string(),
            });
        }
        match &self.audit.bundle_store {
            BundleStoreConfig::Memory => {}
            BundleStoreConfig::LocalFiles { directory } => {
                if directory.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "audit.bundle_store.directory",
                        reason: "must not be empty".to_string(),
                    });
                }
            }
        }

        Ok(())
    }
}

impl PheromoneBackendConfig {
    pub fn is_durable(&self) -> bool {
        matches!(self, Self::LocalJournal { .. })
    }
}

impl BundleStoreConfig {
    pub fn is_durable(&self) -> bool {
        matches!(self, Self::LocalFiles { .. })
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            bundle_store: BundleStoreConfig::default(),
            recent_decisions_limit: default_recent_decisions_limit(),
        }
    }
}

const fn default_recent_decisions_limit() -> usize {
    20
}
