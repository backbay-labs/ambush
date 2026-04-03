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
    /// Async investigation settings layered on top of the hot path.
    #[serde(default)]
    pub investigation: InvestigationConfig,
    /// Correlation settings for assembling reviewable incidents.
    #[serde(default)]
    pub correlation: CorrelationConfig,
    /// Bounded live canary settings for verified candidate detectors.
    #[serde(default)]
    pub canary: CanaryConfig,
    /// Controlled production-promotion settings for canary-approved detectors.
    #[serde(default)]
    pub promotion: PromotionConfig,
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

/// Async investigation settings that stay off the critical lane.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvestigationConfig {
    /// Whether the investigation queue is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Number of background workers allowed to process queued jobs concurrently.
    #[serde(default = "default_investigation_worker_count")]
    pub worker_count: usize,
    /// Maximum queued jobs buffered before new submissions degrade visibly.
    #[serde(default = "default_investigation_max_pending_jobs")]
    pub max_pending_jobs: usize,
    /// Maximum time budget for one investigation run.
    #[serde(default = "default_investigation_time_budget_ms")]
    pub time_budget_ms: u64,
    /// Store used for investigation bundles and lookup by stable identifiers.
    #[serde(default)]
    pub bundle_store: BundleStoreConfig,
}

/// Incident correlation settings layered on top of investigation bundles.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationConfig {
    /// Whether incident correlation is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Maximum age difference between investigations to be considered together.
    #[serde(default = "default_correlation_time_window_ms")]
    pub time_window_ms: i64,
    /// Minimum shared correlation keys required for inclusion.
    #[serde(default = "default_correlation_min_shared_keys")]
    pub min_shared_keys: usize,
    /// Maximum recent investigations to scan when assembling one incident.
    #[serde(default = "default_correlation_candidate_limit")]
    pub candidate_limit: usize,
    /// Store used for correlated incident artifacts.
    #[serde(default)]
    pub incident_store: BundleStoreConfig,
}

/// Bounded canary settings layered on top of verified candidate detectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryConfig {
    /// Whether the bounded canary lane is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Stable slot identifier for the active canary lane.
    #[serde(default = "default_canary_slot_id")]
    pub slot_id: String,
    /// Number of live events observed before a canary can complete normally.
    #[serde(default = "default_canary_observation_window_events")]
    pub observation_window_events: usize,
    /// Maximum allowed candidate-only detection rate across the canary window.
    #[serde(default = "default_canary_max_candidate_only_rate")]
    pub max_candidate_only_rate: f64,
    /// Maximum allowed rate of baseline detections that the candidate misses.
    #[serde(default = "default_canary_max_baseline_miss_rate")]
    pub max_baseline_miss_rate: f64,
    /// Maximum allowed candidate detect latency in microseconds.
    #[serde(default = "default_canary_max_detect_latency_us")]
    pub max_detect_latency_us: u64,
    /// Maximum allowed candidate detection volume across the canary window.
    #[serde(default = "default_canary_max_total_detections")]
    pub max_total_detections: usize,
}

/// Controlled production-promotion settings layered on top of completed canary runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionConfig {
    /// Whether the controlled production-promotion lane is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Stable window identifier for the active production observation window.
    #[serde(default = "default_promotion_window_id")]
    pub window_id: String,
    /// Number of live events observed before a promotion can complete normally.
    #[serde(default = "default_promotion_observation_window_events")]
    pub observation_window_events: usize,
    /// Maximum allowed promoted-only detection rate across the observation window.
    #[serde(default = "default_promotion_max_promoted_only_rate")]
    pub max_promoted_only_rate: f64,
    /// Maximum allowed rate of fallback detections that the promoted detector misses.
    #[serde(default = "default_promotion_max_fallback_recovery_rate")]
    pub max_fallback_recovery_rate: f64,
    /// Maximum allowed promoted detect latency in microseconds.
    #[serde(default = "default_promotion_max_detect_latency_us")]
    pub max_detect_latency_us: u64,
    /// Maximum allowed promoted detection volume across the observation window.
    #[serde(default = "default_promotion_max_total_detections")]
    pub max_total_detections: usize,
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

        if self.investigation.enabled {
            if self.investigation.worker_count == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "investigation.worker_count",
                    reason: "must be greater than zero when investigation is enabled".to_string(),
                });
            }
            if self.investigation.max_pending_jobs == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "investigation.max_pending_jobs",
                    reason: "must be greater than zero when investigation is enabled".to_string(),
                });
            }
            if self.investigation.time_budget_ms == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "investigation.time_budget_ms",
                    reason: "must be greater than zero when investigation is enabled".to_string(),
                });
            }
        }
        match &self.investigation.bundle_store {
            BundleStoreConfig::Memory => {}
            BundleStoreConfig::LocalFiles { directory } => {
                if directory.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "investigation.bundle_store.directory",
                        reason: "must not be empty".to_string(),
                    });
                }
            }
        }

        if self.correlation.enabled {
            if self.correlation.time_window_ms <= 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "correlation.time_window_ms",
                    reason: "must be greater than zero when correlation is enabled".to_string(),
                });
            }
            if self.correlation.min_shared_keys == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "correlation.min_shared_keys",
                    reason: "must be greater than zero when correlation is enabled".to_string(),
                });
            }
            if self.correlation.candidate_limit == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "correlation.candidate_limit",
                    reason: "must be greater than zero when correlation is enabled".to_string(),
                });
            }
        }
        match &self.correlation.incident_store {
            BundleStoreConfig::Memory => {}
            BundleStoreConfig::LocalFiles { directory } => {
                if directory.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "correlation.incident_store.directory",
                        reason: "must not be empty".to_string(),
                    });
                }
            }
        }

        if self.canary.enabled {
            if self.canary.slot_id.trim().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "canary.slot_id",
                    reason: "must not be empty when canary is enabled".to_string(),
                });
            }
            if self.canary.observation_window_events == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "canary.observation_window_events",
                    reason: "must be greater than zero when canary is enabled".to_string(),
                });
            }
            if !(0.0..=1.0).contains(&self.canary.max_candidate_only_rate) {
                return Err(ConfigValidationError::InvalidField {
                    field: "canary.max_candidate_only_rate",
                    reason: "must be between 0.0 and 1.0".to_string(),
                });
            }
            if !(0.0..=1.0).contains(&self.canary.max_baseline_miss_rate) {
                return Err(ConfigValidationError::InvalidField {
                    field: "canary.max_baseline_miss_rate",
                    reason: "must be between 0.0 and 1.0".to_string(),
                });
            }
            if self.canary.max_detect_latency_us == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "canary.max_detect_latency_us",
                    reason: "must be greater than zero when canary is enabled".to_string(),
                });
            }
            if self.canary.max_total_detections == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "canary.max_total_detections",
                    reason: "must be greater than zero when canary is enabled".to_string(),
                });
            }
        }

        if self.promotion.enabled {
            if self.promotion.window_id.trim().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "promotion.window_id",
                    reason: "must not be empty when promotion is enabled".to_string(),
                });
            }
            if self.promotion.observation_window_events == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "promotion.observation_window_events",
                    reason: "must be greater than zero when promotion is enabled".to_string(),
                });
            }
            if !(0.0..=1.0).contains(&self.promotion.max_promoted_only_rate) {
                return Err(ConfigValidationError::InvalidField {
                    field: "promotion.max_promoted_only_rate",
                    reason: "must be between 0.0 and 1.0".to_string(),
                });
            }
            if !(0.0..=1.0).contains(&self.promotion.max_fallback_recovery_rate) {
                return Err(ConfigValidationError::InvalidField {
                    field: "promotion.max_fallback_recovery_rate",
                    reason: "must be between 0.0 and 1.0".to_string(),
                });
            }
            if self.promotion.max_detect_latency_us == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "promotion.max_detect_latency_us",
                    reason: "must be greater than zero when promotion is enabled".to_string(),
                });
            }
            if self.promotion.max_total_detections == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "promotion.max_total_detections",
                    reason: "must be greater than zero when promotion is enabled".to_string(),
                });
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

impl Default for InvestigationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            worker_count: default_investigation_worker_count(),
            max_pending_jobs: default_investigation_max_pending_jobs(),
            time_budget_ms: default_investigation_time_budget_ms(),
            bundle_store: BundleStoreConfig::default(),
        }
    }
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            time_window_ms: default_correlation_time_window_ms(),
            min_shared_keys: default_correlation_min_shared_keys(),
            candidate_limit: default_correlation_candidate_limit(),
            incident_store: BundleStoreConfig::default(),
        }
    }
}

impl Default for CanaryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            slot_id: default_canary_slot_id(),
            observation_window_events: default_canary_observation_window_events(),
            max_candidate_only_rate: default_canary_max_candidate_only_rate(),
            max_baseline_miss_rate: default_canary_max_baseline_miss_rate(),
            max_detect_latency_us: default_canary_max_detect_latency_us(),
            max_total_detections: default_canary_max_total_detections(),
        }
    }
}

impl Default for PromotionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window_id: default_promotion_window_id(),
            observation_window_events: default_promotion_observation_window_events(),
            max_promoted_only_rate: default_promotion_max_promoted_only_rate(),
            max_fallback_recovery_rate: default_promotion_max_fallback_recovery_rate(),
            max_detect_latency_us: default_promotion_max_detect_latency_us(),
            max_total_detections: default_promotion_max_total_detections(),
        }
    }
}

const fn default_recent_decisions_limit() -> usize {
    20
}

const fn default_investigation_worker_count() -> usize {
    1
}

const fn default_investigation_max_pending_jobs() -> usize {
    16
}

const fn default_investigation_time_budget_ms() -> u64 {
    250
}

const fn default_correlation_time_window_ms() -> i64 {
    300_000
}

const fn default_correlation_min_shared_keys() -> usize {
    1
}

const fn default_correlation_candidate_limit() -> usize {
    32
}

fn default_canary_slot_id() -> String {
    "canary-primary".to_string()
}

const fn default_canary_observation_window_events() -> usize {
    3
}

const fn default_canary_max_candidate_only_rate() -> f64 {
    0.25
}

const fn default_canary_max_baseline_miss_rate() -> f64 {
    0.25
}

const fn default_canary_max_detect_latency_us() -> u64 {
    10_000
}

const fn default_canary_max_total_detections() -> usize {
    8
}

fn default_promotion_window_id() -> String {
    "production-primary".to_string()
}

const fn default_promotion_observation_window_events() -> usize {
    3
}

const fn default_promotion_max_promoted_only_rate() -> f64 {
    0.20
}

const fn default_promotion_max_fallback_recovery_rate() -> f64 {
    0.20
}

const fn default_promotion_max_detect_latency_us() -> u64 {
    10_000
}

const fn default_promotion_max_total_detections() -> usize {
    12
}
