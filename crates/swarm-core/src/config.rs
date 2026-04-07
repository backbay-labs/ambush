//! Canonical v1 configuration types for the Rust-first runtime.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

use crate::types::Severity;

/// Top-level repository-owned configuration for the v1 Rust runtime slice.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmConfig {
    /// Explicit schema version for the repository-owned config contract.
    pub schema_version: u32,
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
    /// Configured response adapter selection for real side effects.
    #[serde(default)]
    pub response_adapter: ResponseAdapterConfig,
    /// Optional finding forwarder for external SIEM/SOAR ingestion.
    #[serde(default)]
    pub siem_forward: Option<SiemForwardConfig>,
    /// Named notification channels for finding-based alert delivery.
    #[serde(default)]
    pub notification_channels: BTreeMap<String, NotificationChannelConfig>,
    /// Finding-routing rules applied to notification channel delivery.
    #[serde(default)]
    pub notification_routing: NotificationRoutingConfig,
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
    /// Local authenticated operator-surface settings.
    #[serde(default, rename = "operator_surface")]
    pub operator: OperatorSurfaceConfig,
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
    /// Maximum time to wait for accepted ingest work to drain during shutdown.
    #[serde(default = "default_drain_timeout_ms")]
    pub drain_timeout_ms: u64,
    /// Require a durable substrate before live response can start.
    #[serde(default)]
    pub require_durable_live_response: bool,
    /// Readiness threshold for process heap pressure.
    #[serde(default = "default_max_heap_pressure")]
    pub max_heap_pressure: f64,
    /// Optional directory holding mounted secret files used by `@secret:` references.
    #[serde(default)]
    pub secret_dir: Option<String>,
}

/// One configured telemetry source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySourceConfig {
    pub name: String,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub bridge: Option<TelemetryBridgeConfig>,
}

/// Bridge-backed telemetry source configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TelemetryBridgeConfig {
    Tetragon {
        #[serde(flatten)]
        config: Box<TetragonBridgeConfig>,
    },
    CloudTrail {
        #[serde(flatten)]
        config: Box<CloudTrailBridgeConfig>,
    },
    GenericJson {
        #[serde(flatten)]
        config: Box<GenericJsonBridgeConfig>,
    },
}

/// File-backed JSON record source used by JSON-oriented bridges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonFileSourceConfig {
    pub path: String,
}

/// Tetragon gRPC bridge configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TetragonBridgeConfig {
    pub endpoint: String,
    #[serde(default = "default_tetragon_reconnect_backoff_ms")]
    pub reconnect_backoff_ms: u64,
    #[serde(default = "default_tetragon_max_reconnect_backoff_ms")]
    pub max_reconnect_backoff_ms: u64,
}

/// CloudTrail bridge configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudTrailBridgeConfig {
    #[serde(flatten)]
    pub source: JsonFileSourceConfig,
}

/// Generic JSON bridge configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenericJsonBridgeConfig {
    #[serde(flatten)]
    pub source: JsonFileSourceConfig,
    pub mapping: FieldMappingConfig,
}

/// Config-driven field mapping for generic JSON bridge normalization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldMappingConfig {
    pub event_id_path: String,
    pub timestamp_path: String,
    #[serde(default)]
    pub host_id_path: Option<String>,
    pub payload: GenericJsonPayloadMappingConfig,
}

/// Configurable payload mappings supported by the generic JSON bridge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GenericJsonPayloadMappingConfig {
    ProcessStart {
        parent_process_path: String,
        process_name_path: String,
        command_line_path: String,
        #[serde(default)]
        user_path: Option<String>,
    },
    NetworkConnect {
        process_name_path: String,
        destination_ip_path: String,
        destination_port_path: String,
        protocol_path: String,
    },
    DnsQuery {
        query_name_path: String,
        query_type_path: String,
        #[serde(default)]
        source_ip_path: Option<String>,
        #[serde(default)]
        process_name_path: Option<String>,
        #[serde(default)]
        response_code_path: Option<String>,
    },
    RegistryAccess {
        process_name_path: String,
        registry_path_path: String,
        access_type_path: String,
        #[serde(default)]
        target_process_path: Option<String>,
    },
    AuthenticationEvent {
        auth_type_path: String,
        #[serde(default)]
        source_host_path: Option<String>,
        #[serde(default)]
        target_host_path: Option<String>,
        #[serde(default)]
        target_service_path: Option<String>,
        #[serde(default)]
        process_name_path: Option<String>,
        success_path: String,
        #[serde(default)]
        user_path: Option<String>,
    },
}

/// Detector-specific tuning for the first concrete strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionConfig {
    pub strategy: String,
    pub high_confidence_threshold: f64,
    pub medium_confidence_threshold: f64,
    #[serde(default)]
    pub profiles: DetectorProfilesConfig,
}

/// Optional raw detector profile configuration payloads keyed by strategy family.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectorProfilesConfig {
    pub suspicious_process_tree: Option<serde_json::Value>,
    pub dns_exfiltration: Option<serde_json::Value>,
    pub lateral_movement: Option<serde_json::Value>,
    pub credential_access: Option<serde_json::Value>,
    pub suspicious_scripting: Option<serde_json::Value>,
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
    JetStream {
        url: String,
        #[serde(default = "default_nats_connect_timeout_ms")]
        connect_timeout_ms: u64,
        #[serde(default = "default_jetstream_gc_page_size")]
        gc_page_size: usize,
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

/// Configuration for the HTTP EDR response adapter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpEdrConfig {
    /// Endpoint receiving block/isolate requests.
    pub endpoint: String,
    /// Bearer token used for outbound authentication.
    pub auth_token: String,
    /// Request timeout in milliseconds.
    #[serde(default = "default_response_adapter_timeout_ms")]
    pub timeout_ms: u64,
    /// Retry policy for transient outbound failures.
    #[serde(default)]
    pub retry: RetryConfig,
    /// Circuit breaker policy for repeated failures.
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    /// JSONL file capturing final failed actions for later inspection.
    #[serde(default = "default_dead_letter_path")]
    pub dead_letter_path: String,
}

/// Configuration for the generic webhook response adapter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    /// Webhook URL receiving escalation payloads.
    pub url: String,
    /// Request timeout in milliseconds.
    #[serde(default = "default_response_adapter_timeout_ms")]
    pub timeout_ms: u64,
    /// Optional channel hint for Slack-compatible receivers.
    #[serde(default)]
    pub channel: Option<String>,
    /// Optional bearer token used for outbound authentication.
    #[serde(default)]
    pub auth_token: Option<String>,
    /// Retry policy for transient outbound failures.
    #[serde(default)]
    pub retry: RetryConfig,
    /// Circuit breaker policy for repeated failures.
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    /// JSONL file capturing final failed actions for later inspection.
    #[serde(default = "default_dead_letter_path")]
    pub dead_letter_path: String,
}

/// Retry policy for resilient response adapters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryConfig {
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: u64,
    #[serde(default = "default_backoff_multiplier")]
    pub backoff_multiplier: f64,
}

/// Circuit-breaker policy for resilient response adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_circuit_breaker_threshold")]
    pub threshold: u32,
    #[serde(default = "default_circuit_breaker_cooldown_ms")]
    pub cooldown_ms: u64,
}

/// Configured response adapter selection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResponseAdapterConfig {
    #[default]
    Sandbox,
    HttpEdr {
        #[serde(flatten)]
        config: HttpEdrConfig,
    },
    Webhook {
        #[serde(flatten)]
        config: WebhookConfig,
    },
}

/// Optional SIEM finding forwarder selection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SiemForwardConfig {
    SplunkHec {
        endpoint: String,
        auth_token: String,
        #[serde(default = "default_response_adapter_timeout_ms")]
        timeout_ms: u64,
        #[serde(default)]
        retry: RetryConfig,
        #[serde(default)]
        circuit_breaker: CircuitBreakerConfig,
        #[serde(default = "default_siem_dead_letter_path")]
        dead_letter_path: String,
    },
    ElkBulk {
        endpoint: String,
        #[serde(default)]
        auth_token: Option<String>,
        #[serde(default = "default_elk_index")]
        index: String,
        #[serde(default = "default_response_adapter_timeout_ms")]
        timeout_ms: u64,
        #[serde(default)]
        retry: RetryConfig,
        #[serde(default)]
        circuit_breaker: CircuitBreakerConfig,
        #[serde(default = "default_siem_dead_letter_path")]
        dead_letter_path: String,
    },
    Chronicle {
        endpoint: String,
        auth_token: String,
        #[serde(default)]
        customer_id: Option<String>,
        #[serde(default = "default_response_adapter_timeout_ms")]
        timeout_ms: u64,
        #[serde(default)]
        retry: RetryConfig,
        #[serde(default)]
        circuit_breaker: CircuitBreakerConfig,
        #[serde(default = "default_siem_dead_letter_path")]
        dead_letter_path: String,
    },
}

/// One named outbound notification target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationChannelConfig {
    pub target_url: String,
    #[serde(default)]
    pub auth_token: Option<String>,
    #[serde(default = "default_response_adapter_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub rate_limit: NotificationRateLimitConfig,
    #[serde(default)]
    pub quiet_hours: Option<QuietHoursConfig>,
    #[serde(default = "default_notification_dead_letter_path")]
    pub dead_letter_path: String,
}

/// In-memory rate limiting for one notification channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationRateLimitConfig {
    #[serde(default = "default_notification_rate_limit_max_notifications")]
    pub max_notifications: usize,
    #[serde(default = "default_notification_rate_limit_window_ms")]
    pub window_ms: u64,
}

/// Optional UTC quiet-hours window for one notification channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuietHoursConfig {
    pub start_hour_utc: u8,
    pub end_hour_utc: u8,
}

/// Repo-owned routing DSL for finding-based notification delivery.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationRoutingConfig {
    #[serde(default = "default_notification_dedup_window_ms")]
    pub dedup_window_ms: u64,
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
}

/// One rule matching findings onto named notification channels.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingRule {
    #[serde(default)]
    pub min_severity: Option<Severity>,
    #[serde(default)]
    pub threat_class: Option<crate::pheromone::ThreatClass>,
    #[serde(default)]
    pub utc_start_hour: Option<u8>,
    #[serde(default)]
    pub utc_end_hour: Option<u8>,
    pub channels: Vec<String>,
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

/// Local authenticated operator-surface settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorSurfaceConfig {
    /// Whether the local HTTP operator surface is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Local socket address the surface listens on.
    #[serde(default = "default_operator_bind_addr")]
    pub bind_addr: String,
    /// Maximum records returned from list endpoints.
    #[serde(default = "default_operator_max_list_results")]
    pub max_list_results: usize,
    /// Bearer-token auth configuration for the local surface.
    #[serde(default)]
    pub auth: OperatorAuthConfig,
}

/// Authentication settings for the local operator surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorAuthConfig {
    /// Logical operator principal attached to authenticated requests.
    #[serde(default = "default_operator_id")]
    pub operator_id: String,
    /// Environment variable name that carries the bearer token.
    #[serde(default = "default_operator_token_env")]
    pub token_env: String,
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

impl TelemetryBridgeConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        match self {
            Self::Tetragon { config } => config.validate(),
            Self::CloudTrail { config } => config.validate(),
            Self::GenericJson { config } => config.validate(),
        }
    }
}

impl JsonFileSourceConfig {
    fn validate(&self, field: &'static str) -> Result<(), ConfigValidationError> {
        if self.path.trim().is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field,
                reason: "must not be empty".to_string(),
            });
        }
        Ok(())
    }
}

impl TetragonBridgeConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.endpoint.trim().is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.telemetry_sources.bridge.endpoint",
                reason: "must not be empty".to_string(),
            });
        }
        if self.reconnect_backoff_ms == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.telemetry_sources.bridge.reconnect_backoff_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.max_reconnect_backoff_ms < self.reconnect_backoff_ms {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.telemetry_sources.bridge.max_reconnect_backoff_ms",
                reason: "must be greater than or equal to reconnect_backoff_ms".to_string(),
            });
        }
        Ok(())
    }
}

impl CloudTrailBridgeConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        self.source
            .validate("runtime.telemetry_sources.bridge.path")
    }
}

impl GenericJsonBridgeConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        self.source
            .validate("runtime.telemetry_sources.bridge.path")?;
        self.mapping.validate()
    }
}

impl FieldMappingConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        validate_json_pointer(
            "runtime.telemetry_sources.bridge.mapping.event_id_path",
            &self.event_id_path,
        )?;
        validate_json_pointer(
            "runtime.telemetry_sources.bridge.mapping.timestamp_path",
            &self.timestamp_path,
        )?;
        if let Some(path) = &self.host_id_path {
            validate_json_pointer(
                "runtime.telemetry_sources.bridge.mapping.host_id_path",
                path,
            )?;
        }
        self.payload.validate()
    }
}

impl GenericJsonPayloadMappingConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        match self {
            Self::ProcessStart {
                parent_process_path,
                process_name_path,
                command_line_path,
                user_path,
            } => {
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.parent_process_path",
                    parent_process_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.process_name_path",
                    process_name_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.command_line_path",
                    command_line_path,
                )?;
                if let Some(path) = user_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.user_path",
                        path,
                    )?;
                }
            }
            Self::NetworkConnect {
                process_name_path,
                destination_ip_path,
                destination_port_path,
                protocol_path,
            } => {
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.process_name_path",
                    process_name_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.destination_ip_path",
                    destination_ip_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.destination_port_path",
                    destination_port_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.protocol_path",
                    protocol_path,
                )?;
            }
            Self::DnsQuery {
                query_name_path,
                query_type_path,
                source_ip_path,
                process_name_path,
                response_code_path,
            } => {
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.query_name_path",
                    query_name_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.query_type_path",
                    query_type_path,
                )?;
                if let Some(path) = source_ip_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.source_ip_path",
                        path,
                    )?;
                }
                if let Some(path) = process_name_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.process_name_path",
                        path,
                    )?;
                }
                if let Some(path) = response_code_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.response_code_path",
                        path,
                    )?;
                }
            }
            Self::RegistryAccess {
                process_name_path,
                registry_path_path,
                access_type_path,
                target_process_path,
            } => {
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.process_name_path",
                    process_name_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.registry_path_path",
                    registry_path_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.access_type_path",
                    access_type_path,
                )?;
                if let Some(path) = target_process_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.target_process_path",
                        path,
                    )?;
                }
            }
            Self::AuthenticationEvent {
                auth_type_path,
                source_host_path,
                target_host_path,
                target_service_path,
                process_name_path,
                success_path,
                user_path,
            } => {
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.auth_type_path",
                    auth_type_path,
                )?;
                if let Some(path) = source_host_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.source_host_path",
                        path,
                    )?;
                }
                if let Some(path) = target_host_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.target_host_path",
                        path,
                    )?;
                }
                if let Some(path) = target_service_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.target_service_path",
                        path,
                    )?;
                }
                if let Some(path) = process_name_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.process_name_path",
                        path,
                    )?;
                }
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.success_path",
                    success_path,
                )?;
                if let Some(path) = user_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.user_path",
                        path,
                    )?;
                }
            }
        }

        Ok(())
    }
}

fn validate_json_pointer(field: &'static str, pointer: &str) -> Result<(), ConfigValidationError> {
    if pointer.trim().is_empty() {
        return Err(ConfigValidationError::InvalidField {
            field,
            reason: "must not be empty".to_string(),
        });
    }
    if !pointer.starts_with('/') {
        return Err(ConfigValidationError::InvalidField {
            field,
            reason: "must be a JSON Pointer starting with `/`".to_string(),
        });
    }
    Ok(())
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

        if self.schema_version == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "schema_version",
                reason: "must be greater than zero".to_string(),
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
        if self.runtime.drain_timeout_ms == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.drain_timeout_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        if !(0.0..=1.0).contains(&self.runtime.max_heap_pressure)
            || self.runtime.max_heap_pressure == 0.0
        {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.max_heap_pressure",
                reason: "must be greater than 0.0 and less than or equal to 1.0".to_string(),
            });
        }
        if let Some(secret_dir) = &self.runtime.secret_dir
            && secret_dir.trim().is_empty()
        {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.secret_dir",
                reason: "must not be empty when provided".to_string(),
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
            if source.subject.trim().is_empty() && source.bridge.is_none() {
                return Err(ConfigValidationError::InvalidField {
                    field: "runtime.telemetry_sources.subject",
                    reason: "must not be empty when bridge is absent".to_string(),
                });
            }
            if let Some(bridge) = &source.bridge {
                bridge.validate()?;
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
            PheromoneBackendConfig::JetStream {
                url,
                connect_timeout_ms,
                gc_page_size,
            } => {
                if url.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "pheromone.backend.url",
                        reason: "must not be empty".to_string(),
                    });
                }
                if *connect_timeout_ms == 0 {
                    return Err(ConfigValidationError::InvalidField {
                        field: "pheromone.backend.connect_timeout_ms",
                        reason: "must be greater than zero".to_string(),
                    });
                }
                if *gc_page_size == 0 {
                    return Err(ConfigValidationError::InvalidField {
                        field: "pheromone.backend.gc_page_size",
                        reason: "must be greater than zero".to_string(),
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

        self.response_adapter.validate()?;
        if let Some(config) = &self.siem_forward {
            config.validate()?;
        }
        for (channel_name, channel) in &self.notification_channels {
            if channel_name.trim().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "notification_channels",
                    reason: "channel names must not be empty".to_string(),
                });
            }
            channel.validate()?;
        }
        self.notification_routing
            .validate(&self.notification_channels)?;

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

        if self.operator.enabled {
            if self.operator.max_list_results == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.max_list_results",
                    reason: "must be greater than zero when operator surface is enabled"
                        .to_string(),
                });
            }

            if self.operator.auth.operator_id.trim().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.auth.operator_id",
                    reason: "must not be empty when operator surface is enabled".to_string(),
                });
            }

            if self.operator.auth.token_env.trim().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.auth.token_env",
                    reason: "must not be empty when operator surface is enabled".to_string(),
                });
            }

            let bind_addr: SocketAddr = self.operator.bind_addr.parse().map_err(|_| {
                ConfigValidationError::InvalidField {
                    field: "operator_surface.bind_addr",
                    reason: "must be a valid socket address".to_string(),
                }
            })?;
            if !bind_addr.ip().is_loopback() {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.bind_addr",
                    reason: "must bind to a loopback address".to_string(),
                });
            }
        }

        Ok(())
    }
}

impl PheromoneBackendConfig {
    pub fn is_durable(&self) -> bool {
        matches!(self, Self::LocalJournal { .. } | Self::JetStream { .. })
    }
}

impl BundleStoreConfig {
    pub fn is_durable(&self) -> bool {
        matches!(self, Self::LocalFiles { .. })
    }
}

impl ResponseAdapterConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        match self {
            Self::Sandbox => Ok(()),
            Self::HttpEdr { config } => {
                if config.endpoint.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "response_adapter.endpoint",
                        reason: "must not be empty".to_string(),
                    });
                }
                if config.auth_token.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "response_adapter.auth_token",
                        reason: "must not be empty".to_string(),
                    });
                }
                if config.timeout_ms == 0 {
                    return Err(ConfigValidationError::InvalidField {
                        field: "response_adapter.timeout_ms",
                        reason: "must be greater than zero".to_string(),
                    });
                }
                validate_retry_config("response_adapter.retry", &config.retry)?;
                validate_circuit_breaker_config(
                    "response_adapter.circuit_breaker",
                    &config.circuit_breaker,
                )?;
                if config.dead_letter_path.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "response_adapter.dead_letter_path",
                        reason: "must not be empty".to_string(),
                    });
                }
                Ok(())
            }
            Self::Webhook { config } => {
                if config.url.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "response_adapter.url",
                        reason: "must not be empty".to_string(),
                    });
                }
                if let Some(auth_token) = &config.auth_token
                    && auth_token.trim().is_empty()
                {
                    return Err(ConfigValidationError::InvalidField {
                        field: "response_adapter.auth_token",
                        reason: "must not be empty when provided".to_string(),
                    });
                }
                if config.timeout_ms == 0 {
                    return Err(ConfigValidationError::InvalidField {
                        field: "response_adapter.timeout_ms",
                        reason: "must be greater than zero".to_string(),
                    });
                }
                validate_retry_config("response_adapter.retry", &config.retry)?;
                validate_circuit_breaker_config(
                    "response_adapter.circuit_breaker",
                    &config.circuit_breaker,
                )?;
                if config.dead_letter_path.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "response_adapter.dead_letter_path",
                        reason: "must not be empty".to_string(),
                    });
                }
                Ok(())
            }
        }
    }
}

impl SiemForwardConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        match self {
            Self::SplunkHec {
                endpoint,
                auth_token,
                timeout_ms,
                retry,
                circuit_breaker,
                dead_letter_path,
            } => {
                validate_non_empty("siem_forward.endpoint", endpoint)?;
                validate_non_empty("siem_forward.auth_token", auth_token)?;
                validate_timeout("siem_forward.timeout_ms", *timeout_ms)?;
                validate_retry_config("siem_forward.retry", retry)?;
                validate_circuit_breaker_config("siem_forward.circuit_breaker", circuit_breaker)?;
                validate_non_empty("siem_forward.dead_letter_path", dead_letter_path)
            }
            Self::ElkBulk {
                endpoint,
                auth_token,
                index,
                timeout_ms,
                retry,
                circuit_breaker,
                dead_letter_path,
            } => {
                validate_non_empty("siem_forward.endpoint", endpoint)?;
                if let Some(auth_token) = auth_token {
                    validate_non_empty("siem_forward.auth_token", auth_token)?;
                }
                validate_non_empty("siem_forward.index", index)?;
                validate_timeout("siem_forward.timeout_ms", *timeout_ms)?;
                validate_retry_config("siem_forward.retry", retry)?;
                validate_circuit_breaker_config("siem_forward.circuit_breaker", circuit_breaker)?;
                validate_non_empty("siem_forward.dead_letter_path", dead_letter_path)
            }
            Self::Chronicle {
                endpoint,
                auth_token,
                customer_id,
                timeout_ms,
                retry,
                circuit_breaker,
                dead_letter_path,
            } => {
                validate_non_empty("siem_forward.endpoint", endpoint)?;
                validate_non_empty("siem_forward.auth_token", auth_token)?;
                if let Some(customer_id) = customer_id {
                    validate_non_empty("siem_forward.customer_id", customer_id)?;
                }
                validate_timeout("siem_forward.timeout_ms", *timeout_ms)?;
                validate_retry_config("siem_forward.retry", retry)?;
                validate_circuit_breaker_config("siem_forward.circuit_breaker", circuit_breaker)?;
                validate_non_empty("siem_forward.dead_letter_path", dead_letter_path)
            }
        }
    }
}

impl NotificationChannelConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        validate_non_empty("notification_channels.target_url", &self.target_url)?;
        if let Some(auth_token) = &self.auth_token {
            validate_non_empty("notification_channels.auth_token", auth_token)?;
        }
        validate_timeout("notification_channels.timeout_ms", self.timeout_ms)?;
        self.rate_limit.validate()?;
        if let Some(quiet_hours) = &self.quiet_hours {
            quiet_hours.validate()?;
        }
        validate_non_empty(
            "notification_channels.dead_letter_path",
            &self.dead_letter_path,
        )
    }
}

impl NotificationRateLimitConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.max_notifications == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_channels.rate_limit.max_notifications",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.window_ms == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_channels.rate_limit.window_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        Ok(())
    }
}

impl QuietHoursConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.start_hour_utc > 23 {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_channels.quiet_hours.start_hour_utc",
                reason: "must be between 0 and 23".to_string(),
            });
        }
        if self.end_hour_utc > 23 {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_channels.quiet_hours.end_hour_utc",
                reason: "must be between 0 and 23".to_string(),
            });
        }
        if self.start_hour_utc == self.end_hour_utc {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_channels.quiet_hours",
                reason: "start and end hour must differ".to_string(),
            });
        }
        Ok(())
    }
}

impl NotificationRoutingConfig {
    fn validate(
        &self,
        channels: &BTreeMap<String, NotificationChannelConfig>,
    ) -> Result<(), ConfigValidationError> {
        if self.dedup_window_ms == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_routing.dedup_window_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        for rule in &self.rules {
            rule.validate(channels)?;
        }
        Ok(())
    }
}

impl RoutingRule {
    fn validate(
        &self,
        channels: &BTreeMap<String, NotificationChannelConfig>,
    ) -> Result<(), ConfigValidationError> {
        if self.channels.is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_routing.rules.channels",
                reason: "must contain at least one channel".to_string(),
            });
        }
        for channel in &self.channels {
            if channel.trim().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "notification_routing.rules.channels",
                    reason: "channel names must not be empty".to_string(),
                });
            }
            if !channels.contains_key(channel) {
                return Err(ConfigValidationError::InvalidField {
                    field: "notification_routing.rules.channels",
                    reason: format!("references unknown channel `{channel}`"),
                });
            }
        }
        if let Some(start) = self.utc_start_hour
            && start > 23
        {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_routing.rules.utc_start_hour",
                reason: "must be between 0 and 23".to_string(),
            });
        }
        if let Some(end) = self.utc_end_hour
            && end > 23
        {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_routing.rules.utc_end_hour",
                reason: "must be between 0 and 23".to_string(),
            });
        }
        if self.utc_start_hour.is_some() != self.utc_end_hour.is_some() {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_routing.rules",
                reason: "utc_start_hour and utc_end_hour must be provided together".to_string(),
            });
        }
        if self.utc_start_hour == self.utc_end_hour && self.utc_start_hour.is_some() {
            return Err(ConfigValidationError::InvalidField {
                field: "notification_routing.rules",
                reason: "utc_start_hour and utc_end_hour must differ".to_string(),
            });
        }
        Ok(())
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            initial_backoff_ms: default_initial_backoff_ms(),
            backoff_multiplier: default_backoff_multiplier(),
        }
    }
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            threshold: default_circuit_breaker_threshold(),
            cooldown_ms: default_circuit_breaker_cooldown_ms(),
        }
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

impl Default for OperatorSurfaceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_addr: default_operator_bind_addr(),
            max_list_results: default_operator_max_list_results(),
            auth: OperatorAuthConfig::default(),
        }
    }
}

impl Default for OperatorAuthConfig {
    fn default() -> Self {
        Self {
            operator_id: default_operator_id(),
            token_env: default_operator_token_env(),
        }
    }
}

impl Default for NotificationRateLimitConfig {
    fn default() -> Self {
        Self {
            max_notifications: default_notification_rate_limit_max_notifications(),
            window_ms: default_notification_rate_limit_window_ms(),
        }
    }
}

impl Default for NotificationRoutingConfig {
    fn default() -> Self {
        Self {
            dedup_window_ms: default_notification_dedup_window_ms(),
            rules: Vec::new(),
        }
    }
}

const fn default_recent_decisions_limit() -> usize {
    20
}

const fn default_drain_timeout_ms() -> u64 {
    30_000
}

const fn default_max_heap_pressure() -> f64 {
    0.90
}

const fn default_investigation_worker_count() -> usize {
    1
}

const fn default_response_adapter_timeout_ms() -> u64 {
    5_000
}

const fn default_max_retries() -> u32 {
    3
}

const fn default_initial_backoff_ms() -> u64 {
    200
}

const fn default_backoff_multiplier() -> f64 {
    2.0
}

const fn default_circuit_breaker_threshold() -> u32 {
    5
}

const fn default_circuit_breaker_cooldown_ms() -> u64 {
    30_000
}

fn default_dead_letter_path() -> String {
    "./dead-letter.jsonl".to_string()
}

fn default_siem_dead_letter_path() -> String {
    "./siem-dead-letter.jsonl".to_string()
}

fn default_notification_dead_letter_path() -> String {
    "./notification-dead-letter.jsonl".to_string()
}

fn default_elk_index() -> String {
    "swarm-findings".to_string()
}

const fn default_notification_rate_limit_max_notifications() -> usize {
    10
}

const fn default_notification_rate_limit_window_ms() -> u64 {
    60_000
}

const fn default_notification_dedup_window_ms() -> u64 {
    30_000
}

const fn default_nats_connect_timeout_ms() -> u64 {
    5_000
}

const fn default_tetragon_reconnect_backoff_ms() -> u64 {
    1_000
}

const fn default_tetragon_max_reconnect_backoff_ms() -> u64 {
    30_000
}

const fn default_jetstream_gc_page_size() -> usize {
    512
}

fn default_operator_bind_addr() -> String {
    "127.0.0.1:7766".to_string()
}

const fn default_operator_max_list_results() -> usize {
    50
}

fn default_operator_id() -> String {
    "local-operator".to_string()
}

fn default_operator_token_env() -> String {
    "SWARM_OPERATOR_TOKEN".to_string()
}

const fn default_investigation_max_pending_jobs() -> usize {
    16
}

fn validate_non_empty(field: &'static str, value: &str) -> Result<(), ConfigValidationError> {
    if value.trim().is_empty() {
        return Err(ConfigValidationError::InvalidField {
            field,
            reason: "must not be empty".to_string(),
        });
    }
    Ok(())
}

fn validate_timeout(field: &'static str, value: u64) -> Result<(), ConfigValidationError> {
    if value == 0 {
        return Err(ConfigValidationError::InvalidField {
            field,
            reason: "must be greater than zero".to_string(),
        });
    }
    Ok(())
}

fn validate_retry_config(
    field_prefix: &'static str,
    retry: &RetryConfig,
) -> Result<(), ConfigValidationError> {
    if retry.initial_backoff_ms == 0 {
        return Err(ConfigValidationError::InvalidField {
            field: field_prefix,
            reason: "initial_backoff_ms must be greater than zero".to_string(),
        });
    }
    if retry.backoff_multiplier < 1.0 {
        return Err(ConfigValidationError::InvalidField {
            field: field_prefix,
            reason: "backoff_multiplier must be at least 1.0".to_string(),
        });
    }
    Ok(())
}

fn validate_circuit_breaker_config(
    field_prefix: &'static str,
    circuit_breaker: &CircuitBreakerConfig,
) -> Result<(), ConfigValidationError> {
    if circuit_breaker.threshold == 0 {
        return Err(ConfigValidationError::InvalidField {
            field: field_prefix,
            reason: "threshold must be greater than zero".to_string(),
        });
    }
    if circuit_breaker.cooldown_ms == 0 {
        return Err(ConfigValidationError::InvalidField {
            field: field_prefix,
            reason: "cooldown_ms must be greater than zero".to_string(),
        });
    }
    Ok(())
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        AuditConfig, BundleStoreConfig, CanaryConfig, CorrelationConfig, InvestigationConfig,
        OperatorSurfaceConfig, PheromoneBackendConfig, PheromoneConfig, PolicyConfig,
        PromotionConfig, RuntimeMode, RuntimeSettings, SwarmConfig, TelemetrySourceConfig,
    };
    use crate::types::Severity;

    fn valid_config(backend: PheromoneBackendConfig) -> SwarmConfig {
        SwarmConfig {
            schema_version: 1,
            name: "test".to_string(),
            description: "test config".to_string(),
            runtime: RuntimeSettings {
                mode: RuntimeMode::LiveResponse,
                telemetry_sources: vec![TelemetrySourceConfig {
                    name: "synthetic".to_string(),
                    subject: "telemetry.synthetic.process".to_string(),
                    bridge: None,
                }],
                max_in_flight_actions: 4,
                drain_timeout_ms: 30_000,
                require_durable_live_response: true,
                max_heap_pressure: 0.90,
                secret_dir: None,
            },
            detection: super::DetectionConfig {
                strategy: "suspicious_process_tree".to_string(),
                high_confidence_threshold: 0.9,
                medium_confidence_threshold: 0.7,
                profiles: super::DetectorProfilesConfig::default(),
            },
            pheromone: PheromoneConfig {
                default_half_life_secs: 3600.0,
                evaporation_threshold: 0.01,
                min_sources_for_escalation: 2,
                alert_threshold: 2.0,
                incident_threshold: 5.0,
                backend,
            },
            policy: PolicyConfig {
                human_gate_severity: Severity::High,
                lease_ttl_ms: 60_000,
            },
            response_adapter: Default::default(),
            siem_forward: None,
            notification_channels: std::collections::BTreeMap::new(),
            notification_routing: super::NotificationRoutingConfig::default(),
            audit: AuditConfig {
                bundle_store: BundleStoreConfig::Memory,
                recent_decisions_limit: 20,
            },
            investigation: InvestigationConfig::default(),
            correlation: CorrelationConfig::default(),
            canary: CanaryConfig::default(),
            promotion: PromotionConfig::default(),
            operator: OperatorSurfaceConfig::default(),
        }
    }

    #[test]
    fn jet_stream_backend_is_durable_and_valid() {
        let config = valid_config(PheromoneBackendConfig::JetStream {
            url: "nats://127.0.0.1:4222".to_string(),
            connect_timeout_ms: 5_000,
            gc_page_size: 512,
        });

        assert!(config.pheromone.backend.is_durable());
        config.validate().unwrap();
    }

    #[test]
    fn jet_stream_backend_requires_non_empty_url() {
        let config = valid_config(PheromoneBackendConfig::JetStream {
            url: "   ".to_string(),
            connect_timeout_ms: 5_000,
            gc_page_size: 512,
        });

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `pheromone.backend.url`: must not be empty"
        );
    }

    #[test]
    fn jet_stream_backend_requires_positive_connect_timeout() {
        let config = valid_config(PheromoneBackendConfig::JetStream {
            url: "nats://127.0.0.1:4222".to_string(),
            connect_timeout_ms: 0,
            gc_page_size: 512,
        });

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `pheromone.backend.connect_timeout_ms`: must be greater than zero"
        );
    }

    #[test]
    fn jet_stream_backend_requires_positive_gc_page_size() {
        let config = valid_config(PheromoneBackendConfig::JetStream {
            url: "nats://127.0.0.1:4222".to_string(),
            connect_timeout_ms: 5_000,
            gc_page_size: 0,
        });

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `pheromone.backend.gc_page_size`: must be greater than zero"
        );
    }

    #[test]
    fn jet_stream_backend_deserializes_from_tagged_config() {
        let backend: PheromoneBackendConfig = serde_json::from_value(serde_json::json!({
            "kind": "jet_stream",
            "url": "nats://127.0.0.1:4222",
            "connect_timeout_ms": 2500,
            "gc_page_size": 64
        }))
        .unwrap();

        assert_eq!(
            backend,
            PheromoneBackendConfig::JetStream {
                url: "nats://127.0.0.1:4222".to_string(),
                connect_timeout_ms: 2_500,
                gc_page_size: 64,
            }
        );
    }
}
