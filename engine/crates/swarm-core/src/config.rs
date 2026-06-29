//! Canonical v1 configuration types for the Rust-first runtime.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

use crate::agent::SwarmMode;
use crate::pheromone::ThreatClass;
use crate::types::{ResponseAction, Severity};

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
    /// Repo-owned evolution settings for Kitten orchestration and drift detection.
    #[serde(default)]
    pub evolution: EvolutionConfig,
    /// Repo-owned deception settings for the runtime Calico lane.
    #[serde(default)]
    pub deception: DeceptionConfig,
    /// Repo-owned durable memory settings for the Sphinx knowledge graph.
    #[serde(default)]
    pub memory: MemoryConfig,
    /// Repo-owned durable identity settings for runtime agents.
    #[serde(default)]
    pub identity: IdentityConfig,
    /// Versioned platform read API settings.
    #[serde(default)]
    pub platform_api: PlatformApiConfig,
    /// Local authenticated operator-surface settings.
    #[serde(default, rename = "operator_surface")]
    pub operator: OperatorSurfaceConfig,
    /// Optional shared TLS settings for both HTTP serve surfaces.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

/// Whether the runtime simulates or executes live response actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    DetectOnly,
    LiveResponse,
}

/// Runtime-wide degradation ladder layered on top of the configured runtime mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDegradationLevel {
    Full,
    DetectOnly,
    ReadOnly,
    EmergencyDrain,
}

impl RuntimeDegradationLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::DetectOnly => "detect_only",
            Self::ReadOnly => "read_only",
            Self::EmergencyDrain => "emergency_drain",
        }
    }

    pub fn accepts_ingest(self) -> bool {
        matches!(self, Self::Full | Self::DetectOnly)
    }

    pub fn allows_detection(self) -> bool {
        matches!(self, Self::Full | Self::DetectOnly)
    }

    pub fn allows_live_response(self, configured_mode: RuntimeMode) -> bool {
        configured_mode == RuntimeMode::LiveResponse && matches!(self, Self::Full)
    }

    pub fn allows_artifact_writes(self) -> bool {
        matches!(self, Self::Full | Self::DetectOnly)
    }

    pub fn drains_ingest(self) -> bool {
        matches!(self, Self::EmergencyDrain)
    }

    pub fn operator_read_surfaces_ready(self) -> bool {
        true
    }

    pub fn ready(self) -> bool {
        matches!(self, Self::Full | Self::DetectOnly)
    }
}

/// Runtime settings for the hot path.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSettings {
    /// Whether responses execute or remain dry-run.
    pub mode: RuntimeMode,
    /// Enable operator-facing demo endpoints such as replay injection and live event streaming.
    #[serde(default)]
    pub demo_mode: bool,
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
    /// Runtime self-protection settings for debugger and library tamper checks.
    #[serde(default)]
    pub anti_tamper: RuntimeAntiTamperConfig,
    /// Bounded recent-event retention used by later sequence detectors.
    #[serde(default)]
    pub temporal_event_window: TemporalEventWindowConfig,
    /// Maximum time in milliseconds for a single agent tick before the dispatcher
    /// marks the agent Degraded and skips that cycle.
    #[serde(default = "default_agent_tick_timeout_ms")]
    pub agent_tick_timeout_ms: u64,
    /// Number of consecutive degraded dispatcher ticks TomAgent tolerates before
    /// escalating an agent to Failed.
    #[serde(default = "default_governance_degraded_tick_threshold")]
    pub governance_degraded_tick_threshold: usize,
    /// Maximum lifetime for pre-staged contingency leases that can be redeemed
    /// during quorum loss.
    #[serde(default = "default_partition_contingency_lease_ttl_ms")]
    pub partition_contingency_lease_ttl_ms: i64,
    /// Maximum number of distinct scoped destructive actions one contingency
    /// lease may authorize during a partition window.
    #[serde(default = "default_partition_contingency_blast_radius_cap")]
    pub partition_contingency_blast_radius_cap: usize,
    /// Maximum size in bytes for dead-letter journal files before rotation.
    /// When set, journals exceeding this size are renamed with a timestamp
    /// suffix and a fresh file is started. When `None` (default), no rotation.
    #[serde(default)]
    pub max_dead_letter_bytes: Option<u64>,
}

/// Bounded runtime-owned recent-event retention for temporal sequence matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalEventWindowConfig {
    /// Maximum age in milliseconds for retained telemetry.
    #[serde(default = "default_temporal_event_window_retention_ms")]
    pub retention_ms: i64,
    /// Maximum number of retained telemetry events across the shared window.
    #[serde(default = "default_temporal_event_window_max_events")]
    pub max_events: usize,
    /// Maximum span in milliseconds that one ordered predicate query may scan.
    #[serde(default = "default_temporal_event_window_max_match_span_ms")]
    pub max_match_span_ms: i64,
    /// Maximum number of ordered predicates one query may request.
    #[serde(default = "default_temporal_event_window_max_predicates_per_match")]
    pub max_predicates_per_match: usize,
}

/// Runtime self-protection settings for Linux anti-tamper monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAntiTamperConfig {
    /// Whether runtime anti-tamper monitoring is active.
    #[serde(default = "default_runtime_anti_tamper_enabled")]
    pub enabled: bool,
    /// Interval in milliseconds between anti-tamper checks.
    #[serde(default = "default_runtime_anti_tamper_check_interval_ms")]
    pub check_interval_ms: u64,
    /// Whether a live-response runtime should fail closed when tamper is detected.
    #[serde(default)]
    pub fail_closed_live_response: bool,
    /// Library path prefixes allowed to load after the initial runtime baseline.
    #[serde(default = "default_runtime_anti_tamper_allowed_library_prefixes")]
    pub allowed_library_prefixes: Vec<String>,
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
    Sentinel {
        #[serde(flatten)]
        config: Box<SentinelBridgeConfig>,
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
    #[serde(default = "default_tetragon_event_timeout_secs")]
    pub event_timeout_secs: u64,
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

/// Sentinel Prometheus scrape bridge configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SentinelBridgeConfig {
    pub endpoint: String,
    #[serde(default = "default_sentinel_scrape_interval_ms")]
    pub scrape_interval_ms: u64,
    #[serde(default = "default_sentinel_scrape_timeout_ms")]
    pub scrape_timeout_ms: u64,
    #[serde(default = "default_thermal_anomaly_threshold_celsius")]
    pub thermal_anomaly_threshold_celsius: f64,
    #[serde(default = "default_memory_exhaustion_threshold_percent")]
    pub memory_exhaustion_threshold_percent: f64,
    #[serde(default = "default_disk_exhaustion_threshold_percent")]
    pub disk_exhaustion_threshold_percent: f64,
    #[serde(default = "default_max_consecutive_sentinel_failures")]
    pub max_consecutive_failures: u32,
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
        #[serde(default)]
        executable_path_path: Option<String>,
        #[serde(default)]
        signer_path: Option<String>,
        #[serde(default)]
        signature_valid_path: Option<String>,
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
    RegistryPersistence {
        process_name_path: String,
        registry_path_path: String,
        access_type_path: String,
        #[serde(default)]
        value_name_path: Option<String>,
        #[serde(default)]
        value_data_path: Option<String>,
    },
    FilePersistence {
        file_path_path: String,
        operation_path: String,
        process_name_path: String,
        #[serde(default)]
        content_preview_path: Option<String>,
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
    #[serde(default)]
    pub strategies: Vec<String>,
    pub high_confidence_threshold: f64,
    pub medium_confidence_threshold: f64,
    #[serde(default)]
    pub profiles: DetectorProfilesConfig,
}

impl DetectionConfig {
    pub fn active_strategies(&self) -> Vec<String> {
        if self.strategies.is_empty() {
            vec![self.strategy.clone()]
        } else {
            self.strategies.clone()
        }
    }

    pub fn validate_rollout_strategy_id(
        &self,
        field: &'static str,
        strategy_id: Option<&str>,
    ) -> Result<Option<String>, ConfigValidationError> {
        let Some(strategy_id) = strategy_id else {
            return Ok(None);
        };

        let strategy_id = strategy_id.trim();
        if strategy_id.is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field,
                reason: "must not be empty when provided".to_string(),
            });
        }

        if !self
            .active_strategies()
            .iter()
            .any(|entry| entry == strategy_id)
        {
            return Err(ConfigValidationError::InvalidField {
                field,
                reason: format!(
                    "must match one of detection.active_strategies(): {}",
                    self.active_strategies().join(", ")
                ),
            });
        }

        Ok(Some(strategy_id.to_string()))
    }

    pub fn resolve_rollout_strategy_id(
        &self,
        field: &'static str,
        strategy_id: Option<&str>,
        require_explicit_in_multi_strategy: bool,
    ) -> Result<String, ConfigValidationError> {
        if let Some(strategy_id) = self.validate_rollout_strategy_id(field, strategy_id)? {
            return Ok(strategy_id);
        }

        let active = self.active_strategies();
        if active.len() == 1 {
            return Ok(active[0].clone());
        }

        let reason = if require_explicit_in_multi_strategy {
            format!(
                "is required when multiple detection.strategies are active: {}",
                active.join(", ")
            )
        } else {
            format!(
                "could not be resolved because multiple detection.strategies are active: {}",
                active.join(", ")
            )
        };
        Err(ConfigValidationError::InvalidField { field, reason })
    }
}

/// Optional raw detector profile configuration payloads keyed by strategy family.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectorProfilesConfig {
    pub suspicious_process_tree: Option<serde_json::Value>,
    pub kill_chain_sequence: Option<serde_json::Value>,
    pub fileless_execution: Option<serde_json::Value>,
    pub behavioral_anomaly: Option<serde_json::Value>,
    pub dns_exfiltration: Option<serde_json::Value>,
    pub lateral_movement: Option<serde_json::Value>,
    pub credential_access: Option<serde_json::Value>,
    pub suspicious_scripting: Option<serde_json::Value>,
    pub persistence: Option<serde_json::Value>,
    pub supply_chain: Option<serde_json::Value>,
    pub network_connect: Option<serde_json::Value>,
    pub infrastructure_anomaly: Option<serde_json::Value>,
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
    /// Cooldown dwell time before the runtime de-escalates back to normal mode.
    #[serde(default = "default_deescalation_cooldown_secs")]
    pub deescalation_cooldown_secs: i64,
    /// Deterministic playbook rules used by PounceAgent action selection.
    #[serde(default)]
    pub response_playbook: ResponsePlaybookConfig,
    /// Backend used to store and recover deposits.
    #[serde(default)]
    pub backend: PheromoneBackendConfig,
}

/// Deterministic action-selection rules for autonomous response.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResponsePlaybookConfig {
    /// Ordered matching rules evaluated by PounceAgent.
    pub rules: Vec<ResponsePlaybookRule>,
}

/// One threat/severity/confidence band mapped to an ordered action sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePlaybookRule {
    /// Threat class this rule applies to.
    pub threat_class: ThreatClass,
    /// Severity this rule applies to.
    pub severity: Severity,
    /// Inclusive lower confidence bound for the rule.
    pub min_confidence: f64,
    /// Inclusive upper confidence bound for the rule.
    pub max_confidence: f64,
    /// Ordered fallback response actions emitted when the rule matches and no
    /// branch-specific selector overrides them.
    #[serde(default)]
    pub actions: Vec<ResponseAction>,
    /// Ordered branch-specific action sequences evaluated after the base rule
    /// matches. The first matching branch wins.
    #[serde(default)]
    pub branches: Vec<ResponsePlaybookBranch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponsePlaybookBranchResolution {
    pub index: usize,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResponsePlaybookRuleResolution {
    pub rule_index: usize,
    pub threat_class: ThreatClass,
    pub severity: Severity,
    pub min_confidence: f64,
    pub max_confidence: f64,
    pub actions: Vec<ResponseAction>,
    pub branch: Option<ResponsePlaybookBranchResolution>,
}

/// One ordered conditional branch under a matched response playbook rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResponsePlaybookBranch {
    /// Optional stable branch label for evidence and operator review.
    pub name: Option<String>,
    /// Additional bounded selectors evaluated against the live runtime context.
    pub when: ResponsePlaybookCondition,
    /// Ordered actions emitted when this branch matches.
    pub actions: Vec<ResponseAction>,
}

/// Additional bounded selectors for one playbook branch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResponsePlaybookCondition {
    /// Optional threat-class override or refinement for this branch.
    pub threat_class: Option<ThreatClass>,
    /// Inclusive lower severity bound.
    pub min_severity: Option<Severity>,
    /// Inclusive upper severity bound.
    pub max_severity: Option<Severity>,
    /// Inclusive lower confidence bound.
    pub min_confidence: Option<f64>,
    /// Inclusive upper confidence bound.
    pub max_confidence: Option<f64>,
    /// Optional runtime modes where this branch is allowed to emit actions.
    #[serde(default)]
    pub modes: Vec<SwarmMode>,
}

impl ResponsePlaybookCondition {
    pub fn matches(
        &self,
        threat_class: ThreatClass,
        severity: Severity,
        confidence: f64,
        mode: SwarmMode,
    ) -> bool {
        if let Some(expected) = self.threat_class.as_ref()
            && expected != &threat_class
        {
            return false;
        }
        if let Some(min_severity) = self.min_severity
            && severity < min_severity
        {
            return false;
        }
        if let Some(max_severity) = self.max_severity
            && severity > max_severity
        {
            return false;
        }
        if let Some(min_confidence) = self.min_confidence
            && confidence < min_confidence
        {
            return false;
        }
        if let Some(max_confidence) = self.max_confidence
            && confidence > max_confidence
        {
            return false;
        }
        if !self.modes.is_empty() && !self.modes.contains(&mode) {
            return false;
        }

        true
    }
}

impl ResponsePlaybookRule {
    pub fn matches(&self, threat_class: &ThreatClass, severity: Severity, confidence: f64) -> bool {
        self.threat_class == *threat_class
            && self.severity == severity
            && confidence >= self.min_confidence
            && confidence <= self.max_confidence
    }

    pub fn resolve(
        &self,
        threat_class: &ThreatClass,
        severity: Severity,
        confidence: f64,
        mode: SwarmMode,
    ) -> Option<ResponsePlaybookRuleResolution> {
        if !self.matches(threat_class, severity, confidence) {
            return None;
        }

        self.resolve_with_index(0, threat_class, severity, confidence, mode)
    }

    pub fn resolve_with_index(
        &self,
        rule_index: usize,
        threat_class: &ThreatClass,
        severity: Severity,
        confidence: f64,
        mode: SwarmMode,
    ) -> Option<ResponsePlaybookRuleResolution> {
        if !self.matches(threat_class, severity, confidence) {
            return None;
        }

        for (index, branch) in self.branches.iter().enumerate() {
            if branch
                .when
                .matches(threat_class.clone(), severity, confidence, mode)
            {
                return Some(ResponsePlaybookRuleResolution {
                    rule_index,
                    threat_class: self.threat_class.clone(),
                    severity: self.severity,
                    min_confidence: self.min_confidence,
                    max_confidence: self.max_confidence,
                    actions: branch.actions.clone(),
                    branch: Some(ResponsePlaybookBranchResolution {
                        index,
                        name: branch.name.clone(),
                    }),
                });
            }
        }

        if self.actions.is_empty() {
            return None;
        }

        Some(ResponsePlaybookRuleResolution {
            rule_index,
            threat_class: self.threat_class.clone(),
            severity: self.severity,
            min_confidence: self.min_confidence,
            max_confidence: self.max_confidence,
            actions: self.actions.clone(),
            branch: None,
        })
    }
}

impl ResponsePlaybookConfig {
    pub fn resolve(
        &self,
        threat_class: &ThreatClass,
        severity: Severity,
        confidence: f64,
        mode: SwarmMode,
    ) -> Option<ResponsePlaybookRuleResolution> {
        self.rules.iter().enumerate().find_map(|(index, rule)| {
            rule.resolve_with_index(index, threat_class, severity, confidence, mode)
        })
    }
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    /// Severity at or above which destructive actions require human approval.
    pub human_gate_severity: Severity,
    /// Capability lease lifetime.
    pub lease_ttl_ms: i64,
    /// Maximum number of actions a single scope may receive inside one minute
    /// before the static fallback gate denies additional requests.
    #[serde(default = "default_max_actions_per_scope_per_minute")]
    pub max_actions_per_scope_per_minute: usize,
    /// Ordered configurable policy rules evaluated before static fallback.
    #[serde(default)]
    pub rules: Vec<PolicyRuleConfig>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            human_gate_severity: Severity::High,
            lease_ttl_ms: 60_000,
            max_actions_per_scope_per_minute: default_max_actions_per_scope_per_minute(),
            rules: Vec::new(),
        }
    }
}

/// One ordered configurable policy rule loaded from repository YAML.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRuleConfig {
    /// Stable rule identifier emitted into logs and audit records.
    pub name: String,
    /// Final verdict emitted when this rule matches and its constraints pass.
    pub decision: PolicyRuleDecision,
    /// Threat class selector for the rule.
    pub threat_class: ThreatClass,
    /// Optional action selector list. Empty means all actions for the threat class.
    #[serde(default)]
    pub actions: Vec<PolicyActionSelector>,
    /// Inclusive lower severity bound for the rule.
    #[serde(default = "default_policy_rule_min_severity")]
    pub min_severity: Severity,
    /// Inclusive upper severity bound for the rule.
    #[serde(default = "default_policy_rule_max_severity")]
    pub max_severity: Severity,
    /// Optional UTC hour window. Requests outside the window are denied by the rule.
    #[serde(default)]
    pub time_window_utc: Option<PolicyTimeWindowConfig>,
    /// Optional per-agent one-minute burst limit scoped to this rule.
    #[serde(default)]
    pub max_actions_per_agent_per_minute: Option<usize>,
    /// Optional human-readable rationale attached to the rule verdict.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Final verdict supported by repository-owned policy rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRuleDecision {
    Allow,
    Deny,
}

/// Action selector used by configurable policy rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyActionSelector {
    BlockEgress,
    IsolateHost,
    RevokeCredential,
    SinkholeDns,
    TerminateUserSession,
    TriggerEdrScan,
    InjectFirewallRule,
    QuarantineFile,
    KillProcess,
    SuspendProcess,
    DisableUserAccount,
    ForcePasswordReset,
    RemoveScheduledTask,
    DeployDecoy,
    Escalate,
}

impl PolicyActionSelector {
    pub fn matches(self, action: &ResponseAction) -> bool {
        matches!(
            (self, action),
            (Self::BlockEgress, ResponseAction::BlockEgress { .. })
                | (Self::IsolateHost, ResponseAction::IsolateHost { .. })
                | (
                    Self::RevokeCredential,
                    ResponseAction::RevokeCredential { .. }
                )
                | (Self::SinkholeDns, ResponseAction::SinkholeDns { .. })
                | (
                    Self::TerminateUserSession,
                    ResponseAction::TerminateUserSession { .. }
                )
                | (Self::TriggerEdrScan, ResponseAction::TriggerEdrScan { .. })
                | (
                    Self::InjectFirewallRule,
                    ResponseAction::InjectFirewallRule { .. }
                )
                | (Self::QuarantineFile, ResponseAction::QuarantineFile { .. })
                | (Self::KillProcess, ResponseAction::KillProcess { .. })
                | (Self::SuspendProcess, ResponseAction::SuspendProcess { .. })
                | (
                    Self::DisableUserAccount,
                    ResponseAction::DisableUserAccount { .. }
                )
                | (
                    Self::ForcePasswordReset,
                    ResponseAction::ForcePasswordReset { .. }
                )
                | (
                    Self::RemoveScheduledTask,
                    ResponseAction::RemoveScheduledTask { .. }
                )
                | (Self::DeployDecoy, ResponseAction::DeployDecoy { .. })
                | (Self::Escalate, ResponseAction::Escalate { .. })
        )
    }
}

/// Optional UTC hour restriction for one configurable policy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTimeWindowConfig {
    /// Inclusive start hour in UTC.
    pub start_hour_utc: u8,
    /// Exclusive end hour in UTC.
    pub end_hour_utc: u8,
}

impl PolicyTimeWindowConfig {
    pub fn contains_hour(self, hour_utc: u8) -> bool {
        if self.start_hour_utc < self.end_hour_utc {
            hour_utc >= self.start_hour_utc && hour_utc < self.end_hour_utc
        } else {
            hour_utc >= self.start_hour_utc || hour_utc < self.end_hour_utc
        }
    }
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
    #[serde(default)]
    pub request_signature: Option<RequestSignatureConfig>,
    #[serde(default = "default_response_adapter_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub rate_limit: NotificationRateLimitConfig,
    #[serde(default)]
    pub quiet_hours: Option<QuietHoursConfig>,
    #[serde(default = "default_notification_dead_letter_path")]
    pub dead_letter_path: String,
}

/// Optional HMAC request signing for outbound notification channels.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestSignatureConfig {
    /// HTTP header receiving the detached signature value.
    #[serde(default = "default_request_signature_header")]
    pub header: String,
    /// Shared secret used to compute an HMAC-SHA256 over the canonical JSON body.
    pub secret: String,
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
    /// Priority boost accrued per second while a job waits in the async queue.
    #[serde(default = "default_investigation_starvation_boost_per_second_basis_points")]
    pub starvation_boost_per_second_basis_points: u16,
    /// Upper bound on starvation boost so queue aging remains bounded.
    #[serde(default = "default_investigation_max_starvation_boost_basis_points")]
    pub max_starvation_boost_basis_points: u16,
    /// Vote delta at or below which the final interpretation remains marked ambiguous.
    #[serde(default = "default_investigation_ambiguity_margin_basis_points")]
    pub ambiguity_margin_basis_points: u16,
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
    /// Optional baseline strategy scope used for rollout comparisons.
    #[serde(default)]
    pub strategy_id: Option<String>,
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
    /// Optional fallback baseline strategy scope for production rollout.
    #[serde(default)]
    pub strategy_id: Option<String>,
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

/// Repo-owned evolution settings for runtime Kitten orchestration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvolutionConfig {
    /// Whether the runtime-owned evolution lane is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Sliding observation window used when evaluating recent drift evidence.
    #[serde(default = "default_evolution_observation_window_secs")]
    pub observation_window_secs: u64,
    /// Fraction of degraded observations required to trigger drift.
    #[serde(default = "default_evolution_drift_threshold_pct")]
    pub drift_threshold_pct: f64,
    /// Minimum number of recent observations required before drift can trigger.
    #[serde(default = "default_evolution_minimum_observations")]
    pub minimum_observations: usize,
    /// Cooldown window after one proposal cycle completes.
    #[serde(default = "default_evolution_cooldown_secs")]
    pub cooldown_secs: u64,
    /// Maximum number of candidate variants materialized during one cycle.
    #[serde(default = "default_evolution_max_variants_per_cycle")]
    pub max_variants_per_cycle: usize,
    /// Number of ranked candidates preserved for proposal review.
    #[serde(default = "default_evolution_shortlist_count")]
    pub shortlist_count: usize,
    /// Maximum number of persisted candidates retained across generations.
    #[serde(default = "default_evolution_population_size")]
    pub population_size: usize,
    /// Tournament width used when selecting Pareto survivors from the population.
    #[serde(default = "default_evolution_pareto_tournament_size")]
    pub pareto_tournament_size: usize,
    /// Maximum number of candidate proposals emitted during a rolling one-hour window.
    #[serde(default = "default_evolution_max_proposals_per_hour")]
    pub max_proposals_per_hour: usize,
    /// Multi-objective weights used when scoring validated candidates.
    #[serde(default)]
    pub fitness_weights: EvolutionFitnessWeightsConfig,
    /// Repo-owned formal safety gate settings for canary admission.
    #[serde(default)]
    pub safety_gate: EvolutionSafetyGateConfig,
    /// Repo-owned assurance policy that turns robustness artifacts into gate inputs.
    #[serde(default)]
    pub assurance: EvolutionAssuranceConfig,
    /// Durable artifact directories shared with the extracted evolution workflows.
    #[serde(default)]
    pub paths: EvolutionPathsConfig,
}

/// Weighting used by the runtime evolution lane when combining replay-derived objectives.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvolutionFitnessWeightsConfig {
    #[serde(default = "default_evolution_fitness_detection_rate_weight")]
    pub detection_rate: f64,
    #[serde(default = "default_evolution_fitness_false_positive_cost_weight")]
    pub false_positive_cost: f64,
    #[serde(default = "default_evolution_fitness_speed_weight")]
    pub speed: f64,
    #[serde(default = "default_evolution_fitness_threat_class_coverage_weight")]
    pub threat_class_coverage: f64,
}

/// Repo-owned formal safety gate settings used before canary admission.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvolutionSafetyGateConfig {
    /// Bundle files defining deterministic safety invariants for evolved candidates.
    #[serde(default = "default_evolution_safety_invariant_bundle_paths")]
    pub invariant_bundle_paths: Vec<String>,
    /// Optional Z3-backed proof mode toggle for future strict verification.
    #[serde(default)]
    pub enable_z3: bool,
}

/// Repo-owned assurance policy used when deciding whether a candidate can stay queue-eligible.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvolutionAssuranceConfig {
    /// Whether a solver summary must be present on proposal proofs.
    #[serde(default)]
    pub require_solver_summary: bool,
    /// Global minimum detector catch rate required across the repo-owned evasion suite.
    #[serde(default = "default_evolution_assurance_min_detector_catch_rate")]
    pub min_detector_catch_rate: f64,
    /// Solver outcomes that remain eligible under the assurance policy.
    #[serde(default = "default_evolution_assurance_allowed_solver_statuses")]
    pub allowed_solver_statuses: Vec<EvolutionAssuranceSolverStatusConfig>,
    /// Per-detector catch-rate overrides for stricter or looser assurance floors.
    #[serde(default)]
    pub coverage_overrides: Vec<EvolutionAssuranceCoverageOverrideConfig>,
    /// Bounded durable regeneration settings for harvested assurance cases.
    #[serde(default)]
    pub harvest: EvolutionAssuranceHarvestConfig,
    /// Bounded signed waiver limits for one blocked assurance decision.
    #[serde(default)]
    pub waiver: EvolutionAssuranceWaiverConfig,
}

/// Repo-owned solver-proof outcomes allowed by the assurance policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionAssuranceSolverStatusConfig {
    Proved,
    Counterexample,
    Timeout,
    Disabled,
    Error,
}

/// Per-detector assurance floor override.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvolutionAssuranceCoverageOverrideConfig {
    pub detector: String,
    pub min_catch_rate: f64,
}

/// Repo-owned harvest settings for replayable assurance cases.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvolutionAssuranceHarvestConfig {
    #[serde(default = "default_evolution_assurance_harvest_results_dir")]
    pub results_dir: String,
    #[serde(default = "default_evolution_assurance_harvest_max_cases_per_proposal")]
    pub max_cases_per_proposal: usize,
    #[serde(default = "default_evolution_assurance_harvest_max_events_per_case")]
    pub max_events_per_case: usize,
}

/// Repo-owned limits that bound one signed assurance waiver.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvolutionAssuranceWaiverConfig {
    #[serde(default)]
    pub allowed_operator_ids: Vec<String>,
    #[serde(default = "default_evolution_assurance_waiver_max_ttl_secs")]
    pub max_ttl_secs: u64,
    #[serde(default = "default_evolution_assurance_waiver_max_actionable_gap_count")]
    pub max_actionable_gap_count: usize,
}

/// Durable artifact paths used by the runtime evolution lane.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvolutionPathsConfig {
    #[serde(default = "default_replay_results_dir")]
    pub replay_results_dir: String,
    #[serde(default = "default_experiment_results_dir")]
    pub experiment_results_dir: String,
    #[serde(default = "default_verification_results_dir")]
    pub verification_results_dir: String,
    #[serde(default = "default_shadow_results_dir")]
    pub shadow_results_dir: String,
    #[serde(default = "default_strategy_memory_results_dir")]
    pub strategy_memory_results_dir: String,
    #[serde(default = "default_strategy_scorecard_results_dir")]
    pub strategy_scorecard_results_dir: String,
    #[serde(default = "default_evolution_proof_results_dir")]
    pub evolution_proof_results_dir: String,
    #[serde(default = "default_evolution_queue_results_dir")]
    pub evolution_queue_results_dir: String,
    #[serde(default = "default_evolution_selection_results_dir")]
    pub evolution_selection_results_dir: String,
    #[serde(default = "default_evolution_bridge_results_dir")]
    pub evolution_bridge_results_dir: String,
    #[serde(default = "default_evolution_handoff_results_dir")]
    pub evolution_handoff_results_dir: String,
    #[serde(default = "default_evolution_pressure_results_dir")]
    pub evolution_pressure_results_dir: String,
    #[serde(default = "default_evolution_draft_results_dir")]
    pub evolution_draft_results_dir: String,
    #[serde(default = "default_evolution_draft_promotion_results_dir")]
    pub evolution_draft_promotion_results_dir: String,
    #[serde(default = "default_evolution_materialization_results_dir")]
    pub evolution_materialization_results_dir: String,
    #[serde(default = "default_evolution_validation_results_dir")]
    pub evolution_validation_results_dir: String,
    #[serde(default = "default_evolution_reconciliation_results_dir")]
    pub evolution_reconciliation_results_dir: String,
    #[serde(default = "default_evolution_mutation_results_dir")]
    pub evolution_mutation_results_dir: String,
    #[serde(default = "default_evolution_mutation_materialization_batch_results_dir")]
    pub evolution_mutation_materialization_batch_results_dir: String,
    #[serde(default = "default_evolution_mutation_validation_batch_results_dir")]
    pub evolution_mutation_validation_batch_results_dir: String,
    #[serde(default = "default_evolution_ranking_results_dir")]
    pub evolution_ranking_results_dir: String,
    #[serde(default = "default_evolution_population_results_dir")]
    pub evolution_population_results_dir: String,
    #[serde(default = "default_canary_results_dir")]
    pub canary_results_dir: String,
}

/// Repo-owned deception settings for the runtime Calico lane.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeceptionConfig {
    /// Whether the runtime should register Calico and manage baseline deception assets.
    pub enabled: bool,
    /// Root directory where durable Calico lifecycle snapshots are persisted.
    #[serde(default = "default_deception_lifecycle_results_dir")]
    pub lifecycle_results_dir: String,
    /// Maximum lifetime for one active decoy generation before Calico rotates it.
    #[serde(default = "default_deception_rotation_interval_secs")]
    pub rotation_interval_secs: u64,
    /// Grace window a rotated decoy remains in the registry before cleanup.
    #[serde(default = "default_deception_cleanup_grace_secs")]
    pub cleanup_grace_secs: u64,
    /// Blend weight used when deception interactions boost Kitten proposal fitness.
    #[serde(default = "default_deception_interaction_fitness_weight")]
    pub interaction_fitness_weight: f64,
    /// Typed repo-owned playbook describing decoys, placement, and monitoring rules.
    pub playbook: DeceptionPlaybookConfig,
}

/// Ordered deception entries the runtime Calico lane deploys and monitors.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeceptionPlaybookConfig {
    /// Named deception entries evaluated in order.
    pub entries: Vec<DeceptionPlaybookEntry>,
}

/// One deception asset definition in the repo-owned playbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeceptionPlaybookEntry {
    /// Stable entry identifier used in audit and runtime evidence.
    pub name: String,
    /// Decoy asset type routed through `ResponseAction::DeployDecoy`.
    pub decoy_type: String,
    /// Zone or segment where the decoy should be placed.
    pub target_zone: String,
    /// Human-readable legitimate-host profile the decoy emulates.
    pub host_profile: String,
    /// Placement strategy for the asset.
    #[serde(default)]
    pub placement_strategy: DeceptionPlacementStrategy,
    /// Monitoring rules used to treat interaction as high-confidence detection.
    #[serde(default)]
    pub monitoring: DeceptionMonitoringConfig,
}

/// Placement strategy for one deception asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeceptionPlacementStrategy {
    #[default]
    Baseline,
    HighValuePath,
    NetworkSegment,
    InvestigationZone,
}

/// Monitoring rules associated with one deception asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeceptionMonitoringConfig {
    /// File-system tripwires that should never be touched by legitimate activity.
    pub file_paths: Vec<String>,
    /// Honeypot ports that indicate suspicious network access when contacted.
    pub honeypot_ports: Vec<u16>,
    /// Canary credentials whose use indicates suspicious activity.
    pub canary_credentials: Vec<String>,
    /// Threat class used when this monitoring rule fires.
    #[serde(default = "default_deception_monitoring_threat_class")]
    pub threat_class: ThreatClass,
    /// Severity attached to emitted Calico findings.
    #[serde(default = "default_deception_monitoring_severity")]
    pub severity: Severity,
    /// Confidence attached to emitted Calico findings. Must stay high-fidelity.
    #[serde(default = "default_deception_monitoring_confidence")]
    pub confidence: f64,
}

/// Repo-owned Sphinx memory settings for the durable knowledge graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryConfig {
    /// Whether the runtime should register Sphinx and persist graph state.
    #[serde(default)]
    pub enabled: bool,
    /// Root directory for the typed knowledge-graph store.
    #[serde(default = "default_memory_knowledge_graph_results_dir")]
    pub knowledge_graph_results_dir: String,
    /// Correlation window for temporal graph edges between related engagements.
    #[serde(default = "default_memory_temporal_window_secs")]
    pub temporal_window_secs: u64,
    /// Retention window in days before stale graph records are garbage-collected.
    #[serde(default = "default_memory_knowledge_retention_days")]
    pub knowledge_retention_days: u64,
}

/// Repo-owned durable identity settings for runtime agents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// Directory where runtime agent Ed25519 seeds are persisted.
    #[serde(default = "default_agent_key_dir")]
    pub agent_key_dir: String,
    /// Directory where identity registry snapshots and continuity proofs are persisted.
    #[serde(default = "default_identity_registry_dir")]
    pub registry_dir: String,
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
    /// Runtime HTTP base URL the live demo dashboard reads from.
    #[serde(default = "default_operator_runtime_base_url")]
    pub runtime_base_url: String,
    /// Public HTTP base URL external systems use for operator drilldown links.
    #[serde(default = "default_operator_public_base_url")]
    pub public_base_url: String,
    /// Additional origins allowed to embed the minimal Providence widget.
    #[serde(default)]
    pub allowed_embed_origins: Vec<String>,
    /// Maximum records returned from list endpoints.
    #[serde(default = "default_operator_max_list_results")]
    pub max_list_results: usize,
    /// Lifetime for Providence widget context tokens.
    #[serde(default = "default_operator_widget_token_ttl_secs")]
    pub widget_token_ttl_secs: u64,
    /// Bearer-token auth configuration for the local surface.
    #[serde(default)]
    pub auth: OperatorAuthConfig,
}

/// Versioned detect-server platform API settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformApiConfig {
    /// Configured API keys allowed to read `/v2/api/*`.
    #[serde(default)]
    pub keys: Vec<PlatformApiKeyConfig>,
}

/// Shared TLS settings for the detect and operator HTTP servers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// PEM-encoded server certificate chain.
    pub cert_path: String,
    /// PEM-encoded private key matching `cert_path`.
    pub key_path: String,
    /// Optional PEM-encoded client CA bundle enabling mTLS.
    #[serde(default)]
    pub client_ca_cert: Option<String>,
}

/// One scoped platform API key entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformApiKeyConfig {
    /// Human-readable name attached to authenticated requests.
    pub name: String,
    /// Lowercase or uppercase SHA-256 hex digest of the raw key material.
    pub key_hash: String,
    /// Scopes granted to this key.
    pub scopes: Vec<PlatformApiScope>,
}

/// Platform API scopes supported by the current detect-server read surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformApiScope {
    Read,
}

/// Operator scopes supported by the authenticated operator and platform surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorScope {
    Read,
    Rehearse,
    Approve,
    Maintenance,
}

/// One scoped operator principal entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorPrincipalConfig {
    /// Logical operator principal attached to authenticated requests.
    pub operator_id: String,
    /// Environment variable name that carries the bearer token for this principal.
    pub token_env: String,
    /// Scopes granted to this principal.
    #[serde(default)]
    pub scopes: Vec<OperatorScope>,
}

/// Authentication settings for the local operator surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorAuthConfig {
    /// Environment variable name used to sign read-only Providence context tokens.
    #[serde(default = "default_operator_context_token_env")]
    pub context_token_env: String,
    /// Supported multi-principal operator auth contract.
    #[serde(default)]
    pub principals: Vec<OperatorPrincipalConfig>,
    /// Logical operator principal attached to authenticated requests.
    #[serde(default = "default_operator_id")]
    pub operator_id: String,
    /// Environment variable name that carries the bearer token.
    #[serde(default = "default_operator_token_env")]
    pub token_env: String,
}

impl OperatorAuthConfig {
    pub fn effective_principals(&self) -> Vec<OperatorPrincipalConfig> {
        if !self.principals.is_empty() {
            return self.principals.clone();
        }
        vec![OperatorPrincipalConfig {
            operator_id: self.operator_id.clone(),
            token_env: self.token_env.clone(),
            scopes: vec![
                OperatorScope::Read,
                OperatorScope::Rehearse,
                OperatorScope::Approve,
                OperatorScope::Maintenance,
            ],
        }]
    }

    pub fn context_token_env(&self) -> &str {
        self.context_token_env.trim()
    }
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
            Self::Sentinel { config } => config.validate(),
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
        if self.event_timeout_secs == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "tetragon.event_timeout_secs",
                reason: "must be greater than zero".to_string(),
            });
        }
        Ok(())
    }
}

impl PlatformApiConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        let mut names = BTreeSet::new();
        let mut hashes = BTreeSet::new();

        for (index, key) in self.keys.iter().enumerate() {
            let name = key.name.trim();
            if name.is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "platform_api.keys",
                    reason: format!("key {index} name must not be empty"),
                });
            }
            if !names.insert(name.to_string()) {
                return Err(ConfigValidationError::InvalidField {
                    field: "platform_api.keys",
                    reason: format!("duplicate key name `{name}`"),
                });
            }

            let key_hash = key.key_hash.trim();
            if key_hash.len() != 64 || !key_hash.chars().all(|ch| ch.is_ascii_hexdigit()) {
                return Err(ConfigValidationError::InvalidField {
                    field: "platform_api.keys.key_hash",
                    reason: format!(
                        "key {index} key_hash must be a 64-character SHA-256 hex digest"
                    ),
                });
            }
            if !hashes.insert(key_hash.to_ascii_lowercase()) {
                return Err(ConfigValidationError::InvalidField {
                    field: "platform_api.keys.key_hash",
                    reason: format!("duplicate key hash for key `{name}`"),
                });
            }

            if key.scopes.is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "platform_api.keys.scopes",
                    reason: format!("key {index} must grant at least one scope"),
                });
            }
        }

        Ok(())
    }
}

impl TlsConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.cert_path.trim().is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "tls.cert_path",
                reason: "must not be empty when TLS is configured".to_string(),
            });
        }
        if self.key_path.trim().is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "tls.key_path",
                reason: "must not be empty when TLS is configured".to_string(),
            });
        }
        if self
            .client_ca_cert
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(ConfigValidationError::InvalidField {
                field: "tls.client_ca_cert",
                reason: "must not be empty when configured".to_string(),
            });
        }
        Ok(())
    }
}

impl EvolutionConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.observation_window_secs == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.observation_window_secs",
                reason: "must be greater than zero when evolution is enabled".to_string(),
            });
        }
        if !(0.0..=1.0).contains(&self.drift_threshold_pct) || self.drift_threshold_pct == 0.0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.drift_threshold_pct",
                reason: "must be greater than 0.0 and less than or equal to 1.0".to_string(),
            });
        }
        if self.minimum_observations == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.minimum_observations",
                reason: "must be greater than zero when evolution is enabled".to_string(),
            });
        }
        if self.cooldown_secs == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.cooldown_secs",
                reason: "must be greater than zero when evolution is enabled".to_string(),
            });
        }
        if self.max_variants_per_cycle == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.max_variants_per_cycle",
                reason: "must be greater than zero when evolution is enabled".to_string(),
            });
        }
        if self.shortlist_count == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.shortlist_count",
                reason: "must be greater than zero when evolution is enabled".to_string(),
            });
        }
        if self.population_size == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.population_size",
                reason: "must be greater than zero when evolution is enabled".to_string(),
            });
        }
        if self.pareto_tournament_size == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.pareto_tournament_size",
                reason: "must be greater than zero when evolution is enabled".to_string(),
            });
        }
        if self.max_proposals_per_hour == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.max_proposals_per_hour",
                reason: "must be greater than zero when evolution is enabled".to_string(),
            });
        }
        self.fitness_weights.validate()?;
        self.safety_gate.validate()?;
        self.assurance.validate()?;
        self.paths.validate()
    }
}

impl EvolutionFitnessWeightsConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        let components = [
            (
                "evolution.fitness_weights.detection_rate",
                self.detection_rate,
            ),
            (
                "evolution.fitness_weights.false_positive_cost",
                self.false_positive_cost,
            ),
            ("evolution.fitness_weights.speed", self.speed),
            (
                "evolution.fitness_weights.threat_class_coverage",
                self.threat_class_coverage,
            ),
        ];
        for (field, value) in components {
            if !value.is_finite() || value < 0.0 {
                return Err(ConfigValidationError::InvalidField {
                    field,
                    reason: "must be finite and greater than or equal to zero".to_string(),
                });
            }
        }
        let total = self.detection_rate
            + self.false_positive_cost
            + self.speed
            + self.threat_class_coverage;
        if total <= 0.0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.fitness_weights",
                reason: "at least one weight must be greater than zero".to_string(),
            });
        }
        Ok(())
    }
}

impl EvolutionSafetyGateConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.invariant_bundle_paths.is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.safety_gate.invariant_bundle_paths",
                reason: "must include at least one repo-owned invariant bundle when evolution is enabled"
                    .to_string(),
            });
        }
        for (index, path) in self.invariant_bundle_paths.iter().enumerate() {
            if path.trim().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "evolution.safety_gate.invariant_bundle_paths",
                    reason: format!("entry {index} must not be empty"),
                });
            }
        }
        Ok(())
    }
}

impl EvolutionAssuranceConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        if !self.min_detector_catch_rate.is_finite()
            || !(0.0..=1.0).contains(&self.min_detector_catch_rate)
        {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.assurance.min_detector_catch_rate",
                reason: "must be between 0.0 and 1.0".to_string(),
            });
        }
        if self.allowed_solver_statuses.is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.assurance.allowed_solver_statuses",
                reason: "must include at least one allowed solver outcome".to_string(),
            });
        }
        for (index, override_config) in self.coverage_overrides.iter().enumerate() {
            if override_config.detector.trim().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "evolution.assurance.coverage_overrides.detector",
                    reason: format!("entry {index} must not be empty"),
                });
            }
            if !override_config.min_catch_rate.is_finite()
                || !(0.0..=1.0).contains(&override_config.min_catch_rate)
            {
                return Err(ConfigValidationError::InvalidField {
                    field: "evolution.assurance.coverage_overrides.min_catch_rate",
                    reason: "must be between 0.0 and 1.0".to_string(),
                });
            }
        }
        self.harvest.validate()?;
        self.waiver.validate()?;
        Ok(())
    }
}

impl EvolutionAssuranceHarvestConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        validate_non_empty("evolution.assurance.harvest.results_dir", &self.results_dir)?;
        if self.max_cases_per_proposal == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.assurance.harvest.max_cases_per_proposal",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.max_events_per_case == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.assurance.harvest.max_events_per_case",
                reason: "must be greater than zero".to_string(),
            });
        }
        Ok(())
    }
}

impl EvolutionAssuranceWaiverConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.max_ttl_secs == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.assurance.waiver.max_ttl_secs",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.max_actionable_gap_count == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.assurance.waiver.max_actionable_gap_count",
                reason: "must be greater than zero".to_string(),
            });
        }
        for (index, operator_id) in self.allowed_operator_ids.iter().enumerate() {
            if operator_id.trim().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "evolution.assurance.waiver.allowed_operator_ids",
                    reason: format!("entry {index} must not be empty"),
                });
            }
            if !operator_id.starts_with("swarm:ed25519:") {
                return Err(ConfigValidationError::InvalidField {
                    field: "evolution.assurance.waiver.allowed_operator_ids",
                    reason: format!("entry {index} must start with swarm:ed25519:"),
                });
            }
        }
        Ok(())
    }
}

impl EvolutionPathsConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        validate_non_empty(
            "evolution.paths.replay_results_dir",
            &self.replay_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.experiment_results_dir",
            &self.experiment_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.verification_results_dir",
            &self.verification_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.shadow_results_dir",
            &self.shadow_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.strategy_memory_results_dir",
            &self.strategy_memory_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.strategy_scorecard_results_dir",
            &self.strategy_scorecard_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_proof_results_dir",
            &self.evolution_proof_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_queue_results_dir",
            &self.evolution_queue_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_selection_results_dir",
            &self.evolution_selection_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_bridge_results_dir",
            &self.evolution_bridge_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_handoff_results_dir",
            &self.evolution_handoff_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_pressure_results_dir",
            &self.evolution_pressure_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_draft_results_dir",
            &self.evolution_draft_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_draft_promotion_results_dir",
            &self.evolution_draft_promotion_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_materialization_results_dir",
            &self.evolution_materialization_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_validation_results_dir",
            &self.evolution_validation_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_reconciliation_results_dir",
            &self.evolution_reconciliation_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_mutation_results_dir",
            &self.evolution_mutation_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_mutation_materialization_batch_results_dir",
            &self.evolution_mutation_materialization_batch_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_mutation_validation_batch_results_dir",
            &self.evolution_mutation_validation_batch_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_ranking_results_dir",
            &self.evolution_ranking_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_population_results_dir",
            &self.evolution_population_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.canary_results_dir",
            &self.canary_results_dir,
        )?;
        Ok(())
    }
}

impl MemoryConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        validate_non_empty(
            "memory.knowledge_graph_results_dir",
            &self.knowledge_graph_results_dir,
        )?;
        if self.temporal_window_secs == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "memory.temporal_window_secs",
                reason: "must be greater than zero when memory is enabled".to_string(),
            });
        }
        if self.knowledge_retention_days == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "memory.knowledge_retention_days",
                reason: "must be greater than zero when memory is enabled".to_string(),
            });
        }
        Ok(())
    }
}

impl DeceptionConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.enabled {
            validate_non_empty(
                "deception.lifecycle_results_dir",
                &self.lifecycle_results_dir,
            )?;
            if self.rotation_interval_secs == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "deception.rotation_interval_secs",
                    reason: "must be greater than zero when deception is enabled".to_string(),
                });
            }
            if self.cleanup_grace_secs == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "deception.cleanup_grace_secs",
                    reason: "must be greater than zero when deception is enabled".to_string(),
                });
            }
            if !(0.0 < self.interaction_fitness_weight && self.interaction_fitness_weight <= 1.0) {
                return Err(ConfigValidationError::InvalidField {
                    field: "deception.interaction_fitness_weight",
                    reason: "must be greater than zero and at most 1.0 when deception is enabled"
                        .to_string(),
                });
            }
        }
        self.playbook.validate(self.enabled)
    }
}

impl DeceptionPlaybookConfig {
    fn validate(&self, enabled: bool) -> Result<(), ConfigValidationError> {
        if enabled && self.entries.is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "deception.playbook.entries",
                reason: "must contain at least one entry when deception is enabled".to_string(),
            });
        }

        let mut names = BTreeSet::new();
        for (index, entry) in self.entries.iter().enumerate() {
            entry.validate(index)?;
            if !names.insert(entry.name.clone()) {
                return Err(ConfigValidationError::InvalidField {
                    field: "deception.playbook.entries.name",
                    reason: format!("duplicate playbook entry `{}`", entry.name),
                });
            }
        }

        Ok(())
    }
}

impl DeceptionPlaybookEntry {
    fn validate(&self, index: usize) -> Result<(), ConfigValidationError> {
        validate_non_empty("deception.playbook.entries.name", &self.name)?;
        validate_non_empty("deception.playbook.entries.decoy_type", &self.decoy_type)?;
        validate_non_empty("deception.playbook.entries.target_zone", &self.target_zone)?;
        validate_non_empty(
            "deception.playbook.entries.host_profile",
            &self.host_profile,
        )?;
        self.monitoring.validate(index)
    }
}

impl DeceptionMonitoringConfig {
    fn validate(&self, index: usize) -> Result<(), ConfigValidationError> {
        if self.file_paths.is_empty()
            && self.honeypot_ports.is_empty()
            && self.canary_credentials.is_empty()
        {
            return Err(ConfigValidationError::InvalidField {
                field: "deception.playbook.entries.monitoring",
                reason: format!(
                    "entry {index} must define at least one monitored file path, honeypot port, or canary credential"
                ),
            });
        }
        for path in &self.file_paths {
            validate_non_empty("deception.playbook.entries.monitoring.file_paths", path)?;
        }
        for credential in &self.canary_credentials {
            validate_non_empty(
                "deception.playbook.entries.monitoring.canary_credentials",
                credential,
            )?;
        }
        if self.honeypot_ports.contains(&0) {
            return Err(ConfigValidationError::InvalidField {
                field: "deception.playbook.entries.monitoring.honeypot_ports",
                reason: "must contain only positive port values".to_string(),
            });
        }
        if !(0.95..=1.0).contains(&self.confidence) {
            return Err(ConfigValidationError::InvalidField {
                field: "deception.playbook.entries.monitoring.confidence",
                reason: "must be between 0.95 and 1.0".to_string(),
            });
        }
        Ok(())
    }
}

impl IdentityConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        validate_non_empty("identity.agent_key_dir", &self.agent_key_dir)?;
        validate_non_empty("identity.registry_dir", &self.registry_dir)
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

impl SentinelBridgeConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.endpoint.trim().is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.telemetry_sources.bridge.endpoint",
                reason: "must not be empty".to_string(),
            });
        }
        if !self.endpoint.starts_with("http://") && !self.endpoint.starts_with("https://") {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.telemetry_sources.bridge.endpoint",
                reason: "must start with http:// or https://".to_string(),
            });
        }
        if self.scrape_interval_ms == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.telemetry_sources.bridge.scrape_interval_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.scrape_timeout_ms == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.telemetry_sources.bridge.scrape_timeout_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        validate_percentage_threshold(
            "runtime.telemetry_sources.bridge.memory_exhaustion_threshold_percent",
            self.memory_exhaustion_threshold_percent,
        )?;
        validate_percentage_threshold(
            "runtime.telemetry_sources.bridge.disk_exhaustion_threshold_percent",
            self.disk_exhaustion_threshold_percent,
        )?;
        if self.thermal_anomaly_threshold_celsius <= 0.0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.telemetry_sources.bridge.thermal_anomaly_threshold_celsius",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.max_consecutive_failures == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.telemetry_sources.bridge.max_consecutive_failures",
                reason: "must be greater than zero".to_string(),
            });
        }
        Ok(())
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
                executable_path_path,
                signer_path,
                signature_valid_path,
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
                if let Some(path) = executable_path_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.executable_path_path",
                        path,
                    )?;
                }
                if let Some(path) = signer_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.signer_path",
                        path,
                    )?;
                }
                if let Some(path) = signature_valid_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.signature_valid_path",
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
            Self::RegistryPersistence {
                process_name_path,
                registry_path_path,
                access_type_path,
                value_name_path,
                value_data_path,
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
                if let Some(path) = value_name_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.value_name_path",
                        path,
                    )?;
                }
                if let Some(path) = value_data_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.value_data_path",
                        path,
                    )?;
                }
            }
            Self::FilePersistence {
                file_path_path,
                operation_path,
                process_name_path,
                content_preview_path,
            } => {
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.file_path_path",
                    file_path_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.operation_path",
                    operation_path,
                )?;
                validate_json_pointer(
                    "runtime.telemetry_sources.bridge.mapping.payload.process_name_path",
                    process_name_path,
                )?;
                if let Some(path) = content_preview_path {
                    validate_json_pointer(
                        "runtime.telemetry_sources.bridge.mapping.payload.content_preview_path",
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

fn validate_percentage_threshold(
    field: &'static str,
    value: f64,
) -> Result<(), ConfigValidationError> {
    if !(0.0..=100.0).contains(&value) || value == 0.0 {
        return Err(ConfigValidationError::InvalidField {
            field,
            reason: "must be greater than 0.0 and less than or equal to 100.0".to_string(),
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
        if let Some(tls) = self.tls.as_ref() {
            tls.validate()?;
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
        if self.runtime.temporal_event_window.retention_ms <= 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.temporal_event_window.retention_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.runtime.temporal_event_window.max_events == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.temporal_event_window.max_events",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.runtime.temporal_event_window.max_match_span_ms <= 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.temporal_event_window.max_match_span_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.runtime.temporal_event_window.max_match_span_ms
            > self.runtime.temporal_event_window.retention_ms
        {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.temporal_event_window.max_match_span_ms",
                reason: "must be less than or equal to retention_ms".to_string(),
            });
        }
        if self.runtime.temporal_event_window.max_predicates_per_match == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.temporal_event_window.max_predicates_per_match",
                reason: "must be greater than zero".to_string(),
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
        if self.runtime.anti_tamper.enabled && self.runtime.anti_tamper.check_interval_ms == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.anti_tamper.check_interval_ms",
                reason: "must be greater than zero when anti-tamper monitoring is enabled"
                    .to_string(),
            });
        }
        if !self.runtime.anti_tamper.enabled && self.runtime.anti_tamper.fail_closed_live_response {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.anti_tamper.fail_closed_live_response",
                reason: "requires runtime.anti_tamper.enabled".to_string(),
            });
        }
        if self
            .runtime
            .anti_tamper
            .allowed_library_prefixes
            .iter()
            .any(|prefix| prefix.trim().is_empty())
        {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.anti_tamper.allowed_library_prefixes",
                reason: "entries must not be empty".to_string(),
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
        let mut active_strategy_ids = BTreeSet::new();
        for strategy_id in self.detection.active_strategies() {
            let strategy_id = strategy_id.trim();
            if strategy_id.is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "detection.strategies",
                    reason: "entries must not be empty".to_string(),
                });
            }
            if !active_strategy_ids.insert(strategy_id.to_string()) {
                return Err(ConfigValidationError::InvalidField {
                    field: "detection.strategies",
                    reason: format!("duplicate detector strategy `{strategy_id}`"),
                });
            }
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
        self.detection.validate_rollout_strategy_id(
            "canary.strategy_id",
            self.canary.strategy_id.as_deref(),
        )?;
        self.detection.validate_rollout_strategy_id(
            "promotion.strategy_id",
            self.promotion.strategy_id.as_deref(),
        )?;

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
        if self.pheromone.deescalation_cooldown_secs <= 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.deescalation_cooldown_secs",
                reason: "must be greater than zero".to_string(),
            });
        }
        self.pheromone.response_playbook.validate()?;
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
        if self.policy.max_actions_per_scope_per_minute == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "policy.max_actions_per_scope_per_minute",
                reason: "must be greater than zero".to_string(),
            });
        }
        for (index, rule) in self.policy.rules.iter().enumerate() {
            rule.validate(index)?;
        }

        if self.runtime.governance_degraded_tick_threshold == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.governance_degraded_tick_threshold",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.runtime.partition_contingency_lease_ttl_ms <= 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.partition_contingency_lease_ttl_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.runtime.partition_contingency_blast_radius_cap == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.partition_contingency_blast_radius_cap",
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
            if self.investigation.starvation_boost_per_second_basis_points == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "investigation.starvation_boost_per_second_basis_points",
                    reason: "must be greater than zero when investigation is enabled".to_string(),
                });
            }
            if self.investigation.max_starvation_boost_basis_points == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "investigation.max_starvation_boost_basis_points",
                    reason: "must be greater than zero when investigation is enabled".to_string(),
                });
            }
            if self.investigation.ambiguity_margin_basis_points == 0
                || self.investigation.ambiguity_margin_basis_points > 10_000
            {
                return Err(ConfigValidationError::InvalidField {
                    field: "investigation.ambiguity_margin_basis_points",
                    reason: "must be between 1 and 10000 when investigation is enabled".to_string(),
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
            if self.detection.active_strategies().len() > 1 && self.canary.strategy_id.is_none() {
                return Err(ConfigValidationError::InvalidField {
                    field: "canary.strategy_id",
                    reason: format!(
                        "is required when multiple detection.strategies are active: {}",
                        self.detection.active_strategies().join(", ")
                    ),
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

        if self.evolution.enabled {
            self.evolution.validate()?;
        }
        if self.deception.enabled || !self.deception.playbook.entries.is_empty() {
            self.deception.validate()?;
        }
        if self.memory.enabled {
            self.memory.validate()?;
        }
        self.identity.validate()?;

        self.platform_api.validate()?;

        let needs_operator_urls = self.operator.enabled
            || self
                .notification_channels
                .contains_key("providence_webhook");
        let needs_operator_auth = self.operator.enabled || !self.platform_api.keys.is_empty();

        if needs_operator_urls {
            let runtime_base_url = self.operator.runtime_base_url.trim();
            if runtime_base_url.is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.runtime_base_url",
                    reason:
                        "must not be empty when operator surface or Providence delivery is enabled"
                            .to_string(),
                });
            }
            if !(runtime_base_url.starts_with("http://")
                || runtime_base_url.starts_with("https://"))
            {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.runtime_base_url",
                    reason: "must start with http:// or https://".to_string(),
                });
            }

            let public_base_url = self.operator.public_base_url.trim();
            if public_base_url.is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.public_base_url",
                    reason:
                        "must not be empty when operator surface or Providence delivery is enabled"
                            .to_string(),
                });
            }
            if !(public_base_url.starts_with("http://") || public_base_url.starts_with("https://"))
            {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.public_base_url",
                    reason: "must start with http:// or https://".to_string(),
                });
            }
        }

        if needs_operator_auth {
            let principals = self.operator.auth.effective_principals();
            if principals.is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.auth.principals",
                    reason: "must contain at least one principal".to_string(),
                });
            }

            let mut seen_operator_ids = BTreeSet::new();
            let mut seen_token_envs = BTreeSet::new();
            for (index, principal) in principals.iter().enumerate() {
                if principal.operator_id.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "operator_surface.auth.principals.operator_id",
                        reason: format!("principal {index} must not have an empty operator_id"),
                    });
                }
                if !seen_operator_ids.insert(principal.operator_id.trim().to_string()) {
                    return Err(ConfigValidationError::InvalidField {
                        field: "operator_surface.auth.principals.operator_id",
                        reason: format!(
                            "principal {index} duplicates operator_id `{}`",
                            principal.operator_id.trim()
                        ),
                    });
                }
                if principal.token_env.trim().is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "operator_surface.auth.principals.token_env",
                        reason: format!("principal {index} must not have an empty token_env"),
                    });
                }
                if !seen_token_envs.insert(principal.token_env.trim().to_string()) {
                    return Err(ConfigValidationError::InvalidField {
                        field: "operator_surface.auth.principals.token_env",
                        reason: format!(
                            "principal {index} reuses token_env `{}`; bearer secrets must map to one principal",
                            principal.token_env.trim()
                        ),
                    });
                }
                if principal.scopes.is_empty() {
                    return Err(ConfigValidationError::InvalidField {
                        field: "operator_surface.auth.principals.scopes",
                        reason: format!("principal {index} must grant at least one scope"),
                    });
                }
            }

            if !principals
                .iter()
                .any(|principal| principal.scopes.contains(&OperatorScope::Read))
            {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.auth.principals.scopes",
                    reason: "at least one principal must grant `read` scope".to_string(),
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
            if self.operator.widget_token_ttl_secs == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.widget_token_ttl_secs",
                    reason: "must be greater than zero when operator surface is enabled"
                        .to_string(),
                });
            }

            if self.operator.auth.context_token_env().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.auth.context_token_env",
                    reason: "must not be empty when operator surface is enabled".to_string(),
                });
            }

            let bind_addr: SocketAddr = self.operator.bind_addr.parse().map_err(|_| {
                ConfigValidationError::InvalidField {
                    field: "operator_surface.bind_addr",
                    reason: "must be a valid socket address".to_string(),
                }
            })?;
            let _ = bind_addr;
        }

        for (index, origin) in self.operator.allowed_embed_origins.iter().enumerate() {
            let trimmed = origin.trim();
            if trimmed.is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.allowed_embed_origins",
                    reason: format!("origin {index} must not be empty"),
                });
            }
            if !(trimmed == "'self'"
                || trimmed.starts_with("http://")
                || trimmed.starts_with("https://"))
            {
                return Err(ConfigValidationError::InvalidField {
                    field: "operator_surface.allowed_embed_origins",
                    reason: format!(
                        "origin {index} must be 'self' or start with http:// or https://"
                    ),
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

impl ResponsePlaybookConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        for (index, rule) in self.rules.iter().enumerate() {
            rule.validate(index)?;
        }
        Ok(())
    }
}

impl ResponsePlaybookRule {
    fn validate(&self, index: usize) -> Result<(), ConfigValidationError> {
        if !(0.0..=1.0).contains(&self.min_confidence) {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.response_playbook",
                reason: format!("rule {index} min_confidence must be between 0.0 and 1.0"),
            });
        }
        if !(0.0..=1.0).contains(&self.max_confidence) {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.response_playbook",
                reason: format!("rule {index} max_confidence must be between 0.0 and 1.0"),
            });
        }
        if self.max_confidence < self.min_confidence {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.response_playbook",
                reason: format!(
                    "rule {index} max_confidence must be greater than or equal to min_confidence"
                ),
            });
        }
        if self.actions.is_empty() && self.branches.is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.response_playbook",
                reason: format!(
                    "rule {index} must declare fallback actions or at least one conditional branch"
                ),
            });
        }
        let mut branch_names = BTreeSet::new();
        for (branch_index, branch) in self.branches.iter().enumerate() {
            branch.validate(index, branch_index)?;
            if let Some(name) = &branch.name {
                let normalized = name.trim().to_string();
                if !branch_names.insert(normalized.clone()) {
                    return Err(ConfigValidationError::InvalidField {
                        field: "pheromone.response_playbook",
                        reason: format!(
                            "rule {index} declares duplicate branch name `{normalized}`"
                        ),
                    });
                }
            }
        }
        Ok(())
    }
}

impl ResponsePlaybookBranch {
    fn validate(
        &self,
        rule_index: usize,
        branch_index: usize,
    ) -> Result<(), ConfigValidationError> {
        if let Some(name) = &self.name
            && name.trim().is_empty()
        {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.response_playbook",
                reason: format!("rule {rule_index} branch {branch_index} name must not be empty"),
            });
        }
        if self.actions.is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.response_playbook",
                reason: format!(
                    "rule {rule_index} branch {branch_index} must declare at least one response action"
                ),
            });
        }
        self.when.validate(rule_index, branch_index)
    }
}

impl ResponsePlaybookCondition {
    fn validate(
        &self,
        rule_index: usize,
        branch_index: usize,
    ) -> Result<(), ConfigValidationError> {
        if let Some(min_confidence) = self.min_confidence
            && !(0.0..=1.0).contains(&min_confidence)
        {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.response_playbook",
                reason: format!(
                    "rule {rule_index} branch {branch_index} min_confidence must be between 0.0 and 1.0"
                ),
            });
        }
        if let Some(max_confidence) = self.max_confidence
            && !(0.0..=1.0).contains(&max_confidence)
        {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.response_playbook",
                reason: format!(
                    "rule {rule_index} branch {branch_index} max_confidence must be between 0.0 and 1.0"
                ),
            });
        }
        if let (Some(min_confidence), Some(max_confidence)) =
            (self.min_confidence, self.max_confidence)
            && max_confidence < min_confidence
        {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.response_playbook",
                reason: format!(
                    "rule {rule_index} branch {branch_index} max_confidence must be greater than or equal to min_confidence"
                ),
            });
        }
        if let (Some(min_severity), Some(max_severity)) = (self.min_severity, self.max_severity)
            && max_severity < min_severity
        {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.response_playbook",
                reason: format!(
                    "rule {rule_index} branch {branch_index} max_severity must be greater than or equal to min_severity"
                ),
            });
        }

        Ok(())
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
        if let Some(signature) = &self.request_signature {
            signature.validate()?;
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

impl RequestSignatureConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        validate_non_empty(
            "notification_channels.request_signature.header",
            &self.header,
        )?;
        validate_non_empty(
            "notification_channels.request_signature.secret",
            &self.secret,
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
            starvation_boost_per_second_basis_points:
                default_investigation_starvation_boost_per_second_basis_points(),
            max_starvation_boost_basis_points:
                default_investigation_max_starvation_boost_basis_points(),
            ambiguity_margin_basis_points: default_investigation_ambiguity_margin_basis_points(),
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
            strategy_id: None,
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
            strategy_id: None,
            observation_window_events: default_promotion_observation_window_events(),
            max_promoted_only_rate: default_promotion_max_promoted_only_rate(),
            max_fallback_recovery_rate: default_promotion_max_fallback_recovery_rate(),
            max_detect_latency_us: default_promotion_max_detect_latency_us(),
            max_total_detections: default_promotion_max_total_detections(),
        }
    }
}

impl Default for EvolutionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            observation_window_secs: default_evolution_observation_window_secs(),
            drift_threshold_pct: default_evolution_drift_threshold_pct(),
            minimum_observations: default_evolution_minimum_observations(),
            cooldown_secs: default_evolution_cooldown_secs(),
            max_variants_per_cycle: default_evolution_max_variants_per_cycle(),
            shortlist_count: default_evolution_shortlist_count(),
            population_size: default_evolution_population_size(),
            pareto_tournament_size: default_evolution_pareto_tournament_size(),
            max_proposals_per_hour: default_evolution_max_proposals_per_hour(),
            fitness_weights: EvolutionFitnessWeightsConfig::default(),
            safety_gate: EvolutionSafetyGateConfig::default(),
            assurance: EvolutionAssuranceConfig::default(),
            paths: EvolutionPathsConfig::default(),
        }
    }
}

impl Default for EvolutionAssuranceConfig {
    fn default() -> Self {
        Self {
            require_solver_summary: false,
            min_detector_catch_rate: default_evolution_assurance_min_detector_catch_rate(),
            allowed_solver_statuses: default_evolution_assurance_allowed_solver_statuses(),
            coverage_overrides: Vec::new(),
            harvest: EvolutionAssuranceHarvestConfig::default(),
            waiver: EvolutionAssuranceWaiverConfig::default(),
        }
    }
}

impl Default for EvolutionAssuranceHarvestConfig {
    fn default() -> Self {
        Self {
            results_dir: default_evolution_assurance_harvest_results_dir(),
            max_cases_per_proposal: default_evolution_assurance_harvest_max_cases_per_proposal(),
            max_events_per_case: default_evolution_assurance_harvest_max_events_per_case(),
        }
    }
}

impl Default for EvolutionAssuranceWaiverConfig {
    fn default() -> Self {
        Self {
            allowed_operator_ids: Vec::new(),
            max_ttl_secs: default_evolution_assurance_waiver_max_ttl_secs(),
            max_actionable_gap_count: default_evolution_assurance_waiver_max_actionable_gap_count(),
        }
    }
}

impl Default for DeceptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            lifecycle_results_dir: default_deception_lifecycle_results_dir(),
            rotation_interval_secs: default_deception_rotation_interval_secs(),
            cleanup_grace_secs: default_deception_cleanup_grace_secs(),
            interaction_fitness_weight: default_deception_interaction_fitness_weight(),
            playbook: DeceptionPlaybookConfig::default(),
        }
    }
}

impl Default for DeceptionMonitoringConfig {
    fn default() -> Self {
        Self {
            file_paths: Vec::new(),
            honeypot_ports: Vec::new(),
            canary_credentials: Vec::new(),
            threat_class: default_deception_monitoring_threat_class(),
            severity: default_deception_monitoring_severity(),
            confidence: default_deception_monitoring_confidence(),
        }
    }
}

impl Default for EvolutionFitnessWeightsConfig {
    fn default() -> Self {
        Self {
            detection_rate: default_evolution_fitness_detection_rate_weight(),
            false_positive_cost: default_evolution_fitness_false_positive_cost_weight(),
            speed: default_evolution_fitness_speed_weight(),
            threat_class_coverage: default_evolution_fitness_threat_class_coverage_weight(),
        }
    }
}

impl Default for EvolutionSafetyGateConfig {
    fn default() -> Self {
        Self {
            invariant_bundle_paths: default_evolution_safety_invariant_bundle_paths(),
            enable_z3: false,
        }
    }
}

impl Default for EvolutionPathsConfig {
    fn default() -> Self {
        Self {
            replay_results_dir: default_replay_results_dir(),
            experiment_results_dir: default_experiment_results_dir(),
            verification_results_dir: default_verification_results_dir(),
            shadow_results_dir: default_shadow_results_dir(),
            strategy_memory_results_dir: default_strategy_memory_results_dir(),
            strategy_scorecard_results_dir: default_strategy_scorecard_results_dir(),
            evolution_proof_results_dir: default_evolution_proof_results_dir(),
            evolution_queue_results_dir: default_evolution_queue_results_dir(),
            evolution_selection_results_dir: default_evolution_selection_results_dir(),
            evolution_bridge_results_dir: default_evolution_bridge_results_dir(),
            evolution_handoff_results_dir: default_evolution_handoff_results_dir(),
            evolution_pressure_results_dir: default_evolution_pressure_results_dir(),
            evolution_draft_results_dir: default_evolution_draft_results_dir(),
            evolution_draft_promotion_results_dir: default_evolution_draft_promotion_results_dir(),
            evolution_materialization_results_dir: default_evolution_materialization_results_dir(),
            evolution_validation_results_dir: default_evolution_validation_results_dir(),
            evolution_reconciliation_results_dir: default_evolution_reconciliation_results_dir(),
            evolution_mutation_results_dir: default_evolution_mutation_results_dir(),
            evolution_mutation_materialization_batch_results_dir:
                default_evolution_mutation_materialization_batch_results_dir(),
            evolution_mutation_validation_batch_results_dir:
                default_evolution_mutation_validation_batch_results_dir(),
            evolution_ranking_results_dir: default_evolution_ranking_results_dir(),
            evolution_population_results_dir: default_evolution_population_results_dir(),
            canary_results_dir: default_canary_results_dir(),
        }
    }
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            knowledge_graph_results_dir: default_memory_knowledge_graph_results_dir(),
            temporal_window_secs: default_memory_temporal_window_secs(),
            knowledge_retention_days: default_memory_knowledge_retention_days(),
        }
    }
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            agent_key_dir: default_agent_key_dir(),
            registry_dir: default_identity_registry_dir(),
        }
    }
}

impl Default for OperatorSurfaceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_addr: default_operator_bind_addr(),
            runtime_base_url: default_operator_runtime_base_url(),
            public_base_url: default_operator_public_base_url(),
            allowed_embed_origins: Vec::new(),
            max_list_results: default_operator_max_list_results(),
            widget_token_ttl_secs: default_operator_widget_token_ttl_secs(),
            auth: OperatorAuthConfig::default(),
        }
    }
}

impl Default for OperatorAuthConfig {
    fn default() -> Self {
        Self {
            context_token_env: default_operator_context_token_env(),
            principals: Vec::new(),
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

impl Default for RuntimeAntiTamperConfig {
    fn default() -> Self {
        Self {
            enabled: default_runtime_anti_tamper_enabled(),
            check_interval_ms: default_runtime_anti_tamper_check_interval_ms(),
            fail_closed_live_response: false,
            allowed_library_prefixes: default_runtime_anti_tamper_allowed_library_prefixes(),
        }
    }
}

impl Default for TemporalEventWindowConfig {
    fn default() -> Self {
        Self {
            retention_ms: default_temporal_event_window_retention_ms(),
            max_events: default_temporal_event_window_max_events(),
            max_match_span_ms: default_temporal_event_window_max_match_span_ms(),
            max_predicates_per_match: default_temporal_event_window_max_predicates_per_match(),
        }
    }
}

const fn default_recent_decisions_limit() -> usize {
    20
}

const fn default_agent_tick_timeout_ms() -> u64 {
    500
}

const fn default_governance_degraded_tick_threshold() -> usize {
    3
}

const fn default_partition_contingency_lease_ttl_ms() -> i64 {
    300_000
}

const fn default_partition_contingency_blast_radius_cap() -> usize {
    1
}

const fn default_drain_timeout_ms() -> u64 {
    30_000
}

const fn default_max_heap_pressure() -> f64 {
    0.90
}

const fn default_temporal_event_window_retention_ms() -> i64 {
    900_000
}

const fn default_temporal_event_window_max_events() -> usize {
    512
}

const fn default_temporal_event_window_max_match_span_ms() -> i64 {
    300_000
}

const fn default_temporal_event_window_max_predicates_per_match() -> usize {
    8
}

const fn default_runtime_anti_tamper_enabled() -> bool {
    true
}

const fn default_runtime_anti_tamper_check_interval_ms() -> u64 {
    5_000
}

fn default_runtime_anti_tamper_allowed_library_prefixes() -> Vec<String> {
    vec![
        "/lib".to_string(),
        "/lib64".to_string(),
        "/usr/lib".to_string(),
        "/usr/local/lib".to_string(),
        "/nix/store".to_string(),
    ]
}

const fn default_deception_monitoring_threat_class() -> ThreatClass {
    ThreatClass::InitialAccess
}

const fn default_deception_monitoring_severity() -> Severity {
    Severity::High
}

const fn default_deception_monitoring_confidence() -> f64 {
    0.99
}

fn default_agent_key_dir() -> String {
    "data/agent-keys".to_string()
}

fn default_identity_registry_dir() -> String {
    "data/agent-identity".to_string()
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

fn default_request_signature_header() -> String {
    "X-Swarm-Signature".to_string()
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

const fn default_tetragon_event_timeout_secs() -> u64 {
    30
}

const fn default_sentinel_scrape_interval_ms() -> u64 {
    5_000
}

const fn default_sentinel_scrape_timeout_ms() -> u64 {
    3_000
}

const fn default_thermal_anomaly_threshold_celsius() -> f64 {
    60.0
}

const fn default_memory_exhaustion_threshold_percent() -> f64 {
    85.0
}

const fn default_disk_exhaustion_threshold_percent() -> f64 {
    90.0
}

const fn default_max_consecutive_sentinel_failures() -> u32 {
    5
}

const fn default_deescalation_cooldown_secs() -> i64 {
    300
}

const fn default_jetstream_gc_page_size() -> usize {
    512
}

fn default_operator_bind_addr() -> String {
    "127.0.0.1:7766".to_string()
}

fn default_operator_runtime_base_url() -> String {
    "http://127.0.0.1:9090".to_string()
}

fn default_operator_public_base_url() -> String {
    "http://127.0.0.1:7766".to_string()
}

const fn default_operator_max_list_results() -> usize {
    50
}

const fn default_operator_widget_token_ttl_secs() -> u64 {
    15 * 60
}

fn default_operator_id() -> String {
    "local-operator".to_string()
}

fn default_operator_token_env() -> String {
    "SWARM_OPERATOR_TOKEN".to_string()
}

fn default_operator_context_token_env() -> String {
    default_operator_token_env()
}

const fn default_investigation_max_pending_jobs() -> usize {
    16
}

const fn default_investigation_starvation_boost_per_second_basis_points() -> u16 {
    15
}

const fn default_investigation_max_starvation_boost_basis_points() -> u16 {
    2_500
}

const fn default_investigation_ambiguity_margin_basis_points() -> u16 {
    900
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

const fn default_evolution_observation_window_secs() -> u64 {
    3_600
}

const fn default_evolution_drift_threshold_pct() -> f64 {
    0.40
}

const fn default_evolution_minimum_observations() -> usize {
    3
}

const fn default_evolution_cooldown_secs() -> u64 {
    900
}

const fn default_evolution_max_variants_per_cycle() -> usize {
    2
}

const fn default_evolution_shortlist_count() -> usize {
    1
}

const fn default_evolution_population_size() -> usize {
    16
}

const fn default_evolution_pareto_tournament_size() -> usize {
    4
}

const fn default_evolution_max_proposals_per_hour() -> usize {
    4
}

const fn default_evolution_assurance_min_detector_catch_rate() -> f64 {
    0.25
}

fn default_evolution_assurance_allowed_solver_statuses() -> Vec<EvolutionAssuranceSolverStatusConfig>
{
    vec![
        EvolutionAssuranceSolverStatusConfig::Proved,
        EvolutionAssuranceSolverStatusConfig::Disabled,
    ]
}

fn default_evolution_assurance_harvest_results_dir() -> String {
    "data/evolution-assurance-cases".to_string()
}

const fn default_evolution_assurance_harvest_max_cases_per_proposal() -> usize {
    8
}

const fn default_evolution_assurance_harvest_max_events_per_case() -> usize {
    16
}

const fn default_evolution_assurance_waiver_max_ttl_secs() -> u64 {
    3600
}

const fn default_evolution_assurance_waiver_max_actionable_gap_count() -> usize {
    4
}

fn default_evolution_safety_invariant_bundle_paths() -> Vec<String> {
    vec!["safety/office-detector-admission.yaml".to_string()]
}

const fn default_evolution_fitness_detection_rate_weight() -> f64 {
    0.40
}

const fn default_evolution_fitness_false_positive_cost_weight() -> f64 {
    0.30
}

const fn default_evolution_fitness_speed_weight() -> f64 {
    0.15
}

const fn default_evolution_fitness_threat_class_coverage_weight() -> f64 {
    0.15
}

fn default_replay_results_dir() -> String {
    "data/replay-runs".to_string()
}

fn default_experiment_results_dir() -> String {
    "data/experiments".to_string()
}

fn default_verification_results_dir() -> String {
    "data/verifications".to_string()
}

fn default_shadow_results_dir() -> String {
    "data/shadows".to_string()
}

fn default_strategy_memory_results_dir() -> String {
    "data/strategy-memory".to_string()
}

fn default_memory_knowledge_graph_results_dir() -> String {
    "data/knowledge-graph".to_string()
}

fn default_deception_lifecycle_results_dir() -> String {
    "data/deception-lifecycle".to_string()
}

const fn default_deception_rotation_interval_secs() -> u64 {
    86_400
}

const fn default_deception_cleanup_grace_secs() -> u64 {
    3_600
}

const fn default_deception_interaction_fitness_weight() -> f64 {
    0.15
}

const fn default_memory_temporal_window_secs() -> u64 {
    3_600
}

const fn default_memory_knowledge_retention_days() -> u64 {
    90
}

fn default_strategy_scorecard_results_dir() -> String {
    "data/strategy-scorecards".to_string()
}

fn default_evolution_proof_results_dir() -> String {
    "data/evolution-proofs".to_string()
}

fn default_evolution_queue_results_dir() -> String {
    "data/evolution-queue".to_string()
}

fn default_evolution_selection_results_dir() -> String {
    "data/evolution-selections".to_string()
}

fn default_evolution_bridge_results_dir() -> String {
    "data/evolution-selection-bridges".to_string()
}

fn default_evolution_handoff_results_dir() -> String {
    "data/evolution-handoffs".to_string()
}

fn default_evolution_pressure_results_dir() -> String {
    "data/evolution-pressures".to_string()
}

fn default_evolution_draft_results_dir() -> String {
    "data/evolution-drafts".to_string()
}

fn default_evolution_draft_promotion_results_dir() -> String {
    "data/evolution-draft-promotions".to_string()
}

fn default_evolution_materialization_results_dir() -> String {
    "data/evolution-materializations".to_string()
}

fn default_evolution_validation_results_dir() -> String {
    "data/evolution-validation-bundles".to_string()
}

fn default_evolution_reconciliation_results_dir() -> String {
    "data/evolution-reconciliations".to_string()
}

fn default_evolution_mutation_results_dir() -> String {
    "data/evolution-mutations".to_string()
}

fn default_evolution_mutation_materialization_batch_results_dir() -> String {
    "data/evolution-mutation-materialization-batches".to_string()
}

fn default_evolution_mutation_validation_batch_results_dir() -> String {
    "data/evolution-mutation-validation-batches".to_string()
}

fn default_evolution_ranking_results_dir() -> String {
    "data/evolution-rankings".to_string()
}

fn default_evolution_population_results_dir() -> String {
    "data/evolution-population".to_string()
}

fn default_canary_results_dir() -> String {
    "data/canaries".to_string()
}

const fn default_max_actions_per_scope_per_minute() -> usize {
    5
}

const fn default_policy_rule_min_severity() -> Severity {
    Severity::Low
}

const fn default_policy_rule_max_severity() -> Severity {
    Severity::Critical
}

impl PolicyRuleConfig {
    fn validate(&self, index: usize) -> Result<(), ConfigValidationError> {
        if self.name.trim().is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "policy.rules",
                reason: format!("rule {index} name must not be empty"),
            });
        }
        if self.max_severity < self.min_severity {
            return Err(ConfigValidationError::InvalidField {
                field: "policy.rules",
                reason: format!(
                    "rule {index} max_severity must be greater than or equal to min_severity"
                ),
            });
        }
        if let Some(limit) = self.max_actions_per_agent_per_minute
            && limit == 0
        {
            return Err(ConfigValidationError::InvalidField {
                field: "policy.rules",
                reason: format!(
                    "rule {index} max_actions_per_agent_per_minute must be greater than zero"
                ),
            });
        }
        if let Some(window) = self.time_window_utc {
            if window.start_hour_utc > 23 {
                return Err(ConfigValidationError::InvalidField {
                    field: "policy.rules",
                    reason: format!("rule {index} start_hour_utc must be between 0 and 23"),
                });
            }
            if window.end_hour_utc == 0 || window.end_hour_utc > 24 {
                return Err(ConfigValidationError::InvalidField {
                    field: "policy.rules",
                    reason: format!("rule {index} end_hour_utc must be between 1 and 24"),
                });
            }
            if window.start_hour_utc == window.end_hour_utc {
                return Err(ConfigValidationError::InvalidField {
                    field: "policy.rules",
                    reason: format!("rule {index} time_window_utc must span at least one UTC hour"),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        AuditConfig, BundleStoreConfig, CanaryConfig, CorrelationConfig, DeceptionConfig,
        DeceptionMonitoringConfig, DeceptionPlacementStrategy, DeceptionPlaybookConfig,
        DeceptionPlaybookEntry, EvolutionAssuranceCoverageOverrideConfig, EvolutionConfig,
        InvestigationConfig, NotificationChannelConfig, OperatorPrincipalConfig, OperatorScope,
        OperatorSurfaceConfig, PheromoneBackendConfig, PheromoneConfig, PlatformApiConfig,
        PlatformApiKeyConfig, PlatformApiScope, PolicyActionSelector, PolicyConfig,
        PolicyRuleConfig, PolicyRuleDecision, PolicyTimeWindowConfig, PromotionConfig,
        RequestSignatureConfig, ResponsePlaybookBranch, ResponsePlaybookCondition,
        ResponsePlaybookConfig, ResponsePlaybookRule, RuntimeAntiTamperConfig, RuntimeMode,
        RuntimeSettings, SentinelBridgeConfig, SwarmConfig, TelemetryBridgeConfig,
        TelemetrySourceConfig, TemporalEventWindowConfig,
    };
    use crate::ThreatClass;
    use crate::agent::SwarmMode;
    use crate::types::{ResponseAction, Severity};

    fn valid_config(backend: PheromoneBackendConfig) -> SwarmConfig {
        SwarmConfig {
            schema_version: 1,
            name: "test".to_string(),
            description: "test config".to_string(),
            runtime: RuntimeSettings {
                mode: RuntimeMode::LiveResponse,
                demo_mode: false,
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
                anti_tamper: RuntimeAntiTamperConfig::default(),
                temporal_event_window: TemporalEventWindowConfig::default(),
                agent_tick_timeout_ms: 500,
                governance_degraded_tick_threshold: 3,
                partition_contingency_lease_ttl_ms: 300_000,
                partition_contingency_blast_radius_cap: 1,
                max_dead_letter_bytes: None,
            },
            detection: super::DetectionConfig {
                strategy: "suspicious_process_tree".to_string(),
                strategies: Vec::new(),
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
                deescalation_cooldown_secs: 300,
                response_playbook: ResponsePlaybookConfig::default(),
                backend,
            },
            policy: PolicyConfig::default(),
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
            evolution: EvolutionConfig::default(),
            deception: DeceptionConfig::default(),
            memory: super::MemoryConfig::default(),
            identity: super::IdentityConfig::default(),
            platform_api: PlatformApiConfig::default(),
            operator: OperatorSurfaceConfig::default(),
            tls: None,
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
    fn anti_tamper_requires_positive_check_interval_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.runtime.anti_tamper.check_interval_ms = 0;

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `runtime.anti_tamper.check_interval_ms`: must be greater than zero when anti-tamper monitoring is enabled"
        );
    }

    #[test]
    fn anti_tamper_fail_closed_requires_monitoring_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.runtime.anti_tamper.enabled = false;
        config.runtime.anti_tamper.fail_closed_live_response = true;

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `runtime.anti_tamper.fail_closed_live_response`: requires runtime.anti_tamper.enabled"
        );
    }

    #[test]
    fn anti_tamper_rejects_empty_allowed_library_prefixes() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.runtime.anti_tamper.allowed_library_prefixes = vec![" ".to_string()];

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `runtime.anti_tamper.allowed_library_prefixes`: entries must not be empty"
        );
    }

    #[test]
    fn temporal_event_window_requires_positive_retention() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.runtime.temporal_event_window.retention_ms = 0;

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `runtime.temporal_event_window.retention_ms`: must be greater than zero"
        );
    }

    #[test]
    fn temporal_event_window_match_span_cannot_exceed_retention() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.runtime.temporal_event_window.retention_ms = 30_000;
        config.runtime.temporal_event_window.max_match_span_ms = 60_000;

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `runtime.temporal_event_window.max_match_span_ms`: must be less than or equal to retention_ms"
        );
    }

    #[test]
    fn operator_surface_requires_http_runtime_base_url_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.operator.enabled = true;
        config.operator.runtime_base_url = "ws://127.0.0.1:9090".to_string();

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `operator_surface.runtime_base_url`: must start with http:// or https://"
        );
    }

    #[test]
    fn deception_enabled_requires_non_empty_playbook() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.deception.enabled = true;

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `deception.playbook.entries`: must contain at least one entry when deception is enabled"
        );
    }

    #[test]
    fn deception_monitoring_confidence_must_be_high_fidelity() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.deception.enabled = true;
        config.deception.playbook = DeceptionPlaybookConfig {
            entries: vec![DeceptionPlaybookEntry {
                name: "finance-canary".to_string(),
                decoy_type: "canary_token".to_string(),
                target_zone: "finance".to_string(),
                host_profile: "linux-app".to_string(),
                placement_strategy: DeceptionPlacementStrategy::HighValuePath,
                monitoring: DeceptionMonitoringConfig {
                    file_paths: vec!["/srv/finance/payroll.xlsx".to_string()],
                    honeypot_ports: Vec::new(),
                    canary_credentials: Vec::new(),
                    threat_class: crate::pheromone::ThreatClass::InitialAccess,
                    severity: Severity::High,
                    confidence: 0.80,
                },
            }],
        };

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `deception.playbook.entries.monitoring.confidence`: must be between 0.95 and 1.0"
        );
    }

    #[test]
    fn deception_requires_non_empty_lifecycle_results_dir_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.deception.enabled = true;
        config.deception.lifecycle_results_dir = " ".to_string();
        config.deception.playbook = DeceptionPlaybookConfig {
            entries: vec![DeceptionPlaybookEntry {
                name: "finance-canary".to_string(),
                decoy_type: "canary_token".to_string(),
                target_zone: "finance".to_string(),
                host_profile: "linux-app".to_string(),
                placement_strategy: DeceptionPlacementStrategy::HighValuePath,
                monitoring: DeceptionMonitoringConfig {
                    file_paths: vec!["/srv/finance/payroll.xlsx".to_string()],
                    honeypot_ports: Vec::new(),
                    canary_credentials: Vec::new(),
                    threat_class: crate::pheromone::ThreatClass::InitialAccess,
                    severity: Severity::High,
                    confidence: 0.99,
                },
            }],
        };

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `deception.lifecycle_results_dir`: must not be empty"
        );
    }

    #[test]
    fn deception_requires_positive_rotation_interval_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.deception.enabled = true;
        config.deception.rotation_interval_secs = 0;
        config.deception.playbook = DeceptionPlaybookConfig {
            entries: vec![DeceptionPlaybookEntry {
                name: "finance-canary".to_string(),
                decoy_type: "canary_token".to_string(),
                target_zone: "finance".to_string(),
                host_profile: "linux-app".to_string(),
                placement_strategy: DeceptionPlacementStrategy::HighValuePath,
                monitoring: DeceptionMonitoringConfig {
                    file_paths: vec!["/srv/finance/payroll.xlsx".to_string()],
                    honeypot_ports: Vec::new(),
                    canary_credentials: Vec::new(),
                    threat_class: crate::pheromone::ThreatClass::InitialAccess,
                    severity: Severity::High,
                    confidence: 0.99,
                },
            }],
        };

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `deception.rotation_interval_secs`: must be greater than zero when deception is enabled"
        );
    }

    #[test]
    fn operator_surface_requires_http_public_base_url_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.operator.enabled = true;
        config.operator.public_base_url = "ws://127.0.0.1:7766".to_string();

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `operator_surface.public_base_url`: must start with http:// or https://"
        );
    }

    #[test]
    fn operator_surface_requires_positive_widget_token_ttl_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.operator.enabled = true;
        config.operator.widget_token_ttl_secs = 0;

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `operator_surface.widget_token_ttl_secs`: must be greater than zero when operator surface is enabled"
        );
    }

    #[test]
    fn operator_surface_rejects_invalid_embed_origin() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.operator.allowed_embed_origins = vec!["ftp://providence.example".to_string()];

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `operator_surface.allowed_embed_origins`: origin 0 must be 'self' or start with http:// or https://"
        );
    }

    #[test]
    fn operator_surface_principals_require_scopes() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.operator.enabled = true;
        config.operator.auth.principals = vec![OperatorPrincipalConfig {
            operator_id: "reader".to_string(),
            token_env: "SWARM_OPERATOR_READER_TOKEN".to_string(),
            scopes: Vec::new(),
        }];

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `operator_surface.auth.principals.scopes`: principal 0 must grant at least one scope"
        );
    }

    #[test]
    fn operator_surface_rejects_duplicate_principal_token_envs() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.operator.enabled = true;
        config.operator.auth.principals = vec![
            OperatorPrincipalConfig {
                operator_id: "reader".to_string(),
                token_env: "SWARM_OPERATOR_SHARED_TOKEN".to_string(),
                scopes: vec![OperatorScope::Read],
            },
            OperatorPrincipalConfig {
                operator_id: "approver".to_string(),
                token_env: "SWARM_OPERATOR_SHARED_TOKEN".to_string(),
                scopes: vec![OperatorScope::Approve],
            },
        ];

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `operator_surface.auth.principals.token_env`: principal 1 reuses token_env `SWARM_OPERATOR_SHARED_TOKEN`; bearer secrets must map to one principal"
        );
    }

    #[test]
    fn operator_surface_requires_read_scope_when_platform_api_is_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.platform_api.keys = vec![PlatformApiKeyConfig {
            name: "reader".to_string(),
            key_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            scopes: vec![PlatformApiScope::Read],
        }];
        config.operator.auth.principals = vec![OperatorPrincipalConfig {
            operator_id: "maintainer".to_string(),
            token_env: "SWARM_OPERATOR_MAINTAINER_TOKEN".to_string(),
            scopes: vec![OperatorScope::Maintenance],
        }];

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `operator_surface.auth.principals.scopes`: at least one principal must grant `read` scope"
        );
    }

    #[test]
    fn platform_api_rejects_invalid_key_hash() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.platform_api.keys = vec![PlatformApiKeyConfig {
            name: "reader".to_string(),
            key_hash: "not-a-sha".to_string(),
            scopes: vec![PlatformApiScope::Read],
        }];

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `platform_api.keys.key_hash`: key 0 key_hash must be a 64-character SHA-256 hex digest"
        );
    }

    #[test]
    fn notification_request_signature_requires_non_empty_secret() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.notification_channels.insert(
            "providence_webhook".to_string(),
            NotificationChannelConfig {
                target_url: "https://providence.example/incidents".to_string(),
                auth_token: Some("@secret:providence_api_token".to_string()),
                request_signature: Some(RequestSignatureConfig {
                    header: "X-Swarm-Signature".to_string(),
                    secret: "   ".to_string(),
                }),
                timeout_ms: 5_000,
                rate_limit: super::NotificationRateLimitConfig::default(),
                quiet_hours: None,
                dead_letter_path: "./notification-providence.jsonl".to_string(),
            },
        );
        config.notification_routing.rules = vec![super::RoutingRule {
            min_severity: Some(Severity::High),
            threat_class: Some(ThreatClass::Execution),
            utc_start_hour: None,
            utc_end_hour: None,
            channels: vec!["providence_webhook".to_string()],
        }];

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `notification_channels.request_signature.secret`: must not be empty"
        );
    }

    #[test]
    fn evolution_requires_non_zero_drift_threshold_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.evolution.enabled = true;
        config.evolution.drift_threshold_pct = 0.0;

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `evolution.drift_threshold_pct`: must be greater than 0.0 and less than or equal to 1.0"
        );
    }

    #[test]
    fn evolution_requires_non_empty_results_paths_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.evolution.enabled = true;
        config.evolution.paths.evolution_validation_results_dir = " ".to_string();

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `evolution.paths.evolution_validation_results_dir`: must not be empty"
        );
    }

    #[test]
    fn evolution_requires_positive_hourly_proposal_limit_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.evolution.enabled = true;
        config.evolution.max_proposals_per_hour = 0;

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `evolution.max_proposals_per_hour`: must be greater than zero when evolution is enabled"
        );
    }

    #[test]
    fn evolution_requires_non_zero_fitness_weight_total_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.evolution.enabled = true;
        config.evolution.fitness_weights.detection_rate = 0.0;
        config.evolution.fitness_weights.false_positive_cost = 0.0;
        config.evolution.fitness_weights.speed = 0.0;
        config.evolution.fitness_weights.threat_class_coverage = 0.0;

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `evolution.fitness_weights`: at least one weight must be greater than zero"
        );
    }

    #[test]
    fn evolution_requires_non_empty_safety_invariant_bundle_paths_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.evolution.enabled = true;
        config.evolution.safety_gate.invariant_bundle_paths.clear();

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `evolution.safety_gate.invariant_bundle_paths`: must include at least one repo-owned invariant bundle when evolution is enabled"
        );
    }

    #[test]
    fn evolution_requires_non_empty_canary_results_dir_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.evolution.enabled = true;
        config.evolution.paths.canary_results_dir = " ".to_string();

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `evolution.paths.canary_results_dir`: must not be empty"
        );
    }

    #[test]
    fn evolution_requires_probability_assurance_floor_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.evolution.enabled = true;
        config.evolution.assurance.min_detector_catch_rate = 1.5;

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `evolution.assurance.min_detector_catch_rate`: must be between 0.0 and 1.0"
        );
    }

    #[test]
    fn evolution_requires_non_empty_allowed_solver_statuses_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.evolution.enabled = true;
        config.evolution.assurance.allowed_solver_statuses.clear();

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `evolution.assurance.allowed_solver_statuses`: must include at least one allowed solver outcome"
        );
    }

    #[test]
    fn evolution_requires_non_empty_assurance_override_detector_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.evolution.enabled = true;
        config.evolution.assurance.coverage_overrides =
            vec![EvolutionAssuranceCoverageOverrideConfig {
                detector: " ".to_string(),
                min_catch_rate: 0.5,
            }];

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `evolution.assurance.coverage_overrides.detector`: entry 0 must not be empty"
        );
    }

    #[test]
    fn evolution_requires_non_empty_assurance_harvest_results_dir_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.evolution.enabled = true;
        config.evolution.assurance.harvest.results_dir = " ".to_string();

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `evolution.assurance.harvest.results_dir`: must not be empty"
        );
    }

    #[test]
    fn evolution_requires_positive_assurance_waiver_ttl_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.evolution.enabled = true;
        config.evolution.assurance.waiver.max_ttl_secs = 0;

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `evolution.assurance.waiver.max_ttl_secs`: must be greater than zero"
        );
    }

    #[test]
    fn evolution_requires_ed25519_assurance_waiver_operator_ids_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.evolution.enabled = true;
        config.evolution.assurance.waiver.allowed_operator_ids = vec!["local-operator".to_string()];

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `evolution.assurance.waiver.allowed_operator_ids`: entry 0 must start with swarm:ed25519:"
        );
    }

    #[test]
    fn memory_requires_non_empty_results_dir_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.memory.enabled = true;
        config.memory.knowledge_graph_results_dir = " ".to_string();

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `memory.knowledge_graph_results_dir`: must not be empty"
        );
    }

    #[test]
    fn memory_requires_positive_temporal_window_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.memory.enabled = true;
        config.memory.temporal_window_secs = 0;

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `memory.temporal_window_secs`: must be greater than zero when memory is enabled"
        );
    }

    #[test]
    fn memory_requires_positive_retention_days_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.memory.enabled = true;
        config.memory.knowledge_retention_days = 0;

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `memory.knowledge_retention_days`: must be greater than zero when memory is enabled"
        );
    }

    #[test]
    fn identity_requires_non_empty_agent_key_dir() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.identity.agent_key_dir = "   ".to_string();

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `identity.agent_key_dir`: must not be empty"
        );
    }

    #[test]
    fn identity_requires_non_empty_registry_dir() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.identity.registry_dir = "   ".to_string();

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `identity.registry_dir`: must not be empty"
        );
    }

    #[test]
    fn sentinel_bridge_requires_http_endpoint() {
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.runtime.telemetry_sources = vec![TelemetrySourceConfig {
            name: "sentinel-primary".to_string(),
            subject: String::new(),
            bridge: Some(TelemetryBridgeConfig::Sentinel {
                config: Box::new(SentinelBridgeConfig {
                    endpoint: "127.0.0.1:9100/metrics".to_string(),
                    scrape_interval_ms: 5_000,
                    scrape_timeout_ms: 3_000,
                    thermal_anomaly_threshold_celsius: 60.0,
                    memory_exhaustion_threshold_percent: 85.0,
                    disk_exhaustion_threshold_percent: 90.0,
                    max_consecutive_failures: 5,
                }),
            }),
        }];

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `runtime.telemetry_sources.bridge.endpoint`: must start with http:// or https://"
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

    #[test]
    fn detection_config_active_strategies_uses_legacy_strategy_when_list_missing() {
        let config: super::DetectionConfig = serde_json::from_value(serde_json::json!({
            "strategy": "suspicious_process_tree",
            "high_confidence_threshold": 0.9,
            "medium_confidence_threshold": 0.7
        }))
        .unwrap();

        assert!(config.strategies.is_empty());
        assert_eq!(config.active_strategies(), vec!["suspicious_process_tree"]);
    }

    #[test]
    fn detection_config_active_strategies_prefers_explicit_list() {
        let config: super::DetectionConfig = serde_json::from_value(serde_json::json!({
            "strategy": "suspicious_process_tree",
            "strategies": ["suspicious_process_tree", "dns_exfiltration"],
            "high_confidence_threshold": 0.9,
            "medium_confidence_threshold": 0.7
        }))
        .unwrap();

        assert_eq!(
            config.active_strategies(),
            vec![
                "suspicious_process_tree".to_string(),
                "dns_exfiltration".to_string()
            ]
        );
    }

    #[test]
    fn rollout_scopes_remain_optional_for_single_strategy_configs() {
        let mut config = valid_config(PheromoneBackendConfig::LocalJournal {
            path: "./journal.jsonl".to_string(),
        });
        config.canary.enabled = true;
        config.promotion.enabled = true;

        config.validate().unwrap();
    }

    #[test]
    fn multi_strategy_canary_requires_explicit_scope() {
        let mut config = valid_config(PheromoneBackendConfig::LocalJournal {
            path: "./journal.jsonl".to_string(),
        });
        config.detection.strategies = vec![
            "suspicious_process_tree".to_string(),
            "dns_exfiltration".to_string(),
        ];
        config.canary.enabled = true;

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `canary.strategy_id`: is required when multiple detection.strategies are active: suspicious_process_tree, dns_exfiltration"
        );
    }

    #[test]
    fn unknown_rollout_strategy_ids_are_rejected() {
        let mut config = valid_config(PheromoneBackendConfig::LocalJournal {
            path: "./journal.jsonl".to_string(),
        });
        config.detection.strategies = vec![
            "suspicious_process_tree".to_string(),
            "dns_exfiltration".to_string(),
        ];
        config.canary.enabled = true;
        config.canary.strategy_id = Some("unknown".to_string());

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `canary.strategy_id`: must match one of detection.active_strategies(): suspicious_process_tree, dns_exfiltration"
        );

        config.canary.strategy_id = Some("dns_exfiltration".to_string());
        config.promotion.strategy_id = Some("unknown".to_string());

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `promotion.strategy_id`: must match one of detection.active_strategies(): suspicious_process_tree, dns_exfiltration"
        );
    }

    #[test]
    fn valid_rollout_scopes_parse_and_validate() {
        let config: SwarmConfig = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "name": "test",
            "description": "test config",
            "runtime": {
                "mode": "live_response",
                "demo_mode": false,
                "telemetry_sources": [
                    {
                        "name": "synthetic",
                        "subject": "telemetry.synthetic.process"
                    }
                ],
                "max_in_flight_actions": 4,
                "drain_timeout_ms": 30000,
                "require_durable_live_response": true,
                "max_heap_pressure": 0.90,
                "agent_tick_timeout_ms": 500,
                "governance_degraded_tick_threshold": 3
            },
            "detection": {
                "strategy": "suspicious_process_tree",
                "strategies": ["suspicious_process_tree", "dns_exfiltration"],
                "high_confidence_threshold": 0.9,
                "medium_confidence_threshold": 0.7
            },
            "pheromone": {
                "default_half_life_secs": 3600.0,
                "evaporation_threshold": 0.01,
                "min_sources_for_escalation": 2,
                "alert_threshold": 2.0,
                "incident_threshold": 5.0,
                "backend": {
                    "kind": "local_journal",
                    "path": "./journal.jsonl"
                }
            },
            "policy": {
                "human_gate_severity": "HIGH",
                "lease_ttl_ms": 60000
            },
            "canary": {
                "enabled": true,
                "slot_id": "canary-primary",
                "strategy_id": "dns_exfiltration",
                "observation_window_events": 2,
                "max_candidate_only_rate": 0.25,
                "max_baseline_miss_rate": 0.25,
                "max_detect_latency_us": 10000,
                "max_total_detections": 8
            },
            "promotion": {
                "enabled": true,
                "window_id": "production-primary",
                "strategy_id": "dns_exfiltration",
                "observation_window_events": 2,
                "max_promoted_only_rate": 0.20,
                "max_fallback_recovery_rate": 0.20,
                "max_detect_latency_us": 10000,
                "max_total_detections": 12
            }
        }))
        .unwrap();

        assert_eq!(
            config.canary.strategy_id.as_deref(),
            Some("dns_exfiltration")
        );
        assert_eq!(
            config.promotion.strategy_id.as_deref(),
            Some("dns_exfiltration")
        );
        config.validate().unwrap();
    }

    #[test]
    fn duplicate_detection_strategy_ids_are_rejected() {
        let mut config = valid_config(PheromoneBackendConfig::LocalJournal {
            path: "./journal.jsonl".to_string(),
        });
        config.detection.strategies = vec![
            "suspicious_process_tree".to_string(),
            "dns_exfiltration".to_string(),
            "dns_exfiltration".to_string(),
        ];

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `detection.strategies`: duplicate detector strategy `dns_exfiltration`"
        );
    }

    #[test]
    fn empty_explicit_detection_strategy_ids_are_rejected() {
        let mut config = valid_config(PheromoneBackendConfig::LocalJournal {
            path: "./journal.jsonl".to_string(),
        });
        config.detection.strategies = vec!["  ".to_string()];

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `detection.strategies`: entries must not be empty"
        );
    }

    #[test]
    fn response_playbook_rules_validate_confidence_ranges() {
        let mut config = valid_config(PheromoneBackendConfig::LocalJournal {
            path: "./journal.jsonl".to_string(),
        });
        config.pheromone.response_playbook = ResponsePlaybookConfig {
            rules: vec![ResponsePlaybookRule {
                threat_class: ThreatClass::Execution,
                severity: Severity::High,
                min_confidence: 0.8,
                max_confidence: 0.5,
                actions: vec![ResponseAction::Escalate {
                    summary: "review required".to_string(),
                    urgency: Severity::High,
                }],
                branches: Vec::new(),
            }],
        };

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `pheromone.response_playbook`: rule 0 max_confidence must be greater than or equal to min_confidence"
        );
    }

    #[test]
    fn response_playbook_branches_reject_empty_action_lists() {
        let mut config = valid_config(PheromoneBackendConfig::LocalJournal {
            path: "./journal.jsonl".to_string(),
        });
        config.pheromone.response_playbook = ResponsePlaybookConfig {
            rules: vec![ResponsePlaybookRule {
                threat_class: ThreatClass::Execution,
                severity: Severity::High,
                min_confidence: 0.8,
                max_confidence: 1.0,
                actions: Vec::new(),
                branches: vec![ResponsePlaybookBranch {
                    name: Some("incident-only".to_string()),
                    when: ResponsePlaybookCondition {
                        modes: vec![SwarmMode::Incident],
                        ..ResponsePlaybookCondition::default()
                    },
                    actions: Vec::new(),
                }],
            }],
        };

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `pheromone.response_playbook`: rule 0 branch 0 must declare at least one response action"
        );
    }

    #[test]
    fn response_playbook_rules_deserialize_from_config_shape() {
        let config: SwarmConfig = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "name": "test",
            "description": "test config",
            "runtime": {
                "mode": "live_response",
                "demo_mode": false,
                "telemetry_sources": [
                    {
                        "name": "synthetic",
                        "subject": "telemetry.synthetic.process"
                    }
                ],
                "max_in_flight_actions": 4,
                "drain_timeout_ms": 30000,
                "require_durable_live_response": true,
                "max_heap_pressure": 0.90,
                "agent_tick_timeout_ms": 500,
                "governance_degraded_tick_threshold": 3
            },
            "detection": {
                "strategy": "suspicious_process_tree",
                "high_confidence_threshold": 0.9,
                "medium_confidence_threshold": 0.7
            },
            "pheromone": {
                "default_half_life_secs": 3600.0,
                "evaporation_threshold": 0.01,
                "min_sources_for_escalation": 2,
                "alert_threshold": 2.0,
                "incident_threshold": 5.0,
                "deescalation_cooldown_secs": 300,
                "response_playbook": {
                    "rules": [
                        {
                            "threat_class": "execution",
                            "severity": "HIGH",
                            "min_confidence": 0.9,
                            "max_confidence": 1.0,
                            "actions": [
                                {
                                    "type": "deploy_decoy",
                                    "decoy_type": "honeypot",
                                    "target_zone": "dmz"
                                },
                                {
                                    "type": "escalate",
                                    "summary": "execution spike requires review",
                                    "urgency": "HIGH"
                                }
                            ]
                        }
                    ]
                },
                "backend": {
                    "kind": "local_journal",
                    "path": "./journal.jsonl"
                }
            },
            "policy": {
                "human_gate_severity": "HIGH",
                "lease_ttl_ms": 60000,
                "max_actions_per_scope_per_minute": 4,
                "rules": [
                    {
                        "name": "execution-after-hours-review",
                        "decision": "allow",
                        "threat_class": "execution",
                        "actions": ["deploy_decoy", "escalate"],
                        "min_severity": "HIGH",
                        "max_severity": "CRITICAL",
                        "time_window_utc": {
                            "start_hour_utc": 18,
                            "end_hour_utc": 24
                        },
                        "max_actions_per_agent_per_minute": 2,
                        "reason": "execution playbook enabled after hours"
                    }
                ]
            }
        }))
        .unwrap();

        assert_eq!(config.pheromone.deescalation_cooldown_secs, 300);
        assert_eq!(config.pheromone.response_playbook.rules.len(), 1);
        assert_eq!(config.policy.max_actions_per_scope_per_minute, 4);
        assert_eq!(config.policy.rules.len(), 1);
        config.validate().unwrap();
    }

    #[test]
    fn response_playbook_branches_deserialize_from_config_shape() {
        let config: SwarmConfig = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "name": "test",
            "description": "test config",
            "runtime": {
                "mode": "live_response",
                "demo_mode": false,
                "telemetry_sources": [
                    {
                        "name": "synthetic",
                        "subject": "telemetry.synthetic.process"
                    }
                ],
                "max_in_flight_actions": 4,
                "drain_timeout_ms": 30000,
                "require_durable_live_response": true,
                "max_heap_pressure": 0.90,
                "agent_tick_timeout_ms": 500,
                "governance_degraded_tick_threshold": 3
            },
            "detection": {
                "strategy": "suspicious_process_tree",
                "high_confidence_threshold": 0.9,
                "medium_confidence_threshold": 0.7
            },
            "pheromone": {
                "default_half_life_secs": 3600.0,
                "evaporation_threshold": 0.01,
                "min_sources_for_escalation": 2,
                "alert_threshold": 2.0,
                "incident_threshold": 5.0,
                "deescalation_cooldown_secs": 300,
                "response_playbook": {
                    "rules": [
                        {
                            "threat_class": "execution",
                            "severity": "HIGH",
                            "min_confidence": 0.9,
                            "max_confidence": 1.0,
                            "actions": [
                                {
                                    "type": "escalate",
                                    "summary": "fallback review",
                                    "urgency": "HIGH"
                                }
                            ],
                            "branches": [
                                {
                                    "name": "incident_containment",
                                    "when": {
                                        "min_confidence": 0.97,
                                        "modes": ["incident"]
                                    },
                                    "actions": [
                                        {
                                            "type": "block_egress",
                                            "target": "203.0.113.10"
                                        },
                                        {
                                            "type": "isolate_host",
                                            "host_id": "host-1"
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                },
                "backend": {
                    "kind": "local_journal",
                    "path": "./journal.jsonl"
                }
            },
            "policy": {
                "human_gate_severity": "HIGH",
                "lease_ttl_ms": 60000
            }
        }))
        .unwrap();

        let rule = &config.pheromone.response_playbook.rules[0];
        assert_eq!(rule.branches.len(), 1);
        assert_eq!(
            rule.branches[0].name.as_deref(),
            Some("incident_containment")
        );
        assert_eq!(rule.branches[0].when.modes, vec![SwarmMode::Incident]);
        assert_eq!(rule.branches[0].actions.len(), 2);
        config.validate().unwrap();
    }

    #[test]
    fn response_playbook_resolve_prefers_first_matching_branch_and_fallback() {
        let playbook = ResponsePlaybookConfig {
            rules: vec![ResponsePlaybookRule {
                threat_class: ThreatClass::Execution,
                severity: Severity::High,
                min_confidence: 0.9,
                max_confidence: 1.0,
                actions: vec![ResponseAction::Escalate {
                    summary: "fallback review".to_string(),
                    urgency: Severity::High,
                }],
                branches: vec![ResponsePlaybookBranch {
                    name: Some("incident_containment".to_string()),
                    when: ResponsePlaybookCondition {
                        min_confidence: Some(0.97),
                        modes: vec![SwarmMode::Incident],
                        ..ResponsePlaybookCondition::default()
                    },
                    actions: vec![
                        ResponseAction::BlockEgress {
                            target: "203.0.113.10".to_string(),
                        },
                        ResponseAction::IsolateHost {
                            host_id: "host-1".to_string(),
                        },
                    ],
                }],
            }],
        };

        let incident = playbook
            .resolve(
                &ThreatClass::Execution,
                Severity::High,
                0.98,
                SwarmMode::Incident,
            )
            .unwrap();
        assert_eq!(
            incident.branch,
            Some(super::ResponsePlaybookBranchResolution {
                index: 0,
                name: Some("incident_containment".to_string()),
            })
        );
        assert_eq!(incident.actions.len(), 2);
        assert!(matches!(
            incident.actions[0],
            ResponseAction::BlockEgress { .. }
        ));

        let fallback = playbook
            .resolve(
                &ThreatClass::Execution,
                Severity::High,
                0.93,
                SwarmMode::Alert,
            )
            .unwrap();
        assert_eq!(fallback.branch, None);
        assert_eq!(
            fallback.actions,
            vec![ResponseAction::Escalate {
                summary: "fallback review".to_string(),
                urgency: Severity::High,
            }]
        );
    }

    #[test]
    fn policy_rules_reject_zero_per_agent_limit() {
        let mut config = valid_config(PheromoneBackendConfig::LocalJournal {
            path: "./journal.jsonl".to_string(),
        });
        config.policy.rules = vec![PolicyRuleConfig {
            name: "deny-execution".to_string(),
            decision: PolicyRuleDecision::Deny,
            threat_class: ThreatClass::Execution,
            actions: vec![PolicyActionSelector::DeployDecoy],
            min_severity: Severity::Medium,
            max_severity: Severity::Critical,
            time_window_utc: Some(PolicyTimeWindowConfig {
                start_hour_utc: 18,
                end_hour_utc: 24,
            }),
            max_actions_per_agent_per_minute: Some(0),
            reason: None,
        }];

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `policy.rules`: rule 0 max_actions_per_agent_per_minute must be greater than zero"
        );
    }

    #[test]
    fn investigation_requires_positive_starvation_boost_when_enabled() {
        let mut config = valid_config(PheromoneBackendConfig::LocalJournal {
            path: "./journal.jsonl".to_string(),
        });
        config.investigation.enabled = true;
        config
            .investigation
            .starvation_boost_per_second_basis_points = 0;

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `investigation.starvation_boost_per_second_basis_points`: must be greater than zero when investigation is enabled"
        );
    }

    #[test]
    fn investigation_requires_ambiguity_margin_within_basis_point_range() {
        let mut config = valid_config(PheromoneBackendConfig::LocalJournal {
            path: "./journal.jsonl".to_string(),
        });
        config.investigation.enabled = true;
        config.investigation.ambiguity_margin_basis_points = 10_001;

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid field `investigation.ambiguity_margin_basis_points`: must be between 1 and 10000 when investigation is enabled"
        );
    }
}
