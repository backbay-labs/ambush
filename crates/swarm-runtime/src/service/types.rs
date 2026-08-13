use super::*;

/// Errors raised by the runtime service wrapper.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error(transparent)]
    Pipeline(#[from] PipelineError),

    #[error(transparent)]
    Substrate(#[from] SubstrateError),

    #[error(transparent)]
    Runtime(#[from] RuntimeError),

    #[error(transparent)]
    ReplayStore(#[from] ReplayStoreError),

    #[error(transparent)]
    Investigation(#[from] InvestigationError),

    #[error(transparent)]
    Correlation(#[from] CorrelationError),

    #[error(transparent)]
    DetectorProfile(#[from] DetectorProfileError),

    #[error(transparent)]
    SequenceDetector(#[from] KillChainSequenceDetectorError),

    #[error(transparent)]
    Approval(#[from] ApprovalError),

    #[error("failed to write replay bundle `{path}`: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read replay bundle `{path}`: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to serialize replay bundle: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("failed to build rehearsal preview: {0}")]
    RehearsalPreview(#[from] RehearsalPreviewError),

    #[error("runtime readiness check failed for {component}: {source}")]
    Readiness {
        component: &'static str,
        #[source]
        source: ReadinessError,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum RehearsalPreviewError {
    #[error("{label} must not be empty")]
    EmptyValue { label: &'static str },

    #[error("{action} did not produce a scoped lease target")]
    MissingScopeTarget { action: &'static str },

    #[error("{action} does not have preview metadata")]
    UnsupportedAction { action: &'static str },
}

#[derive(Debug, thiserror::Error)]
pub enum ReadinessError {
    #[error("backend `{backend}` is not ready")]
    SubstrateNotReady { backend: String },

    #[error("backend `{backend}` is not durable but live response requires durability")]
    SubstrateNotDurable { backend: String },
}

/// Inputs that stay constant while processing one event through the critical lane.
pub struct EventExecutionContext<'a> {
    pub agent_id: &'a AgentId,
    pub approval: &'a ApprovalContext,
    pub signing_key: &'a ed25519_dalek::SigningKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyBucketSnapshot {
    pub upper_bound_us: u64,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageMetricsSnapshot {
    pub successes: u64,
    pub failures: u64,
    pub total_latency_us: u64,
    pub max_latency_us: u64,
    pub average_latency_us: u64,
    pub latency_buckets: Vec<LatencyBucketSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeMetricsSnapshot {
    pub detect: StageMetricsSnapshot,
    pub policy: StageMetricsSnapshot,
    pub persist: StageMetricsSnapshot,
    pub response: StageMetricsSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStatus {
    pub ready: bool,
    pub durable: Option<bool>,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDegradationTriggerKind {
    ConfiguredMode,
    AgentHealth,
    Detector,
    Substrate,
    ReplayStore,
    StartupAttestation,
    AntiTamper,
    HeapPressure,
    Draining,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeDegradationTrigger {
    pub kind: RuntimeDegradationTriggerKind,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeDegradationCapabilities {
    pub accepts_ingest: bool,
    pub allows_detection: bool,
    pub allows_live_response: bool,
    pub allows_artifact_writes: bool,
    pub operator_read_surfaces_ready: bool,
    pub drains_ingest: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeDegradationStatus {
    pub level: RuntimeDegradationLevel,
    pub configured_mode: RuntimeMode,
    pub ready: bool,
    pub summary: String,
    pub capabilities: RuntimeDegradationCapabilities,
    #[serde(default)]
    pub triggers: Vec<RuntimeDegradationTrigger>,
    pub transitioned_at_ms: i64,
}
pub struct RuntimeDegradationSignals {
    pub configured_mode: RuntimeMode,
    pub detector_ready: bool,
    pub substrate_ready: bool,
    pub replay_store_ready: bool,
    pub startup_attestation_ready: bool,
    pub anti_tamper_ready: bool,
    pub heap_ready: bool,
    pub draining: bool,
    pub degraded_agents: usize,
    pub failed_agents: usize,
    pub transitioned_at_ms: i64,
}

impl RuntimeDegradationStatus {
    pub fn same_state_as(&self, other: &Self) -> bool {
        self.level == other.level
            && self.configured_mode == other.configured_mode
            && self.ready == other.ready
            && self.summary == other.summary
            && self.capabilities == other.capabilities
            && self.triggers == other.triggers
    }
}

impl Default for RuntimeDegradationStatus {
    fn default() -> Self {
        let configured_mode = RuntimeMode::DetectOnly;
        let level = RuntimeDegradationLevel::DetectOnly;
        Self {
            level,
            configured_mode,
            ready: level.ready(),
            summary: "runtime is limited to detect-only execution by configuration".to_string(),
            capabilities: runtime_degradation_capabilities(level, configured_mode),
            triggers: vec![RuntimeDegradationTrigger {
                kind: RuntimeDegradationTriggerKind::ConfiguredMode,
                details: "configured runtime mode is detect_only".to_string(),
            }],
            transitioned_at_ms: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorStatusReport {
    pub mode: RuntimeMode,
    pub active_detectors: Vec<String>,
    pub degradation: RuntimeDegradationStatus,
    pub detector: ComponentStatus,
    pub substrate: ComponentStatus,
    pub policy: ComponentStatus,
    pub response: ComponentStatus,
    pub replay_store: ComponentStatus,
    pub providence: Option<ProvidenceHealthStatus>,
    pub bridges: Option<BridgeStatusReport>,
    pub metrics: RuntimeMetricsSnapshot,
    pub recent_finding_count: usize,
    pub recent_decisions: Vec<ReplayBundleRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_escalation: Option<OperatorEscalationSummary>,
    pub async_lane: AsyncLaneStatusSnapshot,
    pub investigation_review: Option<InvestigationReviewStatus>,
    pub incident_review: Option<IncidentReviewStatus>,
    pub freshness: ReviewFreshness,
    pub evolution: Option<EvolutionStatusReport>,
    pub false_positive_tracking: FalsePositiveMeasurementReport,
    pub alert_tuning: AlertTuningReport,
    pub bearer_tokens: Vec<OperatorBearerTokenStatus>,
    pub rate_limit: HttpRateLimitStatus,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorEscalationSummary {
    pub mode: SwarmMode,
    pub threat_class: ThreatClass,
    pub timestamp: i64,
    pub distinct_sources: usize,
    pub total_strength: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorBearerTokenStatus {
    pub operator_id: String,
    pub token_env: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<i64>,
    pub expired: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationReviewStatus {
    pub queue: InvestigationQueueSnapshot,
    pub store: ComponentStatus,
    pub recent: Vec<InvestigationBundleRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentReviewStatus {
    pub store: ComponentStatus,
    pub recent: Vec<IncidentRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReviewFreshness {
    pub latest_hot_path_decision_at_ms: Option<i64>,
    pub latest_investigation_update_at_ms: Option<i64>,
    pub latest_incident_at_ms: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct PersistedReplayBundle {
    pub record: ReplayBundleRecord,
    pub bundle: ReplayBundle,
}

#[derive(Debug, Clone)]
pub struct PersistedReplayBundleWithInvestigation {
    pub replay: PersistedReplayBundle,
    pub investigation: Option<InvestigationBundleRecord>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResponsePlaybookPreviewRequest {
    pub threat_class: ThreatClass,
    pub severity: Severity,
    pub confidence: f64,
    pub mode: SwarmMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponsePlaybookPreviewStatus {
    Matched,
    NoMatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponsePlaybookPolicyPreview {
    pub verdict: PolicyVerdict,
    pub rule_name: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_expires_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResponsePlaybookActionPreview {
    pub order: usize,
    pub action: ResponseAction,
    pub rehearsal: ResponseRehearsalPreview,
    pub policy: ResponsePlaybookPolicyPreview,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponsePlaybookApprovalSummary {
    pub allow_count: usize,
    pub require_human_count: usize,
    pub deny_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResponsePlaybookPreviewReport {
    pub status: ResponsePlaybookPreviewStatus,
    pub configured_runtime_mode: RuntimeMode,
    pub request: ResponsePlaybookPreviewRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<ResponsePlaybookRuleResolution>,
    #[serde(default)]
    pub actions: Vec<ResponsePlaybookActionPreview>,
    pub approval_summary: ResponsePlaybookApprovalSummary,
    #[serde(default)]
    pub notes: Vec<String>,
}

impl OperatorStatusReport {
    pub fn with_bridges(mut self, bridges: BridgeStatusReport) -> Self {
        if bridges.has_degraded() {
            self.warnings
                .push(format!("{} telemetry bridge(s) degraded", bridges.degraded));
        }
        self.bridges = Some(bridges);
        self
    }

    pub fn with_evolution(mut self, evolution: EvolutionStatusReport) -> Self {
        self.evolution = Some(evolution);
        self
    }
}

pub fn derive_runtime_degradation_status(
    signals: RuntimeDegradationSignals,
) -> RuntimeDegradationStatus {
    let mut detect_only_triggers = Vec::new();
    let mut read_only_triggers = Vec::new();
    let mut emergency_triggers = Vec::new();

    if signals.configured_mode == RuntimeMode::DetectOnly {
        detect_only_triggers.push(RuntimeDegradationTrigger {
            kind: RuntimeDegradationTriggerKind::ConfiguredMode,
            details: "configured runtime mode is detect_only".to_string(),
        });
    }
    if !signals.substrate_ready {
        detect_only_triggers.push(RuntimeDegradationTrigger {
            kind: RuntimeDegradationTriggerKind::Substrate,
            details: "substrate health is not ready for live response".to_string(),
        });
    }
    if signals.degraded_agents > 0 || signals.failed_agents > 0 {
        detect_only_triggers.push(RuntimeDegradationTrigger {
            kind: RuntimeDegradationTriggerKind::AgentHealth,
            details: format!(
                "{} degraded and {} failed agent(s) are active",
                signals.degraded_agents, signals.failed_agents
            ),
        });
    }

    if !signals.detector_ready {
        read_only_triggers.push(RuntimeDegradationTrigger {
            kind: RuntimeDegradationTriggerKind::Detector,
            details: "detector runtime is not ready".to_string(),
        });
    }
    if !signals.replay_store_ready {
        read_only_triggers.push(RuntimeDegradationTrigger {
            kind: RuntimeDegradationTriggerKind::ReplayStore,
            details: "replay store health is not ready".to_string(),
        });
    }

    if !signals.startup_attestation_ready {
        emergency_triggers.push(RuntimeDegradationTrigger {
            kind: RuntimeDegradationTriggerKind::StartupAttestation,
            details: "startup attestation is not ready for the configured runtime mode".to_string(),
        });
    }
    if !signals.anti_tamper_ready {
        emergency_triggers.push(RuntimeDegradationTrigger {
            kind: RuntimeDegradationTriggerKind::AntiTamper,
            details: "anti-tamper monitoring is not effectively ready".to_string(),
        });
    }
    if !signals.heap_ready {
        emergency_triggers.push(RuntimeDegradationTrigger {
            kind: RuntimeDegradationTriggerKind::HeapPressure,
            details: "heap pressure exceeded the configured readiness threshold".to_string(),
        });
    }
    if signals.draining {
        emergency_triggers.push(RuntimeDegradationTrigger {
            kind: RuntimeDegradationTriggerKind::Draining,
            details: "runtime drain has been requested".to_string(),
        });
    }

    let (level, triggers, summary) = if !emergency_triggers.is_empty() {
        (
            RuntimeDegradationLevel::EmergencyDrain,
            emergency_triggers,
            "runtime is in emergency drain and rejecting new ingest".to_string(),
        )
    } else if !read_only_triggers.is_empty() {
        (
            RuntimeDegradationLevel::ReadOnly,
            read_only_triggers,
            "runtime is limited to operator read surfaces while critical write-path health is degraded"
                .to_string(),
        )
    } else if !detect_only_triggers.is_empty() {
        (
            RuntimeDegradationLevel::DetectOnly,
            detect_only_triggers,
            "runtime is limited to detect-only execution".to_string(),
        )
    } else {
        (
            RuntimeDegradationLevel::Full,
            Vec::new(),
            "runtime is operating with full response capability".to_string(),
        )
    };

    RuntimeDegradationStatus {
        level,
        configured_mode: signals.configured_mode,
        ready: level.ready(),
        summary,
        capabilities: runtime_degradation_capabilities(level, signals.configured_mode),
        triggers,
        transitioned_at_ms: signals.transitioned_at_ms,
    }
}

fn runtime_degradation_capabilities(
    level: RuntimeDegradationLevel,
    configured_mode: RuntimeMode,
) -> RuntimeDegradationCapabilities {
    RuntimeDegradationCapabilities {
        accepts_ingest: level.accepts_ingest(),
        allows_detection: level.allows_detection(),
        allows_live_response: level.allows_live_response(configured_mode),
        allows_artifact_writes: level.allows_artifact_writes(),
        operator_read_surfaces_ready: level.operator_read_surfaces_ready(),
        drains_ingest: level.drains_ingest(),
    }
}

/// Repository-configured runtime stack that composes critical-lane and async review components.
pub struct ConfiguredRuntimeStack<P, E, Strategy> {
    pub service: RuntimeService<P, E>,
    pub substrate: ConfiguredPheromoneSubstrate,
    pub replay_store: ConfiguredReplayBundleStore,
    pub investigation: InvestigationCoordinator<Strategy, ConfiguredInvestigationBundleStore>,
    pub investigation_store: ConfiguredInvestigationBundleStore,
    pub correlation: CorrelationEngine,
    pub incident_store: ConfiguredIncidentStore,
}

#[derive(Debug, Clone, Default)]
pub(super) struct RuntimeMetrics {
    inner: Arc<Mutex<RuntimeMetricsInner>>,
}

#[derive(Debug, Clone, Default)]
struct RuntimeMetricsInner {
    detect: StageMetrics,
    policy: StageMetrics,
    persist: StageMetrics,
    response: StageMetrics,
}

#[derive(Debug, Clone)]
struct StageMetrics {
    successes: u64,
    failures: u64,
    total_latency_us: u64,
    max_latency_us: u64,
    bucket_counts: [u64; LATENCY_BUCKETS_US.len()],
}

impl Default for StageMetrics {
    fn default() -> Self {
        Self {
            successes: 0,
            failures: 0,
            total_latency_us: 0,
            max_latency_us: 0,
            bucket_counts: [0; LATENCY_BUCKETS_US.len()],
        }
    }
}

impl RuntimeMetrics {
    pub(super) fn record(&self, stage: RuntimeStage, elapsed_us: u64, success: bool) {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let target = match stage {
            RuntimeStage::Detect => &mut guard.detect,
            RuntimeStage::Policy => &mut guard.policy,
            RuntimeStage::Persist => &mut guard.persist,
            RuntimeStage::Response => &mut guard.response,
        };

        if success {
            target.successes = target.successes.saturating_add(1);
        } else {
            target.failures = target.failures.saturating_add(1);
        }
        target.total_latency_us = target.total_latency_us.saturating_add(elapsed_us);
        target.max_latency_us = target.max_latency_us.max(elapsed_us);
        let bucket_index = LATENCY_BUCKETS_US
            .iter()
            .position(|upper_bound| elapsed_us <= *upper_bound)
            .unwrap_or(LATENCY_BUCKETS_US.len() - 1);
        target.bucket_counts[bucket_index] = target.bucket_counts[bucket_index].saturating_add(1);
    }

    pub(super) fn snapshot(&self) -> RuntimeMetricsSnapshot {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        RuntimeMetricsSnapshot {
            detect: StageMetricsSnapshot::from_metrics(&guard.detect),
            policy: StageMetricsSnapshot::from_metrics(&guard.policy),
            persist: StageMetricsSnapshot::from_metrics(&guard.persist),
            response: StageMetricsSnapshot::from_metrics(&guard.response),
        }
    }
}

impl StageMetricsSnapshot {
    fn from_metrics(metrics: &StageMetrics) -> Self {
        let total = metrics.successes + metrics.failures;
        Self {
            successes: metrics.successes,
            failures: metrics.failures,
            total_latency_us: metrics.total_latency_us,
            max_latency_us: metrics.max_latency_us,
            average_latency_us: metrics.total_latency_us.checked_div(total).unwrap_or(0),
            latency_buckets: LATENCY_BUCKETS_US
                .iter()
                .zip(metrics.bucket_counts.iter())
                .map(|(upper_bound_us, count)| LatencyBucketSnapshot {
                    upper_bound_us: *upper_bound_us,
                    count: *count,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum RuntimeStage {
    Detect,
    Policy,
    Persist,
    Response,
}

const LATENCY_BUCKETS_US: [u64; 7] = [100, 500, 1_000, 5_000, 10_000, 50_000, u64::MAX];
