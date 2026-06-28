use crate::alert_tuning::{AlertTuningReport, build_alert_tuning_report};
use crate::bridge_runtime::BridgeStatusReport;
use crate::config::{DetectorProfileError, RuntimeConfig, kill_chain_sequence_profile};
use crate::correlation::{CorrelationEngine, CorrelationError, CorrelationOutcome};
use crate::detection::metrics::CriticalPathMetrics;
use crate::detection::pipeline::{
    DetectionPipelineOutcome, PipelineError, detect_and_deposit, infer_agent_role,
    persist_findings_as_deposits,
};
use crate::evolution_status::EvolutionStatusReport;
use crate::investigation::{
    InvestigationCoordinator, InvestigationError, InvestigationQueueSnapshot, InvestigationStrategy,
};
use crate::providence::{PROVIDENCE_CHANNEL, ProvidenceHealthStatus};
use crate::runtime_events::{AsyncLaneStatusLevel, AsyncLaneStatusSnapshot, now_ms};
use crate::sequence_detector::{
    KILL_CHAIN_SEQUENCE_STRATEGY_ID, KillChainSequenceDetector, KillChainSequenceDetectorError,
};
use crate::{RuntimeError, RuntimeMode, SwarmRuntime};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::any::type_name;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use swarm_core::agent::SwarmMode;
use swarm_core::config::{ResponsePlaybookRuleResolution, RuntimeDegradationLevel, SwarmConfig};
use swarm_core::observability::with_trace_id;
use swarm_core::pheromone::ThreatClass;
use swarm_core::telemetry::TelemetryPayload;
use swarm_core::types::{
    AgentId, ResponseAction, ResponseBlastRadiusImpact, ResponseBlastRadiusPreview,
    ResponseRehearsalPreview, ResponseRehearsalScopeKind, ResponseRollbackPreview,
    ResponseRollbackStep, ResponseRollbackStepKind, Severity,
};
use swarm_pheromone::{
    ConfiguredPheromoneSubstrate, PheromoneSubstrate, SubstrateError, SubstrateHealth,
};
use swarm_policy::ApprovalGate;
use swarm_policy::configurable_gate::ConfigurableApprovalGate;
use swarm_policy::static_gate::scope_for_response_action;
use swarm_policy::{ActionRequest, ApprovalContext, ApprovalError, PolicyVerdict};
use swarm_response::{
    DispatchingExecutor, NotificationRouter, ResponseExecutor, SiemFindingForwarder,
};
use swarm_spine::{
    AuditResponseRecord, ConfiguredIncidentStore, ConfiguredInvestigationBundleStore,
    ConfiguredReplayBundleStore, FalsePositiveMeasurementReport, IncidentLookup, IncidentRecord,
    IncidentStore, IncidentStoreHealth, InvestigationBundleLookup, InvestigationBundleRecord,
    InvestigationBundleStore, InvestigationStoreHealth, ReplayBundle, ReplayBundleLookup,
    ReplayBundleRecord, ReplayBundleStore, ReplayPreview, ReplayStoreError, ReplayStoreHealth,
    summarize_false_positive_measurements,
};
use swarm_whisker::{DetectionFinding, DetectionStrategy, TelemetryEvent};
use tracing::Instrument as _;

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

#[derive(Debug, Clone, Copy)]
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
    pub degradation: RuntimeDegradationStatus,
    pub detector: ComponentStatus,
    pub substrate: ComponentStatus,
    pub policy: ComponentStatus,
    pub response: ComponentStatus,
    pub replay_store: ComponentStatus,
    pub providence: Option<ProvidenceHealthStatus>,
    pub bridges: Option<BridgeStatusReport>,
    pub metrics: RuntimeMetricsSnapshot,
    pub recent_decisions: Vec<ReplayBundleRecord>,
    pub async_lane: AsyncLaneStatusSnapshot,
    pub investigation_review: Option<InvestigationReviewStatus>,
    pub incident_review: Option<IncidentReviewStatus>,
    pub freshness: ReviewFreshness,
    pub evolution: Option<EvolutionStatusReport>,
    pub false_positive_tracking: FalsePositiveMeasurementReport,
    pub alert_tuning: AlertTuningReport,
    pub warnings: Vec<String>,
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
struct RuntimeMetrics {
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
    fn record(&self, stage: RuntimeStage, elapsed_us: u64, success: bool) {
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

    fn snapshot(&self) -> RuntimeMetricsSnapshot {
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
            average_latency_us: if total == 0 {
                0
            } else {
                metrics.total_latency_us / total
            },
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
enum RuntimeStage {
    Detect,
    Policy,
    Persist,
    Response,
}

const LATENCY_BUCKETS_US: [u64; 7] = [100, 500, 1_000, 5_000, 10_000, 50_000, u64::MAX];

#[derive(Debug, Clone, Copy, Default)]
struct FindingEnrichmentService;

impl FindingEnrichmentService {
    fn enrich(
        &self,
        event: &TelemetryEvent,
        findings: Vec<DetectionFinding>,
        detected_at_ms: i64,
    ) -> Vec<DetectionFinding> {
        findings
            .into_iter()
            .map(|finding| DetectionFinding {
                evidence: enrich_finding_evidence(event, finding.evidence, detected_at_ms),
                ..finding
            })
            .collect()
    }
}

fn approval_correlation_id(context: &ApprovalContext) -> &str {
    context.correlation_id.as_deref().unwrap_or("unknown")
}

fn threat_class_label(threat_class: &ThreatClass) -> &str {
    match threat_class {
        ThreatClass::LateralMovement => "lateral_movement",
        ThreatClass::DataExfiltration => "data_exfiltration",
        ThreatClass::PrivilegeEscalation => "privilege_escalation",
        ThreatClass::CommandAndControl => "command_and_control",
        ThreatClass::InitialAccess => "initial_access",
        ThreatClass::Persistence => "persistence",
        ThreatClass::SupplyChain => "supply_chain",
        ThreatClass::DefenseEvasion => "defense_evasion",
        ThreatClass::CredentialAccess => "credential_access",
        ThreatClass::Discovery => "discovery",
        ThreatClass::Execution => "execution",
        ThreatClass::Impact => "impact",
        ThreatClass::Custom(value) => value.as_str(),
    }
}

fn verdict_label(verdict: PolicyVerdict) -> &'static str {
    match verdict {
        PolicyVerdict::Deny => "deny",
        PolicyVerdict::Allow => "allow",
        PolicyVerdict::RequireHuman => "require_human",
    }
}

fn adapter_outcome_label(response: &AuditResponseRecord) -> Option<&'static str> {
    match response {
        AuditResponseRecord::Success(_) => Some("success"),
        AuditResponseRecord::Failure(failure) => {
            let is_timeout = failure
                .details
                .get("status")
                .and_then(serde_json::Value::as_str)
                == Some("timeout");
            Some(if is_timeout { "timeout" } else { "failure" })
        }
        AuditResponseRecord::Skipped { .. } | AuditResponseRecord::GuardRejected { .. } => None,
    }
}

fn merge_rehearsal_receipt_chain(
    approval: &ApprovalContext,
    source: &ReplayBundle,
) -> ApprovalContext {
    let mut receipt_chain = approval.receipt_chain.clone();
    for receipt_id in source.audit.all_receipt_ids() {
        if !receipt_chain.iter().any(|existing| existing == &receipt_id) {
            receipt_chain.push(receipt_id);
        }
    }
    ApprovalContext {
        receipt_chain,
        ..approval.clone()
    }
}

fn build_rehearsal_preview(
    request: &ActionRequest,
    source_bundle_id: &str,
    prepared_at_ms: i64,
) -> Result<ResponseRehearsalPreview, ServiceError> {
    fn require_value(label: &'static str, value: &str) -> Result<String, RehearsalPreviewError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(RehearsalPreviewError::EmptyValue { label });
        }
        Ok(trimmed.to_string())
    }

    fn preview(
        rehearsal_id: &str,
        source_bundle_id: &str,
        prepared_at_ms: i64,
        blast_radius: ResponseBlastRadiusPreview,
        rollback: ResponseRollbackPreview,
    ) -> ResponseRehearsalPreview {
        ResponseRehearsalPreview {
            rehearsal_id: rehearsal_id.to_string(),
            source_bundle_id: source_bundle_id.to_string(),
            prepared_at_ms,
            simulated_only: true,
            blast_radius,
            rollback,
        }
    }

    fn rollback_step(
        kind: ResponseRollbackStepKind,
        summary: impl Into<String>,
    ) -> ResponseRollbackStep {
        ResponseRollbackStep {
            kind,
            summary: summary.into(),
        }
    }

    let rehearsal_id = format!("rehearsal:{}:{}", request.hunt_id.0, prepared_at_ms);

    let preview = match &request.action {
        ResponseAction::BlockEgress { .. } => {
            let scope_value = scope_for_response_action(&request.action).ok_or(
                RehearsalPreviewError::MissingScopeTarget {
                    action: "block_egress",
                },
            )?;
            let target = require_value("block target", &scope_value)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::NetworkTarget,
                    scope_value: target.clone(),
                    impact: ResponseBlastRadiusImpact::NetworkEgressBlocked,
                    max_affected_scopes: 1,
                    affected_capabilities: vec!["egress_connectivity".to_string()],
                    summary: format!(
                        "Blocks outbound connectivity to the scoped network target `{target}`"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Remove the temporary egress deny rule for `{target}` to restore traffic"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::RemoveNetworkBlock,
                        format!(
                            "Remove the egress deny rule for `{target}` and confirm traffic flows normally"
                        ),
                    )],
                },
            )
        }
        ResponseAction::IsolateHost { .. } => {
            let scope_value = scope_for_response_action(&request.action).ok_or(
                RehearsalPreviewError::MissingScopeTarget {
                    action: "isolate_host",
                },
            )?;
            let host_id = require_value("host_id", &scope_value)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::Host,
                    scope_value: host_id.clone(),
                    impact: ResponseBlastRadiusImpact::HostConnectivityIsolated,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "network_connectivity".to_string(),
                        "remote_management".to_string(),
                    ],
                    summary: format!(
                        "Cuts the scoped host `{host_id}` off from normal network communication"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Restore normal connectivity for the isolated host `{host_id}`"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::RestoreHostConnectivity,
                        format!(
                            "Remove the isolation policy for `{host_id}` and verify host reachability"
                        ),
                    )],
                },
            )
        }
        ResponseAction::RevokeCredential { .. } => {
            let scope_value = scope_for_response_action(&request.action).ok_or(
                RehearsalPreviewError::MissingScopeTarget {
                    action: "revoke_credential",
                },
            )?;
            let credential_id = require_value("credential_id", &scope_value)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::Credential,
                    scope_value: credential_id.clone(),
                    impact: ResponseBlastRadiusImpact::CredentialAccessRevoked,
                    max_affected_scopes: 1,
                    affected_capabilities: vec!["credential_authentication".to_string()],
                    summary: format!(
                        "Removes the scoped credential `{credential_id}` from future authentication attempts"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Restore or rotate the revoked credential `{credential_id}` with bounded access"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::RestoreCredential,
                        format!(
                            "Reissue or restore `{credential_id}` after validation of the owning principal"
                        ),
                    )],
                },
            )
        }
        ResponseAction::SinkholeDns { domain } => {
            let domain = require_value("domain", domain)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::NetworkTarget,
                    scope_value: domain.clone(),
                    impact: ResponseBlastRadiusImpact::DnsResolutionSinkholed,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "dns_resolution".to_string(),
                        "domain_reachability".to_string(),
                    ],
                    summary: format!(
                        "Redirects name resolution for the scoped domain `{domain}` to a controlled sinkhole target"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Remove the sinkhole override for `{domain}` to restore normal DNS answers"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::RemoveDnsSinkhole,
                        format!(
                            "Delete the sinkhole record for `{domain}` and confirm DNS responses return to baseline"
                        ),
                    )],
                },
            )
        }
        ResponseAction::TerminateUserSession {
            host_id,
            session_id,
        } => {
            let host_id = require_value("host_id", host_id)?;
            let session_id = require_value("session_id", session_id)?;
            let scope_value = format!("{host_id}:{session_id}");
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::UserSession,
                    scope_value: scope_value.clone(),
                    impact: ResponseBlastRadiusImpact::UserSessionTerminated,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "interactive_session".to_string(),
                        "session_bound_credentials".to_string(),
                    ],
                    summary: format!(
                        "Ends the scoped session `{session_id}` on host `{host_id}` and forces that principal to reconnect"
                    ),
                },
                ResponseRollbackPreview {
                    required: false,
                    summary: format!(
                        "The terminated session `{session_id}` cannot be resumed; if this was a false positive, the user must establish a fresh session on `{host_id}`"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::ReauthenticateUserSession,
                        format!(
                            "After validation, allow the principal tied to `{session_id}` to authenticate again on `{host_id}`"
                        ),
                    )],
                },
            )
        }
        ResponseAction::TriggerEdrScan {
            host_id,
            scan_profile,
        } => {
            let host_id = require_value("host_id", host_id)?;
            let scan_profile = require_value("scan_profile", scan_profile)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::Host,
                    scope_value: host_id.clone(),
                    impact: ResponseBlastRadiusImpact::HostScanTriggered,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "endpoint_scan_capacity".to_string(),
                        "cpu_headroom".to_string(),
                    ],
                    summary: format!(
                        "Starts the EDR scan profile `{scan_profile}` on host `{host_id}`, consuming bounded endpoint inspection capacity"
                    ),
                },
                ResponseRollbackPreview {
                    required: false,
                    summary: format!(
                        "The scan job is non-destructive; cancel the `{scan_profile}` scan on `{host_id}` only if it was launched in error"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::CancelHostScan,
                        format!(
                            "Cancel the active `{scan_profile}` EDR scan on `{host_id}` or allow it to complete if the load is acceptable"
                        ),
                    )],
                },
            )
        }
        ResponseAction::InjectFirewallRule {
            host_id,
            rule_name,
            direction,
            cidr,
            port,
        } => {
            let host_id = require_value("host_id", host_id)?;
            let rule_name = require_value("rule_name", rule_name)?;
            let direction = require_value("direction", direction)?;
            let cidr = require_value("cidr", cidr)?;
            let port_clause = port
                .map(|value| format!(" on port `{value}`"))
                .unwrap_or_default();
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::Host,
                    scope_value: host_id.clone(),
                    impact: ResponseBlastRadiusImpact::HostFirewallPolicyChanged,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "host_network_connectivity".to_string(),
                        "firewall_policy".to_string(),
                    ],
                    summary: format!(
                        "Adds firewall rule `{rule_name}` on host `{host_id}` for {direction} traffic matching `{cidr}`{port_clause}"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Remove firewall rule `{rule_name}` from `{host_id}` to restore the pre-action policy"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::RemoveFirewallRule,
                        format!(
                            "Delete firewall rule `{rule_name}` from `{host_id}` and verify expected traffic resumes"
                        ),
                    )],
                },
            )
        }
        ResponseAction::QuarantineFile { host_id, file_path } => {
            let host_id = require_value("host_id", host_id)?;
            let file_path = require_value("file_path", file_path)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::File,
                    scope_value: format!("{host_id}:{file_path}"),
                    impact: ResponseBlastRadiusImpact::FileQuarantined,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "file_access".to_string(),
                        "file_execution".to_string(),
                    ],
                    summary: format!(
                        "Moves the scoped file `{file_path}` on host `{host_id}` into quarantine, blocking normal access and execution"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Release `{file_path}` from quarantine on `{host_id}` only after validating it is benign"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::ReleaseQuarantinedFile,
                        format!(
                            "Restore `{file_path}` to its original location on `{host_id}` and confirm the file hash matches the approved baseline"
                        ),
                    )],
                },
            )
        }
        ResponseAction::KillProcess {
            host_id,
            process_name,
        } => {
            let host_id = require_value("host_id", host_id)?;
            let process_name = require_value("process_name", process_name)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::Process,
                    scope_value: format!("{host_id}:{process_name}"),
                    impact: ResponseBlastRadiusImpact::ProcessTerminated,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "process_execution".to_string(),
                        "task_continuity".to_string(),
                    ],
                    summary: format!(
                        "Terminates process `{process_name}` on host `{host_id}`, immediately interrupting that workload"
                    ),
                },
                ResponseRollbackPreview {
                    required: false,
                    summary: format!(
                        "The terminated process `{process_name}` does not resume automatically; restart it only if post-review confirms the workload is benign"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::RestartProcess,
                        format!(
                            "Relaunch the approved `{process_name}` workload on `{host_id}` with normal supervision if business impact warrants recovery"
                        ),
                    )],
                },
            )
        }
        ResponseAction::SuspendProcess {
            host_id,
            process_name,
        } => {
            let host_id = require_value("host_id", host_id)?;
            let process_name = require_value("process_name", process_name)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::Process,
                    scope_value: format!("{host_id}:{process_name}"),
                    impact: ResponseBlastRadiusImpact::ProcessSuspended,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "process_execution".to_string(),
                        "interactive_task_progress".to_string(),
                    ],
                    summary: format!(
                        "Suspends process `{process_name}` on host `{host_id}`, pausing its execution without removing it from memory"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Resume suspended process `{process_name}` on `{host_id}` if the action is later judged unnecessary"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::ResumeProcess,
                        format!(
                            "Resume process `{process_name}` on `{host_id}` and confirm it returns to the expected execution state"
                        ),
                    )],
                },
            )
        }
        ResponseAction::DisableUserAccount { user_id } => {
            let user_id = require_value("user_id", user_id)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::UserAccount,
                    scope_value: user_id.clone(),
                    impact: ResponseBlastRadiusImpact::UserAccountDisabled,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "interactive_authentication".to_string(),
                        "privileged_access".to_string(),
                    ],
                    summary: format!(
                        "Disables user account `{user_id}`, blocking new authentication and inherited access"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Re-enable account `{user_id}` only after identity validation and scope review"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::ReenableUserAccount,
                        format!(
                            "Restore account `{user_id}` and confirm its expected group membership and MFA state before the next login"
                        ),
                    )],
                },
            )
        }
        ResponseAction::ForcePasswordReset { user_id } => {
            let user_id = require_value("user_id", user_id)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::UserAccount,
                    scope_value: user_id.clone(),
                    impact: ResponseBlastRadiusImpact::PasswordResetEnforced,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "interactive_authentication".to_string(),
                        "credential_rotation".to_string(),
                    ],
                    summary: format!(
                        "Marks account `{user_id}` for password reset before the next successful login"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Clear the forced-reset requirement for `{user_id}` only if the reset was queued in error"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::ClearPasswordResetRequirement,
                        format!(
                            "Remove the forced-reset flag for `{user_id}` or issue a controlled temporary credential after validation"
                        ),
                    )],
                },
            )
        }
        ResponseAction::RemoveScheduledTask { host_id, task_name } => {
            let host_id = require_value("host_id", host_id)?;
            let task_name = require_value("task_name", task_name)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::ScheduledTask,
                    scope_value: format!("{host_id}:{task_name}"),
                    impact: ResponseBlastRadiusImpact::ScheduledTaskRemoved,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "scheduled_automation".to_string(),
                        "task_execution".to_string(),
                    ],
                    summary: format!(
                        "Deletes scheduled task `{task_name}` from host `{host_id}`, preventing future automated execution"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Recreate scheduled task `{task_name}` on `{host_id}` if the removal was not justified"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::RestoreScheduledTask,
                        format!(
                            "Restore scheduled task `{task_name}` on `{host_id}` with its approved trigger and command definition"
                        ),
                    )],
                },
            )
        }
        ResponseAction::DeployDecoy { decoy_type, .. } => {
            let decoy_type = require_value("decoy_type", decoy_type)?;
            let zone = scope_for_response_action(&request.action).ok_or(
                RehearsalPreviewError::MissingScopeTarget {
                    action: "deploy_decoy",
                },
            )?;
            let zone = require_value("target_zone", &zone)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::Zone,
                    scope_value: zone.clone(),
                    impact: ResponseBlastRadiusImpact::DeceptionCoverageChanged,
                    max_affected_scopes: 1,
                    affected_capabilities: vec!["deception_coverage".to_string()],
                    summary: format!(
                        "Adds a `{decoy_type}` deception asset inside the bounded zone `{zone}`"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Withdraw the rehearsal-scoped `{decoy_type}` decoy from zone `{zone}` if it is promoted"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::WithdrawDecoy,
                        format!(
                            "Remove the `{decoy_type}` decoy from `{zone}` and confirm sensors return to baseline"
                        ),
                    )],
                },
            )
        }
        ResponseAction::Escalate { summary, .. } => {
            let summary = require_value("summary", summary)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::OperatorQueue,
                    scope_value: "human_review".to_string(),
                    impact: ResponseBlastRadiusImpact::OperatorEscalationOnly,
                    max_affected_scopes: 1,
                    affected_capabilities: vec!["operator_review_queue".to_string()],
                    summary: format!(
                        "Queues one bounded operator review using the escalation summary `{summary}`"
                    ),
                },
                ResponseRollbackPreview {
                    required: false,
                    summary:
                        "No containment rollback is required; only the queued escalation note may need closure"
                            .to_string(),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::CloseEscalation,
                        "Close or supersede the rehearsal-only escalation note after review",
                    )],
                },
            )
        }
    };

    Ok(preview)
}

fn playbook_preview_approval_context(prepared_at_ms: i64, live_mode: bool) -> ApprovalContext {
    ApprovalContext {
        live_mode,
        receipt_chain: vec![format!("playbook-preview:{prepared_at_ms}")],
        correlation_id: Some(format!("playbook-preview-{prepared_at_ms}")),
        now_ms: prepared_at_ms,
    }
}

fn playbook_preview_hunt_id(prepared_at_ms: i64) -> swarm_core::types::HuntId {
    swarm_core::types::HuntId(format!("playbook-preview-{prepared_at_ms}"))
}

fn playbook_preview_evidence(
    request: &ResponsePlaybookPreviewRequest,
    resolution: &ResponsePlaybookRuleResolution,
) -> serde_json::Value {
    json!({
        "preview": true,
        "escalation": {
            "threat_class": request.threat_class,
            "severity": request.severity,
            "confidence": request.confidence,
            "mode": request.mode,
        },
        "playbook_match": {
            "rule_index": resolution.rule_index,
            "threat_class": resolution.threat_class,
            "severity": resolution.severity,
            "min_confidence": resolution.min_confidence,
            "max_confidence": resolution.max_confidence,
            "branch": resolution.branch.as_ref().map(|branch| json!({
                "index": branch.index,
                "name": branch.name,
            })),
        }
    })
}

fn enrich_finding_evidence(
    event: &TelemetryEvent,
    evidence: serde_json::Value,
    detected_at_ms: i64,
) -> serde_json::Value {
    let ancestry = parent_process_ancestry(event);
    let host_metadata = json!({
        "source": event.source,
        "host_id": event.host_id,
        "event_id": event.event_id,
        "event_timestamp": event.timestamp,
    });
    let time_to_detect_ms = (detected_at_ms - normalized_timestamp_ms(event.timestamp)).max(0);

    match evidence {
        serde_json::Value::Object(mut object) => {
            object.insert(
                "parent_process_ancestry".to_string(),
                serde_json::json!(ancestry),
            );
            object.insert("host_metadata".to_string(), host_metadata);
            object.insert(
                "time_to_detect_ms".to_string(),
                serde_json::json!(time_to_detect_ms),
            );
            serde_json::Value::Object(object)
        }
        other => serde_json::json!({
            "evidence": other,
            "parent_process_ancestry": ancestry,
            "host_metadata": host_metadata,
            "time_to_detect_ms": time_to_detect_ms,
        }),
    }
}

fn parent_process_ancestry(event: &TelemetryEvent) -> Vec<String> {
    match &event.payload {
        TelemetryPayload::ProcessStart(process) => {
            vec![process.parent_process.clone(), process.process_name.clone()]
                .into_iter()
                .filter(|value| !value.trim().is_empty())
                .collect()
        }
        TelemetryPayload::ProcessMemoryAccess(access) => {
            vec![access.source_process.clone(), access.target_process.clone()]
                .into_iter()
                .filter(|value| !value.trim().is_empty())
                .collect()
        }
        TelemetryPayload::NetworkConnect(connection) => vec![connection.process_name.clone()]
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect(),
        TelemetryPayload::DnsQuery(dns) => dns
            .process_name
            .clone()
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect(),
        TelemetryPayload::RegistryAccess(registry) => {
            let mut ancestry = vec![registry.process_name.clone()];
            if let Some(target_process) = &registry.target_process {
                ancestry.push(target_process.clone());
            }
            ancestry
                .into_iter()
                .filter(|value| !value.trim().is_empty())
                .collect()
        }
        TelemetryPayload::RegistryPersistence(registry) => vec![registry.process_name.clone()]
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect(),
        TelemetryPayload::FilePersistence(file) => vec![file.process_name.clone()]
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect(),
        TelemetryPayload::AuthenticationEvent(authentication) => authentication
            .process_name
            .clone()
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect(),
        TelemetryPayload::InfrastructureHealth(health) => vec![health.node_name.clone()]
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect(),
        TelemetryPayload::ThermalAnomaly(thermal) => vec![thermal.node_name.clone()]
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect(),
        TelemetryPayload::ResourceExhaustion(exhaustion) => vec![exhaustion.node_name.clone()]
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect(),
    }
}

fn normalized_timestamp_ms(timestamp: i64) -> i64 {
    if timestamp.abs() < 100_000_000_000 {
        timestamp.saturating_mul(1_000)
    } else {
        timestamp
    }
}

fn notification_config_without_providence(
    config: &SwarmConfig,
) -> (
    BTreeMap<String, swarm_core::config::NotificationChannelConfig>,
    swarm_core::config::NotificationRoutingConfig,
) {
    let mut channels = config.notification_channels.clone();
    channels.remove(PROVIDENCE_CHANNEL);
    let mut routing = config.notification_routing.clone();
    for rule in &mut routing.rules {
        rule.channels
            .retain(|channel| channel != PROVIDENCE_CHANNEL);
    }
    routing.rules.retain(|rule| !rule.channels.is_empty());
    (channels, routing)
}

/// Thin service wrapper around the first Rust-only runtime slice.
pub struct RuntimeService<P, E> {
    pub config: SwarmConfig,
    pub runtime: SwarmRuntime<P, E>,
    metrics: RuntimeMetrics,
    prometheus: Option<CriticalPathMetrics>,
    sequence_detector: Option<KillChainSequenceDetector>,
    siem_forwarder: Option<SiemFindingForwarder>,
    notification_router: Option<NotificationRouter>,
}

impl<P, E> RuntimeService<P, E>
where
    P: ApprovalGate,
    E: ResponseExecutor,
{
    pub fn new(config: SwarmConfig, mut runtime: SwarmRuntime<P, E>) -> Self {
        runtime.configure_temporal_event_window(config.runtime.temporal_event_window.clone());
        let siem_forwarder = config.siem_forward.clone().map(SiemFindingForwarder::new);
        let (notification_channels, notification_routing) =
            notification_config_without_providence(&config);
        let notification_router =
            if notification_channels.is_empty() || notification_routing.rules.is_empty() {
                None
            } else {
                Some(NotificationRouter::new(
                    notification_channels,
                    notification_routing,
                    config.runtime.max_dead_letter_bytes,
                ))
            };
        Self {
            config,
            runtime,
            metrics: RuntimeMetrics::default(),
            prometheus: None,
            sequence_detector: None,
            siem_forwarder,
            notification_router,
        }
    }

    pub fn with_prometheus(mut self, metrics: CriticalPathMetrics) -> Self {
        self.prometheus = Some(metrics);
        self
    }

    pub fn with_sequence_detector(mut self, detector: KillChainSequenceDetector) -> Self {
        self.sequence_detector = Some(detector);
        self
    }

    pub fn with_configured_sequence_detector(mut self) -> Result<Self, ServiceError> {
        if self
            .config
            .detection
            .active_strategies()
            .iter()
            .any(|strategy| strategy == KILL_CHAIN_SEQUENCE_STRATEGY_ID)
        {
            let detector = KillChainSequenceDetector::from_profile(
                KILL_CHAIN_SEQUENCE_STRATEGY_ID,
                kill_chain_sequence_profile(&self.config.detection)?,
                self.runtime.temporal_event_window(),
            )?;
            self = self.with_sequence_detector(detector);
        }
        Ok(self)
    }

    pub fn mode(&self) -> RuntimeMode {
        self.runtime.mode()
    }

    pub fn runtime_config(&self) -> &RuntimeConfig {
        &self.config.runtime
    }

    pub async fn ensure_substrate_ready<S>(
        &self,
        substrate: &S,
    ) -> Result<SubstrateHealth, ServiceError>
    where
        S: PheromoneSubstrate,
    {
        let health = substrate.health().await?;
        if self.runtime.mode() == RuntimeMode::LiveResponse
            && self.config.runtime.require_durable_live_response
        {
            if !health.ready {
                return Err(ServiceError::Readiness {
                    component: "substrate",
                    source: ReadinessError::SubstrateNotReady {
                        backend: health.backend.clone(),
                    },
                });
            }
            if !health.durable {
                return Err(ServiceError::Readiness {
                    component: "substrate",
                    source: ReadinessError::SubstrateNotDurable {
                        backend: health.backend.clone(),
                    },
                });
            }
        }
        Ok(health)
    }

    async fn evaluate_sequence_findings<S>(
        &self,
        substrate: &S,
        event: &TelemetryEvent,
        agent_id: &AgentId,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<
        (
            Vec<DetectionFinding>,
            Vec<swarm_core::pheromone::PheromoneDeposit>,
        ),
        ServiceError,
    >
    where
        S: PheromoneSubstrate,
    {
        let Some(detector) = &self.sequence_detector else {
            return Ok((Vec::new(), Vec::new()));
        };
        let findings = detector.evaluate(event);
        if findings.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let deposits = persist_findings_as_deposits(
            substrate,
            &findings,
            event,
            agent_id,
            infer_agent_role(agent_id),
            &self.config.pheromone,
            signing_key,
        )
        .await?;
        Ok((findings, deposits))
    }

    /// Run the full critical lane for one event and build a replay bundle.
    pub async fn process_event<D, S, F>(
        &self,
        detector: &D,
        substrate: &S,
        event: &TelemetryEvent,
        execution: EventExecutionContext<'_>,
        request_builder: F,
    ) -> Result<Option<ReplayBundle>, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        F: Fn(&DetectionFinding) -> Option<ResponseAction>,
    {
        self.process_event_with_finding_observer(
            detector,
            substrate,
            event,
            execution,
            request_builder,
            |_event, _findings| {},
        )
        .await
    }

    /// Run the full critical lane and expose enriched findings before action selection.
    pub async fn process_event_with_finding_observer<D, S, F, O>(
        &self,
        detector: &D,
        substrate: &S,
        event: &TelemetryEvent,
        execution: EventExecutionContext<'_>,
        request_builder: F,
        observe_findings: O,
    ) -> Result<Option<ReplayBundle>, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        F: Fn(&DetectionFinding) -> Option<ResponseAction>,
        O: Fn(&TelemetryEvent, &[DetectionFinding]),
    {
        let trace_id = approval_correlation_id(execution.approval).to_string();
        let span = tracing::info_span!(
            "runtime.process_event_with_finding_observer",
            trace_id = %trace_id,
            event_id = %event.event_id,
            host_id = ?event.host_id,
            requested_by = %execution.agent_id.0
        );

        with_trace_id(
            trace_id,
            async {
                let substrate_health = self.ensure_substrate_ready(substrate).await?;
                tracing::debug!(
                    backend = %substrate_health.backend,
                    durable = substrate_health.durable,
                    ready = substrate_health.ready,
                    "substrate health verified"
                );
                self.runtime.record_temporal_event(event);

                let detect_started = Instant::now();
                let detection_result = detect_and_deposit(
                    detector,
                    substrate,
                    event,
                    execution.agent_id,
                    &self.config.pheromone,
                    execution.signing_key,
                )
                .await;
                let detect_elapsed_us = detect_started.elapsed().as_micros() as u64;
                self.metrics.record(
                    RuntimeStage::Detect,
                    detect_elapsed_us,
                    detection_result.is_ok(),
                );
                if let Some(prometheus) = &self.prometheus {
                    prometheus.observe_detect(detect_elapsed_us as f64);
                }

                let DetectionPipelineOutcome {
                    event,
                    findings,
                    deposits,
                } = detection_result?;
                let (sequence_findings, sequence_deposits) = self
                    .evaluate_sequence_findings(
                        substrate,
                        &event,
                        execution.agent_id,
                        execution.signing_key,
                    )
                    .await?;
                let mut findings = findings;
                findings.extend(sequence_findings);
                let mut deposits = deposits;
                deposits.extend(sequence_deposits);
                let detected_at_ms = execution.approval.now_ms;
                let findings = FindingEnrichmentService.enrich(&event, findings, detected_at_ms);
                observe_findings(&event, &findings);
                tracing::info!(
                    correlation_id = %approval_correlation_id(execution.approval),
                    event_id = %event.event_id,
                    finding_count = findings.len(),
                    deposit_count = deposits.len(),
                    module = module_path!(),
                    "detection completed"
                );
                if let Some(prometheus) = &self.prometheus {
                    for finding in &findings {
                        prometheus.observe_finding(
                            threat_class_label(&finding.threat_class),
                            &finding.strategy_id,
                        );
                    }
                }
                if let Some(forwarder) = &self.siem_forwarder {
                    for finding in &findings {
                        match forwarder.forward_finding(finding).await {
                            Ok(receipt) if receipt.status.indicates_success() => {
                                tracing::info!(
                                    event_id = %finding.event_id,
                                    finding_id = %finding.finding_id,
                                    transport = "siem_forward",
                                    status = ?receipt.status,
                                    "forwarded finding to SIEM"
                                );
                            }
                            Ok(receipt) => {
                                tracing::warn!(
                                    event_id = %finding.event_id,
                                    finding_id = %finding.finding_id,
                                    status = ?receipt.status,
                                    summary = %receipt.summary,
                                    "siem finding forward degraded"
                                );
                            }
                            Err(error) => {
                                tracing::error!(
                                    event_id = %finding.event_id,
                                    finding_id = %finding.finding_id,
                                    reason = %error,
                                    "siem finding forward failed"
                                );
                            }
                        }
                    }
                }
                if let Some(router) = &self.notification_router {
                    for finding in &findings {
                        router.route_finding(finding).await;
                    }
                }

                let Some(primary_finding) = findings.first().cloned() else {
                    tracing::info!(
                        correlation_id = %approval_correlation_id(execution.approval),
                        event_id = %event.event_id,
                        module = module_path!(),
                        "no findings emitted for event"
                    );
                    return Ok(None);
                };

                let Some(action) = request_builder(&primary_finding) else {
                    tracing::info!(
                        correlation_id = %approval_correlation_id(execution.approval),
                        event_id = %primary_finding.event_id,
                        module = module_path!(),
                        "no action proposed for finding"
                    );
                    return Ok(None);
                };

                let request = ActionRequest {
                    hunt_id: swarm_core::types::HuntId(primary_finding.event_id.clone()),
                    requested_by: execution.agent_id.clone(),
                    action,
                    severity: primary_finding.severity,
                    evidence: primary_finding.evidence.clone(),
                };
                let execution_started = Instant::now();
                let execution_result = self
                    .runtime
                    .audit_authorize_and_execute_instrumented(
                        &primary_finding,
                        &request,
                        execution.approval,
                    )
                    .await;
                let execution_report = match execution_result {
                    Ok(report) => report,
                    Err(error) => {
                        let elapsed_us = execution_started.elapsed().as_micros() as u64;
                        self.metrics.record(RuntimeStage::Policy, elapsed_us, false);
                        if let Some(prometheus) = &self.prometheus {
                            prometheus.observe_policy(elapsed_us as f64);
                        }
                        tracing::error!(
                            correlation_id = %approval_correlation_id(execution.approval),
                            event_id = %event.event_id,
                            reason = %error,
                            module = module_path!(),
                            "authorization or response execution failed"
                        );
                        return Err(error.into());
                    }
                };
                self.metrics.record(
                    RuntimeStage::Policy,
                    execution_report.policy_elapsed_us,
                    true,
                );
                if let Some(prometheus) = &self.prometheus {
                    prometheus.observe_policy(execution_report.policy_elapsed_us as f64);
                    prometheus
                        .observe_verdict(verdict_label(execution_report.audit.policy.verdict));
                    if let AuditResponseRecord::GuardRejected { guard_name, .. } =
                        &execution_report.audit.response
                    {
                        prometheus.observe_guard_rejection(guard_name);
                    }
                    if let Some(outcome) = adapter_outcome_label(&execution_report.audit.response) {
                        prometheus.observe_adapter_outcome(outcome);
                    }
                }
                if let Some(response_elapsed_us) = execution_report.response_elapsed_us {
                    self.metrics.record(
                        RuntimeStage::Response,
                        response_elapsed_us,
                        execution_report.response_succeeded,
                    );
                    if let Some(prometheus) = &self.prometheus {
                        prometheus.observe_response(response_elapsed_us as f64);
                    }
                }

                Ok(Some(ReplayBundle {
                    bundle_id: format!(
                        "bundle:{}:{}",
                        request.hunt_id.0, execution.approval.now_ms
                    ),
                    event,
                    findings,
                    deposits,
                    action_request: request,
                    rehearsal: None,
                    audit: execution_report.audit,
                }))
            }
            .instrument(span),
        )
        .await
    }

    pub fn metrics_snapshot(&self) -> RuntimeMetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn prometheus_metrics(&self) -> Option<&CriticalPathMetrics> {
        self.prometheus.as_ref()
    }

    pub fn notification_router(&self) -> Option<&NotificationRouter> {
        self.notification_router.as_ref()
    }

    pub fn persist_replay_bundle<Store>(
        &self,
        store: &Store,
        bundle: &ReplayBundle,
    ) -> Result<ReplayBundleRecord, ServiceError>
    where
        Store: ReplayBundleStore,
    {
        let started = Instant::now();
        let persisted = store.persist(bundle);
        let elapsed_us = started.elapsed().as_micros() as u64;
        self.metrics
            .record(RuntimeStage::Persist, elapsed_us, persisted.is_ok());
        let record = persisted?;
        tracing::info!(
            hunt_id = %record.hunt_id,
            trail_id = %record.trail_id,
            bundle_id = %record.bundle_id,
            response_receipt_id = ?record.response_receipt_id,
            "persisted replay bundle"
        );
        Ok(record)
    }

    pub async fn rehearse_bundle_with_store<Store>(
        &self,
        store: &Store,
        source: &ReplayBundle,
        approval: &ApprovalContext,
    ) -> Result<PersistedReplayBundle, ServiceError>
    where
        Store: ReplayBundleStore,
    {
        let preview =
            build_rehearsal_preview(&source.action_request, &source.bundle_id, approval.now_ms)?;
        let approval = merge_rehearsal_receipt_chain(approval, source);
        let execution_started = Instant::now();
        let execution_result = self
            .runtime
            .audit_rehearse_authorize_and_execute_instrumented(
                &source.audit.detection,
                &source.action_request,
                &approval,
            )
            .await;
        let execution_report = match execution_result {
            Ok(report) => report,
            Err(error) => {
                let elapsed_us = execution_started.elapsed().as_micros() as u64;
                self.metrics.record(RuntimeStage::Policy, elapsed_us, false);
                if let Some(prometheus) = &self.prometheus {
                    prometheus.observe_policy(elapsed_us as f64);
                }
                tracing::error!(
                    correlation_id = %approval_correlation_id(&approval),
                    hunt_id = %source.action_request.hunt_id.0,
                    source_bundle_id = %source.bundle_id,
                    reason = %error,
                    module = module_path!(),
                    "rehearsal authorization or response execution failed"
                );
                return Err(error.into());
            }
        };
        self.metrics.record(
            RuntimeStage::Policy,
            execution_report.policy_elapsed_us,
            true,
        );
        if let Some(prometheus) = &self.prometheus {
            prometheus.observe_policy(execution_report.policy_elapsed_us as f64);
            prometheus.observe_verdict(verdict_label(execution_report.audit.policy.verdict));
            if let AuditResponseRecord::GuardRejected { guard_name, .. } =
                &execution_report.audit.response
            {
                prometheus.observe_guard_rejection(guard_name);
            }
            if let Some(outcome) = adapter_outcome_label(&execution_report.audit.response) {
                prometheus.observe_adapter_outcome(outcome);
            }
        }
        if let Some(response_elapsed_us) = execution_report.response_elapsed_us {
            self.metrics.record(
                RuntimeStage::Response,
                response_elapsed_us,
                execution_report.response_succeeded,
            );
            if let Some(prometheus) = &self.prometheus {
                prometheus.observe_response(response_elapsed_us as f64);
            }
        }

        let bundle = ReplayBundle {
            bundle_id: format!(
                "bundle:rehearsal:{}:{}",
                source.action_request.hunt_id.0, approval.now_ms
            ),
            event: source.event.clone(),
            findings: source.findings.clone(),
            deposits: source.deposits.clone(),
            action_request: source.action_request.clone(),
            rehearsal: Some(preview),
            audit: execution_report.audit,
        };
        let record = self.persist_replay_bundle(store, &bundle)?;
        Ok(PersistedReplayBundle { record, bundle })
    }

    pub async fn process_event_with_store<D, S, F, Store>(
        &self,
        detector: &D,
        substrate: &S,
        store: &Store,
        event: &TelemetryEvent,
        execution: EventExecutionContext<'_>,
        request_builder: F,
    ) -> Result<Option<PersistedReplayBundle>, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        F: Fn(&DetectionFinding) -> Option<ResponseAction>,
        Store: ReplayBundleStore,
    {
        self.process_event_with_store_and_finding_observer(
            detector,
            substrate,
            store,
            event,
            execution,
            request_builder,
            |_event, _findings| {},
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn process_event_with_store_and_finding_observer<D, S, F, Store, O>(
        &self,
        detector: &D,
        substrate: &S,
        store: &Store,
        event: &TelemetryEvent,
        execution: EventExecutionContext<'_>,
        request_builder: F,
        observe_findings: O,
    ) -> Result<Option<PersistedReplayBundle>, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        F: Fn(&DetectionFinding) -> Option<ResponseAction>,
        Store: ReplayBundleStore,
        O: Fn(&TelemetryEvent, &[DetectionFinding]),
    {
        let Some(bundle) = self
            .process_event_with_finding_observer(
                detector,
                substrate,
                event,
                execution,
                request_builder,
                observe_findings,
            )
            .await?
        else {
            return Ok(None);
        };
        let record = self.persist_replay_bundle(store, &bundle)?;
        Ok(Some(PersistedReplayBundle { record, bundle }))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn process_event_with_store_and_investigation<
        D,
        S,
        F,
        Store,
        Strategy,
        InvestigationStore,
    >(
        &self,
        detector: &D,
        substrate: &S,
        store: &Store,
        investigation: &InvestigationCoordinator<Strategy, InvestigationStore>,
        event: &TelemetryEvent,
        execution: EventExecutionContext<'_>,
        request_builder: F,
    ) -> Result<Option<PersistedReplayBundleWithInvestigation>, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        F: Fn(&DetectionFinding) -> Option<ResponseAction>,
        Store: ReplayBundleStore,
        Strategy: InvestigationStrategy,
        InvestigationStore: InvestigationBundleStore + Clone + Send + Sync + 'static,
    {
        self.process_event_with_store_and_investigation_and_finding_observer(
            detector,
            substrate,
            store,
            investigation,
            event,
            execution,
            request_builder,
            |_event, _findings| {},
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn process_event_with_store_and_investigation_and_finding_observer<
        D,
        S,
        F,
        Store,
        Strategy,
        InvestigationStore,
        O,
    >(
        &self,
        detector: &D,
        substrate: &S,
        store: &Store,
        investigation: &InvestigationCoordinator<Strategy, InvestigationStore>,
        event: &TelemetryEvent,
        execution: EventExecutionContext<'_>,
        request_builder: F,
        observe_findings: O,
    ) -> Result<Option<PersistedReplayBundleWithInvestigation>, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        F: Fn(&DetectionFinding) -> Option<ResponseAction>,
        Store: ReplayBundleStore,
        Strategy: InvestigationStrategy,
        InvestigationStore: InvestigationBundleStore + Clone + Send + Sync + 'static,
        O: Fn(&TelemetryEvent, &[DetectionFinding]),
    {
        let Some(replay) = self
            .process_event_with_store_and_finding_observer(
                detector,
                substrate,
                store,
                event,
                execution,
                request_builder,
                observe_findings,
            )
            .await?
        else {
            return Ok(None);
        };
        let investigation_record = investigation.submit(&replay.bundle)?;
        Ok(Some(PersistedReplayBundleWithInvestigation {
            replay,
            investigation: investigation_record,
        }))
    }

    pub fn load_persisted_bundle_by_hunt_id<Store>(
        &self,
        store: &Store,
        hunt_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ServiceError>
    where
        Store: ReplayBundleStore,
    {
        Ok(store.load_by_hunt_id(hunt_id)?)
    }

    pub fn load_persisted_bundle_by_bundle_id<Store>(
        &self,
        store: &Store,
        bundle_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ServiceError>
    where
        Store: ReplayBundleStore,
    {
        Ok(store.load_by_bundle_id(bundle_id)?)
    }

    pub fn load_persisted_bundle_by_receipt_id<Store>(
        &self,
        store: &Store,
        receipt_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ServiceError>
    where
        Store: ReplayBundleStore,
    {
        Ok(store.load_by_receipt_id(receipt_id)?)
    }

    pub fn load_persisted_investigation_by_hunt_id<Store>(
        &self,
        store: &Store,
        hunt_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, ServiceError>
    where
        Store: InvestigationBundleStore,
    {
        Ok(store
            .load_by_hunt_id(hunt_id)
            .map_err(InvestigationError::from)?)
    }

    pub fn load_persisted_investigation_by_investigation_id<Store>(
        &self,
        store: &Store,
        investigation_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, ServiceError>
    where
        Store: InvestigationBundleStore,
    {
        Ok(store
            .load_by_investigation_id(investigation_id)
            .map_err(InvestigationError::from)?)
    }

    pub fn load_persisted_investigation_by_receipt_id<Store>(
        &self,
        store: &Store,
        receipt_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, ServiceError>
    where
        Store: InvestigationBundleStore,
    {
        Ok(store
            .load_by_receipt_id(receipt_id)
            .map_err(InvestigationError::from)?)
    }

    pub fn correlate_hunt<Investigations, Incidents>(
        &self,
        engine: &CorrelationEngine,
        investigations: &Investigations,
        incidents: &Incidents,
        hunt_id: &str,
    ) -> Result<Option<CorrelationOutcome>, ServiceError>
    where
        Investigations: InvestigationBundleStore,
        Incidents: IncidentStore,
    {
        Ok(engine.correlate_hunt(investigations, incidents, hunt_id)?)
    }

    pub fn load_incident_by_hunt_id<Store>(
        &self,
        store: &Store,
        hunt_id: &str,
    ) -> Result<Option<IncidentLookup>, ServiceError>
    where
        Store: IncidentStore,
    {
        Ok(store
            .load_by_hunt_id(hunt_id)
            .map_err(CorrelationError::from)?)
    }

    pub fn load_incident_by_incident_id<Store>(
        &self,
        store: &Store,
        incident_id: &str,
    ) -> Result<Option<IncidentLookup>, ServiceError>
    where
        Store: IncidentStore,
    {
        Ok(store
            .load_by_incident_id(incident_id)
            .map_err(CorrelationError::from)?)
    }

    pub fn replay_preview(&self, bundle: &ReplayBundle) -> ReplayPreview {
        ReplayPreview::from_bundle(bundle)
    }

    pub fn rehearsal_preview(
        &self,
        request: &ActionRequest,
        source_bundle_id: &str,
        prepared_at_ms: i64,
    ) -> Result<ResponseRehearsalPreview, ServiceError> {
        build_rehearsal_preview(request, source_bundle_id, prepared_at_ms)
    }

    pub fn playbook_preview(
        &self,
        request: ResponsePlaybookPreviewRequest,
        prepared_at_ms: i64,
    ) -> Result<ResponsePlaybookPreviewReport, ServiceError> {
        let mut notes = Vec::new();
        if self.runtime.mode() != RuntimeMode::LiveResponse {
            notes.push(
                "configured runtime mode is detect_only; preview still evaluates the playbook and policy path without executor side effects"
                    .to_string(),
            );
        }

        let Some(matched_rule) = self.config.pheromone.response_playbook.resolve(
            &request.threat_class,
            request.severity,
            request.confidence,
            request.mode,
        ) else {
            notes.push(
                "no response playbook rule matched the supplied threat class, severity, confidence, and swarm mode"
                    .to_string(),
            );
            return Ok(ResponsePlaybookPreviewReport {
                status: ResponsePlaybookPreviewStatus::NoMatch,
                configured_runtime_mode: self.runtime.mode(),
                request,
                matched_rule: None,
                actions: Vec::new(),
                approval_summary: ResponsePlaybookApprovalSummary::default(),
                notes,
            });
        };

        let source_bundle_id = format!("playbook-preview:{prepared_at_ms}");
        let approval = playbook_preview_approval_context(
            prepared_at_ms,
            self.runtime.mode() == RuntimeMode::LiveResponse,
        );
        let hunt_id = playbook_preview_hunt_id(prepared_at_ms);
        let requested_by = AgentId("operator-preview".to_string());
        let evidence = playbook_preview_evidence(&request, &matched_rule);
        let gate = ConfigurableApprovalGate::from_config(&self.config.policy);
        let mut approval_summary = ResponsePlaybookApprovalSummary::default();
        let mut actions = Vec::with_capacity(matched_rule.actions.len());

        for (order, action) in matched_rule.actions.iter().cloned().enumerate() {
            let request_action = ActionRequest {
                hunt_id: hunt_id.clone(),
                requested_by: requested_by.clone(),
                action: action.clone(),
                severity: request.severity,
                evidence: evidence.clone(),
            };
            let policy = gate.evaluate(&request_action, &approval)?;
            let lease = if policy.verdict == PolicyVerdict::Allow {
                Some(gate.issue_lease(&request_action, &approval)?)
            } else {
                None
            };
            let rehearsal =
                build_rehearsal_preview(&request_action, &source_bundle_id, prepared_at_ms)?;

            match policy.verdict {
                PolicyVerdict::Allow => approval_summary.allow_count += 1,
                PolicyVerdict::RequireHuman => approval_summary.require_human_count += 1,
                PolicyVerdict::Deny => approval_summary.deny_count += 1,
            }

            actions.push(ResponsePlaybookActionPreview {
                order,
                action,
                rehearsal,
                policy: ResponsePlaybookPolicyPreview {
                    verdict: policy.verdict,
                    rule_name: policy.rule_name,
                    reason: policy.reason,
                    lease_scope: lease.as_ref().and_then(|value| value.scope.clone()),
                    lease_expires_at_ms: lease.as_ref().map(|value| value.expires_at_ms),
                },
            });
        }

        Ok(ResponsePlaybookPreviewReport {
            status: ResponsePlaybookPreviewStatus::Matched,
            configured_runtime_mode: self.runtime.mode(),
            request,
            matched_rule: Some(matched_rule),
            actions,
            approval_summary,
            notes,
        })
    }

    pub async fn operator_status<D, S, Store>(
        &self,
        detector: &D,
        substrate: &S,
        store: &Store,
    ) -> Result<OperatorStatusReport, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        Store: ReplayBundleStore,
    {
        let substrate_health = substrate.health().await?;
        let replay_store_health = store.health()?;
        let mut warnings = Vec::new();
        if self.runtime.mode() == RuntimeMode::LiveResponse
            && self.config.runtime.require_durable_live_response
            && !substrate_health.durable
        {
            warnings.push("live response requires a durable substrate backend".to_string());
        }
        if !substrate_health.ready {
            warnings.push(format!(
                "substrate backend `{}` is not ready",
                substrate_health.backend
            ));
        }
        if self.runtime.mode() == RuntimeMode::LiveResponse
            && self.config.audit.bundle_store.is_durable()
            && !replay_store_health.ready
        {
            warnings.push("durable replay store is not ready".to_string());
        }
        let recent_decisions = store.recent(self.config.audit.recent_decisions_limit)?;
        let degradation = derive_runtime_degradation_status(RuntimeDegradationSignals {
            configured_mode: self.runtime.mode(),
            detector_ready: true,
            substrate_ready: substrate_health.ready
                && (!self.config.runtime.require_durable_live_response
                    || self.runtime.mode() != RuntimeMode::LiveResponse
                    || substrate_health.durable),
            replay_store_ready: replay_store_health.ready,
            startup_attestation_ready: true,
            anti_tamper_ready: true,
            heap_ready: true,
            draining: false,
            degraded_agents: 0,
            failed_agents: 0,
            transitioned_at_ms: now_ms(),
        });

        Ok(OperatorStatusReport {
            mode: self.runtime.mode(),
            degradation,
            detector: ComponentStatus {
                ready: true,
                durable: None,
                details: format!("strategy `{}`", detector.id()),
            },
            substrate: component_status_from_substrate(&substrate_health),
            policy: ComponentStatus {
                ready: true,
                durable: None,
                details: type_name::<P>().to_string(),
            },
            response: ComponentStatus {
                ready: true,
                durable: None,
                details: type_name::<E>().to_string(),
            },
            replay_store: component_status_from_replay_store(&replay_store_health),
            providence: None,
            bridges: None,
            metrics: self.metrics_snapshot(),
            recent_decisions: recent_decisions.clone(),
            async_lane: AsyncLaneStatusSnapshot::disabled(),
            investigation_review: None,
            incident_review: None,
            freshness: ReviewFreshness {
                latest_hot_path_decision_at_ms: recent_decisions
                    .first()
                    .map(|record| record.created_at_ms),
                latest_investigation_update_at_ms: None,
                latest_incident_at_ms: None,
            },
            evolution: None,
            false_positive_tracking: FalsePositiveMeasurementReport::default(),
            alert_tuning: AlertTuningReport::default(),
            warnings,
        })
    }

    pub async fn operator_review_status<
        D,
        S,
        ReplayStore,
        Strategy,
        InvestigationStoreT,
        IncidentStoreT,
    >(
        &self,
        detector: &D,
        substrate: &S,
        replay_store: &ReplayStore,
        investigation: &InvestigationCoordinator<Strategy, InvestigationStoreT>,
        incident_store: &IncidentStoreT,
    ) -> Result<OperatorStatusReport, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        ReplayStore: ReplayBundleStore,
        Strategy: InvestigationStrategy,
        InvestigationStoreT: InvestigationBundleStore + Clone + Send + Sync + 'static,
        IncidentStoreT: IncidentStore,
    {
        let mut report = self
            .operator_status(detector, substrate, replay_store)
            .await?;
        let queue = investigation.snapshot();
        let investigation_store_health = investigation.health()?;
        let incident_store_health = incident_store.health().map_err(CorrelationError::from)?;
        let recent_investigations =
            investigation.recent(self.config.audit.recent_decisions_limit)?;
        let recent_incidents = incident_store
            .recent(self.config.audit.recent_decisions_limit)
            .map_err(CorrelationError::from)?;

        if self.config.investigation.enabled && !investigation_store_health.ready {
            report
                .warnings
                .push("durable investigation store is not ready".to_string());
        }
        if self.config.correlation.enabled && !incident_store_health.ready {
            report
                .warnings
                .push("durable incident store is not ready".to_string());
        }
        if let Some(reason) = &queue.last_failure_reason {
            report.warnings.push(format!(
                "investigation queue reported recent failure: {reason}"
            ));
        }

        let async_lane = summarize_async_lane_status(
            &self.config,
            investigation.strategy_id(),
            &queue,
            &investigation_store_health,
            &incident_store_health,
            &recent_investigations,
            &recent_incidents,
        );
        extend_unique_warnings(&mut report.warnings, async_lane.warnings.clone());

        report.investigation_review = Some(InvestigationReviewStatus {
            queue,
            store: component_status_from_investigation_store(&investigation_store_health),
            recent: recent_investigations.clone(),
        });
        report.incident_review = Some(IncidentReviewStatus {
            store: component_status_from_incident_store(&incident_store_health),
            recent: recent_incidents.clone(),
        });
        report.false_positive_tracking = summarize_false_positive_measurements(&recent_incidents);
        report.alert_tuning = build_alert_tuning_report(&recent_incidents);
        report.async_lane = async_lane;
        report.freshness.latest_investigation_update_at_ms = recent_investigations
            .first()
            .map(|record| record.last_updated_ms);
        report.freshness.latest_incident_at_ms =
            recent_incidents.first().map(|record| record.created_at_ms);

        Ok(report)
    }

    pub async fn operator_status_with_bridges<D, S, Store>(
        &self,
        detector: &D,
        substrate: &S,
        store: &Store,
        bridges: BridgeStatusReport,
    ) -> Result<OperatorStatusReport, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        Store: ReplayBundleStore,
    {
        Ok(self
            .operator_status(detector, substrate, store)
            .await?
            .with_bridges(bridges))
    }

    pub async fn operator_review_status_with_bridges<
        D,
        S,
        ReplayStore,
        Strategy,
        InvestigationStoreT,
        IncidentStoreT,
    >(
        &self,
        detector: &D,
        substrate: &S,
        replay_store: &ReplayStore,
        investigation: &InvestigationCoordinator<Strategy, InvestigationStoreT>,
        incident_store: &IncidentStoreT,
        bridges: BridgeStatusReport,
    ) -> Result<OperatorStatusReport, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        ReplayStore: ReplayBundleStore,
        Strategy: InvestigationStrategy,
        InvestigationStoreT: InvestigationBundleStore + Clone + Send + Sync + 'static,
        IncidentStoreT: IncidentStore,
    {
        Ok(self
            .operator_review_status(
                detector,
                substrate,
                replay_store,
                investigation,
                incident_store,
            )
            .await?
            .with_bridges(bridges))
    }

    pub fn save_replay_bundle(
        &self,
        bundle: &ReplayBundle,
        path: impl AsRef<Path>,
    ) -> Result<(), ServiceError> {
        let path = path.as_ref();
        let serialized = serde_json::to_string_pretty(bundle)?;
        fs::write(path, serialized).map_err(|source| ServiceError::Write {
            path: path.display().to_string(),
            source,
        })
    }

    pub fn load_replay_bundle(&self, path: impl AsRef<Path>) -> Result<ReplayBundle, ServiceError> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path).map_err(|source| ServiceError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Ok(serde_json::from_str(&raw)?)
    }
}

impl<P, E, Strategy> ConfiguredRuntimeStack<P, E, Strategy>
where
    P: ApprovalGate,
    E: ResponseExecutor,
    Strategy: InvestigationStrategy,
{
    /// Build the runtime composition root directly from repository-owned config.
    pub fn from_runtime(
        config: SwarmConfig,
        runtime: SwarmRuntime<P, E>,
        strategy: Strategy,
    ) -> Result<Self, ServiceError> {
        let substrate = ConfiguredPheromoneSubstrate::from_config(&config.pheromone)?;
        let replay_store = ConfiguredReplayBundleStore::from_config(&config.audit.bundle_store)?;
        let investigation_store =
            ConfiguredInvestigationBundleStore::from_config(&config.investigation.bundle_store)
                .map_err(InvestigationError::from)?;
        let incident_store =
            ConfiguredIncidentStore::from_config(&config.correlation.incident_store)
                .map_err(CorrelationError::from)?;
        let investigation = InvestigationCoordinator::new(
            config.investigation.clone(),
            strategy,
            investigation_store.clone(),
        );
        let correlation = CorrelationEngine::new(config.correlation.clone());
        let service = RuntimeService::new(config, runtime).with_configured_sequence_detector()?;
        let service = service.with_prometheus(CriticalPathMetrics::new());

        Ok(Self {
            service,
            substrate,
            replay_store,
            investigation,
            investigation_store,
            correlation,
            incident_store,
        })
    }

    /// Build the runtime stack from policy, response, and investigation components.
    pub fn from_components(
        config: SwarmConfig,
        policy: P,
        response: E,
        strategy: Strategy,
    ) -> Result<Self, ServiceError> {
        let mode = config.runtime.mode;
        Self::from_runtime(config, SwarmRuntime::new(mode, policy, response), strategy)
    }

    /// Run the critical path, persist the replay bundle, and queue async investigation.
    pub async fn process_event<D, F>(
        &self,
        detector: &D,
        event: &TelemetryEvent,
        execution: EventExecutionContext<'_>,
        request_builder: F,
    ) -> Result<Option<PersistedReplayBundleWithInvestigation>, ServiceError>
    where
        D: DetectionStrategy,
        F: Fn(&DetectionFinding) -> Option<ResponseAction>,
    {
        self.process_event_with_finding_observer(
            detector,
            event,
            execution,
            request_builder,
            |_event, _findings| {},
        )
        .await
    }

    /// Run the critical path, persist the replay bundle, queue investigation, and observe findings.
    pub async fn process_event_with_finding_observer<D, F, O>(
        &self,
        detector: &D,
        event: &TelemetryEvent,
        execution: EventExecutionContext<'_>,
        request_builder: F,
        observe_findings: O,
    ) -> Result<Option<PersistedReplayBundleWithInvestigation>, ServiceError>
    where
        D: DetectionStrategy,
        F: Fn(&DetectionFinding) -> Option<ResponseAction>,
        O: Fn(&TelemetryEvent, &[DetectionFinding]),
    {
        self.service
            .process_event_with_store_and_investigation_and_finding_observer(
                detector,
                &self.substrate,
                &self.replay_store,
                &self.investigation,
                event,
                execution,
                request_builder,
                observe_findings,
            )
            .await
    }

    /// Assemble or reload one correlated incident from the configured stores.
    pub fn correlate_hunt(
        &self,
        hunt_id: &str,
    ) -> Result<Option<CorrelationOutcome>, ServiceError> {
        self.service.correlate_hunt(
            &self.correlation,
            &self.investigation_store,
            &self.incident_store,
            hunt_id,
        )
    }

    /// Load a persisted replay bundle from the configured replay store.
    pub fn replay_bundle_by_bundle_id(
        &self,
        bundle_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ServiceError> {
        self.service
            .load_persisted_bundle_by_bundle_id(&self.replay_store, bundle_id)
    }

    /// Load a persisted replay bundle by hunt identifier from the configured replay store.
    pub fn replay_bundle_by_hunt_id(
        &self,
        hunt_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ServiceError> {
        self.service
            .load_persisted_bundle_by_hunt_id(&self.replay_store, hunt_id)
    }

    /// Load a persisted replay bundle by receipt identifier from the configured replay store.
    pub fn replay_bundle_by_receipt_id(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ServiceError> {
        self.service
            .load_persisted_bundle_by_receipt_id(&self.replay_store, receipt_id)
    }

    /// Load a persisted investigation bundle from the configured investigation store.
    pub fn investigation_by_investigation_id(
        &self,
        investigation_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, ServiceError> {
        self.service
            .load_persisted_investigation_by_investigation_id(
                &self.investigation_store,
                investigation_id,
            )
    }

    /// Load a persisted investigation bundle by hunt identifier from the configured store.
    pub fn investigation_by_hunt_id(
        &self,
        hunt_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, ServiceError> {
        self.service
            .load_persisted_investigation_by_hunt_id(&self.investigation_store, hunt_id)
    }

    /// Load a persisted investigation bundle by receipt identifier from the configured store.
    pub fn investigation_by_receipt_id(
        &self,
        receipt_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, ServiceError> {
        self.service
            .load_persisted_investigation_by_receipt_id(&self.investigation_store, receipt_id)
    }

    /// Load a correlated incident from the configured incident store by incident id.
    pub fn incident_by_incident_id(
        &self,
        incident_id: &str,
    ) -> Result<Option<IncidentLookup>, ServiceError> {
        self.service
            .load_incident_by_incident_id(&self.incident_store, incident_id)
    }

    /// Load a correlated incident from the configured incident store by hunt id.
    pub fn incident_by_hunt_id(
        &self,
        hunt_id: &str,
    ) -> Result<Option<IncidentLookup>, ServiceError> {
        self.service
            .load_incident_by_hunt_id(&self.incident_store, hunt_id)
    }

    /// Produce the full operator review report from the configured stack.
    pub async fn operator_review_status<D>(
        &self,
        detector: &D,
    ) -> Result<OperatorStatusReport, ServiceError>
    where
        D: DetectionStrategy,
    {
        self.service
            .operator_review_status(
                detector,
                &self.substrate,
                &self.replay_store,
                &self.investigation,
                &self.incident_store,
            )
            .await
    }
}

impl<Strategy> ConfiguredRuntimeStack<ConfigurableApprovalGate, DispatchingExecutor, Strategy>
where
    Strategy: InvestigationStrategy,
{
    /// Build the runtime stack from repository config using the configured response adapter.
    pub fn from_config(config: SwarmConfig, strategy: Strategy) -> Result<Self, ServiceError> {
        let response = DispatchingExecutor::from_config(
            config.response_adapter.clone(),
            config.runtime.max_dead_letter_bytes,
        )
        .map_err(|error| ServiceError::Runtime(crate::RuntimeError::Response(error)))?;
        let gate = ConfigurableApprovalGate::from_config(&config.policy);
        Self::from_components(config, gate, response, strategy)
    }
}

fn component_status_from_substrate(health: &SubstrateHealth) -> ComponentStatus {
    ComponentStatus {
        ready: health.ready,
        durable: Some(health.durable),
        details: format!("{} ({})", health.backend, health.details),
    }
}

fn component_status_from_replay_store(health: &ReplayStoreHealth) -> ComponentStatus {
    ComponentStatus {
        ready: health.ready,
        durable: Some(health.durable),
        details: format!("{} ({})", health.backend, health.details),
    }
}

fn component_status_from_investigation_store(health: &InvestigationStoreHealth) -> ComponentStatus {
    ComponentStatus {
        ready: health.ready,
        durable: Some(health.durable),
        details: format!("{} ({})", health.backend, health.details),
    }
}

fn component_status_from_incident_store(health: &IncidentStoreHealth) -> ComponentStatus {
    ComponentStatus {
        ready: health.ready,
        durable: Some(health.durable),
        details: format!("{} ({})", health.backend, health.details),
    }
}

fn summarize_async_lane_status(
    config: &SwarmConfig,
    investigation_strategy: &str,
    queue: &InvestigationQueueSnapshot,
    investigation_store_health: &InvestigationStoreHealth,
    incident_store_health: &IncidentStoreHealth,
    recent_investigations: &[InvestigationBundleRecord],
    recent_incidents: &[IncidentRecord],
) -> AsyncLaneStatusSnapshot {
    let investigation_enabled = config.investigation.enabled;
    let correlation_enabled = config.correlation.enabled;
    let enabled = investigation_enabled || correlation_enabled;
    if !enabled {
        return AsyncLaneStatusSnapshot::disabled();
    }

    let mut warnings = Vec::new();
    if investigation_enabled && !investigation_store_health.ready {
        warnings.push("durable investigation store is not ready".to_string());
    }
    if correlation_enabled && !incident_store_health.ready {
        warnings.push("durable incident store is not ready".to_string());
    }
    if let Some(reason) = &queue.last_failure_reason {
        warnings.push(format!("recent investigation failure: {reason}"));
    }
    if queue.timed_out_jobs > 0 {
        warnings.push(format!(
            "{} investigation job(s) timed out",
            queue.timed_out_jobs
        ));
    }
    if queue.queue_budget_remaining == 0 && queue.max_pending_jobs > 0 {
        warnings.push("investigation queue budget is exhausted".to_string());
    } else if queue.budget_evictions > 0 {
        warnings.push(format!(
            "investigation queue evicted {} job(s) under pressure",
            queue.budget_evictions
        ));
    }

    let latest_incident = recent_incidents.first();
    AsyncLaneStatusSnapshot {
        enabled,
        investigation_enabled,
        correlation_enabled,
        status: if warnings.is_empty() {
            AsyncLaneStatusLevel::Ok
        } else {
            AsyncLaneStatusLevel::Degraded
        },
        investigation_strategy: Some(investigation_strategy.to_string()),
        investigation_store_ready: !investigation_enabled || investigation_store_health.ready,
        incident_store_ready: !correlation_enabled || incident_store_health.ready,
        queued_jobs: queue.queued_jobs,
        running_jobs: queue.running_jobs,
        queue_budget_remaining: queue.queue_budget_remaining,
        highest_priority_score_basis_points: queue.highest_priority_score_basis_points,
        oldest_job_age_ms: queue.oldest_job_age_ms,
        completed_jobs: queue.completed_jobs,
        failed_jobs: queue.failed_jobs,
        timed_out_jobs: queue.timed_out_jobs,
        budget_evictions: queue.budget_evictions,
        starvation_preventions: queue.starvation_preventions,
        recent_investigations: recent_investigations.len(),
        ambiguous_recent_investigations: recent_investigations
            .iter()
            .filter(|record| record.ambiguous)
            .count(),
        recent_incidents: recent_incidents.len(),
        latest_investigation_id: recent_investigations
            .first()
            .map(|record| record.investigation_id.clone()),
        latest_incident_id: latest_incident.map(|record| record.incident_id.clone()),
        latest_incident_confidence_score: latest_incident.map(|record| record.confidence_score),
        latest_incident_graph_dimensions: latest_incident
            .map(|record| record.graph_dimensions.clone())
            .unwrap_or_default(),
        last_failure_reason: queue.last_failure_reason.clone(),
        warnings,
    }
}

fn extend_unique_warnings(target: &mut Vec<String>, new_warnings: Vec<String>) {
    for warning in new_warnings {
        if !target.iter().any(|existing| existing == &warning) {
            target.push(warning);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        ConfiguredRuntimeStack, EventExecutionContext, ReadinessError, RehearsalPreviewError,
        ResponsePlaybookPreviewRequest, ResponsePlaybookPreviewStatus, RuntimeService,
        ServiceError,
    };
    use crate::bridge_runtime::{BridgeStatusReport, BridgeStatusSnapshot};
    use crate::correlation::CorrelationEngine;
    use crate::detection::metrics::{CriticalPathMetrics, encode_metrics};
    use crate::investigation::{InvestigationOutcome, InvestigationStrategy};
    use crate::{RuntimeMode, SwarmRuntime};
    use async_trait::async_trait;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::{Value, json};
    use swarm_core::agent::SwarmMode;
    use swarm_core::config::{
        AuditConfig, BundleStoreConfig, CanaryConfig, CircuitBreakerConfig, CorrelationConfig,
        InvestigationConfig, PheromoneBackendConfig, PheromoneConfig, PolicyConfig,
        PolicyRuleConfig, PolicyRuleDecision, PromotionConfig, ResponsePlaybookBranch,
        ResponsePlaybookCondition, ResponsePlaybookConfig, ResponsePlaybookRule, RetryConfig,
        RuntimeSettings, SiemForwardConfig, SwarmConfig, TelemetrySourceConfig,
        TemporalEventWindowConfig,
    };
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::{
        AgentId, HuntId, ResponseAction, ResponseBlastRadiusImpact, ResponseRehearsalScopeKind,
        ResponseRollbackStepKind, Severity,
    };
    use swarm_guard::{
        Guard, GuardAction, GuardContext, GuardPipeline, GuardResult, Severity as GuardSeverity,
    };
    use swarm_pheromone::{InMemoryPheromoneSubstrate, LocalJournalPheromoneSubstrate};
    use swarm_policy::static_gate::StaticApprovalGate;
    use swarm_policy::{ActionRequest, ApprovalContext, CapabilityLease, PolicyVerdict};
    use swarm_response::adapters::SandboxExecutor;
    use swarm_response::{
        ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt, ResponseStatus,
    };
    use swarm_spine::{
        AuditResponseRecord, FileReplayBundleStore, InvestigationBundleStore, MemoryIncidentStore,
        MemoryInvestigationBundleStore, MemoryReplayBundleStore, ReplayBundle, ReplayBundleStore,
    };
    use swarm_whisker::{
        ProcessStartEvent, SuspiciousProcessTreeDetector, TelemetryEvent, TelemetryEventPredicate,
        TelemetryPayload,
    };
    use tokio::sync::{Mutex as AsyncMutex, oneshot};

    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[42u8; 32])
    }

    fn test_agent_id() -> AgentId {
        AgentId::from_verifying_key(&test_signing_key().verifying_key())
    }

    fn service_config(
        mode: RuntimeMode,
        backend: PheromoneBackendConfig,
        require_durable: bool,
    ) -> SwarmConfig {
        SwarmConfig {
            schema_version: 1,
            name: "test".to_string(),
            description: "test config".to_string(),
            runtime: RuntimeSettings {
                mode,
                demo_mode: false,
                telemetry_sources: vec![TelemetrySourceConfig {
                    name: "synthetic".to_string(),
                    subject: "telemetry.synthetic.process".to_string(),
                    bridge: None,
                }],
                max_in_flight_actions: 4,
                drain_timeout_ms: 30_000,
                require_durable_live_response: require_durable,
                max_heap_pressure: 0.90,
                secret_dir: None,
                anti_tamper: Default::default(),
                temporal_event_window: TemporalEventWindowConfig::default(),
                agent_tick_timeout_ms: 500,
                governance_degraded_tick_threshold: 3,
                partition_contingency_lease_ttl_ms: 300_000,
                partition_contingency_blast_radius_cap: 1,
                max_dead_letter_bytes: None,
            },
            detection: swarm_core::config::DetectionConfig {
                strategy: "suspicious_process_tree".to_string(),
                strategies: Vec::new(),
                high_confidence_threshold: 0.9,
                medium_confidence_threshold: 0.7,
                profiles: swarm_core::config::DetectorProfilesConfig::default(),
            },
            pheromone: PheromoneConfig {
                default_half_life_secs: 3600.0,
                evaporation_threshold: 0.01,
                min_sources_for_escalation: 2,
                alert_threshold: 2.0,
                incident_threshold: 5.0,
                deescalation_cooldown_secs: 300,
                response_playbook: Default::default(),
                backend,
            },
            policy: PolicyConfig {
                human_gate_severity: Severity::High,
                lease_ttl_ms: 60_000,
                ..PolicyConfig::default()
            },
            response_adapter: swarm_core::config::ResponseAdapterConfig::Sandbox,
            siem_forward: None,
            notification_channels: std::collections::BTreeMap::new(),
            notification_routing: swarm_core::config::NotificationRoutingConfig::default(),
            audit: AuditConfig {
                bundle_store: BundleStoreConfig::Memory,
                recent_decisions_limit: 20,
            },
            investigation: InvestigationConfig::default(),
            correlation: CorrelationConfig::default(),
            canary: CanaryConfig::default(),
            promotion: PromotionConfig::default(),
            evolution: swarm_core::config::EvolutionConfig::default(),
            deception: swarm_core::config::DeceptionConfig::default(),
            memory: swarm_core::config::MemoryConfig::default(),
            identity: swarm_core::config::IdentityConfig::default(),
            platform_api: Default::default(),
            operator: swarm_core::config::OperatorSurfaceConfig::default(),
            tls: None,
        }
    }

    fn runtime_service() -> RuntimeService<StaticApprovalGate, SandboxExecutor> {
        RuntimeService::new(
            service_config(
                RuntimeMode::LiveResponse,
                PheromoneBackendConfig::InMemory,
                false,
            ),
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        )
    }

    fn runtime_service_with_prometheus() -> RuntimeService<StaticApprovalGate, SandboxExecutor> {
        runtime_service().with_prometheus(CriticalPathMetrics::new())
    }

    fn permissive_policy_rules() -> Vec<PolicyRuleConfig> {
        vec![PolicyRuleConfig {
            name: "service-preview-allow-execution".to_string(),
            decision: PolicyRuleDecision::Allow,
            threat_class: ThreatClass::Execution,
            actions: Vec::new(),
            min_severity: Severity::Low,
            max_severity: Severity::Critical,
            time_window_utc: None,
            max_actions_per_agent_per_minute: None,
            reason: Some("service preview tests allow execution responses".to_string()),
        }]
    }

    fn branching_playbook() -> ResponsePlaybookConfig {
        ResponsePlaybookConfig {
            rules: vec![ResponsePlaybookRule {
                threat_class: ThreatClass::Execution,
                severity: Severity::High,
                min_confidence: 0.90,
                max_confidence: 1.0,
                actions: vec![ResponseAction::Escalate {
                    summary: "fallback execution review".to_string(),
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
        }
    }

    fn runtime_service_with_branching_playbook()
    -> RuntimeService<StaticApprovalGate, SandboxExecutor> {
        let mut config = service_config(
            RuntimeMode::LiveResponse,
            PheromoneBackendConfig::InMemory,
            false,
        );
        config.policy.rules = permissive_policy_rules();
        config.pheromone.response_playbook = branching_playbook();
        RuntimeService::new(
            config,
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        )
    }

    fn suspicious_event(event_id: &str, command_line: &str) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: event_id.to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword".to_string(),
                process_name: "powershell".to_string(),
                command_line: command_line.to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        }
    }

    fn approval_context(now_ms: i64, correlation_id: &str) -> ApprovalContext {
        ApprovalContext {
            live_mode: true,
            receipt_chain: vec![format!("receipt-upstream-{now_ms}")],
            correlation_id: Some(correlation_id.to_string()),
            now_ms,
        }
    }

    fn preview_request(action: ResponseAction) -> ActionRequest {
        ActionRequest {
            hunt_id: HuntId("hunt-preview".to_string()),
            requested_by: test_agent_id(),
            action,
            severity: Severity::High,
            evidence: json!({
                "test": "phase_213_preview"
            }),
        }
    }

    #[derive(Clone, Default)]
    struct ForwardCaptureState {
        auth: std::sync::Arc<AsyncMutex<Option<String>>>,
        payloads: std::sync::Arc<AsyncMutex<Vec<Value>>>,
    }

    async fn forward_capture_handler(
        State(state): State<ForwardCaptureState>,
        headers: HeaderMap,
        Json(payload): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        {
            let mut auth = state.auth.lock().await;
            *auth = headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string);
        }
        {
            let mut payloads = state.payloads.lock().await;
            payloads.push(payload);
        }
        (StatusCode::OK, Json(json!({"ok": true})))
    }

    async fn spawn_forward_capture_server() -> (
        String,
        ForwardCaptureState,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let state = ForwardCaptureState::default();
        let app = Router::new()
            .route("/", post(forward_capture_handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let server = axum::serve(listener, app).with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            });
            let _ = server.await;
        });
        (format!("http://{address}/"), state, shutdown_tx, handle)
    }

    fn temp_jsonl_path(label: &str) -> String {
        std::env::temp_dir()
            .join(format!(
                "swarm-runtime-{label}-{}-{}.jsonl",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
            .display()
            .to_string()
    }

    struct BlockingGuard;

    impl Guard for BlockingGuard {
        fn name(&self) -> &str {
            "test_guard"
        }

        fn handles(&self, _action: &GuardAction<'_>) -> bool {
            true
        }

        fn check(&self, _action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
            GuardResult::block("test_guard", GuardSeverity::Critical, "blocked in test")
        }
    }

    #[derive(Clone)]
    struct TimeoutExecutor;

    #[async_trait]
    impl ResponseExecutor for TimeoutExecutor {
        async fn execute(
            &self,
            request: &ActionRequest,
            _lease: &CapabilityLease,
            mode: ExecutionMode,
        ) -> Result<ResponseReceipt, ResponseError> {
            Ok(ResponseReceipt {
                receipt_id: format!("timeout:{}", request.hunt_id.0),
                action: request.action.kind().to_string(),
                mode,
                status: ResponseStatus::Timeout,
                summary: "timed out in test".to_string(),
                details: serde_json::json!({
                    "adapter": "timeout_test",
                    "status": "timeout",
                }),
                audit: Default::default(),
            })
        }
    }

    #[derive(Clone, Default)]
    struct RecordingModeExecutor {
        modes: std::sync::Arc<AsyncMutex<Vec<ExecutionMode>>>,
    }

    #[async_trait]
    impl ResponseExecutor for RecordingModeExecutor {
        async fn execute(
            &self,
            request: &ActionRequest,
            _lease: &CapabilityLease,
            mode: ExecutionMode,
        ) -> Result<ResponseReceipt, ResponseError> {
            self.modes.lock().await.push(mode);
            Ok(ResponseReceipt {
                receipt_id: format!("recorded:{}", request.hunt_id.0),
                action: request.action.kind().to_string(),
                mode,
                status: if mode == ExecutionMode::DryRun {
                    ResponseStatus::Simulated
                } else {
                    ResponseStatus::Executed
                },
                summary: "recorded execution".to_string(),
                details: serde_json::json!({
                    "adapter": "recording_mode_executor",
                }),
                audit: Default::default(),
            })
        }
    }

    fn runtime_service_with_recording_modes() -> (
        RuntimeService<StaticApprovalGate, RecordingModeExecutor>,
        std::sync::Arc<AsyncMutex<Vec<ExecutionMode>>>,
    ) {
        let executor = RecordingModeExecutor::default();
        let modes = executor.modes.clone();
        (
            RuntimeService::new(
                service_config(
                    RuntimeMode::LiveResponse,
                    PheromoneBackendConfig::InMemory,
                    false,
                ),
                SwarmRuntime::new(
                    RuntimeMode::LiveResponse,
                    StaticApprovalGate::default(),
                    executor,
                ),
            ),
            modes,
        )
    }

    #[derive(Debug, Clone)]
    struct SlowInvestigator {
        delay_ms: u64,
    }

    #[async_trait]
    impl InvestigationStrategy for SlowInvestigator {
        fn id(&self) -> &str {
            "slow_service_test_investigator"
        }

        async fn investigate(&self, replay: &ReplayBundle) -> Result<InvestigationOutcome, String> {
            tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
            Ok(InvestigationOutcome {
                summary: format!("investigated {}", replay.audit.hunt_id),
                evidence_points: vec!["host_id=host-1".to_string()],
                correlation_keys: vec!["host:host-1".to_string()],
                candidate_interpretations: Vec::new(),
                vote_lineage: Vec::new(),
            })
        }
    }

    #[tokio::test]
    async fn process_event_creates_and_replays_bundle() {
        let service = runtime_service();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-1".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword".to_string(),
                process_name: "powershell".to_string(),
                command_line: "powershell.exe -enc AAA=".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };
        let context = ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-1".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_000_000,
        };
        let agent_id = test_agent_id();

        let bundle = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(swarm_core::types::ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        match &bundle.audit.response {
            AuditResponseRecord::Success(receipt) => {
                assert_eq!(receipt.status, ResponseStatus::Executed);
            }
            other => panic!("expected successful response record, got {other:?}"),
        }

        let path = std::env::temp_dir().join("swarm-runtime-replay-bundle.json");
        service.save_replay_bundle(&bundle, &path).unwrap();
        let replayed = service.load_replay_bundle(&path).unwrap();

        assert_eq!(replayed.audit.trail_id, bundle.audit.trail_id);
        assert_eq!(replayed.findings.len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn process_event_records_temporal_window_state_without_findings() {
        let mut config = service_config(
            RuntimeMode::DetectOnly,
            PheromoneBackendConfig::InMemory,
            false,
        );
        config.runtime.temporal_event_window = TemporalEventWindowConfig {
            retention_ms: 120_000,
            max_events: 4,
            max_match_span_ms: 120_000,
            max_predicates_per_match: 4,
        };
        let service = RuntimeService::new(
            config,
            SwarmRuntime::new(
                RuntimeMode::DetectOnly,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        );
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let agent_id = test_agent_id();
        let first_event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-seq-a".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "explorer".to_string(),
                process_name: "cmd".to_string(),
                command_line: "cmd.exe /c whoami".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };
        let second_event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-seq-b".to_string(),
            timestamp: 1_700_000_030,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "cmd".to_string(),
                process_name: "whoami".to_string(),
                command_line: "whoami".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };
        let first_context = ApprovalContext {
            live_mode: false,
            receipt_chain: vec!["receipt-seq-a".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_000_000,
        };
        let second_context = ApprovalContext {
            live_mode: false,
            receipt_chain: vec!["receipt-seq-b".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_030_000,
        };

        assert!(
            service
                .process_event(
                    &detector,
                    &substrate,
                    &first_event,
                    EventExecutionContext {
                        agent_id: &agent_id,
                        approval: &first_context,
                        signing_key: &test_signing_key(),
                    },
                    |_finding| None,
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            service
                .process_event(
                    &detector,
                    &substrate,
                    &second_event,
                    EventExecutionContext {
                        agent_id: &agent_id,
                        approval: &second_context,
                        signing_key: &test_signing_key(),
                    },
                    |_finding| None,
                )
                .await
                .unwrap()
                .is_none()
        );

        let snapshot = service.runtime.temporal_event_window_snapshot();
        assert_eq!(snapshot.retained_events, 2);

        let first_step = |event: &TelemetryEvent| event.event_id == "evt-seq-a";
        let second_step = |event: &TelemetryEvent| event.event_id == "evt-seq-b";
        let predicates: [&dyn TelemetryEventPredicate; 2] = [&first_step, &second_step];
        let matched = service
            .runtime
            .match_temporal_sequence(&predicates, Some(60_000))
            .unwrap()
            .unwrap();
        assert_eq!(matched.matched_events.len(), 2);
        assert_eq!(matched.matched_events[0].event_id, "evt-seq-a");
        assert_eq!(matched.matched_events[1].event_id, "evt-seq-b");
    }

    #[tokio::test]
    async fn process_event_preserves_stable_identity_in_request_and_receipt() {
        let service = runtime_service();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-stable-identity".to_string(),
            timestamp: 1_700_000_111,
            host_id: Some("host-identity".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword".to_string(),
                process_name: "powershell".to_string(),
                command_line: "powershell.exe -enc AAA=".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };
        let context = ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-identity-1".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_111_000,
        };
        let agent_id = AgentId::from_verifying_key(&test_signing_key().verifying_key());

        let bundle = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(swarm_core::types::ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        assert_eq!(bundle.action_request.requested_by, agent_id);
        let AuditResponseRecord::Success(receipt) = &bundle.audit.response else {
            panic!(
                "expected successful response record, got {:?}",
                bundle.audit.response
            );
        };
        assert_eq!(receipt.details["requested_by"], serde_json::json!(agent_id));
    }

    #[tokio::test]
    async fn process_event_enriches_findings_before_bundle_persistence() {
        let service = runtime_service();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = suspicious_event("evt-enrichment-1", "powershell.exe -enc AAA=");
        let context = approval_context(1_700_000_000_005, "corr-enrichment");
        let agent_id = test_agent_id();

        let bundle = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        let evidence = &bundle.findings[0].evidence;
        assert_eq!(
            evidence["parent_process_ancestry"],
            json!(["winword", "powershell"])
        );
        assert_eq!(evidence["host_metadata"]["source"], "synthetic");
        assert_eq!(evidence["host_metadata"]["host_id"], "host-1");
        assert_eq!(evidence["host_metadata"]["event_id"], "evt-enrichment-1");
        assert_eq!(evidence["host_metadata"]["event_timestamp"], 1_700_000_000);
        assert!(evidence["time_to_detect_ms"].as_i64().unwrap() >= 0);
    }

    #[tokio::test]
    async fn process_event_forwards_enriched_findings_to_siem() {
        let (endpoint, state, shutdown_tx, handle) = spawn_forward_capture_server().await;
        let dead_letter_path = temp_jsonl_path("siem-forward");
        let mut config = service_config(
            RuntimeMode::LiveResponse,
            PheromoneBackendConfig::InMemory,
            false,
        );
        config.siem_forward = Some(SiemForwardConfig::SplunkHec {
            endpoint,
            auth_token: "splunk-secret".to_string(),
            timeout_ms: 500,
            retry: RetryConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            dead_letter_path: dead_letter_path.clone(),
        });
        let service = RuntimeService::new(
            config,
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        );
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = suspicious_event("evt-siem-1", "powershell.exe -enc AAA=");
        let context = approval_context(1_700_000_000_021, "corr-siem");
        let agent_id = test_agent_id();

        let bundle = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
                    signing_key: &test_signing_key(),
                },
                |_finding| None,
            )
            .await
            .unwrap();

        assert!(bundle.is_none());
        assert_eq!(
            state.auth.lock().await.clone().as_deref(),
            Some("Splunk splunk-secret")
        );
        let payloads = state.payloads.lock().await.clone();
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0]["event"]["schema"], "swarm_finding");
        assert_eq!(payloads[0]["event"]["event_id"], "evt-siem-1");
        assert_eq!(
            payloads[0]["event"]["evidence"]["parent_process_ancestry"],
            json!(["winword", "powershell"])
        );
        assert_eq!(
            payloads[0]["event"]["evidence"]["host_metadata"]["host_id"],
            "host-1"
        );
        assert!(
            payloads[0]["event"]["evidence"]["time_to_detect_ms"]
                .as_i64()
                .unwrap()
                >= 0
        );

        let _ = shutdown_tx.send(());
        handle.abort();
        let _ = std::fs::remove_file(dead_letter_path);
    }

    #[tokio::test]
    async fn process_event_records_success_metrics_in_prometheus() {
        let service = runtime_service_with_prometheus();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = suspicious_event("evt-metrics-success", "powershell.exe -enc AAA=");
        let context = approval_context(1_700_000_000_010, "corr-success");
        let agent_id = test_agent_id();

        let bundle = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        assert_eq!(bundle.audit.policy.verdict, PolicyVerdict::Allow);
        let encoded = encode_metrics(service.prometheus_metrics().unwrap());
        assert!(encoded.contains("swarm_verdict_total{verdict=\"allow\"} 1"));
        assert!(encoded.contains("swarm_adapter_outcomes_total{outcome=\"success\"} 1"));
        assert!(
            encoded.contains(
                "swarm_findings_total{detector=\"suspicious_process_tree\",threat_class=\"execution\"} 1"
            ) || encoded.contains(
                "swarm_findings_total{threat_class=\"execution\",detector=\"suspicious_process_tree\"} 1"
            )
        );
    }

    #[tokio::test]
    async fn process_event_records_guard_rejection_metrics_in_prometheus() {
        let runtime = SwarmRuntime::new(
            RuntimeMode::LiveResponse,
            StaticApprovalGate::default(),
            SandboxExecutor,
        )
        .with_guard_pipeline(GuardPipeline::new(vec![Box::new(BlockingGuard)]));
        let service = RuntimeService::new(
            service_config(
                RuntimeMode::LiveResponse,
                PheromoneBackendConfig::InMemory,
                false,
            ),
            runtime,
        )
        .with_prometheus(CriticalPathMetrics::new());
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = suspicious_event("evt-metrics-guard", "powershell.exe -enc AAA=");
        let context = approval_context(1_700_000_000_011, "corr-guard");
        let agent_id = test_agent_id();

        let bundle = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        assert!(matches!(
            bundle.audit.response,
            AuditResponseRecord::GuardRejected { .. }
        ));
        let encoded = encode_metrics(service.prometheus_metrics().unwrap());
        assert!(encoded.contains("swarm_verdict_total{verdict=\"allow\"} 1"));
        assert!(encoded.contains("swarm_guard_rejections_total{guard_name=\"test_guard\"} 1"));
    }

    #[tokio::test]
    async fn process_event_records_timeout_metrics_in_prometheus() {
        let service = RuntimeService::new(
            service_config(
                RuntimeMode::LiveResponse,
                PheromoneBackendConfig::InMemory,
                false,
            ),
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                TimeoutExecutor,
            ),
        )
        .with_prometheus(CriticalPathMetrics::new());
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = suspicious_event("evt-metrics-timeout", "powershell.exe -enc AAA=");
        let context = approval_context(1_700_000_000_012, "corr-timeout");
        let agent_id = test_agent_id();

        let bundle = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        assert!(matches!(
            bundle.audit.response,
            AuditResponseRecord::Failure(_)
        ));
        let encoded = encode_metrics(service.prometheus_metrics().unwrap());
        assert!(encoded.contains("swarm_verdict_total{verdict=\"allow\"} 1"));
        assert!(encoded.contains("swarm_adapter_outcomes_total{outcome=\"timeout\"} 1"));
    }

    #[tokio::test]
    async fn process_event_records_require_human_metrics_in_prometheus() {
        let service = runtime_service_with_prometheus();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = suspicious_event("evt-metrics-human", "powershell.exe -enc AAA=");
        let context = approval_context(1_700_000_000_013, "corr-human");
        let agent_id = test_agent_id();

        let bundle = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(ResponseAction::BlockEgress {
                        target: "203.0.113.10".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        assert_eq!(bundle.audit.policy.verdict, PolicyVerdict::RequireHuman);
        assert!(matches!(
            bundle.audit.response,
            AuditResponseRecord::Skipped { .. }
        ));
        let encoded = encode_metrics(service.prometheus_metrics().unwrap());
        assert!(encoded.contains("swarm_verdict_total{verdict=\"require_human\"} 1"));
    }

    #[tokio::test]
    async fn live_response_requires_durable_substrate_when_enabled() {
        let service = RuntimeService::new(
            service_config(
                RuntimeMode::LiveResponse,
                PheromoneBackendConfig::InMemory,
                true,
            ),
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        );
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());

        let error = service
            .ensure_substrate_ready(&substrate)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ServiceError::Readiness {
                component: "substrate",
                source: ReadinessError::SubstrateNotDurable { .. },
            }
        ));
    }

    #[tokio::test]
    async fn local_journal_satisfies_durable_live_response_readiness() {
        let path = std::env::temp_dir().join("swarm-runtime-durable-substrate.jsonl");
        let service = RuntimeService::new(
            service_config(
                RuntimeMode::LiveResponse,
                PheromoneBackendConfig::LocalJournal {
                    path: path.display().to_string(),
                },
                true,
            ),
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        );
        let substrate =
            LocalJournalPheromoneSubstrate::open(service.config.pheromone.clone(), &path).unwrap();

        let health = service.ensure_substrate_ready(&substrate).await.unwrap();
        assert!(health.ready);
        assert!(health.durable);

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn process_event_with_store_persists_and_loads_by_receipt_id() {
        let service = runtime_service();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let store_root = std::env::temp_dir().join("swarm-runtime-file-store");
        let _ = std::fs::remove_dir_all(&store_root);
        let store = FileReplayBundleStore::open(&store_root).unwrap();
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-store-1".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword".to_string(),
                process_name: "powershell".to_string(),
                command_line: "powershell.exe -enc AAA=".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };
        let context = ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-upstream-1".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_000_001,
        };
        let agent_id = test_agent_id();

        let persisted = service
            .process_event_with_store(
                &detector,
                &substrate,
                &store,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(swarm_core::types::ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        let response_receipt_id = persisted
            .record
            .response_receipt_id
            .clone()
            .expect("response receipt id");
        let loaded = service
            .load_persisted_bundle_by_receipt_id(&store, &response_receipt_id)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.record.bundle_id, persisted.record.bundle_id);

        let preview = service.replay_preview(&loaded.bundle);
        assert_eq!(preview.bundle_id, persisted.record.bundle_id);
        assert!(
            preview
                .note
                .contains("no live response action was re-executed")
        );

        let _ = std::fs::remove_dir_all(store_root);
    }

    #[tokio::test]
    async fn rehearse_bundle_persists_typed_preview_and_forces_dry_run() {
        let (service, modes) = runtime_service_with_recording_modes();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = suspicious_event("evt-rehearsal-1", "powershell.exe -enc AAA=");
        let source_context = approval_context(1_700_000_000_100, "corr-rehearsal-source");
        let agent_id = test_agent_id();

        let source = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &source_context,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(ResponseAction::BlockEgress {
                        target: "203.0.113.10".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        assert!(matches!(
            source.audit.response,
            AuditResponseRecord::Skipped { .. }
        ));
        assert!(modes.lock().await.is_empty());

        let store = MemoryReplayBundleStore::default();
        let rehearsal_context = approval_context(1_700_000_000_200, "corr-rehearsal-run");
        let persisted = service
            .rehearse_bundle_with_store(&store, &source, &rehearsal_context)
            .await
            .unwrap();

        assert_eq!(&*modes.lock().await, &[ExecutionMode::DryRun]);
        assert!(persisted.record.is_rehearsal);
        assert!(persisted.record.bundle_id.contains("rehearsal"));
        let rehearsal = persisted
            .bundle
            .rehearsal
            .as_ref()
            .expect("rehearsal preview");
        assert_eq!(rehearsal.source_bundle_id, source.bundle_id);
        assert!(rehearsal.simulated_only);
        assert_eq!(
            rehearsal.blast_radius.scope_kind,
            ResponseRehearsalScopeKind::NetworkTarget
        );
        assert_eq!(
            rehearsal.rollback.steps[0].kind,
            ResponseRollbackStepKind::RemoveNetworkBlock
        );
        let AuditResponseRecord::Success(receipt) = &persisted.bundle.audit.response else {
            panic!(
                "expected successful rehearsal response, got {:?}",
                persisted.bundle.audit.response
            );
        };
        assert_eq!(
            persisted.bundle.audit.policy.verdict,
            PolicyVerdict::RequireHuman
        );
        assert_eq!(receipt.mode, ExecutionMode::DryRun);
        assert_eq!(receipt.status, ResponseStatus::Simulated);

        let loaded = service
            .load_persisted_bundle_by_bundle_id(&store, &persisted.record.bundle_id)
            .unwrap()
            .unwrap();
        let preview = service.replay_preview(&loaded.bundle);
        assert!(preview.rehearsal.is_some());
        assert!(preview.note.contains("dry-run receipt"));
    }

    #[test]
    fn rehearsal_preview_covers_expanded_response_action_catalog() {
        let service = runtime_service();
        let source_bundle_id = "bundle-expanded-catalog";
        let prepared_at_ms = 1_700_000_000_250;
        let cases = vec![
            (
                ResponseAction::SinkholeDns {
                    domain: "sinkhole.example".to_string(),
                },
                ResponseRehearsalScopeKind::NetworkTarget,
                "sinkhole.example".to_string(),
                ResponseBlastRadiusImpact::DnsResolutionSinkholed,
                true,
                ResponseRollbackStepKind::RemoveDnsSinkhole,
            ),
            (
                ResponseAction::TerminateUserSession {
                    host_id: "host-77".to_string(),
                    session_id: "session-9".to_string(),
                },
                ResponseRehearsalScopeKind::UserSession,
                "host-77:session-9".to_string(),
                ResponseBlastRadiusImpact::UserSessionTerminated,
                false,
                ResponseRollbackStepKind::ReauthenticateUserSession,
            ),
            (
                ResponseAction::TriggerEdrScan {
                    host_id: "host-22".to_string(),
                    scan_profile: "memory_quick".to_string(),
                },
                ResponseRehearsalScopeKind::Host,
                "host-22".to_string(),
                ResponseBlastRadiusImpact::HostScanTriggered,
                false,
                ResponseRollbackStepKind::CancelHostScan,
            ),
            (
                ResponseAction::InjectFirewallRule {
                    host_id: "host-44".to_string(),
                    rule_name: "deny-c2".to_string(),
                    direction: "egress".to_string(),
                    cidr: "203.0.113.0/24".to_string(),
                    port: Some(443),
                },
                ResponseRehearsalScopeKind::Host,
                "host-44".to_string(),
                ResponseBlastRadiusImpact::HostFirewallPolicyChanged,
                true,
                ResponseRollbackStepKind::RemoveFirewallRule,
            ),
            (
                ResponseAction::QuarantineFile {
                    host_id: "host-55".to_string(),
                    file_path: "/tmp/payload.exe".to_string(),
                },
                ResponseRehearsalScopeKind::File,
                "host-55:/tmp/payload.exe".to_string(),
                ResponseBlastRadiusImpact::FileQuarantined,
                true,
                ResponseRollbackStepKind::ReleaseQuarantinedFile,
            ),
            (
                ResponseAction::KillProcess {
                    host_id: "host-88".to_string(),
                    process_name: "powershell.exe".to_string(),
                },
                ResponseRehearsalScopeKind::Process,
                "host-88:powershell.exe".to_string(),
                ResponseBlastRadiusImpact::ProcessTerminated,
                false,
                ResponseRollbackStepKind::RestartProcess,
            ),
            (
                ResponseAction::SuspendProcess {
                    host_id: "host-99".to_string(),
                    process_name: "cmd.exe".to_string(),
                },
                ResponseRehearsalScopeKind::Process,
                "host-99:cmd.exe".to_string(),
                ResponseBlastRadiusImpact::ProcessSuspended,
                true,
                ResponseRollbackStepKind::ResumeProcess,
            ),
            (
                ResponseAction::DisableUserAccount {
                    user_id: "alice@example.com".to_string(),
                },
                ResponseRehearsalScopeKind::UserAccount,
                "alice@example.com".to_string(),
                ResponseBlastRadiusImpact::UserAccountDisabled,
                true,
                ResponseRollbackStepKind::ReenableUserAccount,
            ),
            (
                ResponseAction::ForcePasswordReset {
                    user_id: "bob@example.com".to_string(),
                },
                ResponseRehearsalScopeKind::UserAccount,
                "bob@example.com".to_string(),
                ResponseBlastRadiusImpact::PasswordResetEnforced,
                true,
                ResponseRollbackStepKind::ClearPasswordResetRequirement,
            ),
            (
                ResponseAction::RemoveScheduledTask {
                    host_id: "host-66".to_string(),
                    task_name: "DailyUpdater".to_string(),
                },
                ResponseRehearsalScopeKind::ScheduledTask,
                "host-66:DailyUpdater".to_string(),
                ResponseBlastRadiusImpact::ScheduledTaskRemoved,
                true,
                ResponseRollbackStepKind::RestoreScheduledTask,
            ),
        ];

        for (
            action,
            expected_scope_kind,
            expected_scope_value,
            expected_impact,
            expected_rollback_required,
            expected_step_kind,
        ) in cases
        {
            let preview = service
                .rehearsal_preview(&preview_request(action), source_bundle_id, prepared_at_ms)
                .expect("expanded action preview");
            assert_eq!(preview.source_bundle_id, source_bundle_id);
            assert!(preview.simulated_only);
            assert_eq!(preview.blast_radius.scope_kind, expected_scope_kind);
            assert_eq!(preview.blast_radius.scope_value, expected_scope_value);
            assert_eq!(preview.blast_radius.impact, expected_impact);
            assert_eq!(preview.rollback.required, expected_rollback_required);
            assert_eq!(preview.rollback.steps.len(), 1);
            assert_eq!(preview.rollback.steps[0].kind, expected_step_kind);
        }
    }

    #[tokio::test]
    async fn rehearse_bundle_supports_expanded_firewall_action_preview() {
        let (service, modes) = runtime_service_with_recording_modes();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = suspicious_event("evt-rehearsal-firewall", "powershell.exe -enc AAA=");
        let source_context = approval_context(1_700_000_000_320, "corr-rehearsal-firewall");
        let agent_id = test_agent_id();

        let source = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &source_context,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(ResponseAction::InjectFirewallRule {
                        host_id: "host-22".to_string(),
                        rule_name: "deny-c2".to_string(),
                        direction: "egress".to_string(),
                        cidr: "203.0.113.0/24".to_string(),
                        port: Some(443),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        assert!(matches!(
            source.audit.response,
            AuditResponseRecord::Skipped { .. }
        ));
        assert!(modes.lock().await.is_empty());

        let store = MemoryReplayBundleStore::default();
        let rehearsal_context = approval_context(1_700_000_000_321, "corr-rehearsal-run");
        let persisted = service
            .rehearse_bundle_with_store(&store, &source, &rehearsal_context)
            .await
            .unwrap();

        assert_eq!(&*modes.lock().await, &[ExecutionMode::DryRun]);
        let rehearsal = persisted
            .bundle
            .rehearsal
            .as_ref()
            .expect("rehearsal preview");
        assert_eq!(
            rehearsal.blast_radius.scope_kind,
            ResponseRehearsalScopeKind::Host
        );
        assert_eq!(
            rehearsal.blast_radius.impact,
            ResponseBlastRadiusImpact::HostFirewallPolicyChanged
        );
        assert_eq!(
            rehearsal.rollback.steps[0].kind,
            ResponseRollbackStepKind::RemoveFirewallRule
        );
    }

    #[tokio::test]
    async fn rehearse_bundle_fails_closed_before_executor_when_scope_metadata_is_missing() {
        let (service, modes) = runtime_service_with_recording_modes();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = suspicious_event("evt-rehearsal-invalid", "powershell.exe -enc AAA=");
        let source_context = approval_context(1_700_000_000_300, "corr-rehearsal-invalid");
        let agent_id = test_agent_id();

        let mut source = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &source_context,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(ResponseAction::BlockEgress {
                        target: "203.0.113.10".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();
        source.action_request.action = ResponseAction::BlockEgress {
            target: "   ".to_string(),
        };

        let store = MemoryReplayBundleStore::default();
        let rehearsal_context = approval_context(1_700_000_000_301, "corr-rehearsal-preview");
        let error = service
            .rehearse_bundle_with_store(&store, &source, &rehearsal_context)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            ServiceError::RehearsalPreview(RehearsalPreviewError::EmptyValue {
                label: "block target"
            })
        ));
        assert!(modes.lock().await.is_empty());
        assert!(store.recent(10).unwrap().is_empty());
    }

    #[test]
    fn playbook_preview_matches_branch_and_projects_policy_requirements() {
        let service = runtime_service_with_branching_playbook();

        let report = service
            .playbook_preview(
                ResponsePlaybookPreviewRequest {
                    threat_class: ThreatClass::Execution,
                    severity: Severity::High,
                    confidence: 0.98,
                    mode: SwarmMode::Incident,
                },
                1_700_000_000_777,
            )
            .expect("playbook preview");

        assert_eq!(report.status, ResponsePlaybookPreviewStatus::Matched);
        assert_eq!(report.actions.len(), 2);
        assert_eq!(report.approval_summary.allow_count, 2);
        let matched = report.matched_rule.expect("matched rule");
        assert_eq!(matched.rule_index, 0);
        assert_eq!(
            matched
                .branch
                .as_ref()
                .and_then(|branch| branch.name.as_deref()),
            Some("incident_containment")
        );
        assert!(matches!(
            report.actions[0].action,
            ResponseAction::BlockEgress { .. }
        ));
        assert_eq!(
            report.actions[0].rehearsal.blast_radius.scope_kind,
            ResponseRehearsalScopeKind::NetworkTarget
        );
        assert_eq!(report.actions[0].policy.verdict, PolicyVerdict::Allow);
        assert!(report.actions[0].policy.lease_scope.is_some());
    }

    #[test]
    fn playbook_preview_uses_fallback_actions_when_no_branch_matches() {
        let service = runtime_service_with_branching_playbook();

        let report = service
            .playbook_preview(
                ResponsePlaybookPreviewRequest {
                    threat_class: ThreatClass::Execution,
                    severity: Severity::High,
                    confidence: 0.93,
                    mode: SwarmMode::Alert,
                },
                1_700_000_000_778,
            )
            .expect("playbook preview");

        assert_eq!(report.status, ResponsePlaybookPreviewStatus::Matched);
        assert_eq!(report.actions.len(), 1);
        assert_eq!(report.approval_summary.allow_count, 1);
        assert_eq!(report.matched_rule.expect("matched rule").branch, None);
        assert!(matches!(
            report.actions[0].action,
            ResponseAction::Escalate { .. }
        ));
    }

    #[tokio::test]
    async fn operator_status_reports_metrics_and_recent_decisions() {
        let service = runtime_service();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let store_root = std::env::temp_dir().join("swarm-runtime-operator-store");
        let _ = std::fs::remove_dir_all(&store_root);
        let store = FileReplayBundleStore::open(&store_root).unwrap();
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-status-1".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword".to_string(),
                process_name: "powershell".to_string(),
                command_line: "powershell.exe -enc AAA=".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };
        let context = ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-upstream-2".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_000_002,
        };
        let agent_id = test_agent_id();

        let _ = service
            .process_event_with_store(
                &detector,
                &substrate,
                &store,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(swarm_core::types::ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        let status = service
            .operator_status(&detector, &substrate, &store)
            .await
            .unwrap();
        assert_eq!(status.mode, RuntimeMode::LiveResponse);
        assert_eq!(
            status.detector.details,
            "strategy `suspicious_process_tree`"
        );
        assert_eq!(status.replay_store.durable, Some(true));
        assert_eq!(status.recent_decisions.len(), 1);
        assert_eq!(status.metrics.detect.successes, 1);
        assert_eq!(status.metrics.policy.successes, 1);
        assert_eq!(status.metrics.persist.successes, 1);
        assert_eq!(status.metrics.response.successes, 1);
        assert!(status.bridges.is_none());
        assert!(status.warnings.is_empty());

        let recent = store.recent(1).unwrap();
        assert_eq!(recent.len(), 1);

        let _ = std::fs::remove_dir_all(store_root);
    }

    #[tokio::test]
    async fn operator_status_with_bridges_surfaces_bridge_report_and_warning() {
        let config = service_config(
            RuntimeMode::DetectOnly,
            PheromoneBackendConfig::InMemory,
            false,
        );
        let service = RuntimeService::new(
            config,
            SwarmRuntime::new(
                RuntimeMode::DetectOnly,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        );
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let store = swarm_spine::MemoryReplayBundleStore::default();

        let bridges = BridgeStatusReport::from_entries(vec![
            BridgeStatusSnapshot {
                name: "cloudtrail-primary".to_string(),
                source_id: "cloudtrail".to_string(),
                ready: true,
                events_processed: 4,
                error_count: 0,
                lag_seconds: Some(1.5),
                last_error: None,
            },
            BridgeStatusSnapshot {
                name: "tetragon-primary".to_string(),
                source_id: "tetragon".to_string(),
                ready: false,
                events_processed: 9,
                error_count: 2,
                lag_seconds: Some(8.0),
                last_error: Some("stream closed".to_string()),
            },
        ]);

        let status = service
            .operator_status_with_bridges(&detector, &substrate, &store, bridges)
            .await
            .unwrap();

        assert_eq!(
            status.bridges.as_ref().map(|report| report.configured),
            Some(2)
        );
        assert!(
            status
                .warnings
                .iter()
                .any(|warning| warning.contains("telemetry bridge"))
        );
    }

    #[tokio::test]
    async fn process_event_with_investigation_stays_nonblocking_and_persists_bundle() {
        let mut config = service_config(
            RuntimeMode::LiveResponse,
            PheromoneBackendConfig::InMemory,
            false,
        );
        config.investigation = InvestigationConfig {
            enabled: true,
            worker_count: 1,
            max_pending_jobs: 2,
            time_budget_ms: 250,
            bundle_store: BundleStoreConfig::Memory,
            ..InvestigationConfig::default()
        };
        let service = RuntimeService::new(
            config.clone(),
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        );
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let replay_store_root =
            std::env::temp_dir().join("swarm-runtime-investigation-replay-store");
        let _ = std::fs::remove_dir_all(&replay_store_root);
        let replay_store = FileReplayBundleStore::open(&replay_store_root).unwrap();
        let investigation_store = MemoryInvestigationBundleStore::default();
        let coordinator = crate::investigation::InvestigationCoordinator::new(
            config.investigation.clone(),
            SlowInvestigator { delay_ms: 75 },
            investigation_store.clone(),
        );
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-investigation-1".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword".to_string(),
                process_name: "powershell".to_string(),
                command_line: "powershell.exe -enc AAA=".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };
        let context = ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-upstream-3".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_000_003,
        };
        let agent_id = test_agent_id();

        let started = std::time::Instant::now();
        let persisted = service
            .process_event_with_store_and_investigation(
                &detector,
                &substrate,
                &replay_store,
                &coordinator,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(swarm_core::types::ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();
        let elapsed = started.elapsed();

        assert!(
            elapsed < std::time::Duration::from_millis(70),
            "expected nonblocking path to return before the 75ms investigation delay, elapsed={elapsed:?}"
        );
        let investigation = persisted.investigation.expect("queued investigation");
        assert_eq!(
            investigation.status,
            swarm_spine::InvestigationStatus::Queued
        );

        tokio::time::sleep(std::time::Duration::from_millis(125)).await;

        let by_hunt = service
            .load_persisted_investigation_by_hunt_id(&investigation_store, "evt-investigation-1")
            .unwrap()
            .unwrap();
        assert_eq!(
            by_hunt.bundle.status,
            swarm_spine::InvestigationStatus::Completed
        );

        let receipt_id = persisted
            .replay
            .record
            .response_receipt_id
            .clone()
            .expect("response receipt id");
        let by_receipt = service
            .load_persisted_investigation_by_receipt_id(&investigation_store, &receipt_id)
            .unwrap()
            .unwrap();
        assert_eq!(by_receipt.bundle.hunt_id, "evt-investigation-1");
        assert!(coordinator.snapshot().completed_jobs >= 1);

        let _ = std::fs::remove_dir_all(replay_store_root);
    }

    #[tokio::test]
    async fn correlate_hunt_persists_incident_with_rejected_candidates() {
        let mut config = service_config(
            RuntimeMode::LiveResponse,
            PheromoneBackendConfig::InMemory,
            false,
        );
        config.investigation = InvestigationConfig {
            enabled: true,
            worker_count: 1,
            max_pending_jobs: 4,
            time_budget_ms: 250,
            bundle_store: BundleStoreConfig::Memory,
            ..InvestigationConfig::default()
        };
        config.correlation = CorrelationConfig {
            enabled: true,
            time_window_ms: 5_000,
            min_shared_keys: 1,
            candidate_limit: 16,
            incident_store: BundleStoreConfig::Memory,
        };
        let service = RuntimeService::new(
            config.clone(),
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        );
        let investigation_store = MemoryInvestigationBundleStore::default();
        let incident_store = MemoryIncidentStore::default();
        let engine = CorrelationEngine::new(config.correlation.clone());

        let completed = |investigation_id: &str,
                         hunt_id: &str,
                         queued_at_ms: i64,
                         correlation_keys: &[&str]| {
            swarm_spine::InvestigationBundle {
                investigation_id: investigation_id.to_string(),
                source_bundle_id: format!("bundle:{hunt_id}:1"),
                hunt_id: hunt_id.to_string(),
                trail_id: format!("trail:{hunt_id}:1"),
                event_id: format!("evt:{hunt_id}"),
                finding_id: format!("finding:{hunt_id}"),
                threat_class: swarm_core::pheromone::ThreatClass::Execution,
                severity: Severity::Critical,
                strategy_id: "summary_investigator".to_string(),
                response_kind: "success".to_string(),
                related_receipt_ids: vec![format!("receipt:{hunt_id}")],
                host_id: Some("host-1".to_string()),
                user: Some("alice".to_string()),
                process_name: Some("powershell".to_string()),
                queued_at_ms,
                started_at_ms: Some(queued_at_ms + 10),
                completed_at_ms: Some(queued_at_ms + 100),
                status: swarm_spine::InvestigationStatus::Completed,
                priority: swarm_spine::InvestigationPriority::default(),
                summary: Some(format!("summary for {hunt_id}")),
                evidence_points: vec!["host_id=host-1".to_string()],
                correlation_keys: correlation_keys.iter().map(|key| key.to_string()).collect(),
                candidate_interpretations: Vec::new(),
                vote_lineage: Vec::new(),
                decision: swarm_spine::InvestigationDecision::default(),
                failure_reason: None,
            }
        };

        investigation_store
            .persist(&completed(
                "investigation:hunt-1:1",
                "hunt-1",
                1_700_000_000_000,
                &["host:host-1", "user:alice", "strategy:summary"],
            ))
            .unwrap();
        investigation_store
            .persist(&completed(
                "investigation:hunt-2:1",
                "hunt-2",
                1_700_000_003_000,
                &["host:host-1", "user:alice"],
            ))
            .unwrap();
        investigation_store
            .persist(&completed(
                "investigation:hunt-3:1",
                "hunt-3",
                1_700_000_010_500,
                &["host:host-1"],
            ))
            .unwrap();

        let outcome = service
            .correlate_hunt(&engine, &investigation_store, &incident_store, "hunt-1")
            .unwrap()
            .unwrap();
        assert_eq!(outcome.incident.included_members.len(), 2);
        assert_eq!(outcome.incident.rejected_members.len(), 1);
        assert!(
            outcome
                .incident
                .rejected_members
                .first()
                .unwrap()
                .reason
                .contains("outside correlation time window")
        );

        let loaded = service
            .load_incident_by_hunt_id(&incident_store, "hunt-2")
            .unwrap()
            .unwrap();
        assert_eq!(loaded.record.incident_id, outcome.record.incident_id);
    }

    #[tokio::test]
    async fn operator_review_status_surfaces_async_context_and_freshness() {
        let mut config = service_config(
            RuntimeMode::LiveResponse,
            PheromoneBackendConfig::InMemory,
            false,
        );
        config.investigation = InvestigationConfig {
            enabled: true,
            worker_count: 1,
            max_pending_jobs: 1,
            time_budget_ms: 500,
            bundle_store: BundleStoreConfig::Memory,
            ..InvestigationConfig::default()
        };
        config.correlation = CorrelationConfig {
            enabled: true,
            time_window_ms: 5_000,
            min_shared_keys: 1,
            candidate_limit: 16,
            incident_store: BundleStoreConfig::Memory,
        };
        let service = RuntimeService::new(
            config.clone(),
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        );
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let replay_store_root = std::env::temp_dir().join("swarm-runtime-review-replay-store");
        let _ = std::fs::remove_dir_all(&replay_store_root);
        let replay_store = FileReplayBundleStore::open(&replay_store_root).unwrap();
        let investigation_store = MemoryInvestigationBundleStore::default();
        let incident_store = MemoryIncidentStore::default();
        let coordinator = crate::investigation::InvestigationCoordinator::new(
            config.investigation.clone(),
            SlowInvestigator { delay_ms: 100 },
            investigation_store.clone(),
        );
        let event_one = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-review-1".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword".to_string(),
                process_name: "powershell".to_string(),
                command_line: "powershell.exe -enc AAA=".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };
        let event_two = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-review-queue-fail".to_string(),
            timestamp: 1_700_000_001,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword".to_string(),
                process_name: "powershell".to_string(),
                command_line: "powershell.exe -enc BBB=".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };
        let context_one = ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-upstream-review-1".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_000_010,
        };
        let context_two = ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-upstream-review-2".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_000_020,
        };
        let agent_id = test_agent_id();

        let _ = service
            .process_event_with_store_and_investigation(
                &detector,
                &substrate,
                &replay_store,
                &coordinator,
                &event_one,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context_one,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(swarm_core::types::ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();
        let _ = service
            .process_event_with_store_and_investigation(
                &detector,
                &substrate,
                &replay_store,
                &coordinator,
                &event_two,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context_two,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(swarm_core::types::ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        investigation_store
            .persist(&swarm_spine::InvestigationBundle {
                investigation_id: "investigation:hunt-2:1".to_string(),
                source_bundle_id: "bundle:hunt-2:1".to_string(),
                hunt_id: "hunt-2".to_string(),
                trail_id: "trail:hunt-2:1".to_string(),
                event_id: "evt:hunt-2".to_string(),
                finding_id: "finding:hunt-2".to_string(),
                threat_class: swarm_core::pheromone::ThreatClass::Execution,
                severity: Severity::Critical,
                strategy_id: "summary_investigator".to_string(),
                response_kind: "success".to_string(),
                related_receipt_ids: vec!["receipt:hunt-2".to_string()],
                host_id: Some("host-1".to_string()),
                user: Some("alice".to_string()),
                process_name: Some("powershell".to_string()),
                queued_at_ms: 1_700_000_003_000,
                started_at_ms: Some(1_700_000_003_010),
                completed_at_ms: Some(1_700_000_003_100),
                status: swarm_spine::InvestigationStatus::Completed,
                priority: swarm_spine::InvestigationPriority::default(),
                summary: Some("summary for hunt-2".to_string()),
                evidence_points: vec!["host_id=host-1".to_string()],
                correlation_keys: vec![
                    "host:host-1".to_string(),
                    "user:alice".to_string(),
                    "strategy:summary_investigator".to_string(),
                ],
                candidate_interpretations: Vec::new(),
                vote_lineage: Vec::new(),
                decision: swarm_spine::InvestigationDecision::default(),
                failure_reason: None,
            })
            .unwrap();

        let engine = CorrelationEngine::new(config.correlation.clone());
        let _ = service
            .correlate_hunt(
                &engine,
                &investigation_store,
                &incident_store,
                "evt-review-1",
            )
            .unwrap()
            .unwrap();

        let status = service
            .operator_review_status(
                &detector,
                &substrate,
                &replay_store,
                &coordinator,
                &incident_store,
            )
            .await
            .unwrap();

        assert_eq!(status.recent_decisions.len(), 2);
        assert!(status.investigation_review.is_some());
        assert!(status.incident_review.is_some());
        assert!(status.async_lane.enabled);
        assert!(status.freshness.latest_hot_path_decision_at_ms.is_some());
        assert!(status.freshness.latest_investigation_update_at_ms.is_some());
        assert!(status.freshness.latest_incident_at_ms.is_some());

        let investigation_review = status.investigation_review.unwrap();
        assert!(investigation_review.recent.len() >= 2);
        assert!(investigation_review.queue.last_failure_reason.is_some());

        let incident_review = status.incident_review.unwrap();
        assert_eq!(incident_review.recent.len(), 1);
        assert_eq!(
            status.async_lane.status,
            super::AsyncLaneStatusLevel::Degraded
        );
        assert!(status.async_lane.recent_investigations >= 2);
        assert_eq!(status.async_lane.recent_incidents, 1);
        assert!(
            status
                .async_lane
                .latest_incident_confidence_score
                .is_some_and(|value| value > 0.0)
        );
        assert!(
            status
                .async_lane
                .warnings
                .iter()
                .any(|warning| warning.contains("recent investigation failure"))
        );
        assert!(
            status
                .warnings
                .iter()
                .any(|warning| warning.contains("investigation queue reported recent failure"))
        );

        let _ = std::fs::remove_dir_all(replay_store_root);
    }

    #[tokio::test]
    async fn configured_runtime_stack_builds_async_layers_from_config() {
        let mut config = service_config(
            RuntimeMode::LiveResponse,
            PheromoneBackendConfig::InMemory,
            false,
        );
        config.audit.bundle_store = BundleStoreConfig::Memory;
        config.investigation = InvestigationConfig {
            enabled: true,
            worker_count: 1,
            max_pending_jobs: 4,
            time_budget_ms: 250,
            bundle_store: BundleStoreConfig::Memory,
            ..InvestigationConfig::default()
        };
        config.correlation = CorrelationConfig {
            enabled: true,
            time_window_ms: 10_000,
            min_shared_keys: 1,
            candidate_limit: 16,
            incident_store: BundleStoreConfig::Memory,
        };

        let stack = ConfiguredRuntimeStack::from_components(
            config,
            StaticApprovalGate::default(),
            SandboxExecutor,
            SlowInvestigator { delay_ms: 50 },
        )
        .unwrap();
        let detector = SuspiciousProcessTreeDetector::default();
        let agent_id = test_agent_id();

        let make_event = |event_id: &str, command_line: &str| TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: event_id.to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword".to_string(),
                process_name: "powershell".to_string(),
                command_line: command_line.to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };
        let make_context = |now_ms| ApprovalContext {
            live_mode: true,
            receipt_chain: vec![format!("receipt-upstream-{now_ms}")],
            correlation_id: None,
            now_ms,
        };

        let first = stack
            .process_event(
                &detector,
                &make_event("evt-stack-1", "powershell.exe -enc AAA="),
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &make_context(1_700_000_000_100),
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(swarm_core::types::ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();
        let second = stack
            .process_event(
                &detector,
                &make_event("evt-stack-2", "powershell.exe -enc BBB="),
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &make_context(1_700_000_000_200),
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(swarm_core::types::ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        assert!(first.investigation.is_some());
        assert!(second.investigation.is_some());

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let incident = stack.correlate_hunt("evt-stack-1").unwrap().unwrap();
        assert_eq!(incident.incident.included_members.len(), 2);

        let report = stack.operator_review_status(&detector).await.unwrap();
        let investigation_review = report.investigation_review.expect("investigation review");
        let incident_review = report.incident_review.expect("incident review");
        assert!(investigation_review.queue.completed_jobs >= 2);
        assert_eq!(incident_review.recent.len(), 1);
        assert_eq!(
            incident_review.recent[0].incident_id,
            incident.record.incident_id
        );
        assert_eq!(
            report.freshness.latest_incident_at_ms,
            Some(incident.record.created_at_ms)
        );
    }
}
