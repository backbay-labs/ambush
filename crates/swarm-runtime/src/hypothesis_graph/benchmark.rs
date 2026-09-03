//! Deterministic paired evaluation for the frozen collective-reasoning corpus.
//!
//! The benchmark consumes the checked-in oracle instead of embedding expected
//! outcomes in executable code. Both lanes receive the same stable task and
//! evidence identities. Logical time alone determines the verdict; host wall
//! clock is reported as an observation and cannot affect any gate.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use swarm_core::hypothesis_graph::{
    CausalEdge, CausalRelation, DecisionKind, DecisionRecord, EdgeId, EdgeState, EvidenceId,
    EvidenceSourceFamily, GraphId, GraphLogicalTime, GraphNodeId, GraphProducerRole,
    GraphResourceLimits, HypothesisGraph, HypothesisId, HypothesisStatus, KillChainClaim,
    KillChainReconstruction, KillChainStage, TaskId, TaskKind, TypedEvidencePayload,
};
use swarm_core::types::AgentId;
use swarm_core::{
    AuthenticationEventData, CloudTrailEvent, KubernetesAuditEvent, NetworkConnectEvent,
    ProcessStartEvent, TelemetryEvent, TelemetryPayload, ThreatIntelEntry,
    ThreatIntelIndicatorType,
};
use swarm_crypto::Keypair;

use super::clock::{DeterministicScheduler, FixedGraphClock};
use super::inference::{InferredCausalRelation, infer_causal_relations};
use super::normalize::{
    NormalizedGraphEvidence, normalize_telemetry_event_for_graph,
    normalize_threat_intel_entry_for_graph,
};

const MANIFEST_REL: &str = "scenarios/collective-hypothesis-graph/manifest.yaml";
const BASELINE_REL: &str = "docs/benchmarks/collective-hypothesis-graph-baseline.json";

#[derive(Debug, thiserror::Error)]
pub enum CollectiveBenchmarkError {
    #[error("failed to read benchmark input `{path}`: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },

    #[error("benchmark YAML does not match its strict schema: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("benchmark JSON does not match its strict schema: {0}")]
    Json(#[from] serde_json::Error),

    #[error("collective benchmark contract violation: {0}")]
    Contract(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SourceFamily {
    Process,
    Identity,
    Kubernetes,
    Cloudtrail,
    Network,
    ThreatIntelligence,
}

impl SourceFamily {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Identity => "identity",
            Self::Kubernetes => "kubernetes",
            Self::Cloudtrail => "cloudtrail",
            Self::Network => "network",
            Self::ThreatIntelligence => "threat_intelligence",
        }
    }

    const fn graph_family(self) -> EvidenceSourceFamily {
        match self {
            Self::Process => EvidenceSourceFamily::Process,
            Self::Identity => EvidenceSourceFamily::Identity,
            Self::Kubernetes => EvidenceSourceFamily::Kubernetes,
            Self::Cloudtrail => EvidenceSourceFamily::Cloudtrail,
            Self::Network => EvidenceSourceFamily::Network,
            Self::ThreatIntelligence => EvidenceSourceFamily::ThreatIntelligence,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ScenarioClass {
    TrainingAttack,
    WithheldAttack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StageStatus {
    Observed,
    MissingEvidence,
}

/// Raw production semantics supplied to the normalizers. This is deliberately
/// independent from the fixture's `supports`/`refutes` scoring oracle so a
/// mislabeled row cannot manufacture the signal that the benchmark is meant
/// to evaluate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FixtureTelemetryProfile {
    UnsignedExecution,
    SignedExecution,
    SuccessfulAuthentication,
    FailedAuthentication,
    WorkloadCreate,
    WorkloadUpdate,
    AssumeRole,
    CreateAccessKey,
    NetworkContact,
    HighConfidenceIndicator,
    LowConfidenceIndicator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkDenominators {
    pub adjudicated_cases: u64,
    pub attack_chain_stages: u64,
    pub causal_edges: u64,
    pub logical_tasks: u64,
    pub evidence_claims: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkThresholds {
    min_hypothesis_time_reduction_bps: u16,
    min_attack_chain_recall_gain_bps: u16,
    min_causal_edge_recall_bps: u16,
    max_false_causal_edge_rate_bps: u16,
    max_duplicate_work_rate_bps: u16,
    min_evidence_coverage_bps: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkLaneMetrics {
    pub median_hypothesis_time_ms: u64,
    pub attack_chain_recall_bps: u16,
    pub causal_edge_recall_bps: u16,
    pub false_causal_edge_rate_bps: u16,
    pub duplicate_work_rate_bps: u16,
    pub evidence_coverage_bps: u16,
    pub logical_work_units: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogicalClock {
    origin_ms: i64,
    tick_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceContract {
    family: SourceFamily,
    corroborating_evidence_id: String,
    conflicting_evidence_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TruthContract {
    hypothesis_ids: Vec<String>,
    selected_hypothesis_id: String,
    node_ids: Vec<String>,
    causal_edges: Vec<CausalEdgeContract>,
    kill_chain_stage_ids: Vec<String>,
    required_evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CausalEdgeContract {
    edge_id: String,
    from: String,
    to: String,
    relation: CausalRelation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CausalEdgeIdentity {
    from: String,
    to: String,
    relation: &'static str,
}

impl From<&CausalEdgeContract> for CausalEdgeIdentity {
    fn from(contract: &CausalEdgeContract) -> Self {
        Self {
            from: contract.from.clone(),
            to: contract.to.clone(),
            relation: causal_relation_name(contract.relation),
        }
    }
}

const fn causal_relation_name(relation: CausalRelation) -> &'static str {
    match relation {
        CausalRelation::ObservedIn => "observed_in",
        CausalRelation::Spawns => "spawns",
        CausalRelation::Uses => "uses",
        CausalRelation::Contacts => "contacts",
        CausalRelation::Assumes => "assumes",
        CausalRelation::Creates => "creates",
        CausalRelation::DependsOn => "depends_on",
        CausalRelation::Supports => "supports",
        CausalRelation::Refutes => "refutes",
        CausalRelation::Contradicts => "contradicts",
        CausalRelation::MatchesIndicator => "matches_indicator",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaneContract {
    lane_id: String,
    max_investigators: u16,
    adaptive_task_allocation: bool,
    corpus_digest_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaneControls {
    single_agent: LaneContract,
    collective: LaneContract,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusLimits {
    max_nodes: usize,
    max_edges: usize,
    max_evidence_bytes: usize,
    max_tasks: usize,
    max_virtual_ms: u64,
    max_work_units: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricContract {
    denominators: BenchmarkDenominators,
    thresholds: BenchmarkThresholds,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkManifest {
    schema_version: u32,
    corpus_id: String,
    corpus_version: u32,
    seed: u64,
    logical_clock: LogicalClock,
    training_fixture: String,
    withheld_fixture: String,
    source_contracts: Vec<SourceContract>,
    truth: TruthContract,
    controls: LaneControls,
    limits: CorpusLimits,
    metrics: MetricContract,
    task_identities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureEvent {
    event_id: String,
    evidence_id: String,
    source_family: SourceFamily,
    logical_time_ms: i64,
    signal_kind: String,
    telemetry_profile: FixtureTelemetryProfile,
    supports: Vec<String>,
    refutes: Vec<String>,
    entity_ids: Vec<String>,
    relation_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureStage {
    stage_id: String,
    status: StageStatus,
    evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioFixture {
    schema_version: u32,
    scenario_id: String,
    class: ScenarioClass,
    seed_time_ms: i64,
    hypothesis_ids: Vec<String>,
    events: Vec<FixtureEvent>,
    expected_kill_chain: Vec<FixtureStage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkOracleDigests {
    pub manifest_sha256: String,
    pub ambiguous_fixture_sha256: String,
    pub withheld_fixture_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkBaseline {
    schema_version: u32,
    corpus_id: String,
    corpus_version: u32,
    oracle_digests: BenchmarkOracleDigests,
    denominators: BenchmarkDenominators,
    thresholds: BenchmarkThresholds,
    single_agent_baseline: BenchmarkLaneMetrics,
}

struct FrozenBenchmarkInputs<'a> {
    manifest_bytes: &'a [u8],
    training_bytes: &'a [u8],
    withheld_bytes: &'a [u8],
    manifest: &'a BenchmarkManifest,
    training: &'a ScenarioFixture,
    withheld: &'a ScenarioFixture,
    baseline: &'a BenchmarkBaseline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkDeltas {
    pub hypothesis_time_reduction_bps: u16,
    pub attack_chain_recall_gain_bps: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkVerdict {
    pub passed: bool,
    pub failed_gates: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkObservations {
    pub single_agent_wall_clock_ms: u64,
    pub collective_wall_clock_ms: u64,
    pub gate_inputs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectiveBenchmarkReport {
    pub schema_version: u32,
    pub corpus_id: String,
    pub seed: u64,
    pub corpus_digest: String,
    pub config_digest: String,
    pub lane_input_digest: String,
    pub oracle_digests: BenchmarkOracleDigests,
    pub source_families: Vec<String>,
    pub denominators: BenchmarkDenominators,
    pub single_agent: BenchmarkLaneMetrics,
    pub collective: BenchmarkLaneMetrics,
    pub deltas: BenchmarkDeltas,
    pub verdict: BenchmarkVerdict,
    pub observations: BenchmarkObservations,
}

fn read(path: &Path) -> Result<Vec<u8>, CollectiveBenchmarkError> {
    fs::read(path).map_err(|source| CollectiveBenchmarkError::Read {
        path: path.display().to_string(),
        source,
    })
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn basis_points(numerator: u64, denominator: u64) -> Result<u16, CollectiveBenchmarkError> {
    if denominator == 0 || numerator > denominator {
        return Err(CollectiveBenchmarkError::Contract(
            "invalid metric numerator or zero denominator".to_string(),
        ));
    }
    Ok(((numerator * 10_000) / denominator) as u16)
}

fn reduction_basis_points(control: u64, candidate: u64) -> u16 {
    if control == 0 || candidate > control {
        return 0;
    }
    (((control - candidate) * 10_000) / control) as u16
}

struct ExecutedTaskLane {
    median_hypothesis_time_ms: u64,
    executed_tasks: u64,
    duplicate_executions: u64,
}

struct ExecutedReasoningLane {
    admitted_evidence: u64,
    admitted_causal_edges: u64,
    false_causal_edges: u64,
    observed_stages: u64,
    observed_edges: BTreeSet<CausalEdgeIdentity>,
    adjudications: Vec<DecisionRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReasoningLaneMode {
    Collective,
    FixedInvestigator,
}

#[derive(Debug, Clone)]
struct EvidenceTopology {
    entity_node_ids: Vec<GraphNodeId>,
}

#[derive(Debug, Clone)]
struct EvidenceAssertions {
    supports: BTreeSet<HypothesisId>,
    refutes: BTreeSet<HypothesisId>,
}

struct ExecutedScenarioGraph {
    graph: HypothesisGraph,
    topology: BTreeMap<EvidenceId, EvidenceTopology>,
    assertions: BTreeMap<EvidenceId, EvidenceAssertions>,
    semantic_node_ids: BTreeMap<GraphNodeId, String>,
    semantic_evidence_ids: BTreeMap<EvidenceId, String>,
}

#[derive(Default)]
struct StageEvidence {
    node_ids: BTreeSet<GraphNodeId>,
    edge_ids: BTreeSet<EdgeId>,
    evidence_ids: BTreeSet<EvidenceId>,
}

fn execute_task_lane(
    manifest: &BenchmarkManifest,
    fixtures: [&ScenarioFixture; 2],
    investigators: u16,
) -> Result<ExecutedTaskLane, CollectiveBenchmarkError> {
    if investigators == 0 {
        return Err(CollectiveBenchmarkError::Contract(
            "a benchmark lane requires at least one investigator".to_string(),
        ));
    }
    let tasks_per_case = manifest
        .metrics
        .denominators
        .logical_tasks
        .div_ceil(manifest.metrics.denominators.adjudicated_cases);
    let tasks_per_case = usize::try_from(tasks_per_case).map_err(|_| {
        CollectiveBenchmarkError::Contract("task partition does not fit usize".to_string())
    })?;
    let mut completion_times = Vec::with_capacity(fixtures.len());
    let mut executed = BTreeSet::new();
    let mut duplicate_executions = 0_u64;

    for (case_index, fixture) in fixtures.into_iter().enumerate() {
        let start = case_index.checked_mul(tasks_per_case).ok_or_else(|| {
            CollectiveBenchmarkError::Contract("task partition overflow".to_string())
        })?;
        let end = start
            .checked_add(tasks_per_case)
            .ok_or_else(|| {
                CollectiveBenchmarkError::Contract("task partition overflow".to_string())
            })?
            .min(manifest.task_identities.len());
        let mut limits = GraphResourceLimits::default();
        limits.max_tasks = manifest.limits.max_tasks;
        let mut scheduler = DeterministicScheduler::with_limits(limits).map_err(|error| {
            CollectiveBenchmarkError::Contract(format!(
                "benchmark scheduler limits are invalid: {error}"
            ))
        })?;
        for (offset, task_identity) in manifest.task_identities[start..end].iter().enumerate() {
            let kind = match offset % 3 {
                0 => TaskKind::AcquireEvidence,
                1 => TaskKind::ChallengeEdge,
                _ => TaskKind::FalsifyHypothesis,
            };
            let priority = match kind {
                TaskKind::AcquireEvidence => 7_000,
                TaskKind::ChallengeEdge => 6_000,
                TaskKind::FalsifyHypothesis => 8_000,
            };
            let task_id = TaskId::new(task_identity.clone());
            let ready_at = GraphLogicalTime::new(fixture.seed_time_ms);
            if !scheduler
                .schedule_task(ready_at, kind, priority, task_id.clone())
                .map_err(|error| {
                    CollectiveBenchmarkError::Contract(format!(
                        "benchmark task admission failed: {error}"
                    ))
                })?
            {
                return Err(CollectiveBenchmarkError::Contract(format!(
                    "fresh benchmark task `{task_id}` was treated as a retry"
                )));
            }
            if scheduler
                .schedule_task(ready_at, kind, priority, task_id)
                .map_err(|error| {
                    CollectiveBenchmarkError::Contract(format!(
                        "benchmark retry admission failed: {error}"
                    ))
                })?
            {
                return Err(CollectiveBenchmarkError::Contract(
                    "an exact benchmark retry created duplicate work".to_string(),
                ));
            }
        }

        let mut rounds = 0_u64;
        while !scheduler.is_empty() {
            rounds = rounds.checked_add(1).ok_or_else(|| {
                CollectiveBenchmarkError::Contract("logical round overflow".to_string())
            })?;
            let elapsed = rounds
                .checked_mul(manifest.logical_clock.tick_ms)
                .ok_or_else(|| {
                    CollectiveBenchmarkError::Contract("logical time overflow".to_string())
                })?;
            if elapsed > manifest.limits.max_virtual_ms {
                return Err(CollectiveBenchmarkError::Contract(
                    "benchmark lane exceeded the virtual-time ceiling".to_string(),
                ));
            }
            let now = GraphLogicalTime::new(
                fixture
                    .seed_time_ms
                    .checked_add(i64::try_from(elapsed).map_err(|_| {
                        CollectiveBenchmarkError::Contract(
                            "logical time does not fit i64".to_string(),
                        )
                    })?)
                    .ok_or_else(|| {
                        CollectiveBenchmarkError::Contract("logical time overflow".to_string())
                    })?,
            );
            for _ in 0..investigators {
                let Some(task) = scheduler.pop_ready(now).map_err(|error| {
                    CollectiveBenchmarkError::Contract(format!(
                        "benchmark task dispatch failed: {error}"
                    ))
                })?
                else {
                    break;
                };
                if !executed.insert(task.task_id) {
                    duplicate_executions = duplicate_executions.saturating_add(1);
                }
            }
        }
        completion_times.push(
            rounds
                .checked_mul(manifest.logical_clock.tick_ms)
                .ok_or_else(|| {
                    CollectiveBenchmarkError::Contract("logical time overflow".to_string())
                })?,
        );
    }
    completion_times.sort_unstable();
    let median_hypothesis_time_ms = completion_times
        .get(completion_times.len().saturating_sub(1) / 2)
        .copied()
        .ok_or_else(|| {
            CollectiveBenchmarkError::Contract("benchmark has no adjudicated cases".to_string())
        })?;
    Ok(ExecutedTaskLane {
        median_hypothesis_time_ms,
        executed_tasks: u64::try_from(executed.len()).unwrap_or(u64::MAX),
        duplicate_executions,
    })
}

fn normalize_fixture_event(
    event: &FixtureEvent,
    signer: &Keypair,
) -> Result<NormalizedGraphEvidence, CollectiveBenchmarkError> {
    let observed_at = GraphLogicalTime::new(event.logical_time_ms);
    let clock = FixedGraphClock::new(observed_at);
    let source = "collective-benchmark".to_string();
    let host_id = Some("benchmark-host-a".to_string());
    let payload = match (event.source_family, event.telemetry_profile) {
        (
            SourceFamily::Process,
            profile @ (FixtureTelemetryProfile::UnsignedExecution
            | FixtureTelemetryProfile::SignedExecution),
        ) => TelemetryPayload::ProcessStart(ProcessStartEvent {
            parent_process: "<none>".to_string(),
            process_name: "runner-a".to_string(),
            command_line: event.signal_kind.clone(),
            user: Some("process-user-a".to_string()),
            executable_path: Some("/opt/benchmark/runner-a".to_string()),
            signer: (profile == FixtureTelemetryProfile::SignedExecution)
                .then(|| "approved-vendor".to_string()),
            signature_valid: Some(profile == FixtureTelemetryProfile::SignedExecution),
        }),
        (
            SourceFamily::Identity,
            profile @ (FixtureTelemetryProfile::SuccessfulAuthentication
            | FixtureTelemetryProfile::FailedAuthentication),
        ) => TelemetryPayload::AuthenticationEvent(AuthenticationEventData {
            auth_type: "service_role".to_string(),
            source_host: host_id.clone(),
            target_host: Some("workload-a".to_string()),
            target_service: Some("role-a".to_string()),
            process_name: Some("runner-a".to_string()),
            success: profile == FixtureTelemetryProfile::SuccessfulAuthentication,
            user: Some("identity-principal-a".to_string()),
        }),
        (
            SourceFamily::Kubernetes,
            profile @ (FixtureTelemetryProfile::WorkloadCreate
            | FixtureTelemetryProfile::WorkloadUpdate),
        ) => TelemetryPayload::KubernetesAudit(KubernetesAuditEvent {
            verb: if profile == FixtureTelemetryProfile::WorkloadCreate {
                "create"
            } else {
                "update"
            }
            .to_string(),
            stage: Some("ResponseComplete".to_string()),
            username: Some("kubernetes-principal-a".to_string()),
            user_groups: vec!["system:authenticated".to_string()],
            source_ips: vec!["198.51.100.10".to_string()],
            user_agent: Some("benchmark-controller".to_string()),
            namespace: Some("production".to_string()),
            resource: "pods".to_string(),
            subresource: None,
            resource_name: Some("workload-a".to_string()),
            api_group: Some("v1".to_string()),
            response_code: Some(201),
            annotations: serde_json::json!({"benchmark_signal": event.signal_kind}),
            request_object: serde_json::json!({"metadata": {"name": "workload-a"}}),
            impersonated_username: None,
        }),
        (
            SourceFamily::Cloudtrail,
            profile @ (FixtureTelemetryProfile::AssumeRole
            | FixtureTelemetryProfile::CreateAccessKey),
        ) => TelemetryPayload::CloudTrail(CloudTrailEvent {
            event_name: if profile == FixtureTelemetryProfile::AssumeRole {
                "AssumeRole"
            } else {
                "CreateAccessKey"
            }
            .to_string(),
            event_source: "sts.amazonaws.com".to_string(),
            aws_account_id: Some("benchmark-account-a".to_string()),
            principal_arn: None,
            principal_id: Some("cloudtrail-principal-a".to_string()),
            principal_name: Some("cloudtrail-principal-a".to_string()),
            principal_type: Some("AssumedRole".to_string()),
            source_ip_address: Some("198.51.100.10".to_string()),
            aws_region: Some("us-east-1".to_string()),
            user_agent: Some("benchmark-agent".to_string()),
            mfa_authenticated: Some(false),
            request_parameters: serde_json::json!({"role": "role-a"}),
            response_elements: serde_json::json!({}),
            error_code: None,
            error_message: None,
        }),
        (SourceFamily::Network, FixtureTelemetryProfile::NetworkContact) => {
            TelemetryPayload::NetworkConnect(NetworkConnectEvent {
                process_name: "runner-a".to_string(),
                destination_ip: "203.0.113.77".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
            })
        }
        (
            SourceFamily::ThreatIntelligence,
            profile @ (FixtureTelemetryProfile::HighConfidenceIndicator
            | FixtureTelemetryProfile::LowConfidenceIndicator),
        ) => {
            let expires_at = event.logical_time_ms.checked_add(60_000).ok_or_else(|| {
                CollectiveBenchmarkError::Contract(
                    "benchmark threat-intelligence expiry overflowed".to_string(),
                )
            })?;
            let entry = ThreatIntelEntry {
                indicator_type: ThreatIntelIndicatorType::IpAddress,
                value: "203.0.113.77".to_string(),
                source: "benchmark-taxii".to_string(),
                indicator_id: Some(format!("indicator:{}", event.event_id)),
                confidence: if profile == FixtureTelemetryProfile::HighConfidenceIndicator {
                    0.95
                } else {
                    0.1
                },
                expires_at,
            };
            return normalize_threat_intel_entry_for_graph(
                &entry,
                &event.event_id,
                observed_at,
                &clock,
                signer,
                GraphProducerRole::Normalizer,
                "collective-benchmark-normalizer",
            )
            .map_err(|error| {
                CollectiveBenchmarkError::Contract(format!(
                    "production threat-intelligence normalization failed: {error}"
                ))
            });
        }
        (family, profile) => {
            return Err(CollectiveBenchmarkError::Contract(format!(
                "telemetry profile `{profile:?}` is incompatible with source family `{family:?}`"
            )));
        }
    };
    normalize_telemetry_event_for_graph(
        &TelemetryEvent {
            source,
            event_id: event.event_id.clone(),
            timestamp: event.logical_time_ms,
            host_id,
            payload,
        },
        &clock,
        signer,
        GraphProducerRole::Normalizer,
        "collective-benchmark-normalizer",
    )
    .map_err(|error| {
        CollectiveBenchmarkError::Contract(format!(
            "production telemetry normalization failed: {error}"
        ))
    })
}

fn inferred_kill_chain_stage(
    payload: &TypedEvidencePayload,
    candidate: &InferredCausalRelation,
) -> Result<Option<KillChainStage>, CollectiveBenchmarkError> {
    let signal_kind = match payload {
        TypedEvidencePayload::Signal { signal_kind, .. }
        | TypedEvidencePayload::Process { signal_kind, .. }
        | TypedEvidencePayload::Identity { signal_kind, .. }
        | TypedEvidencePayload::KubernetesAudit { signal_kind, .. }
        | TypedEvidencePayload::Cloudtrail { signal_kind, .. }
        | TypedEvidencePayload::Network { signal_kind, .. }
        | TypedEvidencePayload::ThreatIntelligence { signal_kind, .. } => signal_kind.as_str(),
    };
    let stage = match candidate.relation {
        CausalRelation::Spawns | CausalRelation::Uses | CausalRelation::DependsOn => {
            Some(KillChainStage::Execution)
        }
        CausalRelation::Creates => Some(KillChainStage::LateralMovement),
        CausalRelation::Contacts | CausalRelation::MatchesIndicator => {
            Some(KillChainStage::CommandAndControl)
        }
        CausalRelation::Assumes => match payload {
            TypedEvidencePayload::Identity { .. } => Some(KillChainStage::InitialAccess),
            TypedEvidencePayload::Cloudtrail { .. } => Some(KillChainStage::CredentialAccess),
            TypedEvidencePayload::Signal { .. } => match signal_kind {
                "anomalous_role_assumption" | "anomalous_service_authentication" => {
                    Some(KillChainStage::InitialAccess)
                }
                "role_used_from_new_source" | "secret_read_after_role_assumption" => {
                    Some(KillChainStage::CredentialAccess)
                }
                _ => {
                    return Err(CollectiveBenchmarkError::Contract(format!(
                        "inferred assumption signal `{signal_kind}` has no kill-chain semantic"
                    )));
                }
            },
            _ => {
                return Err(CollectiveBenchmarkError::Contract(format!(
                    "inferred assumption payload `{signal_kind}` has no kill-chain semantic"
                )));
            }
        },
        CausalRelation::ObservedIn
        | CausalRelation::Supports
        | CausalRelation::Refutes
        | CausalRelation::Contradicts => None,
    };
    Ok(stage)
}

fn production_evidence_weight(payload: &TypedEvidencePayload, entity_count: usize) -> i64 {
    let entity_weight = i64::try_from(entity_count.max(1)).unwrap_or(i64::MAX);
    let quality_weight = match payload {
        TypedEvidencePayload::Identity {
            success: Some(true),
            ..
        } => 2,
        TypedEvidencePayload::KubernetesAudit { verb, .. }
            if verb.eq_ignore_ascii_case("create") =>
        {
            2
        }
        TypedEvidencePayload::Cloudtrail { event_name, .. }
            if event_name.eq_ignore_ascii_case("AssumeRole") =>
        {
            2
        }
        TypedEvidencePayload::ThreatIntelligence {
            confidence_basis_points,
            ..
        } => i64::from(*confidence_basis_points / 2_500),
        _ => 0,
    };
    entity_weight.saturating_add(quality_weight)
}

const fn kill_chain_stage_id(stage: KillChainStage) -> &'static str {
    match stage {
        KillChainStage::InitialAccess => "stage:initial-access",
        KillChainStage::Execution => "stage:execution",
        KillChainStage::CredentialAccess => "stage:credential-access",
        KillChainStage::LateralMovement => "stage:lateral-movement",
        KillChainStage::CommandAndControl => "stage:command-and-control",
    }
}

/// The frozen control is one generalist investigator with the four telemetry
/// adapters available on the ordinary runtime path. Kubernetes and threat
/// intelligence require recruited specialists in the collective lane. This
/// capability is fixed before either fixture executes and never inferred from
/// the withheld corpus.
const fn fixed_investigator_supports(source_family: SourceFamily) -> bool {
    matches!(
        source_family,
        SourceFamily::Process
            | SourceFamily::Identity
            | SourceFamily::Cloudtrail
            | SourceFamily::Network
    )
}

fn signed_benchmark_edge(
    signer: &Keypair,
    source: &GraphNodeId,
    target: &GraphNodeId,
    evidence_id: EvidenceId,
    relation: CausalRelation,
    observed_at: GraphLogicalTime,
    state: EdgeState,
) -> Result<CausalEdge, CollectiveBenchmarkError> {
    CausalEdge::new(
        source,
        target,
        relation,
        9_000,
        [evidence_id],
        GraphProducerRole::Hunter,
        AgentId::from_public_key_hex(&signer.public_key().to_hex()),
        observed_at,
        state,
    )
    .and_then(|edge| edge.signed_with(signer, "collective-benchmark-edge"))
    .map_err(|error| {
        CollectiveBenchmarkError::Contract(format!(
            "benchmark causal-edge production failed: {error}"
        ))
    })
}

fn execute_reasoning_lane(
    manifest: &BenchmarkManifest,
    fixtures: [&ScenarioFixture; 2],
    mode: ReasoningLaneMode,
) -> Result<ExecutedReasoningLane, CollectiveBenchmarkError> {
    let seed_digest = Sha256::digest(manifest.seed.to_le_bytes());
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&seed_digest);
    let signer = Keypair::from_seed(&seed);
    let producer = AgentId::from_public_key_hex(&signer.public_key().to_hex());
    let mut scenarios = Vec::with_capacity(fixtures.len());
    for (fixture_index, fixture) in fixtures.iter().copied().enumerate() {
        let mut limits = GraphResourceLimits::default();
        limits.max_nodes = manifest.limits.max_nodes;
        limits.max_edges = manifest.limits.max_edges;
        limits.max_evidence_bytes = manifest.limits.max_evidence_bytes;
        limits.max_tasks = manifest.limits.max_tasks;
        let mut graph = HypothesisGraph::new(
            GraphId::new(format!("graph:benchmark:{}:{fixture_index}", manifest.seed)),
            limits,
        )
        .map_err(|error| {
            CollectiveBenchmarkError::Contract(format!(
                "benchmark graph initialization failed: {error}"
            ))
        })?;
        let mut topology = BTreeMap::new();
        let mut semantic_nodes = BTreeMap::<String, GraphNodeId>::new();
        let mut semantic_node_ids = BTreeMap::<GraphNodeId, String>::new();
        let mut semantic_evidence_ids = BTreeMap::<EvidenceId, String>::new();
        let mut assertions = BTreeMap::<EvidenceId, EvidenceAssertions>::new();

        for event in &fixture.events {
            if mode == ReasoningLaneMode::FixedInvestigator
                && !fixed_investigator_supports(event.source_family)
            {
                continue;
            }
            let normalized = normalize_fixture_event(event, &signer)?;
            let evidence = normalized.evidence;
            if evidence.source_family != event.source_family.graph_family() {
                return Err(CollectiveBenchmarkError::Contract(format!(
                    "production normalization changed fixture family `{}`",
                    event.evidence_id
                )));
            }
            let entity_node_ids = evidence.entity_ids();
            if entity_node_ids.len() != event.entity_ids.len() {
                return Err(CollectiveBenchmarkError::Contract(format!(
                    "fixture `{}` declares {} semantic entities but production normalization emitted {}",
                    event.evidence_id,
                    event.entity_ids.len(),
                    entity_node_ids.len()
                )));
            }
            for (node_id, semantic_id) in entity_node_ids.iter().zip(&event.entity_ids) {
                if let Some(existing) = semantic_nodes.insert(semantic_id.clone(), node_id.clone())
                    && existing != *node_id
                {
                    return Err(CollectiveBenchmarkError::Contract(format!(
                        "production normalization split semantic entity `{semantic_id}` across distinct graph nodes"
                    )));
                }
                if let Some(existing) =
                    semantic_node_ids.insert(node_id.clone(), semantic_id.clone())
                    && existing != *semantic_id
                {
                    return Err(CollectiveBenchmarkError::Contract(format!(
                        "production normalization collapsed semantic entities `{existing}` and `{semantic_id}`"
                    )));
                }
            }
            for node in normalized.nodes {
                graph.admit_node(node).map_err(|error| {
                    CollectiveBenchmarkError::Contract(format!(
                        "production-normalized benchmark node admission failed: {error}"
                    ))
                })?;
            }
            let evidence_id = evidence.evidence_id.clone();
            graph.admit_evidence(evidence).map_err(|error| {
                CollectiveBenchmarkError::Contract(format!(
                    "benchmark evidence admission failed: {error}"
                ))
            })?;
            topology.insert(evidence_id.clone(), EvidenceTopology { entity_node_ids });
            assertions.insert(
                evidence_id.clone(),
                EvidenceAssertions {
                    supports: event
                        .supports
                        .iter()
                        .cloned()
                        .map(HypothesisId::new)
                        .collect(),
                    refutes: event
                        .refutes
                        .iter()
                        .cloned()
                        .map(HypothesisId::new)
                        .collect(),
                },
            );
            semantic_evidence_ids.insert(evidence_id, event.evidence_id.clone());
        }

        scenarios.push(ExecutedScenarioGraph {
            graph,
            topology,
            assertions,
            semantic_node_ids,
            semantic_evidence_ids,
        });
    }

    let mut admitted_evidence = 0_u64;
    let mut observed_stages = 0_u64;
    let mut adjudications = Vec::with_capacity(scenarios.len());
    for (case_index, scenario) in scenarios.iter_mut().enumerate() {
        admitted_evidence = admitted_evidence
            .saturating_add(u64::try_from(scenario.graph.evidence.len()).unwrap_or(u64::MAX));
        let mut hypothesis_scores = manifest
            .truth
            .hypothesis_ids
            .iter()
            .cloned()
            .map(|id| (HypothesisId::new(id), 0_i64))
            .collect::<BTreeMap<_, _>>();
        let mut source_hypothesis_scores =
            BTreeMap::<(EvidenceSourceFamily, HypothesisId), i64>::new();
        let mut evidence_for_adjudication = BTreeSet::new();
        let mut adjudicated_at = GraphLogicalTime::new(manifest.logical_clock.origin_ms);
        for evidence in scenario.graph.evidence.values() {
            evidence_for_adjudication.insert(evidence.evidence_id.clone());
            adjudicated_at = adjudicated_at.max(evidence.clock.observed_at);
            let assertions = scenario
                .assertions
                .get(&evidence.evidence_id)
                .ok_or_else(|| {
                    CollectiveBenchmarkError::Contract(format!(
                        "admitted evidence `{}` has no benchmark assertions",
                        evidence.evidence_id
                    ))
                })?;
            // Topology and payload semantics determine evidentiary strength:
            // successful authentication, a workload creation, role assumption,
            // and high-confidence threat intelligence carry more information
            // than their benign controls. The frozen fixture declares only the
            // competing hypothesis direction; it cannot manufacture identities
            // or weights outside the production-normalized envelope.
            let weight = production_evidence_weight(&evidence.payload, evidence.entity_ids().len());
            for hypothesis_id in &assertions.supports {
                let score = hypothesis_scores.get_mut(hypothesis_id).ok_or_else(|| {
                    CollectiveBenchmarkError::Contract(format!(
                        "evidence supports undeclared hypothesis `{hypothesis_id}`"
                    ))
                })?;
                *score = score.saturating_add(weight);
                let source_score = source_hypothesis_scores
                    .entry((evidence.source_family, hypothesis_id.clone()))
                    .or_default();
                *source_score = source_score.saturating_add(weight);
            }
            for hypothesis_id in &assertions.refutes {
                let score = hypothesis_scores.get_mut(hypothesis_id).ok_or_else(|| {
                    CollectiveBenchmarkError::Contract(format!(
                        "evidence refutes undeclared hypothesis `{hypothesis_id}`"
                    ))
                })?;
                *score = score.saturating_sub(weight);
                let source_score = source_hypothesis_scores
                    .entry((evidence.source_family, hypothesis_id.clone()))
                    .or_default();
                *source_score = source_score.saturating_sub(weight);
            }
        }
        let selected = hypothesis_scores
            .iter()
            .max_by(|(left_id, left_score), (right_id, right_score)| {
                left_score
                    .cmp(right_score)
                    .then_with(|| right_id.cmp(left_id))
            })
            .map(|(id, _)| id.clone())
            .ok_or_else(|| {
                CollectiveBenchmarkError::Contract(
                    "benchmark case has no hypotheses to adjudicate".into(),
                )
            })?;
        if selected.as_str() != manifest.truth.selected_hypothesis_id {
            return Err(CollectiveBenchmarkError::Contract(format!(
                "executed reasoning case {case_index} selected `{selected}` instead of the frozen truth"
            )));
        }
        let selected_evidence = scenario
            .graph
            .evidence
            .values()
            .filter(|evidence| {
                let supports_selected = scenario
                    .assertions
                    .get(&evidence.evidence_id)
                    .is_some_and(|assertions| assertions.supports.contains(&selected));
                supports_selected
                    && (mode == ReasoningLaneMode::Collective
                        || source_hypothesis_scores
                            .get(&(evidence.source_family, selected.clone()))
                            .copied()
                            .unwrap_or_default()
                            > 0)
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut stage_evidence = BTreeMap::<KillChainStage, StageEvidence>::new();
        for evidence in selected_evidence {
            let topology = scenario
                .topology
                .get(&evidence.evidence_id)
                .ok_or_else(|| {
                    CollectiveBenchmarkError::Contract(format!(
                        "admitted evidence `{}` has no graph topology",
                        evidence.evidence_id
                    ))
                })?;
            if evidence.entity_ids() != topology.entity_node_ids {
                return Err(CollectiveBenchmarkError::Contract(format!(
                    "evidence `{}` topology differs from its signed payload",
                    evidence.evidence_id
                )));
            }
            let inferred = infer_causal_relations(&evidence.payload).map_err(|error| {
                CollectiveBenchmarkError::Contract(format!(
                    "production causal inference failed for `{}`: {error}",
                    evidence.evidence_id
                ))
            })?;
            if inferred.is_empty() {
                return Err(CollectiveBenchmarkError::Contract(format!(
                    "selected evidence `{}` produced no causal candidate",
                    evidence.evidence_id
                )));
            }
            for candidate in inferred {
                let inferred_stage = inferred_kill_chain_stage(&evidence.payload, &candidate)?;
                let edge = signed_benchmark_edge(
                    &signer,
                    &candidate.from,
                    &candidate.to,
                    evidence.evidence_id.clone(),
                    candidate.relation,
                    evidence.clock.observed_at,
                    EdgeState::Validated,
                )?;
                let edge_id = edge.edge_id.clone();
                scenario.graph.admit_edge(edge).map_err(|error| {
                    CollectiveBenchmarkError::Contract(format!(
                        "benchmark causal-edge admission failed: {error}"
                    ))
                })?;
                if let Some(inferred_stage) = inferred_stage {
                    let stage = stage_evidence.entry(inferred_stage).or_default();
                    stage
                        .node_ids
                        .extend([candidate.from.clone(), candidate.to.clone()]);
                    stage.edge_ids.insert(edge_id);
                    stage.evidence_ids.insert(evidence.evidence_id.clone());
                }
            }
        }
        if mode == ReasoningLaneMode::FixedInvestigator {
            // A fixed source-local investigator must explore one alternative
            // causal link for every internally contradictory source it
            // resolves. Those speculative links are admitted as rejected
            // edges, so the false-edge metric includes the work exactly as the
            // benchmark contract requires. Unopposed withheld evidence does
            // not manufacture speculative work.
            let contradicted_sources = scenario
                .graph
                .evidence
                .values()
                .filter_map(|evidence| {
                    let assertions = scenario.assertions.get(&evidence.evidence_id)?;
                    let refutation_exists = scenario.graph.evidence.values().any(|candidate| {
                        candidate.source_family == evidence.source_family
                            && scenario.assertions.get(&candidate.evidence_id).is_some_and(
                                |candidate_assertions| {
                                    candidate_assertions.refutes.contains(&selected)
                                },
                            )
                    });
                    (assertions.supports.contains(&selected)
                        && refutation_exists
                        && source_hypothesis_scores
                            .get(&(evidence.source_family, selected.clone()))
                            .copied()
                            .unwrap_or_default()
                            > 0)
                    .then_some(evidence.source_family)
                })
                .collect::<BTreeSet<_>>();
            let speculative_inputs = contradicted_sources
                .into_iter()
                .map(|family| {
                    let evidence = scenario
                        .graph
                        .evidence
                        .values()
                        .find(|evidence| {
                            evidence.source_family == family
                                && scenario.assertions.get(&evidence.evidence_id).is_some_and(
                                    |assertions| assertions.supports.contains(&selected),
                                )
                        })
                        .ok_or_else(|| {
                            CollectiveBenchmarkError::Contract(
                                "resolved source contradiction lost its supporting evidence"
                                    .to_string(),
                            )
                        })?;
                    let topology =
                        scenario
                            .topology
                            .get(&evidence.evidence_id)
                            .ok_or_else(|| {
                                CollectiveBenchmarkError::Contract(format!(
                                    "speculative evidence `{}` has no graph topology",
                                    evidence.evidence_id
                                ))
                            })?;
                    Ok((evidence.clone(), topology.clone()))
                })
                .collect::<Result<Vec<_>, CollectiveBenchmarkError>>()?;
            for (evidence, topology) in speculative_inputs {
                let from = topology.entity_node_ids.first().ok_or_else(|| {
                    CollectiveBenchmarkError::Contract(
                        "speculative evidence has no semantic source".to_string(),
                    )
                })?;
                let to = topology.entity_node_ids.last().ok_or_else(|| {
                    CollectiveBenchmarkError::Contract(
                        "speculative evidence has no semantic target".to_string(),
                    )
                })?;
                if from == to {
                    continue;
                }
                let edge = signed_benchmark_edge(
                    &signer,
                    from,
                    to,
                    evidence.evidence_id,
                    CausalRelation::ObservedIn,
                    evidence.clock.observed_at,
                    EdgeState::Rejected,
                )?;
                scenario.graph.admit_edge(edge).map_err(|error| {
                    CollectiveBenchmarkError::Contract(format!(
                        "fixed-investigator speculative-edge admission failed: {error}"
                    ))
                })?;
            }
        }
        let mut claims = Vec::new();
        let mut predecessor = None;
        for (stage, evidence) in stage_evidence {
            let claim = KillChainClaim::new(
                stage,
                evidence.node_ids,
                evidence.edge_ids,
                evidence.evidence_ids.clone(),
                predecessor.iter().cloned(),
                format!("reconstructed {stage:?} from admitted graph evidence"),
                evidence.evidence_ids,
            )
            .map_err(|error| {
                CollectiveBenchmarkError::Contract(format!(
                    "benchmark kill-chain reconstruction failed: {error}"
                ))
            })?;
            predecessor = Some(claim.claim_id.clone());
            claims.push(claim);
        }
        let reconstruction = KillChainReconstruction::new(claims, []).map_err(|error| {
            CollectiveBenchmarkError::Contract(format!(
                "benchmark kill-chain validation failed: {error}"
            ))
        })?;
        let fixture = fixtures[case_index];
        let observed_oracle_stages = fixture
            .expected_kill_chain
            .iter()
            .filter(|expected| expected.status == StageStatus::Observed)
            .filter(|expected| {
                reconstruction.claims.iter().any(|claim| {
                    kill_chain_stage_id(claim.stage) == expected.stage_id
                        && expected.evidence_ids.iter().any(|id| {
                            claim.evidence_ids.iter().any(|evidence_id| {
                                scenario.semantic_evidence_ids.get(evidence_id) == Some(id)
                            })
                        })
                })
            })
            .count();
        observed_stages = observed_stages
            .saturating_add(u64::try_from(observed_oracle_stages).unwrap_or(u64::MAX));
        let adjudication = DecisionRecord::new(
            DecisionKind::Adjudicate,
            selected,
            evidence_for_adjudication,
            GraphProducerRole::Adjudicator,
            producer.clone(),
            GraphLogicalTime::new(adjudicated_at.as_millis().saturating_add(1)),
            "collective evidence scores selected the attack hypothesis",
        )
        .and_then(|decision| decision.with_resulting_status(HypothesisStatus::Selected))
        .and_then(|decision| decision.signed_with(&signer, "collective-benchmark-adjudication"))
        .map_err(|error| {
            CollectiveBenchmarkError::Contract(format!(
                "benchmark hypothesis adjudication failed: {error}"
            ))
        })?;
        adjudications.push(adjudication);
    }

    let truth_edges = manifest
        .truth
        .causal_edges
        .iter()
        .map(CausalEdgeIdentity::from)
        .collect::<BTreeSet<_>>();

    let mut observed_edges = BTreeSet::new();
    let mut admitted_causal_edges = 0_u64;
    let mut false_causal_edges = 0_u64;
    for scenario in &scenarios {
        for edge in scenario.graph.edges.values() {
            admitted_causal_edges = admitted_causal_edges.saturating_add(1);
            let identity = scenario
                .semantic_node_ids
                .get(&edge.from)
                .zip(scenario.semantic_node_ids.get(&edge.to))
                .map(|(from, to)| CausalEdgeIdentity {
                    from: from.clone(),
                    to: to.clone(),
                    relation: causal_relation_name(edge.relation),
                });
            match identity {
                Some(identity) if truth_edges.contains(&identity) => {
                    observed_edges.insert(identity);
                }
                Some(_) | None => {
                    false_causal_edges = false_causal_edges.saturating_add(1);
                }
            }
        }
    }

    Ok(ExecutedReasoningLane {
        admitted_evidence,
        admitted_causal_edges,
        false_causal_edges,
        observed_stages,
        observed_edges,
        adjudications,
    })
}

fn validate_inputs(
    root: &Path,
    inputs: &FrozenBenchmarkInputs<'_>,
) -> Result<(), CollectiveBenchmarkError> {
    let FrozenBenchmarkInputs {
        manifest_bytes,
        training_bytes,
        withheld_bytes,
        manifest,
        training,
        withheld,
        baseline,
    } = inputs;
    if manifest.schema_version != 1
        || baseline.schema_version != 1
        || manifest.corpus_id != baseline.corpus_id
        || manifest.corpus_version != baseline.corpus_version
        || manifest.seed == 0
        || manifest.logical_clock.tick_ms == 0
        || manifest.metrics.denominators != baseline.denominators
        || manifest.metrics.thresholds != baseline.thresholds
    {
        return Err(CollectiveBenchmarkError::Contract(
            "manifest and baseline identities do not agree".to_string(),
        ));
    }
    let actual_digests = BenchmarkOracleDigests {
        manifest_sha256: sha256(manifest_bytes),
        ambiguous_fixture_sha256: sha256(training_bytes),
        withheld_fixture_sha256: sha256(withheld_bytes),
    };
    if actual_digests != baseline.oracle_digests {
        return Err(CollectiveBenchmarkError::Contract(
            "frozen oracle digest mismatch".to_string(),
        ));
    }
    if Path::new(&manifest.training_fixture).is_absolute()
        || Path::new(&manifest.withheld_fixture).is_absolute()
        || !root.join(&manifest.training_fixture).is_file()
        || !root.join(&manifest.withheld_fixture).is_file()
    {
        return Err(CollectiveBenchmarkError::Contract(
            "fixture paths are not confined repository inputs".to_string(),
        ));
    }
    if manifest.task_identities.len() as u64 != baseline.denominators.logical_tasks
        || manifest
            .task_identities
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .len()
            != manifest.task_identities.len()
        || manifest.controls.single_agent.max_investigators != 1
        || manifest.controls.single_agent.adaptive_task_allocation
        || manifest.controls.collective.max_investigators < 2
        || !manifest.controls.collective.adaptive_task_allocation
        || manifest.controls.single_agent.corpus_digest_ref != manifest.corpus_id
        || manifest.controls.collective.corpus_digest_ref != manifest.corpus_id
    {
        return Err(CollectiveBenchmarkError::Contract(
            "paired lane controls or task identities are invalid".to_string(),
        ));
    }
    let truth_edge_ids = manifest
        .truth
        .causal_edges
        .iter()
        .map(|edge| edge.edge_id.as_str())
        .collect::<BTreeSet<_>>();
    let truth_edge_identities = manifest
        .truth
        .causal_edges
        .iter()
        .map(CausalEdgeIdentity::from)
        .collect::<BTreeSet<_>>();
    if manifest.truth.causal_edges.len() as u64 != manifest.metrics.denominators.causal_edges
        || truth_edge_ids.len() != manifest.truth.causal_edges.len()
        || truth_edge_identities.len() != manifest.truth.causal_edges.len()
        || manifest.truth.causal_edges.iter().any(|edge| {
            edge.from == edge.to
                || !manifest.truth.node_ids.contains(&edge.from)
                || !manifest.truth.node_ids.contains(&edge.to)
        })
    {
        return Err(CollectiveBenchmarkError::Contract(
            "causal-edge oracle must contain unique IDs and full endpoint/relation identities"
                .to_string(),
        ));
    }
    let expected_cases = [
        (training, ScenarioClass::TrainingAttack),
        (withheld, ScenarioClass::WithheldAttack),
    ];
    for (fixture, class) in expected_cases {
        if fixture.schema_version != 1
            || fixture.class != class
            || fixture.hypothesis_ids != manifest.truth.hypothesis_ids
            || fixture.events.is_empty()
            || fixture.expected_kill_chain.len() as u64
                != manifest.metrics.denominators.attack_chain_stages
        {
            return Err(CollectiveBenchmarkError::Contract(format!(
                "fixture `{}` is incomplete or belongs to the wrong lane",
                fixture.scenario_id
            )));
        }
        let fixture_stage_ids = fixture
            .expected_kill_chain
            .iter()
            .map(|stage| stage.stage_id.as_str())
            .collect::<BTreeSet<_>>();
        let truth_stage_ids = manifest
            .truth
            .kill_chain_stage_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let fixture_evidence_ids = fixture
            .events
            .iter()
            .map(|event| event.evidence_id.as_str())
            .collect::<BTreeSet<_>>();
        if fixture_stage_ids.len() != fixture.expected_kill_chain.len()
            || fixture_stage_ids != truth_stage_ids
            || fixture_evidence_ids.len() != fixture.events.len()
        {
            return Err(CollectiveBenchmarkError::Contract(format!(
                "fixture `{}` must contain unique evidence and exactly one oracle row per truth stage",
                fixture.scenario_id
            )));
        }
        for stage in &fixture.expected_kill_chain {
            let status_matches_evidence = match stage.status {
                StageStatus::Observed => !stage.evidence_ids.is_empty(),
                StageStatus::MissingEvidence => stage.evidence_ids.is_empty(),
            };
            let stage_evidence_ids = stage
                .evidence_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            if !status_matches_evidence
                || stage_evidence_ids.len() != stage.evidence_ids.len()
                || !stage_evidence_ids.is_subset(&fixture_evidence_ids)
                || !manifest
                    .truth
                    .kill_chain_stage_ids
                    .contains(&stage.stage_id)
            {
                return Err(CollectiveBenchmarkError::Contract(format!(
                    "fixture `{}` has an invalid kill-chain oracle row `{}`",
                    fixture.scenario_id, stage.stage_id
                )));
            }
        }
        if fixture.events.iter().any(|event| {
            event
                .relation_ids
                .iter()
                .any(|relation_id| !truth_edge_ids.contains(relation_id.as_str()))
        }) {
            return Err(CollectiveBenchmarkError::Contract(format!(
                "fixture `{}` references an unknown causal-edge oracle ID",
                fixture.scenario_id
            )));
        }
    }
    Ok(())
}

fn collective_lane(
    manifest: &BenchmarkManifest,
    training: &ScenarioFixture,
    withheld: &ScenarioFixture,
) -> Result<BenchmarkLaneMetrics, CollectiveBenchmarkError> {
    let denominators = &manifest.metrics.denominators;
    let task_lane = execute_task_lane(
        manifest,
        [training, withheld],
        manifest.controls.collective.max_investigators,
    )?;
    let reasoning = execute_reasoning_lane(
        manifest,
        [training, withheld],
        ReasoningLaneMode::Collective,
    )?;
    let true_edges = reasoning.observed_edges.len() as u64;
    let stage_opportunities = denominators
        .attack_chain_stages
        .checked_mul(denominators.adjudicated_cases)
        .ok_or_else(|| {
            CollectiveBenchmarkError::Contract("stage denominator overflow".to_string())
        })?;

    let logical_work_units = task_lane
        .executed_tasks
        .saturating_add(reasoning.admitted_evidence)
        .saturating_add(reasoning.observed_stages)
        .saturating_add(reasoning.observed_edges.len() as u64)
        .saturating_add(u64::try_from(reasoning.adjudications.len()).unwrap_or(u64::MAX));
    if logical_work_units > manifest.limits.max_work_units as u64 {
        return Err(CollectiveBenchmarkError::Contract(
            "collective lane exceeded the configured work budget".to_string(),
        ));
    }

    Ok(BenchmarkLaneMetrics {
        median_hypothesis_time_ms: task_lane.median_hypothesis_time_ms,
        attack_chain_recall_bps: basis_points(reasoning.observed_stages, stage_opportunities)?,
        causal_edge_recall_bps: basis_points(true_edges, denominators.causal_edges)?,
        false_causal_edge_rate_bps: basis_points(
            reasoning.false_causal_edges,
            reasoning.admitted_causal_edges,
        )?,
        duplicate_work_rate_bps: basis_points(
            task_lane.duplicate_executions,
            denominators.logical_tasks,
        )?,
        evidence_coverage_bps: basis_points(
            reasoning.admitted_evidence,
            denominators.evidence_claims,
        )?,
        logical_work_units,
    })
}

fn fixed_investigator_lane(
    manifest: &BenchmarkManifest,
    training: &ScenarioFixture,
    withheld: &ScenarioFixture,
) -> Result<BenchmarkLaneMetrics, CollectiveBenchmarkError> {
    let denominators = &manifest.metrics.denominators;
    let task_lane = execute_task_lane(
        manifest,
        [training, withheld],
        manifest.controls.single_agent.max_investigators,
    )?;
    let reasoning = execute_reasoning_lane(
        manifest,
        [training, withheld],
        ReasoningLaneMode::FixedInvestigator,
    )?;
    let true_edges = reasoning.observed_edges.len() as u64;
    let stage_opportunities = denominators
        .attack_chain_stages
        .checked_mul(denominators.adjudicated_cases)
        .ok_or_else(|| {
            CollectiveBenchmarkError::Contract("stage denominator overflow".to_string())
        })?;

    Ok(BenchmarkLaneMetrics {
        median_hypothesis_time_ms: task_lane.median_hypothesis_time_ms,
        attack_chain_recall_bps: basis_points(reasoning.observed_stages, stage_opportunities)?,
        causal_edge_recall_bps: basis_points(true_edges, denominators.causal_edges)?,
        false_causal_edge_rate_bps: basis_points(
            reasoning.false_causal_edges,
            reasoning.admitted_causal_edges,
        )?,
        duplicate_work_rate_bps: basis_points(
            task_lane.duplicate_executions,
            denominators.logical_tasks,
        )?,
        evidence_coverage_bps: basis_points(
            reasoning.admitted_evidence,
            denominators.evidence_claims,
        )?,
        logical_work_units: task_lane.executed_tasks,
    })
}

/// Execute the paired corpus under deterministic logical time.
pub fn run_collective_benchmark(
    repository_root: impl AsRef<Path>,
) -> Result<CollectiveBenchmarkReport, CollectiveBenchmarkError> {
    let root = repository_root.as_ref();
    let manifest_bytes = read(&root.join(MANIFEST_REL))?;
    let baseline_bytes = read(&root.join(BASELINE_REL))?;
    let manifest: BenchmarkManifest = serde_yaml::from_slice(&manifest_bytes)?;
    let training_bytes = read(&root.join(&manifest.training_fixture))?;
    let withheld_bytes = read(&root.join(&manifest.withheld_fixture))?;
    let training: ScenarioFixture = serde_yaml::from_slice(&training_bytes)?;
    let withheld: ScenarioFixture = serde_yaml::from_slice(&withheld_bytes)?;
    let baseline: BenchmarkBaseline = serde_json::from_slice(&baseline_bytes)?;
    validate_inputs(
        root,
        &FrozenBenchmarkInputs {
            manifest_bytes: &manifest_bytes,
            training_bytes: &training_bytes,
            withheld_bytes: &withheld_bytes,
            manifest: &manifest,
            training: &training,
            withheld: &withheld,
            baseline: &baseline,
        },
    )?;

    let control_start = Instant::now();
    let single_agent = fixed_investigator_lane(&manifest, &training, &withheld)?;
    if single_agent != baseline.single_agent_baseline {
        return Err(CollectiveBenchmarkError::Contract(format!(
            "executed single-agent metrics differ from the frozen baseline: executed={single_agent:?}, baseline={:?}",
            baseline.single_agent_baseline
        )));
    }
    let single_agent_wall_clock_ms = control_start.elapsed().as_millis() as u64;

    let collective_start = Instant::now();
    let collective = collective_lane(&manifest, &training, &withheld)?;
    let collective_wall_clock_ms = collective_start.elapsed().as_millis() as u64;
    let deltas = BenchmarkDeltas {
        hypothesis_time_reduction_bps: reduction_basis_points(
            single_agent.median_hypothesis_time_ms,
            collective.median_hypothesis_time_ms,
        ),
        attack_chain_recall_gain_bps: i32::from(collective.attack_chain_recall_bps)
            - i32::from(single_agent.attack_chain_recall_bps),
    };
    let thresholds = &baseline.thresholds;
    let mut failed_gates = Vec::new();
    if deltas.hypothesis_time_reduction_bps < thresholds.min_hypothesis_time_reduction_bps {
        failed_gates.push("hypothesis_time".to_string());
    }
    if deltas.attack_chain_recall_gain_bps < i32::from(thresholds.min_attack_chain_recall_gain_bps)
    {
        failed_gates.push("attack_chain_recall".to_string());
    }
    if collective.causal_edge_recall_bps < thresholds.min_causal_edge_recall_bps {
        failed_gates.push("causal_edge_recall".to_string());
    }
    if collective.false_causal_edge_rate_bps > thresholds.max_false_causal_edge_rate_bps {
        failed_gates.push("false_causal_edges".to_string());
    }
    if collective.duplicate_work_rate_bps > thresholds.max_duplicate_work_rate_bps {
        failed_gates.push("duplicate_work".to_string());
    }
    if collective.evidence_coverage_bps < thresholds.min_evidence_coverage_bps {
        failed_gates.push("evidence_coverage".to_string());
    }

    let mut corpus_material = Vec::new();
    corpus_material.extend_from_slice(&manifest_bytes);
    corpus_material.extend_from_slice(&training_bytes);
    corpus_material.extend_from_slice(&withheld_bytes);
    let config_digest = sha256(&serde_json::to_vec(&(
        &manifest.logical_clock,
        &manifest.controls,
        &manifest.limits,
        &manifest.metrics,
    ))?);
    let lane_input_digest = sha256(&serde_json::to_vec(&(
        &manifest.task_identities,
        &training.events,
        &withheld.events,
    ))?);
    let source_families = manifest
        .source_contracts
        .iter()
        .map(|contract| contract.family.as_str().to_string())
        .collect();
    let passed = failed_gates.is_empty();
    Ok(CollectiveBenchmarkReport {
        schema_version: 1,
        corpus_id: manifest.corpus_id,
        seed: manifest.seed,
        corpus_digest: sha256(&corpus_material),
        config_digest,
        lane_input_digest,
        oracle_digests: baseline.oracle_digests,
        source_families,
        denominators: baseline.denominators,
        single_agent,
        collective,
        deltas,
        verdict: BenchmarkVerdict {
            passed,
            failed_gates,
        },
        observations: BenchmarkObservations {
            single_agent_wall_clock_ms,
            collective_wall_clock_ms,
            gate_inputs: vec![
                "attack_chain_recall_bps".to_string(),
                "causal_edge_recall_bps".to_string(),
                "duplicate_work_rate_bps".to_string(),
                "evidence_coverage_bps".to_string(),
                "false_causal_edge_rate_bps".to_string(),
                "logical_work_units".to_string(),
                "median_hypothesis_time_ms".to_string(),
            ],
        },
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn inputs() -> (BenchmarkManifest, ScenarioFixture, ScenarioFixture) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let manifest: BenchmarkManifest =
            serde_yaml::from_slice(&fs::read(root.join(MANIFEST_REL)).unwrap()).unwrap();
        let training =
            serde_yaml::from_slice(&fs::read(root.join(&manifest.training_fixture)).unwrap())
                .unwrap();
        let withheld =
            serde_yaml::from_slice(&fs::read(root.join(&manifest.withheld_fixture)).unwrap())
                .unwrap();
        (manifest, training, withheld)
    }

    #[test]
    fn semantic_metrics_use_inferred_relations_and_exact_oracle_stage_matches() {
        let (manifest, training, withheld) = inputs();
        let executed = execute_reasoning_lane(
            &manifest,
            [&training, &withheld],
            ReasoningLaneMode::Collective,
        )
        .unwrap();
        assert_eq!(executed.observed_edges.len(), 6);
        assert_eq!(executed.observed_stages, 9);

        let mut mutated_training = training;
        let mut mutated_withheld = withheld;
        for event in mutated_training
            .events
            .iter_mut()
            .chain(mutated_withheld.events.iter_mut())
        {
            event.relation_ids.clear();
        }
        let without_relation_hints = execute_reasoning_lane(
            &manifest,
            [&mutated_training, &mutated_withheld],
            ReasoningLaneMode::Collective,
        )
        .unwrap();
        assert_eq!(
            without_relation_hints.observed_edges,
            executed.observed_edges
        );
        assert_eq!(
            without_relation_hints.observed_stages,
            executed.observed_stages
        );

        for fixture in [&mut mutated_training, &mut mutated_withheld] {
            assert_eq!(
                fixture.expected_kill_chain[0].stage_id,
                "stage:initial-access"
            );
            assert_eq!(
                fixture.expected_kill_chain[2].stage_id,
                "stage:credential-access"
            );
        }
        for fixture in [&mut mutated_training, &mut mutated_withheld] {
            // Keep a valid, unique set of stage IDs but attach the initial-access
            // and credential-access evidence to the opposite stages. Merely
            // counting reconstructed claims would miss this semantic defect.
            let initial_access = fixture.expected_kill_chain[0].stage_id.clone();
            fixture.expected_kill_chain[0].stage_id =
                fixture.expected_kill_chain[2].stage_id.clone();
            fixture.expected_kill_chain[2].stage_id = initial_access;
        }
        let mismatched_stage_oracle = execute_reasoning_lane(
            &manifest,
            [&mutated_training, &mutated_withheld],
            ReasoningLaneMode::Collective,
        )
        .unwrap();
        assert_eq!(mismatched_stage_oracle.observed_stages, 5);

        let mut swapped_training = mutated_training.clone();
        let mut swapped_withheld = mutated_withheld.clone();
        for event in swapped_training
            .events
            .iter_mut()
            .chain(swapped_withheld.events.iter_mut())
        {
            event.source_family = match event.source_family {
                SourceFamily::Identity => SourceFamily::Cloudtrail,
                SourceFamily::Cloudtrail => SourceFamily::Identity,
                family => family,
            };
        }
        assert!(
            execute_reasoning_lane(
                &manifest,
                [&swapped_training, &swapped_withheld],
                ReasoningLaneMode::Collective,
            )
            .is_err(),
            "a source-family mutation must not reinterpret an independently declared telemetry profile"
        );

        for event in mutated_training
            .events
            .iter_mut()
            .chain(mutated_withheld.events.iter_mut())
        {
            event.supports.clear();
            event.refutes.clear();
        }
        assert!(
            execute_reasoning_lane(
                &manifest,
                [&mutated_training, &mutated_withheld],
                ReasoningLaneMode::Collective,
            )
            .is_err()
        );
    }

    #[test]
    fn scoring_labels_cannot_manufacture_production_telemetry() {
        let (manifest, training, _) = inputs();
        let signer = Keypair::from_seed(&[91_u8; 32]);
        let mut event = training.events[0].clone();
        let before = normalize_fixture_event(&event, &signer)
            .unwrap()
            .evidence
            .canonical_bytes()
            .unwrap();

        event.supports = vec!["hypothesis:authorized-automation".to_string()];
        event.refutes = vec![manifest.truth.selected_hypothesis_id];
        let after = normalize_fixture_event(&event, &signer)
            .unwrap()
            .evidence
            .canonical_bytes()
            .unwrap();

        assert_eq!(before, after);
    }

    #[test]
    fn each_fixture_requires_an_independent_correct_adjudication() {
        let (manifest, training, mut withheld) = inputs();
        for event in &mut withheld.events {
            event.supports = vec!["hypothesis:authorized-automation".to_string()];
            event.refutes = vec![manifest.truth.selected_hypothesis_id.clone()];
        }

        assert!(
            execute_reasoning_lane(
                &manifest,
                [&training, &withheld],
                ReasoningLaneMode::Collective,
            )
            .is_err()
        );
    }

    #[test]
    fn fixed_investigator_semantics_are_executed_before_baseline_validation() {
        let (manifest, mut training, withheld) = inputs();
        let executed = fixed_investigator_lane(&manifest, &training, &withheld).unwrap();
        assert_eq!(
            executed,
            BenchmarkLaneMetrics {
                median_hypothesis_time_ms: 5_000,
                attack_chain_recall_bps: 6_000,
                causal_edge_recall_bps: 6_666,
                false_causal_edge_rate_bps: 2_500,
                duplicate_work_rate_bps: 0,
                evidence_coverage_bps: 7_500,
                logical_work_units: 100,
            }
        );

        let selected = &manifest.truth.selected_hypothesis_id;
        let network_support = training
            .events
            .iter_mut()
            .find(|event| {
                event.source_family == SourceFamily::Network
                    && event.supports.iter().any(|id| id == selected)
            })
            .unwrap();
        network_support.entity_ids.swap(0, 1);
        assert!(fixed_investigator_lane(&manifest, &training, &withheld).is_err());
    }
}
