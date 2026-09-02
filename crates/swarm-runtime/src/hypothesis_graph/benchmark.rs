//! Deterministic paired evaluation for the frozen collective-reasoning corpus.
//!
//! The benchmark consumes the checked-in oracle instead of embedding expected
//! outcomes in executable code. Both lanes receive the same stable task and
//! evidence identities. Logical time alone determines the verdict; host wall
//! clock is reported as an observation and cannot affect any gate.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use swarm_core::hypothesis_graph::{GraphLogicalTime, GraphResourceLimits, TaskId, TaskKind};

use super::clock::DeterministicScheduler;

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
    max_false_causal_edge_rate_bps: u16,
    max_duplicate_work_rate_bps: u16,
    min_evidence_coverage_bps: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkLaneMetrics {
    pub median_hypothesis_time_ms: u64,
    pub attack_chain_recall_bps: u16,
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
    causal_edge_ids: Vec<String>,
    kill_chain_stage_ids: Vec<String>,
    required_evidence_ids: Vec<String>,
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

    let events = training.events.iter().chain(&withheld.events);
    let evidence = events
        .clone()
        .map(|event| event.evidence_id.clone())
        .collect::<BTreeSet<_>>();
    let observed_edges = events
        .flat_map(|event| event.relation_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    let truth_edges = manifest
        .truth
        .causal_edge_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let false_edges = observed_edges.difference(&truth_edges).count() as u64;
    let observed_stages = training
        .expected_kill_chain
        .iter()
        .chain(&withheld.expected_kill_chain)
        .filter(|stage| stage.status == StageStatus::Observed)
        .count() as u64;
    let stage_opportunities = denominators
        .attack_chain_stages
        .checked_mul(denominators.adjudicated_cases)
        .ok_or_else(|| {
            CollectiveBenchmarkError::Contract("stage denominator overflow".to_string())
        })?;

    let logical_work_units = task_lane
        .executed_tasks
        .saturating_add(evidence.len() as u64)
        .saturating_add(observed_stages)
        .saturating_add(observed_edges.len() as u64);
    if logical_work_units > manifest.limits.max_work_units as u64 {
        return Err(CollectiveBenchmarkError::Contract(
            "collective lane exceeded the configured work budget".to_string(),
        ));
    }

    Ok(BenchmarkLaneMetrics {
        median_hypothesis_time_ms: task_lane.median_hypothesis_time_ms,
        attack_chain_recall_bps: basis_points(observed_stages, stage_opportunities)?,
        false_causal_edge_rate_bps: basis_points(false_edges, denominators.causal_edges)?,
        duplicate_work_rate_bps: basis_points(
            task_lane.duplicate_executions,
            denominators.logical_tasks,
        )?,
        evidence_coverage_bps: basis_points(evidence.len() as u64, denominators.evidence_claims)?,
        logical_work_units,
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
    let single_agent = baseline.single_agent_baseline.clone();
    let executed_control = execute_task_lane(
        &manifest,
        [&training, &withheld],
        manifest.controls.single_agent.max_investigators,
    )?;
    if executed_control.median_hypothesis_time_ms != single_agent.median_hypothesis_time_ms
        || executed_control.executed_tasks != manifest.metrics.denominators.logical_tasks
        || executed_control.duplicate_executions != 0
    {
        return Err(CollectiveBenchmarkError::Contract(
            "single-agent baseline is not bound to the executed paired workload".to_string(),
        ));
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
                "duplicate_work_rate_bps".to_string(),
                "evidence_coverage_bps".to_string(),
                "false_causal_edge_rate_bps".to_string(),
                "logical_work_units".to_string(),
                "median_hypothesis_time_ms".to_string(),
            ],
        },
    })
}
