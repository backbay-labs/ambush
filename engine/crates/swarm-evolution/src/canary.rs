use crate::config::{DetectorProfileError, RuntimeConfigError, load_config};
use crate::detector_factory::{
    DetectorFactoryError, RuntimeDetector, build_detector_from_candidate,
    build_detector_from_strategy,
};
use crate::evolution::{
    EvolutionProposalAssuranceSummary, assurance_gate_block_reason, render_assurance_summary_lines,
};
use crate::replay::{
    DetectorCandidateManifest, DetectorExperimentManifest, ExperimentLineage, FileShadowStore,
    FileVerificationStore, ReplayHarnessError, ShadowStoreError, VerificationStoreError,
    load_detector_experiment_manifest,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use swarm_core::config::{CanaryConfig, ConfigValidationError, SwarmConfig};
use swarm_core::types::Severity;
use swarm_whisker::stream::{evaluate_event, findings_to_deposits};
use swarm_whisker::{DetectionFinding, TelemetryEvent};

/// Errors surfaced by the bounded canary lane.
#[derive(Debug, thiserror::Error)]
pub enum CanaryError {
    #[error(transparent)]
    Config(#[from] RuntimeConfigError),

    #[error(transparent)]
    Replay(#[from] ReplayHarnessError),

    #[error(transparent)]
    ConfigValidation(#[from] ConfigValidationError),

    #[error(transparent)]
    DetectorProfile(#[from] DetectorProfileError),

    #[error(transparent)]
    ProfileValidation(#[from] swarm_whisker::ProfileValidationError),

    #[error(transparent)]
    VerificationStore(#[from] VerificationStoreError),

    #[error(transparent)]
    ShadowStore(#[from] ShadowStoreError),

    #[error(transparent)]
    Store(#[from] CanaryStoreError),

    #[error("failed to read telemetry event `{path}`: {source}")]
    EventRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse telemetry event `{path}`: {source}")]
    EventParse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("bounded canary is disabled in the repo-owned config")]
    Disabled,

    #[error("verification artifact `{verification_id}` was not found")]
    VerificationNotFound { verification_id: String },

    #[error("shadow artifact `{shadow_id}` was not found")]
    ShadowNotFound { shadow_id: String },

    #[error("verification artifact `{verification_id}` did not pass")]
    VerificationFailed { verification_id: String },

    #[error("shadow artifact `{shadow_id}` did not pass")]
    ShadowFailed { shadow_id: String },

    #[error("canary assurance policy is not satisfied: {reason}")]
    AssuranceNotSatisfied { reason: String },

    #[error("artifact mismatch for {artifact}: expected experiment `{expected}`, found `{actual}`")]
    ExperimentMismatch {
        artifact: &'static str,
        expected: String,
        actual: String,
    },

    #[error("{artifact} lineage mismatch: expected `{expected}`, found `{actual}`")]
    LineageMismatch {
        artifact: &'static str,
        expected: String,
        actual: String,
    },

    #[error("{artifact} baseline mismatch: expected `{expected}`, found `{actual}`")]
    BaselineMismatch {
        artifact: &'static str,
        expected: String,
        actual: String,
    },

    #[error("an active canary already exists for slot `{slot_id}`: `{run_id}`")]
    ActiveRunExists { slot_id: String, run_id: String },

    #[error("canary run `{run_id}` was not found")]
    RunNotFound { run_id: String },

    #[error("canary run `{run_id}` is not active (status `{status:?}`)")]
    RunNotActive {
        run_id: String,
        status: CanaryRunStatus,
    },

    #[error("unsupported detector strategy `{strategy}`")]
    UnsupportedDetector { strategy: String },
}

/// Errors raised by the persisted canary store.
#[derive(Debug, thiserror::Error)]
pub enum CanaryStoreError {
    #[error("failed to read canary store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write canary store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse canary store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Runtime status for one canary run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryRunStatus {
    Active,
    Completed,
    RolledBack,
    Halted,
}

/// Final operator recommendation for one bounded canary run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryRecommendation {
    Observing,
    ReadyForPromotionReview,
    Blocked,
}

/// Automatic or manual source of one rollback-like action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryRollbackTrigger {
    AutomaticThreshold,
    AutomaticBudget,
    ManualHalt,
    ManualRollback,
}

/// One persisted rollback or halt event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryRollbackRecord {
    pub trigger: CanaryRollbackTrigger,
    pub reason: String,
    pub occurred_at_ms: i64,
    pub slot_id: String,
    pub reverted_baseline_strategy_id: String,
}

/// One threshold verdict preserved in the canary artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanaryThresholdResult {
    pub name: String,
    pub passed: bool,
    pub expected: serde_json::Value,
    pub actual: serde_json::Value,
    pub details: String,
}

/// One recent candidate finding preserved for operator inspection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanaryFindingPreview {
    pub event_id: String,
    pub strategy_id: String,
    pub severity: Severity,
    pub confidence: f64,
    pub shared_with_baseline: bool,
}

/// Aggregate canary metrics over the bounded observation window.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CanaryMetrics {
    pub total_events: usize,
    pub baseline_detections: usize,
    pub candidate_detections: usize,
    pub shared_detections: usize,
    pub candidate_only_detections: usize,
    pub baseline_only_detections: usize,
    pub candidate_only_rate: f64,
    pub baseline_miss_rate: f64,
    pub total_baseline_detect_latency_us: u64,
    pub average_baseline_detect_latency_us: u64,
    pub max_baseline_detect_latency_us: u64,
    pub total_candidate_detect_latency_us: u64,
    pub average_candidate_detect_latency_us: u64,
    pub max_candidate_detect_latency_us: u64,
    pub total_candidate_deposits: usize,
}

impl CanaryMetrics {
    fn observe(
        &mut self,
        baseline_findings: &[DetectionFinding],
        candidate_findings: &[DetectionFinding],
        baseline_latency_us: u64,
        candidate_latency_us: u64,
        candidate_deposit_count: usize,
    ) {
        self.total_events = self.total_events.saturating_add(1);
        self.total_baseline_detect_latency_us = self
            .total_baseline_detect_latency_us
            .saturating_add(baseline_latency_us);
        self.total_candidate_detect_latency_us = self
            .total_candidate_detect_latency_us
            .saturating_add(candidate_latency_us);
        self.max_baseline_detect_latency_us =
            self.max_baseline_detect_latency_us.max(baseline_latency_us);
        self.max_candidate_detect_latency_us = self
            .max_candidate_detect_latency_us
            .max(candidate_latency_us);
        self.average_baseline_detect_latency_us =
            self.total_baseline_detect_latency_us / self.total_events as u64;
        self.average_candidate_detect_latency_us =
            self.total_candidate_detect_latency_us / self.total_events as u64;
        self.total_candidate_deposits = self
            .total_candidate_deposits
            .saturating_add(candidate_deposit_count);

        let baseline_detected = !baseline_findings.is_empty();
        let candidate_detected = !candidate_findings.is_empty();
        if baseline_detected {
            self.baseline_detections = self.baseline_detections.saturating_add(1);
        }
        if candidate_detected {
            self.candidate_detections = self.candidate_detections.saturating_add(1);
        }
        if baseline_detected && candidate_detected {
            self.shared_detections = self.shared_detections.saturating_add(1);
        } else if candidate_detected {
            self.candidate_only_detections = self.candidate_only_detections.saturating_add(1);
        } else if baseline_detected {
            self.baseline_only_detections = self.baseline_only_detections.saturating_add(1);
        }

        self.candidate_only_rate = if self.total_events == 0 {
            0.0
        } else {
            self.candidate_only_detections as f64 / self.total_events as f64
        };
        self.baseline_miss_rate = if self.baseline_detections == 0 {
            0.0
        } else {
            self.baseline_only_detections as f64 / self.baseline_detections as f64
        };
    }
}

/// Stable assignment details for one bounded canary run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryAssignment {
    pub experiment_id: String,
    pub experiment_name: String,
    pub experiment_path: String,
    pub suite_name: String,
    pub corpus_version: String,
    pub baseline_strategy_id: String,
    pub candidate_strategy_id: String,
    pub candidate_description: String,
    pub candidate: DetectorCandidateManifest,
    pub lineage: ExperimentLineage,
    pub verification_id: String,
    pub verification_passed: bool,
    pub shadow_id: String,
    pub shadow_passed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance: Option<EvolutionProposalAssuranceSummary>,
    pub canary: CanaryConfig,
}

/// Persisted canary run artifact exposed to operators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryRunReport {
    pub run_id: String,
    pub slot_id: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub status: CanaryRunStatus,
    pub recommendation: CanaryRecommendation,
    pub assignment: CanaryAssignment,
    pub metrics: CanaryMetrics,
    pub threshold_results: Vec<CanaryThresholdResult>,
    pub recent_candidate_findings: Vec<CanaryFindingPreview>,
    pub rollback_history: Vec<CanaryRollbackRecord>,
}

/// Metadata surfaced for one persisted canary run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryRunRecord {
    pub run_id: String,
    pub slot_id: String,
    pub experiment_id: String,
    pub candidate_strategy_id: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub status: CanaryRunStatus,
    pub recommendation: CanaryRecommendation,
    pub bundle_path: String,
}

impl CanaryRunRecord {
    fn from_report(report: &CanaryRunReport, bundle_path: String) -> Self {
        Self {
            run_id: report.run_id.clone(),
            slot_id: report.slot_id.clone(),
            experiment_id: report.assignment.experiment_id.clone(),
            candidate_strategy_id: report.assignment.candidate_strategy_id.clone(),
            created_at_ms: report.created_at_ms,
            updated_at_ms: report.updated_at_ms,
            status: report.status,
            recommendation: report.recommendation,
            bundle_path,
        }
    }
}

/// Persisted canary run loaded with metadata.
#[derive(Debug, Clone)]
pub struct CanaryRunLookup {
    pub record: CanaryRunRecord,
    pub report: CanaryRunReport,
}

/// File-backed canary store used for bounded live canary runs.
#[derive(Debug, Clone)]
pub struct FileCanaryStore {
    root: PathBuf,
}

impl FileCanaryStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CanaryStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| CanaryStoreError::Write {
            path: root.clone(),
            source,
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, run_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(run_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<CanaryIndex, CanaryStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(CanaryIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| CanaryStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw).map_err(|source| CanaryStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &CanaryIndex) -> Result<(), CanaryStoreError> {
        let path = self.index_path();
        let raw =
            serde_json::to_string_pretty(index).map_err(|source| CanaryStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        fs::write(&path, raw).map_err(|source| CanaryStoreError::Write { path, source })
    }

    pub fn persist(&self, report: &CanaryRunReport) -> Result<CanaryRunRecord, CanaryStoreError> {
        let path = self.report_path(&report.run_id);
        let raw =
            serde_json::to_string_pretty(report).map_err(|source| CanaryStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        fs::write(&path, raw).map_err(|source| CanaryStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = CanaryRunRecord::from_report(report, path.display().to_string());
        index.entries.retain(|entry| entry.run_id != record.run_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.updated_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(&self, run_id: &str) -> Result<Option<CanaryRunLookup>, CanaryStoreError> {
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
        let raw = fs::read_to_string(&path).map_err(|source| CanaryStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let report = serde_json::from_str(&raw).map_err(|source| CanaryStoreError::Parse {
            path: path.clone(),
            source,
        })?;
        Ok(Some(CanaryRunLookup { record, report }))
    }

    pub fn load_active(&self, slot_id: &str) -> Result<Option<CanaryRunLookup>, CanaryStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.slot_id == slot_id && entry.status == CanaryRunStatus::Active)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| CanaryStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let report = serde_json::from_str(&raw).map_err(|source| CanaryStoreError::Parse {
            path: path.clone(),
            source,
        })?;
        Ok(Some(CanaryRunLookup { record, report }))
    }
}

/// Runtime-side bounded canary harness built from repo-owned config.
pub struct DefaultCanaryHarness {
    pub config_path: PathBuf,
    pub config: SwarmConfig,
    pub store: FileCanaryStore,
}

impl DefaultCanaryHarness {
    pub fn from_path(
        config_path: impl AsRef<Path>,
        results_dir: impl AsRef<Path>,
    ) -> Result<Self, CanaryError> {
        let config_path = config_path.as_ref();
        let config = load_config(config_path)?;
        Self::from_config(config_path, config, results_dir)
    }

    pub fn from_config(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
        results_dir: impl AsRef<Path>,
    ) -> Result<Self, CanaryError> {
        let store = FileCanaryStore::open(results_dir)?;
        Ok(Self {
            config_path: config_path.into(),
            config,
            store,
        })
    }

    pub fn start_run(
        &self,
        experiment_path: impl AsRef<Path>,
        verification_results_dir: impl AsRef<Path>,
        verification_id: &str,
        shadow_results_dir: impl AsRef<Path>,
        shadow_id: &str,
    ) -> Result<CanaryRunLookup, CanaryError> {
        self.start_run_internal(
            experiment_path,
            verification_results_dir,
            verification_id,
            shadow_results_dir,
            shadow_id,
            None,
            false,
        )
    }

    pub fn start_run_with_assurance(
        &self,
        experiment_path: impl AsRef<Path>,
        verification_results_dir: impl AsRef<Path>,
        verification_id: &str,
        shadow_results_dir: impl AsRef<Path>,
        shadow_id: &str,
        assurance: Option<EvolutionProposalAssuranceSummary>,
    ) -> Result<CanaryRunLookup, CanaryError> {
        self.start_run_internal(
            experiment_path,
            verification_results_dir,
            verification_id,
            shadow_results_dir,
            shadow_id,
            assurance,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn start_run_internal(
        &self,
        experiment_path: impl AsRef<Path>,
        verification_results_dir: impl AsRef<Path>,
        verification_id: &str,
        shadow_results_dir: impl AsRef<Path>,
        shadow_id: &str,
        assurance: Option<EvolutionProposalAssuranceSummary>,
        require_assurance: bool,
    ) -> Result<CanaryRunLookup, CanaryError> {
        if !self.config.canary.enabled {
            return Err(CanaryError::Disabled);
        }

        if require_assurance
            && let Some(reason) = canary_assurance_block_reason(&self.config, assurance.as_ref())
        {
            return Err(CanaryError::AssuranceNotSatisfied { reason });
        }

        if let Some(active) = self.store.load_active(&self.config.canary.slot_id)? {
            return Err(CanaryError::ActiveRunExists {
                slot_id: self.config.canary.slot_id.clone(),
                run_id: active.record.run_id,
            });
        }

        let experiment_path = experiment_path.as_ref().to_path_buf();
        let experiment = load_detector_experiment_manifest(&experiment_path)?;
        let baseline_strategy_id = resolve_canary_rollout_strategy_id(&self.config)?;
        if experiment.lineage.parent_strategy_id != baseline_strategy_id {
            return Err(CanaryError::LineageMismatch {
                artifact: "experiment",
                expected: baseline_strategy_id,
                actual: experiment.lineage.parent_strategy_id.clone(),
            });
        }
        let experiment_id = experiment_id_for_manifest(&experiment);

        let verification_store = FileVerificationStore::open(verification_results_dir)?;
        let verification = verification_store.load(verification_id)?.ok_or_else(|| {
            CanaryError::VerificationNotFound {
                verification_id: verification_id.to_string(),
            }
        })?;
        if verification.report.experiment_id != experiment_id {
            return Err(CanaryError::ExperimentMismatch {
                artifact: "verification",
                expected: experiment_id.clone(),
                actual: verification.report.experiment_id.clone(),
            });
        }
        if !verification.report.passed {
            return Err(CanaryError::VerificationFailed {
                verification_id: verification_id.to_string(),
            });
        }
        if verification.report.lineage != experiment.lineage {
            return Err(CanaryError::LineageMismatch {
                artifact: "verification",
                expected: lineage_label(&experiment.lineage),
                actual: lineage_label(&verification.report.lineage),
            });
        }

        let shadow_store = FileShadowStore::open(shadow_results_dir)?;
        let shadow = shadow_store
            .load(shadow_id)?
            .ok_or_else(|| CanaryError::ShadowNotFound {
                shadow_id: shadow_id.to_string(),
            })?;
        if shadow.report.experiment_id != experiment_id {
            return Err(CanaryError::ExperimentMismatch {
                artifact: "shadow",
                expected: experiment_id.clone(),
                actual: shadow.report.experiment_id.clone(),
            });
        }
        if !shadow.report.passed {
            return Err(CanaryError::ShadowFailed {
                shadow_id: shadow_id.to_string(),
            });
        }
        if shadow.report.lineage != experiment.lineage {
            return Err(CanaryError::LineageMismatch {
                artifact: "shadow",
                expected: lineage_label(&experiment.lineage),
                actual: lineage_label(&shadow.report.lineage),
            });
        }
        let baseline_strategy_id = resolve_canary_rollout_strategy_id(&self.config)?;
        if shadow.report.baseline_strategy_id != baseline_strategy_id {
            return Err(CanaryError::BaselineMismatch {
                artifact: "shadow",
                expected: baseline_strategy_id.clone(),
                actual: shadow.report.baseline_strategy_id.clone(),
            });
        }

        let now_ms = now_ms();
        let assignment = CanaryAssignment {
            experiment_id,
            experiment_name: experiment.name.clone(),
            experiment_path: experiment_path.display().to_string(),
            suite_name: shadow.report.suite_name.clone(),
            corpus_version: shadow.report.corpus_version.clone(),
            baseline_strategy_id,
            candidate_strategy_id: experiment.candidate.strategy_id().to_string(),
            candidate_description: experiment.candidate.description().to_string(),
            candidate: experiment.candidate.clone(),
            lineage: experiment.lineage.clone(),
            verification_id: verification.report.verification_id.clone(),
            verification_passed: verification.report.passed,
            shadow_id: shadow.report.shadow_id.clone(),
            shadow_passed: shadow.report.passed,
            assurance,
            canary: self.config.canary.clone(),
        };
        let run_id = canary_run_id(&self.config.canary.slot_id, &assignment, now_ms);
        let threshold_results = evaluate_thresholds(&CanaryMetrics::default(), &assignment.canary);
        let report = CanaryRunReport {
            run_id,
            slot_id: self.config.canary.slot_id.clone(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            status: CanaryRunStatus::Active,
            recommendation: CanaryRecommendation::Observing,
            assignment,
            metrics: CanaryMetrics::default(),
            threshold_results,
            recent_candidate_findings: Vec::new(),
            rollback_history: Vec::new(),
        };
        let record = self.store.persist(&report)?;
        Ok(CanaryRunLookup { record, report })
    }

    pub fn ingest_event_path(
        &self,
        run_id: &str,
        event_path: impl AsRef<Path>,
    ) -> Result<CanaryRunLookup, CanaryError> {
        let event_path = event_path.as_ref().to_path_buf();
        let raw = fs::read_to_string(&event_path).map_err(|source| CanaryError::EventRead {
            path: event_path.clone(),
            source,
        })?;
        let event = serde_yaml::from_str::<TelemetryEvent>(&raw).map_err(|source| {
            CanaryError::EventParse {
                path: event_path.clone(),
                source,
            }
        })?;
        self.ingest_event(run_id, &event)
    }

    pub fn ingest_event(
        &self,
        run_id: &str,
        event: &TelemetryEvent,
    ) -> Result<CanaryRunLookup, CanaryError> {
        let mut lookup = self
            .store
            .load(run_id)?
            .ok_or_else(|| CanaryError::RunNotFound {
                run_id: run_id.to_string(),
            })?;
        if lookup.report.status != CanaryRunStatus::Active {
            return Err(CanaryError::RunNotActive {
                run_id: run_id.to_string(),
                status: lookup.report.status,
            });
        }

        let baseline =
            baseline_detector(&lookup.report.assignment.baseline_strategy_id, &self.config)?;
        let candidate = candidate_detector(&lookup.report.assignment.candidate)?;

        let baseline_started = Instant::now();
        let baseline_findings = evaluate_event(&baseline, event);
        let baseline_latency_us = baseline_started.elapsed().as_micros() as u64;

        let candidate_started = Instant::now();
        let candidate_findings = evaluate_event(&candidate, event);
        let candidate_latency_us = candidate_started.elapsed().as_micros() as u64;

        let candidate_deposits = findings_to_deposits(
            &candidate_findings,
            event,
            &swarm_core::types::AgentId(format!("canary:{}", lookup.report.slot_id)),
            &self.config.pheromone,
        );

        lookup.report.metrics.observe(
            &baseline_findings,
            &candidate_findings,
            baseline_latency_us,
            candidate_latency_us,
            candidate_deposits.len(),
        );
        append_recent_candidate_findings(
            &mut lookup.report.recent_candidate_findings,
            &candidate_findings,
            !baseline_findings.is_empty(),
        );

        lookup.report.threshold_results =
            evaluate_thresholds(&lookup.report.metrics, &lookup.report.assignment.canary);
        lookup.report.updated_at_ms = now_ms();

        if let Some(failure) = lookup
            .report
            .threshold_results
            .iter()
            .find(|result| !result.passed)
        {
            let trigger = rollback_trigger_for_threshold(&failure.name);
            lookup.report.status = CanaryRunStatus::RolledBack;
            lookup.report.recommendation = CanaryRecommendation::Blocked;
            lookup.report.rollback_history.push(CanaryRollbackRecord {
                trigger,
                reason: failure.details.clone(),
                occurred_at_ms: lookup.report.updated_at_ms,
                slot_id: lookup.report.slot_id.clone(),
                reverted_baseline_strategy_id: lookup
                    .report
                    .assignment
                    .baseline_strategy_id
                    .clone(),
            });
        } else if lookup.report.metrics.total_events
            >= lookup.report.assignment.canary.observation_window_events
        {
            lookup.report.status = CanaryRunStatus::Completed;
            lookup.report.recommendation = CanaryRecommendation::ReadyForPromotionReview;
        } else {
            lookup.report.status = CanaryRunStatus::Active;
            lookup.report.recommendation = CanaryRecommendation::Observing;
        }

        lookup.record = self.store.persist(&lookup.report)?;
        Ok(lookup)
    }

    pub fn halt_run(&self, run_id: &str, reason: &str) -> Result<CanaryRunLookup, CanaryError> {
        self.finalize_run(
            run_id,
            reason,
            CanaryRunStatus::Halted,
            CanaryRollbackTrigger::ManualHalt,
        )
    }

    pub fn rollback_run(&self, run_id: &str, reason: &str) -> Result<CanaryRunLookup, CanaryError> {
        self.finalize_run(
            run_id,
            reason,
            CanaryRunStatus::RolledBack,
            CanaryRollbackTrigger::ManualRollback,
        )
    }

    pub fn load_run(&self, run_id: &str) -> Result<Option<CanaryRunLookup>, CanaryError> {
        Ok(self.store.load(run_id)?)
    }

    fn finalize_run(
        &self,
        run_id: &str,
        reason: &str,
        status: CanaryRunStatus,
        trigger: CanaryRollbackTrigger,
    ) -> Result<CanaryRunLookup, CanaryError> {
        let mut lookup = self
            .store
            .load(run_id)?
            .ok_or_else(|| CanaryError::RunNotFound {
                run_id: run_id.to_string(),
            })?;
        if lookup.report.status != CanaryRunStatus::Active {
            return Err(CanaryError::RunNotActive {
                run_id: run_id.to_string(),
                status: lookup.report.status,
            });
        }

        lookup.report.status = status;
        lookup.report.recommendation = CanaryRecommendation::Blocked;
        lookup.report.updated_at_ms = now_ms();
        lookup.report.rollback_history.push(CanaryRollbackRecord {
            trigger,
            reason: reason.to_string(),
            occurred_at_ms: lookup.report.updated_at_ms,
            slot_id: lookup.report.slot_id.clone(),
            reverted_baseline_strategy_id: lookup.report.assignment.baseline_strategy_id.clone(),
        });
        lookup.record = self.store.persist(&lookup.report)?;
        Ok(lookup)
    }
}

fn canary_assurance_block_reason(
    config: &SwarmConfig,
    assurance: Option<&EvolutionProposalAssuranceSummary>,
) -> Option<String> {
    assurance_gate_block_reason(assurance, config, current_time_ms(), "canary entry")
}

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub fn render_canary_run_report(report: &CanaryRunReport) -> String {
    let mut lines = vec![
        "Bounded Canary Run".to_string(),
        format!("Run ID: {}", report.run_id),
        format!("Slot: {}", report.slot_id),
        format!("Status: {:?}", report.status),
        format!("Recommendation: {:?}", report.recommendation),
        format!(
            "Baseline: {} | Candidate: {}",
            report.assignment.baseline_strategy_id, report.assignment.candidate_strategy_id
        ),
        format!(
            "Verification: {} (passed={}) | Shadow: {} (passed={})",
            report.assignment.verification_id,
            report.assignment.verification_passed,
            report.assignment.shadow_id,
            report.assignment.shadow_passed
        ),
        format!(
            "Observed events: {} / {}",
            report.metrics.total_events, report.assignment.canary.observation_window_events
        ),
        format!(
            "Detections: baseline={} candidate={} shared={}",
            report.metrics.baseline_detections,
            report.metrics.candidate_detections,
            report.metrics.shared_detections
        ),
        format!(
            "False-positive proxy: candidate_only={} rate={:.2}",
            report.metrics.candidate_only_detections, report.metrics.candidate_only_rate
        ),
        format!(
            "Baseline misses: {} rate={:.2}",
            report.metrics.baseline_only_detections, report.metrics.baseline_miss_rate
        ),
        format!(
            "Latency us: baseline_avg={} candidate_avg={} candidate_max={}",
            report.metrics.average_baseline_detect_latency_us,
            report.metrics.average_candidate_detect_latency_us,
            report.metrics.max_candidate_detect_latency_us
        ),
        format!(
            "Candidate detection volume: {}",
            report.metrics.total_candidate_deposits
        ),
    ];

    if let Some(assurance) = &report.assignment.assurance {
        lines.extend(render_assurance_summary_lines(assurance));
    } else {
        lines.push("Assurance: unavailable".to_string());
    }

    if report.threshold_results.is_empty() {
        lines.push("Thresholds: none".to_string());
    } else {
        lines.push("Thresholds:".to_string());
        for result in &report.threshold_results {
            lines.push(format!(
                "- {}: {} | {}",
                result.name,
                if result.passed { "pass" } else { "fail" },
                result.details
            ));
        }
    }

    if report.rollback_history.is_empty() {
        lines.push("Rollback history: none".to_string());
    } else {
        lines.push("Rollback history:".to_string());
        for rollback in &report.rollback_history {
            lines.push(format!(
                "- {:?} at {} | reason={} | reverted_baseline={}",
                rollback.trigger,
                rollback.occurred_at_ms,
                rollback.reason,
                rollback.reverted_baseline_strategy_id
            ));
        }
    }

    if report.recent_candidate_findings.is_empty() {
        lines.push("Recent candidate findings: none".to_string());
    } else {
        lines.push("Recent candidate findings:".to_string());
        for finding in &report.recent_candidate_findings {
            lines.push(format!(
                "- {} via {} severity={:?} confidence={:.2} shared_with_baseline={}",
                finding.event_id,
                finding.strategy_id,
                finding.severity,
                finding.confidence,
                finding.shared_with_baseline
            ));
        }
    }

    lines.join("\n")
}

fn baseline_detector(
    strategy_id: &str,
    config: &SwarmConfig,
) -> Result<RuntimeDetector, CanaryError> {
    build_detector_from_strategy(strategy_id, &config.detection).map_err(detector_factory_error)
}

fn candidate_detector(
    candidate: &DetectorCandidateManifest,
) -> Result<RuntimeDetector, CanaryError> {
    build_detector_from_candidate(candidate).map_err(detector_factory_error)
}

fn resolve_canary_rollout_strategy_id(config: &SwarmConfig) -> Result<String, CanaryError> {
    Ok(config.detection.resolve_rollout_strategy_id(
        "canary.strategy_id",
        config.canary.strategy_id.as_deref(),
        true,
    )?)
}

fn detector_factory_error(error: DetectorFactoryError) -> CanaryError {
    match error {
        DetectorFactoryError::DetectorProfile(source) => CanaryError::DetectorProfile(source),
        DetectorFactoryError::UnsupportedDetector { strategy } => {
            CanaryError::UnsupportedDetector { strategy }
        }
    }
}

fn lineage_label(lineage: &ExperimentLineage) -> String {
    format!(
        "parent_strategy_id={} mutation={} rationale={}",
        lineage.parent_strategy_id, lineage.mutation, lineage.rationale
    )
}

fn evaluate_thresholds(
    metrics: &CanaryMetrics,
    config: &CanaryConfig,
) -> Vec<CanaryThresholdResult> {
    vec![
        float_threshold(
            "candidate_only_rate",
            config.max_candidate_only_rate,
            metrics.candidate_only_rate,
            "candidate-only detection rate stayed within the configured bound",
            "candidate-only detection rate exceeded the configured bound",
        ),
        float_threshold(
            "baseline_miss_rate",
            config.max_baseline_miss_rate,
            metrics.baseline_miss_rate,
            "baseline miss rate stayed within the configured bound",
            "baseline miss rate exceeded the configured bound",
        ),
        int_threshold(
            "detect_latency_threshold",
            config.max_detect_latency_us as u128,
            metrics.max_candidate_detect_latency_us as u128,
            "candidate detect latency stayed within the configured bound",
            "candidate detect latency exceeded the configured bound",
        ),
        int_threshold(
            "total_detection_budget",
            config.max_total_detections as u128,
            metrics.total_candidate_deposits as u128,
            "candidate detection volume stayed within the configured budget",
            "candidate detection volume exceeded the configured budget",
        ),
    ]
}

fn float_threshold(
    name: &str,
    expected: f64,
    actual: f64,
    success_details: &str,
    failure_details: &str,
) -> CanaryThresholdResult {
    let passed = actual <= expected;
    CanaryThresholdResult {
        name: name.to_string(),
        passed,
        expected: serde_json::json!(expected),
        actual: serde_json::json!(actual),
        details: if passed {
            success_details.to_string()
        } else {
            failure_details.to_string()
        },
    }
}

fn int_threshold(
    name: &str,
    expected: u128,
    actual: u128,
    success_details: &str,
    failure_details: &str,
) -> CanaryThresholdResult {
    let passed = actual <= expected;
    CanaryThresholdResult {
        name: name.to_string(),
        passed,
        expected: serde_json::json!(expected),
        actual: serde_json::json!(actual),
        details: if passed {
            success_details.to_string()
        } else {
            failure_details.to_string()
        },
    }
}

fn append_recent_candidate_findings(
    previews: &mut Vec<CanaryFindingPreview>,
    findings: &[DetectionFinding],
    shared_with_baseline: bool,
) {
    for finding in findings {
        previews.push(CanaryFindingPreview {
            event_id: finding.event_id.clone(),
            strategy_id: finding.strategy_id.clone(),
            severity: finding.severity,
            confidence: finding.confidence,
            shared_with_baseline,
        });
    }
    if previews.len() > 10 {
        let drop_count = previews.len() - 10;
        previews.drain(0..drop_count);
    }
}

fn rollback_trigger_for_threshold(name: &str) -> CanaryRollbackTrigger {
    match name {
        "total_detection_budget" => CanaryRollbackTrigger::AutomaticBudget,
        _ => CanaryRollbackTrigger::AutomaticThreshold,
    }
}

fn experiment_id_for_manifest(manifest: &DetectorExperimentManifest) -> String {
    format!(
        "experiment:{}:{}",
        manifest.name,
        manifest.candidate.strategy_id()
    )
}

fn canary_run_id(slot_id: &str, assignment: &CanaryAssignment, started_at_ms: i64) -> String {
    format!(
        "canary:{}:{}:{}",
        slot_id, assignment.candidate_strategy_id, started_at_ms
    )
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CanaryIndex {
    entries: Vec<CanaryRunRecord>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        CanaryError, CanaryRecommendation, CanaryRollbackTrigger, CanaryRunStatus,
        DefaultCanaryHarness, render_canary_run_report,
    };
    use crate::config::RuntimeMode;
    use crate::evolution::{
        EvolutionProposalAssuranceCoverageSummary, EvolutionProposalAssuranceDecision,
        EvolutionProposalAssuranceSolverSummary, EvolutionProposalAssuranceSummary,
        build_assurance_waiver_summary,
    };
    use crate::replay::{
        DetectorCandidateManifest, DetectorExperimentManifest, DetectorVerificationReport,
        ExperimentCorpusTarget, ExperimentGateConfig, ExperimentLineage,
        ExperimentVerificationTarget, FileShadowStore, FileVerificationStore,
        StrategyExperimentComparison, StrategyExperimentMetricDelta, StrategyExperimentMetrics,
        StrategyShadowReport,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use swarm_core::config::{
        AuditConfig, BundleStoreConfig, CanaryConfig, CorrelationConfig, DetectionConfig,
        DetectorProfilesConfig, InvestigationConfig, PheromoneBackendConfig, PheromoneConfig,
        PolicyConfig, PromotionConfig, ResponseAdapterConfig, RuntimeSettings, SwarmConfig,
        TelemetrySourceConfig,
    };
    use swarm_core::types::{AgentId, Severity};
    use swarm_crypto::Ed25519Signer;
    use swarm_whisker::{
        DetectionStrategy, NetworkConnectProfile, ProcessStartEvent, SuspiciousProcessTreeProfile,
        TelemetryEvent, TelemetryPayload,
    };

    fn unique_temp_dir(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "swarm-runtime-canary-{label}-{}",
            std::process::id()
        ));
        if root.exists() {
            let _ = fs::remove_dir_all(&root);
        }
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn canary_config() -> SwarmConfig {
        SwarmConfig {
            schema_version: 1,
            name: "canary-test".to_string(),
            description: "bounded canary test config".to_string(),
            runtime: RuntimeSettings {
                mode: RuntimeMode::DetectOnly,
                demo_mode: false,
                telemetry_sources: vec![TelemetrySourceConfig {
                    name: "synthetic".to_string(),
                    subject: "telemetry.synthetic.process".to_string(),
                    bridge: None,
                }],
                max_in_flight_actions: 2,
                drain_timeout_ms: 30_000,
                require_durable_live_response: false,
                max_heap_pressure: 0.90,
                secret_dir: None,
                anti_tamper: Default::default(),
                temporal_event_window: swarm_core::config::TemporalEventWindowConfig::default(),
                agent_tick_timeout_ms: 500,
                governance_degraded_tick_threshold: 3,
                partition_contingency_lease_ttl_ms: 300_000,
                partition_contingency_blast_radius_cap: 1,
                max_dead_letter_bytes: None,
            },
            detection: DetectionConfig {
                strategy: "suspicious_process_tree".to_string(),
                strategies: Vec::new(),
                high_confidence_threshold: 0.9,
                medium_confidence_threshold: 0.7,
                profiles: DetectorProfilesConfig::default(),
            },
            pheromone: PheromoneConfig {
                default_half_life_secs: 3600.0,
                evaporation_threshold: 0.01,
                min_sources_for_escalation: 2,
                alert_threshold: 2.0,
                incident_threshold: 5.0,
                deescalation_cooldown_secs: 300,
                response_playbook: Default::default(),
                backend: PheromoneBackendConfig::InMemory,
            },
            policy: PolicyConfig {
                human_gate_severity: Severity::High,
                lease_ttl_ms: 60_000,
                ..PolicyConfig::default()
            },
            response_adapter: ResponseAdapterConfig::Sandbox,
            siem_forward: None,
            notification_channels: std::collections::BTreeMap::new(),
            notification_routing: swarm_core::config::NotificationRoutingConfig::default(),
            audit: AuditConfig {
                bundle_store: BundleStoreConfig::Memory,
                recent_decisions_limit: 20,
            },
            investigation: InvestigationConfig::default(),
            correlation: CorrelationConfig::default(),
            canary: CanaryConfig {
                enabled: true,
                slot_id: "canary-primary".to_string(),
                strategy_id: Some("suspicious_process_tree".to_string()),
                observation_window_events: 2,
                max_candidate_only_rate: 0.0,
                max_baseline_miss_rate: 0.0,
                max_detect_latency_us: 10_000,
                max_total_detections: 4,
            },
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

    fn control_candidate() -> DetectorCandidateManifest {
        DetectorCandidateManifest::SuspiciousProcessTree {
            strategy_id: "office_baseline_control".to_string(),
            description: "control candidate".to_string(),
            profile: SuspiciousProcessTreeProfile::default(),
        }
    }

    fn broadened_candidate() -> DetectorCandidateManifest {
        DetectorCandidateManifest::SuspiciousProcessTree {
            strategy_id: "office_python_parent_broadening".to_string(),
            description: "broaden parent set with python".to_string(),
            profile: SuspiciousProcessTreeProfile {
                suspicious_parents: vec![
                    "winword".to_string(),
                    "excel".to_string(),
                    "outlook".to_string(),
                    "acrord32".to_string(),
                    "teams".to_string(),
                    "python".to_string(),
                ],
                ..SuspiciousProcessTreeProfile::default()
            },
        }
    }

    fn blocked_assurance_summary() -> EvolutionProposalAssuranceSummary {
        EvolutionProposalAssuranceSummary {
            decision: EvolutionProposalAssuranceDecision::Blocked,
            coverage: EvolutionProposalAssuranceCoverageSummary {
                detector: "office_baseline_control".to_string(),
                suite_name: Some("evasion-breadth-v1".to_string()),
                corpus_version: Some("2026-04-03".to_string()),
                required_catch_rate: 0.75,
                actual_catch_rate: Some(0.25),
                actionable_gap_count: 2,
            },
            solver: EvolutionProposalAssuranceSolverSummary {
                required: true,
                status: None,
                allowed_statuses: Vec::new(),
            },
            harvested_case_ids: vec!["case-a".to_string()],
            waiver: None,
        }
    }

    fn waived_assurance_summary(
        operator_id: &str,
        secret_material: &str,
    ) -> EvolutionProposalAssuranceSummary {
        let signer = Ed25519Signer::from_secret_material(secret_material);
        let mut summary = blocked_assurance_summary();
        summary.waiver = Some(
            build_assurance_waiver_summary(
                "proposal-test",
                &summary,
                operator_id,
                &signer,
                super::current_time_ms() - 1_000,
                300,
                "bounded canary waiver",
            )
            .unwrap(),
        );
        summary
    }

    #[test]
    fn network_connect_baseline_and_candidate_detectors_are_supported()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = canary_config();
        config.detection.strategy = "network_connect".to_string();
        config.canary.strategy_id = Some("network_connect".to_string());

        let baseline = super::baseline_detector("network_connect", &config)?;
        assert_eq!(baseline.id(), "network_connect");

        let candidate = super::candidate_detector(&DetectorCandidateManifest::NetworkConnect {
            strategy_id: "network_connect_candidate".to_string(),
            description: "network connect candidate".to_string(),
            profile: NetworkConnectProfile {
                suspicious_ports: vec![4444],
                ..NetworkConnectProfile::default()
            },
        })?;
        assert_eq!(candidate.id(), "network_connect_candidate");
        Ok(())
    }

    fn experiment_manifest(
        name: &str,
        candidate: DetectorCandidateManifest,
    ) -> DetectorExperimentManifest {
        DetectorExperimentManifest {
            name: name.to_string(),
            description: format!("experiment {name}"),
            corpus: ExperimentCorpusTarget {
                suite: "../scenario-suites/hellcat-office-v1.yaml".to_string(),
            },
            verification: ExperimentVerificationTarget {
                corpus: "../verifications/office-detector-safety-v1.yaml".to_string(),
            },
            candidate,
            lineage: ExperimentLineage {
                parent_strategy_id: "suspicious_process_tree".to_string(),
                mutation: "test".to_string(),
                rationale: "test rationale".to_string(),
            },
            gates: ExperimentGateConfig::default(),
        }
    }

    fn write_experiment(root: &Path, manifest: &DetectorExperimentManifest) -> PathBuf {
        let path = root.join(format!("{}.yaml", manifest.name));
        fs::write(&path, serde_yaml::to_string(manifest).unwrap()).unwrap();
        path
    }

    fn persist_supporting_artifacts(
        root: &Path,
        manifest: &DetectorExperimentManifest,
    ) -> (PathBuf, PathBuf, String, String) {
        persist_supporting_artifacts_with_overrides(root, manifest, None, None, None)
    }

    fn persist_supporting_artifacts_with_overrides(
        root: &Path,
        manifest: &DetectorExperimentManifest,
        verification_lineage: Option<ExperimentLineage>,
        shadow_lineage: Option<ExperimentLineage>,
        shadow_baseline_strategy_id: Option<&str>,
    ) -> (PathBuf, PathBuf, String, String) {
        let verifications_dir = root.join("verifications");
        let shadows_dir = root.join("shadows");
        let experiment_id = format!(
            "experiment:{}:{}",
            manifest.name,
            manifest.candidate.strategy_id()
        );
        let verification_report = DetectorVerificationReport {
            verification_id: format!(
                "verification:{}:{}:office_detector_safety_v1",
                manifest.name,
                manifest.candidate.strategy_id()
            ),
            experiment_id: experiment_id.clone(),
            experiment_name: manifest.name.clone(),
            corpus_name: "office_detector_safety_v1".to_string(),
            corpus_path: "../verifications/office-detector-safety-v1.yaml".to_string(),
            created_at_ms: 1_700_000_000_000,
            lineage: verification_lineage.unwrap_or_else(|| manifest.lineage.clone()),
            candidate_strategy_id: manifest.candidate.strategy_id().to_string(),
            candidate_description: manifest.candidate.description().to_string(),
            invariants: vec![],
            passed: true,
        };
        let shadow_report = StrategyShadowReport {
            shadow_id: format!(
                "shadow:{}:{}:office_detector_safety_v1",
                manifest.name,
                manifest.candidate.strategy_id()
            ),
            experiment_id,
            experiment_name: manifest.name.clone(),
            created_at_ms: 1_700_000_000_001,
            source_artifacts: vec![manifest.corpus.suite.clone()],
            suite_name: "hellcat_office_v1".to_string(),
            suite_path: manifest.corpus.suite.clone(),
            corpus_version: "office_detector_safety_v1".to_string(),
            lineage: shadow_lineage.unwrap_or_else(|| manifest.lineage.clone()),
            baseline_strategy_id: shadow_baseline_strategy_id
                .unwrap_or(&manifest.lineage.parent_strategy_id)
                .to_string(),
            candidate_strategy_id: manifest.candidate.strategy_id().to_string(),
            candidate_description: manifest.candidate.description().to_string(),
            comparison: StrategyExperimentComparison {
                baseline: StrategyExperimentMetrics {
                    total_scenarios: 2,
                    adversarial_scenarios: 1,
                    benign_scenarios: 1,
                    true_positive_scenarios: 1,
                    false_negative_scenarios: 0,
                    true_negative_scenarios: 1,
                    false_positive_scenarios: 0,
                    detection_rate: 1.0,
                    false_positive_rate: 0.0,
                    max_detect_latency_us: 50,
                },
                candidate: StrategyExperimentMetrics {
                    total_scenarios: 2,
                    adversarial_scenarios: 1,
                    benign_scenarios: 1,
                    true_positive_scenarios: 1,
                    false_negative_scenarios: 0,
                    true_negative_scenarios: 1,
                    false_positive_scenarios: 0,
                    detection_rate: 1.0,
                    false_positive_rate: 0.0,
                    max_detect_latency_us: 50,
                },
                delta: StrategyExperimentMetricDelta {
                    detection_rate_delta: 0.0,
                    false_positive_rate_delta: 0.0,
                    max_detect_latency_delta_us: 0,
                    false_positive_scenario_delta: 0,
                },
                scenario_regressions: vec![],
                technique_regressions: vec![],
            },
            gates: vec![],
            passed: true,
        };

        let verification_store = FileVerificationStore::open(&verifications_dir).unwrap();
        let shadow_store = FileShadowStore::open(&shadows_dir).unwrap();
        let verification_record = verification_store.persist(&verification_report).unwrap();
        let shadow_record = shadow_store.persist(&shadow_report).unwrap();
        (
            verifications_dir,
            shadows_dir,
            verification_record.verification_id,
            shadow_record.shadow_id,
        )
    }

    fn suspicious_event(event_id: &str) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: event_id.to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "WINWORD".to_string(),
                process_name: "powershell".to_string(),
                command_line: "powershell.exe -enc AAA=".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        }
    }

    fn benign_python_event(event_id: &str) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: event_id.to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "python".to_string(),
                process_name: "curl".to_string(),
                command_line: "curl https://example.invalid/script.ps1".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        }
    }

    #[test]
    fn canary_start_rejects_verification_lineage_mismatch() {
        let root = unique_temp_dir("verification-lineage-mismatch");
        let results_dir = root.join("canaries");
        let config = canary_config();
        let manifest = experiment_manifest("control", control_candidate());
        let experiment_path = write_experiment(&root, &manifest);
        let stale_lineage = ExperimentLineage {
            parent_strategy_id: manifest.lineage.parent_strategy_id.clone(),
            mutation: "stale".to_string(),
            rationale: "artifact drift".to_string(),
        };
        let (verifications_dir, shadows_dir, verification_id, shadow_id) =
            persist_supporting_artifacts_with_overrides(
                &root,
                &manifest,
                Some(stale_lineage),
                None,
                None,
            );

        let harness =
            DefaultCanaryHarness::from_config("rulesets/default.yaml", config, &results_dir)
                .unwrap();
        let error = harness
            .start_run(
                &experiment_path,
                &verifications_dir,
                &verification_id,
                &shadows_dir,
                &shadow_id,
            )
            .unwrap_err();

        assert!(matches!(
            error,
            CanaryError::LineageMismatch {
                artifact: "verification",
                ..
            }
        ));
    }

    #[test]
    fn canary_start_rejects_shadow_baseline_scope_mismatch() {
        let root = unique_temp_dir("shadow-baseline-mismatch");
        let results_dir = root.join("canaries");
        let mut config = canary_config();
        config.detection.strategies = vec![
            "suspicious_process_tree".to_string(),
            "dns_exfiltration".to_string(),
        ];
        config.canary.strategy_id = Some("suspicious_process_tree".to_string());
        let manifest = experiment_manifest("control", control_candidate());
        let experiment_path = write_experiment(&root, &manifest);
        let (verifications_dir, shadows_dir, verification_id, shadow_id) =
            persist_supporting_artifacts_with_overrides(
                &root,
                &manifest,
                None,
                None,
                Some("dns_exfiltration"),
            );

        let harness =
            DefaultCanaryHarness::from_config("rulesets/default.yaml", config, &results_dir)
                .unwrap();
        let error = harness
            .start_run(
                &experiment_path,
                &verifications_dir,
                &verification_id,
                &shadows_dir,
                &shadow_id,
            )
            .unwrap_err();

        assert!(matches!(
            error,
            CanaryError::BaselineMismatch {
                artifact: "shadow",
                ..
            }
        ));
    }

    #[test]
    fn canary_run_starts_from_verified_candidate() {
        let root = unique_temp_dir("start");
        let results_dir = root.join("canaries");
        let config = canary_config();
        let manifest = experiment_manifest("control", control_candidate());
        let experiment_path = write_experiment(&root, &manifest);
        let (verifications_dir, shadows_dir, verification_id, shadow_id) =
            persist_supporting_artifacts(&root, &manifest);

        let harness =
            DefaultCanaryHarness::from_config("rulesets/default.yaml", config, &results_dir)
                .unwrap();
        let lookup = harness
            .start_run(
                &experiment_path,
                &verifications_dir,
                &verification_id,
                &shadows_dir,
                &shadow_id,
            )
            .unwrap();

        assert_eq!(lookup.report.status, CanaryRunStatus::Active);
        assert_eq!(
            lookup.report.recommendation,
            CanaryRecommendation::Observing
        );
        assert_eq!(
            lookup.report.assignment.baseline_strategy_id,
            "suspicious_process_tree"
        );
        assert_eq!(
            lookup.report.assignment.candidate_strategy_id,
            "office_baseline_control"
        );
    }

    #[test]
    fn canary_start_with_assurance_rejects_blocked_lineage() {
        let root = unique_temp_dir("blocked-assurance");
        let results_dir = root.join("canaries");
        let config = canary_config();
        let manifest = experiment_manifest("control", control_candidate());
        let experiment_path = write_experiment(&root, &manifest);
        let (verifications_dir, shadows_dir, verification_id, shadow_id) =
            persist_supporting_artifacts(&root, &manifest);

        let harness =
            DefaultCanaryHarness::from_config("rulesets/default.yaml", config, &results_dir)
                .unwrap();
        let error = harness
            .start_run_with_assurance(
                &experiment_path,
                &verifications_dir,
                &verification_id,
                &shadows_dir,
                &shadow_id,
                Some(blocked_assurance_summary()),
            )
            .unwrap_err();

        assert!(matches!(error, CanaryError::AssuranceNotSatisfied { .. }));
    }

    #[test]
    fn canary_start_with_assurance_accepts_active_waiver_lineage() {
        let root = unique_temp_dir("waived-assurance");
        let results_dir = root.join("canaries");
        let mut config = canary_config();
        let secret_material = "phase-175-canary-waiver";
        let operator_id = AgentId::from_public_key_hex(
            Ed25519Signer::from_secret_material(secret_material).public_key_hex(),
        )
        .to_string();
        config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
        let manifest = experiment_manifest("control", control_candidate());
        let experiment_path = write_experiment(&root, &manifest);
        let (verifications_dir, shadows_dir, verification_id, shadow_id) =
            persist_supporting_artifacts(&root, &manifest);

        let harness =
            DefaultCanaryHarness::from_config("rulesets/default.yaml", config, &results_dir)
                .unwrap();
        let started = harness
            .start_run_with_assurance(
                &experiment_path,
                &verifications_dir,
                &verification_id,
                &shadows_dir,
                &shadow_id,
                Some(waived_assurance_summary(&operator_id, secret_material)),
            )
            .unwrap();

        assert_eq!(started.report.status, CanaryRunStatus::Active);
        assert!(render_canary_run_report(&started.report).contains("Assurance waiver:"));
        assert!(
            render_canary_run_report(&started.report)
                .contains("Waiver reason: bounded canary waiver")
        );
    }

    #[test]
    fn canary_control_candidate_completes_after_window() {
        let root = unique_temp_dir("complete");
        let results_dir = root.join("canaries");
        let config = canary_config();
        let manifest = experiment_manifest("control", control_candidate());
        let experiment_path = write_experiment(&root, &manifest);
        let (verifications_dir, shadows_dir, verification_id, shadow_id) =
            persist_supporting_artifacts(&root, &manifest);

        let harness =
            DefaultCanaryHarness::from_config("rulesets/default.yaml", config, &results_dir)
                .unwrap();
        let started = harness
            .start_run(
                &experiment_path,
                &verifications_dir,
                &verification_id,
                &shadows_dir,
                &shadow_id,
            )
            .unwrap();

        let after_first = harness
            .ingest_event(&started.record.run_id, &suspicious_event("evt-canary-1"))
            .unwrap();
        assert_eq!(after_first.report.status, CanaryRunStatus::Active);

        let completed = harness
            .ingest_event(&started.record.run_id, &suspicious_event("evt-canary-2"))
            .unwrap();
        assert_eq!(completed.report.status, CanaryRunStatus::Completed);
        assert_eq!(
            completed.report.recommendation,
            CanaryRecommendation::ReadyForPromotionReview
        );
        assert!(render_canary_run_report(&completed.report).contains("Bounded Canary Run"));
    }

    #[test]
    fn canary_auto_rollback_triggers_on_candidate_only_detection() {
        let root = unique_temp_dir("rollback");
        let results_dir = root.join("canaries");
        let config = canary_config();
        let manifest = experiment_manifest("broad", broadened_candidate());
        let experiment_path = write_experiment(&root, &manifest);
        let (verifications_dir, shadows_dir, verification_id, shadow_id) =
            persist_supporting_artifacts(&root, &manifest);

        let harness =
            DefaultCanaryHarness::from_config("rulesets/default.yaml", config, &results_dir)
                .unwrap();
        let started = harness
            .start_run(
                &experiment_path,
                &verifications_dir,
                &verification_id,
                &shadows_dir,
                &shadow_id,
            )
            .unwrap();

        let rolled_back = harness
            .ingest_event(
                &started.record.run_id,
                &benign_python_event("evt-canary-python"),
            )
            .unwrap();
        assert_eq!(rolled_back.report.status, CanaryRunStatus::RolledBack);
        assert_eq!(
            rolled_back.report.recommendation,
            CanaryRecommendation::Blocked
        );
        assert_eq!(rolled_back.report.rollback_history.len(), 1);
        assert_eq!(
            rolled_back.report.rollback_history[0].trigger,
            CanaryRollbackTrigger::AutomaticThreshold
        );
        assert!(
            rolled_back
                .report
                .threshold_results
                .iter()
                .any(|result| result.name == "candidate_only_rate" && !result.passed)
        );
    }

    #[test]
    fn canary_manual_halt_records_reason() {
        let root = unique_temp_dir("halt");
        let results_dir = root.join("canaries");
        let config = canary_config();
        let manifest = experiment_manifest("control", control_candidate());
        let experiment_path = write_experiment(&root, &manifest);
        let (verifications_dir, shadows_dir, verification_id, shadow_id) =
            persist_supporting_artifacts(&root, &manifest);

        let harness =
            DefaultCanaryHarness::from_config("rulesets/default.yaml", config, &results_dir)
                .unwrap();
        let started = harness
            .start_run(
                &experiment_path,
                &verifications_dir,
                &verification_id,
                &shadows_dir,
                &shadow_id,
            )
            .unwrap();

        let halted = harness
            .halt_run(&started.record.run_id, "operator requested stop")
            .unwrap();
        assert_eq!(halted.report.status, CanaryRunStatus::Halted);
        assert_eq!(halted.report.rollback_history.len(), 1);
        assert_eq!(
            halted.report.rollback_history[0].trigger,
            CanaryRollbackTrigger::ManualHalt
        );
        assert_eq!(
            halted.report.rollback_history[0].reason,
            "operator requested stop"
        );
    }
}
