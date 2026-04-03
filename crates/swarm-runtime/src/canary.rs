use crate::config::{RuntimeConfigError, load_config};
use crate::replay::{
    DetectorCandidateManifest, DetectorExperimentManifest, ExperimentLineage, FileShadowStore,
    FileVerificationStore, ReplayHarnessError, ShadowStoreError, VerificationStoreError,
    load_detector_experiment_manifest,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use swarm_core::config::CanaryConfig;
use swarm_core::config::SwarmConfig;
use swarm_core::types::Severity;
use swarm_whisker::stream::{evaluate_event, findings_to_deposits};
use swarm_whisker::{
    DetectionFinding, DetectionStrategy, SuspiciousProcessTreeDetector, TelemetryEvent,
};

/// Errors surfaced by the bounded canary lane.
#[derive(Debug, thiserror::Error)]
pub enum CanaryError {
    #[error(transparent)]
    Config(#[from] RuntimeConfigError),

    #[error(transparent)]
    Replay(#[from] ReplayHarnessError),

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

    #[error("artifact mismatch for {artifact}: expected experiment `{expected}`, found `{actual}`")]
    ExperimentMismatch {
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
        if !self.config.canary.enabled {
            return Err(CanaryError::Disabled);
        }

        if let Some(active) = self.store.load_active(&self.config.canary.slot_id)? {
            return Err(CanaryError::ActiveRunExists {
                slot_id: self.config.canary.slot_id.clone(),
                run_id: active.record.run_id,
            });
        }

        let experiment_path = experiment_path.as_ref().to_path_buf();
        let experiment = load_detector_experiment_manifest(&experiment_path)?;
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

        let now_ms = now_ms();
        let assignment = CanaryAssignment {
            experiment_id,
            experiment_name: experiment.name.clone(),
            experiment_path: experiment_path.display().to_string(),
            suite_name: shadow.report.suite_name.clone(),
            corpus_version: shadow.report.corpus_version.clone(),
            baseline_strategy_id: self.config.detection.strategy.clone(),
            candidate_strategy_id: experiment.candidate.strategy_id().to_string(),
            candidate_description: experiment.candidate.description().to_string(),
            candidate: experiment.candidate.clone(),
            lineage: experiment.lineage.clone(),
            verification_id: verification.report.verification_id.clone(),
            verification_passed: verification.report.passed,
            shadow_id: shadow.report.shadow_id.clone(),
            shadow_passed: shadow.report.passed,
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

        let baseline = baseline_detector(&self.config)?;
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

#[derive(Debug, Clone)]
enum SupportedCanaryDetector {
    SuspiciousProcessTree {
        strategy_id: String,
        detector: SuspiciousProcessTreeDetector,
    },
}

impl DetectionStrategy for SupportedCanaryDetector {
    fn id(&self) -> &str {
        match self {
            Self::SuspiciousProcessTree { strategy_id, .. } => strategy_id.as_str(),
        }
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        match self {
            Self::SuspiciousProcessTree { detector, .. } => detector.evaluate(event),
        }
    }
}

impl SupportedCanaryDetector {
    fn suspicious_process_tree(
        strategy_id: impl Into<String>,
        profile: swarm_whisker::SuspiciousProcessTreeProfile,
    ) -> Self {
        Self::SuspiciousProcessTree {
            strategy_id: strategy_id.into(),
            detector: SuspiciousProcessTreeDetector::from_profile(profile),
        }
    }
}

fn baseline_detector(config: &SwarmConfig) -> Result<SupportedCanaryDetector, CanaryError> {
    match config.detection.strategy.as_str() {
        "suspicious_process_tree" => Ok(SupportedCanaryDetector::suspicious_process_tree(
            config.detection.strategy.clone(),
            swarm_whisker::SuspiciousProcessTreeProfile {
                high_confidence_threshold: config.detection.high_confidence_threshold,
                medium_confidence_threshold: config.detection.medium_confidence_threshold,
                ..swarm_whisker::SuspiciousProcessTreeProfile::default()
            },
        )),
        other => Err(CanaryError::UnsupportedDetector {
            strategy: other.to_string(),
        }),
    }
}

fn candidate_detector(
    candidate: &DetectorCandidateManifest,
) -> Result<SupportedCanaryDetector, CanaryError> {
    match candidate {
        DetectorCandidateManifest::SuspiciousProcessTree {
            strategy_id,
            profile,
            ..
        } => Ok(SupportedCanaryDetector::suspicious_process_tree(
            strategy_id.clone(),
            profile.clone(),
        )),
    }
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
        .expect("system time after unix epoch")
        .as_millis() as i64
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CanaryIndex {
    entries: Vec<CanaryRunRecord>,
}

#[cfg(test)]
mod tests {
    use super::{
        CanaryRecommendation, CanaryRollbackTrigger, CanaryRunStatus, DefaultCanaryHarness,
        render_canary_run_report,
    };
    use crate::config::RuntimeMode;
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
        InvestigationConfig, PheromoneBackendConfig, PheromoneConfig, PolicyConfig,
        RuntimeSettings, SwarmConfig, TelemetrySourceConfig,
    };
    use swarm_core::types::Severity;
    use swarm_whisker::{
        ProcessStartEvent, SuspiciousProcessTreeProfile, TelemetryEvent, TelemetryPayload,
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
            name: "canary-test".to_string(),
            description: "bounded canary test config".to_string(),
            runtime: RuntimeSettings {
                mode: RuntimeMode::DetectOnly,
                telemetry_sources: vec![TelemetrySourceConfig {
                    name: "synthetic".to_string(),
                    subject: "telemetry.synthetic.process".to_string(),
                }],
                max_in_flight_actions: 2,
                require_durable_live_response: false,
            },
            detection: DetectionConfig {
                strategy: "suspicious_process_tree".to_string(),
                high_confidence_threshold: 0.9,
                medium_confidence_threshold: 0.7,
            },
            pheromone: PheromoneConfig {
                default_half_life_secs: 3600.0,
                evaporation_threshold: 0.01,
                min_sources_for_escalation: 2,
                alert_threshold: 2.0,
                incident_threshold: 5.0,
                backend: PheromoneBackendConfig::InMemory,
            },
            policy: PolicyConfig {
                human_gate_severity: Severity::High,
                lease_ttl_ms: 60_000,
            },
            audit: AuditConfig {
                bundle_store: BundleStoreConfig::Memory,
                recent_decisions_limit: 20,
            },
            investigation: InvestigationConfig::default(),
            correlation: CorrelationConfig::default(),
            canary: CanaryConfig {
                enabled: true,
                slot_id: "canary-primary".to_string(),
                observation_window_events: 2,
                max_candidate_only_rate: 0.0,
                max_baseline_miss_rate: 0.0,
                max_detect_latency_us: 10_000,
                max_total_detections: 4,
            },
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
            lineage: manifest.lineage.clone(),
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
            lineage: manifest.lineage.clone(),
            baseline_strategy_id: "suspicious_process_tree".to_string(),
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
            }),
        }
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
