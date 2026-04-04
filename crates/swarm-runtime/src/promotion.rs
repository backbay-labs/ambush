use crate::canary::{
    CanaryRecommendation, CanaryRunReport, CanaryRunStatus, CanaryStoreError, FileCanaryStore,
};
use crate::config::{RuntimeConfigError, load_config};
use crate::replay::{DetectorCandidateManifest, ExperimentLineage};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use swarm_core::config::{PromotionConfig, SwarmConfig};
use swarm_core::types::Severity;
use swarm_whisker::stream::{evaluate_event, findings_to_deposits};
use swarm_whisker::{
    DetectionFinding, DetectionStrategy, SuspiciousProcessTreeDetector, TelemetryEvent,
};

/// Errors surfaced by the controlled production-promotion lane.
#[derive(Debug, thiserror::Error)]
pub enum ProductionPromotionError {
    #[error(transparent)]
    Config(#[from] RuntimeConfigError),

    #[error(transparent)]
    CanaryStore(#[from] CanaryStoreError),

    #[error(transparent)]
    Store(#[from] ProductionPromotionStoreError),

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

    #[error("controlled production promotion is disabled in the repo-owned config")]
    Disabled,

    #[error("canary run `{run_id}` was not found")]
    CanaryNotFound { run_id: String },

    #[error(
        "canary run `{run_id}` is not ready for production promotion (status `{status:?}`, recommendation `{recommendation:?}`)"
    )]
    CanaryNotReady {
        run_id: String,
        status: CanaryRunStatus,
        recommendation: CanaryRecommendation,
    },

    #[error("canary baseline mismatch: expected current production `{expected}`, found `{actual}`")]
    BaselineMismatch { expected: String, actual: String },

    #[error(
        "an active production promotion already exists for window `{window_id}`: `{promotion_id}`"
    )]
    ActiveRunExists {
        window_id: String,
        promotion_id: String,
    },

    #[error("production promotion `{promotion_id}` was not found")]
    RunNotFound { promotion_id: String },

    #[error("production promotion `{promotion_id}` is not active (status `{status:?}`)")]
    RunNotActive {
        promotion_id: String,
        status: ProductionPromotionStatus,
    },

    #[error("unsupported detector strategy `{strategy}`")]
    UnsupportedDetector { strategy: String },
}

/// Errors raised by the persisted production-promotion store.
#[derive(Debug, thiserror::Error)]
pub enum ProductionPromotionStoreError {
    #[error("failed to read production promotion store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write production promotion store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse production promotion store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Runtime status for one production-promotion run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionPromotionStatus {
    Active,
    Completed,
    RolledBack,
    Halted,
}

/// Final operator recommendation for one production-promotion run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionPromotionRecommendation {
    Observing,
    StableInProduction,
    Blocked,
}

/// Automatic or manual source of one production rollback-like action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionPromotionRollbackTrigger {
    AutomaticThreshold,
    AutomaticBudget,
    ManualHalt,
    ManualRollback,
}

/// One persisted rollback or halt event for a production promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionPromotionRollbackRecord {
    pub trigger: ProductionPromotionRollbackTrigger,
    pub reason: String,
    pub occurred_at_ms: i64,
    pub window_id: String,
    pub restored_baseline_strategy_id: String,
    pub observed_events: usize,
}

/// One threshold verdict preserved in the production-promotion artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProductionPromotionThresholdResult {
    pub name: String,
    pub passed: bool,
    pub expected: serde_json::Value,
    pub actual: serde_json::Value,
    pub details: String,
}

/// One recent promoted finding preserved for operator inspection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProductionPromotionFindingPreview {
    pub event_id: String,
    pub strategy_id: String,
    pub severity: Severity,
    pub confidence: f64,
    pub shared_with_fallback: bool,
}

/// Aggregate metrics recorded over the production observation window.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProductionPromotionMetrics {
    pub total_events: usize,
    pub fallback_detections: usize,
    pub promoted_detections: usize,
    pub shared_detections: usize,
    pub promoted_only_detections: usize,
    pub fallback_only_detections: usize,
    pub promoted_only_rate: f64,
    pub fallback_recovery_rate: f64,
    pub total_fallback_detect_latency_us: u64,
    pub average_fallback_detect_latency_us: u64,
    pub max_fallback_detect_latency_us: u64,
    pub total_promoted_detect_latency_us: u64,
    pub average_promoted_detect_latency_us: u64,
    pub max_promoted_detect_latency_us: u64,
    pub total_promoted_deposits: usize,
}

impl ProductionPromotionMetrics {
    fn observe(
        &mut self,
        fallback_findings: &[DetectionFinding],
        promoted_findings: &[DetectionFinding],
        fallback_latency_us: u64,
        promoted_latency_us: u64,
        promoted_deposit_count: usize,
    ) {
        self.total_events = self.total_events.saturating_add(1);
        self.total_fallback_detect_latency_us = self
            .total_fallback_detect_latency_us
            .saturating_add(fallback_latency_us);
        self.total_promoted_detect_latency_us = self
            .total_promoted_detect_latency_us
            .saturating_add(promoted_latency_us);
        self.max_fallback_detect_latency_us =
            self.max_fallback_detect_latency_us.max(fallback_latency_us);
        self.max_promoted_detect_latency_us =
            self.max_promoted_detect_latency_us.max(promoted_latency_us);
        self.average_fallback_detect_latency_us =
            self.total_fallback_detect_latency_us / self.total_events as u64;
        self.average_promoted_detect_latency_us =
            self.total_promoted_detect_latency_us / self.total_events as u64;
        self.total_promoted_deposits = self
            .total_promoted_deposits
            .saturating_add(promoted_deposit_count);

        let fallback_detected = !fallback_findings.is_empty();
        let promoted_detected = !promoted_findings.is_empty();
        if fallback_detected {
            self.fallback_detections = self.fallback_detections.saturating_add(1);
        }
        if promoted_detected {
            self.promoted_detections = self.promoted_detections.saturating_add(1);
        }
        if fallback_detected && promoted_detected {
            self.shared_detections = self.shared_detections.saturating_add(1);
        } else if promoted_detected {
            self.promoted_only_detections = self.promoted_only_detections.saturating_add(1);
        } else if fallback_detected {
            self.fallback_only_detections = self.fallback_only_detections.saturating_add(1);
        }

        self.promoted_only_rate = if self.total_events == 0 {
            0.0
        } else {
            self.promoted_only_detections as f64 / self.total_events as f64
        };
        self.fallback_recovery_rate = if self.fallback_detections == 0 {
            0.0
        } else {
            self.fallback_only_detections as f64 / self.fallback_detections as f64
        };
    }
}

/// Stable assignment details for one production-promotion run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductionPromotionAssignment {
    pub canary_run_id: String,
    pub canary_report: CanaryRunReport,
    pub experiment_id: String,
    pub experiment_name: String,
    pub suite_name: String,
    pub corpus_version: String,
    pub previous_production_strategy_id: String,
    pub promoted_strategy_id: String,
    pub promoted_description: String,
    pub previous_production_candidate: DetectorCandidateManifest,
    pub promoted_candidate: DetectorCandidateManifest,
    pub lineage: ExperimentLineage,
    pub promotion: PromotionConfig,
}

/// Persisted production-promotion artifact exposed to operators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductionPromotionReport {
    pub promotion_id: String,
    pub window_id: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub status: ProductionPromotionStatus,
    pub recommendation: ProductionPromotionRecommendation,
    pub assignment: ProductionPromotionAssignment,
    pub metrics: ProductionPromotionMetrics,
    pub threshold_results: Vec<ProductionPromotionThresholdResult>,
    pub recent_promoted_findings: Vec<ProductionPromotionFindingPreview>,
    pub rollback_history: Vec<ProductionPromotionRollbackRecord>,
}

/// Metadata surfaced for one persisted production-promotion run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionPromotionRecord {
    pub promotion_id: String,
    pub window_id: String,
    pub canary_run_id: String,
    pub promoted_strategy_id: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub status: ProductionPromotionStatus,
    pub recommendation: ProductionPromotionRecommendation,
    pub bundle_path: String,
}

impl ProductionPromotionRecord {
    fn from_report(report: &ProductionPromotionReport, bundle_path: String) -> Self {
        Self {
            promotion_id: report.promotion_id.clone(),
            window_id: report.window_id.clone(),
            canary_run_id: report.assignment.canary_run_id.clone(),
            promoted_strategy_id: report.assignment.promoted_strategy_id.clone(),
            created_at_ms: report.created_at_ms,
            updated_at_ms: report.updated_at_ms,
            status: report.status,
            recommendation: report.recommendation,
            bundle_path,
        }
    }
}

/// Persisted production promotion loaded with metadata.
#[derive(Debug, Clone)]
pub struct ProductionPromotionLookup {
    pub record: ProductionPromotionRecord,
    pub report: ProductionPromotionReport,
}

/// File-backed store used for controlled production-promotion runs.
#[derive(Debug, Clone)]
pub struct FileProductionPromotionStore {
    root: PathBuf,
}

impl FileProductionPromotionStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ProductionPromotionStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            ProductionPromotionStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, promotion_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(promotion_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<ProductionPromotionIndex, ProductionPromotionStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(ProductionPromotionIndex::default());
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| ProductionPromotionStoreError::Read {
                path: path.clone(),
                source,
            })?;
        serde_json::from_str(&raw)
            .map_err(|source| ProductionPromotionStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &ProductionPromotionIndex,
    ) -> Result<(), ProductionPromotionStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            ProductionPromotionStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| ProductionPromotionStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &ProductionPromotionReport,
    ) -> Result<ProductionPromotionRecord, ProductionPromotionStoreError> {
        let path = self.report_path(&report.promotion_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            ProductionPromotionStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| ProductionPromotionStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = ProductionPromotionRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.promotion_id != record.promotion_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.updated_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        promotion_id: &str,
    ) -> Result<Option<ProductionPromotionLookup>, ProductionPromotionStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.promotion_id == promotion_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw =
            fs::read_to_string(&path).map_err(|source| ProductionPromotionStoreError::Read {
                path: path.clone(),
                source,
            })?;
        let report =
            serde_json::from_str(&raw).map_err(|source| ProductionPromotionStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        Ok(Some(ProductionPromotionLookup { record, report }))
    }

    pub fn load_active(
        &self,
        window_id: &str,
    ) -> Result<Option<ProductionPromotionLookup>, ProductionPromotionStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| {
                entry.window_id == window_id && entry.status == ProductionPromotionStatus::Active
            })
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw =
            fs::read_to_string(&path).map_err(|source| ProductionPromotionStoreError::Read {
                path: path.clone(),
                source,
            })?;
        let report =
            serde_json::from_str(&raw).map_err(|source| ProductionPromotionStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        Ok(Some(ProductionPromotionLookup { record, report }))
    }
}

/// Runtime-side production-promotion harness built from repo-owned config.
pub struct DefaultProductionPromotionHarness {
    pub config_path: PathBuf,
    pub config: SwarmConfig,
    pub store: FileProductionPromotionStore,
}

impl DefaultProductionPromotionHarness {
    pub fn from_path(
        config_path: impl AsRef<Path>,
        results_dir: impl AsRef<Path>,
    ) -> Result<Self, ProductionPromotionError> {
        let config_path = config_path.as_ref();
        let config = load_config(config_path)?;
        Self::from_config(config_path, config, results_dir)
    }

    pub fn from_config(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
        results_dir: impl AsRef<Path>,
    ) -> Result<Self, ProductionPromotionError> {
        let store = FileProductionPromotionStore::open(results_dir)?;
        Ok(Self {
            config_path: config_path.into(),
            config,
            store,
        })
    }

    pub fn start_run(
        &self,
        canary_results_dir: impl AsRef<Path>,
        canary_run_id: &str,
    ) -> Result<ProductionPromotionLookup, ProductionPromotionError> {
        if !self.config.promotion.enabled {
            return Err(ProductionPromotionError::Disabled);
        }

        if let Some(active) = self.store.load_active(&self.config.promotion.window_id)? {
            return Err(ProductionPromotionError::ActiveRunExists {
                window_id: self.config.promotion.window_id.clone(),
                promotion_id: active.record.promotion_id,
            });
        }

        let canary_store = FileCanaryStore::open(canary_results_dir)?;
        let canary = canary_store.load(canary_run_id)?.ok_or_else(|| {
            ProductionPromotionError::CanaryNotFound {
                run_id: canary_run_id.to_string(),
            }
        })?;
        if canary.report.status != CanaryRunStatus::Completed
            || canary.report.recommendation != CanaryRecommendation::ReadyForPromotionReview
        {
            return Err(ProductionPromotionError::CanaryNotReady {
                run_id: canary_run_id.to_string(),
                status: canary.report.status,
                recommendation: canary.report.recommendation,
            });
        }

        if canary.report.assignment.baseline_strategy_id != self.config.detection.strategy {
            return Err(ProductionPromotionError::BaselineMismatch {
                expected: self.config.detection.strategy.clone(),
                actual: canary.report.assignment.baseline_strategy_id.clone(),
            });
        }

        let now_ms = now_ms();
        let previous_production_candidate = baseline_candidate_from_config(&self.config)?;
        let assignment = ProductionPromotionAssignment {
            canary_run_id: canary.report.run_id.clone(),
            canary_report: canary.report.clone(),
            experiment_id: canary.report.assignment.experiment_id.clone(),
            experiment_name: canary.report.assignment.experiment_name.clone(),
            suite_name: canary.report.assignment.suite_name.clone(),
            corpus_version: canary.report.assignment.corpus_version.clone(),
            previous_production_strategy_id: canary.report.assignment.baseline_strategy_id.clone(),
            promoted_strategy_id: canary.report.assignment.candidate_strategy_id.clone(),
            promoted_description: canary.report.assignment.candidate_description.clone(),
            previous_production_candidate,
            promoted_candidate: canary.report.assignment.candidate.clone(),
            lineage: canary.report.assignment.lineage.clone(),
            promotion: self.config.promotion.clone(),
        };
        let promotion_id =
            production_promotion_id(&self.config.promotion.window_id, &assignment, now_ms);
        let threshold_results = evaluate_thresholds(
            &ProductionPromotionMetrics::default(),
            &assignment.promotion,
        );
        let report = ProductionPromotionReport {
            promotion_id,
            window_id: self.config.promotion.window_id.clone(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            status: ProductionPromotionStatus::Active,
            recommendation: ProductionPromotionRecommendation::Observing,
            assignment,
            metrics: ProductionPromotionMetrics::default(),
            threshold_results,
            recent_promoted_findings: Vec::new(),
            rollback_history: Vec::new(),
        };
        let record = self.store.persist(&report)?;
        Ok(ProductionPromotionLookup { record, report })
    }

    pub fn ingest_event_path(
        &self,
        promotion_id: &str,
        event_path: impl AsRef<Path>,
    ) -> Result<ProductionPromotionLookup, ProductionPromotionError> {
        let event_path = event_path.as_ref().to_path_buf();
        let raw = fs::read_to_string(&event_path).map_err(|source| {
            ProductionPromotionError::EventRead {
                path: event_path.clone(),
                source,
            }
        })?;
        let event = serde_yaml::from_str::<TelemetryEvent>(&raw).map_err(|source| {
            ProductionPromotionError::EventParse {
                path: event_path.clone(),
                source,
            }
        })?;
        self.ingest_event(promotion_id, &event)
    }

    pub fn ingest_event(
        &self,
        promotion_id: &str,
        event: &TelemetryEvent,
    ) -> Result<ProductionPromotionLookup, ProductionPromotionError> {
        let mut lookup = self.store.load(promotion_id)?.ok_or_else(|| {
            ProductionPromotionError::RunNotFound {
                promotion_id: promotion_id.to_string(),
            }
        })?;
        if lookup.report.status != ProductionPromotionStatus::Active {
            return Err(ProductionPromotionError::RunNotActive {
                promotion_id: promotion_id.to_string(),
                status: lookup.report.status,
            });
        }

        let fallback =
            detector_from_candidate(&lookup.report.assignment.previous_production_candidate)?;
        let promoted = detector_from_candidate(&lookup.report.assignment.promoted_candidate)?;

        let fallback_started = Instant::now();
        let fallback_findings = evaluate_event(&fallback, event);
        let fallback_latency_us = fallback_started.elapsed().as_micros() as u64;

        let promoted_started = Instant::now();
        let promoted_findings = evaluate_event(&promoted, event);
        let promoted_latency_us = promoted_started.elapsed().as_micros() as u64;

        let promoted_deposits = findings_to_deposits(
            &promoted_findings,
            event,
            &swarm_core::types::AgentId(format!("production:{}", lookup.report.window_id)),
            &self.config.pheromone,
        );

        lookup.report.metrics.observe(
            &fallback_findings,
            &promoted_findings,
            fallback_latency_us,
            promoted_latency_us,
            promoted_deposits.len(),
        );
        append_recent_promoted_findings(
            &mut lookup.report.recent_promoted_findings,
            &promoted_findings,
            !fallback_findings.is_empty(),
        );

        lookup.report.threshold_results =
            evaluate_thresholds(&lookup.report.metrics, &lookup.report.assignment.promotion);
        lookup.report.updated_at_ms = now_ms();

        if let Some(failure) = lookup
            .report
            .threshold_results
            .iter()
            .find(|result| !result.passed)
        {
            let trigger = rollback_trigger_for_threshold(&failure.name);
            lookup.report.status = ProductionPromotionStatus::RolledBack;
            lookup.report.recommendation = ProductionPromotionRecommendation::Blocked;
            lookup
                .report
                .rollback_history
                .push(ProductionPromotionRollbackRecord {
                    trigger,
                    reason: failure.details.clone(),
                    occurred_at_ms: lookup.report.updated_at_ms,
                    window_id: lookup.report.window_id.clone(),
                    restored_baseline_strategy_id: lookup
                        .report
                        .assignment
                        .previous_production_strategy_id
                        .clone(),
                    observed_events: lookup.report.metrics.total_events,
                });
        } else if lookup.report.metrics.total_events
            >= lookup.report.assignment.promotion.observation_window_events
        {
            lookup.report.status = ProductionPromotionStatus::Completed;
            lookup.report.recommendation = ProductionPromotionRecommendation::StableInProduction;
        } else {
            lookup.report.status = ProductionPromotionStatus::Active;
            lookup.report.recommendation = ProductionPromotionRecommendation::Observing;
        }

        lookup.record = self.store.persist(&lookup.report)?;
        Ok(lookup)
    }

    pub fn halt_run(
        &self,
        promotion_id: &str,
        reason: &str,
    ) -> Result<ProductionPromotionLookup, ProductionPromotionError> {
        self.finalize_run(
            promotion_id,
            reason,
            ProductionPromotionStatus::Halted,
            ProductionPromotionRollbackTrigger::ManualHalt,
        )
    }

    pub fn rollback_run(
        &self,
        promotion_id: &str,
        reason: &str,
    ) -> Result<ProductionPromotionLookup, ProductionPromotionError> {
        self.finalize_run(
            promotion_id,
            reason,
            ProductionPromotionStatus::RolledBack,
            ProductionPromotionRollbackTrigger::ManualRollback,
        )
    }

    pub fn load_run(
        &self,
        promotion_id: &str,
    ) -> Result<Option<ProductionPromotionLookup>, ProductionPromotionError> {
        Ok(self.store.load(promotion_id)?)
    }

    fn finalize_run(
        &self,
        promotion_id: &str,
        reason: &str,
        status: ProductionPromotionStatus,
        trigger: ProductionPromotionRollbackTrigger,
    ) -> Result<ProductionPromotionLookup, ProductionPromotionError> {
        let mut lookup = self.store.load(promotion_id)?.ok_or_else(|| {
            ProductionPromotionError::RunNotFound {
                promotion_id: promotion_id.to_string(),
            }
        })?;
        if lookup.report.status != ProductionPromotionStatus::Active {
            return Err(ProductionPromotionError::RunNotActive {
                promotion_id: promotion_id.to_string(),
                status: lookup.report.status,
            });
        }

        lookup.report.status = status;
        lookup.report.recommendation = ProductionPromotionRecommendation::Blocked;
        lookup.report.updated_at_ms = now_ms();
        lookup
            .report
            .rollback_history
            .push(ProductionPromotionRollbackRecord {
                trigger,
                reason: reason.to_string(),
                occurred_at_ms: lookup.report.updated_at_ms,
                window_id: lookup.report.window_id.clone(),
                restored_baseline_strategy_id: lookup
                    .report
                    .assignment
                    .previous_production_strategy_id
                    .clone(),
                observed_events: lookup.report.metrics.total_events,
            });
        lookup.record = self.store.persist(&lookup.report)?;
        Ok(lookup)
    }
}

pub fn render_production_promotion_report(report: &ProductionPromotionReport) -> String {
    let mut lines = vec![
        "Production Promotion Run".to_string(),
        format!("Promotion ID: {}", report.promotion_id),
        format!("Window: {}", report.window_id),
        format!("Status: {:?}", report.status),
        format!("Recommendation: {:?}", report.recommendation),
        format!(
            "Rollback target: {} | Promoted: {}",
            report.assignment.previous_production_strategy_id,
            report.assignment.promoted_strategy_id
        ),
        format!(
            "Canary handoff: {} | status={:?} | recommendation={:?}",
            report.assignment.canary_run_id,
            report.assignment.canary_report.status,
            report.assignment.canary_report.recommendation
        ),
        format!(
            "Observed events: {} / {}",
            report.metrics.total_events, report.assignment.promotion.observation_window_events
        ),
        format!(
            "Detections: fallback={} promoted={} shared={}",
            report.metrics.fallback_detections,
            report.metrics.promoted_detections,
            report.metrics.shared_detections
        ),
        format!(
            "Divergence: promoted_only={} rate={:.2}",
            report.metrics.promoted_only_detections, report.metrics.promoted_only_rate
        ),
        format!(
            "Fallback recovery: {} rate={:.2}",
            report.metrics.fallback_only_detections, report.metrics.fallback_recovery_rate
        ),
        format!(
            "Latency us: fallback_avg={} promoted_avg={} promoted_max={}",
            report.metrics.average_fallback_detect_latency_us,
            report.metrics.average_promoted_detect_latency_us,
            report.metrics.max_promoted_detect_latency_us
        ),
        format!(
            "Promoted detection volume: {}",
            report.metrics.total_promoted_deposits
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
                "- {:?} at {} | reason={} | restored_baseline={} | observed_events={}",
                rollback.trigger,
                rollback.occurred_at_ms,
                rollback.reason,
                rollback.restored_baseline_strategy_id,
                rollback.observed_events
            ));
        }
    }

    if report.recent_promoted_findings.is_empty() {
        lines.push("Recent promoted findings: none".to_string());
    } else {
        lines.push("Recent promoted findings:".to_string());
        for finding in &report.recent_promoted_findings {
            lines.push(format!(
                "- {} via {} severity={:?} confidence={:.2} shared_with_fallback={}",
                finding.event_id,
                finding.strategy_id,
                finding.severity,
                finding.confidence,
                finding.shared_with_fallback
            ));
        }
    }

    lines.join("\n")
}

#[derive(Debug, Clone)]
enum SupportedPromotionDetector {
    SuspiciousProcessTree {
        strategy_id: String,
        detector: SuspiciousProcessTreeDetector,
    },
}

impl DetectionStrategy for SupportedPromotionDetector {
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

impl SupportedPromotionDetector {
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

fn baseline_candidate_from_config(
    config: &SwarmConfig,
) -> Result<DetectorCandidateManifest, ProductionPromotionError> {
    match config.detection.strategy.as_str() {
        "suspicious_process_tree" => Ok(DetectorCandidateManifest::SuspiciousProcessTree {
            strategy_id: config.detection.strategy.clone(),
            description: "production baseline at promotion start".to_string(),
            profile: swarm_whisker::SuspiciousProcessTreeProfile {
                high_confidence_threshold: config.detection.high_confidence_threshold,
                medium_confidence_threshold: config.detection.medium_confidence_threshold,
                ..swarm_whisker::SuspiciousProcessTreeProfile::default()
            },
        }),
        other => Err(ProductionPromotionError::UnsupportedDetector {
            strategy: other.to_string(),
        }),
    }
}

fn detector_from_candidate(
    candidate: &DetectorCandidateManifest,
) -> Result<SupportedPromotionDetector, ProductionPromotionError> {
    match candidate {
        DetectorCandidateManifest::SuspiciousProcessTree {
            strategy_id,
            profile,
            ..
        } => Ok(SupportedPromotionDetector::suspicious_process_tree(
            strategy_id.clone(),
            profile.clone(),
        )),
    }
}

fn evaluate_thresholds(
    metrics: &ProductionPromotionMetrics,
    config: &PromotionConfig,
) -> Vec<ProductionPromotionThresholdResult> {
    vec![
        float_threshold(
            "promoted_only_rate",
            config.max_promoted_only_rate,
            metrics.promoted_only_rate,
            "promoted-only detection rate stayed within the configured bound",
            "promoted-only detection rate exceeded the configured bound",
        ),
        float_threshold(
            "fallback_recovery_rate",
            config.max_fallback_recovery_rate,
            metrics.fallback_recovery_rate,
            "fallback recovery rate stayed within the configured bound",
            "fallback recovery rate exceeded the configured bound",
        ),
        int_threshold(
            "detect_latency_threshold",
            config.max_detect_latency_us as u128,
            metrics.max_promoted_detect_latency_us as u128,
            "promoted detect latency stayed within the configured bound",
            "promoted detect latency exceeded the configured bound",
        ),
        int_threshold(
            "total_detection_budget",
            config.max_total_detections as u128,
            metrics.total_promoted_deposits as u128,
            "promoted detection volume stayed within the configured budget",
            "promoted detection volume exceeded the configured budget",
        ),
    ]
}

fn float_threshold(
    name: &str,
    expected: f64,
    actual: f64,
    success_details: &str,
    failure_details: &str,
) -> ProductionPromotionThresholdResult {
    let passed = actual <= expected;
    ProductionPromotionThresholdResult {
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
) -> ProductionPromotionThresholdResult {
    let passed = actual <= expected;
    ProductionPromotionThresholdResult {
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

fn append_recent_promoted_findings(
    previews: &mut Vec<ProductionPromotionFindingPreview>,
    findings: &[DetectionFinding],
    shared_with_fallback: bool,
) {
    for finding in findings {
        previews.push(ProductionPromotionFindingPreview {
            event_id: finding.event_id.clone(),
            strategy_id: finding.strategy_id.clone(),
            severity: finding.severity,
            confidence: finding.confidence,
            shared_with_fallback,
        });
    }
    if previews.len() > 10 {
        let drop_count = previews.len() - 10;
        previews.drain(0..drop_count);
    }
}

fn rollback_trigger_for_threshold(name: &str) -> ProductionPromotionRollbackTrigger {
    match name {
        "total_detection_budget" => ProductionPromotionRollbackTrigger::AutomaticBudget,
        _ => ProductionPromotionRollbackTrigger::AutomaticThreshold,
    }
}

fn production_promotion_id(
    window_id: &str,
    assignment: &ProductionPromotionAssignment,
    started_at_ms: i64,
) -> String {
    format!(
        "promotion:{}:{}:{}",
        window_id, assignment.promoted_strategy_id, started_at_ms
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
struct ProductionPromotionIndex {
    entries: Vec<ProductionPromotionRecord>,
}

#[cfg(test)]
mod tests {
    use super::{
        DefaultProductionPromotionHarness, ProductionPromotionRecommendation,
        ProductionPromotionRollbackTrigger, ProductionPromotionStatus,
        render_production_promotion_report,
    };
    use crate::canary::{
        CanaryAssignment, CanaryRecommendation, CanaryRunReport, CanaryRunStatus, FileCanaryStore,
    };
    use crate::config::RuntimeMode;
    use crate::replay::{DetectorCandidateManifest, ExperimentLineage};
    use std::fs;
    use std::path::PathBuf;
    use swarm_core::config::{
        AuditConfig, BundleStoreConfig, CanaryConfig, CorrelationConfig, DetectionConfig,
        InvestigationConfig, PheromoneBackendConfig, PheromoneConfig, PolicyConfig,
        PromotionConfig, RuntimeSettings, SwarmConfig, TelemetrySourceConfig,
    };
    use swarm_core::types::Severity;
    use swarm_whisker::{
        ProcessStartEvent, SuspiciousProcessTreeProfile, TelemetryEvent, TelemetryPayload,
    };

    fn unique_temp_dir(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "swarm-runtime-promotion-{label}-{}",
            std::process::id()
        ));
        if root.exists() {
            let _ = fs::remove_dir_all(&root);
        }
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn promotion_config() -> SwarmConfig {
        SwarmConfig {
            name: "promotion-test".to_string(),
            description: "production promotion test config".to_string(),
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
            promotion: PromotionConfig {
                enabled: true,
                window_id: "production-primary".to_string(),
                observation_window_events: 2,
                max_promoted_only_rate: 0.0,
                max_fallback_recovery_rate: 0.0,
                max_detect_latency_us: 10_000,
                max_total_detections: 4,
            },
            operator: swarm_core::config::OperatorSurfaceConfig::default(),
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

    fn ready_canary_report(
        config: &SwarmConfig,
        candidate: DetectorCandidateManifest,
    ) -> CanaryRunReport {
        CanaryRunReport {
            run_id: format!(
                "canary:canary-primary:{}:1700000000000",
                candidate.strategy_id()
            ),
            slot_id: config.canary.slot_id.clone(),
            created_at_ms: 1_700_000_000_000,
            updated_at_ms: 1_700_000_000_100,
            status: CanaryRunStatus::Completed,
            recommendation: CanaryRecommendation::ReadyForPromotionReview,
            assignment: CanaryAssignment {
                experiment_id: format!("experiment:test:{}", candidate.strategy_id()),
                experiment_name: "test".to_string(),
                experiment_path: "experiments/test.yaml".to_string(),
                suite_name: "hellcat_office_v1".to_string(),
                corpus_version: "2026-04-03".to_string(),
                baseline_strategy_id: config.detection.strategy.clone(),
                candidate_strategy_id: candidate.strategy_id().to_string(),
                candidate_description: candidate.description().to_string(),
                candidate: candidate.clone(),
                lineage: ExperimentLineage {
                    parent_strategy_id: config.detection.strategy.clone(),
                    mutation: "test".to_string(),
                    rationale: "test rationale".to_string(),
                },
                verification_id: format!("verification:test:{}", candidate.strategy_id()),
                verification_passed: true,
                shadow_id: format!("shadow:test:{}", candidate.strategy_id()),
                shadow_passed: true,
                canary: config.canary.clone(),
            },
            metrics: Default::default(),
            threshold_results: Vec::new(),
            recent_candidate_findings: Vec::new(),
            rollback_history: Vec::new(),
        }
    }

    fn persist_ready_canary(root: &PathBuf, report: &CanaryRunReport) -> (PathBuf, String) {
        let canaries_dir = root.join("canaries");
        let store = FileCanaryStore::open(&canaries_dir).unwrap();
        let record = store.persist(report).unwrap();
        (canaries_dir, record.run_id)
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
    fn promotion_run_starts_from_ready_canary() {
        let root = unique_temp_dir("start");
        let results_dir = root.join("promotions");
        let config = promotion_config();
        let ready_canary = ready_canary_report(&config, control_candidate());
        let (canaries_dir, canary_run_id) = persist_ready_canary(&root, &ready_canary);

        let harness = DefaultProductionPromotionHarness::from_config(
            "rulesets/default.yaml",
            config,
            &results_dir,
        )
        .unwrap();
        let lookup = harness.start_run(&canaries_dir, &canary_run_id).unwrap();

        assert_eq!(lookup.report.status, ProductionPromotionStatus::Active);
        assert_eq!(
            lookup.report.recommendation,
            ProductionPromotionRecommendation::Observing
        );
        assert_eq!(
            lookup.report.assignment.previous_production_strategy_id,
            "suspicious_process_tree"
        );
        assert_eq!(
            lookup.report.assignment.promoted_strategy_id,
            "office_baseline_control"
        );
    }

    #[test]
    fn promotion_control_candidate_completes_after_window() {
        let root = unique_temp_dir("complete");
        let results_dir = root.join("promotions");
        let config = promotion_config();
        let ready_canary = ready_canary_report(&config, control_candidate());
        let (canaries_dir, canary_run_id) = persist_ready_canary(&root, &ready_canary);

        let harness = DefaultProductionPromotionHarness::from_config(
            "rulesets/default.yaml",
            config,
            &results_dir,
        )
        .unwrap();
        let started = harness.start_run(&canaries_dir, &canary_run_id).unwrap();

        let after_first = harness
            .ingest_event(
                &started.record.promotion_id,
                &suspicious_event("evt-promotion-1"),
            )
            .unwrap();
        assert_eq!(after_first.report.status, ProductionPromotionStatus::Active);

        let completed = harness
            .ingest_event(
                &started.record.promotion_id,
                &suspicious_event("evt-promotion-2"),
            )
            .unwrap();
        assert_eq!(
            completed.report.status,
            ProductionPromotionStatus::Completed
        );
        assert_eq!(
            completed.report.recommendation,
            ProductionPromotionRecommendation::StableInProduction
        );
        assert!(
            render_production_promotion_report(&completed.report)
                .contains("Production Promotion Run")
        );
    }

    #[test]
    fn promotion_auto_rollback_triggers_on_promoted_only_detection() {
        let root = unique_temp_dir("rollback");
        let results_dir = root.join("promotions");
        let config = promotion_config();
        let ready_canary = ready_canary_report(&config, broadened_candidate());
        let (canaries_dir, canary_run_id) = persist_ready_canary(&root, &ready_canary);

        let harness = DefaultProductionPromotionHarness::from_config(
            "rulesets/default.yaml",
            config,
            &results_dir,
        )
        .unwrap();
        let started = harness.start_run(&canaries_dir, &canary_run_id).unwrap();

        let rolled_back = harness
            .ingest_event(
                &started.record.promotion_id,
                &benign_python_event("evt-promotion-python"),
            )
            .unwrap();
        assert_eq!(
            rolled_back.report.status,
            ProductionPromotionStatus::RolledBack
        );
        assert_eq!(
            rolled_back.report.recommendation,
            ProductionPromotionRecommendation::Blocked
        );
        assert_eq!(rolled_back.report.rollback_history.len(), 1);
        assert_eq!(
            rolled_back.report.rollback_history[0].trigger,
            ProductionPromotionRollbackTrigger::AutomaticThreshold
        );
        assert!(
            rolled_back
                .report
                .threshold_results
                .iter()
                .any(|result| result.name == "promoted_only_rate" && !result.passed)
        );
    }

    #[test]
    fn promotion_manual_halt_records_reason() {
        let root = unique_temp_dir("halt");
        let results_dir = root.join("promotions");
        let config = promotion_config();
        let ready_canary = ready_canary_report(&config, control_candidate());
        let (canaries_dir, canary_run_id) = persist_ready_canary(&root, &ready_canary);

        let harness = DefaultProductionPromotionHarness::from_config(
            "rulesets/default.yaml",
            config,
            &results_dir,
        )
        .unwrap();
        let started = harness.start_run(&canaries_dir, &canary_run_id).unwrap();

        let halted = harness
            .halt_run(&started.record.promotion_id, "operator requested stop")
            .unwrap();
        assert_eq!(halted.report.status, ProductionPromotionStatus::Halted);
        assert_eq!(halted.report.rollback_history.len(), 1);
        assert_eq!(
            halted.report.rollback_history[0].trigger,
            ProductionPromotionRollbackTrigger::ManualHalt
        );
        assert_eq!(
            halted.report.rollback_history[0].reason,
            "operator requested stop"
        );
    }
}
