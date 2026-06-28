use crate::canary::{
    CanaryRecommendation, CanaryRunReport, CanaryRunStatus, CanaryStoreError, FileCanaryStore,
};
use crate::config::{RuntimeConfigError, load_config};
use crate::promotion::{
    FileProductionPromotionStore, ProductionPromotionRecommendation, ProductionPromotionStatus,
    ProductionPromotionStoreError,
};
use crate::replay::{
    DefaultReplayHarness, DetectorVerificationLookup, ExperimentLineage, ReplayHarnessError,
    StrategyExperimentMetrics, StrategyExperimentReport, VerificationStoreError,
    load_detector_experiment_manifest,
};
use crate::replay::{FileVerificationStore, StrategyExperimentLookup};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::SwarmConfig;

const CANARY_STAGE_WEIGHT: f64 = 0.75;
const PROMOTION_STAGE_WEIGHT: f64 = 1.00;
const CANARY_READY_OUTCOME_WEIGHT: f64 = 0.60;
const CANARY_BLOCKED_OUTCOME_WEIGHT: f64 = -0.75;
const CANARY_HALTED_OUTCOME_WEIGHT: f64 = -0.50;
const PROMOTION_STABLE_OUTCOME_WEIGHT: f64 = 1.00;
const PROMOTION_BLOCKED_OUTCOME_WEIGHT: f64 = -1.00;
const PROMOTION_HALTED_OUTCOME_WEIGHT: f64 = -0.60;
const MIN_LIVE_MEMORIES: usize = 2;
pub const RECENCY_HALF_LIFE_HOURS: f64 = 168.0;
const BASE_CONTEXT_RELEVANCE: f64 = 0.25;
const SUITE_MATCH_BONUS: f64 = 0.30;
const CORPUS_MATCH_BONUS: f64 = 0.20;
const REFERENCE_MATCH_BONUS: f64 = 0.15;
const PARENT_MATCH_BONUS: f64 = 0.10;
const SCORE_RECOMMENDATION_EPSILON: f64 = 0.05;
const LATENCY_PENALTY_CAP_US: f64 = 10_000.0;

/// Errors surfaced by the strategy-memory and advisory-scoring flows.
#[derive(Debug, thiserror::Error)]
pub enum StrategyAdvisorError {
    #[error(transparent)]
    Config(#[from] RuntimeConfigError),

    #[error(transparent)]
    Replay(#[from] ReplayHarnessError),

    #[error(transparent)]
    CanaryStore(#[from] CanaryStoreError),

    #[error(transparent)]
    PromotionStore(#[from] ProductionPromotionStoreError),

    #[error(transparent)]
    VerificationStore(#[from] VerificationStoreError),

    #[error(transparent)]
    MemoryStore(#[from] StrategyMemoryStoreError),

    #[error(transparent)]
    ScorecardStore(#[from] StrategyScorecardStoreError),

    #[error("canary run `{run_id}` was not found")]
    CanaryNotFound { run_id: String },

    #[error("canary run `{run_id}` is still active and cannot produce a durable memory yet")]
    CanaryNotFinalized { run_id: String },

    #[error("production promotion `{promotion_id}` was not found")]
    PromotionNotFound { promotion_id: String },

    #[error(
        "production promotion `{promotion_id}` is still active and cannot produce a durable memory yet"
    )]
    PromotionNotFinalized { promotion_id: String },

    #[error("strategy memory `{memory_id}` was not found")]
    MemoryNotFound { memory_id: String },

    #[error("verification artifact `{verification_id}` was not found")]
    VerificationNotFound { verification_id: String },

    #[error("verification artifact `{verification_id}` did not pass")]
    VerificationFailed { verification_id: String },

    #[error("artifact mismatch for {artifact}: expected experiment `{expected}`, found `{actual}`")]
    ExperimentMismatch {
        artifact: &'static str,
        expected: String,
        actual: String,
    },

    #[error("strategy scorecard `{scorecard_id}` was not found")]
    ScorecardNotFound { scorecard_id: String },
}

/// Whether one durable strategy memory came from a canary or a production promotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyMemorySourceKind {
    Canary,
    Promotion,
}

/// Interpreted rollout outcome captured by one durable strategy memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyMemoryOutcomeKind {
    ReadyForPromotionReview,
    StableInProduction,
    Blocked,
    Halted,
}

/// One durable strategy-memory record derived from a rollout artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyMemoryReport {
    pub memory_id: String,
    pub strategy_id: String,
    pub strategy_description: String,
    pub created_at_ms: i64,
    pub observed_at_ms: i64,
    pub source_kind: StrategyMemorySourceKind,
    pub source_artifact_id: String,
    pub source_status: String,
    pub outcome_kind: StrategyMemoryOutcomeKind,
    pub suite_name: String,
    pub corpus_version: String,
    pub reference_strategy_id: String,
    pub lineage: ExperimentLineage,
    pub rollout_stage_weight: f64,
    pub outcome_weight: f64,
    pub observed_events: usize,
    pub exclusive_detection_rate: f64,
    pub recovery_rate: f64,
    pub max_detect_latency_us: u64,
    pub total_detection_volume: usize,
    pub blocking_reasons: Vec<String>,
}

/// Metadata surfaced for one persisted strategy memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyMemoryRecord {
    pub memory_id: String,
    pub strategy_id: String,
    pub source_kind: StrategyMemorySourceKind,
    pub source_artifact_id: String,
    pub observed_at_ms: i64,
    pub outcome_kind: StrategyMemoryOutcomeKind,
    pub bundle_path: String,
}

impl StrategyMemoryRecord {
    fn from_report(report: &StrategyMemoryReport, bundle_path: String) -> Self {
        Self {
            memory_id: report.memory_id.clone(),
            strategy_id: report.strategy_id.clone(),
            source_kind: report.source_kind,
            source_artifact_id: report.source_artifact_id.clone(),
            observed_at_ms: report.observed_at_ms,
            outcome_kind: report.outcome_kind,
            bundle_path,
        }
    }
}

/// Persisted strategy memory loaded with metadata.
#[derive(Debug, Clone)]
pub struct StrategyMemoryLookup {
    pub record: StrategyMemoryRecord,
    pub report: StrategyMemoryReport,
}

/// Strategy-scoped history loaded from durable memory records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyMemoryHistory {
    pub strategy_id: String,
    pub memory_count: usize,
    pub latest_rollout_state: Option<StrategyRolloutStateSummary>,
    pub memories: Vec<StrategyMemoryReport>,
}

/// Summary of the latest rollout state known for one strategy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyRolloutStateSummary {
    pub source_kind: StrategyMemorySourceKind,
    pub source_artifact_id: String,
    pub outcome_kind: StrategyMemoryOutcomeKind,
    pub observed_at_ms: i64,
}

/// Errors raised by the persisted strategy-memory store.
#[derive(Debug, thiserror::Error)]
pub enum StrategyMemoryStoreError {
    #[error("failed to read strategy memory store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write strategy memory store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse strategy memory store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// File-backed store for durable strategy memories.
#[derive(Debug, Clone)]
pub struct FileStrategyMemoryStore {
    root: PathBuf,
}

impl FileStrategyMemoryStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StrategyMemoryStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            StrategyMemoryStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, memory_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(memory_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<StrategyMemoryIndex, StrategyMemoryStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(StrategyMemoryIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| StrategyMemoryStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| StrategyMemoryStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &StrategyMemoryIndex) -> Result<(), StrategyMemoryStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            StrategyMemoryStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| StrategyMemoryStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &StrategyMemoryReport,
    ) -> Result<StrategyMemoryRecord, StrategyMemoryStoreError> {
        let path = self.report_path(&report.memory_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            StrategyMemoryStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| StrategyMemoryStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = StrategyMemoryRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.memory_id != record.memory_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.observed_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        memory_id: &str,
    ) -> Result<Option<StrategyMemoryLookup>, StrategyMemoryStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.memory_id == memory_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| StrategyMemoryStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| StrategyMemoryStoreError::Parse { path, source })?;
        Ok(Some(StrategyMemoryLookup { record, report }))
    }

    pub fn history(
        &self,
        strategy_id: &str,
    ) -> Result<Vec<StrategyMemoryLookup>, StrategyMemoryStoreError> {
        let mut entries = self
            .read_index()?
            .entries
            .into_iter()
            .filter(|entry| entry.strategy_id == strategy_id)
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.observed_at_ms));
        let mut lookups = Vec::with_capacity(entries.len());
        for record in entries {
            let path = PathBuf::from(&record.bundle_path);
            let raw =
                fs::read_to_string(&path).map_err(|source| StrategyMemoryStoreError::Read {
                    path: path.clone(),
                    source,
                })?;
            let report = serde_json::from_str(&raw)
                .map_err(|source| StrategyMemoryStoreError::Parse { path, source })?;
            lookups.push(StrategyMemoryLookup { record, report });
        }
        Ok(lookups)
    }
}

/// Harness that derives durable strategy memories from completed rollout artifacts.
pub struct DefaultStrategyMemoryHarness {
    pub config_path: PathBuf,
    pub config: SwarmConfig,
    pub store: FileStrategyMemoryStore,
}

impl DefaultStrategyMemoryHarness {
    pub fn from_path(
        config_path: impl AsRef<Path>,
        results_dir: impl AsRef<Path>,
    ) -> Result<Self, StrategyAdvisorError> {
        let config_path = config_path.as_ref();
        let config = load_config(config_path)?;
        Self::from_config(config_path, config, results_dir)
    }

    pub fn from_config(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
        results_dir: impl AsRef<Path>,
    ) -> Result<Self, StrategyAdvisorError> {
        let store = FileStrategyMemoryStore::open(results_dir)?;
        Ok(Self {
            config_path: config_path.into(),
            config,
            store,
        })
    }

    pub fn ingest_canary(
        &self,
        canary_results_dir: impl AsRef<Path>,
        run_id: &str,
    ) -> Result<StrategyMemoryLookup, StrategyAdvisorError> {
        let canary_store = FileCanaryStore::open(canary_results_dir)?;
        let canary =
            canary_store
                .load(run_id)?
                .ok_or_else(|| StrategyAdvisorError::CanaryNotFound {
                    run_id: run_id.to_string(),
                })?;
        if canary.report.status == CanaryRunStatus::Active {
            return Err(StrategyAdvisorError::CanaryNotFinalized {
                run_id: run_id.to_string(),
            });
        }

        let report = strategy_memory_from_canary(&canary.report);
        let record = self.store.persist(&report)?;
        Ok(StrategyMemoryLookup { record, report })
    }

    pub fn ingest_promotion(
        &self,
        promotion_results_dir: impl AsRef<Path>,
        promotion_id: &str,
    ) -> Result<StrategyMemoryLookup, StrategyAdvisorError> {
        let promotion_store = FileProductionPromotionStore::open(promotion_results_dir)?;
        let promotion = promotion_store.load(promotion_id)?.ok_or_else(|| {
            StrategyAdvisorError::PromotionNotFound {
                promotion_id: promotion_id.to_string(),
            }
        })?;
        if promotion.report.status == ProductionPromotionStatus::Active {
            return Err(StrategyAdvisorError::PromotionNotFinalized {
                promotion_id: promotion_id.to_string(),
            });
        }

        let report = strategy_memory_from_promotion(&promotion.report);
        let record = self.store.persist(&report)?;
        Ok(StrategyMemoryLookup { record, report })
    }

    pub fn load_memory(
        &self,
        memory_id: &str,
    ) -> Result<Option<StrategyMemoryLookup>, StrategyAdvisorError> {
        Ok(self.store.load(memory_id)?)
    }

    pub fn history(
        &self,
        strategy_id: &str,
    ) -> Result<StrategyMemoryHistory, StrategyAdvisorError> {
        let lookups = self.store.history(strategy_id)?;
        let memories = lookups
            .iter()
            .map(|lookup| lookup.report.clone())
            .collect::<Vec<_>>();
        let latest_rollout_state = lookups.first().map(|lookup| StrategyRolloutStateSummary {
            source_kind: lookup.report.source_kind,
            source_artifact_id: lookup.report.source_artifact_id.clone(),
            outcome_kind: lookup.report.outcome_kind,
            observed_at_ms: lookup.report.observed_at_ms,
        });
        Ok(StrategyMemoryHistory {
            strategy_id: strategy_id.to_string(),
            memory_count: memories.len(),
            latest_rollout_state,
            memories,
        })
    }
}

/// One score contribution from a durable strategy memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyMemoryContribution {
    pub memory_id: String,
    pub source_kind: StrategyMemorySourceKind,
    pub source_artifact_id: String,
    pub observed_at_ms: i64,
    pub outcome_weight: f64,
    pub rollout_stage_weight: f64,
    pub recency_decay: f64,
    pub context_relevance: f64,
    pub weighted_contribution: f64,
    pub context_matches: Vec<String>,
    pub summary: String,
}

/// One score breakdown for one strategy under one experiment context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyScoreBreakdown {
    pub strategy_id: String,
    pub strategy_description: String,
    pub latest_rollout_state: Option<StrategyRolloutStateSummary>,
    pub matching_memory_count: usize,
    pub memory_score: Option<f64>,
    pub replay_fallback_score: f64,
    pub fallback_applied: bool,
    pub final_score: f64,
    pub contributions: Vec<StrategyMemoryContribution>,
}

/// Final advisory recommendation from one scorecard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyAdvisoryRecommendation {
    RetainBaseline,
    CandidatePreferred,
    CandidateAlreadyStableInProduction,
}

/// Durable operator-facing scorecard comparing the production baseline and a verified candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyScorecard {
    pub scorecard_id: String,
    pub experiment_id: String,
    pub experiment_name: String,
    pub verification_id: String,
    pub created_at_ms: i64,
    pub suite_name: String,
    pub corpus_version: String,
    pub lineage: ExperimentLineage,
    pub baseline_strategy_id: String,
    pub candidate_strategy_id: String,
    pub candidate_description: String,
    pub recommendation: StrategyAdvisoryRecommendation,
    pub score_delta: f64,
    pub baseline: StrategyScoreBreakdown,
    pub candidate: StrategyScoreBreakdown,
}

/// Metadata surfaced for one persisted strategy scorecard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyScorecardRecord {
    pub scorecard_id: String,
    pub experiment_id: String,
    pub candidate_strategy_id: String,
    pub created_at_ms: i64,
    pub recommendation: StrategyAdvisoryRecommendation,
    pub bundle_path: String,
}

impl StrategyScorecardRecord {
    fn from_report(report: &StrategyScorecard, bundle_path: String) -> Self {
        Self {
            scorecard_id: report.scorecard_id.clone(),
            experiment_id: report.experiment_id.clone(),
            candidate_strategy_id: report.candidate_strategy_id.clone(),
            created_at_ms: report.created_at_ms,
            recommendation: report.recommendation,
            bundle_path,
        }
    }
}

/// Persisted strategy scorecard loaded with metadata.
#[derive(Debug, Clone)]
pub struct StrategyScorecardLookup {
    pub record: StrategyScorecardRecord,
    pub report: StrategyScorecard,
}

/// Errors raised by the persisted strategy-scorecard store.
#[derive(Debug, thiserror::Error)]
pub enum StrategyScorecardStoreError {
    #[error("failed to read strategy scorecard store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write strategy scorecard store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse strategy scorecard store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// File-backed store for durable strategy scorecards.
#[derive(Debug, Clone)]
pub struct FileStrategyScorecardStore {
    root: PathBuf,
}

impl FileStrategyScorecardStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StrategyScorecardStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            StrategyScorecardStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, scorecard_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(scorecard_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<StrategyScorecardIndex, StrategyScorecardStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(StrategyScorecardIndex::default());
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| StrategyScorecardStoreError::Read {
                path: path.clone(),
                source,
            })?;
        serde_json::from_str(&raw)
            .map_err(|source| StrategyScorecardStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &StrategyScorecardIndex,
    ) -> Result<(), StrategyScorecardStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            StrategyScorecardStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| StrategyScorecardStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &StrategyScorecard,
    ) -> Result<StrategyScorecardRecord, StrategyScorecardStoreError> {
        let path = self.report_path(&report.scorecard_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            StrategyScorecardStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| StrategyScorecardStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = StrategyScorecardRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.scorecard_id != record.scorecard_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        scorecard_id: &str,
    ) -> Result<Option<StrategyScorecardLookup>, StrategyScorecardStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.scorecard_id == scorecard_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw =
            fs::read_to_string(&path).map_err(|source| StrategyScorecardStoreError::Read {
                path: path.clone(),
                source,
            })?;
        let report =
            serde_json::from_str(&raw).map_err(|source| StrategyScorecardStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        Ok(Some(StrategyScorecardLookup { record, report }))
    }
}

/// Harness that computes advisory scorecards from verification, experiment, and strategy-memory evidence.
pub struct DefaultStrategyScorecardHarness {
    pub config_path: PathBuf,
    pub config: SwarmConfig,
    pub memory_store: FileStrategyMemoryStore,
    pub scorecard_store: FileStrategyScorecardStore,
}

impl DefaultStrategyScorecardHarness {
    pub fn from_path(
        config_path: impl AsRef<Path>,
        memory_results_dir: impl AsRef<Path>,
        scorecard_results_dir: impl AsRef<Path>,
    ) -> Result<Self, StrategyAdvisorError> {
        let config_path = config_path.as_ref();
        let config = load_config(config_path)?;
        Self::from_config(
            config_path,
            config,
            memory_results_dir,
            scorecard_results_dir,
        )
    }

    pub fn from_config(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
        memory_results_dir: impl AsRef<Path>,
        scorecard_results_dir: impl AsRef<Path>,
    ) -> Result<Self, StrategyAdvisorError> {
        Ok(Self {
            config_path: config_path.into(),
            config,
            memory_store: FileStrategyMemoryStore::open(memory_results_dir)?,
            scorecard_store: FileStrategyScorecardStore::open(scorecard_results_dir)?,
        })
    }

    pub async fn create_scorecard(
        &self,
        replay_harness: &DefaultReplayHarness,
        experiment_path: impl AsRef<Path>,
        experiment_results_dir: impl AsRef<Path>,
        verification_results_dir: impl AsRef<Path>,
        verification_id: &str,
    ) -> Result<StrategyScorecardLookup, StrategyAdvisorError> {
        let experiment_path = experiment_path.as_ref().to_path_buf();
        let manifest = load_detector_experiment_manifest(&experiment_path)?;
        let experiment_id = format!(
            "experiment:{}:{}",
            manifest.name,
            manifest.candidate.strategy_id()
        );
        let experiment = load_or_evaluate_experiment(
            replay_harness,
            &experiment_path,
            experiment_results_dir,
            &experiment_id,
        )
        .await?;
        let verification = load_verification_report(
            verification_results_dir,
            verification_id,
            &experiment.report.experiment_id,
        )?;
        let scorecard =
            build_scorecard(&self.memory_store, &experiment.report, &verification.report)?;
        let record = self.scorecard_store.persist(&scorecard)?;
        Ok(StrategyScorecardLookup {
            record,
            report: scorecard,
        })
    }

    pub fn load_scorecard(
        &self,
        scorecard_id: &str,
    ) -> Result<Option<StrategyScorecardLookup>, StrategyAdvisorError> {
        Ok(self.scorecard_store.load(scorecard_id)?)
    }
}

pub fn render_strategy_memory(report: &StrategyMemoryReport) -> String {
    let mut lines = vec![
        "Strategy Memory".to_string(),
        format!("Memory ID: {}", report.memory_id),
        format!(
            "Strategy: {} | {}",
            report.strategy_id, report.strategy_description
        ),
        format!(
            "Source: {:?} {}",
            report.source_kind, report.source_artifact_id
        ),
        format!("Source status: {}", report.source_status),
        format!(
            "Outcome: {:?} | weight={:.2}",
            report.outcome_kind, report.outcome_weight
        ),
        format!(
            "Context: suite={} corpus={} reference={} parent={}",
            report.suite_name,
            report.corpus_version,
            report.reference_strategy_id,
            report.lineage.parent_strategy_id
        ),
        format!(
            "Observed: events={} exclusive_rate={:.2} recovery_rate={:.2}",
            report.observed_events, report.exclusive_detection_rate, report.recovery_rate
        ),
        format!(
            "Latency us: max={} | detection volume={}",
            report.max_detect_latency_us, report.total_detection_volume
        ),
        format!("Rollout stage weight: {:.2}", report.rollout_stage_weight),
    ];

    if report.blocking_reasons.is_empty() {
        lines.push("Blocking reasons: none".to_string());
    } else {
        lines.push("Blocking reasons:".to_string());
        for reason in &report.blocking_reasons {
            lines.push(format!("- {reason}"));
        }
    }

    lines.join("\n")
}

pub fn render_strategy_memory_history(history: &StrategyMemoryHistory) -> String {
    let mut lines = vec![
        "Strategy Memory History".to_string(),
        format!("Strategy: {}", history.strategy_id),
        format!("Memories: {}", history.memory_count),
    ];

    if let Some(latest) = &history.latest_rollout_state {
        lines.push(format!(
            "Latest rollout state: {:?} via {:?} {} at {}",
            latest.outcome_kind,
            latest.source_kind,
            latest.source_artifact_id,
            latest.observed_at_ms
        ));
    } else {
        lines.push("Latest rollout state: none".to_string());
    }

    if history.memories.is_empty() {
        lines.push("Entries: none".to_string());
    } else {
        lines.push("Entries:".to_string());
        for memory in &history.memories {
            lines.push(format!(
                "- {} | {:?} | {:?} | suite={} | observed={}",
                memory.memory_id,
                memory.source_kind,
                memory.outcome_kind,
                memory.suite_name,
                memory.observed_at_ms
            ));
        }
    }

    lines.join("\n")
}

pub fn render_strategy_scorecard(report: &StrategyScorecard) -> String {
    let mut lines = vec![
        "Strategy Advisory Scorecard".to_string(),
        format!("Scorecard ID: {}", report.scorecard_id),
        format!(
            "Experiment: {} ({})",
            report.experiment_name, report.experiment_id
        ),
        format!("Verification: {}", report.verification_id),
        format!(
            "Context: suite={} corpus={} parent={}",
            report.suite_name, report.corpus_version, report.lineage.parent_strategy_id
        ),
        format!("Recommendation: {:?}", report.recommendation),
        format!("Score delta: {:.3}", report.score_delta),
    ];

    lines.extend(render_score_breakdown("Baseline", &report.baseline));
    lines.extend(render_score_breakdown("Candidate", &report.candidate));

    lines.join("\n")
}

fn render_score_breakdown(label: &str, breakdown: &StrategyScoreBreakdown) -> Vec<String> {
    let mut lines = vec![
        format!(
            "{label}: {} | {}",
            breakdown.strategy_id, breakdown.strategy_description
        ),
        format!(
            "{label} score: final={:.3} replay_fallback={:.3} fallback_applied={} matching_memories={}",
            breakdown.final_score,
            breakdown.replay_fallback_score,
            breakdown.fallback_applied,
            breakdown.matching_memory_count
        ),
    ];
    if let Some(memory_score) = breakdown.memory_score {
        lines.push(format!("{label} live memory score: {memory_score:.3}"));
    } else {
        lines.push(format!("{label} live memory score: none"));
    }
    if let Some(latest) = &breakdown.latest_rollout_state {
        lines.push(format!(
            "{label} latest rollout: {:?} via {:?} {}",
            latest.outcome_kind, latest.source_kind, latest.source_artifact_id
        ));
    } else {
        lines.push(format!("{label} latest rollout: none"));
    }
    if breakdown.contributions.is_empty() {
        lines.push(format!("{label} contributions: none"));
    } else {
        lines.push(format!("{label} contributions:"));
        for contribution in &breakdown.contributions {
            lines.push(format!(
                "- {} | {:?} | outcome={:.2} recency={:.3} context={:.2} weighted={:.3} | matches={}",
                contribution.memory_id,
                contribution.source_kind,
                contribution.outcome_weight,
                contribution.recency_decay,
                contribution.context_relevance,
                contribution.weighted_contribution,
                if contribution.context_matches.is_empty() {
                    "none".to_string()
                } else {
                    contribution.context_matches.join(",")
                }
            ));
        }
    }
    lines
}

fn strategy_memory_from_canary(report: &CanaryRunReport) -> StrategyMemoryReport {
    let (outcome_kind, outcome_weight) = match (report.status, report.recommendation) {
        (CanaryRunStatus::Completed, CanaryRecommendation::ReadyForPromotionReview) => (
            StrategyMemoryOutcomeKind::ReadyForPromotionReview,
            CANARY_READY_OUTCOME_WEIGHT,
        ),
        (CanaryRunStatus::Halted, _) => (
            StrategyMemoryOutcomeKind::Halted,
            CANARY_HALTED_OUTCOME_WEIGHT,
        ),
        _ => (
            StrategyMemoryOutcomeKind::Blocked,
            CANARY_BLOCKED_OUTCOME_WEIGHT,
        ),
    };
    StrategyMemoryReport {
        memory_id: strategy_memory_id(StrategyMemorySourceKind::Canary, &report.run_id),
        strategy_id: report.assignment.candidate_strategy_id.clone(),
        strategy_description: report.assignment.candidate_description.clone(),
        created_at_ms: now_ms(),
        observed_at_ms: report.updated_at_ms,
        source_kind: StrategyMemorySourceKind::Canary,
        source_artifact_id: report.run_id.clone(),
        source_status: format!("{:?}/{:?}", report.status, report.recommendation),
        outcome_kind,
        suite_name: report.assignment.suite_name.clone(),
        corpus_version: report.assignment.corpus_version.clone(),
        reference_strategy_id: report.assignment.baseline_strategy_id.clone(),
        lineage: report.assignment.lineage.clone(),
        rollout_stage_weight: CANARY_STAGE_WEIGHT,
        outcome_weight,
        observed_events: report.metrics.total_events,
        exclusive_detection_rate: report.metrics.candidate_only_rate,
        recovery_rate: report.metrics.baseline_miss_rate,
        max_detect_latency_us: report.metrics.max_candidate_detect_latency_us,
        total_detection_volume: report.metrics.total_candidate_deposits,
        blocking_reasons: report
            .rollback_history
            .iter()
            .map(|rollback| rollback.reason.clone())
            .collect(),
    }
}

fn strategy_memory_from_promotion(
    report: &crate::promotion::ProductionPromotionReport,
) -> StrategyMemoryReport {
    let (outcome_kind, outcome_weight) = match (report.status, report.recommendation) {
        (
            ProductionPromotionStatus::Completed,
            ProductionPromotionRecommendation::StableInProduction,
        ) => (
            StrategyMemoryOutcomeKind::StableInProduction,
            PROMOTION_STABLE_OUTCOME_WEIGHT,
        ),
        (ProductionPromotionStatus::Halted, _) => (
            StrategyMemoryOutcomeKind::Halted,
            PROMOTION_HALTED_OUTCOME_WEIGHT,
        ),
        _ => (
            StrategyMemoryOutcomeKind::Blocked,
            PROMOTION_BLOCKED_OUTCOME_WEIGHT,
        ),
    };
    StrategyMemoryReport {
        memory_id: strategy_memory_id(StrategyMemorySourceKind::Promotion, &report.promotion_id),
        strategy_id: report.assignment.promoted_strategy_id.clone(),
        strategy_description: report.assignment.promoted_description.clone(),
        created_at_ms: now_ms(),
        observed_at_ms: report.updated_at_ms,
        source_kind: StrategyMemorySourceKind::Promotion,
        source_artifact_id: report.promotion_id.clone(),
        source_status: format!("{:?}/{:?}", report.status, report.recommendation),
        outcome_kind,
        suite_name: report.assignment.suite_name.clone(),
        corpus_version: report.assignment.corpus_version.clone(),
        reference_strategy_id: report.assignment.previous_production_strategy_id.clone(),
        lineage: report.assignment.lineage.clone(),
        rollout_stage_weight: PROMOTION_STAGE_WEIGHT,
        outcome_weight,
        observed_events: report.metrics.total_events,
        exclusive_detection_rate: report.metrics.promoted_only_rate,
        recovery_rate: report.metrics.fallback_recovery_rate,
        max_detect_latency_us: report.metrics.max_promoted_detect_latency_us,
        total_detection_volume: report.metrics.total_promoted_deposits,
        blocking_reasons: report
            .rollback_history
            .iter()
            .map(|rollback| rollback.reason.clone())
            .collect(),
    }
}

fn strategy_memory_id(kind: StrategyMemorySourceKind, source_artifact_id: &str) -> String {
    match kind {
        StrategyMemorySourceKind::Canary => {
            format!("strategy_memory:canary:{source_artifact_id}")
        }
        StrategyMemorySourceKind::Promotion => {
            format!("strategy_memory:promotion:{source_artifact_id}")
        }
    }
}

async fn load_or_evaluate_experiment(
    replay_harness: &DefaultReplayHarness,
    experiment_path: &Path,
    experiment_results_dir: impl AsRef<Path>,
    experiment_id: &str,
) -> Result<StrategyExperimentLookup, StrategyAdvisorError> {
    if let Some(existing) =
        replay_harness.load_experiment(&experiment_results_dir, experiment_id)?
    {
        return Ok(existing);
    }
    Ok(replay_harness
        .evaluate_experiment_path(experiment_path, experiment_results_dir)
        .await?)
}

fn load_verification_report(
    verification_results_dir: impl AsRef<Path>,
    verification_id: &str,
    experiment_id: &str,
) -> Result<DetectorVerificationLookup, StrategyAdvisorError> {
    let store = FileVerificationStore::open(verification_results_dir)?;
    let verification =
        store
            .load(verification_id)?
            .ok_or_else(|| StrategyAdvisorError::VerificationNotFound {
                verification_id: verification_id.to_string(),
            })?;
    if verification.report.experiment_id != experiment_id {
        return Err(StrategyAdvisorError::ExperimentMismatch {
            artifact: "verification",
            expected: experiment_id.to_string(),
            actual: verification.report.experiment_id.clone(),
        });
    }
    if !verification.report.passed {
        return Err(StrategyAdvisorError::VerificationFailed {
            verification_id: verification_id.to_string(),
        });
    }
    Ok(verification)
}

fn build_scorecard(
    memory_store: &FileStrategyMemoryStore,
    experiment: &StrategyExperimentReport,
    verification: &crate::replay::DetectorVerificationReport,
) -> Result<StrategyScorecard, StrategyAdvisorError> {
    let context = StrategyScoreContext {
        suite_name: experiment.suite_name.clone(),
        corpus_version: experiment.corpus_version.clone(),
        reference_strategy_id: experiment.baseline_strategy_id.clone(),
        parent_strategy_id: experiment.lineage.parent_strategy_id.clone(),
    };
    let baseline_history = memory_store.history(&experiment.baseline_strategy_id)?;
    let candidate_history = memory_store.history(&experiment.candidate_strategy_id)?;

    let baseline = build_strategy_score_breakdown(
        &experiment.baseline_strategy_id,
        "current production baseline",
        &baseline_history,
        &experiment.comparison.baseline,
        &context,
    );
    let candidate = build_strategy_score_breakdown(
        &experiment.candidate_strategy_id,
        &experiment.candidate_description,
        &candidate_history,
        &experiment.comparison.candidate,
        &context,
    );
    let recommendation = choose_recommendation(&baseline, &candidate);
    let created_at_ms = now_ms();
    Ok(StrategyScorecard {
        scorecard_id: scorecard_id(
            &experiment.experiment_name,
            &experiment.candidate_strategy_id,
            created_at_ms,
        ),
        experiment_id: experiment.experiment_id.clone(),
        experiment_name: experiment.experiment_name.clone(),
        verification_id: verification.verification_id.clone(),
        created_at_ms,
        suite_name: experiment.suite_name.clone(),
        corpus_version: experiment.corpus_version.clone(),
        lineage: experiment.lineage.clone(),
        baseline_strategy_id: experiment.baseline_strategy_id.clone(),
        candidate_strategy_id: experiment.candidate_strategy_id.clone(),
        candidate_description: experiment.candidate_description.clone(),
        recommendation,
        score_delta: candidate.final_score - baseline.final_score,
        baseline,
        candidate,
    })
}

fn build_strategy_score_breakdown(
    strategy_id: &str,
    strategy_description: &str,
    history: &[StrategyMemoryLookup],
    fallback_metrics: &StrategyExperimentMetrics,
    context: &StrategyScoreContext,
) -> StrategyScoreBreakdown {
    let mut contributions = Vec::new();
    let mut weighted_sum = 0.0;
    let mut total_weight = 0.0;
    for memory in history {
        let context_matches = context_matches(&memory.report, context);
        let context_relevance = context_relevance(&context_matches);
        let recency_decay = recency_decay(memory.report.observed_at_ms, now_ms());
        let composite_weight =
            memory.report.rollout_stage_weight * recency_decay * context_relevance;
        let weighted_contribution = memory.report.outcome_weight * composite_weight;
        weighted_sum += weighted_contribution;
        total_weight += composite_weight;
        contributions.push(StrategyMemoryContribution {
            memory_id: memory.report.memory_id.clone(),
            source_kind: memory.report.source_kind,
            source_artifact_id: memory.report.source_artifact_id.clone(),
            observed_at_ms: memory.report.observed_at_ms,
            outcome_weight: memory.report.outcome_weight,
            rollout_stage_weight: memory.report.rollout_stage_weight,
            recency_decay,
            context_relevance,
            weighted_contribution,
            context_matches,
            summary: format!(
                "{:?} {} | status={} | exclusive_rate={:.2} | recovery_rate={:.2}",
                memory.report.outcome_kind,
                memory.report.source_artifact_id,
                memory.report.source_status,
                memory.report.exclusive_detection_rate,
                memory.report.recovery_rate
            ),
        });
    }
    let matching_memory_count = contributions.len();
    let memory_score = if total_weight > 0.0 {
        Some((weighted_sum / total_weight).clamp(-1.0, 1.0))
    } else {
        None
    };
    let replay_fallback_score = replay_fallback_score(fallback_metrics);
    let fallback_applied = matching_memory_count < MIN_LIVE_MEMORIES;
    let final_score = if matching_memory_count == 0 {
        replay_fallback_score
    } else if matching_memory_count >= MIN_LIVE_MEMORIES {
        memory_score.unwrap_or(replay_fallback_score)
    } else {
        let live_score = memory_score.unwrap_or(replay_fallback_score);
        let live_weight = matching_memory_count as f64;
        let fallback_weight = (MIN_LIVE_MEMORIES - matching_memory_count) as f64;
        ((live_score * live_weight) + (replay_fallback_score * fallback_weight))
            / MIN_LIVE_MEMORIES as f64
    };
    StrategyScoreBreakdown {
        strategy_id: strategy_id.to_string(),
        strategy_description: strategy_description.to_string(),
        latest_rollout_state: history.first().map(|memory| StrategyRolloutStateSummary {
            source_kind: memory.report.source_kind,
            source_artifact_id: memory.report.source_artifact_id.clone(),
            outcome_kind: memory.report.outcome_kind,
            observed_at_ms: memory.report.observed_at_ms,
        }),
        matching_memory_count,
        memory_score,
        replay_fallback_score,
        fallback_applied,
        final_score,
        contributions,
    }
}

fn context_matches(memory: &StrategyMemoryReport, context: &StrategyScoreContext) -> Vec<String> {
    let mut matches = Vec::new();
    if memory.suite_name == context.suite_name {
        matches.push("suite_name".to_string());
    }
    if memory.corpus_version == context.corpus_version {
        matches.push("corpus_version".to_string());
    }
    if memory.reference_strategy_id == context.reference_strategy_id {
        matches.push("reference_strategy_id".to_string());
    }
    if memory.lineage.parent_strategy_id == context.parent_strategy_id {
        matches.push("parent_strategy_id".to_string());
    }
    matches
}

fn context_relevance(matches: &[String]) -> f64 {
    let mut relevance = BASE_CONTEXT_RELEVANCE;
    for matched in matches {
        match matched.as_str() {
            "suite_name" => relevance += SUITE_MATCH_BONUS,
            "corpus_version" => relevance += CORPUS_MATCH_BONUS,
            "reference_strategy_id" => relevance += REFERENCE_MATCH_BONUS,
            "parent_strategy_id" => relevance += PARENT_MATCH_BONUS,
            _ => {}
        }
    }
    relevance.min(1.0)
}

fn recency_decay(observed_at_ms: i64, now_ms: i64) -> f64 {
    let age_ms = now_ms.saturating_sub(observed_at_ms).max(0) as f64;
    let age_hours = age_ms / 3_600_000.0;
    0.5_f64.powf(age_hours / RECENCY_HALF_LIFE_HOURS)
}

fn replay_fallback_score(metrics: &StrategyExperimentMetrics) -> f64 {
    let latency_penalty =
        (metrics.max_detect_latency_us as f64 / LATENCY_PENALTY_CAP_US).min(1.0) * 0.25;
    (metrics.detection_rate - metrics.false_positive_rate - latency_penalty).clamp(-1.0, 1.0)
}

fn choose_recommendation(
    baseline: &StrategyScoreBreakdown,
    candidate: &StrategyScoreBreakdown,
) -> StrategyAdvisoryRecommendation {
    if matches!(
        candidate
            .latest_rollout_state
            .as_ref()
            .map(|state| state.outcome_kind),
        Some(StrategyMemoryOutcomeKind::StableInProduction)
    ) {
        return StrategyAdvisoryRecommendation::CandidateAlreadyStableInProduction;
    }
    if candidate.final_score > baseline.final_score + SCORE_RECOMMENDATION_EPSILON {
        StrategyAdvisoryRecommendation::CandidatePreferred
    } else {
        StrategyAdvisoryRecommendation::RetainBaseline
    }
}

fn scorecard_id(experiment_name: &str, candidate_strategy_id: &str, created_at_ms: i64) -> String {
    format!(
        "strategy_scorecard:{}:{}:{}",
        experiment_name, candidate_strategy_id, created_at_ms
    )
}

#[derive(Debug, Clone)]
struct StrategyScoreContext {
    suite_name: String,
    corpus_version: String,
    reference_strategy_id: String,
    parent_strategy_id: String,
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
struct StrategyMemoryIndex {
    entries: Vec<StrategyMemoryRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StrategyScorecardIndex {
    entries: Vec<StrategyScorecardRecord>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        DefaultStrategyMemoryHarness, DefaultStrategyScorecardHarness,
        StrategyAdvisoryRecommendation, StrategyMemoryOutcomeKind, StrategyMemorySourceKind,
        render_strategy_memory, render_strategy_memory_history, render_strategy_scorecard,
    };
    use crate::canary::{
        CanaryAssignment, CanaryRecommendation, CanaryRunReport, CanaryRunStatus, FileCanaryStore,
    };
    use crate::config::RuntimeMode;
    use crate::promotion::{
        FileProductionPromotionStore, ProductionPromotionAssignment, ProductionPromotionMetrics,
        ProductionPromotionRecommendation, ProductionPromotionReport, ProductionPromotionStatus,
    };
    use crate::replay::{
        DefaultReplayHarness, DetectorCandidateManifest, DetectorVerificationReport,
        ExperimentCorpusTarget, ExperimentGateConfig, ExperimentLineage,
        ExperimentVerificationTarget, FileExperimentStore, FileVerificationStore,
        ReplaySuiteReport, ReplaySuiteSourceKind, StrategyExperimentComparison,
        StrategyExperimentMetricDelta, StrategyExperimentMetrics, StrategyExperimentReport,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use swarm_core::config::{
        AuditConfig, BundleStoreConfig, CanaryConfig, CorrelationConfig, DetectionConfig,
        DetectorProfilesConfig, InvestigationConfig, PheromoneBackendConfig, PheromoneConfig,
        PolicyConfig, PromotionConfig, ResponseAdapterConfig, RuntimeSettings, SwarmConfig,
        TelemetrySourceConfig,
    };
    use swarm_core::types::Severity;
    use swarm_whisker::SuspiciousProcessTreeProfile;

    fn unique_temp_dir(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "swarm-runtime-strategy-{label}-{}",
            std::process::id()
        ));
        if root.exists() {
            let _ = fs::remove_dir_all(&root);
        }
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn strategy_config() -> SwarmConfig {
        SwarmConfig {
            schema_version: 1,
            name: "strategy-test".to_string(),
            description: "strategy memory test config".to_string(),
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
                max_candidate_only_rate: 0.25,
                max_baseline_miss_rate: 0.25,
                max_detect_latency_us: 10_000,
                max_total_detections: 8,
            },
            promotion: PromotionConfig {
                enabled: true,
                window_id: "production-primary".to_string(),
                strategy_id: None,
                observation_window_events: 2,
                max_promoted_only_rate: 0.20,
                max_fallback_recovery_rate: 0.20,
                max_detect_latency_us: 10_000,
                max_total_detections: 12,
            },
            evolution: swarm_core::config::EvolutionConfig::default(),
            deception: swarm_core::config::DeceptionConfig::default(),
            memory: swarm_core::config::MemoryConfig::default(),
            identity: swarm_core::config::IdentityConfig::default(),
            platform_api: Default::default(),
            operator: swarm_core::config::OperatorSurfaceConfig::default(),
            tls: None,
        }
    }

    fn rollout_baseline_strategy_id(config: &SwarmConfig) -> String {
        config
            .canary
            .strategy_id
            .clone()
            .unwrap_or_else(|| config.detection.strategy.clone())
    }

    fn control_candidate() -> DetectorCandidateManifest {
        DetectorCandidateManifest::SuspiciousProcessTree {
            strategy_id: "office_baseline_control".to_string(),
            description: "control candidate".to_string(),
            profile: SuspiciousProcessTreeProfile::default(),
        }
    }

    fn ready_canary_report(
        config: &SwarmConfig,
        candidate: &DetectorCandidateManifest,
        updated_at_ms: i64,
    ) -> CanaryRunReport {
        let baseline_strategy_id = rollout_baseline_strategy_id(config);
        CanaryRunReport {
            run_id: format!(
                "canary:{}:{}:1700000000000",
                config.canary.slot_id,
                candidate.strategy_id()
            ),
            slot_id: config.canary.slot_id.clone(),
            created_at_ms: updated_at_ms - 100,
            updated_at_ms,
            status: CanaryRunStatus::Completed,
            recommendation: CanaryRecommendation::ReadyForPromotionReview,
            assignment: CanaryAssignment {
                experiment_id: format!("experiment:test:{}", candidate.strategy_id()),
                experiment_name: "test".to_string(),
                experiment_path: "experiments/test.yaml".to_string(),
                suite_name: "hellcat_office_v1".to_string(),
                corpus_version: "2026-04-03".to_string(),
                baseline_strategy_id: baseline_strategy_id.clone(),
                candidate_strategy_id: candidate.strategy_id().to_string(),
                candidate_description: candidate.description().to_string(),
                candidate: candidate.clone(),
                lineage: ExperimentLineage {
                    parent_strategy_id: baseline_strategy_id,
                    mutation: "control".to_string(),
                    rationale: "test rollout".to_string(),
                },
                verification_id: format!("verification:test:{}", candidate.strategy_id()),
                verification_passed: true,
                shadow_id: format!("shadow:test:{}", candidate.strategy_id()),
                shadow_passed: true,
                assurance: None,
                canary: config.canary.clone(),
            },
            metrics: crate::canary::CanaryMetrics {
                total_events: 2,
                baseline_detections: 2,
                candidate_detections: 2,
                shared_detections: 2,
                candidate_only_detections: 0,
                baseline_only_detections: 0,
                candidate_only_rate: 0.0,
                baseline_miss_rate: 0.0,
                total_baseline_detect_latency_us: 40,
                average_baseline_detect_latency_us: 20,
                max_baseline_detect_latency_us: 25,
                total_candidate_detect_latency_us: 36,
                average_candidate_detect_latency_us: 18,
                max_candidate_detect_latency_us: 20,
                total_candidate_deposits: 2,
            },
            threshold_results: Vec::new(),
            recent_candidate_findings: Vec::new(),
            rollback_history: Vec::new(),
        }
    }

    fn stable_promotion_report(
        config: &SwarmConfig,
        candidate: &DetectorCandidateManifest,
        updated_at_ms: i64,
    ) -> ProductionPromotionReport {
        let canary_report = ready_canary_report(config, candidate, updated_at_ms - 500);
        let baseline_strategy_id = rollout_baseline_strategy_id(config);
        ProductionPromotionReport {
            promotion_id: format!(
                "promotion:{}:{}:{}",
                config.promotion.window_id,
                candidate.strategy_id(),
                updated_at_ms
            ),
            window_id: config.promotion.window_id.clone(),
            created_at_ms: updated_at_ms - 100,
            updated_at_ms,
            status: ProductionPromotionStatus::Completed,
            recommendation: ProductionPromotionRecommendation::StableInProduction,
            assignment: ProductionPromotionAssignment {
                canary_run_id: canary_report.run_id.clone(),
                canary_report,
                experiment_id: format!("experiment:test:{}", candidate.strategy_id()),
                experiment_name: "test".to_string(),
                suite_name: "hellcat_office_v1".to_string(),
                corpus_version: "2026-04-03".to_string(),
                previous_production_strategy_id: baseline_strategy_id.clone(),
                promoted_strategy_id: candidate.strategy_id().to_string(),
                promoted_description: candidate.description().to_string(),
                previous_production_candidate: DetectorCandidateManifest::SuspiciousProcessTree {
                    strategy_id: baseline_strategy_id.clone(),
                    description: "current production baseline".to_string(),
                    profile: SuspiciousProcessTreeProfile::default(),
                },
                promoted_candidate: candidate.clone(),
                lineage: ExperimentLineage {
                    parent_strategy_id: baseline_strategy_id,
                    mutation: "control".to_string(),
                    rationale: "test rollout".to_string(),
                },
                assurance: None,
                promotion: config.promotion.clone(),
            },
            metrics: ProductionPromotionMetrics {
                total_events: 2,
                fallback_detections: 2,
                promoted_detections: 2,
                shared_detections: 2,
                promoted_only_detections: 0,
                fallback_only_detections: 0,
                promoted_only_rate: 0.0,
                fallback_recovery_rate: 0.0,
                total_fallback_detect_latency_us: 42,
                average_fallback_detect_latency_us: 21,
                max_fallback_detect_latency_us: 22,
                total_promoted_detect_latency_us: 34,
                average_promoted_detect_latency_us: 17,
                max_promoted_detect_latency_us: 18,
                total_promoted_deposits: 2,
            },
            threshold_results: Vec::new(),
            recent_promoted_findings: Vec::new(),
            rollback_history: Vec::new(),
            pending_review: None,
            approval_votes: Vec::new(),
            consensus_receipt: None,
            approval_severity: None,
            quorum_gate_config: None,
        }
    }

    fn write_experiment_manifest(root: &Path, candidate: &DetectorCandidateManifest) -> PathBuf {
        let experiments_dir = root.join("experiments");
        fs::create_dir_all(&experiments_dir).unwrap();
        let path = experiments_dir.join("control.yaml");
        let raw = serde_yaml::to_string(&crate::replay::DetectorExperimentManifest {
            name: "test".to_string(),
            description: "test experiment".to_string(),
            corpus: ExperimentCorpusTarget {
                suite: "../scenario-suites/hellcat-office-v1.yaml".to_string(),
            },
            verification: ExperimentVerificationTarget {
                corpus: "../verifications/office-detector-safety-v1.yaml".to_string(),
            },
            candidate: candidate.clone(),
            lineage: ExperimentLineage {
                parent_strategy_id: "suspicious_process_tree".to_string(),
                mutation: "control".to_string(),
                rationale: "test rollout".to_string(),
            },
            gates: ExperimentGateConfig::default(),
        })
        .unwrap();
        fs::write(&path, raw).unwrap();
        path
    }

    fn suite_report(
        suite_name: &str,
        corpus_version: &str,
        _detection_rate: f64,
        _false_positive_rate: f64,
        _max_detect_latency_us: u64,
    ) -> ReplaySuiteReport {
        ReplaySuiteReport {
            source: "scenario-suites/hellcat-office-v1.yaml".to_string(),
            source_kind: ReplaySuiteSourceKind::SuiteManifest,
            suite_name: Some(suite_name.to_string()),
            suite_description: Some("test suite".to_string()),
            corpus_version: Some(corpus_version.to_string()),
            total_scenarios: 2,
            passed_scenarios: 2,
            failed_scenarios: 0,
            passed: true,
            scenario_reports: Vec::new(),
            technique_groups: Vec::new(),
        }
    }

    fn experiment_report(candidate: &DetectorCandidateManifest) -> StrategyExperimentReport {
        let baseline = StrategyExperimentMetrics {
            total_scenarios: 2,
            adversarial_scenarios: 1,
            benign_scenarios: 1,
            true_positive_scenarios: 1,
            false_negative_scenarios: 0,
            true_negative_scenarios: 1,
            false_positive_scenarios: 0,
            detection_rate: 0.80,
            false_positive_rate: 0.05,
            max_detect_latency_us: 22,
        };
        let candidate_metrics = StrategyExperimentMetrics {
            detection_rate: 0.86,
            false_positive_rate: 0.02,
            max_detect_latency_us: 18,
            ..baseline.clone()
        };
        StrategyExperimentReport {
            experiment_id: format!("experiment:test:{}", candidate.strategy_id()),
            experiment_name: "test".to_string(),
            description: "test experiment".to_string(),
            created_at_ms: 1_700_000_000_000,
            suite_name: "hellcat_office_v1".to_string(),
            suite_path: "scenario-suites/hellcat-office-v1.yaml".to_string(),
            corpus_version: "2026-04-03".to_string(),
            lineage: ExperimentLineage {
                parent_strategy_id: "suspicious_process_tree".to_string(),
                mutation: "control".to_string(),
                rationale: "test rollout".to_string(),
            },
            baseline_strategy_id: "suspicious_process_tree".to_string(),
            candidate_strategy_id: candidate.strategy_id().to_string(),
            candidate_description: candidate.description().to_string(),
            baseline_report: suite_report("hellcat_office_v1", "2026-04-03", 0.80, 0.05, 22),
            candidate_report: suite_report("hellcat_office_v1", "2026-04-03", 0.86, 0.02, 18),
            comparison: StrategyExperimentComparison {
                baseline,
                candidate: candidate_metrics,
                delta: StrategyExperimentMetricDelta {
                    detection_rate_delta: 0.06,
                    false_positive_rate_delta: -0.03,
                    max_detect_latency_delta_us: -4,
                    false_positive_scenario_delta: 0,
                },
                scenario_regressions: Vec::new(),
                technique_regressions: Vec::new(),
            },
            gates: Vec::new(),
            passed: true,
        }
    }

    fn verification_report(candidate: &DetectorCandidateManifest) -> DetectorVerificationReport {
        DetectorVerificationReport {
            verification_id: format!("verification:test:{}", candidate.strategy_id()),
            experiment_id: format!("experiment:test:{}", candidate.strategy_id()),
            experiment_name: "test".to_string(),
            corpus_name: "office-detector-safety-v1".to_string(),
            corpus_path: "verifications/office-detector-safety-v1.yaml".to_string(),
            created_at_ms: 1_700_000_000_100,
            lineage: ExperimentLineage {
                parent_strategy_id: "suspicious_process_tree".to_string(),
                mutation: "control".to_string(),
                rationale: "test rollout".to_string(),
            },
            candidate_strategy_id: candidate.strategy_id().to_string(),
            candidate_description: candidate.description().to_string(),
            invariants: Vec::new(),
            passed: true,
        }
    }

    #[test]
    fn strategy_ingests_canary_memory_by_stable_id() {
        let root = unique_temp_dir("canary-memory");
        let canaries_dir = root.join("canaries");
        let memories_dir = root.join("strategy-memory");
        let config = strategy_config();
        let candidate = control_candidate();
        let canary = ready_canary_report(&config, &candidate, 1_700_000_000_500);
        let store = FileCanaryStore::open(&canaries_dir).unwrap();
        let record = store.persist(&canary).unwrap();

        let harness = DefaultStrategyMemoryHarness::from_config(
            "rulesets/default.yaml",
            config,
            &memories_dir,
        )
        .unwrap();
        let lookup = harness
            .ingest_canary(&canaries_dir, &record.run_id)
            .unwrap();

        assert_eq!(lookup.report.source_kind, StrategyMemorySourceKind::Canary);
        assert_eq!(
            lookup.report.outcome_kind,
            StrategyMemoryOutcomeKind::ReadyForPromotionReview
        );
        assert_eq!(
            lookup.report.memory_id,
            format!("strategy_memory:canary:{}", record.run_id)
        );
        assert!(render_strategy_memory(&lookup.report).contains("Strategy Memory"));
    }

    #[test]
    fn strategy_history_sorts_latest_memory_first() {
        let root = unique_temp_dir("history");
        let canaries_dir = root.join("canaries");
        let promotions_dir = root.join("promotions");
        let memories_dir = root.join("strategy-memory");
        let config = strategy_config();
        let candidate = control_candidate();
        let canary = ready_canary_report(&config, &candidate, 1_700_000_000_500);
        let promotion = stable_promotion_report(&config, &candidate, 1_700_000_001_000);
        FileCanaryStore::open(&canaries_dir)
            .unwrap()
            .persist(&canary)
            .unwrap();
        FileProductionPromotionStore::open(&promotions_dir)
            .unwrap()
            .persist(&promotion)
            .unwrap();

        let harness = DefaultStrategyMemoryHarness::from_config(
            "rulesets/default.yaml",
            config,
            &memories_dir,
        )
        .unwrap();
        harness
            .ingest_canary(&canaries_dir, &canary.run_id)
            .unwrap();
        harness
            .ingest_promotion(&promotions_dir, &promotion.promotion_id)
            .unwrap();

        let history = harness.history(candidate.strategy_id()).unwrap();
        assert_eq!(history.memory_count, 2);
        assert_eq!(
            history.latest_rollout_state.as_ref().unwrap().outcome_kind,
            StrategyMemoryOutcomeKind::StableInProduction
        );
        assert_eq!(
            history.memories.first().unwrap().source_kind,
            StrategyMemorySourceKind::Promotion
        );
        assert!(render_strategy_memory_history(&history).contains("Strategy Memory History"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn strategy_scorecard_prefers_candidate_with_live_memories() {
        let root = unique_temp_dir("scorecard-live");
        let canaries_dir = root.join("canaries");
        let promotions_dir = root.join("promotions");
        let memories_dir = root.join("strategy-memory");
        let scorecards_dir = root.join("strategy-scorecards");
        let experiments_dir = root.join("experiments-results");
        let verifications_dir = root.join("verifications-results");
        let replay_runs_dir = root.join("replay-runs");
        let config = strategy_config();
        let candidate = control_candidate();
        let canary = ready_canary_report(&config, &candidate, 1_700_000_000_500);
        let promotion = stable_promotion_report(&config, &candidate, 1_700_000_001_000);
        FileCanaryStore::open(&canaries_dir)
            .unwrap()
            .persist(&canary)
            .unwrap();
        FileProductionPromotionStore::open(&promotions_dir)
            .unwrap()
            .persist(&promotion)
            .unwrap();
        let memory_harness = DefaultStrategyMemoryHarness::from_config(
            "rulesets/default.yaml",
            config.clone(),
            &memories_dir,
        )
        .unwrap();
        memory_harness
            .ingest_canary(&canaries_dir, &canary.run_id)
            .unwrap();
        memory_harness
            .ingest_promotion(&promotions_dir, &promotion.promotion_id)
            .unwrap();

        let experiment_path = write_experiment_manifest(&root, &candidate);
        let experiment_report = experiment_report(&candidate);
        FileExperimentStore::open(&experiments_dir)
            .unwrap()
            .persist(&experiment_report)
            .unwrap();
        let verification_report = verification_report(&candidate);
        FileVerificationStore::open(&verifications_dir)
            .unwrap()
            .persist(&verification_report)
            .unwrap();

        let replay_harness = DefaultReplayHarness::from_config(
            "rulesets/default.yaml",
            config.clone(),
            &replay_runs_dir,
        )
        .unwrap();
        let harness = DefaultStrategyScorecardHarness::from_config(
            "rulesets/default.yaml",
            config,
            &memories_dir,
            &scorecards_dir,
        )
        .unwrap();
        let lookup = harness
            .create_scorecard(
                &replay_harness,
                &experiment_path,
                &experiments_dir,
                &verifications_dir,
                &verification_report.verification_id,
            )
            .await
            .unwrap();

        assert_eq!(
            lookup.report.recommendation,
            StrategyAdvisoryRecommendation::CandidateAlreadyStableInProduction
        );
        assert_eq!(lookup.report.candidate.matching_memory_count, 2);
        assert!(!lookup.report.candidate.fallback_applied);
        let loaded = harness
            .load_scorecard(&lookup.report.scorecard_id)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.report.scorecard_id, lookup.report.scorecard_id);
        assert!(render_strategy_scorecard(&lookup.report).contains("Strategy Advisory Scorecard"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn strategy_scorecard_uses_replay_fallback_when_memory_is_sparse() {
        let root = unique_temp_dir("scorecard-fallback");
        let memories_dir = root.join("strategy-memory");
        let scorecards_dir = root.join("strategy-scorecards");
        let experiments_dir = root.join("experiments-results");
        let verifications_dir = root.join("verifications-results");
        let replay_runs_dir = root.join("replay-runs");
        let config = strategy_config();
        let candidate = control_candidate();
        let experiment_path = write_experiment_manifest(&root, &candidate);
        let experiment_report = experiment_report(&candidate);
        FileExperimentStore::open(&experiments_dir)
            .unwrap()
            .persist(&experiment_report)
            .unwrap();
        let verification_report = verification_report(&candidate);
        FileVerificationStore::open(&verifications_dir)
            .unwrap()
            .persist(&verification_report)
            .unwrap();

        let replay_harness = DefaultReplayHarness::from_config(
            "rulesets/default.yaml",
            config.clone(),
            &replay_runs_dir,
        )
        .unwrap();
        let harness = DefaultStrategyScorecardHarness::from_config(
            "rulesets/default.yaml",
            config,
            &memories_dir,
            &scorecards_dir,
        )
        .unwrap();
        let lookup = harness
            .create_scorecard(
                &replay_harness,
                &experiment_path,
                &experiments_dir,
                &verifications_dir,
                &verification_report.verification_id,
            )
            .await
            .unwrap();

        assert!(lookup.report.candidate.fallback_applied);
        assert_eq!(lookup.report.candidate.matching_memory_count, 0);
        assert!(lookup.report.baseline.fallback_applied);
    }
}
