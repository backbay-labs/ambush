use crate::config::{RuntimeConfigError, load_config};
use crate::evolution::{
    EvolutionProposalBlockingReason, EvolutionProposalProofStatus, EvolutionProposalReport,
    EvolutionProposalReviewState, EvolutionProposalStoreError, FileEvolutionProposalStore,
};
use crate::replay::{DefaultReplayHarness, ExperimentLineage, ReplayHarnessError};
use crate::strategy::{
    DefaultStrategyScorecardHarness, StrategyAdvisorError, StrategyAdvisoryRecommendation,
    StrategyMemoryOutcomeKind, StrategyRolloutStateSummary,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::SwarmConfig;

/// Errors surfaced by the selection-pressure and proposal-draft workflows.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionDraftingError {
    #[error(transparent)]
    Config(#[from] RuntimeConfigError),

    #[error(transparent)]
    Replay(#[from] ReplayHarnessError),

    #[error(transparent)]
    Strategy(#[from] StrategyAdvisorError),

    #[error(transparent)]
    PressureStore(#[from] EvolutionPressureStoreError),

    #[error(transparent)]
    DraftStore(#[from] EvolutionDraftStoreError),

    #[error(transparent)]
    DraftPromotionStore(#[from] EvolutionDraftPromotionStoreError),

    #[error(transparent)]
    ProposalStore(#[from] EvolutionProposalStoreError),

    #[error(transparent)]
    Serialization(#[from] serde_json::Error),

    #[error("experiment artifact `{experiment_id}` was not found")]
    ExperimentNotFound { experiment_id: String },

    #[error("verification artifact `{verification_id}` was not found")]
    VerificationNotFound { verification_id: String },

    #[error("strategy scorecard `{scorecard_id}` was not found")]
    ScorecardNotFound { scorecard_id: String },

    #[error("selection pressure report `{pressure_id}` was not found")]
    PressureNotFound { pressure_id: String },

    #[error("proposal draft `{draft_id}` was not found")]
    DraftNotFound { draft_id: String },

    #[error("no selection pressure was found in `{artifact}`")]
    NoSelectionPressure { artifact: String },

    #[error("proposal draft `{draft_id}` was already promoted into queue proposal `{proposal_id}`")]
    DraftAlreadyPromoted {
        draft_id: String,
        proposal_id: String,
    },
}

/// Source evidence category for one durable pressure report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionPressureSourceKind {
    ReplayRegression,
    VerificationDrift,
    StrategyMemoryGap,
}

/// Stable reference to one source artifact preserved on a pressure report or draft.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionPressureArtifactRef {
    pub kind: String,
    pub id: String,
    pub summary: String,
}

/// One evidence-backed signal explaining why more detector work is warranted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionPressureSignal {
    pub name: String,
    pub details: String,
    pub references: Vec<String>,
}

/// Durable off-hot-path report showing pressure to draft more detector work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionPressureReport {
    pub pressure_id: String,
    pub created_at_ms: i64,
    pub source_kind: EvolutionPressureSourceKind,
    pub experiment_id: Option<String>,
    pub experiment_name: Option<String>,
    pub strategy_id: String,
    pub strategy_description: String,
    pub parent_strategy_id: String,
    pub lineage: Option<ExperimentLineage>,
    pub summary: String,
    pub rationale: String,
    pub source_artifacts: Vec<EvolutionPressureArtifactRef>,
    pub signals: Vec<EvolutionPressureSignal>,
}

/// Metadata surfaced for one persisted pressure report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionPressureRecord {
    pub pressure_id: String,
    pub source_kind: EvolutionPressureSourceKind,
    pub strategy_id: String,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl EvolutionPressureRecord {
    fn from_report(report: &EvolutionPressureReport, bundle_path: String) -> Self {
        Self {
            pressure_id: report.pressure_id.clone(),
            source_kind: report.source_kind,
            strategy_id: report.strategy_id.clone(),
            created_at_ms: report.created_at_ms,
            bundle_path,
        }
    }
}

/// Persisted pressure report loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionPressureLookup {
    pub record: EvolutionPressureRecord,
    pub report: EvolutionPressureReport,
}

/// Operator-supplied hints used to package one proposal draft.
#[derive(Debug, Clone)]
pub struct EvolutionDraftCreateRequest {
    pub pressure_id: String,
    pub strategy_id: String,
    pub strategy_description: String,
    pub mutation: String,
    pub rationale: String,
}

/// Durable draft artifact derived from one pressure report plus explicit operator hints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionDraftReport {
    pub draft_id: String,
    pub pressure_id: String,
    pub created_at_ms: i64,
    pub source_kind: EvolutionPressureSourceKind,
    pub pressure_summary: String,
    pub parent_strategy_id: String,
    pub strategy_id: String,
    pub strategy_description: String,
    pub lineage_mutation: String,
    pub lineage_rationale: String,
    pub source_artifacts: Vec<EvolutionPressureArtifactRef>,
    pub signal_names: Vec<String>,
}

/// Metadata surfaced for one persisted draft artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionDraftRecord {
    pub draft_id: String,
    pub pressure_id: String,
    pub strategy_id: String,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl EvolutionDraftRecord {
    fn from_report(report: &EvolutionDraftReport, bundle_path: String) -> Self {
        Self {
            draft_id: report.draft_id.clone(),
            pressure_id: report.pressure_id.clone(),
            strategy_id: report.strategy_id.clone(),
            created_at_ms: report.created_at_ms,
            bundle_path,
        }
    }
}

/// Persisted draft artifact loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionDraftLookup {
    pub record: EvolutionDraftRecord,
    pub report: EvolutionDraftReport,
}

/// Durable record tying one draft to the resulting reviewed queue entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionDraftPromotionReport {
    pub promotion_id: String,
    pub created_at_ms: i64,
    pub draft_id: String,
    pub pressure_id: String,
    pub strategy_id: String,
    pub queue_proposal_id: String,
    pub queue_review_state: EvolutionProposalReviewState,
    pub operator_reason: String,
}

/// Metadata surfaced for one persisted draft-promotion record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionDraftPromotionRecord {
    pub promotion_id: String,
    pub draft_id: String,
    pub pressure_id: String,
    pub queue_proposal_id: String,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl EvolutionDraftPromotionRecord {
    fn from_report(report: &EvolutionDraftPromotionReport, bundle_path: String) -> Self {
        Self {
            promotion_id: report.promotion_id.clone(),
            draft_id: report.draft_id.clone(),
            pressure_id: report.pressure_id.clone(),
            queue_proposal_id: report.queue_proposal_id.clone(),
            created_at_ms: report.created_at_ms,
            bundle_path,
        }
    }
}

/// Persisted draft-promotion record loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionDraftPromotionLookup {
    pub record: EvolutionDraftPromotionRecord,
    pub report: EvolutionDraftPromotionReport,
}

/// Errors raised by the persisted pressure store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionPressureStoreError {
    #[error("failed to read evolution pressure store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution pressure store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution pressure store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised by the persisted draft store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionDraftStoreError {
    #[error("failed to read evolution draft store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution draft store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution draft store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised by the persisted draft-promotion store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionDraftPromotionStoreError {
    #[error("failed to read evolution draft promotion store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution draft promotion store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution draft promotion store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// File-backed store for durable selection-pressure reports.
#[derive(Debug, Clone)]
pub struct FileEvolutionPressureStore {
    root: PathBuf,
}

impl FileEvolutionPressureStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionPressureStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionPressureStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, pressure_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(pressure_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<EvolutionPressureIndex, EvolutionPressureStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionPressureIndex::default());
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| EvolutionPressureStoreError::Read {
                path: path.clone(),
                source,
            })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionPressureStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionPressureIndex,
    ) -> Result<(), EvolutionPressureStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionPressureStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionPressureStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionPressureReport,
    ) -> Result<EvolutionPressureRecord, EvolutionPressureStoreError> {
        let path = self.report_path(&report.pressure_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionPressureStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionPressureStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = EvolutionPressureRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.pressure_id != record.pressure_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        pressure_id: &str,
    ) -> Result<Option<EvolutionPressureLookup>, EvolutionPressureStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.pressure_id == pressure_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw =
            fs::read_to_string(&path).map_err(|source| EvolutionPressureStoreError::Read {
                path: path.clone(),
                source,
            })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionPressureStoreError::Parse { path, source })?;
        Ok(Some(EvolutionPressureLookup { record, report }))
    }
}

/// File-backed store for durable proposal drafts.
#[derive(Debug, Clone)]
pub struct FileEvolutionDraftStore {
    root: PathBuf,
}

impl FileEvolutionDraftStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionDraftStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionDraftStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, draft_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(draft_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<EvolutionDraftIndex, EvolutionDraftStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionDraftIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| EvolutionDraftStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionDraftStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &EvolutionDraftIndex) -> Result<(), EvolutionDraftStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionDraftStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionDraftStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionDraftReport,
    ) -> Result<EvolutionDraftRecord, EvolutionDraftStoreError> {
        let path = self.report_path(&report.draft_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionDraftStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionDraftStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = EvolutionDraftRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.draft_id != record.draft_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        draft_id: &str,
    ) -> Result<Option<EvolutionDraftLookup>, EvolutionDraftStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.draft_id == draft_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| EvolutionDraftStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionDraftStoreError::Parse { path, source })?;
        Ok(Some(EvolutionDraftLookup { record, report }))
    }
}

/// File-backed store for durable draft-promotion records.
#[derive(Debug, Clone)]
pub struct FileEvolutionDraftPromotionStore {
    root: PathBuf,
}

impl FileEvolutionDraftPromotionStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionDraftPromotionStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionDraftPromotionStoreError::Write {
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

    fn read_index(
        &self,
    ) -> Result<EvolutionDraftPromotionIndex, EvolutionDraftPromotionStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionDraftPromotionIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionDraftPromotionStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionDraftPromotionStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionDraftPromotionIndex,
    ) -> Result<(), EvolutionDraftPromotionStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionDraftPromotionStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| EvolutionDraftPromotionStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionDraftPromotionReport,
    ) -> Result<EvolutionDraftPromotionRecord, EvolutionDraftPromotionStoreError> {
        let path = self.report_path(&report.promotion_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionDraftPromotionStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionDraftPromotionStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = EvolutionDraftPromotionRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.promotion_id != record.promotion_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        promotion_id: &str,
    ) -> Result<Option<EvolutionDraftPromotionLookup>, EvolutionDraftPromotionStoreError> {
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
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionDraftPromotionStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionDraftPromotionStoreError::Parse { path, source })?;
        Ok(Some(EvolutionDraftPromotionLookup { record, report }))
    }

    pub fn load_for_draft(
        &self,
        draft_id: &str,
    ) -> Result<Option<EvolutionDraftPromotionLookup>, EvolutionDraftPromotionStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.draft_id == draft_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionDraftPromotionStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionDraftPromotionStoreError::Parse { path, source })?;
        Ok(Some(EvolutionDraftPromotionLookup { record, report }))
    }
}

/// Harness for off-hot-path selection pressure, draft packaging, and queue promotion.
pub struct DefaultEvolutionDraftingHarness {
    pub config_path: PathBuf,
    pub config: SwarmConfig,
    pub pressure_store: FileEvolutionPressureStore,
    pub draft_store: FileEvolutionDraftStore,
    pub promotion_store: FileEvolutionDraftPromotionStore,
}

impl DefaultEvolutionDraftingHarness {
    pub fn from_path(
        config_path: impl AsRef<Path>,
        pressure_results_dir: impl AsRef<Path>,
        draft_results_dir: impl AsRef<Path>,
        promotion_results_dir: impl AsRef<Path>,
    ) -> Result<Self, EvolutionDraftingError> {
        let config_path = config_path.as_ref();
        let config = load_config(config_path)?;
        Self::from_config(
            config_path,
            config,
            pressure_results_dir,
            draft_results_dir,
            promotion_results_dir,
        )
    }

    pub fn from_config(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
        pressure_results_dir: impl AsRef<Path>,
        draft_results_dir: impl AsRef<Path>,
        promotion_results_dir: impl AsRef<Path>,
    ) -> Result<Self, EvolutionDraftingError> {
        Ok(Self {
            config_path: config_path.into(),
            config,
            pressure_store: FileEvolutionPressureStore::open(pressure_results_dir)?,
            draft_store: FileEvolutionDraftStore::open(draft_results_dir)?,
            promotion_store: FileEvolutionDraftPromotionStore::open(promotion_results_dir)?,
        })
    }

    pub fn create_pressure_from_experiment(
        &self,
        replay_harness: &DefaultReplayHarness,
        experiment_results_dir: impl AsRef<Path>,
        experiment_id: &str,
    ) -> Result<EvolutionPressureLookup, EvolutionDraftingError> {
        let experiment = replay_harness
            .load_experiment(experiment_results_dir, experiment_id)?
            .ok_or_else(|| EvolutionDraftingError::ExperimentNotFound {
                experiment_id: experiment_id.to_string(),
            })?;
        let report = pressure_from_experiment(&experiment.report)?;
        let record = self.pressure_store.persist(&report)?;
        Ok(EvolutionPressureLookup { record, report })
    }

    pub fn create_pressure_from_verification(
        &self,
        replay_harness: &DefaultReplayHarness,
        verification_results_dir: impl AsRef<Path>,
        verification_id: &str,
    ) -> Result<EvolutionPressureLookup, EvolutionDraftingError> {
        let verification = replay_harness
            .load_verification(verification_results_dir, verification_id)?
            .ok_or_else(|| EvolutionDraftingError::VerificationNotFound {
                verification_id: verification_id.to_string(),
            })?;
        let report = pressure_from_verification(&verification.report)?;
        let record = self.pressure_store.persist(&report)?;
        Ok(EvolutionPressureLookup { record, report })
    }

    pub fn create_pressure_from_scorecard(
        &self,
        scorecard_harness: &DefaultStrategyScorecardHarness,
        scorecard_id: &str,
    ) -> Result<EvolutionPressureLookup, EvolutionDraftingError> {
        let scorecard = scorecard_harness
            .load_scorecard(scorecard_id)?
            .ok_or_else(|| EvolutionDraftingError::ScorecardNotFound {
                scorecard_id: scorecard_id.to_string(),
            })?;
        let report = pressure_from_scorecard(&scorecard.report)?;
        let record = self.pressure_store.persist(&report)?;
        Ok(EvolutionPressureLookup { record, report })
    }

    pub fn load_pressure(
        &self,
        pressure_id: &str,
    ) -> Result<Option<EvolutionPressureLookup>, EvolutionDraftingError> {
        Ok(self.pressure_store.load(pressure_id)?)
    }

    pub fn create_draft(
        &self,
        request: EvolutionDraftCreateRequest,
    ) -> Result<EvolutionDraftLookup, EvolutionDraftingError> {
        let pressure = self
            .pressure_store
            .load(&request.pressure_id)?
            .ok_or_else(|| EvolutionDraftingError::PressureNotFound {
                pressure_id: request.pressure_id.clone(),
            })?;
        let created_at_ms = now_ms();
        let report = EvolutionDraftReport {
            draft_id: draft_id(&request.strategy_id, created_at_ms),
            pressure_id: pressure.report.pressure_id.clone(),
            created_at_ms,
            source_kind: pressure.report.source_kind,
            pressure_summary: pressure.report.summary.clone(),
            parent_strategy_id: pressure.report.parent_strategy_id.clone(),
            strategy_id: request.strategy_id,
            strategy_description: request.strategy_description,
            lineage_mutation: request.mutation,
            lineage_rationale: request.rationale,
            source_artifacts: pressure.report.source_artifacts.clone(),
            signal_names: pressure
                .report
                .signals
                .iter()
                .map(|signal| signal.name.clone())
                .collect(),
        };
        let record = self.draft_store.persist(&report)?;
        Ok(EvolutionDraftLookup { record, report })
    }

    pub fn load_draft(
        &self,
        draft_id: &str,
    ) -> Result<Option<EvolutionDraftLookup>, EvolutionDraftingError> {
        Ok(self.draft_store.load(draft_id)?)
    }

    pub fn promote_draft(
        &self,
        queue_results_dir: impl AsRef<Path>,
        draft_id: &str,
        reason: &str,
    ) -> Result<EvolutionDraftPromotionLookup, EvolutionDraftingError> {
        if let Some(existing) = self.promotion_store.load_for_draft(draft_id)? {
            return Err(EvolutionDraftingError::DraftAlreadyPromoted {
                draft_id: draft_id.to_string(),
                proposal_id: existing.report.queue_proposal_id,
            });
        }

        let draft = self.draft_store.load(draft_id)?.ok_or_else(|| {
            EvolutionDraftingError::DraftNotFound {
                draft_id: draft_id.to_string(),
            }
        })?;
        let queue_store = FileEvolutionProposalStore::open(queue_results_dir)?;
        let created_at_ms = now_ms();
        let queue_report = EvolutionProposalReport {
            proposal_id: queue_proposal_id(&draft.report.strategy_id, created_at_ms),
            experiment_id: format!(
                "draft_experiment:{}:{}",
                draft.report.strategy_id, created_at_ms
            ),
            experiment_name: format!("draft-{}", draft.report.strategy_id),
            experiment_path: String::new(),
            created_at_ms,
            strategy_id: draft.report.strategy_id.clone(),
            strategy_description: draft.report.strategy_description.clone(),
            lineage: ExperimentLineage {
                parent_strategy_id: draft.report.parent_strategy_id.clone(),
                mutation: draft.report.lineage_mutation.clone(),
                rationale: draft.report.lineage_rationale.clone(),
            },
            verification_id: None,
            verification_passed: false,
            proof_status: EvolutionProposalProofStatus::Missing,
            proof: None,
            advisory: None,
            review_state: EvolutionProposalReviewState::PendingReview,
            blocking_reasons: vec![EvolutionProposalBlockingReason {
                source: "draft".to_string(),
                name: "requires_materialized_experiment_and_proof".to_string(),
                details: "draft promotion creates a reviewed queue entry only; experiment, verification, proof, and shadow evidence must still be produced before canary admission".to_string(),
                references: vec![
                    draft.report.draft_id.clone(),
                    draft.report.pressure_id.clone(),
                ],
            }],
            decision_history: Vec::new(),
        };
        let queue_record = queue_store.persist(&queue_report)?;
        let promotion_report = EvolutionDraftPromotionReport {
            promotion_id: draft_promotion_id(&draft.report.draft_id, created_at_ms),
            created_at_ms,
            draft_id: draft.report.draft_id.clone(),
            pressure_id: draft.report.pressure_id.clone(),
            strategy_id: draft.report.strategy_id.clone(),
            queue_proposal_id: queue_record.proposal_id.clone(),
            queue_review_state: queue_report.review_state,
            operator_reason: reason.to_string(),
        };
        let record = self.promotion_store.persist(&promotion_report)?;
        Ok(EvolutionDraftPromotionLookup {
            record,
            report: promotion_report,
        })
    }

    pub fn load_draft_promotion(
        &self,
        promotion_id: &str,
    ) -> Result<Option<EvolutionDraftPromotionLookup>, EvolutionDraftingError> {
        Ok(self.promotion_store.load(promotion_id)?)
    }
}

/// Render one durable selection-pressure report.
pub fn render_evolution_pressure(report: &EvolutionPressureReport) -> String {
    let mut lines = vec![
        "Evolution Selection Pressure".to_string(),
        format!("Pressure ID: {}", report.pressure_id),
        format!("Source: {}", pressure_source_label(report.source_kind)),
        format!(
            "Strategy: {} | {}",
            report.strategy_id, report.strategy_description
        ),
        format!("Parent strategy: {}", report.parent_strategy_id),
        format!("Summary: {}", report.summary),
        format!("Rationale: {}", report.rationale),
    ];

    if let Some(experiment_id) = &report.experiment_id {
        lines.push(format!(
            "Experiment: {} ({})",
            report.experiment_name.as_deref().unwrap_or("unknown"),
            experiment_id
        ));
    }

    lines.push("Source artifacts:".to_string());
    for artifact in &report.source_artifacts {
        lines.push(format!(
            "- {} {} | {}",
            artifact.kind, artifact.id, artifact.summary
        ));
    }

    lines.push("Signals:".to_string());
    for signal in &report.signals {
        lines.push(format!(
            "- {} | {} | refs={}",
            signal.name,
            signal.details,
            if signal.references.is_empty() {
                "none".to_string()
            } else {
                signal.references.join(",")
            }
        ));
    }

    lines.join("\n")
}

/// Render one durable proposal draft.
pub fn render_evolution_draft(report: &EvolutionDraftReport) -> String {
    let mut lines = vec![
        "Evolution Proposal Draft".to_string(),
        format!("Draft ID: {}", report.draft_id),
        format!("Pressure ID: {}", report.pressure_id),
        format!(
            "Strategy hint: {} | {}",
            report.strategy_id, report.strategy_description
        ),
        format!("Parent strategy: {}", report.parent_strategy_id),
        format!(
            "Pressure source: {}",
            pressure_source_label(report.source_kind)
        ),
        format!("Pressure summary: {}", report.pressure_summary),
        format!(
            "Lineage hint: mutation={} rationale={}",
            report.lineage_mutation, report.lineage_rationale
        ),
    ];

    if report.signal_names.is_empty() {
        lines.push("Signals: none".to_string());
    } else {
        lines.push(format!("Signals: {}", report.signal_names.join(", ")));
    }

    lines.push("Source artifacts:".to_string());
    for artifact in &report.source_artifacts {
        lines.push(format!(
            "- {} {} | {}",
            artifact.kind, artifact.id, artifact.summary
        ));
    }

    lines.join("\n")
}

/// Render one draft-promotion record.
pub fn render_evolution_draft_promotion(report: &EvolutionDraftPromotionReport) -> String {
    [
        "Evolution Draft Promotion".to_string(),
        format!("Promotion ID: {}", report.promotion_id),
        format!("Draft ID: {}", report.draft_id),
        format!("Pressure ID: {}", report.pressure_id),
        format!("Strategy: {}", report.strategy_id),
        format!("Queue proposal: {}", report.queue_proposal_id),
        format!("Queue state: {:?}", report.queue_review_state),
        format!("Operator reason: {}", report.operator_reason),
    ]
    .join("\n")
}

fn pressure_from_experiment(
    report: &crate::replay::StrategyExperimentReport,
) -> Result<EvolutionPressureReport, EvolutionDraftingError> {
    let mut signals = report
        .gates
        .iter()
        .filter(|gate| !gate.passed)
        .map(|gate| EvolutionPressureSignal {
            name: format!("failed_gate_{}", gate.name),
            details: gate.details.clone(),
            references: vec![report.experiment_id.clone()],
        })
        .collect::<Vec<_>>();

    signals.extend(
        report
            .comparison
            .technique_regressions
            .iter()
            .map(|regression| EvolutionPressureSignal {
                name: format!("technique_regression_{}", regression.technique),
                details: format!(
                    "candidate regressed on {} scenario(s) for technique `{}`",
                    regression.scenarios.len(),
                    regression.technique
                ),
                references: regression.scenarios.clone(),
            }),
    );

    signals.extend(
        report
            .comparison
            .scenario_regressions
            .iter()
            .map(|regression| EvolutionPressureSignal {
                name: format!("scenario_regression_{}", regression.scenario_name),
                details: regression.reason.clone(),
                references: vec![regression.scenario_path.clone()],
            }),
    );

    if signals.is_empty() && report.passed {
        return Err(EvolutionDraftingError::NoSelectionPressure {
            artifact: report.experiment_id.clone(),
        });
    }

    let created_at_ms = now_ms();
    let failed_gate_count = report.gates.iter().filter(|gate| !gate.passed).count();
    let regression_count = report.comparison.scenario_regressions.len();
    Ok(EvolutionPressureReport {
        pressure_id: pressure_id(
            EvolutionPressureSourceKind::ReplayRegression,
            &report.candidate_strategy_id,
            created_at_ms,
        ),
        created_at_ms,
        source_kind: EvolutionPressureSourceKind::ReplayRegression,
        experiment_id: Some(report.experiment_id.clone()),
        experiment_name: Some(report.experiment_name.clone()),
        strategy_id: report.candidate_strategy_id.clone(),
        strategy_description: report.candidate_description.clone(),
        parent_strategy_id: report.lineage.parent_strategy_id.clone(),
        lineage: Some(report.lineage.clone()),
        summary: format!(
            "{} replay regression(s), {} failed gate(s), detection delta={:.3}",
            regression_count, failed_gate_count, report.comparison.delta.detection_rate_delta
        ),
        rationale: format!(
            "Replay evidence shows regressions for `{}` across suite `{}` and justifies another detector draft.",
            report.candidate_strategy_id, report.suite_name
        ),
        source_artifacts: vec![EvolutionPressureArtifactRef {
            kind: "experiment".to_string(),
            id: report.experiment_id.clone(),
            summary: format!(
                "suite={} corpus={} passed={}",
                report.suite_name, report.corpus_version, report.passed
            ),
        }],
        signals,
    })
}

fn pressure_from_verification(
    report: &crate::replay::DetectorVerificationReport,
) -> Result<EvolutionPressureReport, EvolutionDraftingError> {
    let signals = report
        .invariants
        .iter()
        .filter(|invariant| !invariant.passed)
        .map(|invariant| EvolutionPressureSignal {
            name: format!("verification_drift_{}", invariant.name),
            details: invariant.details.clone(),
            references: invariant
                .counterexamples
                .iter()
                .map(|counterexample| counterexample.reference.clone())
                .collect(),
        })
        .collect::<Vec<_>>();

    if signals.is_empty() && report.passed {
        return Err(EvolutionDraftingError::NoSelectionPressure {
            artifact: report.verification_id.clone(),
        });
    }

    let counterexample_count = report
        .invariants
        .iter()
        .filter(|invariant| !invariant.passed)
        .map(|invariant| invariant.counterexamples.len())
        .sum::<usize>();
    let created_at_ms = now_ms();
    Ok(EvolutionPressureReport {
        pressure_id: pressure_id(
            EvolutionPressureSourceKind::VerificationDrift,
            &report.candidate_strategy_id,
            created_at_ms,
        ),
        created_at_ms,
        source_kind: EvolutionPressureSourceKind::VerificationDrift,
        experiment_id: Some(report.experiment_id.clone()),
        experiment_name: Some(report.experiment_name.clone()),
        strategy_id: report.candidate_strategy_id.clone(),
        strategy_description: report.candidate_description.clone(),
        parent_strategy_id: report.lineage.parent_strategy_id.clone(),
        lineage: Some(report.lineage.clone()),
        summary: format!(
            "{} failing invariant(s), {} counterexample(s)",
            signals.len(),
            counterexample_count
        ),
        rationale: format!(
            "Verification drift for `{}` broke tracked invariants in corpus `{}` and warrants another draft.",
            report.candidate_strategy_id, report.corpus_name
        ),
        source_artifacts: vec![EvolutionPressureArtifactRef {
            kind: "verification".to_string(),
            id: report.verification_id.clone(),
            summary: format!("corpus={} passed={}", report.corpus_name, report.passed),
        }],
        signals,
    })
}

fn pressure_from_scorecard(
    report: &crate::strategy::StrategyScorecard,
) -> Result<EvolutionPressureReport, EvolutionDraftingError> {
    let mut signals = Vec::new();

    if report.candidate.fallback_applied || report.candidate.matching_memory_count == 0 {
        signals.push(EvolutionPressureSignal {
            name: "insufficient_live_memory".to_string(),
            details: format!(
                "candidate only has {} matching live memory record(s); advisory fallback remained active",
                report.candidate.matching_memory_count
            ),
            references: report
                .candidate
                .contributions
                .iter()
                .map(|contribution| contribution.memory_id.clone())
                .collect(),
        });
    }

    if matches!(
        rollout_outcome(report.candidate.latest_rollout_state.as_ref()),
        Some(StrategyMemoryOutcomeKind::Blocked | StrategyMemoryOutcomeKind::Halted)
    ) {
        signals.push(EvolutionPressureSignal {
            name: "negative_live_rollout_signal".to_string(),
            details: format!(
                "latest rollout state is `{}`",
                rollout_outcome_label(report.candidate.latest_rollout_state.as_ref())
            ),
            references: report
                .candidate
                .latest_rollout_state
                .as_ref()
                .map(|state| vec![state.source_artifact_id.clone()])
                .unwrap_or_default(),
        });
    }

    if matches!(
        report.recommendation,
        StrategyAdvisoryRecommendation::RetainBaseline
    ) && report.score_delta <= 0.0
    {
        signals.push(EvolutionPressureSignal {
            name: "candidate_outscored_by_baseline".to_string(),
            details: format!(
                "candidate final score {:.3} did not exceed baseline {:.3}",
                report.candidate.final_score, report.baseline.final_score
            ),
            references: vec![report.scorecard_id.clone()],
        });
    }

    if signals.is_empty() {
        return Err(EvolutionDraftingError::NoSelectionPressure {
            artifact: report.scorecard_id.clone(),
        });
    }

    let mut source_artifacts = vec![EvolutionPressureArtifactRef {
        kind: "scorecard".to_string(),
        id: report.scorecard_id.clone(),
        summary: format!(
            "recommendation={:?} score_delta={:.3}",
            report.recommendation, report.score_delta
        ),
    }];
    for contribution in &report.candidate.contributions {
        source_artifacts.push(EvolutionPressureArtifactRef {
            kind: "strategy_memory".to_string(),
            id: contribution.memory_id.clone(),
            summary: contribution.summary.clone(),
        });
    }
    if let Some(latest) = &report.candidate.latest_rollout_state {
        source_artifacts.push(EvolutionPressureArtifactRef {
            kind: "latest_rollout".to_string(),
            id: latest.source_artifact_id.clone(),
            summary: format!(
                "outcome={} source={}",
                rollout_outcome_label(Some(latest)),
                rollout_source_label(latest)
            ),
        });
    }

    let created_at_ms = now_ms();
    Ok(EvolutionPressureReport {
        pressure_id: pressure_id(
            EvolutionPressureSourceKind::StrategyMemoryGap,
            &report.candidate_strategy_id,
            created_at_ms,
        ),
        created_at_ms,
        source_kind: EvolutionPressureSourceKind::StrategyMemoryGap,
        experiment_id: Some(report.experiment_id.clone()),
        experiment_name: Some(report.experiment_name.clone()),
        strategy_id: report.candidate_strategy_id.clone(),
        strategy_description: report.candidate_description.clone(),
        parent_strategy_id: report.lineage.parent_strategy_id.clone(),
        lineage: Some(report.lineage.clone()),
        summary: format!(
            "matching_memories={} fallback_applied={} recommendation={:?}",
            report.candidate.matching_memory_count,
            report.candidate.fallback_applied,
            report.recommendation
        ),
        rationale: format!(
            "Strategy memory for `{}` is sparse or unfavorable in context `{}` / `{}`, so another draft should be reviewed before queue admission.",
            report.candidate_strategy_id, report.suite_name, report.corpus_version
        ),
        source_artifacts,
        signals,
    })
}

fn pressure_source_label(kind: EvolutionPressureSourceKind) -> &'static str {
    match kind {
        EvolutionPressureSourceKind::ReplayRegression => "replay_regression",
        EvolutionPressureSourceKind::VerificationDrift => "verification_drift",
        EvolutionPressureSourceKind::StrategyMemoryGap => "strategy_memory_gap",
    }
}

fn rollout_source_label(summary: &StrategyRolloutStateSummary) -> &'static str {
    match summary.source_kind {
        crate::strategy::StrategyMemorySourceKind::Canary => "canary",
        crate::strategy::StrategyMemorySourceKind::Promotion => "promotion",
    }
}

fn rollout_outcome(
    latest_rollout_state: Option<&StrategyRolloutStateSummary>,
) -> Option<StrategyMemoryOutcomeKind> {
    latest_rollout_state.map(|state| state.outcome_kind)
}

fn rollout_outcome_label(
    latest_rollout_state: Option<&StrategyRolloutStateSummary>,
) -> &'static str {
    match rollout_outcome(latest_rollout_state) {
        Some(StrategyMemoryOutcomeKind::ReadyForPromotionReview) => "ready_for_promotion_review",
        Some(StrategyMemoryOutcomeKind::StableInProduction) => "stable_in_production",
        Some(StrategyMemoryOutcomeKind::Blocked) => "blocked",
        Some(StrategyMemoryOutcomeKind::Halted) => "halted",
        None => "none",
    }
}

fn pressure_id(
    source_kind: EvolutionPressureSourceKind,
    strategy_id: &str,
    created_at_ms: i64,
) -> String {
    format!(
        "evolution_pressure:{}:{}:{}",
        pressure_source_label(source_kind),
        strategy_id,
        created_at_ms
    )
}

fn draft_id(strategy_id: &str, created_at_ms: i64) -> String {
    format!("evolution_draft:{}:{}", strategy_id, created_at_ms)
}

fn queue_proposal_id(strategy_id: &str, created_at_ms: i64) -> String {
    format!("evolution_proposal:draft:{}:{}", strategy_id, created_at_ms)
}

fn draft_promotion_id(draft_id: &str, created_at_ms: i64) -> String {
    format!(
        "evolution_draft_promotion:{}:{}",
        sanitize_id(draft_id),
        created_at_ms
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
struct EvolutionPressureIndex {
    entries: Vec<EvolutionPressureRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct EvolutionDraftIndex {
    entries: Vec<EvolutionDraftRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct EvolutionDraftPromotionIndex {
    entries: Vec<EvolutionDraftPromotionRecord>,
}

#[cfg(test)]
mod tests {
    use super::{
        DefaultEvolutionDraftingHarness, EvolutionDraftCreateRequest, EvolutionDraftingError,
        EvolutionPressureSourceKind, render_evolution_draft, render_evolution_draft_promotion,
        render_evolution_pressure,
    };
    use crate::evolution::FileEvolutionProposalStore;
    use crate::replay::DefaultReplayHarness;
    use crate::strategy::DefaultStrategyScorecardHarness;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use swarm_core::config::SwarmConfig;

    fn sample_config() -> SwarmConfig {
        serde_yaml::from_str(include_str!("../../../rulesets/default.yaml")).unwrap()
    }

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf()
    }

    fn office_control_experiment() -> PathBuf {
        repo_root().join("experiments/office-baseline-control.yaml")
    }

    fn office_broadening_experiment() -> PathBuf {
        repo_root().join("experiments/office-python-parent-broadening.yaml")
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "swarm-runtime-drafting-{label}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[tokio::test]
    async fn replay_regression_pressure_persists() {
        let root = unique_temp_dir("pressure-replay");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let pressure_dir = root.join("pressures");
        let draft_dir = root.join("drafts");
        let promotion_dir = root.join("promotions");
        let config = sample_config();
        let replay =
            DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
        let experiment = replay
            .evaluate_experiment_path(office_broadening_experiment(), &experiment_dir)
            .await
            .unwrap();
        let harness = DefaultEvolutionDraftingHarness::from_config(
            "inline",
            config,
            &pressure_dir,
            &draft_dir,
            &promotion_dir,
        )
        .unwrap();

        let lookup = harness
            .create_pressure_from_experiment(
                &replay,
                &experiment_dir,
                &experiment.report.experiment_id,
            )
            .unwrap();

        assert_eq!(
            lookup.report.source_kind,
            EvolutionPressureSourceKind::ReplayRegression
        );
        assert!(!lookup.report.signals.is_empty());
        assert!(render_evolution_pressure(&lookup.report).contains("Evolution Selection Pressure"));
    }

    #[tokio::test]
    async fn verification_drift_pressure_persists() {
        let root = unique_temp_dir("pressure-verification");
        let replay_dir = root.join("replay");
        let verification_dir = root.join("verifications");
        let pressure_dir = root.join("pressures");
        let draft_dir = root.join("drafts");
        let promotion_dir = root.join("promotions");
        let config = sample_config();
        let replay =
            DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
        let verification = replay
            .evaluate_verification_path(office_broadening_experiment(), &verification_dir)
            .await
            .unwrap();
        let harness = DefaultEvolutionDraftingHarness::from_config(
            "inline",
            config,
            &pressure_dir,
            &draft_dir,
            &promotion_dir,
        )
        .unwrap();

        let lookup = harness
            .create_pressure_from_verification(
                &replay,
                &verification_dir,
                &verification.report.verification_id,
            )
            .unwrap();

        assert_eq!(
            lookup.report.source_kind,
            EvolutionPressureSourceKind::VerificationDrift
        );
        assert!(
            lookup
                .report
                .signals
                .iter()
                .any(|signal| signal.name.contains("verification_drift"))
        );
    }

    #[tokio::test]
    async fn draft_promotion_creates_pending_queue_entry() {
        let root = unique_temp_dir("draft-promotion");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verifications");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let pressure_dir = root.join("pressures");
        let draft_dir = root.join("drafts");
        let draft_promotion_dir = root.join("draft-promotions");
        let queue_dir = root.join("queue");
        let config = sample_config();
        let replay =
            DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
        let verification = replay
            .evaluate_verification_path(office_control_experiment(), &verification_dir)
            .await
            .unwrap();
        let scorecards = DefaultStrategyScorecardHarness::from_config(
            "inline",
            config.clone(),
            &memory_dir,
            &scorecard_dir,
        )
        .unwrap();
        let scorecard = scorecards
            .create_scorecard(
                &replay,
                office_control_experiment(),
                &experiment_dir,
                &verification_dir,
                &verification.report.verification_id,
            )
            .await
            .unwrap();
        let harness = DefaultEvolutionDraftingHarness::from_config(
            "inline",
            config,
            &pressure_dir,
            &draft_dir,
            &draft_promotion_dir,
        )
        .unwrap();

        let pressure = harness
            .create_pressure_from_scorecard(&scorecards, &scorecard.report.scorecard_id)
            .unwrap();
        let draft = harness
            .create_draft(EvolutionDraftCreateRequest {
                pressure_id: pressure.report.pressure_id.clone(),
                strategy_id: "office_memory_followup_v1".to_string(),
                strategy_description: "tighten process ancestry while keeping office controls"
                    .to_string(),
                mutation: "memory_gap_followup".to_string(),
                rationale: "scorecard fell back to replay because live evidence is sparse"
                    .to_string(),
            })
            .unwrap();
        let promotion = harness
            .promote_draft(
                &queue_dir,
                &draft.report.draft_id,
                "queue for explicit operator review",
            )
            .unwrap();
        let queue_store = FileEvolutionProposalStore::open(&queue_dir).unwrap();
        let queue_lookup = queue_store
            .load(&promotion.report.queue_proposal_id)
            .unwrap()
            .unwrap();

        assert_eq!(
            queue_lookup.report.review_state,
            crate::evolution::EvolutionProposalReviewState::PendingReview
        );
        assert_eq!(
            queue_lookup.report.proof_status,
            crate::evolution::EvolutionProposalProofStatus::Missing
        );
        assert!(!queue_lookup.report.blocking_reasons.is_empty());
        assert!(render_evolution_draft(&draft.report).contains("Evolution Proposal Draft"));
        assert!(
            render_evolution_draft_promotion(&promotion.report)
                .contains("Evolution Draft Promotion")
        );

        let duplicate = harness.promote_draft(
            &queue_dir,
            &draft.report.draft_id,
            "repeat queue promotion should fail",
        );
        assert!(matches!(
            duplicate,
            Err(EvolutionDraftingError::DraftAlreadyPromoted { .. })
        ));
    }
}
