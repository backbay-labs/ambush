use crate::config::{RuntimeConfigError, load_config};
use crate::evolution::{
    DefaultEvolutionProofHarness, EvolutionProposalAdvisorySummary,
    EvolutionProposalBlockingReason, EvolutionProposalProofStatus, EvolutionProposalProofSummary,
    EvolutionProposalReport, EvolutionProposalReviewState, EvolutionProposalStoreError,
    FileEvolutionProposalStore,
};
use crate::replay::{
    DefaultReplayHarness, DetectorCandidateManifest, DetectorExperimentManifest, ExperimentLineage,
    ReplayHarnessError, load_detector_experiment_manifest,
};
use crate::strategy::{
    DefaultStrategyScorecardHarness, StrategyAdvisorError, StrategyAdvisoryRecommendation,
    StrategyMemoryOutcomeKind, StrategyRolloutStateSummary,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::SwarmConfig;
use swarm_whisker::SuspiciousProcessTreeProfile;

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
    MaterializationStore(#[from] EvolutionMaterializationStoreError),

    #[error(transparent)]
    ValidationBundleStore(#[from] EvolutionValidationBundleStoreError),

    #[error(transparent)]
    ReconciliationStore(#[from] EvolutionQueueReconciliationStoreError),

    #[error(transparent)]
    ProposalStore(#[from] EvolutionProposalStoreError),

    #[error(transparent)]
    Serialization(#[from] serde_json::Error),

    #[error("failed to serialize materialized experiment manifest `{path}`: {source}")]
    ManifestSerialize {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("failed to write materialized experiment manifest `{path}`: {source}")]
    ManifestWrite {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read experiment search path `{path}`: {source}")]
    ManifestReadDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

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

    #[error("draft promotion record `{promotion_id}` was not found")]
    DraftPromotionNotFound { promotion_id: String },

    #[error("materialized draft artifact `{materialization_id}` was not found")]
    MaterializationNotFound { materialization_id: String },

    #[error("validation bundle `{validation_bundle_id}` was not found")]
    ValidationBundleNotFound { validation_bundle_id: String },

    #[error("queue proposal `{proposal_id}` was not found")]
    QueueProposalNotFound { proposal_id: String },

    #[error("could not resolve a base experiment manifest for draft `{draft_id}`")]
    BaseExperimentNotFound { draft_id: String },

    #[error("invalid materialization request: {reason}")]
    InvalidMaterializationRequest { reason: String },

    #[error(
        "proposal `{proposal_id}` cannot be reconciled from promotion `{promotion_id}`: {reason}"
    )]
    InvalidQueueReconciliation {
        promotion_id: String,
        proposal_id: String,
        reason: String,
    },

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

/// Operator-supplied overrides used to materialize one concrete detector candidate from a draft.
#[derive(Debug, Clone, Default)]
pub struct EvolutionDraftMaterializationRequest {
    pub draft_id: String,
    pub base_experiment_path: Option<PathBuf>,
    pub add_suspicious_parents: Vec<String>,
    pub remove_suspicious_parents: Vec<String>,
    pub add_suspicious_children: Vec<String>,
    pub remove_suspicious_children: Vec<String>,
    pub high_confidence_threshold: Option<f64>,
    pub medium_confidence_threshold: Option<f64>,
}

/// Durable record describing one repo-owned experiment manifest materialized from a draft.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionMaterializationReport {
    pub materialization_id: String,
    pub created_at_ms: i64,
    pub draft_id: String,
    pub pressure_id: String,
    pub source_experiment_id: String,
    pub source_experiment_name: String,
    pub base_experiment_path: String,
    pub experiment_id: String,
    pub experiment_name: String,
    pub experiment_path: String,
    pub strategy_id: String,
    pub strategy_description: String,
    pub lineage: ExperimentLineage,
    pub profile: SuspiciousProcessTreeProfile,
    pub manifest_sha256: String,
    pub lineage_sha256: String,
    pub applied_changes: Vec<String>,
}

/// Metadata surfaced for one persisted materialization artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionMaterializationRecord {
    pub materialization_id: String,
    pub draft_id: String,
    pub experiment_id: String,
    pub strategy_id: String,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl EvolutionMaterializationRecord {
    fn from_report(report: &EvolutionMaterializationReport, bundle_path: String) -> Self {
        Self {
            materialization_id: report.materialization_id.clone(),
            draft_id: report.draft_id.clone(),
            experiment_id: report.experiment_id.clone(),
            strategy_id: report.strategy_id.clone(),
            created_at_ms: report.created_at_ms,
            bundle_path,
        }
    }
}

/// Persisted materialization artifact loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionMaterializationLookup {
    pub record: EvolutionMaterializationRecord,
    pub report: EvolutionMaterializationReport,
}

/// Durable validation state after refreshing experiment, verification, proof, shadow, and scorecard evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionValidationBundleStatus {
    ReadyForQueue,
    Blocked,
}

/// Durable validation bundle linking one materialized candidate to refreshed evidence artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionValidationBundleReport {
    pub validation_bundle_id: String,
    pub created_at_ms: i64,
    pub materialization_id: String,
    pub draft_id: String,
    pub pressure_id: String,
    pub experiment_id: String,
    pub experiment_name: String,
    pub experiment_path: String,
    pub strategy_id: String,
    pub strategy_description: String,
    pub lineage: ExperimentLineage,
    pub manifest_sha256: String,
    pub lineage_sha256: String,
    pub experiment_report_id: String,
    pub experiment_passed: bool,
    pub verification_id: String,
    pub verification_passed: bool,
    pub proof_status: EvolutionProposalProofStatus,
    pub proof: Option<EvolutionProposalProofSummary>,
    pub advisory: Option<EvolutionProposalAdvisorySummary>,
    pub shadow_id: String,
    pub shadow_passed: bool,
    pub status: EvolutionValidationBundleStatus,
    pub blocking_reasons: Vec<EvolutionProposalBlockingReason>,
}

/// Metadata surfaced for one persisted validation bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionValidationBundleRecord {
    pub validation_bundle_id: String,
    pub materialization_id: String,
    pub experiment_id: String,
    pub strategy_id: String,
    pub created_at_ms: i64,
    pub status: EvolutionValidationBundleStatus,
    pub bundle_path: String,
}

impl EvolutionValidationBundleRecord {
    fn from_report(report: &EvolutionValidationBundleReport, bundle_path: String) -> Self {
        Self {
            validation_bundle_id: report.validation_bundle_id.clone(),
            materialization_id: report.materialization_id.clone(),
            experiment_id: report.experiment_id.clone(),
            strategy_id: report.strategy_id.clone(),
            created_at_ms: report.created_at_ms,
            status: report.status,
            bundle_path,
        }
    }
}

/// Persisted validation bundle loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionValidationBundleLookup {
    pub record: EvolutionValidationBundleRecord,
    pub report: EvolutionValidationBundleReport,
}

/// Durable record describing one queue proposal reconciliation against refreshed draft evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionQueueReconciliationReport {
    pub reconciliation_id: String,
    pub created_at_ms: i64,
    pub promotion_id: String,
    pub draft_id: String,
    pub queue_proposal_id: String,
    pub validation_bundle_id: String,
    pub experiment_id: String,
    pub verification_id: String,
    pub proof_id: Option<String>,
    pub proof_status: EvolutionProposalProofStatus,
    pub shadow_id: String,
    pub advisory_scorecard_id: Option<String>,
    pub resulting_review_state: EvolutionProposalReviewState,
    pub handoff_ready: bool,
    pub blocking_reasons: Vec<EvolutionProposalBlockingReason>,
}

/// Metadata surfaced for one persisted reconciliation artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionQueueReconciliationRecord {
    pub reconciliation_id: String,
    pub promotion_id: String,
    pub queue_proposal_id: String,
    pub validation_bundle_id: String,
    pub created_at_ms: i64,
    pub resulting_review_state: EvolutionProposalReviewState,
    pub handoff_ready: bool,
    pub bundle_path: String,
}

impl EvolutionQueueReconciliationRecord {
    fn from_report(report: &EvolutionQueueReconciliationReport, bundle_path: String) -> Self {
        Self {
            reconciliation_id: report.reconciliation_id.clone(),
            promotion_id: report.promotion_id.clone(),
            queue_proposal_id: report.queue_proposal_id.clone(),
            validation_bundle_id: report.validation_bundle_id.clone(),
            created_at_ms: report.created_at_ms,
            resulting_review_state: report.resulting_review_state,
            handoff_ready: report.handoff_ready,
            bundle_path,
        }
    }
}

/// Persisted queue reconciliation loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionQueueReconciliationLookup {
    pub record: EvolutionQueueReconciliationRecord,
    pub report: EvolutionQueueReconciliationReport,
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

/// Errors raised by the persisted materialization store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionMaterializationStoreError {
    #[error("failed to read evolution materialization store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution materialization store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution materialization store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised by the persisted validation bundle store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionValidationBundleStoreError {
    #[error("failed to read evolution validation bundle store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution validation bundle store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution validation bundle store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised by the persisted queue reconciliation store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionQueueReconciliationStoreError {
    #[error("failed to read evolution queue reconciliation store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution queue reconciliation store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution queue reconciliation store file `{path}`: {source}")]
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

/// File-backed store for durable draft materialization artifacts.
#[derive(Debug, Clone)]
pub struct FileEvolutionMaterializationStore {
    root: PathBuf,
}

impl FileEvolutionMaterializationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionMaterializationStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionMaterializationStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, materialization_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(materialization_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(
        &self,
    ) -> Result<EvolutionMaterializationIndex, EvolutionMaterializationStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionMaterializationIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionMaterializationStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionMaterializationStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionMaterializationIndex,
    ) -> Result<(), EvolutionMaterializationStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionMaterializationStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| EvolutionMaterializationStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionMaterializationReport,
    ) -> Result<EvolutionMaterializationRecord, EvolutionMaterializationStoreError> {
        let path = self.report_path(&report.materialization_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionMaterializationStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionMaterializationStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record =
            EvolutionMaterializationRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.materialization_id != record.materialization_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        materialization_id: &str,
    ) -> Result<Option<EvolutionMaterializationLookup>, EvolutionMaterializationStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.materialization_id == materialization_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionMaterializationStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionMaterializationStoreError::Parse { path, source })?;
        Ok(Some(EvolutionMaterializationLookup { record, report }))
    }
}

/// File-backed store for durable validation bundles.
#[derive(Debug, Clone)]
pub struct FileEvolutionValidationBundleStore {
    root: PathBuf,
}

impl FileEvolutionValidationBundleStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionValidationBundleStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionValidationBundleStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, validation_bundle_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(validation_bundle_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(
        &self,
    ) -> Result<EvolutionValidationBundleIndex, EvolutionValidationBundleStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionValidationBundleIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionValidationBundleStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionValidationBundleStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionValidationBundleIndex,
    ) -> Result<(), EvolutionValidationBundleStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionValidationBundleStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| EvolutionValidationBundleStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionValidationBundleReport,
    ) -> Result<EvolutionValidationBundleRecord, EvolutionValidationBundleStoreError> {
        let path = self.report_path(&report.validation_bundle_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionValidationBundleStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionValidationBundleStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record =
            EvolutionValidationBundleRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.validation_bundle_id != record.validation_bundle_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        validation_bundle_id: &str,
    ) -> Result<Option<EvolutionValidationBundleLookup>, EvolutionValidationBundleStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.validation_bundle_id == validation_bundle_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionValidationBundleStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionValidationBundleStoreError::Parse { path, source })?;
        Ok(Some(EvolutionValidationBundleLookup { record, report }))
    }
}

/// File-backed store for durable queue reconciliation artifacts.
#[derive(Debug, Clone)]
pub struct FileEvolutionQueueReconciliationStore {
    root: PathBuf,
}

impl FileEvolutionQueueReconciliationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionQueueReconciliationStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionQueueReconciliationStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, reconciliation_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(reconciliation_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(
        &self,
    ) -> Result<EvolutionQueueReconciliationIndex, EvolutionQueueReconciliationStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionQueueReconciliationIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionQueueReconciliationStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionQueueReconciliationStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionQueueReconciliationIndex,
    ) -> Result<(), EvolutionQueueReconciliationStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionQueueReconciliationStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| EvolutionQueueReconciliationStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionQueueReconciliationReport,
    ) -> Result<EvolutionQueueReconciliationRecord, EvolutionQueueReconciliationStoreError> {
        let path = self.report_path(&report.reconciliation_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionQueueReconciliationStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionQueueReconciliationStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record =
            EvolutionQueueReconciliationRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.reconciliation_id != record.reconciliation_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        reconciliation_id: &str,
    ) -> Result<Option<EvolutionQueueReconciliationLookup>, EvolutionQueueReconciliationStoreError>
    {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.reconciliation_id == reconciliation_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionQueueReconciliationStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionQueueReconciliationStoreError::Parse { path, source })?;
        Ok(Some(EvolutionQueueReconciliationLookup { record, report }))
    }
}

/// Harness for off-hot-path selection pressure, draft packaging, and queue promotion.
pub struct DefaultEvolutionDraftingHarness {
    pub config_path: PathBuf,
    pub config: SwarmConfig,
    pub pressure_store: FileEvolutionPressureStore,
    pub draft_store: FileEvolutionDraftStore,
    pub promotion_store: FileEvolutionDraftPromotionStore,
    pub materialization_store: FileEvolutionMaterializationStore,
    pub validation_store: FileEvolutionValidationBundleStore,
    pub reconciliation_store: FileEvolutionQueueReconciliationStore,
}

impl DefaultEvolutionDraftingHarness {
    pub fn from_path(
        config_path: impl AsRef<Path>,
        pressure_results_dir: impl AsRef<Path>,
        draft_results_dir: impl AsRef<Path>,
        promotion_results_dir: impl AsRef<Path>,
        materialization_results_dir: impl AsRef<Path>,
        validation_results_dir: impl AsRef<Path>,
        reconciliation_results_dir: impl AsRef<Path>,
    ) -> Result<Self, EvolutionDraftingError> {
        let config_path = config_path.as_ref();
        let config = load_config(config_path)?;
        Self::from_config(
            config_path,
            config,
            pressure_results_dir,
            draft_results_dir,
            promotion_results_dir,
            materialization_results_dir,
            validation_results_dir,
            reconciliation_results_dir,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_config(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
        pressure_results_dir: impl AsRef<Path>,
        draft_results_dir: impl AsRef<Path>,
        promotion_results_dir: impl AsRef<Path>,
        materialization_results_dir: impl AsRef<Path>,
        validation_results_dir: impl AsRef<Path>,
        reconciliation_results_dir: impl AsRef<Path>,
    ) -> Result<Self, EvolutionDraftingError> {
        Ok(Self {
            config_path: config_path.into(),
            config,
            pressure_store: FileEvolutionPressureStore::open(pressure_results_dir)?,
            draft_store: FileEvolutionDraftStore::open(draft_results_dir)?,
            promotion_store: FileEvolutionDraftPromotionStore::open(promotion_results_dir)?,
            materialization_store: FileEvolutionMaterializationStore::open(
                materialization_results_dir,
            )?,
            validation_store: FileEvolutionValidationBundleStore::open(validation_results_dir)?,
            reconciliation_store: FileEvolutionQueueReconciliationStore::open(
                reconciliation_results_dir,
            )?,
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
            assurance: None,
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

    pub fn materialize_draft(
        &self,
        request: EvolutionDraftMaterializationRequest,
    ) -> Result<EvolutionMaterializationLookup, EvolutionDraftingError> {
        validate_materialization_request(&request)?;

        let draft = self.draft_store.load(&request.draft_id)?.ok_or_else(|| {
            EvolutionDraftingError::DraftNotFound {
                draft_id: request.draft_id.clone(),
            }
        })?;
        let pressure = self
            .pressure_store
            .load(&draft.report.pressure_id)?
            .ok_or_else(|| EvolutionDraftingError::PressureNotFound {
                pressure_id: draft.report.pressure_id.clone(),
            })?;
        let base_experiment_path = match request.base_experiment_path.clone() {
            Some(path) => path,
            None => self.infer_base_experiment_path(&draft.report.draft_id, &pressure.report)?,
        };
        let base_manifest = load_detector_experiment_manifest(&base_experiment_path)?;
        let mut profile = match &base_manifest.candidate {
            DetectorCandidateManifest::SuspiciousProcessTree { profile, .. } => profile.clone(),
            DetectorCandidateManifest::FilelessExecution { strategy_id, .. }
            | DetectorCandidateManifest::BehavioralAnomaly { strategy_id, .. }
            | DetectorCandidateManifest::DnsExfiltration { strategy_id, .. }
            | DetectorCandidateManifest::LateralMovement { strategy_id, .. }
            | DetectorCandidateManifest::CredentialAccess { strategy_id, .. }
            | DetectorCandidateManifest::SuspiciousScripting { strategy_id, .. }
            | DetectorCandidateManifest::Persistence { strategy_id, .. }
            | DetectorCandidateManifest::SupplyChain { strategy_id, .. }
            | DetectorCandidateManifest::NetworkConnect { strategy_id, .. } => {
                return Err(ReplayHarnessError::UnsupportedDetector {
                    strategy: format!(
                        "pressure-mutation not yet supported for detector `{strategy_id}`"
                    ),
                }
                .into());
            }
        };
        let applied_changes = apply_profile_overrides(&mut profile, &request)?;
        let created_at_ms = now_ms();
        let experiment_name =
            materialized_experiment_name(&draft.report.strategy_id, created_at_ms);
        let experiment_path = materialized_experiment_path(
            &base_experiment_path,
            &draft.report.strategy_id,
            created_at_ms,
        );
        let manifest = DetectorExperimentManifest {
            name: experiment_name.clone(),
            description: format!(
                "Materialized from draft `{}` using base experiment `{}`",
                draft.report.draft_id, base_manifest.name
            ),
            corpus: base_manifest.corpus.clone(),
            verification: base_manifest.verification.clone(),
            candidate: DetectorCandidateManifest::SuspiciousProcessTree {
                strategy_id: draft.report.strategy_id.clone(),
                description: draft.report.strategy_description.clone(),
                profile: profile.clone(),
            },
            lineage: ExperimentLineage {
                parent_strategy_id: draft.report.parent_strategy_id.clone(),
                mutation: draft.report.lineage_mutation.clone(),
                rationale: draft.report.lineage_rationale.clone(),
            },
            gates: base_manifest.gates.clone(),
        };

        if let Some(parent) = experiment_path.parent() {
            fs::create_dir_all(parent).map_err(|source| EvolutionDraftingError::ManifestWrite {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let raw = serde_yaml::to_string(&manifest).map_err(|source| {
            EvolutionDraftingError::ManifestSerialize {
                path: experiment_path.clone(),
                source,
            }
        })?;
        fs::write(&experiment_path, raw).map_err(|source| {
            EvolutionDraftingError::ManifestWrite {
                path: experiment_path.clone(),
                source,
            }
        })?;

        let report = EvolutionMaterializationReport {
            materialization_id: materialization_id(&draft.report.draft_id, created_at_ms),
            created_at_ms,
            draft_id: draft.report.draft_id.clone(),
            pressure_id: draft.report.pressure_id.clone(),
            source_experiment_id: pressure
                .report
                .experiment_id
                .clone()
                .unwrap_or_else(|| experiment_id_for_manifest(&base_manifest)),
            source_experiment_name: pressure
                .report
                .experiment_name
                .clone()
                .unwrap_or_else(|| base_manifest.name.clone()),
            base_experiment_path: base_experiment_path.display().to_string(),
            experiment_id: experiment_id_for_manifest(&manifest),
            experiment_name,
            experiment_path: experiment_path.display().to_string(),
            strategy_id: draft.report.strategy_id.clone(),
            strategy_description: draft.report.strategy_description.clone(),
            lineage: manifest.lineage.clone(),
            profile,
            manifest_sha256: sha256_hex(&manifest)?,
            lineage_sha256: sha256_hex(&manifest.lineage)?,
            applied_changes,
        };
        let record = self.materialization_store.persist(&report)?;
        Ok(EvolutionMaterializationLookup { record, report })
    }

    pub fn load_materialization(
        &self,
        materialization_id: &str,
    ) -> Result<Option<EvolutionMaterializationLookup>, EvolutionDraftingError> {
        Ok(self.materialization_store.load(materialization_id)?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn refresh_validation_bundle(
        &self,
        replay_harness: &DefaultReplayHarness,
        proof_harness: &DefaultEvolutionProofHarness,
        scorecard_harness: &DefaultStrategyScorecardHarness,
        experiment_results_dir: impl AsRef<Path>,
        verification_results_dir: impl AsRef<Path>,
        shadow_results_dir: impl AsRef<Path>,
        materialization_id: &str,
    ) -> Result<EvolutionValidationBundleLookup, EvolutionDraftingError> {
        let experiment_results_dir = experiment_results_dir.as_ref();
        let verification_results_dir = verification_results_dir.as_ref();
        let shadow_results_dir = shadow_results_dir.as_ref();
        let materialization = self
            .materialization_store
            .load(materialization_id)?
            .ok_or_else(|| EvolutionDraftingError::MaterializationNotFound {
                materialization_id: materialization_id.to_string(),
            })?;
        let experiment_path = PathBuf::from(&materialization.report.experiment_path);
        let manifest = load_detector_experiment_manifest(&experiment_path)?;
        let current_manifest_sha256 = sha256_hex(&manifest)?;
        let current_lineage_sha256 = sha256_hex(&manifest.lineage)?;
        let mut blocking_reasons = Vec::new();

        if manifest.name != materialization.report.experiment_name {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "materialization".to_string(),
                name: "experiment_name_drift".to_string(),
                details: format!(
                    "materialized manifest name `{}` no longer matches recorded name `{}`",
                    manifest.name, materialization.report.experiment_name
                ),
                references: vec![materialization.report.materialization_id.clone()],
            });
        }
        if manifest.candidate.strategy_id() != materialization.report.strategy_id {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "materialization".to_string(),
                name: "strategy_drift".to_string(),
                details: format!(
                    "materialized manifest strategy `{}` no longer matches recorded strategy `{}`",
                    manifest.candidate.strategy_id(),
                    materialization.report.strategy_id
                ),
                references: vec![materialization.report.materialization_id.clone()],
            });
        }
        if current_manifest_sha256 != materialization.report.manifest_sha256 {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "materialization".to_string(),
                name: "manifest_digest_drift".to_string(),
                details: "materialized experiment manifest digest changed since the draft was materialized"
                    .to_string(),
                references: vec![materialization.report.materialization_id.clone()],
            });
        }
        if current_lineage_sha256 != materialization.report.lineage_sha256 {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "materialization".to_string(),
                name: "lineage_digest_drift".to_string(),
                details: "materialized experiment lineage digest changed since the draft was materialized"
                    .to_string(),
                references: vec![materialization.report.materialization_id.clone()],
            });
        }

        let (experiment, shadow) = replay_harness
            .evaluate_experiment_and_shadow_path(
                &experiment_path,
                experiment_results_dir,
                shadow_results_dir,
            )
            .await?;
        if experiment.report.experiment_id != materialization.report.experiment_id {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "experiment".to_string(),
                name: "experiment_id_mismatch".to_string(),
                details: format!(
                    "experiment report `{}` belongs to `{}` instead of `{}`",
                    experiment.report.experiment_id,
                    experiment.report.experiment_id,
                    materialization.report.experiment_id
                ),
                references: vec![experiment.report.experiment_id.clone()],
            });
        }
        if !experiment.report.passed {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "experiment".to_string(),
                name: "experiment_gates_failed".to_string(),
                details:
                    "offline experiment comparison or gates failed for the materialized candidate"
                        .to_string(),
                references: vec![experiment.report.experiment_id.clone()],
            });
        }

        let verification = replay_harness
            .evaluate_verification_path(&experiment_path, verification_results_dir)
            .await?;
        if verification.report.experiment_id != materialization.report.experiment_id {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "verification".to_string(),
                name: "experiment_mismatch".to_string(),
                details: format!(
                    "verification `{}` belongs to `{}` instead of `{}`",
                    verification.report.verification_id,
                    verification.report.experiment_id,
                    materialization.report.experiment_id
                ),
                references: vec![verification.report.verification_id.clone()],
            });
        }
        let verification_passed = verification.report.passed
            && verification
                .report
                .invariants
                .iter()
                .all(|invariant| invariant.passed);
        if !verification_passed {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "verification".to_string(),
                name: "verification_failed".to_string(),
                details: "verification invariants did not all pass for the materialized candidate"
                    .to_string(),
                references: vec![verification.report.verification_id.clone()],
            });
        }

        let (proof, proof_status) = if verification_passed {
            match proof_harness.create_proof(
                &experiment_path,
                verification_results_dir,
                &verification.report.verification_id,
            ) {
                Ok(lookup) => {
                    let mut proof_inconsistent = false;
                    if lookup.report.experiment_id != materialization.report.experiment_id {
                        proof_inconsistent = true;
                        blocking_reasons.push(EvolutionProposalBlockingReason {
                            source: "proof".to_string(),
                            name: "experiment_mismatch".to_string(),
                            details: format!(
                                "proof `{}` belongs to `{}` instead of `{}`",
                                lookup.report.proof_id,
                                lookup.report.experiment_id,
                                materialization.report.experiment_id
                            ),
                            references: vec![lookup.report.proof_id.clone()],
                        });
                    }
                    if lookup.report.experiment_manifest_sha256 != current_manifest_sha256 {
                        proof_inconsistent = true;
                        blocking_reasons.push(EvolutionProposalBlockingReason {
                            source: "proof".to_string(),
                            name: "experiment_digest_mismatch".to_string(),
                            details: "proof digest does not match the current materialized experiment manifest"
                                .to_string(),
                            references: vec![lookup.report.proof_id.clone()],
                        });
                    }
                    if lookup.report.lineage_sha256 != current_lineage_sha256 {
                        proof_inconsistent = true;
                        blocking_reasons.push(EvolutionProposalBlockingReason {
                            source: "proof".to_string(),
                            name: "lineage_digest_mismatch".to_string(),
                            details: "proof digest does not match the current materialized lineage"
                                .to_string(),
                            references: vec![lookup.report.proof_id.clone()],
                        });
                    }
                    if lookup.report.verification_report_sha256 != sha256_hex(&verification.report)?
                    {
                        proof_inconsistent = true;
                        blocking_reasons.push(EvolutionProposalBlockingReason {
                            source: "proof".to_string(),
                            name: "verification_digest_mismatch".to_string(),
                            details:
                                "proof digest does not match the refreshed verification artifact"
                                    .to_string(),
                            references: vec![
                                lookup.report.proof_id.clone(),
                                verification.report.verification_id.clone(),
                            ],
                        });
                    }
                    let summary = proof_summary_from_report(&lookup.report);
                    let status = if proof_inconsistent {
                        EvolutionProposalProofStatus::Inconsistent
                    } else {
                        EvolutionProposalProofStatus::Proved
                    };
                    (Some(summary), status)
                }
                Err(error) => {
                    blocking_reasons.push(EvolutionProposalBlockingReason {
                        source: "proof".to_string(),
                        name: "proof_generation_failed".to_string(),
                        details: error.to_string(),
                        references: vec![verification.report.verification_id.clone()],
                    });
                    (None, EvolutionProposalProofStatus::Missing)
                }
            }
        } else {
            (None, EvolutionProposalProofStatus::Missing)
        };

        if shadow.report.experiment_id != materialization.report.experiment_id {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "shadow".to_string(),
                name: "experiment_mismatch".to_string(),
                details: format!(
                    "shadow `{}` belongs to `{}` instead of `{}`",
                    shadow.report.shadow_id,
                    shadow.report.experiment_id,
                    materialization.report.experiment_id
                ),
                references: vec![shadow.report.shadow_id.clone()],
            });
        }
        if shadow.report.candidate_strategy_id != materialization.report.strategy_id {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "shadow".to_string(),
                name: "strategy_mismatch".to_string(),
                details: format!(
                    "shadow `{}` targets strategy `{}` instead of `{}`",
                    shadow.report.shadow_id,
                    shadow.report.candidate_strategy_id,
                    materialization.report.strategy_id
                ),
                references: vec![shadow.report.shadow_id.clone()],
            });
        }
        if !shadow.report.passed {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "shadow".to_string(),
                name: "shadow_failed".to_string(),
                details: "offline shadow evaluation failed for the materialized candidate"
                    .to_string(),
                references: vec![shadow.report.shadow_id.clone()],
            });
        }

        let advisory = if verification_passed {
            match scorecard_harness
                .create_scorecard(
                    replay_harness,
                    &experiment_path,
                    experiment_results_dir,
                    verification_results_dir,
                    &verification.report.verification_id,
                )
                .await
            {
                Ok(lookup) => Some(advisory_summary_from_scorecard(&lookup.report)),
                Err(error) => {
                    blocking_reasons.push(EvolutionProposalBlockingReason {
                        source: "advisory".to_string(),
                        name: "scorecard_generation_failed".to_string(),
                        details: error.to_string(),
                        references: vec![verification.report.verification_id.clone()],
                    });
                    None
                }
            }
        } else {
            None
        };

        let created_at_ms = now_ms();
        let report = EvolutionValidationBundleReport {
            validation_bundle_id: validation_bundle_id(&materialization.report.materialization_id),
            created_at_ms,
            materialization_id: materialization.report.materialization_id.clone(),
            draft_id: materialization.report.draft_id.clone(),
            pressure_id: materialization.report.pressure_id.clone(),
            experiment_id: materialization.report.experiment_id.clone(),
            experiment_name: materialization.report.experiment_name.clone(),
            experiment_path: materialization.report.experiment_path.clone(),
            strategy_id: materialization.report.strategy_id.clone(),
            strategy_description: materialization.report.strategy_description.clone(),
            lineage: materialization.report.lineage.clone(),
            manifest_sha256: current_manifest_sha256,
            lineage_sha256: current_lineage_sha256,
            experiment_report_id: experiment.report.experiment_id.clone(),
            experiment_passed: experiment.report.passed,
            verification_id: verification.report.verification_id.clone(),
            verification_passed,
            proof_status,
            proof,
            advisory,
            shadow_id: shadow.report.shadow_id.clone(),
            shadow_passed: shadow.report.passed,
            status: if blocking_reasons.is_empty() {
                EvolutionValidationBundleStatus::ReadyForQueue
            } else {
                EvolutionValidationBundleStatus::Blocked
            },
            blocking_reasons,
        };
        let record = self.validation_store.persist(&report)?;
        Ok(EvolutionValidationBundleLookup { record, report })
    }

    pub fn load_validation_bundle(
        &self,
        validation_bundle_id: &str,
    ) -> Result<Option<EvolutionValidationBundleLookup>, EvolutionDraftingError> {
        Ok(self.validation_store.load(validation_bundle_id)?)
    }

    pub fn reconcile_queue_proposal(
        &self,
        queue_results_dir: impl AsRef<Path>,
        promotion_id: &str,
        validation_bundle_id: &str,
    ) -> Result<EvolutionQueueReconciliationLookup, EvolutionDraftingError> {
        let promotion = self.promotion_store.load(promotion_id)?.ok_or_else(|| {
            EvolutionDraftingError::DraftPromotionNotFound {
                promotion_id: promotion_id.to_string(),
            }
        })?;
        let validation = self
            .validation_store
            .load(validation_bundle_id)?
            .ok_or_else(|| EvolutionDraftingError::ValidationBundleNotFound {
                validation_bundle_id: validation_bundle_id.to_string(),
            })?;
        if promotion.report.draft_id != validation.report.draft_id {
            return Err(EvolutionDraftingError::InvalidQueueReconciliation {
                promotion_id: promotion.report.promotion_id.clone(),
                proposal_id: promotion.report.queue_proposal_id.clone(),
                reason: format!(
                    "promotion draft `{}` does not match validation draft `{}`",
                    promotion.report.draft_id, validation.report.draft_id
                ),
            });
        }

        let queue_store = FileEvolutionProposalStore::open(queue_results_dir)?;
        let mut proposal = queue_store
            .load(&promotion.report.queue_proposal_id)?
            .ok_or_else(|| EvolutionDraftingError::QueueProposalNotFound {
                proposal_id: promotion.report.queue_proposal_id.clone(),
            })?;
        if proposal.report.strategy_id != validation.report.strategy_id {
            return Err(EvolutionDraftingError::InvalidQueueReconciliation {
                promotion_id: promotion.report.promotion_id.clone(),
                proposal_id: proposal.report.proposal_id.clone(),
                reason: format!(
                    "queue strategy `{}` does not match validation strategy `{}`",
                    proposal.report.strategy_id, validation.report.strategy_id
                ),
            });
        }
        if matches!(
            proposal.report.review_state,
            EvolutionProposalReviewState::AcceptedForCanary
                | EvolutionProposalReviewState::Rejected
        ) {
            return Err(EvolutionDraftingError::InvalidQueueReconciliation {
                promotion_id: promotion.report.promotion_id.clone(),
                proposal_id: proposal.report.proposal_id.clone(),
                reason: format!(
                    "queue proposal is already in terminal state `{:?}`",
                    proposal.report.review_state
                ),
            });
        }

        let mut blocking_reasons = proposal
            .report
            .blocking_reasons
            .iter()
            .filter(|reason| {
                !(reason.source == "draft"
                    && reason.name == "requires_materialized_experiment_and_proof")
            })
            .cloned()
            .collect::<Vec<_>>();
        blocking_reasons.extend(validation.report.blocking_reasons.clone());
        let resulting_review_state = if blocking_reasons.is_empty() {
            match proposal.report.review_state {
                EvolutionProposalReviewState::Deferred => EvolutionProposalReviewState::Deferred,
                _ => EvolutionProposalReviewState::PendingReview,
            }
        } else {
            EvolutionProposalReviewState::Blocked
        };

        proposal.report.experiment_id = validation.report.experiment_id.clone();
        proposal.report.experiment_name = validation.report.experiment_name.clone();
        proposal.report.experiment_path = validation.report.experiment_path.clone();
        proposal.report.strategy_description = validation.report.strategy_description.clone();
        proposal.report.lineage = validation.report.lineage.clone();
        proposal.report.verification_id = Some(validation.report.verification_id.clone());
        proposal.report.verification_passed = validation.report.verification_passed;
        proposal.report.proof_status = validation.report.proof_status;
        proposal.report.proof = validation.report.proof.clone();
        proposal.report.advisory = validation.report.advisory.clone();
        proposal.report.review_state = resulting_review_state;
        proposal.report.blocking_reasons = blocking_reasons.clone();
        let queue_record = queue_store.persist(&proposal.report)?;

        let report = EvolutionQueueReconciliationReport {
            reconciliation_id: reconciliation_id(
                &promotion.report.promotion_id,
                &validation.report.validation_bundle_id,
            ),
            created_at_ms: now_ms(),
            promotion_id: promotion.report.promotion_id.clone(),
            draft_id: promotion.report.draft_id.clone(),
            queue_proposal_id: queue_record.proposal_id.clone(),
            validation_bundle_id: validation.report.validation_bundle_id.clone(),
            experiment_id: validation.report.experiment_id.clone(),
            verification_id: validation.report.verification_id.clone(),
            proof_id: validation
                .report
                .proof
                .as_ref()
                .map(|proof| proof.proof_id.clone()),
            proof_status: validation.report.proof_status,
            shadow_id: validation.report.shadow_id.clone(),
            advisory_scorecard_id: validation
                .report
                .advisory
                .as_ref()
                .map(|advisory| advisory.scorecard_id.clone()),
            resulting_review_state,
            handoff_ready: blocking_reasons.is_empty()
                && validation.report.proof_status == EvolutionProposalProofStatus::Proved
                && validation.report.verification_passed
                && validation.report.shadow_passed
                && validation.report.status == EvolutionValidationBundleStatus::ReadyForQueue,
            blocking_reasons,
        };
        let record = self.reconciliation_store.persist(&report)?;
        Ok(EvolutionQueueReconciliationLookup { record, report })
    }

    pub fn load_queue_reconciliation(
        &self,
        reconciliation_id: &str,
    ) -> Result<Option<EvolutionQueueReconciliationLookup>, EvolutionDraftingError> {
        Ok(self.reconciliation_store.load(reconciliation_id)?)
    }

    fn infer_base_experiment_path(
        &self,
        draft_id: &str,
        pressure: &EvolutionPressureReport,
    ) -> Result<PathBuf, EvolutionDraftingError> {
        let experiment_name = pressure.experiment_name.as_deref().ok_or_else(|| {
            EvolutionDraftingError::BaseExperimentNotFound {
                draft_id: draft_id.to_string(),
            }
        })?;
        let experiments_dir = repo_root_from_config_path(&self.config_path).join("experiments");
        find_experiment_manifest_path(&experiments_dir, experiment_name)?.ok_or_else(|| {
            EvolutionDraftingError::BaseExperimentNotFound {
                draft_id: draft_id.to_string(),
            }
        })
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

/// Render one draft materialization artifact.
pub fn render_evolution_materialization(report: &EvolutionMaterializationReport) -> String {
    let mut lines = vec![
        "Evolution Draft Materialization".to_string(),
        format!("Materialization ID: {}", report.materialization_id),
        format!("Draft ID: {}", report.draft_id),
        format!("Pressure ID: {}", report.pressure_id),
        format!(
            "Source experiment: {} ({})",
            report.source_experiment_name, report.source_experiment_id
        ),
        format!("Base experiment path: {}", report.base_experiment_path),
        format!(
            "Materialized experiment: {} ({})",
            report.experiment_name, report.experiment_id
        ),
        format!("Materialized path: {}", report.experiment_path),
        format!(
            "Strategy: {} | {}",
            report.strategy_id, report.strategy_description
        ),
        format!(
            "Lineage: parent={} mutation={} rationale={}",
            report.lineage.parent_strategy_id, report.lineage.mutation, report.lineage.rationale
        ),
        format!(
            "Thresholds: high={:.3} medium={:.3}",
            report.profile.high_confidence_threshold, report.profile.medium_confidence_threshold
        ),
        format!("Manifest digest: {}", report.manifest_sha256),
    ];
    lines.push("Applied changes:".to_string());
    for change in &report.applied_changes {
        lines.push(format!("- {}", change));
    }
    lines.join("\n")
}

/// Render one refreshed validation bundle.
pub fn render_evolution_validation_bundle(report: &EvolutionValidationBundleReport) -> String {
    let mut lines = vec![
        "Evolution Validation Bundle".to_string(),
        format!("Validation bundle ID: {}", report.validation_bundle_id),
        format!("Materialization ID: {}", report.materialization_id),
        format!("Draft ID: {}", report.draft_id),
        format!(
            "Experiment: {} ({})",
            report.experiment_name, report.experiment_id
        ),
        format!(
            "Strategy: {} | {}",
            report.strategy_id, report.strategy_description
        ),
        format!("Status: {}", validation_bundle_status_label(report.status)),
        format!(
            "Experiment report: {} | passed={}",
            report.experiment_report_id, report.experiment_passed
        ),
        format!(
            "Verification: {} | passed={}",
            report.verification_id, report.verification_passed
        ),
        format!("Proof status: {}", proof_status_label(report.proof_status)),
        format!(
            "Shadow: {} | passed={}",
            report.shadow_id, report.shadow_passed
        ),
    ];

    if let Some(proof) = &report.proof {
        lines.push(format!(
            "Proof: {} | system={} | invariants={}",
            proof.proof_id, proof.proof_system, proof.invariant_count
        ));
    } else {
        lines.push("Proof: none attached".to_string());
    }

    if let Some(advisory) = &report.advisory {
        lines.push(format!(
            "Advisory: scorecard={} recommendation={:?} delta={:.3}",
            advisory.scorecard_id, advisory.recommendation, advisory.score_delta
        ));
    } else {
        lines.push("Advisory: unavailable".to_string());
    }

    if report.blocking_reasons.is_empty() {
        lines.push("Blocking reasons: none".to_string());
    } else {
        lines.push("Blocking reasons:".to_string());
        for reason in &report.blocking_reasons {
            lines.push(format!(
                "- [{}] {}: {}",
                reason.source, reason.name, reason.details
            ));
        }
    }

    lines.join("\n")
}

/// Render one queue reconciliation artifact.
pub fn render_evolution_queue_reconciliation(
    report: &EvolutionQueueReconciliationReport,
) -> String {
    let mut lines = vec![
        "Evolution Queue Reconciliation".to_string(),
        format!("Reconciliation ID: {}", report.reconciliation_id),
        format!("Promotion ID: {}", report.promotion_id),
        format!("Draft ID: {}", report.draft_id),
        format!("Queue proposal: {}", report.queue_proposal_id),
        format!("Validation bundle: {}", report.validation_bundle_id),
        format!("Experiment: {}", report.experiment_id),
        format!("Verification: {}", report.verification_id),
        format!("Proof status: {}", proof_status_label(report.proof_status)),
        format!("Shadow: {}", report.shadow_id),
        format!(
            "Resulting queue state: {}",
            review_state_label(report.resulting_review_state)
        ),
        format!("Handoff ready: {}", report.handoff_ready),
    ];

    if let Some(proof_id) = &report.proof_id {
        lines.push(format!("Proof: {}", proof_id));
    }
    if let Some(scorecard_id) = &report.advisory_scorecard_id {
        lines.push(format!("Advisory scorecard: {}", scorecard_id));
    }

    if report.blocking_reasons.is_empty() {
        lines.push("Blocking reasons: none".to_string());
    } else {
        lines.push("Blocking reasons:".to_string());
        for reason in &report.blocking_reasons {
            lines.push(format!(
                "- [{}] {}: {}",
                reason.source, reason.name, reason.details
            ));
        }
    }

    lines.join("\n")
}

fn validate_materialization_request(
    request: &EvolutionDraftMaterializationRequest,
) -> Result<(), EvolutionDraftingError> {
    if let Some(value) = request.high_confidence_threshold
        && !(0.0..=1.0).contains(&value)
    {
        return Err(EvolutionDraftingError::InvalidMaterializationRequest {
            reason: format!("high confidence threshold must be between 0.0 and 1.0, got {value}"),
        });
    }
    if let Some(value) = request.medium_confidence_threshold
        && !(0.0..=1.0).contains(&value)
    {
        return Err(EvolutionDraftingError::InvalidMaterializationRequest {
            reason: format!("medium confidence threshold must be between 0.0 and 1.0, got {value}"),
        });
    }

    let high = request.high_confidence_threshold.unwrap_or(1.0);
    let medium = request.medium_confidence_threshold.unwrap_or(0.0);
    if request.high_confidence_threshold.is_some()
        && request.medium_confidence_threshold.is_some()
        && medium > high
    {
        return Err(EvolutionDraftingError::InvalidMaterializationRequest {
            reason: format!(
                "medium confidence threshold {medium} cannot exceed high confidence threshold {high}"
            ),
        });
    }

    Ok(())
}

fn apply_profile_overrides(
    profile: &mut SuspiciousProcessTreeProfile,
    request: &EvolutionDraftMaterializationRequest,
) -> Result<Vec<String>, EvolutionDraftingError> {
    let mut changes = Vec::new();

    for parent in &request.add_suspicious_parents {
        let parent = parent.to_ascii_lowercase();
        if !profile
            .suspicious_parents
            .iter()
            .any(|entry| entry.eq_ignore_ascii_case(&parent))
        {
            profile.suspicious_parents.push(parent.clone());
            changes.push(format!("add suspicious parent `{parent}`"));
        }
    }
    for parent in &request.remove_suspicious_parents {
        let parent = parent.to_ascii_lowercase();
        let before = profile.suspicious_parents.len();
        profile
            .suspicious_parents
            .retain(|entry| !entry.eq_ignore_ascii_case(&parent));
        if before != profile.suspicious_parents.len() {
            changes.push(format!("remove suspicious parent `{parent}`"));
        }
    }
    for child in &request.add_suspicious_children {
        let child = child.to_ascii_lowercase();
        if !profile
            .suspicious_children
            .iter()
            .any(|entry| entry.eq_ignore_ascii_case(&child))
        {
            profile.suspicious_children.push(child.clone());
            changes.push(format!("add suspicious child `{child}`"));
        }
    }
    for child in &request.remove_suspicious_children {
        let child = child.to_ascii_lowercase();
        let before = profile.suspicious_children.len();
        profile
            .suspicious_children
            .retain(|entry| !entry.eq_ignore_ascii_case(&child));
        if before != profile.suspicious_children.len() {
            changes.push(format!("remove suspicious child `{child}`"));
        }
    }

    if let Some(value) = request.high_confidence_threshold {
        if profile.high_confidence_threshold != value {
            changes.push(format!("set high confidence threshold to {:.3}", value));
        }
        profile.high_confidence_threshold = value;
    }
    if let Some(value) = request.medium_confidence_threshold {
        if profile.medium_confidence_threshold != value {
            changes.push(format!("set medium confidence threshold to {:.3}", value));
        }
        profile.medium_confidence_threshold = value;
    }
    if profile.medium_confidence_threshold > profile.high_confidence_threshold {
        return Err(EvolutionDraftingError::InvalidMaterializationRequest {
            reason: format!(
                "medium confidence threshold {:.3} cannot exceed high confidence threshold {:.3}",
                profile.medium_confidence_threshold, profile.high_confidence_threshold
            ),
        });
    }

    normalize_profile_entries(&mut profile.suspicious_parents);
    normalize_profile_entries(&mut profile.suspicious_children);

    if changes.is_empty() {
        changes.push("profile copied from base experiment without profile overrides".to_string());
    }

    Ok(changes)
}

fn normalize_profile_entries(values: &mut Vec<String>) {
    let mut normalized = Vec::new();
    for value in values.drain(..) {
        let lowered = value.to_ascii_lowercase();
        if !normalized
            .iter()
            .any(|entry: &String| entry.eq_ignore_ascii_case(&lowered))
        {
            normalized.push(lowered);
        }
    }
    *values = normalized;
}

fn advisory_summary_from_scorecard(
    scorecard: &crate::strategy::StrategyScorecard,
) -> EvolutionProposalAdvisorySummary {
    EvolutionProposalAdvisorySummary {
        scorecard_id: scorecard.scorecard_id.clone(),
        recommendation: scorecard.recommendation,
        score_delta: scorecard.score_delta,
        baseline_strategy_id: scorecard.baseline_strategy_id.clone(),
        baseline_final_score: scorecard.baseline.final_score,
        candidate_final_score: scorecard.candidate.final_score,
        candidate_matching_memory_count: scorecard.candidate.matching_memory_count,
        latest_rollout_state: scorecard.candidate.latest_rollout_state.clone(),
    }
}

fn proof_summary_from_report(
    report: &crate::evolution::EvolutionProofReport,
) -> EvolutionProposalProofSummary {
    EvolutionProposalProofSummary {
        proof_id: report.proof_id.clone(),
        proof_system: report.proof_system.clone(),
        attestation_sha256: report.attestation_sha256.clone(),
        invariant_count: report.invariants.len(),
    }
}

fn repo_root_from_config_path(config_path: &Path) -> PathBuf {
    if let Some(parent) = config_path.parent() {
        if parent.file_name().is_some_and(|name| name == "rulesets") {
            return parent.parent().unwrap_or(parent).to_path_buf();
        }
        return parent.to_path_buf();
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn find_experiment_manifest_path(
    root: &Path,
    experiment_name: &str,
) -> Result<Option<PathBuf>, EvolutionDraftingError> {
    if !root.exists() {
        return Ok(None);
    }

    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries =
            fs::read_dir(&dir).map_err(|source| EvolutionDraftingError::ManifestReadDir {
                path: dir.clone(),
                source,
            })?;
        for entry in entries {
            let entry = entry.map_err(|source| EvolutionDraftingError::ManifestReadDir {
                path: dir.clone(),
                source,
            })?;
            let path = entry.path();
            let file_type =
                entry
                    .file_type()
                    .map_err(|source| EvolutionDraftingError::ManifestReadDir {
                        path: path.clone(),
                        source,
                    })?;
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
                continue;
            };
            if !matches!(extension, "yaml" | "yml") {
                continue;
            }
            let manifest = load_detector_experiment_manifest(&path)?;
            if manifest.name == experiment_name {
                return Ok(Some(path));
            }
        }
    }

    Ok(None)
}

fn materialized_experiment_name(strategy_id: &str, created_at_ms: i64) -> String {
    format!(
        "draft_materialized_{}_{}",
        sanitize_id(strategy_id),
        created_at_ms
    )
}

fn materialized_experiment_path(
    base_experiment_path: &Path,
    strategy_id: &str,
    created_at_ms: i64,
) -> PathBuf {
    let parent = base_experiment_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    parent.join(format!(
        "materialized-{}-{}.yaml",
        sanitize_id(strategy_id),
        created_at_ms
    ))
}

fn experiment_id_for_manifest(manifest: &DetectorExperimentManifest) -> String {
    format!(
        "experiment:{}:{}",
        manifest.name,
        manifest.candidate.strategy_id()
    )
}

fn materialization_id(draft_id: &str, created_at_ms: i64) -> String {
    format!(
        "evolution_materialization:{}:{}",
        sanitize_id(draft_id),
        created_at_ms
    )
}

fn validation_bundle_id(materialization_id: &str) -> String {
    format!(
        "evolution_validation_bundle:{}",
        sanitize_id(materialization_id)
    )
}

fn reconciliation_id(promotion_id: &str, validation_bundle_id: &str) -> String {
    let digest = Sha256::digest(format!("{promotion_id}:{validation_bundle_id}").as_bytes());
    let token = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("evolution_queue_reconciliation:{token}")
}

fn review_state_label(value: EvolutionProposalReviewState) -> &'static str {
    match value {
        EvolutionProposalReviewState::PendingReview => "pending_review",
        EvolutionProposalReviewState::AcceptedForCanary => "accepted_for_canary",
        EvolutionProposalReviewState::Deferred => "deferred",
        EvolutionProposalReviewState::Rejected => "rejected",
        EvolutionProposalReviewState::Blocked => "blocked",
    }
}

fn proof_status_label(value: EvolutionProposalProofStatus) -> &'static str {
    match value {
        EvolutionProposalProofStatus::Proved => "proved",
        EvolutionProposalProofStatus::Missing => "missing",
        EvolutionProposalProofStatus::Inconsistent => "inconsistent",
    }
}

fn validation_bundle_status_label(value: EvolutionValidationBundleStatus) -> &'static str {
    match value {
        EvolutionValidationBundleStatus::ReadyForQueue => "ready_for_queue",
        EvolutionValidationBundleStatus::Blocked => "blocked",
    }
}

fn sha256_hex<T: Serialize>(value: &T) -> Result<String, EvolutionDraftingError> {
    let bytes = serde_json::to_vec(value)?;
    let digest = Sha256::digest(bytes);
    Ok(format!("{digest:x}"))
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
        .unwrap_or_default()
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct EvolutionMaterializationIndex {
    entries: Vec<EvolutionMaterializationRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct EvolutionValidationBundleIndex {
    entries: Vec<EvolutionValidationBundleRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct EvolutionQueueReconciliationIndex {
    entries: Vec<EvolutionQueueReconciliationRecord>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        DefaultEvolutionDraftingHarness, EvolutionDraftCreateRequest,
        EvolutionDraftMaterializationRequest, EvolutionDraftingError, EvolutionPressureSourceKind,
        EvolutionValidationBundleStatus, render_evolution_draft, render_evolution_draft_promotion,
        render_evolution_materialization, render_evolution_pressure,
        render_evolution_queue_reconciliation, render_evolution_validation_bundle,
    };
    use crate::evolution::{
        DefaultEvolutionHandoffHarness, DefaultEvolutionProofHarness, DefaultEvolutionQueueHarness,
        EvolutionProposalAssuranceCoverageSummary, EvolutionProposalAssuranceDecision,
        EvolutionProposalAssuranceSolverSummary, EvolutionProposalAssuranceSummary,
        EvolutionProposalDecisionAction, EvolutionProposalProofStatus,
        EvolutionProposalReviewState, FileEvolutionProposalStore,
    };
    use crate::replay::DefaultReplayHarness;
    use crate::strategy::DefaultStrategyScorecardHarness;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use swarm_core::ThreatClass;
    use swarm_core::config::{PolicyRuleConfig, PolicyRuleDecision, SwarmConfig};
    use swarm_core::types::Severity;

    fn sample_config() -> SwarmConfig {
        let mut config: SwarmConfig =
            serde_yaml::from_str(include_str!("../../../rulesets/default.yaml")).unwrap();
        config.policy.rules = permissive_policy_rules();
        config.evolution.assurance.min_detector_catch_rate = 0.0;
        config
    }

    fn passed_assurance_summary() -> EvolutionProposalAssuranceSummary {
        EvolutionProposalAssuranceSummary {
            decision: EvolutionProposalAssuranceDecision::Passed,
            coverage: EvolutionProposalAssuranceCoverageSummary {
                detector: "office_baseline_control".to_string(),
                suite_name: Some("evasion-breadth-v1".to_string()),
                corpus_version: Some("2026-04-03".to_string()),
                required_catch_rate: 0.75,
                actual_catch_rate: Some(1.0),
                actionable_gap_count: 0,
            },
            solver: EvolutionProposalAssuranceSolverSummary {
                required: false,
                status: None,
                allowed_statuses: Vec::new(),
            },
            harvested_case_ids: Vec::new(),
            waiver: None,
        }
    }

    fn permissive_policy_rules() -> Vec<PolicyRuleConfig> {
        use ThreatClass::{
            CommandAndControl, CredentialAccess, DataExfiltration, DefenseEvasion, Discovery,
            Execution, Impact, InitialAccess, LateralMovement, Persistence, PrivilegeEscalation,
            SupplyChain,
        };

        [
            Execution,
            CommandAndControl,
            CredentialAccess,
            DataExfiltration,
            DefenseEvasion,
            Discovery,
            Impact,
            InitialAccess,
            LateralMovement,
            Persistence,
            PrivilegeEscalation,
            SupplyChain,
        ]
        .into_iter()
        .map(|threat_class| PolicyRuleConfig {
            name: format!("drafting-test-allow-{threat_class:?}"),
            decision: PolicyRuleDecision::Allow,
            threat_class,
            actions: Vec::new(),
            min_severity: Severity::Low,
            max_severity: Severity::Critical,
            time_window_utc: None,
            max_actions_per_agent_per_minute: None,
            reason: None,
        })
        .collect()
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
        let materialization_dir = root.join("materializations");
        let validation_dir = root.join("validation");
        let reconciliation_dir = root.join("reconciliations");
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
            &materialization_dir,
            &validation_dir,
            &reconciliation_dir,
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
        let materialization_dir = root.join("materializations");
        let validation_dir = root.join("validation");
        let reconciliation_dir = root.join("reconciliations");
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
            &materialization_dir,
            &validation_dir,
            &reconciliation_dir,
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
        let materialization_dir = root.join("materializations");
        let validation_dir = root.join("validation");
        let reconciliation_dir = root.join("reconciliations");
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
            &materialization_dir,
            &validation_dir,
            &reconciliation_dir,
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

    #[tokio::test]
    async fn materialized_candidate_refreshes_validation_and_reconciles_queue() {
        let root = unique_temp_dir("materialize-success");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verifications");
        let shadow_dir = root.join("shadows");
        let proof_dir = root.join("proofs");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let pressure_dir = root.join("pressures");
        let draft_dir = root.join("drafts");
        let draft_promotion_dir = root.join("draft-promotions");
        let materialization_dir = root.join("materializations");
        let validation_dir = root.join("validation");
        let reconciliation_dir = root.join("reconciliations");
        let queue_dir = root.join("queue");
        let handoff_dir = root.join("handoffs");
        let config = sample_config();
        let replay =
            DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
        let verification = replay
            .evaluate_verification_path(office_control_experiment(), &verification_dir)
            .await
            .unwrap();
        let proofs =
            DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proof_dir)
                .unwrap();
        let queue = DefaultEvolutionQueueHarness::from_config("inline", config.clone(), &queue_dir)
            .unwrap();
        let handoff =
            DefaultEvolutionHandoffHarness::from_config("inline", config.clone(), &handoff_dir)
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
            &materialization_dir,
            &validation_dir,
            &reconciliation_dir,
        )
        .unwrap();

        let pressure = harness
            .create_pressure_from_scorecard(&scorecards, &scorecard.report.scorecard_id)
            .unwrap();
        let draft = harness
            .create_draft(EvolutionDraftCreateRequest {
                pressure_id: pressure.report.pressure_id.clone(),
                strategy_id: "office_materialized_followup_v1".to_string(),
                strategy_description:
                    "materialized office follow-up that preserves baseline profile".to_string(),
                mutation: "package_control_profile_for_materialized_validation".to_string(),
                rationale: "close the draft-to-validation gap without changing detector behavior"
                    .to_string(),
            })
            .unwrap();
        let promotion = harness
            .promote_draft(
                &queue_dir,
                &draft.report.draft_id,
                "queue this draft before materialization reconciliation",
            )
            .unwrap();
        let materialization = harness
            .materialize_draft(EvolutionDraftMaterializationRequest {
                draft_id: draft.report.draft_id.clone(),
                base_experiment_path: Some(office_control_experiment()),
                ..EvolutionDraftMaterializationRequest::default()
            })
            .unwrap();
        let validation = harness
            .refresh_validation_bundle(
                &replay,
                &proofs,
                &scorecards,
                &experiment_dir,
                &verification_dir,
                &shadow_dir,
                &materialization.report.materialization_id,
            )
            .await
            .unwrap();
        let reconciliation = harness
            .reconcile_queue_proposal(
                &queue_dir,
                &promotion.report.promotion_id,
                &validation.report.validation_bundle_id,
            )
            .unwrap();
        let queue_lookup = FileEvolutionProposalStore::open(&queue_dir)
            .unwrap()
            .load(&promotion.report.queue_proposal_id)
            .unwrap()
            .unwrap();

        assert_eq!(
            validation.report.status,
            EvolutionValidationBundleStatus::ReadyForQueue
        );
        assert_eq!(
            validation.report.proof_status,
            EvolutionProposalProofStatus::Proved
        );
        assert!(validation.report.blocking_reasons.is_empty());
        assert_eq!(
            queue_lookup.report.review_state,
            EvolutionProposalReviewState::PendingReview
        );
        assert_eq!(
            queue_lookup.report.proof_status,
            EvolutionProposalProofStatus::Proved
        );
        assert!(queue_lookup.report.blocking_reasons.is_empty());
        assert!(reconciliation.report.handoff_ready);
        assert!(
            render_evolution_materialization(&materialization.report)
                .contains("Evolution Draft Materialization")
        );
        assert!(
            render_evolution_validation_bundle(&validation.report)
                .contains("Evolution Validation Bundle")
        );
        assert!(
            render_evolution_queue_reconciliation(&reconciliation.report)
                .contains("Evolution Queue Reconciliation")
        );

        // Supply assurance lineage so the proposal passes the v1.51 assurance gate.
        {
            let store = FileEvolutionProposalStore::open(&queue_dir).unwrap();
            let mut proposal = store
                .load(&promotion.report.queue_proposal_id)
                .unwrap()
                .unwrap()
                .report;
            proposal.assurance = Some(passed_assurance_summary());
            proposal
                .blocking_reasons
                .retain(|r| r.source != "assurance");
            store.persist(&proposal).unwrap();
        }

        let accepted = queue
            .record_decision(
                &promotion.report.queue_proposal_id,
                EvolutionProposalDecisionAction::AcceptForCanary,
                "validated materialized candidate is ready for bounded canary review",
            )
            .unwrap();
        assert_eq!(
            accepted.report.review_state,
            EvolutionProposalReviewState::AcceptedForCanary
        );

        let handoff_lookup = handoff
            .create_handoff(
                &queue_dir,
                &promotion.report.queue_proposal_id,
                &shadow_dir,
                &validation.report.shadow_id,
            )
            .unwrap();
        assert!(handoff_lookup.report.blocking_reasons.is_empty());
    }

    #[tokio::test]
    async fn failed_materialized_candidate_blocks_reconciliation() {
        let root = unique_temp_dir("materialize-blocked");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verifications");
        let shadow_dir = root.join("shadows");
        let proof_dir = root.join("proofs");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let pressure_dir = root.join("pressures");
        let draft_dir = root.join("drafts");
        let draft_promotion_dir = root.join("draft-promotions");
        let materialization_dir = root.join("materializations");
        let validation_dir = root.join("validation");
        let reconciliation_dir = root.join("reconciliations");
        let queue_dir = root.join("queue");
        let config = sample_config();
        let replay =
            DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
        let verification = replay
            .evaluate_verification_path(office_control_experiment(), &verification_dir)
            .await
            .unwrap();
        let proofs =
            DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proof_dir)
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
            &materialization_dir,
            &validation_dir,
            &reconciliation_dir,
        )
        .unwrap();

        let pressure = harness
            .create_pressure_from_scorecard(&scorecards, &scorecard.report.scorecard_id)
            .unwrap();
        let draft = harness
            .create_draft(EvolutionDraftCreateRequest {
                pressure_id: pressure.report.pressure_id.clone(),
                strategy_id: "office_python_parent_followup_v1".to_string(),
                strategy_description: "broadens suspicious parent matching to python".to_string(),
                mutation: "broaden suspicious parent set".to_string(),
                rationale: "use materialization to prove the broadened candidate stays blocked"
                    .to_string(),
            })
            .unwrap();
        let promotion = harness
            .promote_draft(
                &queue_dir,
                &draft.report.draft_id,
                "queue this broadened draft for blocked reconciliation coverage",
            )
            .unwrap();
        let materialization = harness
            .materialize_draft(EvolutionDraftMaterializationRequest {
                draft_id: draft.report.draft_id.clone(),
                base_experiment_path: Some(office_control_experiment()),
                add_suspicious_parents: vec!["python".to_string()],
                ..EvolutionDraftMaterializationRequest::default()
            })
            .unwrap();
        let validation = harness
            .refresh_validation_bundle(
                &replay,
                &proofs,
                &scorecards,
                &experiment_dir,
                &verification_dir,
                &shadow_dir,
                &materialization.report.materialization_id,
            )
            .await
            .unwrap();
        let reconciliation = harness
            .reconcile_queue_proposal(
                &queue_dir,
                &promotion.report.promotion_id,
                &validation.report.validation_bundle_id,
            )
            .unwrap();
        let queue_lookup = FileEvolutionProposalStore::open(&queue_dir)
            .unwrap()
            .load(&promotion.report.queue_proposal_id)
            .unwrap()
            .unwrap();

        assert_eq!(
            validation.report.status,
            EvolutionValidationBundleStatus::Blocked
        );
        assert!(!validation.report.blocking_reasons.is_empty());
        assert_eq!(
            queue_lookup.report.review_state,
            EvolutionProposalReviewState::Blocked
        );
        assert!(!queue_lookup.report.blocking_reasons.is_empty());
        assert!(!reconciliation.report.handoff_ready);
    }
}
