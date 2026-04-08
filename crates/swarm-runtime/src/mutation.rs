use crate::drafting::{
    DefaultEvolutionDraftingHarness, EvolutionDraftMaterializationRequest,
    EvolutionDraftPromotionStoreError, EvolutionDraftingError, EvolutionMaterializationLookup,
    EvolutionMaterializationReport, EvolutionMaterializationStoreError, EvolutionPressureReport,
    EvolutionPressureSourceKind, EvolutionValidationBundleStatus,
};
use crate::evolution::{EvolutionProposalAdvisorySummary, EvolutionProposalProofStatus};
use crate::evolution::{
    EvolutionProposalReviewState, EvolutionProposalStoreError, FileEvolutionProposalStore,
};
use crate::replay::{
    DefaultReplayHarness, DetectorCandidateManifest, DetectorExperimentManifest, ExperimentLineage,
    ReplayHarnessError, load_detector_experiment_manifest,
};
use crate::strategy::{
    DefaultStrategyScorecardHarness, StrategyAdvisorError, StrategyAdvisoryRecommendation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_whisker::SuspiciousProcessTreeProfile;

/// Errors surfaced by the guided mutation workflow.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionMutationError {
    #[error(transparent)]
    Drafting(#[from] EvolutionDraftingError),

    #[error(transparent)]
    Replay(#[from] ReplayHarnessError),

    #[error(transparent)]
    PromotionStore(#[from] EvolutionDraftPromotionStoreError),

    #[error(transparent)]
    ProposalStore(#[from] EvolutionProposalStoreError),

    #[error(transparent)]
    MaterializationStore(#[from] EvolutionMaterializationStoreError),

    #[error(transparent)]
    Strategy(#[from] StrategyAdvisorError),

    #[error(transparent)]
    MutationStore(#[from] EvolutionMutationStoreError),

    #[error(transparent)]
    MutationMaterializationBatchStore(#[from] EvolutionMutationMaterializationBatchStoreError),

    #[error(transparent)]
    MutationValidationBatchStore(#[from] EvolutionMutationValidationBatchStoreError),

    #[error(transparent)]
    MutationRankingStore(#[from] EvolutionMutationRankingStoreError),

    #[error(transparent)]
    Serialization(#[from] serde_json::Error),

    #[error("invalid mutation spec request: {reason}")]
    InvalidMutationSpecRequest { reason: String },

    #[error("mutation spec `{mutation_spec_id}` was not found")]
    MutationSpecNotFound { mutation_spec_id: String },

    #[error("mutation spec `{mutation_spec_id}` already defines variant `{variant_id}`")]
    DuplicateVariantId {
        mutation_spec_id: String,
        variant_id: String,
    },

    #[error("mutation spec `{mutation_spec_id}` already defines strategy `{strategy_id}`")]
    DuplicateStrategyId {
        mutation_spec_id: String,
        strategy_id: String,
    },

    #[error("mutation spec `{mutation_spec_id}` does not define any variants yet")]
    MutationSpecHasNoVariants { mutation_spec_id: String },

    #[error("materialization batch `{batch_id}` was not found")]
    MaterializationBatchNotFound { batch_id: String },

    #[error("validation batch `{validation_batch_id}` was not found")]
    ValidationBatchNotFound { validation_batch_id: String },

    #[error("candidate ranking `{ranking_id}` was not found")]
    RankingNotFound { ranking_id: String },

    #[error("failed to read experiment search path `{path}`: {source}")]
    ManifestReadDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

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
}

/// Stable source kind for one mutation spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionMutationSourceKind {
    Draft,
    Materialization,
}

/// Structured profile overrides applied to one variant candidate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionMutationProfileOverrides {
    pub add_suspicious_parents: Vec<String>,
    pub remove_suspicious_parents: Vec<String>,
    pub add_suspicious_children: Vec<String>,
    pub remove_suspicious_children: Vec<String>,
    pub high_confidence_threshold: Option<String>,
    pub medium_confidence_threshold: Option<String>,
}

impl EvolutionMutationProfileOverrides {
    fn to_materialization_request(
        &self,
        draft_id: String,
        base_experiment_path: PathBuf,
    ) -> Result<EvolutionDraftMaterializationRequest, EvolutionMutationError> {
        let high_confidence_threshold = parse_optional_threshold(
            self.high_confidence_threshold.as_deref(),
            "high_confidence_threshold",
        )?;
        let medium_confidence_threshold = parse_optional_threshold(
            self.medium_confidence_threshold.as_deref(),
            "medium_confidence_threshold",
        )?;
        if let (Some(high), Some(medium)) = (high_confidence_threshold, medium_confidence_threshold)
            && medium > high
        {
            return Err(EvolutionMutationError::InvalidMutationSpecRequest {
                reason: format!(
                    "medium_confidence_threshold {medium:.3} cannot exceed high_confidence_threshold {high:.3}"
                ),
            });
        }

        Ok(EvolutionDraftMaterializationRequest {
            draft_id,
            base_experiment_path: Some(base_experiment_path),
            add_suspicious_parents: normalize_entries(&self.add_suspicious_parents),
            remove_suspicious_parents: normalize_entries(&self.remove_suspicious_parents),
            add_suspicious_children: normalize_entries(&self.add_suspicious_children),
            remove_suspicious_children: normalize_entries(&self.remove_suspicious_children),
            high_confidence_threshold,
            medium_confidence_threshold,
        })
    }

    fn dimensions(&self) -> Vec<String> {
        let mut dimensions = Vec::new();
        if !self.add_suspicious_parents.is_empty() {
            dimensions.push("add_suspicious_parent".to_string());
        }
        if !self.remove_suspicious_parents.is_empty() {
            dimensions.push("remove_suspicious_parent".to_string());
        }
        if !self.add_suspicious_children.is_empty() {
            dimensions.push("add_suspicious_child".to_string());
        }
        if !self.remove_suspicious_children.is_empty() {
            dimensions.push("remove_suspicious_child".to_string());
        }
        if self.high_confidence_threshold.is_some() {
            dimensions.push("high_confidence_threshold".to_string());
        }
        if self.medium_confidence_threshold.is_some() {
            dimensions.push("medium_confidence_threshold".to_string());
        }
        if dimensions.is_empty() {
            dimensions.push("profile_copy".to_string());
        }
        dimensions
    }
}

/// Request used to create one durable mutation spec from a draft or materialization.
#[derive(Debug, Clone)]
pub struct EvolutionMutationSpecCreateRequest {
    pub draft_id: Option<String>,
    pub materialization_id: Option<String>,
    pub base_experiment_path: Option<PathBuf>,
    pub rationale: String,
}

/// One operator-authored variant attached to a mutation spec.
#[derive(Debug, Clone)]
pub struct EvolutionMutationVariantCreateRequest {
    pub variant_id: Option<String>,
    pub strategy_id: String,
    pub strategy_description: String,
    pub mutation: String,
    pub rationale: String,
    pub overrides: EvolutionMutationProfileOverrides,
}

/// Durable mutation variant preserved on a mutation spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionMutationVariantSpec {
    pub variant_id: String,
    pub strategy_id: String,
    pub strategy_description: String,
    pub mutation: String,
    pub rationale: String,
    pub mutation_dimensions: Vec<String>,
    pub overrides: EvolutionMutationProfileOverrides,
}

/// Durable operator-authored mutation spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionMutationSpecReport {
    pub mutation_spec_id: String,
    pub created_at_ms: i64,
    pub source_kind: EvolutionMutationSourceKind,
    pub draft_id: String,
    pub materialization_id: Option<String>,
    pub pressure_id: String,
    pub promotion_id: Option<String>,
    pub queue_proposal_id: Option<String>,
    pub source_strategy_id: String,
    pub source_strategy_description: String,
    pub source_lineage: ExperimentLineage,
    pub source_pressure_kind: EvolutionPressureSourceKind,
    pub source_experiment_id: String,
    pub source_experiment_name: String,
    pub base_experiment_path: String,
    pub operator_rationale: String,
    pub variants: Vec<EvolutionMutationVariantSpec>,
}

/// Metadata surfaced for one persisted mutation spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionMutationSpecRecord {
    pub mutation_spec_id: String,
    pub source_kind: EvolutionMutationSourceKind,
    pub source_strategy_id: String,
    pub variant_count: usize,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl EvolutionMutationSpecRecord {
    fn from_report(report: &EvolutionMutationSpecReport, bundle_path: String) -> Self {
        Self {
            mutation_spec_id: report.mutation_spec_id.clone(),
            source_kind: report.source_kind,
            source_strategy_id: report.source_strategy_id.clone(),
            variant_count: report.variants.len(),
            created_at_ms: report.created_at_ms,
            bundle_path,
        }
    }
}

/// Persisted mutation spec loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionMutationSpecLookup {
    pub record: EvolutionMutationSpecRecord,
    pub report: EvolutionMutationSpecReport,
}

/// One candidate materialized from a mutation spec variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionMutationMaterializationEntry {
    pub variant_id: String,
    pub strategy_id: String,
    pub materialization_id: String,
    pub experiment_id: String,
    pub experiment_path: String,
    pub mutation_dimensions: Vec<String>,
    pub promotion_id: Option<String>,
    pub queue_proposal_id: Option<String>,
}

/// Durable batch artifact linking a mutation spec to several materialized candidates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionMutationMaterializationBatchReport {
    pub batch_id: String,
    pub mutation_spec_id: String,
    pub created_at_ms: i64,
    pub source_strategy_id: String,
    pub candidate_count: usize,
    pub entries: Vec<EvolutionMutationMaterializationEntry>,
}

/// Metadata surfaced for one persisted materialization batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionMutationMaterializationBatchRecord {
    pub batch_id: String,
    pub mutation_spec_id: String,
    pub candidate_count: usize,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl EvolutionMutationMaterializationBatchRecord {
    fn from_report(
        report: &EvolutionMutationMaterializationBatchReport,
        bundle_path: String,
    ) -> Self {
        Self {
            batch_id: report.batch_id.clone(),
            mutation_spec_id: report.mutation_spec_id.clone(),
            candidate_count: report.candidate_count,
            created_at_ms: report.created_at_ms,
            bundle_path,
        }
    }
}

/// Persisted materialization batch loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionMutationMaterializationBatchLookup {
    pub record: EvolutionMutationMaterializationBatchRecord,
    pub report: EvolutionMutationMaterializationBatchReport,
}

/// One validation result attached to one mutation-spec candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionMutationValidationEntry {
    pub variant_id: String,
    pub strategy_id: String,
    pub materialization_id: String,
    pub validation_bundle_id: String,
    pub status: EvolutionValidationBundleStatus,
    pub proof_status: EvolutionProposalProofStatus,
    pub advisory: Option<EvolutionProposalAdvisorySummary>,
    pub promotion_id: Option<String>,
    pub queue_proposal_id: Option<String>,
    pub blocking_reason_names: Vec<String>,
}

/// Durable batch artifact linking a mutation-spec candidate set to validation results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionMutationValidationBatchReport {
    pub validation_batch_id: String,
    pub mutation_spec_id: String,
    pub materialization_batch_id: String,
    pub created_at_ms: i64,
    pub ready_count: usize,
    pub blocked_count: usize,
    pub entries: Vec<EvolutionMutationValidationEntry>,
}

/// Metadata surfaced for one persisted validation batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionMutationValidationBatchRecord {
    pub validation_batch_id: String,
    pub mutation_spec_id: String,
    pub materialization_batch_id: String,
    pub ready_count: usize,
    pub blocked_count: usize,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl EvolutionMutationValidationBatchRecord {
    fn from_report(report: &EvolutionMutationValidationBatchReport, bundle_path: String) -> Self {
        Self {
            validation_batch_id: report.validation_batch_id.clone(),
            mutation_spec_id: report.mutation_spec_id.clone(),
            materialization_batch_id: report.materialization_batch_id.clone(),
            ready_count: report.ready_count,
            blocked_count: report.blocked_count,
            created_at_ms: report.created_at_ms,
            bundle_path,
        }
    }
}

/// Persisted validation batch loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionMutationValidationBatchLookup {
    pub record: EvolutionMutationValidationBatchRecord,
    pub report: EvolutionMutationValidationBatchReport,
}

/// One deterministic ranking entry derived from a validated mutation candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionCandidateRankingEntry {
    pub rank: usize,
    pub variant_id: String,
    pub strategy_id: String,
    pub materialization_id: String,
    pub validation_bundle_id: String,
    pub queue_proposal_id: Option<String>,
    pub queue_review_state: Option<EvolutionProposalReviewState>,
    pub score: f64,
    pub status: EvolutionValidationBundleStatus,
    pub proof_status: EvolutionProposalProofStatus,
    pub advisory_recommendation: Option<StrategyAdvisoryRecommendation>,
    pub advisory_score_delta: Option<f64>,
    pub blocking_reason_names: Vec<String>,
    pub ready_for_review: bool,
    pub summary: String,
}

/// One durable review packet extracted from the top-ranked candidates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionCandidateReviewPacket {
    pub packet_id: String,
    pub rank: usize,
    pub variant_id: String,
    pub strategy_id: String,
    pub materialization_id: String,
    pub validation_bundle_id: String,
    pub queue_proposal_id: Option<String>,
    pub queue_review_state: Option<EvolutionProposalReviewState>,
    pub advisory_scorecard_id: Option<String>,
    pub score: f64,
    pub summary: String,
}

/// Durable ranking report for one validated mutation batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionMutationRankingReport {
    pub ranking_id: String,
    pub mutation_spec_id: String,
    pub validation_batch_id: String,
    pub created_at_ms: i64,
    pub shortlist_count: usize,
    pub ranked_candidates: Vec<EvolutionCandidateRankingEntry>,
    pub review_packets: Vec<EvolutionCandidateReviewPacket>,
}

/// Metadata surfaced for one persisted ranking report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionMutationRankingRecord {
    pub ranking_id: String,
    pub mutation_spec_id: String,
    pub validation_batch_id: String,
    pub shortlist_count: usize,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl EvolutionMutationRankingRecord {
    fn from_report(report: &EvolutionMutationRankingReport, bundle_path: String) -> Self {
        Self {
            ranking_id: report.ranking_id.clone(),
            mutation_spec_id: report.mutation_spec_id.clone(),
            validation_batch_id: report.validation_batch_id.clone(),
            shortlist_count: report.shortlist_count,
            created_at_ms: report.created_at_ms,
            bundle_path,
        }
    }
}

/// Persisted ranking report loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionMutationRankingLookup {
    pub record: EvolutionMutationRankingRecord,
    pub report: EvolutionMutationRankingReport,
}

/// Errors raised by the persisted mutation-spec store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionMutationStoreError {
    #[error("failed to read evolution mutation store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution mutation store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution mutation store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised by the persisted materialization-batch store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionMutationMaterializationBatchStoreError {
    #[error(
        "failed to read evolution mutation materialization batch store file `{path}`: {source}"
    )]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "failed to write evolution mutation materialization batch store file `{path}`: {source}"
    )]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "failed to parse evolution mutation materialization batch store file `{path}`: {source}"
    )]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised by the persisted validation-batch store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionMutationValidationBatchStoreError {
    #[error("failed to read evolution mutation validation batch store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution mutation validation batch store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution mutation validation batch store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised by the persisted ranking store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionMutationRankingStoreError {
    #[error("failed to read evolution mutation ranking store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution mutation ranking store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution mutation ranking store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// File-backed store for durable mutation specs.
#[derive(Debug, Clone)]
pub struct FileEvolutionMutationStore {
    root: PathBuf,
}

impl FileEvolutionMutationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionMutationStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionMutationStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, mutation_spec_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(mutation_spec_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<EvolutionMutationIndex, EvolutionMutationStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionMutationIndex::default());
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| EvolutionMutationStoreError::Read {
                path: path.clone(),
                source,
            })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionMutationStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionMutationIndex,
    ) -> Result<(), EvolutionMutationStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionMutationStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionMutationStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionMutationSpecReport,
    ) -> Result<EvolutionMutationSpecRecord, EvolutionMutationStoreError> {
        let path = self.report_path(&report.mutation_spec_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionMutationStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionMutationStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = EvolutionMutationSpecRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.mutation_spec_id != record.mutation_spec_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        mutation_spec_id: &str,
    ) -> Result<Option<EvolutionMutationSpecLookup>, EvolutionMutationStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.mutation_spec_id == mutation_spec_id)
            .cloned()
        else {
            return Ok(None);
        };

        let path = PathBuf::from(&record.bundle_path);
        let raw =
            fs::read_to_string(&path).map_err(|source| EvolutionMutationStoreError::Read {
                path: path.clone(),
                source,
            })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionMutationStoreError::Parse { path, source })?;
        Ok(Some(EvolutionMutationSpecLookup { record, report }))
    }
}

/// File-backed store for durable materialization batches.
#[derive(Debug, Clone)]
pub struct FileEvolutionMutationMaterializationBatchStore {
    root: PathBuf,
}

impl FileEvolutionMutationMaterializationBatchStore {
    pub fn open(
        path: impl AsRef<Path>,
    ) -> Result<Self, EvolutionMutationMaterializationBatchStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionMutationMaterializationBatchStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, batch_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(batch_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(
        &self,
    ) -> Result<
        EvolutionMutationMaterializationBatchIndex,
        EvolutionMutationMaterializationBatchStoreError,
    > {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionMutationMaterializationBatchIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionMutationMaterializationBatchStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        serde_json::from_str(&raw).map_err(|source| {
            EvolutionMutationMaterializationBatchStoreError::Parse { path, source }
        })
    }

    fn write_index(
        &self,
        index: &EvolutionMutationMaterializationBatchIndex,
    ) -> Result<(), EvolutionMutationMaterializationBatchStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionMutationMaterializationBatchStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| {
            EvolutionMutationMaterializationBatchStoreError::Write { path, source }
        })
    }

    pub fn persist(
        &self,
        report: &EvolutionMutationMaterializationBatchReport,
    ) -> Result<
        EvolutionMutationMaterializationBatchRecord,
        EvolutionMutationMaterializationBatchStoreError,
    > {
        let path = self.report_path(&report.batch_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionMutationMaterializationBatchStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| {
            EvolutionMutationMaterializationBatchStoreError::Write {
                path: path.clone(),
                source,
            }
        })?;

        let mut index = self.read_index()?;
        let record = EvolutionMutationMaterializationBatchRecord::from_report(
            report,
            path.display().to_string(),
        );
        index
            .entries
            .retain(|entry| entry.batch_id != record.batch_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        batch_id: &str,
    ) -> Result<
        Option<EvolutionMutationMaterializationBatchLookup>,
        EvolutionMutationMaterializationBatchStoreError,
    > {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.batch_id == batch_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionMutationMaterializationBatchStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let report = serde_json::from_str(&raw).map_err(|source| {
            EvolutionMutationMaterializationBatchStoreError::Parse { path, source }
        })?;
        Ok(Some(EvolutionMutationMaterializationBatchLookup {
            record,
            report,
        }))
    }
}

/// File-backed store for durable validation batches.
#[derive(Debug, Clone)]
pub struct FileEvolutionMutationValidationBatchStore {
    root: PathBuf,
}

impl FileEvolutionMutationValidationBatchStore {
    pub fn open(
        path: impl AsRef<Path>,
    ) -> Result<Self, EvolutionMutationValidationBatchStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionMutationValidationBatchStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, validation_batch_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(validation_batch_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(
        &self,
    ) -> Result<EvolutionMutationValidationBatchIndex, EvolutionMutationValidationBatchStoreError>
    {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionMutationValidationBatchIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionMutationValidationBatchStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionMutationValidationBatchStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionMutationValidationBatchIndex,
    ) -> Result<(), EvolutionMutationValidationBatchStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionMutationValidationBatchStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| EvolutionMutationValidationBatchStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionMutationValidationBatchReport,
    ) -> Result<EvolutionMutationValidationBatchRecord, EvolutionMutationValidationBatchStoreError>
    {
        let path = self.report_path(&report.validation_batch_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionMutationValidationBatchStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| {
            EvolutionMutationValidationBatchStoreError::Write {
                path: path.clone(),
                source,
            }
        })?;

        let mut index = self.read_index()?;
        let record =
            EvolutionMutationValidationBatchRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.validation_batch_id != record.validation_batch_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        validation_batch_id: &str,
    ) -> Result<
        Option<EvolutionMutationValidationBatchLookup>,
        EvolutionMutationValidationBatchStoreError,
    > {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.validation_batch_id == validation_batch_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionMutationValidationBatchStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionMutationValidationBatchStoreError::Parse { path, source })?;
        Ok(Some(EvolutionMutationValidationBatchLookup {
            record,
            report,
        }))
    }
}

/// File-backed store for durable candidate rankings.
#[derive(Debug, Clone)]
pub struct FileEvolutionMutationRankingStore {
    root: PathBuf,
}

impl FileEvolutionMutationRankingStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionMutationRankingStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionMutationRankingStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, ranking_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(ranking_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(
        &self,
    ) -> Result<EvolutionMutationRankingIndex, EvolutionMutationRankingStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionMutationRankingIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionMutationRankingStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionMutationRankingStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionMutationRankingIndex,
    ) -> Result<(), EvolutionMutationRankingStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionMutationRankingStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| EvolutionMutationRankingStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionMutationRankingReport,
    ) -> Result<EvolutionMutationRankingRecord, EvolutionMutationRankingStoreError> {
        let path = self.report_path(&report.ranking_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionMutationRankingStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionMutationRankingStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record =
            EvolutionMutationRankingRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.ranking_id != record.ranking_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        ranking_id: &str,
    ) -> Result<Option<EvolutionMutationRankingLookup>, EvolutionMutationRankingStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.ranking_id == ranking_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionMutationRankingStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionMutationRankingStoreError::Parse { path, source })?;
        Ok(Some(EvolutionMutationRankingLookup { record, report }))
    }
}

/// Harness for operator-authored mutation specs.
pub struct DefaultEvolutionMutationHarness {
    pub mutation_store: FileEvolutionMutationStore,
    pub materialization_batch_store: FileEvolutionMutationMaterializationBatchStore,
    pub validation_batch_store: FileEvolutionMutationValidationBatchStore,
    pub ranking_store: FileEvolutionMutationRankingStore,
}

impl DefaultEvolutionMutationHarness {
    pub fn from_path(
        mutation_results_dir: impl AsRef<Path>,
        materialization_batch_results_dir: impl AsRef<Path>,
        validation_batch_results_dir: impl AsRef<Path>,
        ranking_results_dir: impl AsRef<Path>,
    ) -> Result<Self, EvolutionMutationError> {
        Ok(Self {
            mutation_store: FileEvolutionMutationStore::open(mutation_results_dir)?,
            materialization_batch_store: FileEvolutionMutationMaterializationBatchStore::open(
                materialization_batch_results_dir,
            )?,
            validation_batch_store: FileEvolutionMutationValidationBatchStore::open(
                validation_batch_results_dir,
            )?,
            ranking_store: FileEvolutionMutationRankingStore::open(ranking_results_dir)?,
        })
    }

    pub fn create_mutation_spec(
        &self,
        drafting: &DefaultEvolutionDraftingHarness,
        request: EvolutionMutationSpecCreateRequest,
    ) -> Result<EvolutionMutationSpecLookup, EvolutionMutationError> {
        validate_create_request(&request)?;
        let created_at_ms = now_ms();

        let report = if let Some(draft_id) = request.draft_id {
            let draft = drafting.load_draft(&draft_id)?.ok_or_else(|| {
                EvolutionDraftingError::DraftNotFound {
                    draft_id: draft_id.clone(),
                }
            })?;
            let pressure = drafting
                .load_pressure(&draft.report.pressure_id)?
                .ok_or_else(|| EvolutionDraftingError::PressureNotFound {
                    pressure_id: draft.report.pressure_id.clone(),
                })?;
            let base_experiment_path = match request.base_experiment_path {
                Some(path) => path,
                None => infer_base_experiment_path(
                    &drafting.config_path,
                    &draft.report.draft_id,
                    &pressure.report,
                )?,
            };
            let base_manifest = load_detector_experiment_manifest(&base_experiment_path)?;
            let promotion = drafting
                .promotion_store
                .load_for_draft(&draft.report.draft_id)?;

            EvolutionMutationSpecReport {
                mutation_spec_id: mutation_spec_id(
                    EvolutionMutationSourceKind::Draft,
                    &draft.report.strategy_id,
                    created_at_ms,
                ),
                created_at_ms,
                source_kind: EvolutionMutationSourceKind::Draft,
                draft_id: draft.report.draft_id.clone(),
                materialization_id: None,
                pressure_id: draft.report.pressure_id.clone(),
                promotion_id: promotion
                    .as_ref()
                    .map(|lookup| lookup.report.promotion_id.clone()),
                queue_proposal_id: promotion
                    .as_ref()
                    .map(|lookup| lookup.report.queue_proposal_id.clone()),
                source_strategy_id: draft.report.strategy_id.clone(),
                source_strategy_description: draft.report.strategy_description.clone(),
                source_lineage: ExperimentLineage {
                    parent_strategy_id: draft.report.parent_strategy_id.clone(),
                    mutation: draft.report.lineage_mutation.clone(),
                    rationale: draft.report.lineage_rationale.clone(),
                },
                source_pressure_kind: pressure.report.source_kind,
                source_experiment_id: pressure
                    .report
                    .experiment_id
                    .clone()
                    .unwrap_or_else(|| format!("experiment:{}", base_manifest.name)),
                source_experiment_name: pressure
                    .report
                    .experiment_name
                    .clone()
                    .unwrap_or_else(|| base_manifest.name.clone()),
                base_experiment_path: base_experiment_path.display().to_string(),
                operator_rationale: request.rationale,
                variants: Vec::new(),
            }
        } else {
            let materialization_id = request.materialization_id.ok_or_else(|| {
                EvolutionMutationError::InvalidMutationSpecRequest {
                    reason: "exactly one of draft_id or materialization_id must be set".to_string(),
                }
            })?;
            let materialization = drafting
                .load_materialization(&materialization_id)?
                .ok_or_else(|| EvolutionDraftingError::MaterializationNotFound {
                    materialization_id: materialization_id.clone(),
                })?;
            let promotion = drafting
                .promotion_store
                .load_for_draft(&materialization.report.draft_id)?;

            EvolutionMutationSpecReport {
                mutation_spec_id: mutation_spec_id(
                    EvolutionMutationSourceKind::Materialization,
                    &materialization.report.strategy_id,
                    created_at_ms,
                ),
                created_at_ms,
                source_kind: EvolutionMutationSourceKind::Materialization,
                draft_id: materialization.report.draft_id.clone(),
                materialization_id: Some(materialization.report.materialization_id.clone()),
                pressure_id: materialization.report.pressure_id.clone(),
                promotion_id: promotion
                    .as_ref()
                    .map(|lookup| lookup.report.promotion_id.clone()),
                queue_proposal_id: promotion
                    .as_ref()
                    .map(|lookup| lookup.report.queue_proposal_id.clone()),
                source_strategy_id: materialization.report.strategy_id.clone(),
                source_strategy_description: materialization.report.strategy_description.clone(),
                source_lineage: materialization.report.lineage.clone(),
                source_pressure_kind: resolve_materialization_pressure_kind(
                    drafting,
                    &materialization,
                )?,
                source_experiment_id: materialization.report.experiment_id.clone(),
                source_experiment_name: materialization.report.experiment_name.clone(),
                base_experiment_path: request
                    .base_experiment_path
                    .unwrap_or_else(|| PathBuf::from(&materialization.report.experiment_path))
                    .display()
                    .to_string(),
                operator_rationale: request.rationale,
                variants: Vec::new(),
            }
        };

        let record = self.mutation_store.persist(&report)?;
        Ok(EvolutionMutationSpecLookup { record, report })
    }

    pub fn append_variant(
        &self,
        mutation_spec_id: &str,
        request: EvolutionMutationVariantCreateRequest,
    ) -> Result<EvolutionMutationSpecLookup, EvolutionMutationError> {
        let mut lookup = self.mutation_store.load(mutation_spec_id)?.ok_or_else(|| {
            EvolutionMutationError::MutationSpecNotFound {
                mutation_spec_id: mutation_spec_id.to_string(),
            }
        })?;

        let variant_id = request
            .variant_id
            .unwrap_or_else(|| sanitize_id(&request.strategy_id));
        if lookup
            .report
            .variants
            .iter()
            .any(|variant| variant.variant_id == variant_id)
        {
            return Err(EvolutionMutationError::DuplicateVariantId {
                mutation_spec_id: mutation_spec_id.to_string(),
                variant_id,
            });
        }
        if lookup
            .report
            .variants
            .iter()
            .any(|variant| variant.strategy_id == request.strategy_id)
        {
            return Err(EvolutionMutationError::DuplicateStrategyId {
                mutation_spec_id: mutation_spec_id.to_string(),
                strategy_id: request.strategy_id,
            });
        }

        let _validation_request = request.overrides.to_materialization_request(
            lookup.report.draft_id.clone(),
            PathBuf::from(&lookup.report.base_experiment_path),
        )?;

        let variant = EvolutionMutationVariantSpec {
            variant_id,
            strategy_id: request.strategy_id,
            strategy_description: request.strategy_description,
            mutation: request.mutation,
            rationale: request.rationale,
            mutation_dimensions: request.overrides.dimensions(),
            overrides: request.overrides,
        };

        lookup.report.variants.push(variant);
        let record = self.mutation_store.persist(&lookup.report)?;
        Ok(EvolutionMutationSpecLookup {
            record,
            report: lookup.report,
        })
    }

    pub fn load_mutation_spec(
        &self,
        mutation_spec_id: &str,
    ) -> Result<Option<EvolutionMutationSpecLookup>, EvolutionMutationError> {
        Ok(self.mutation_store.load(mutation_spec_id)?)
    }

    pub fn materialize_batch(
        &self,
        drafting: &DefaultEvolutionDraftingHarness,
        mutation_spec_id: &str,
    ) -> Result<EvolutionMutationMaterializationBatchLookup, EvolutionMutationError> {
        let spec = self.mutation_store.load(mutation_spec_id)?.ok_or_else(|| {
            EvolutionMutationError::MutationSpecNotFound {
                mutation_spec_id: mutation_spec_id.to_string(),
            }
        })?;
        if spec.report.variants.is_empty() {
            return Err(EvolutionMutationError::MutationSpecHasNoVariants {
                mutation_spec_id: mutation_spec_id.to_string(),
            });
        }

        let base_experiment_path = PathBuf::from(&spec.report.base_experiment_path);
        let created_at_ms = now_ms();
        let mut entries = Vec::new();

        for (index, variant) in spec.report.variants.iter().enumerate() {
            let request = variant.overrides.to_materialization_request(
                spec.report.draft_id.clone(),
                base_experiment_path.clone(),
            )?;
            let report = materialize_variant_report(
                &spec.report,
                variant,
                &request,
                created_at_ms + index as i64,
            )?;
            drafting.materialization_store.persist(&report)?;
            entries.push(EvolutionMutationMaterializationEntry {
                variant_id: variant.variant_id.clone(),
                strategy_id: variant.strategy_id.clone(),
                materialization_id: report.materialization_id,
                experiment_id: report.experiment_id,
                experiment_path: report.experiment_path,
                mutation_dimensions: variant.mutation_dimensions.clone(),
                promotion_id: spec.report.promotion_id.clone(),
                queue_proposal_id: spec.report.queue_proposal_id.clone(),
            });
        }

        let report = EvolutionMutationMaterializationBatchReport {
            batch_id: mutation_materialization_batch_id(
                &spec.report.mutation_spec_id,
                created_at_ms,
            ),
            mutation_spec_id: spec.report.mutation_spec_id.clone(),
            created_at_ms,
            source_strategy_id: spec.report.source_strategy_id.clone(),
            candidate_count: entries.len(),
            entries,
        };
        let record = self.materialization_batch_store.persist(&report)?;
        Ok(EvolutionMutationMaterializationBatchLookup { record, report })
    }

    pub fn load_materialization_batch(
        &self,
        batch_id: &str,
    ) -> Result<Option<EvolutionMutationMaterializationBatchLookup>, EvolutionMutationError> {
        Ok(self.materialization_batch_store.load(batch_id)?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn refresh_validation_batch(
        &self,
        drafting: &DefaultEvolutionDraftingHarness,
        replay_harness: &DefaultReplayHarness,
        proof_harness: &crate::evolution::DefaultEvolutionProofHarness,
        scorecard_harness: &DefaultStrategyScorecardHarness,
        experiment_results_dir: impl AsRef<Path>,
        verification_results_dir: impl AsRef<Path>,
        shadow_results_dir: impl AsRef<Path>,
        batch_id: &str,
    ) -> Result<EvolutionMutationValidationBatchLookup, EvolutionMutationError> {
        let batch = self
            .materialization_batch_store
            .load(batch_id)?
            .ok_or_else(|| EvolutionMutationError::MaterializationBatchNotFound {
                batch_id: batch_id.to_string(),
            })?;
        let created_at_ms = now_ms();
        let mut entries = Vec::new();

        for item in &batch.report.entries {
            let validation = drafting
                .refresh_validation_bundle(
                    replay_harness,
                    proof_harness,
                    scorecard_harness,
                    experiment_results_dir.as_ref(),
                    verification_results_dir.as_ref(),
                    shadow_results_dir.as_ref(),
                    &item.materialization_id,
                )
                .await?;
            entries.push(EvolutionMutationValidationEntry {
                variant_id: item.variant_id.clone(),
                strategy_id: item.strategy_id.clone(),
                materialization_id: item.materialization_id.clone(),
                validation_bundle_id: validation.report.validation_bundle_id.clone(),
                status: validation.report.status,
                proof_status: validation.report.proof_status,
                advisory: validation.report.advisory.clone(),
                promotion_id: item.promotion_id.clone(),
                queue_proposal_id: item.queue_proposal_id.clone(),
                blocking_reason_names: validation
                    .report
                    .blocking_reasons
                    .iter()
                    .map(|reason| reason.name.clone())
                    .collect(),
            });
        }

        let ready_count = entries
            .iter()
            .filter(|entry| entry.status == EvolutionValidationBundleStatus::ReadyForQueue)
            .count();
        let blocked_count = entries.len() - ready_count;
        let report = EvolutionMutationValidationBatchReport {
            validation_batch_id: mutation_validation_batch_id(
                &batch.report.mutation_spec_id,
                created_at_ms,
            ),
            mutation_spec_id: batch.report.mutation_spec_id.clone(),
            materialization_batch_id: batch.report.batch_id.clone(),
            created_at_ms,
            ready_count,
            blocked_count,
            entries,
        };
        let record = self.validation_batch_store.persist(&report)?;
        Ok(EvolutionMutationValidationBatchLookup { record, report })
    }

    pub fn load_validation_batch(
        &self,
        validation_batch_id: &str,
    ) -> Result<Option<EvolutionMutationValidationBatchLookup>, EvolutionMutationError> {
        Ok(self.validation_batch_store.load(validation_batch_id)?)
    }

    pub fn rank_candidates(
        &self,
        queue_results_dir: impl AsRef<Path>,
        validation_batch_id: &str,
        shortlist_count: usize,
    ) -> Result<EvolutionMutationRankingLookup, EvolutionMutationError> {
        let validation_batch = self
            .validation_batch_store
            .load(validation_batch_id)?
            .ok_or_else(|| EvolutionMutationError::ValidationBatchNotFound {
                validation_batch_id: validation_batch_id.to_string(),
            })?;
        let queue_store = FileEvolutionProposalStore::open(queue_results_dir)?;
        let created_at_ms = now_ms();
        let mut ranked_candidates = validation_batch
            .report
            .entries
            .iter()
            .map(|entry| {
                let queue_review_state = match entry.queue_proposal_id.as_deref() {
                    Some(proposal_id) => queue_store
                        .load(proposal_id)?
                        .map(|lookup| lookup.report.review_state),
                    None => None,
                };
                let score = candidate_score(entry, queue_review_state);
                let summary = candidate_summary(entry, queue_review_state, score);
                Ok::<_, EvolutionMutationError>(EvolutionCandidateRankingEntry {
                    rank: 0,
                    variant_id: entry.variant_id.clone(),
                    strategy_id: entry.strategy_id.clone(),
                    materialization_id: entry.materialization_id.clone(),
                    validation_bundle_id: entry.validation_bundle_id.clone(),
                    queue_proposal_id: entry.queue_proposal_id.clone(),
                    queue_review_state,
                    score,
                    status: entry.status,
                    proof_status: entry.proof_status,
                    advisory_recommendation: entry.advisory.as_ref().map(|a| a.recommendation),
                    advisory_score_delta: entry.advisory.as_ref().map(|a| a.score_delta),
                    blocking_reason_names: entry.blocking_reason_names.clone(),
                    ready_for_review: entry.status
                        == EvolutionValidationBundleStatus::ReadyForQueue,
                    summary,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        ranked_candidates.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.strategy_id.cmp(&right.strategy_id))
        });
        for (index, candidate) in ranked_candidates.iter_mut().enumerate() {
            candidate.rank = index + 1;
        }

        let shortlist_count = shortlist_count.max(1).min(ranked_candidates.len());
        let review_packets = ranked_candidates
            .iter()
            .take(shortlist_count)
            .map(|candidate| EvolutionCandidateReviewPacket {
                packet_id: review_packet_id(
                    &validation_batch.report.validation_batch_id,
                    candidate.rank,
                    &candidate.variant_id,
                ),
                rank: candidate.rank,
                variant_id: candidate.variant_id.clone(),
                strategy_id: candidate.strategy_id.clone(),
                materialization_id: candidate.materialization_id.clone(),
                validation_bundle_id: candidate.validation_bundle_id.clone(),
                queue_proposal_id: candidate.queue_proposal_id.clone(),
                queue_review_state: candidate.queue_review_state,
                advisory_scorecard_id: validation_batch
                    .report
                    .entries
                    .iter()
                    .find(|entry| entry.variant_id == candidate.variant_id)
                    .and_then(|entry| entry.advisory.as_ref().map(|a| a.scorecard_id.clone())),
                score: candidate.score,
                summary: candidate.summary.clone(),
            })
            .collect::<Vec<_>>();

        let report = EvolutionMutationRankingReport {
            ranking_id: mutation_ranking_id(
                &validation_batch.report.mutation_spec_id,
                &validation_batch.report.validation_batch_id,
                created_at_ms,
            ),
            mutation_spec_id: validation_batch.report.mutation_spec_id.clone(),
            validation_batch_id: validation_batch.report.validation_batch_id.clone(),
            created_at_ms,
            shortlist_count,
            ranked_candidates,
            review_packets,
        };
        let record = self.ranking_store.persist(&report)?;
        Ok(EvolutionMutationRankingLookup { record, report })
    }

    pub fn load_ranking(
        &self,
        ranking_id: &str,
    ) -> Result<Option<EvolutionMutationRankingLookup>, EvolutionMutationError> {
        Ok(self.ranking_store.load(ranking_id)?)
    }
}

/// Render one durable mutation spec.
pub fn render_evolution_mutation_spec(report: &EvolutionMutationSpecReport) -> String {
    let mut lines = vec![
        "Evolution Mutation Spec".to_string(),
        format!("Mutation spec ID: {}", report.mutation_spec_id),
        format!("Source kind: {}", mutation_source_label(report.source_kind)),
        format!("Draft ID: {}", report.draft_id),
        format!(
            "Source strategy: {} | {}",
            report.source_strategy_id, report.source_strategy_description
        ),
        format!(
            "Source experiment: {} ({})",
            report.source_experiment_name, report.source_experiment_id
        ),
        format!("Base experiment path: {}", report.base_experiment_path),
        format!("Operator rationale: {}", report.operator_rationale),
    ];

    if let Some(materialization_id) = &report.materialization_id {
        lines.push(format!("Source materialization: {}", materialization_id));
    }
    if let Some(queue_proposal_id) = &report.queue_proposal_id {
        lines.push(format!("Reviewed queue proposal: {}", queue_proposal_id));
    }

    if report.variants.is_empty() {
        lines.push("Variants: none".to_string());
    } else {
        lines.push("Variants:".to_string());
        for variant in &report.variants {
            lines.push(format!(
                "- {} | strategy={} | mutation={} | dims={}",
                variant.variant_id,
                variant.strategy_id,
                variant.mutation,
                variant.mutation_dimensions.join(",")
            ));
        }
    }

    lines.join("\n")
}

/// Render one mutation materialization batch.
pub fn render_evolution_mutation_materialization_batch(
    report: &EvolutionMutationMaterializationBatchReport,
) -> String {
    let mut lines = vec![
        "Evolution Mutation Materialization Batch".to_string(),
        format!("Batch ID: {}", report.batch_id),
        format!("Mutation spec ID: {}", report.mutation_spec_id),
        format!("Source strategy: {}", report.source_strategy_id),
        format!("Candidate count: {}", report.candidate_count),
        "Entries:".to_string(),
    ];
    for entry in &report.entries {
        lines.push(format!(
            "- {} | strategy={} | materialization={} | dims={}",
            entry.variant_id,
            entry.strategy_id,
            entry.materialization_id,
            entry.mutation_dimensions.join(",")
        ));
    }
    lines.join("\n")
}

/// Render one mutation validation batch.
pub fn render_evolution_mutation_validation_batch(
    report: &EvolutionMutationValidationBatchReport,
) -> String {
    let mut lines = vec![
        "Evolution Mutation Validation Batch".to_string(),
        format!("Validation batch ID: {}", report.validation_batch_id),
        format!("Mutation spec ID: {}", report.mutation_spec_id),
        format!(
            "Materialization batch ID: {}",
            report.materialization_batch_id
        ),
        format!(
            "Ready: {} | Blocked: {}",
            report.ready_count, report.blocked_count
        ),
        "Entries:".to_string(),
    ];
    for entry in &report.entries {
        lines.push(format!(
            "- {} | strategy={} | validation={} | status={} | proof={}",
            entry.variant_id,
            entry.strategy_id,
            entry.validation_bundle_id,
            validation_bundle_status_label(entry.status),
            proof_status_label(entry.proof_status)
        ));
    }
    lines.join("\n")
}

/// Render one candidate ranking report.
pub fn render_evolution_mutation_ranking(report: &EvolutionMutationRankingReport) -> String {
    let mut lines = vec![
        "Evolution Mutation Candidate Ranking".to_string(),
        format!("Ranking ID: {}", report.ranking_id),
        format!("Mutation spec ID: {}", report.mutation_spec_id),
        format!("Validation batch ID: {}", report.validation_batch_id),
        format!("Shortlist count: {}", report.shortlist_count),
        "Ranked candidates:".to_string(),
    ];
    for candidate in &report.ranked_candidates {
        lines.push(format!(
            "- #{} {} | strategy={} | score={:.3} | status={} | queue={}",
            candidate.rank,
            candidate.variant_id,
            candidate.strategy_id,
            candidate.score,
            validation_bundle_status_label(candidate.status),
            candidate
                .queue_review_state
                .map(review_state_label)
                .unwrap_or("none")
        ));
    }
    lines.push("Review packets:".to_string());
    for packet in &report.review_packets {
        lines.push(format!(
            "- {} | rank={} | strategy={} | validation={}",
            packet.packet_id, packet.rank, packet.strategy_id, packet.validation_bundle_id
        ));
    }
    lines.join("\n")
}

fn materialize_variant_report(
    spec: &EvolutionMutationSpecReport,
    variant: &EvolutionMutationVariantSpec,
    request: &EvolutionDraftMaterializationRequest,
    created_at_ms: i64,
) -> Result<EvolutionMaterializationReport, EvolutionMutationError> {
    let base_experiment_path = request.base_experiment_path.as_ref().ok_or_else(|| {
        EvolutionMutationError::InvalidMutationSpecRequest {
            reason: "materialization request is missing a base experiment path".to_string(),
        }
    })?;
    let base_manifest = load_detector_experiment_manifest(base_experiment_path)?;
    let mut profile = match &base_manifest.candidate {
        DetectorCandidateManifest::SuspiciousProcessTree { profile, .. } => profile.clone(),
        DetectorCandidateManifest::DnsExfiltration { strategy_id, .. }
        | DetectorCandidateManifest::LateralMovement { strategy_id, .. }
        | DetectorCandidateManifest::CredentialAccess { strategy_id, .. }
        | DetectorCandidateManifest::SuspiciousScripting { strategy_id, .. }
        | DetectorCandidateManifest::Persistence { strategy_id, .. }
        | DetectorCandidateManifest::SupplyChain { strategy_id, .. }
        | DetectorCandidateManifest::NetworkConnect { strategy_id, .. } => {
            return Err(ReplayHarnessError::UnsupportedDetector {
                strategy: format!(
                    "mutation materialization not yet supported for detector `{strategy_id}`"
                ),
            }
            .into());
        }
    };
    let applied_changes = apply_profile_overrides(&mut profile, request)?;
    let experiment_name = materialized_experiment_name(&variant.strategy_id, created_at_ms);
    let experiment_path =
        materialized_experiment_path(base_experiment_path, &variant.strategy_id, created_at_ms);
    let manifest = DetectorExperimentManifest {
        name: experiment_name.clone(),
        description: format!(
            "Materialized from mutation spec `{}` variant `{}` using base experiment `{}`",
            spec.mutation_spec_id, variant.variant_id, base_manifest.name
        ),
        corpus: base_manifest.corpus.clone(),
        verification: base_manifest.verification.clone(),
        candidate: DetectorCandidateManifest::SuspiciousProcessTree {
            strategy_id: variant.strategy_id.clone(),
            description: variant.strategy_description.clone(),
            profile: profile.clone(),
        },
        lineage: ExperimentLineage {
            parent_strategy_id: spec.source_strategy_id.clone(),
            mutation: variant.mutation.clone(),
            rationale: format!("{} | {}", spec.operator_rationale, variant.rationale),
        },
        gates: base_manifest.gates.clone(),
    };

    if let Some(parent) = experiment_path.parent() {
        fs::create_dir_all(parent).map_err(|source| EvolutionMutationError::ManifestWrite {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let raw = serde_yaml::to_string(&manifest).map_err(|source| {
        EvolutionMutationError::ManifestSerialize {
            path: experiment_path.clone(),
            source,
        }
    })?;
    fs::write(&experiment_path, raw).map_err(|source| EvolutionMutationError::ManifestWrite {
        path: experiment_path.clone(),
        source,
    })?;

    Ok(EvolutionMaterializationReport {
        materialization_id: mutation_materialization_id(
            &spec.mutation_spec_id,
            &variant.variant_id,
            created_at_ms,
        ),
        created_at_ms,
        draft_id: spec.draft_id.clone(),
        pressure_id: spec.pressure_id.clone(),
        source_experiment_id: spec.source_experiment_id.clone(),
        source_experiment_name: spec.source_experiment_name.clone(),
        base_experiment_path: spec.base_experiment_path.clone(),
        experiment_id: experiment_id_for_manifest(&manifest),
        experiment_name,
        experiment_path: experiment_path.display().to_string(),
        strategy_id: variant.strategy_id.clone(),
        strategy_description: variant.strategy_description.clone(),
        lineage: manifest.lineage.clone(),
        profile,
        manifest_sha256: sha256_hex(&manifest)?,
        lineage_sha256: sha256_hex(&manifest.lineage)?,
        applied_changes,
    })
}

fn candidate_score(
    entry: &EvolutionMutationValidationEntry,
    queue_review_state: Option<EvolutionProposalReviewState>,
) -> f64 {
    let mut score = 0.0;
    score += match entry.status {
        EvolutionValidationBundleStatus::ReadyForQueue => 100.0,
        EvolutionValidationBundleStatus::Blocked => 0.0,
    };
    score += match entry.proof_status {
        EvolutionProposalProofStatus::Proved => 15.0,
        EvolutionProposalProofStatus::Inconsistent => -10.0,
        EvolutionProposalProofStatus::Missing => -20.0,
    };
    if let Some(advisory) = &entry.advisory {
        score += advisory.score_delta * 25.0;
        score += advisory.candidate_matching_memory_count as f64;
        score += match advisory.recommendation {
            StrategyAdvisoryRecommendation::CandidatePreferred => 6.0,
            StrategyAdvisoryRecommendation::CandidateAlreadyStableInProduction => 2.0,
            StrategyAdvisoryRecommendation::RetainBaseline => 0.0,
        };
    }
    score -= (entry.blocking_reason_names.len() as f64) * 5.0;
    score += match queue_review_state {
        Some(EvolutionProposalReviewState::PendingReview) => 1.0,
        Some(EvolutionProposalReviewState::AcceptedForCanary) => 2.0,
        Some(EvolutionProposalReviewState::Deferred) => 0.0,
        Some(EvolutionProposalReviewState::Rejected) => -20.0,
        Some(EvolutionProposalReviewState::Blocked) => -20.0,
        None => 0.0,
    };
    score
}

fn candidate_summary(
    entry: &EvolutionMutationValidationEntry,
    queue_review_state: Option<EvolutionProposalReviewState>,
    score: f64,
) -> String {
    format!(
        "status={} proof={} recommendation={} queue_state={} score={score:.3}",
        validation_bundle_status_label(entry.status),
        proof_status_label(entry.proof_status),
        advisory_recommendation_label(entry.advisory.as_ref().map(|a| a.recommendation)),
        queue_review_state.map(review_state_label).unwrap_or("none"),
    )
}

fn mutation_source_label(kind: EvolutionMutationSourceKind) -> &'static str {
    match kind {
        EvolutionMutationSourceKind::Draft => "draft",
        EvolutionMutationSourceKind::Materialization => "materialization",
    }
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

fn advisory_recommendation_label(value: Option<StrategyAdvisoryRecommendation>) -> &'static str {
    match value {
        Some(StrategyAdvisoryRecommendation::RetainBaseline) => "retain_baseline",
        Some(StrategyAdvisoryRecommendation::CandidatePreferred) => "candidate_preferred",
        Some(StrategyAdvisoryRecommendation::CandidateAlreadyStableInProduction) => {
            "candidate_already_stable_in_production"
        }
        None => "none",
    }
}

fn validate_create_request(
    request: &EvolutionMutationSpecCreateRequest,
) -> Result<(), EvolutionMutationError> {
    match (&request.draft_id, &request.materialization_id) {
        (Some(_), None) | (None, Some(_)) => {}
        _ => {
            return Err(EvolutionMutationError::InvalidMutationSpecRequest {
                reason: "exactly one of draft_id or materialization_id must be set".to_string(),
            });
        }
    }
    if request.rationale.trim().is_empty() {
        return Err(EvolutionMutationError::InvalidMutationSpecRequest {
            reason: "rationale cannot be empty".to_string(),
        });
    }
    Ok(())
}

fn apply_profile_overrides(
    profile: &mut SuspiciousProcessTreeProfile,
    request: &EvolutionDraftMaterializationRequest,
) -> Result<Vec<String>, EvolutionMutationError> {
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
        return Err(EvolutionMutationError::InvalidMutationSpecRequest {
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

fn resolve_materialization_pressure_kind(
    drafting: &DefaultEvolutionDraftingHarness,
    materialization: &EvolutionMaterializationLookup,
) -> Result<EvolutionPressureSourceKind, EvolutionMutationError> {
    let pressure = drafting
        .load_pressure(&materialization.report.pressure_id)?
        .ok_or_else(|| EvolutionDraftingError::PressureNotFound {
            pressure_id: materialization.report.pressure_id.clone(),
        })?;
    Ok(pressure.report.source_kind)
}

fn infer_base_experiment_path(
    config_path: &Path,
    draft_id: &str,
    pressure: &EvolutionPressureReport,
) -> Result<PathBuf, EvolutionMutationError> {
    let experiment_name = pressure.experiment_name.as_deref().ok_or_else(|| {
        EvolutionMutationError::InvalidMutationSpecRequest {
            reason: format!("no source experiment name found for draft `{draft_id}`"),
        }
    })?;
    let experiments_dir = repo_root_from_config_path(config_path).join("experiments");
    find_experiment_manifest_path(&experiments_dir, experiment_name)?.ok_or_else(|| {
        EvolutionMutationError::InvalidMutationSpecRequest {
            reason: format!("could not resolve a base experiment manifest for draft `{draft_id}`"),
        }
    })
}

fn find_experiment_manifest_path(
    root: &Path,
    experiment_name: &str,
) -> Result<Option<PathBuf>, EvolutionMutationError> {
    if !root.exists() {
        return Ok(None);
    }

    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries =
            fs::read_dir(&dir).map_err(|source| EvolutionMutationError::ManifestReadDir {
                path: dir.clone(),
                source,
            })?;
        for entry in entries {
            let entry = entry.map_err(|source| EvolutionMutationError::ManifestReadDir {
                path: dir.clone(),
                source,
            })?;
            let path = entry.path();
            let file_type =
                entry
                    .file_type()
                    .map_err(|source| EvolutionMutationError::ManifestReadDir {
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

fn repo_root_from_config_path(config_path: &Path) -> PathBuf {
    if let Some(parent) = config_path.parent() {
        if parent.file_name().is_some_and(|name| name == "rulesets") {
            return parent.parent().unwrap_or(parent).to_path_buf();
        }
        return parent.to_path_buf();
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn parse_optional_threshold(
    raw: Option<&str>,
    field: &str,
) -> Result<Option<f64>, EvolutionMutationError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let value =
        raw.parse::<f64>()
            .map_err(|_| EvolutionMutationError::InvalidMutationSpecRequest {
                reason: format!("{field} must be a valid floating-point number, got `{raw}`"),
            })?;
    if !(0.0..=1.0).contains(&value) {
        return Err(EvolutionMutationError::InvalidMutationSpecRequest {
            reason: format!("{field} must be between 0.0 and 1.0, got {value}"),
        });
    }
    Ok(Some(value))
}

fn normalize_entries(values: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    for value in values {
        let lowered = value.to_ascii_lowercase();
        if !normalized
            .iter()
            .any(|entry: &String| entry.eq_ignore_ascii_case(&lowered))
        {
            normalized.push(lowered);
        }
    }
    normalized
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

fn mutation_spec_id(
    source_kind: EvolutionMutationSourceKind,
    strategy_id: &str,
    created_at_ms: i64,
) -> String {
    format!(
        "evolution_mutation_spec:{}:{}:{}",
        mutation_source_label(source_kind),
        strategy_id,
        created_at_ms
    )
}

fn mutation_materialization_batch_id(mutation_spec_id: &str, created_at_ms: i64) -> String {
    format!(
        "evolution_mutation_materialization_batch:{}:{}",
        sanitize_id(mutation_spec_id),
        created_at_ms
    )
}

fn mutation_validation_batch_id(mutation_spec_id: &str, created_at_ms: i64) -> String {
    format!(
        "evolution_mutation_validation_batch:{}:{}",
        sanitize_id(mutation_spec_id),
        created_at_ms
    )
}

fn mutation_ranking_id(
    mutation_spec_id: &str,
    validation_batch_id: &str,
    created_at_ms: i64,
) -> String {
    format!(
        "evolution_mutation_ranking:{}:{}:{}",
        sanitize_id(mutation_spec_id),
        sanitize_id(validation_batch_id),
        created_at_ms
    )
}

fn review_packet_id(validation_batch_id: &str, rank: usize, variant_id: &str) -> String {
    format!(
        "evolution_review_packet:{}:{}:{}",
        sanitize_id(validation_batch_id),
        rank,
        sanitize_id(variant_id)
    )
}

fn mutation_materialization_id(
    mutation_spec_id: &str,
    variant_id: &str,
    created_at_ms: i64,
) -> String {
    format!(
        "evolution_mutation_materialization:{}:{}:{}",
        sanitize_id(mutation_spec_id),
        sanitize_id(variant_id),
        created_at_ms
    )
}

fn materialized_experiment_name(strategy_id: &str, created_at_ms: i64) -> String {
    format!(
        "mutation_materialized_{}_{}",
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
        "mutation-{}-{}.yaml",
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

fn validation_bundle_status_label(value: EvolutionValidationBundleStatus) -> &'static str {
    match value {
        EvolutionValidationBundleStatus::ReadyForQueue => "ready_for_queue",
        EvolutionValidationBundleStatus::Blocked => "blocked",
    }
}

fn proof_status_label(value: EvolutionProposalProofStatus) -> &'static str {
    match value {
        EvolutionProposalProofStatus::Proved => "proved",
        EvolutionProposalProofStatus::Missing => "missing",
        EvolutionProposalProofStatus::Inconsistent => "inconsistent",
    }
}

fn sha256_hex<T: Serialize>(value: &T) -> Result<String, EvolutionMutationError> {
    let bytes = serde_json::to_vec(value)?;
    let digest = Sha256::digest(bytes);
    Ok(format!("{digest:x}"))
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
struct EvolutionMutationIndex {
    entries: Vec<EvolutionMutationSpecRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct EvolutionMutationMaterializationBatchIndex {
    entries: Vec<EvolutionMutationMaterializationBatchRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct EvolutionMutationValidationBatchIndex {
    entries: Vec<EvolutionMutationValidationBatchRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct EvolutionMutationRankingIndex {
    entries: Vec<EvolutionMutationRankingRecord>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        DefaultEvolutionMutationHarness, EvolutionDraftMaterializationRequest,
        EvolutionMutationProfileOverrides, EvolutionMutationSourceKind,
        EvolutionMutationSpecCreateRequest, EvolutionMutationVariantCreateRequest,
        EvolutionValidationBundleStatus, render_evolution_mutation_materialization_batch,
        render_evolution_mutation_ranking, render_evolution_mutation_spec,
        render_evolution_mutation_validation_batch,
    };
    use crate::drafting::{DefaultEvolutionDraftingHarness, EvolutionDraftCreateRequest};
    use crate::evolution::DefaultEvolutionProofHarness;
    use crate::replay::DefaultReplayHarness;
    use crate::strategy::DefaultStrategyScorecardHarness;
    use std::fs;
    use std::path::PathBuf;
    use swarm_core::ThreatClass;
    use swarm_core::config::{PolicyRuleConfig, PolicyRuleDecision, SwarmConfig};
    use swarm_core::types::Severity;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .unwrap()
            .to_path_buf()
    }

    fn sample_config() -> SwarmConfig {
        let mut config: SwarmConfig =
            serde_yaml::from_str(include_str!("../../../rulesets/default.yaml")).unwrap();
        config.policy.rules = permissive_policy_rules();
        config
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
            name: format!("mutation-test-allow-{threat_class:?}"),
            decision: PolicyRuleDecision::Allow,
            threat_class,
            actions: Vec::new(),
            min_severity: Severity::Low,
            max_severity: Severity::Critical,
            time_window_utc: None,
            max_actions_per_agent_per_minute: None,
            reason: Some("mutation tests allow replay and verification responses".to_string()),
        })
        .collect()
    }

    fn office_control_experiment() -> PathBuf {
        repo_root().join("experiments/office-baseline-control.yaml")
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "swarm-team-six-{}-{}",
            label,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn copy_experiment_fixture(root: &std::path::Path, name: &str) -> PathBuf {
        let path = root.join(format!("{name}.yaml"));
        let raw = fs::read_to_string(office_control_experiment()).unwrap();
        let mut manifest: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
        manifest["corpus"]["suite"] = serde_yaml::Value::String(
            repo_root()
                .join("scenario-suites/hellcat-office-v1.yaml")
                .display()
                .to_string(),
        );
        manifest["verification"]["corpus"] = serde_yaml::Value::String(
            repo_root()
                .join("verifications/office-detector-safety-v1.yaml")
                .display()
                .to_string(),
        );
        fs::write(&path, serde_yaml::to_string(&manifest).unwrap()).unwrap();
        path
    }

    #[tokio::test]
    async fn mutation_spec_from_reviewed_draft_persists() {
        let root = unique_temp_dir("mutation-spec-draft");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verifications");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let pressure_dir = root.join("pressures");
        let draft_dir = root.join("drafts");
        let promotion_dir = root.join("promotions");
        let materialization_dir = root.join("materializations");
        let validation_dir = root.join("validation");
        let reconciliation_dir = root.join("reconciliations");
        let queue_dir = root.join("queue");
        let mutation_dir = root.join("mutations");
        let mutation_materialization_batch_dir = root.join("mutation-materialization-batches");
        let mutation_validation_batch_dir = root.join("mutation-validation-batches");
        let mutation_ranking_dir = root.join("mutation-rankings");
        let base_experiment = copy_experiment_fixture(&root, "office-control-copy");

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
        let drafting = DefaultEvolutionDraftingHarness::from_config(
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
        let pressure = drafting
            .create_pressure_from_scorecard(&scorecards, &scorecard.report.scorecard_id)
            .unwrap();
        let draft = drafting
            .create_draft(EvolutionDraftCreateRequest {
                pressure_id: pressure.report.pressure_id.clone(),
                strategy_id: "office_mutation_parent_v1".to_string(),
                strategy_description: "mutation parent draft for office control".to_string(),
                mutation: "guided_mutation_seed".to_string(),
                rationale: "operator wants to compare several explicit variants".to_string(),
            })
            .unwrap();
        let promotion = drafting
            .promote_draft(
                &queue_dir,
                &draft.report.draft_id,
                "review this parent draft first",
            )
            .unwrap();

        let mutation = DefaultEvolutionMutationHarness::from_path(
            &mutation_dir,
            &mutation_materialization_batch_dir,
            &mutation_validation_batch_dir,
            &mutation_ranking_dir,
        )
        .unwrap();
        let spec = mutation
            .create_mutation_spec(
                &drafting,
                EvolutionMutationSpecCreateRequest {
                    draft_id: Some(draft.report.draft_id.clone()),
                    materialization_id: None,
                    base_experiment_path: Some(base_experiment),
                    rationale: "package explicit parent and threshold mutations under one spec"
                        .to_string(),
                },
            )
            .unwrap();
        let spec = mutation
            .append_variant(
                &spec.report.mutation_spec_id,
                EvolutionMutationVariantCreateRequest {
                    variant_id: Some("tighter-thresholds".to_string()),
                    strategy_id: "office_mutation_threshold_v1".to_string(),
                    strategy_description: "raise confidence thresholds without changing parents"
                        .to_string(),
                    mutation: "raise_thresholds".to_string(),
                    rationale: "test whether stricter gating reduces replay regressions"
                        .to_string(),
                    overrides: EvolutionMutationProfileOverrides {
                        high_confidence_threshold: Some("0.98".to_string()),
                        medium_confidence_threshold: Some("0.92".to_string()),
                        ..EvolutionMutationProfileOverrides::default()
                    },
                },
            )
            .unwrap();

        assert_eq!(spec.report.source_kind, EvolutionMutationSourceKind::Draft);
        assert_eq!(
            spec.report.queue_proposal_id.as_deref(),
            Some(promotion.report.queue_proposal_id.as_str())
        );
        assert_eq!(spec.report.variants.len(), 1);
        assert_eq!(
            spec.report.variants[0].mutation_dimensions,
            vec![
                "high_confidence_threshold".to_string(),
                "medium_confidence_threshold".to_string()
            ]
        );
        assert!(render_evolution_mutation_spec(&spec.report).contains("Evolution Mutation Spec"));

        let loaded = mutation
            .load_mutation_spec(&spec.report.mutation_spec_id)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.report.variants.len(), 1);
    }

    #[tokio::test]
    async fn mutation_spec_from_materialized_candidate_persists() {
        let root = unique_temp_dir("mutation-spec-materialization");
        let replay_dir = root.join("replay");
        let verification_dir = root.join("verifications");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let pressure_dir = root.join("pressures");
        let draft_dir = root.join("drafts");
        let promotion_dir = root.join("promotions");
        let materialization_dir = root.join("materializations");
        let validation_dir = root.join("validation");
        let reconciliation_dir = root.join("reconciliations");
        let mutation_dir = root.join("mutations");
        let mutation_materialization_batch_dir = root.join("mutation-materialization-batches");
        let mutation_validation_batch_dir = root.join("mutation-validation-batches");
        let mutation_ranking_dir = root.join("mutation-rankings");
        let queue_dir = root.join("queue");
        let base_experiment = copy_experiment_fixture(&root, "office-control-seed");

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
                &root.join("experiments"),
                &verification_dir,
                &verification.report.verification_id,
            )
            .await
            .unwrap();
        let drafting = DefaultEvolutionDraftingHarness::from_config(
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
        let pressure = drafting
            .create_pressure_from_scorecard(&scorecards, &scorecard.report.scorecard_id)
            .unwrap();
        let draft = drafting
            .create_draft(EvolutionDraftCreateRequest {
                pressure_id: pressure.report.pressure_id.clone(),
                strategy_id: "office_materialized_parent_v1".to_string(),
                strategy_description: "materialized parent draft".to_string(),
                mutation: "materialize_parent_for_guided_mutation".to_string(),
                rationale: "seed a later mutation bench from a concrete candidate".to_string(),
            })
            .unwrap();
        drafting
            .promote_draft(
                &queue_dir,
                &draft.report.draft_id,
                "review the parent draft before mutation",
            )
            .unwrap();
        let materialization = drafting
            .materialize_draft(EvolutionDraftMaterializationRequest {
                draft_id: draft.report.draft_id.clone(),
                base_experiment_path: Some(base_experiment),
                ..EvolutionDraftMaterializationRequest::default()
            })
            .unwrap();

        let mutation = DefaultEvolutionMutationHarness::from_path(
            &mutation_dir,
            &mutation_materialization_batch_dir,
            &mutation_validation_batch_dir,
            &mutation_ranking_dir,
        )
        .unwrap();
        let spec = mutation
            .create_mutation_spec(
                &drafting,
                EvolutionMutationSpecCreateRequest {
                    draft_id: None,
                    materialization_id: Some(materialization.report.materialization_id.clone()),
                    base_experiment_path: None,
                    rationale:
                        "branch explicit parent and child mutations from the materialized candidate"
                            .to_string(),
                },
            )
            .unwrap();
        let spec = mutation
            .append_variant(
                &spec.report.mutation_spec_id,
                EvolutionMutationVariantCreateRequest {
                    variant_id: Some("python-parent".to_string()),
                    strategy_id: "office_python_parent_v2".to_string(),
                    strategy_description: "broaden parent matching to python".to_string(),
                    mutation: "broaden_parent_set".to_string(),
                    rationale: "explicitly measure the broader parent signal".to_string(),
                    overrides: EvolutionMutationProfileOverrides {
                        add_suspicious_parents: vec!["python".to_string()],
                        ..EvolutionMutationProfileOverrides::default()
                    },
                },
            )
            .unwrap();

        assert_eq!(
            spec.report.source_kind,
            EvolutionMutationSourceKind::Materialization
        );
        assert_eq!(
            spec.report.materialization_id.as_deref(),
            Some(materialization.report.materialization_id.as_str())
        );
        assert_eq!(
            spec.report.base_experiment_path,
            materialization.report.experiment_path
        );
        assert_eq!(spec.report.variants.len(), 1);
    }

    #[tokio::test]
    async fn mutation_batch_materializes_variants() {
        let root = unique_temp_dir("mutation-batch-materialize");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verifications");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let pressure_dir = root.join("pressures");
        let draft_dir = root.join("drafts");
        let promotion_dir = root.join("promotions");
        let materialization_dir = root.join("materializations");
        let validation_dir = root.join("validation");
        let reconciliation_dir = root.join("reconciliations");
        let mutation_dir = root.join("mutations");
        let mutation_materialization_batch_dir = root.join("mutation-materialization-batches");
        let mutation_validation_batch_dir = root.join("mutation-validation-batches");
        let mutation_ranking_dir = root.join("mutation-rankings");
        let queue_dir = root.join("queue");
        let base_experiment = copy_experiment_fixture(&root, "office-control-batch");

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
        let drafting = DefaultEvolutionDraftingHarness::from_config(
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
        let pressure = drafting
            .create_pressure_from_scorecard(&scorecards, &scorecard.report.scorecard_id)
            .unwrap();
        let draft = drafting
            .create_draft(EvolutionDraftCreateRequest {
                pressure_id: pressure.report.pressure_id.clone(),
                strategy_id: "office_batch_parent_v1".to_string(),
                strategy_description: "batch mutation parent".to_string(),
                mutation: "guided_batch_seed".to_string(),
                rationale: "materialize two explicit variants from one spec".to_string(),
            })
            .unwrap();
        let promotion = drafting
            .promote_draft(
                &queue_dir,
                &draft.report.draft_id,
                "hold a reviewed parent queue ref",
            )
            .unwrap();
        let mutation = DefaultEvolutionMutationHarness::from_path(
            &mutation_dir,
            &mutation_materialization_batch_dir,
            &mutation_validation_batch_dir,
            &mutation_ranking_dir,
        )
        .unwrap();
        let spec = mutation
            .create_mutation_spec(
                &drafting,
                EvolutionMutationSpecCreateRequest {
                    draft_id: Some(draft.report.draft_id.clone()),
                    materialization_id: None,
                    base_experiment_path: Some(base_experiment),
                    rationale: "compare a control-preserving variant with a broader parent match"
                        .to_string(),
                },
            )
            .unwrap();
        let spec = mutation
            .append_variant(
                &spec.report.mutation_spec_id,
                EvolutionMutationVariantCreateRequest {
                    variant_id: Some("control-copy".to_string()),
                    strategy_id: "office_batch_control_v1".to_string(),
                    strategy_description: "preserve the control profile".to_string(),
                    mutation: "copy_control_profile".to_string(),
                    rationale: "keep one no-op control branch for comparison".to_string(),
                    overrides: EvolutionMutationProfileOverrides::default(),
                },
            )
            .unwrap();
        let _spec = mutation
            .append_variant(
                &spec.report.mutation_spec_id,
                EvolutionMutationVariantCreateRequest {
                    variant_id: Some("python-parent".to_string()),
                    strategy_id: "office_batch_python_parent_v1".to_string(),
                    strategy_description: "broaden suspicious parent matching to python"
                        .to_string(),
                    mutation: "broaden_parent_set".to_string(),
                    rationale: "explicitly compare a broader parent signal".to_string(),
                    overrides: EvolutionMutationProfileOverrides {
                        add_suspicious_parents: vec!["python".to_string()],
                        ..EvolutionMutationProfileOverrides::default()
                    },
                },
            )
            .unwrap();

        let batch = mutation
            .materialize_batch(&drafting, &spec.report.mutation_spec_id)
            .unwrap();
        assert_eq!(batch.report.candidate_count, 2);
        assert!(
            batch
                .report
                .entries
                .iter()
                .all(|entry| entry.queue_proposal_id.as_deref()
                    == Some(promotion.report.queue_proposal_id.as_str()))
        );
        assert!(
            render_evolution_mutation_materialization_batch(&batch.report)
                .contains("Evolution Mutation Materialization Batch")
        );
    }

    #[tokio::test]
    async fn mutation_batch_refreshes_ready_and_blocked_validation() {
        let root = unique_temp_dir("mutation-batch-validation");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verifications");
        let shadow_dir = root.join("shadows");
        let proof_dir = root.join("proofs");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let pressure_dir = root.join("pressures");
        let draft_dir = root.join("drafts");
        let promotion_dir = root.join("promotions");
        let materialization_dir = root.join("materializations");
        let validation_dir = root.join("validation");
        let reconciliation_dir = root.join("reconciliations");
        let mutation_dir = root.join("mutations");
        let mutation_materialization_batch_dir = root.join("mutation-materialization-batches");
        let mutation_validation_batch_dir = root.join("mutation-validation-batches");
        let mutation_ranking_dir = root.join("mutation-rankings");
        let queue_dir = root.join("queue");
        let base_experiment = copy_experiment_fixture(&root, "office-control-validation");

        let config = sample_config();
        let replay =
            DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
        let verification = replay
            .evaluate_verification_path(&base_experiment, &verification_dir)
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
                &base_experiment,
                &experiment_dir,
                &verification_dir,
                &verification.report.verification_id,
            )
            .await
            .unwrap();
        let drafting = DefaultEvolutionDraftingHarness::from_config(
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
        let pressure = drafting
            .create_pressure_from_scorecard(&scorecards, &scorecard.report.scorecard_id)
            .unwrap();
        let draft = drafting
            .create_draft(EvolutionDraftCreateRequest {
                pressure_id: pressure.report.pressure_id.clone(),
                strategy_id: "suspicious_process_tree".to_string(),
                strategy_description: "validation parent".to_string(),
                mutation: "guided_validation_seed".to_string(),
                rationale: "refresh two variants through the existing validation lane".to_string(),
            })
            .unwrap();
        drafting
            .promote_draft(
                &queue_dir,
                &draft.report.draft_id,
                "hold the reviewed queue ref while validating variants",
            )
            .unwrap();
        let mutation = DefaultEvolutionMutationHarness::from_path(
            &mutation_dir,
            &mutation_materialization_batch_dir,
            &mutation_validation_batch_dir,
            &mutation_ranking_dir,
        )
        .unwrap();
        let spec = mutation
            .create_mutation_spec(
                &drafting,
                EvolutionMutationSpecCreateRequest {
                    draft_id: Some(draft.report.draft_id.clone()),
                    materialization_id: None,
                    base_experiment_path: Some(base_experiment),
                    rationale: "compare one ready variant and one blocked variant".to_string(),
                },
            )
            .unwrap();
        let spec = mutation
            .append_variant(
                &spec.report.mutation_spec_id,
                EvolutionMutationVariantCreateRequest {
                    variant_id: Some("control-copy".to_string()),
                    strategy_id: "office_validation_control_v1".to_string(),
                    strategy_description: "keep the control profile".to_string(),
                    mutation: "copy_control_profile".to_string(),
                    rationale: "preserve a ready branch".to_string(),
                    overrides: EvolutionMutationProfileOverrides::default(),
                },
            )
            .unwrap();
        let spec = mutation
            .append_variant(
                &spec.report.mutation_spec_id,
                EvolutionMutationVariantCreateRequest {
                    variant_id: Some("python-parent".to_string()),
                    strategy_id: "office_validation_python_parent_v1".to_string(),
                    strategy_description: "broaden suspicious parent matching to python"
                        .to_string(),
                    mutation: "broaden_parent_set".to_string(),
                    rationale: "preserve one explicitly blocked branch".to_string(),
                    overrides: EvolutionMutationProfileOverrides {
                        add_suspicious_parents: vec!["python".to_string()],
                        ..EvolutionMutationProfileOverrides::default()
                    },
                },
            )
            .unwrap();

        let batch = mutation
            .materialize_batch(&drafting, &spec.report.mutation_spec_id)
            .unwrap();
        let validation_batch = mutation
            .refresh_validation_batch(
                &drafting,
                &replay,
                &proofs,
                &scorecards,
                &experiment_dir,
                &verification_dir,
                &shadow_dir,
                &batch.report.batch_id,
            )
            .await
            .unwrap();

        assert_eq!(validation_batch.report.ready_count, 1);
        assert_eq!(validation_batch.report.blocked_count, 1);
        assert!(
            validation_batch
                .report
                .entries
                .iter()
                .any(|entry| entry.status == EvolutionValidationBundleStatus::Blocked)
        );
        assert!(
            render_evolution_mutation_validation_batch(&validation_batch.report)
                .contains("Evolution Mutation Validation Batch")
        );

        for entry in &batch.report.entries {
            let path = PathBuf::from(&entry.experiment_path);
            if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn mutation_ranking_orders_ready_candidate_first() {
        let root = unique_temp_dir("mutation-ranking");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verifications");
        let shadow_dir = root.join("shadows");
        let proof_dir = root.join("proofs");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let pressure_dir = root.join("pressures");
        let draft_dir = root.join("drafts");
        let promotion_dir = root.join("promotions");
        let materialization_dir = root.join("materializations");
        let validation_dir = root.join("validation");
        let reconciliation_dir = root.join("reconciliations");
        let mutation_dir = root.join("mutations");
        let mutation_materialization_batch_dir = root.join("mutation-materialization-batches");
        let mutation_validation_batch_dir = root.join("mutation-validation-batches");
        let mutation_ranking_dir = root.join("mutation-rankings");
        let queue_dir = root.join("queue");
        let base_experiment = office_control_experiment();

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
        let drafting = DefaultEvolutionDraftingHarness::from_config(
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
        let pressure = drafting
            .create_pressure_from_scorecard(&scorecards, &scorecard.report.scorecard_id)
            .unwrap();
        let draft = drafting
            .create_draft(EvolutionDraftCreateRequest {
                pressure_id: pressure.report.pressure_id.clone(),
                strategy_id: "suspicious_process_tree".to_string(),
                strategy_description: "ranking parent".to_string(),
                mutation: "guided_ranking_seed".to_string(),
                rationale: "rank a ready branch against a blocked branch".to_string(),
            })
            .unwrap();
        let promotion = drafting
            .promote_draft(
                &queue_dir,
                &draft.report.draft_id,
                "keep the reviewed queue reference attached",
            )
            .unwrap();
        let mutation = DefaultEvolutionMutationHarness::from_path(
            &mutation_dir,
            &mutation_materialization_batch_dir,
            &mutation_validation_batch_dir,
            &mutation_ranking_dir,
        )
        .unwrap();
        let spec = mutation
            .create_mutation_spec(
                &drafting,
                EvolutionMutationSpecCreateRequest {
                    draft_id: Some(draft.report.draft_id.clone()),
                    materialization_id: None,
                    base_experiment_path: Some(base_experiment),
                    rationale: "preserve one ready branch and one blocked branch".to_string(),
                },
            )
            .unwrap();
        let spec = mutation
            .append_variant(
                &spec.report.mutation_spec_id,
                EvolutionMutationVariantCreateRequest {
                    variant_id: Some("control-copy".to_string()),
                    strategy_id: "office_ranking_control_v1".to_string(),
                    strategy_description: "keep the control profile".to_string(),
                    mutation: "copy_control_profile".to_string(),
                    rationale: "ready branch".to_string(),
                    overrides: EvolutionMutationProfileOverrides::default(),
                },
            )
            .unwrap();
        let spec = mutation
            .append_variant(
                &spec.report.mutation_spec_id,
                EvolutionMutationVariantCreateRequest {
                    variant_id: Some("python-parent".to_string()),
                    strategy_id: "office_ranking_python_parent_v1".to_string(),
                    strategy_description: "broaden suspicious parent matching to python"
                        .to_string(),
                    mutation: "broaden_parent_set".to_string(),
                    rationale: "blocked branch".to_string(),
                    overrides: EvolutionMutationProfileOverrides {
                        add_suspicious_parents: vec!["python".to_string()],
                        ..EvolutionMutationProfileOverrides::default()
                    },
                },
            )
            .unwrap();

        let batch = mutation
            .materialize_batch(&drafting, &spec.report.mutation_spec_id)
            .unwrap();
        let validation_batch = mutation
            .refresh_validation_batch(
                &drafting,
                &replay,
                &proofs,
                &scorecards,
                &experiment_dir,
                &verification_dir,
                &shadow_dir,
                &batch.report.batch_id,
            )
            .await
            .unwrap();
        let ranking = mutation
            .rank_candidates(&queue_dir, &validation_batch.report.validation_batch_id, 1)
            .unwrap();

        assert_eq!(ranking.report.ranked_candidates.len(), 2);
        assert_eq!(ranking.report.ranked_candidates[0].rank, 1);
        assert_eq!(
            ranking.report.ranked_candidates[0].strategy_id,
            "office_ranking_control_v1"
        );
        assert_eq!(ranking.report.review_packets.len(), 1);
        assert_eq!(
            ranking.report.review_packets[0]
                .queue_proposal_id
                .as_deref(),
            Some(promotion.report.queue_proposal_id.as_str())
        );
        assert!(
            render_evolution_mutation_ranking(&ranking.report)
                .contains("Evolution Mutation Candidate Ranking")
        );

        for entry in &batch.report.entries {
            let path = PathBuf::from(&entry.experiment_path);
            if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
    }
}
