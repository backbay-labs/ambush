use crate::drafting::EvolutionValidationBundleStatus;
use crate::evolution::{
    EvolutionProposalAdvisorySummary, EvolutionProposalBlockingReason,
    EvolutionProposalProofStatus, EvolutionProposalProofSummary, EvolutionProposalReviewState,
};
use crate::mutation::{EvolutionMutationRankingStoreError, FileEvolutionMutationRankingStore};
use crate::replay::{ExperimentLineage, ReplayHarnessError, load_detector_experiment_manifest};
use crate::selection::{EvolutionSelectionStoreError, FileEvolutionSelectionStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// One operator-supplied portfolio input item assembled from a ranked selection.
#[derive(Debug, Clone)]
pub struct EvolutionPortfolioEntryCreateRequest {
    pub selection_id: String,
    pub cohort: Option<String>,
}

/// Review state for one portfolio entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvolutionPortfolioEntryReviewState {
    PendingReview,
    Included,
    Deferred,
    Dropped,
    Blocked,
}

/// Operator decision actions supported for portfolio entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvolutionPortfolioDecisionAction {
    Include,
    Defer,
    Drop,
}

/// One durable operator decision on a portfolio entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionPortfolioDecisionRecord {
    pub decided_at_ms: i64,
    pub action: EvolutionPortfolioDecisionAction,
    pub reason: String,
}

/// One durable portfolio entry assembled from a ranked-candidate selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionPortfolioEntryReport {
    pub entry_id: String,
    pub selection_id: String,
    pub ranking_id: String,
    pub validation_batch_id: String,
    pub mutation_spec_id: String,
    pub cohort: String,
    pub rank: usize,
    pub strategy_id: String,
    pub strategy_description: String,
    pub score: f64,
    pub summary: String,
    pub materialization_id: String,
    pub validation_bundle_id: String,
    pub experiment_id: String,
    pub experiment_name: String,
    pub experiment_path: String,
    pub lineage: ExperimentLineage,
    pub manifest_sha256: String,
    pub lineage_sha256: String,
    pub verification_id: String,
    pub verification_passed: bool,
    pub proof_status: EvolutionProposalProofStatus,
    pub proof: Option<EvolutionProposalProofSummary>,
    pub advisory: Option<EvolutionProposalAdvisorySummary>,
    pub shadow_id: String,
    pub shadow_passed: bool,
    pub validation_status: EvolutionValidationBundleStatus,
    pub parent_queue_proposal_id: Option<String>,
    pub parent_queue_review_state: Option<EvolutionProposalReviewState>,
    pub selection_review_state: EvolutionProposalReviewState,
    pub portfolio_review_state: EvolutionPortfolioEntryReviewState,
    pub blocking_reasons: Vec<EvolutionProposalBlockingReason>,
    pub decision_history: Vec<EvolutionPortfolioDecisionRecord>,
}

/// Durable portfolio assembled from multiple ranked selections or cohorts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionPortfolioReport {
    pub portfolio_id: String,
    pub portfolio_name: String,
    pub operator_rationale: String,
    pub created_at_ms: i64,
    pub entries: Vec<EvolutionPortfolioEntryReport>,
}

/// Metadata surfaced for one persisted portfolio artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionPortfolioRecord {
    pub portfolio_id: String,
    pub portfolio_name: String,
    pub entry_count: usize,
    pub included_count: usize,
    pub blocked_count: usize,
    pub cohorts: Vec<String>,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl EvolutionPortfolioRecord {
    fn from_report(report: &EvolutionPortfolioReport, bundle_path: String) -> Self {
        let cohorts = report
            .entries
            .iter()
            .map(|entry| entry.cohort.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        Self {
            portfolio_id: report.portfolio_id.clone(),
            portfolio_name: report.portfolio_name.clone(),
            entry_count: report.entries.len(),
            included_count: report
                .entries
                .iter()
                .filter(|entry| {
                    entry.portfolio_review_state == EvolutionPortfolioEntryReviewState::Included
                })
                .count(),
            blocked_count: report
                .entries
                .iter()
                .filter(|entry| {
                    entry.portfolio_review_state == EvolutionPortfolioEntryReviewState::Blocked
                })
                .count(),
            cohorts,
            created_at_ms: report.created_at_ms,
            bundle_path,
        }
    }
}

/// Persisted portfolio loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionPortfolioLookup {
    pub record: EvolutionPortfolioRecord,
    pub report: EvolutionPortfolioReport,
}

/// Operator-facing portfolio listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionPortfolioList {
    pub total_count: usize,
    pub cohort: Option<String>,
    pub review_state: Option<EvolutionPortfolioEntryReviewState>,
    pub portfolios: Vec<EvolutionPortfolioRecord>,
}

/// Durable governance-ready review packet created from a curated portfolio entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionGovernanceReviewPacketReport {
    pub packet_id: String,
    pub portfolio_id: String,
    pub portfolio_name: String,
    pub entry_id: String,
    pub selection_id: String,
    pub ranking_id: String,
    pub validation_batch_id: String,
    pub mutation_spec_id: String,
    pub created_at_ms: i64,
    pub cohort: String,
    pub rank: usize,
    pub strategy_id: String,
    pub strategy_description: String,
    pub score: f64,
    pub summary: String,
    pub materialization_id: String,
    pub validation_bundle_id: String,
    pub experiment_id: String,
    pub experiment_name: String,
    pub experiment_path: String,
    pub lineage: ExperimentLineage,
    pub manifest_sha256: String,
    pub lineage_sha256: String,
    pub verification_id: String,
    pub verification_passed: bool,
    pub proof_status: EvolutionProposalProofStatus,
    pub proof: Option<EvolutionProposalProofSummary>,
    pub advisory: Option<EvolutionProposalAdvisorySummary>,
    pub shadow_id: String,
    pub shadow_passed: bool,
    pub validation_status: EvolutionValidationBundleStatus,
    pub parent_queue_proposal_id: Option<String>,
    pub parent_queue_review_state: Option<EvolutionProposalReviewState>,
    pub selection_review_state: EvolutionProposalReviewState,
    pub portfolio_review_state: EvolutionPortfolioEntryReviewState,
    pub operator_reason: String,
    pub ready_for_governance: bool,
    pub blocking_reasons: Vec<EvolutionProposalBlockingReason>,
}

/// Metadata surfaced for one persisted governance-ready review packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionGovernanceReviewPacketRecord {
    pub packet_id: String,
    pub portfolio_id: String,
    pub entry_id: String,
    pub strategy_id: String,
    pub created_at_ms: i64,
    pub ready_for_governance: bool,
    pub bundle_path: String,
}

impl EvolutionGovernanceReviewPacketRecord {
    fn from_report(report: &EvolutionGovernanceReviewPacketReport, bundle_path: String) -> Self {
        Self {
            packet_id: report.packet_id.clone(),
            portfolio_id: report.portfolio_id.clone(),
            entry_id: report.entry_id.clone(),
            strategy_id: report.strategy_id.clone(),
            created_at_ms: report.created_at_ms,
            ready_for_governance: report.ready_for_governance,
            bundle_path,
        }
    }
}

/// Persisted governance-ready review packet loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionGovernanceReviewPacketLookup {
    pub record: EvolutionGovernanceReviewPacketRecord,
    pub report: EvolutionGovernanceReviewPacketReport,
}

/// Errors raised by the persisted portfolio store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionPortfolioStoreError {
    #[error("failed to read evolution portfolio store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution portfolio store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution portfolio store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised by the persisted governance review packet store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionGovernanceReviewPacketStoreError {
    #[error("failed to read evolution governance review packet store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution governance review packet store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution governance review packet store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors surfaced by the portfolio and governance-prep workflows.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionPortfolioError {
    #[error(transparent)]
    RankingStore(#[from] EvolutionMutationRankingStoreError),

    #[error(transparent)]
    SelectionStore(#[from] EvolutionSelectionStoreError),

    #[error(transparent)]
    PortfolioStore(#[from] EvolutionPortfolioStoreError),

    #[error(transparent)]
    GovernancePacketStore(#[from] EvolutionGovernanceReviewPacketStoreError),

    #[error(transparent)]
    Replay(#[from] ReplayHarnessError),

    #[error(transparent)]
    Serialization(#[from] serde_json::Error),

    #[error("ranked-candidate selection `{selection_id}` was not found")]
    SelectionNotFound { selection_id: String },

    #[error("candidate ranking `{ranking_id}` was not found")]
    RankingNotFound { ranking_id: String },

    #[error("portfolio `{portfolio_id}` was not found")]
    PortfolioNotFound { portfolio_id: String },

    #[error("portfolio entry `{entry_id}` was not found in portfolio `{portfolio_id}`")]
    PortfolioEntryNotFound {
        portfolio_id: String,
        entry_id: String,
    },

    #[error("governance review packet `{packet_id}` was not found")]
    GovernancePacketNotFound { packet_id: String },

    #[error("invalid portfolio request: {reason}")]
    InvalidPortfolioRequest { reason: String },

    #[error(
        "portfolio `{portfolio_id}` entry `{entry_id}` cannot apply decision `{decision}` from state `{state}`: {reason}"
    )]
    InvalidDecision {
        portfolio_id: String,
        entry_id: String,
        state: String,
        decision: String,
        reason: String,
    },
}

/// File-backed store for portfolio artifacts.
#[derive(Debug, Clone)]
pub struct FileEvolutionPortfolioStore {
    root: PathBuf,
}

impl FileEvolutionPortfolioStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionPortfolioStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionPortfolioStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, portfolio_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(portfolio_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<EvolutionPortfolioIndex, EvolutionPortfolioStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionPortfolioIndex::default());
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| EvolutionPortfolioStoreError::Read {
                path: path.clone(),
                source,
            })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionPortfolioStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionPortfolioIndex,
    ) -> Result<(), EvolutionPortfolioStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionPortfolioStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionPortfolioStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionPortfolioReport,
    ) -> Result<EvolutionPortfolioRecord, EvolutionPortfolioStoreError> {
        let path = self.report_path(&report.portfolio_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionPortfolioStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionPortfolioStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = EvolutionPortfolioRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.portfolio_id != record.portfolio_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        portfolio_id: &str,
    ) -> Result<Option<EvolutionPortfolioLookup>, EvolutionPortfolioStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.portfolio_id == portfolio_id)
            .cloned()
        else {
            return Ok(None);
        };

        let path = PathBuf::from(&record.bundle_path);
        let raw =
            fs::read_to_string(&path).map_err(|source| EvolutionPortfolioStoreError::Read {
                path: path.clone(),
                source,
            })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionPortfolioStoreError::Parse { path, source })?;
        Ok(Some(EvolutionPortfolioLookup { record, report }))
    }

    pub fn list(
        &self,
        cohort: Option<&str>,
        review_state: Option<EvolutionPortfolioEntryReviewState>,
    ) -> Result<EvolutionPortfolioList, EvolutionPortfolioStoreError> {
        let index = self.read_index()?;
        let portfolios = if cohort.is_none() && review_state.is_none() {
            index.entries
        } else {
            index
                .entries
                .into_iter()
                .filter(|record| match self.load(&record.portfolio_id) {
                    Ok(Some(lookup)) => lookup.report.entries.iter().any(|entry| {
                        cohort
                            .map(|expected| entry.cohort == expected)
                            .unwrap_or(true)
                            && review_state
                                .map(|expected| entry.portfolio_review_state == expected)
                                .unwrap_or(true)
                    }),
                    _ => false,
                })
                .collect::<Vec<_>>()
        };
        Ok(EvolutionPortfolioList {
            total_count: portfolios.len(),
            cohort: cohort.map(ToOwned::to_owned),
            review_state,
            portfolios,
        })
    }
}

/// File-backed store for governance-ready review packets.
#[derive(Debug, Clone)]
pub struct FileEvolutionGovernanceReviewPacketStore {
    root: PathBuf,
}

impl FileEvolutionGovernanceReviewPacketStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionGovernanceReviewPacketStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionGovernanceReviewPacketStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, packet_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(packet_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(
        &self,
    ) -> Result<EvolutionGovernanceReviewPacketIndex, EvolutionGovernanceReviewPacketStoreError>
    {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionGovernanceReviewPacketIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionGovernanceReviewPacketStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionGovernanceReviewPacketStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionGovernanceReviewPacketIndex,
    ) -> Result<(), EvolutionGovernanceReviewPacketStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionGovernanceReviewPacketStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| EvolutionGovernanceReviewPacketStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionGovernanceReviewPacketReport,
    ) -> Result<EvolutionGovernanceReviewPacketRecord, EvolutionGovernanceReviewPacketStoreError>
    {
        let path = self.report_path(&report.packet_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionGovernanceReviewPacketStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| {
            EvolutionGovernanceReviewPacketStoreError::Write {
                path: path.clone(),
                source,
            }
        })?;

        let mut index = self.read_index()?;
        let record =
            EvolutionGovernanceReviewPacketRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.packet_id != record.packet_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        packet_id: &str,
    ) -> Result<
        Option<EvolutionGovernanceReviewPacketLookup>,
        EvolutionGovernanceReviewPacketStoreError,
    > {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.packet_id == packet_id)
            .cloned()
        else {
            return Ok(None);
        };

        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionGovernanceReviewPacketStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionGovernanceReviewPacketStoreError::Parse { path, source })?;
        Ok(Some(EvolutionGovernanceReviewPacketLookup {
            record,
            report,
        }))
    }

    pub fn load_latest_for_entry(
        &self,
        entry_id: &str,
    ) -> Result<
        Option<EvolutionGovernanceReviewPacketLookup>,
        EvolutionGovernanceReviewPacketStoreError,
    > {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.entry_id == entry_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionGovernanceReviewPacketStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionGovernanceReviewPacketStoreError::Parse { path, source })?;
        Ok(Some(EvolutionGovernanceReviewPacketLookup {
            record,
            report,
        }))
    }
}

/// Harness for cross-batch portfolio assembly, curation, and governance packet preparation.
#[derive(Debug, Clone)]
pub struct DefaultEvolutionPortfolioHarness {
    pub ranking_store: FileEvolutionMutationRankingStore,
    pub selection_store: FileEvolutionSelectionStore,
    pub portfolio_store: FileEvolutionPortfolioStore,
    pub governance_packet_store: FileEvolutionGovernanceReviewPacketStore,
}

impl DefaultEvolutionPortfolioHarness {
    pub fn from_path(
        ranking_results_dir: impl AsRef<Path>,
        selection_results_dir: impl AsRef<Path>,
        portfolio_results_dir: impl AsRef<Path>,
        governance_packet_results_dir: impl AsRef<Path>,
    ) -> Result<Self, EvolutionPortfolioError> {
        Ok(Self {
            ranking_store: FileEvolutionMutationRankingStore::open(ranking_results_dir)?,
            selection_store: FileEvolutionSelectionStore::open(selection_results_dir)?,
            portfolio_store: FileEvolutionPortfolioStore::open(portfolio_results_dir)?,
            governance_packet_store: FileEvolutionGovernanceReviewPacketStore::open(
                governance_packet_results_dir,
            )?,
        })
    }

    pub fn create_portfolio(
        &self,
        name: &str,
        rationale: &str,
        entries: Vec<EvolutionPortfolioEntryCreateRequest>,
    ) -> Result<EvolutionPortfolioLookup, EvolutionPortfolioError> {
        if entries.is_empty() {
            return Err(EvolutionPortfolioError::InvalidPortfolioRequest {
                reason: "at least one ranked selection is required".to_string(),
            });
        }
        if name.trim().is_empty() {
            return Err(EvolutionPortfolioError::InvalidPortfolioRequest {
                reason: "portfolio name cannot be empty".to_string(),
            });
        }
        let created_at_ms = now_ms();
        let mut seen = BTreeSet::new();
        let mut reports = Vec::new();

        for (index, request) in entries.into_iter().enumerate() {
            let selection = self
                .selection_store
                .load(&request.selection_id)?
                .ok_or_else(|| EvolutionPortfolioError::SelectionNotFound {
                    selection_id: request.selection_id.clone(),
                })?;
            let ranking = self
                .ranking_store
                .load(&selection.report.ranking_id)?
                .ok_or_else(|| EvolutionPortfolioError::RankingNotFound {
                    ranking_id: selection.report.ranking_id.clone(),
                })?;
            let cohort = request
                .cohort
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| selection.report.experiment_name.clone());
            let dedupe_key = format!("{}::{}", selection.report.selection_id, cohort);
            if !seen.insert(dedupe_key) {
                continue;
            }

            let mut blocking_reasons = selection.report.blocking_reasons.clone();
            match selection.report.review_state {
                EvolutionProposalReviewState::Blocked => {
                    blocking_reasons.push(EvolutionProposalBlockingReason {
                        source: "portfolio".to_string(),
                        name: "selection_blocked".to_string(),
                        details: format!(
                            "selection `{}` is already blocked and cannot enter portfolio review cleanly",
                            selection.report.selection_id
                        ),
                        references: vec![selection.report.selection_id.clone()],
                    });
                }
                EvolutionProposalReviewState::Rejected => {
                    blocking_reasons.push(EvolutionProposalBlockingReason {
                        source: "portfolio".to_string(),
                        name: "selection_rejected".to_string(),
                        details: format!(
                            "selection `{}` was already rejected in the prior review lane",
                            selection.report.selection_id
                        ),
                        references: vec![selection.report.selection_id.clone()],
                    });
                }
                _ => {}
            }

            reports.push(EvolutionPortfolioEntryReport {
                entry_id: portfolio_entry_id(&selection.report.selection_id, &cohort, index),
                selection_id: selection.report.selection_id.clone(),
                ranking_id: selection.report.ranking_id.clone(),
                validation_batch_id: ranking.report.validation_batch_id.clone(),
                mutation_spec_id: ranking.report.mutation_spec_id.clone(),
                cohort,
                rank: selection.report.rank,
                strategy_id: selection.report.strategy_id.clone(),
                strategy_description: selection.report.strategy_description.clone(),
                score: selection.report.score,
                summary: selection.report.summary.clone(),
                materialization_id: selection.report.materialization_id.clone(),
                validation_bundle_id: selection.report.validation_bundle_id.clone(),
                experiment_id: selection.report.experiment_id.clone(),
                experiment_name: selection.report.experiment_name.clone(),
                experiment_path: selection.report.experiment_path.clone(),
                lineage: selection.report.lineage.clone(),
                manifest_sha256: selection.report.manifest_sha256.clone(),
                lineage_sha256: selection.report.lineage_sha256.clone(),
                verification_id: selection.report.verification_id.clone(),
                verification_passed: selection.report.verification_passed,
                proof_status: selection.report.proof_status,
                proof: selection.report.proof.clone(),
                advisory: selection.report.advisory.clone(),
                shadow_id: selection.report.shadow_id.clone(),
                shadow_passed: selection.report.shadow_passed,
                validation_status: selection.report.validation_status,
                parent_queue_proposal_id: selection.report.parent_queue_proposal_id.clone(),
                parent_queue_review_state: selection.report.parent_queue_review_state,
                selection_review_state: selection.report.review_state,
                portfolio_review_state: if blocking_reasons.is_empty() {
                    EvolutionPortfolioEntryReviewState::PendingReview
                } else {
                    EvolutionPortfolioEntryReviewState::Blocked
                },
                blocking_reasons,
                decision_history: Vec::new(),
            });
        }

        if reports.is_empty() {
            return Err(EvolutionPortfolioError::InvalidPortfolioRequest {
                reason: "no unique ranked selections were provided".to_string(),
            });
        }

        let report = EvolutionPortfolioReport {
            portfolio_id: portfolio_id(name, created_at_ms),
            portfolio_name: name.trim().to_string(),
            operator_rationale: rationale.trim().to_string(),
            created_at_ms,
            entries: reports,
        };
        let record = self.portfolio_store.persist(&report)?;
        Ok(EvolutionPortfolioLookup { record, report })
    }

    pub fn load_portfolio(
        &self,
        portfolio_id: &str,
    ) -> Result<Option<EvolutionPortfolioLookup>, EvolutionPortfolioError> {
        Ok(self.portfolio_store.load(portfolio_id)?)
    }

    pub fn list_portfolios(
        &self,
        cohort: Option<&str>,
        review_state: Option<EvolutionPortfolioEntryReviewState>,
    ) -> Result<EvolutionPortfolioList, EvolutionPortfolioError> {
        Ok(self.portfolio_store.list(cohort, review_state)?)
    }

    pub fn record_decision(
        &self,
        portfolio_id: &str,
        entry_id: &str,
        action: EvolutionPortfolioDecisionAction,
        reason: &str,
    ) -> Result<EvolutionPortfolioLookup, EvolutionPortfolioError> {
        let mut lookup = self.portfolio_store.load(portfolio_id)?.ok_or_else(|| {
            EvolutionPortfolioError::PortfolioNotFound {
                portfolio_id: portfolio_id.to_string(),
            }
        })?;
        let entry = lookup
            .report
            .entries
            .iter_mut()
            .find(|entry| entry.entry_id == entry_id)
            .ok_or_else(|| EvolutionPortfolioError::PortfolioEntryNotFound {
                portfolio_id: portfolio_id.to_string(),
                entry_id: entry_id.to_string(),
            })?;

        let new_state = match (entry.portfolio_review_state, action) {
            (
                EvolutionPortfolioEntryReviewState::PendingReview,
                EvolutionPortfolioDecisionAction::Include,
            )
            | (
                EvolutionPortfolioEntryReviewState::Deferred,
                EvolutionPortfolioDecisionAction::Include,
            ) => {
                if !entry.blocking_reasons.is_empty() {
                    return Err(EvolutionPortfolioError::InvalidDecision {
                        portfolio_id: portfolio_id.to_string(),
                        entry_id: entry_id.to_string(),
                        state: portfolio_review_state_label(entry.portfolio_review_state)
                            .to_string(),
                        decision: portfolio_decision_action_label(action).to_string(),
                        reason: "only unblocked portfolio entries can be included".to_string(),
                    });
                }
                EvolutionPortfolioEntryReviewState::Included
            }
            (
                EvolutionPortfolioEntryReviewState::PendingReview,
                EvolutionPortfolioDecisionAction::Defer,
            )
            | (
                EvolutionPortfolioEntryReviewState::Deferred,
                EvolutionPortfolioDecisionAction::Defer,
            )
            | (
                EvolutionPortfolioEntryReviewState::Included,
                EvolutionPortfolioDecisionAction::Defer,
            ) => EvolutionPortfolioEntryReviewState::Deferred,
            (
                EvolutionPortfolioEntryReviewState::PendingReview,
                EvolutionPortfolioDecisionAction::Drop,
            )
            | (
                EvolutionPortfolioEntryReviewState::Deferred,
                EvolutionPortfolioDecisionAction::Drop,
            )
            | (
                EvolutionPortfolioEntryReviewState::Included,
                EvolutionPortfolioDecisionAction::Drop,
            )
            | (
                EvolutionPortfolioEntryReviewState::Blocked,
                EvolutionPortfolioDecisionAction::Drop,
            ) => EvolutionPortfolioEntryReviewState::Dropped,
            (EvolutionPortfolioEntryReviewState::Blocked, _) => {
                return Err(EvolutionPortfolioError::InvalidDecision {
                    portfolio_id: portfolio_id.to_string(),
                    entry_id: entry_id.to_string(),
                    state: portfolio_review_state_label(entry.portfolio_review_state).to_string(),
                    decision: portfolio_decision_action_label(action).to_string(),
                    reason: "blocked entries may only be explicitly dropped".to_string(),
                });
            }
            (EvolutionPortfolioEntryReviewState::Dropped, _)
            | (
                EvolutionPortfolioEntryReviewState::Included,
                EvolutionPortfolioDecisionAction::Include,
            ) => {
                return Err(EvolutionPortfolioError::InvalidDecision {
                    portfolio_id: portfolio_id.to_string(),
                    entry_id: entry_id.to_string(),
                    state: portfolio_review_state_label(entry.portfolio_review_state).to_string(),
                    decision: portfolio_decision_action_label(action).to_string(),
                    reason: "the portfolio entry is already in a terminal or identical state"
                        .to_string(),
                });
            }
        };

        entry.portfolio_review_state = new_state;
        entry
            .decision_history
            .push(EvolutionPortfolioDecisionRecord {
                decided_at_ms: now_ms(),
                action,
                reason: reason.to_string(),
            });
        let record = self.portfolio_store.persist(&lookup.report)?;
        Ok(EvolutionPortfolioLookup {
            record,
            report: lookup.report,
        })
    }

    pub fn create_governance_review_packet(
        &self,
        portfolio_id: &str,
        entry_id: &str,
        reason: &str,
    ) -> Result<EvolutionGovernanceReviewPacketLookup, EvolutionPortfolioError> {
        let lookup = self.portfolio_store.load(portfolio_id)?.ok_or_else(|| {
            EvolutionPortfolioError::PortfolioNotFound {
                portfolio_id: portfolio_id.to_string(),
            }
        })?;
        let entry = lookup
            .report
            .entries
            .iter()
            .find(|entry| entry.entry_id == entry_id)
            .ok_or_else(|| EvolutionPortfolioError::PortfolioEntryNotFound {
                portfolio_id: portfolio_id.to_string(),
                entry_id: entry_id.to_string(),
            })?;

        if let Some(existing) = self
            .governance_packet_store
            .load_latest_for_entry(entry_id)?
            && existing.report.ready_for_governance
            && existing.report.blocking_reasons.is_empty()
        {
            return Ok(existing);
        }

        let mut blocking_reasons = Vec::new();
        if entry.portfolio_review_state != EvolutionPortfolioEntryReviewState::Included {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "portfolio".to_string(),
                name: "portfolio_entry_not_included".to_string(),
                details: format!(
                    "portfolio entry `{}` is in state `{}` instead of `included`",
                    entry.entry_id,
                    portfolio_review_state_label(entry.portfolio_review_state)
                ),
                references: vec![entry.entry_id.clone(), lookup.report.portfolio_id.clone()],
            });
        }
        if !entry.blocking_reasons.is_empty() {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "portfolio".to_string(),
                name: "portfolio_entry_already_blocked".to_string(),
                details: "portfolio entry still carries blocking reasons and cannot produce a clean governance-ready packet"
                    .to_string(),
                references: vec![entry.entry_id.clone()],
            });
        }
        if entry.validation_status != EvolutionValidationBundleStatus::ReadyForQueue {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "portfolio".to_string(),
                name: "validation_not_ready_for_queue".to_string(),
                details: format!(
                    "portfolio entry validation status is `{}` instead of `ready_for_queue`",
                    validation_status_label(entry.validation_status)
                ),
                references: vec![entry.validation_bundle_id.clone()],
            });
        }
        if !entry.verification_passed {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "portfolio".to_string(),
                name: "verification_not_passed".to_string(),
                details: "portfolio entry still references a non-passing verification result"
                    .to_string(),
                references: vec![entry.verification_id.clone()],
            });
        }
        if entry.proof_status != EvolutionProposalProofStatus::Proved {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "portfolio".to_string(),
                name: "proof_not_proved".to_string(),
                details: "portfolio entry still references a non-proved proof artifact".to_string(),
                references: vec![entry.entry_id.clone()],
            });
        }
        if !entry.shadow_passed {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "portfolio".to_string(),
                name: "shadow_not_passed".to_string(),
                details: "portfolio entry still references a non-passing shadow artifact"
                    .to_string(),
                references: vec![entry.shadow_id.clone()],
            });
        }
        if entry.experiment_path.trim().is_empty() {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "portfolio".to_string(),
                name: "missing_experiment_path".to_string(),
                details: "portfolio entry does not preserve an experiment manifest path"
                    .to_string(),
                references: vec![entry.entry_id.clone()],
            });
        }

        if blocking_reasons.is_empty() {
            match load_detector_experiment_manifest(PathBuf::from(&entry.experiment_path)) {
                Ok(manifest) => {
                    let current_manifest_sha256 = sha256_hex(&manifest)?;
                    let current_lineage_sha256 = sha256_hex(&manifest.lineage)?;
                    if experiment_id_for_manifest(&manifest) != entry.experiment_id {
                        blocking_reasons.push(EvolutionProposalBlockingReason {
                            source: "governance_packet".to_string(),
                            name: "experiment_id_drift".to_string(),
                            details: format!(
                                "current experiment id `{}` no longer matches portfolio entry experiment `{}`",
                                experiment_id_for_manifest(&manifest),
                                entry.experiment_id
                            ),
                            references: vec![entry.entry_id.clone()],
                        });
                    }
                    if manifest.candidate.strategy_id() != entry.strategy_id {
                        blocking_reasons.push(EvolutionProposalBlockingReason {
                            source: "governance_packet".to_string(),
                            name: "strategy_drift".to_string(),
                            details: format!(
                                "current experiment strategy `{}` no longer matches portfolio entry strategy `{}`",
                                manifest.candidate.strategy_id(),
                                entry.strategy_id
                            ),
                            references: vec![entry.entry_id.clone()],
                        });
                    }
                    if current_manifest_sha256 != entry.manifest_sha256 {
                        blocking_reasons.push(EvolutionProposalBlockingReason {
                            source: "governance_packet".to_string(),
                            name: "manifest_digest_drift".to_string(),
                            details: "current experiment manifest digest no longer matches the preserved portfolio entry"
                                .to_string(),
                            references: vec![entry.entry_id.clone()],
                        });
                    }
                    if current_lineage_sha256 != entry.lineage_sha256 {
                        blocking_reasons.push(EvolutionProposalBlockingReason {
                            source: "governance_packet".to_string(),
                            name: "lineage_digest_drift".to_string(),
                            details: "current experiment lineage digest no longer matches the preserved portfolio entry"
                                .to_string(),
                            references: vec![entry.entry_id.clone()],
                        });
                    }
                }
                Err(error) => blocking_reasons.push(EvolutionProposalBlockingReason {
                    source: "governance_packet".to_string(),
                    name: "experiment_manifest_unreadable".to_string(),
                    details: error.to_string(),
                    references: vec![entry.experiment_path.clone()],
                }),
            }
        }

        let created_at_ms = now_ms();
        let report = EvolutionGovernanceReviewPacketReport {
            packet_id: governance_packet_id(
                &lookup.report.portfolio_id,
                &entry.entry_id,
                created_at_ms,
            ),
            portfolio_id: lookup.report.portfolio_id.clone(),
            portfolio_name: lookup.report.portfolio_name.clone(),
            entry_id: entry.entry_id.clone(),
            selection_id: entry.selection_id.clone(),
            ranking_id: entry.ranking_id.clone(),
            validation_batch_id: entry.validation_batch_id.clone(),
            mutation_spec_id: entry.mutation_spec_id.clone(),
            created_at_ms,
            cohort: entry.cohort.clone(),
            rank: entry.rank,
            strategy_id: entry.strategy_id.clone(),
            strategy_description: entry.strategy_description.clone(),
            score: entry.score,
            summary: entry.summary.clone(),
            materialization_id: entry.materialization_id.clone(),
            validation_bundle_id: entry.validation_bundle_id.clone(),
            experiment_id: entry.experiment_id.clone(),
            experiment_name: entry.experiment_name.clone(),
            experiment_path: entry.experiment_path.clone(),
            lineage: entry.lineage.clone(),
            manifest_sha256: entry.manifest_sha256.clone(),
            lineage_sha256: entry.lineage_sha256.clone(),
            verification_id: entry.verification_id.clone(),
            verification_passed: entry.verification_passed,
            proof_status: entry.proof_status,
            proof: entry.proof.clone(),
            advisory: entry.advisory.clone(),
            shadow_id: entry.shadow_id.clone(),
            shadow_passed: entry.shadow_passed,
            validation_status: entry.validation_status,
            parent_queue_proposal_id: entry.parent_queue_proposal_id.clone(),
            parent_queue_review_state: entry.parent_queue_review_state,
            selection_review_state: entry.selection_review_state,
            portfolio_review_state: entry.portfolio_review_state,
            operator_reason: reason.to_string(),
            ready_for_governance: blocking_reasons.is_empty(),
            blocking_reasons,
        };
        let record = self.governance_packet_store.persist(&report)?;
        Ok(EvolutionGovernanceReviewPacketLookup { record, report })
    }

    pub fn load_governance_review_packet(
        &self,
        packet_id: &str,
    ) -> Result<Option<EvolutionGovernanceReviewPacketLookup>, EvolutionPortfolioError> {
        Ok(self.governance_packet_store.load(packet_id)?)
    }
}

/// Render one cross-batch portfolio artifact.
pub fn render_evolution_portfolio(report: &EvolutionPortfolioReport) -> String {
    let mut lines = vec![
        "Evolution Portfolio".to_string(),
        format!("Portfolio ID: {}", report.portfolio_id),
        format!("Name: {}", report.portfolio_name),
        format!("Entries: {}", report.entries.len()),
        format!("Rationale: {}", report.operator_rationale),
    ];
    for entry in &report.entries {
        lines.push(format!(
            "- {} | cohort={} | strategy={} | rank={} | state={} | batch={}",
            entry.entry_id,
            entry.cohort,
            entry.strategy_id,
            entry.rank,
            portfolio_review_state_label(entry.portfolio_review_state),
            entry.validation_batch_id
        ));
    }
    lines.join("\n")
}

/// Render a filtered portfolio listing for operators.
pub fn render_evolution_portfolio_list(list: &EvolutionPortfolioList) -> String {
    let mut lines = vec![
        "Evolution Portfolios".to_string(),
        format!("Total portfolios: {}", list.total_count),
    ];
    if let Some(cohort) = &list.cohort {
        lines.push(format!("Cohort filter: {}", cohort));
    }
    if let Some(review_state) = list.review_state {
        lines.push(format!(
            "Review-state filter: {}",
            portfolio_review_state_label(review_state)
        ));
    }
    if list.portfolios.is_empty() {
        lines.push("No portfolios matched the requested filters.".to_string());
        return lines.join("\n");
    }
    for portfolio in &list.portfolios {
        lines.push(format!(
            "- {} | name={} | entries={} | included={} | blocked={} | cohorts={}",
            portfolio.portfolio_id,
            portfolio.portfolio_name,
            portfolio.entry_count,
            portfolio.included_count,
            portfolio.blocked_count,
            portfolio.cohorts.join(",")
        ));
    }
    lines.join("\n")
}

/// Render one governance-ready review packet.
pub fn render_evolution_governance_review_packet(
    report: &EvolutionGovernanceReviewPacketReport,
) -> String {
    let mut lines = vec![
        "Evolution Governance Review Packet".to_string(),
        format!("Packet ID: {}", report.packet_id),
        format!(
            "Portfolio: {} ({}) | Entry: {}",
            report.portfolio_name, report.portfolio_id, report.entry_id
        ),
        format!(
            "Cohort: {} | Strategy: {} | score={:.3}",
            report.cohort, report.strategy_id, report.score
        ),
        format!(
            "Selection: {} | Ranking: {}",
            report.selection_id, report.ranking_id
        ),
        format!(
            "Review state: selection={} portfolio={}",
            selection_review_state_label(report.selection_review_state),
            portfolio_review_state_label(report.portfolio_review_state)
        ),
        format!(
            "Validation: {} | Proof: {} | ready_for_governance={}",
            validation_status_label(report.validation_status),
            proof_status_label(report.proof_status),
            report.ready_for_governance
        ),
        format!(
            "Verification: {} | Shadow: {} (passed={})",
            report.verification_id, report.shadow_id, report.shadow_passed
        ),
        format!(
            "Parent queue: {} ({})",
            report.parent_queue_proposal_id.as_deref().unwrap_or("none"),
            report
                .parent_queue_review_state
                .map(selection_review_state_label)
                .unwrap_or("none")
        ),
        format!("Reason: {}", report.operator_reason),
    ];
    if let Some(advisory) = &report.advisory {
        lines.push(format!(
            "Advisory: scorecard={} recommendation={} delta={:.3}",
            advisory.scorecard_id,
            advisory_recommendation_label(advisory.recommendation),
            advisory.score_delta
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

fn portfolio_id(name: &str, created_at_ms: i64) -> String {
    format!(
        "evolution_portfolio:{}:{}",
        short_digest(name),
        created_at_ms
    )
}

fn portfolio_entry_id(selection_id: &str, cohort: &str, index: usize) -> String {
    format!(
        "evolution_portfolio_entry:{}:{}:{}",
        short_digest(selection_id),
        short_digest(cohort),
        index + 1
    )
}

fn governance_packet_id(portfolio_id: &str, entry_id: &str, created_at_ms: i64) -> String {
    format!(
        "evolution_governance_packet:{}:{}:{}",
        short_digest(portfolio_id),
        short_digest(entry_id),
        created_at_ms
    )
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

fn short_digest(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    digest[..12].to_string()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn experiment_id_for_manifest(manifest: &crate::replay::DetectorExperimentManifest) -> String {
    format!(
        "experiment:{}:{}",
        manifest.name,
        manifest.candidate.strategy_id()
    )
}

fn sha256_hex<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(value)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

fn portfolio_review_state_label(state: EvolutionPortfolioEntryReviewState) -> &'static str {
    match state {
        EvolutionPortfolioEntryReviewState::PendingReview => "pending_review",
        EvolutionPortfolioEntryReviewState::Included => "included",
        EvolutionPortfolioEntryReviewState::Deferred => "deferred",
        EvolutionPortfolioEntryReviewState::Dropped => "dropped",
        EvolutionPortfolioEntryReviewState::Blocked => "blocked",
    }
}

fn portfolio_decision_action_label(action: EvolutionPortfolioDecisionAction) -> &'static str {
    match action {
        EvolutionPortfolioDecisionAction::Include => "include",
        EvolutionPortfolioDecisionAction::Defer => "defer",
        EvolutionPortfolioDecisionAction::Drop => "drop",
    }
}

fn selection_review_state_label(state: EvolutionProposalReviewState) -> &'static str {
    match state {
        EvolutionProposalReviewState::PendingReview => "pending_review",
        EvolutionProposalReviewState::AcceptedForCanary => "accepted_for_canary",
        EvolutionProposalReviewState::Deferred => "deferred",
        EvolutionProposalReviewState::Rejected => "rejected",
        EvolutionProposalReviewState::Blocked => "blocked",
    }
}

fn validation_status_label(status: EvolutionValidationBundleStatus) -> &'static str {
    match status {
        EvolutionValidationBundleStatus::ReadyForQueue => "ready_for_queue",
        EvolutionValidationBundleStatus::Blocked => "blocked",
    }
}

fn proof_status_label(status: EvolutionProposalProofStatus) -> &'static str {
    match status {
        EvolutionProposalProofStatus::Proved => "proved",
        EvolutionProposalProofStatus::Missing => "missing",
        EvolutionProposalProofStatus::Inconsistent => "inconsistent",
    }
}

fn advisory_recommendation_label(
    value: crate::strategy::StrategyAdvisoryRecommendation,
) -> &'static str {
    match value {
        crate::strategy::StrategyAdvisoryRecommendation::RetainBaseline => "retain_baseline",
        crate::strategy::StrategyAdvisoryRecommendation::CandidatePreferred => {
            "candidate_preferred"
        }
        crate::strategy::StrategyAdvisoryRecommendation::CandidateAlreadyStableInProduction => {
            "candidate_already_stable_in_production"
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct EvolutionPortfolioIndex {
    entries: Vec<EvolutionPortfolioRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct EvolutionGovernanceReviewPacketIndex {
    entries: Vec<EvolutionGovernanceReviewPacketRecord>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        DefaultEvolutionPortfolioHarness, EvolutionPortfolioDecisionAction,
        EvolutionPortfolioEntryCreateRequest, EvolutionPortfolioEntryReviewState,
        EvolutionProposalReviewState, render_evolution_governance_review_packet,
        render_evolution_portfolio, render_evolution_portfolio_list,
    };
    use crate::drafting::{DefaultEvolutionDraftingHarness, EvolutionDraftCreateRequest};
    use crate::mutation::{
        DefaultEvolutionMutationHarness, EvolutionMutationProfileOverrides,
        EvolutionMutationSpecCreateRequest, EvolutionMutationVariantCreateRequest,
    };
    use crate::portfolio::EvolutionPortfolioError;
    use crate::replay::DefaultReplayHarness;
    use crate::selection::DefaultEvolutionSelectionHarness;
    use crate::strategy::DefaultStrategyScorecardHarness;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use swarm_core::ThreatClass;
    use swarm_core::config::{PolicyRuleConfig, PolicyRuleDecision, SwarmConfig};
    use swarm_core::types::Severity;

    static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

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
            name: format!("portfolio-test-allow-{threat_class:?}"),
            decision: PolicyRuleDecision::Allow,
            threat_class,
            actions: Vec::new(),
            min_severity: Severity::Low,
            max_severity: Severity::Critical,
            time_window_utc: None,
            max_actions_per_agent_per_minute: None,
            reason: Some("portfolio tests allow replay and verification responses".to_string()),
        })
        .collect()
    }

    fn office_control_experiment() -> PathBuf {
        repo_root().join("experiments/office-baseline-control.yaml")
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        path.push(format!(
            "swarm-team-six-{}-{}-{}",
            label,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            counter
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

    struct PortfolioFixture {
        _root: PathBuf,
        portfolio_harness: DefaultEvolutionPortfolioHarness,
        ready_selection_id: String,
        blocked_selection_id: String,
        ranking_id: String,
        validation_batch_id: String,
        mutation_spec_id: String,
    }

    async fn build_fixture() -> PortfolioFixture {
        let root = unique_temp_dir("portfolio");
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
        let selection_dir = root.join("selections");
        let selection_bridge_dir = root.join("selection-bridges");
        let portfolio_dir = root.join("portfolios");
        let governance_packet_dir = root.join("governance-packets");
        let queue_dir = root.join("queue");
        let base_experiment = copy_experiment_fixture(&root, "office-control-portfolio");

        let config = sample_config();
        let replay =
            DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
        let verification = replay
            .evaluate_verification_path(&base_experiment, &verification_dir)
            .await
            .unwrap();
        let proofs = crate::evolution::DefaultEvolutionProofHarness::from_config(
            "inline",
            config.clone(),
            &proof_dir,
        )
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
                strategy_description: "portfolio parent".to_string(),
                mutation: "guided_portfolio_seed".to_string(),
                rationale: "compare ranked selections across cohorts".to_string(),
            })
            .unwrap();
        drafting
            .promote_draft(
                &queue_dir,
                &draft.report.draft_id,
                "seed a reviewed queue parent for portfolio assembly",
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
                    rationale: "compare ready and blocked ranked candidates for portfolio review"
                        .to_string(),
                },
            )
            .unwrap();
        let spec = mutation
            .append_variant(
                &spec.report.mutation_spec_id,
                EvolutionMutationVariantCreateRequest {
                    variant_id: Some("control-copy".to_string()),
                    strategy_id: "office_portfolio_control_v1".to_string(),
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
                    strategy_id: "office_portfolio_python_parent_v1".to_string(),
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
            .rank_candidates(&queue_dir, &validation_batch.report.validation_batch_id, 2)
            .unwrap();
        let selection_harness = DefaultEvolutionSelectionHarness::from_path(
            &mutation_ranking_dir,
            &validation_dir,
            &selection_dir,
            &selection_bridge_dir,
        )
        .unwrap();
        let first_selection = selection_harness
            .create_selection(
                &ranking.report.ranking_id,
                &ranking.report.review_packets[0].packet_id,
            )
            .unwrap();
        let second_selection = selection_harness
            .create_selection(
                &ranking.report.ranking_id,
                &ranking.report.review_packets[1].packet_id,
            )
            .unwrap();
        let (ready_selection, blocked_selection) =
            if first_selection.report.review_state == EvolutionProposalReviewState::PendingReview {
                (first_selection, second_selection)
            } else {
                (second_selection, first_selection)
            };
        let portfolio_harness = DefaultEvolutionPortfolioHarness::from_path(
            &mutation_ranking_dir,
            &selection_dir,
            &portfolio_dir,
            &governance_packet_dir,
        )
        .unwrap();

        PortfolioFixture {
            _root: root,
            portfolio_harness,
            ready_selection_id: ready_selection.report.selection_id.clone(),
            blocked_selection_id: blocked_selection.report.selection_id.clone(),
            ranking_id: ranking.report.ranking_id.clone(),
            validation_batch_id: ranking.report.validation_batch_id.clone(),
            mutation_spec_id: ranking.report.mutation_spec_id.clone(),
        }
    }

    #[tokio::test]
    async fn portfolio_persists_multi_entry_assembly() {
        let fixture = build_fixture().await;
        let portfolio = fixture
            .portfolio_harness
            .create_portfolio(
                "office cross cohort shortlist",
                "compare ready and blocked ranked candidates across two operator cohorts",
                vec![
                    EvolutionPortfolioEntryCreateRequest {
                        selection_id: fixture.ready_selection_id.clone(),
                        cohort: Some("hellcat.office_loader".to_string()),
                    },
                    EvolutionPortfolioEntryCreateRequest {
                        selection_id: fixture.blocked_selection_id.clone(),
                        cohort: Some("operator.maintenance".to_string()),
                    },
                ],
            )
            .unwrap();

        assert_eq!(portfolio.report.entries.len(), 2);
        assert_eq!(portfolio.report.entries[0].ranking_id, fixture.ranking_id);
        assert_eq!(
            portfolio.report.entries[0].validation_batch_id,
            fixture.validation_batch_id
        );
        assert_eq!(
            portfolio.report.entries[0].mutation_spec_id,
            fixture.mutation_spec_id
        );
        assert!(
            portfolio
                .report
                .entries
                .iter()
                .any(|entry| entry.cohort == "hellcat.office_loader")
        );
        assert!(render_evolution_portfolio(&portfolio.report).contains("Evolution Portfolio"));
    }

    #[tokio::test]
    async fn portfolio_supports_curation_and_listing() {
        let fixture = build_fixture().await;
        let portfolio = fixture
            .portfolio_harness
            .create_portfolio(
                "office portfolio curation",
                "curate the ready candidate and drop the blocked one",
                vec![
                    EvolutionPortfolioEntryCreateRequest {
                        selection_id: fixture.ready_selection_id.clone(),
                        cohort: Some("hellcat.office_loader".to_string()),
                    },
                    EvolutionPortfolioEntryCreateRequest {
                        selection_id: fixture.blocked_selection_id.clone(),
                        cohort: Some("operator.maintenance".to_string()),
                    },
                ],
            )
            .unwrap();
        let ready_entry = portfolio
            .report
            .entries
            .iter()
            .find(|entry| entry.selection_id == fixture.ready_selection_id)
            .unwrap();
        let blocked_entry = portfolio
            .report
            .entries
            .iter()
            .find(|entry| entry.selection_id == fixture.blocked_selection_id)
            .unwrap();

        let portfolio = fixture
            .portfolio_harness
            .record_decision(
                &portfolio.report.portfolio_id,
                &ready_entry.entry_id,
                EvolutionPortfolioDecisionAction::Include,
                "include the ready shortlisted candidate in the curated portfolio",
            )
            .unwrap();
        let portfolio = fixture
            .portfolio_harness
            .record_decision(
                &portfolio.report.portfolio_id,
                &blocked_entry.entry_id,
                EvolutionPortfolioDecisionAction::Drop,
                "drop the blocked shortlisted candidate from the curated portfolio",
            )
            .unwrap();

        let ready_entry = portfolio
            .report
            .entries
            .iter()
            .find(|entry| entry.selection_id == fixture.ready_selection_id)
            .unwrap();
        let blocked_entry = portfolio
            .report
            .entries
            .iter()
            .find(|entry| entry.selection_id == fixture.blocked_selection_id)
            .unwrap();
        assert_eq!(
            ready_entry.portfolio_review_state,
            EvolutionPortfolioEntryReviewState::Included
        );
        assert_eq!(
            blocked_entry.portfolio_review_state,
            EvolutionPortfolioEntryReviewState::Dropped
        );

        let list = fixture
            .portfolio_harness
            .list_portfolios(None, Some(EvolutionPortfolioEntryReviewState::Included))
            .unwrap();
        assert_eq!(list.total_count, 1);
        assert!(render_evolution_portfolio_list(&list).contains("Evolution Portfolios"));
    }

    #[tokio::test]
    async fn included_portfolio_entry_persists_governance_packet() {
        let fixture = build_fixture().await;
        let portfolio = fixture
            .portfolio_harness
            .create_portfolio(
                "office governance prep",
                "package the best shortlisted candidate for future governance review",
                vec![EvolutionPortfolioEntryCreateRequest {
                    selection_id: fixture.ready_selection_id.clone(),
                    cohort: Some("hellcat.office_loader".to_string()),
                }],
            )
            .unwrap();
        let entry = portfolio.report.entries.first().unwrap();
        let portfolio = fixture
            .portfolio_harness
            .record_decision(
                &portfolio.report.portfolio_id,
                &entry.entry_id,
                EvolutionPortfolioDecisionAction::Include,
                "include the portfolio entry for future governance review",
            )
            .unwrap();
        let entry = portfolio.report.entries.first().unwrap();
        let packet = fixture
            .portfolio_harness
            .create_governance_review_packet(
                &portfolio.report.portfolio_id,
                &entry.entry_id,
                "prepare this entry for a later governance-backed review lane",
            )
            .unwrap();

        assert!(packet.report.ready_for_governance);
        assert!(packet.report.blocking_reasons.is_empty());
        assert!(
            render_evolution_governance_review_packet(&packet.report)
                .contains("Evolution Governance Review Packet")
        );
    }

    #[tokio::test]
    async fn blocked_portfolio_entry_fails_closed_for_governance_packet() {
        let fixture = build_fixture().await;
        let portfolio = fixture
            .portfolio_harness
            .create_portfolio(
                "office blocked governance prep",
                "show that blocked entries persist blocked governance packets",
                vec![EvolutionPortfolioEntryCreateRequest {
                    selection_id: fixture.blocked_selection_id.clone(),
                    cohort: Some("operator.maintenance".to_string()),
                }],
            )
            .unwrap();
        let entry = portfolio.report.entries.first().unwrap();
        let packet = fixture
            .portfolio_harness
            .create_governance_review_packet(
                &portfolio.report.portfolio_id,
                &entry.entry_id,
                "attempt to package a blocked entry for governance review",
            )
            .unwrap();

        assert!(!packet.report.ready_for_governance);
        assert!(!packet.report.blocking_reasons.is_empty());
        assert!(
            packet
                .report
                .blocking_reasons
                .iter()
                .any(|reason| reason.name.contains("blocked")
                    || reason.name.contains("not_included"))
        );
    }

    #[tokio::test]
    async fn included_portfolio_requires_unblocked_entries() {
        let fixture = build_fixture().await;
        let portfolio = fixture
            .portfolio_harness
            .create_portfolio(
                "office invalid include",
                "blocked entries should not be includable",
                vec![EvolutionPortfolioEntryCreateRequest {
                    selection_id: fixture.blocked_selection_id.clone(),
                    cohort: Some("operator.maintenance".to_string()),
                }],
            )
            .unwrap();
        let entry = portfolio.report.entries.first().unwrap();
        let error = fixture
            .portfolio_harness
            .record_decision(
                &portfolio.report.portfolio_id,
                &entry.entry_id,
                EvolutionPortfolioDecisionAction::Include,
                "try to include a blocked entry",
            )
            .unwrap_err();

        assert!(matches!(
            error,
            EvolutionPortfolioError::InvalidDecision { .. }
        ));
    }
}
