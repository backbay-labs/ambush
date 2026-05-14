use crate::drafting::EvolutionValidationBundleStatus;
use crate::evolution::{
    EvolutionProposalAdvisorySummary, EvolutionProposalBlockingReason,
    EvolutionProposalProofStatus, EvolutionProposalProofSummary, EvolutionProposalReviewState,
};
use crate::portfolio::{
    EvolutionGovernanceReviewPacketReport, EvolutionGovernanceReviewPacketStoreError,
    EvolutionPortfolioEntryReviewState, FileEvolutionGovernanceReviewPacketStore,
};
use crate::replay::ExperimentLineage;
use crate::strategy::{
    FileStrategyMemoryStore, StrategyMemoryOutcomeKind, StrategyMemoryStoreError,
    StrategyRolloutStateSummary,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// One source review packet copied into a durable governance packet-set artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionGovernancePacketSetEntryReport {
    pub packet_set_entry_id: String,
    pub source_packet_set_entry_id: Option<String>,
    pub packet_id: String,
    pub source_packet_created_at_ms: i64,
    pub operator_reason: String,
    pub portfolio_id: String,
    pub portfolio_name: String,
    pub portfolio_entry_id: String,
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
    pub ready_for_governance: bool,
    pub blocking_reasons: Vec<EvolutionProposalBlockingReason>,
}

/// One durable packet-set assembled from multiple governance review packets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionGovernancePacketSetReport {
    pub packet_set_id: String,
    pub packet_set_name: String,
    pub operator_rationale: String,
    pub created_at_ms: i64,
    pub parent_packet_set_id: Option<String>,
    pub entries: Vec<EvolutionGovernancePacketSetEntryReport>,
}

/// Metadata surfaced for one persisted governance packet set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionGovernancePacketSetRecord {
    pub packet_set_id: String,
    pub packet_set_name: String,
    pub packet_count: usize,
    pub ready_count: usize,
    pub blocked_count: usize,
    pub cohorts: Vec<String>,
    pub created_at_ms: i64,
    pub parent_packet_set_id: Option<String>,
    pub bundle_path: String,
}

impl EvolutionGovernancePacketSetRecord {
    fn from_report(report: &EvolutionGovernancePacketSetReport, bundle_path: String) -> Self {
        let cohorts = report
            .entries
            .iter()
            .map(|entry| entry.cohort.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        Self {
            packet_set_id: report.packet_set_id.clone(),
            packet_set_name: report.packet_set_name.clone(),
            packet_count: report.entries.len(),
            ready_count: report
                .entries
                .iter()
                .filter(|entry| entry.ready_for_governance)
                .count(),
            blocked_count: report
                .entries
                .iter()
                .filter(|entry| !entry.ready_for_governance)
                .count(),
            cohorts,
            created_at_ms: report.created_at_ms,
            parent_packet_set_id: report.parent_packet_set_id.clone(),
            bundle_path,
        }
    }
}

/// Persisted governance packet set loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionGovernancePacketSetLookup {
    pub record: EvolutionGovernancePacketSetRecord,
    pub report: EvolutionGovernancePacketSetReport,
}

/// Operator-facing packet-set listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionGovernancePacketSetList {
    pub total_count: usize,
    pub cohort: Option<String>,
    pub packet_sets: Vec<EvolutionGovernancePacketSetRecord>,
}

/// Outcome class derived from durable strategy memories for one packet-set entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionPortfolioHistoryOutcomeKind {
    NoObservedRollout,
    ReadyForPromotionReview,
    StableInProduction,
    Blocked,
    Halted,
}

/// Unresolved review debt still attached to one packet-set entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionPortfolioHistoryReviewDebtKind {
    PendingGovernanceFollowUp,
    AwaitingStableOutcome,
}

/// One packet-set entry linked to later rollout outcomes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionPortfolioHistoryEntryReport {
    pub packet_set_entry_id: String,
    pub packet_id: String,
    pub portfolio_id: String,
    pub portfolio_name: String,
    pub portfolio_entry_id: String,
    pub cohort: String,
    pub strategy_id: String,
    pub strategy_description: String,
    pub ready_for_governance: bool,
    pub blocking_reasons: Vec<EvolutionProposalBlockingReason>,
    pub memory_ids: Vec<String>,
    pub latest_rollout_state: Option<StrategyRolloutStateSummary>,
    pub outcome: EvolutionPortfolioHistoryOutcomeKind,
    pub survived_live_rollout: bool,
    pub review_debt: Option<EvolutionPortfolioHistoryReviewDebtKind>,
}

/// Cohort-scoped history summary surfaced on one portfolio history artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionPortfolioHistoryCohortSummary {
    pub cohort: String,
    pub entry_count: usize,
    pub survived_count: usize,
    pub stable_count: usize,
    pub blocked_count: usize,
    pub halted_count: usize,
    pub unobserved_count: usize,
    pub review_debt_count: usize,
}

/// Aggregate rollout and debt counts over one portfolio history snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionPortfolioHistoryOutcomeCounts {
    pub entry_count: usize,
    pub survived_count: usize,
    pub stable_count: usize,
    pub ready_for_promotion_review_count: usize,
    pub blocked_count: usize,
    pub halted_count: usize,
    pub unobserved_count: usize,
    pub review_debt_count: usize,
}

/// Durable history snapshot derived from one governance packet set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionPortfolioHistoryReport {
    pub history_id: String,
    pub packet_set_id: String,
    pub packet_set_name: String,
    pub created_at_ms: i64,
    pub outcomes: EvolutionPortfolioHistoryOutcomeCounts,
    pub cohorts: Vec<EvolutionPortfolioHistoryCohortSummary>,
    pub entries: Vec<EvolutionPortfolioHistoryEntryReport>,
}

/// Metadata surfaced for one persisted portfolio history snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionPortfolioHistoryRecord {
    pub history_id: String,
    pub packet_set_id: String,
    pub packet_set_name: String,
    pub entry_count: usize,
    pub survived_count: usize,
    pub stable_count: usize,
    pub review_debt_count: usize,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl EvolutionPortfolioHistoryRecord {
    fn from_report(report: &EvolutionPortfolioHistoryReport, bundle_path: String) -> Self {
        Self {
            history_id: report.history_id.clone(),
            packet_set_id: report.packet_set_id.clone(),
            packet_set_name: report.packet_set_name.clone(),
            entry_count: report.entries.len(),
            survived_count: report.outcomes.survived_count,
            stable_count: report.outcomes.stable_count,
            review_debt_count: report.outcomes.review_debt_count,
            created_at_ms: report.created_at_ms,
            bundle_path,
        }
    }
}

/// Persisted portfolio history loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionPortfolioHistoryLookup {
    pub record: EvolutionPortfolioHistoryRecord,
    pub report: EvolutionPortfolioHistoryReport,
}

/// Operator-facing portfolio-history listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionPortfolioHistoryList {
    pub total_count: usize,
    pub cohort: Option<String>,
    pub histories: Vec<EvolutionPortfolioHistoryRecord>,
}

/// Errors raised by the persisted governance packet-set store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionGovernancePacketSetStoreError {
    #[error("failed to read governance packet-set store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write governance packet-set store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse governance packet-set store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised by the persisted portfolio-history store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionPortfolioHistoryStoreError {
    #[error("failed to read portfolio history store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write portfolio history store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse portfolio history store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors surfaced by governance packet-set and history workflows.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionGovernancePrepError {
    #[error(transparent)]
    GovernancePacketStore(#[from] EvolutionGovernanceReviewPacketStoreError),

    #[error(transparent)]
    PacketSetStore(#[from] EvolutionGovernancePacketSetStoreError),

    #[error(transparent)]
    HistoryStore(#[from] EvolutionPortfolioHistoryStoreError),

    #[error(transparent)]
    StrategyMemoryStore(#[from] StrategyMemoryStoreError),

    #[error("governance review packet `{packet_id}` was not found")]
    GovernancePacketNotFound { packet_id: String },

    #[error("governance packet set `{packet_set_id}` was not found")]
    PacketSetNotFound { packet_set_id: String },

    #[error("portfolio history `{history_id}` was not found")]
    PortfolioHistoryNotFound { history_id: String },

    #[error("invalid governance packet-set request: {reason}")]
    InvalidPacketSetRequest { reason: String },

    #[error("packet `{packet_id}` was not found in governance packet set `{packet_set_id}`")]
    PacketNotInSet {
        packet_id: String,
        packet_set_id: String,
    },

    #[error("inconsistent packet evidence for `{packet_id}`: {reason}")]
    InconsistentPacketEvidence { packet_id: String, reason: String },
}

/// File-backed store for governance packet-set artifacts.
#[derive(Debug, Clone)]
pub struct FileEvolutionGovernancePacketSetStore {
    root: PathBuf,
}

impl FileEvolutionGovernancePacketSetStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionGovernancePacketSetStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionGovernancePacketSetStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, packet_set_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(packet_set_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(
        &self,
    ) -> Result<EvolutionGovernancePacketSetIndex, EvolutionGovernancePacketSetStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionGovernancePacketSetIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionGovernancePacketSetStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionGovernancePacketSetStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionGovernancePacketSetIndex,
    ) -> Result<(), EvolutionGovernancePacketSetStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionGovernancePacketSetStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| EvolutionGovernancePacketSetStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionGovernancePacketSetReport,
    ) -> Result<EvolutionGovernancePacketSetRecord, EvolutionGovernancePacketSetStoreError> {
        let path = self.report_path(&report.packet_set_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionGovernancePacketSetStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionGovernancePacketSetStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record =
            EvolutionGovernancePacketSetRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.packet_set_id != record.packet_set_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        packet_set_id: &str,
    ) -> Result<Option<EvolutionGovernancePacketSetLookup>, EvolutionGovernancePacketSetStoreError>
    {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.packet_set_id == packet_set_id)
            .cloned()
        else {
            return Ok(None);
        };

        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionGovernancePacketSetStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionGovernancePacketSetStoreError::Parse { path, source })?;
        Ok(Some(EvolutionGovernancePacketSetLookup { record, report }))
    }

    pub fn list(
        &self,
        cohort: Option<&str>,
    ) -> Result<EvolutionGovernancePacketSetList, EvolutionGovernancePacketSetStoreError> {
        let index = self.read_index()?;
        let packet_sets = if let Some(expected_cohort) = cohort {
            index
                .entries
                .into_iter()
                .filter(|record| match self.load(&record.packet_set_id) {
                    Ok(Some(lookup)) => lookup
                        .report
                        .entries
                        .iter()
                        .any(|entry| entry.cohort == expected_cohort),
                    _ => false,
                })
                .collect::<Vec<_>>()
        } else {
            index.entries
        };
        Ok(EvolutionGovernancePacketSetList {
            total_count: packet_sets.len(),
            cohort: cohort.map(ToOwned::to_owned),
            packet_sets,
        })
    }
}

/// File-backed store for portfolio history snapshots.
#[derive(Debug, Clone)]
pub struct FileEvolutionPortfolioHistoryStore {
    root: PathBuf,
}

impl FileEvolutionPortfolioHistoryStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionPortfolioHistoryStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionPortfolioHistoryStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, history_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(history_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(
        &self,
    ) -> Result<EvolutionPortfolioHistoryIndex, EvolutionPortfolioHistoryStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionPortfolioHistoryIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionPortfolioHistoryStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionPortfolioHistoryStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionPortfolioHistoryIndex,
    ) -> Result<(), EvolutionPortfolioHistoryStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionPortfolioHistoryStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| EvolutionPortfolioHistoryStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionPortfolioHistoryReport,
    ) -> Result<EvolutionPortfolioHistoryRecord, EvolutionPortfolioHistoryStoreError> {
        let path = self.report_path(&report.history_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionPortfolioHistoryStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionPortfolioHistoryStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record =
            EvolutionPortfolioHistoryRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.history_id != record.history_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        history_id: &str,
    ) -> Result<Option<EvolutionPortfolioHistoryLookup>, EvolutionPortfolioHistoryStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.history_id == history_id)
            .cloned()
        else {
            return Ok(None);
        };

        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionPortfolioHistoryStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionPortfolioHistoryStoreError::Parse { path, source })?;
        Ok(Some(EvolutionPortfolioHistoryLookup { record, report }))
    }

    pub fn list(
        &self,
        cohort: Option<&str>,
    ) -> Result<EvolutionPortfolioHistoryList, EvolutionPortfolioHistoryStoreError> {
        let index = self.read_index()?;
        let histories = if let Some(expected_cohort) = cohort {
            index
                .entries
                .into_iter()
                .filter(|record| match self.load(&record.history_id) {
                    Ok(Some(lookup)) => lookup
                        .report
                        .entries
                        .iter()
                        .any(|entry| entry.cohort == expected_cohort),
                    _ => false,
                })
                .collect::<Vec<_>>()
        } else {
            index.entries
        };
        Ok(EvolutionPortfolioHistoryList {
            total_count: histories.len(),
            cohort: cohort.map(ToOwned::to_owned),
            histories,
        })
    }
}

/// Harness for governance packet-set operations and portfolio history snapshots.
#[derive(Debug, Clone)]
pub struct DefaultEvolutionGovernancePrepHarness {
    pub governance_packet_store: FileEvolutionGovernanceReviewPacketStore,
    pub packet_set_store: FileEvolutionGovernancePacketSetStore,
    pub strategy_memory_store: FileStrategyMemoryStore,
    pub history_store: FileEvolutionPortfolioHistoryStore,
}

impl DefaultEvolutionGovernancePrepHarness {
    pub fn from_path(
        governance_packet_results_dir: impl AsRef<Path>,
        packet_set_results_dir: impl AsRef<Path>,
        strategy_memory_results_dir: impl AsRef<Path>,
        portfolio_history_results_dir: impl AsRef<Path>,
    ) -> Result<Self, EvolutionGovernancePrepError> {
        Ok(Self {
            governance_packet_store: FileEvolutionGovernanceReviewPacketStore::open(
                governance_packet_results_dir,
            )?,
            packet_set_store: FileEvolutionGovernancePacketSetStore::open(packet_set_results_dir)?,
            strategy_memory_store: FileStrategyMemoryStore::open(strategy_memory_results_dir)?,
            history_store: FileEvolutionPortfolioHistoryStore::open(portfolio_history_results_dir)?,
        })
    }

    pub fn create_packet_set(
        &self,
        name: &str,
        rationale: &str,
        packet_ids: Vec<String>,
    ) -> Result<EvolutionGovernancePacketSetLookup, EvolutionGovernancePrepError> {
        let entries = packet_set_entries_from_packets(&self.governance_packet_store, packet_ids)?;
        let created_at_ms = now_ms();
        let report = EvolutionGovernancePacketSetReport {
            packet_set_id: packet_set_id(name, created_at_ms),
            packet_set_name: name.trim().to_string(),
            operator_rationale: rationale.trim().to_string(),
            created_at_ms,
            parent_packet_set_id: None,
            entries,
        };
        let record = self.packet_set_store.persist(&report)?;
        Ok(EvolutionGovernancePacketSetLookup { record, report })
    }

    pub fn split_packet_set(
        &self,
        parent_packet_set_id: &str,
        name: &str,
        rationale: &str,
        packet_ids: Vec<String>,
    ) -> Result<EvolutionGovernancePacketSetLookup, EvolutionGovernancePrepError> {
        validate_packet_set_name(name)?;
        let parent = self
            .packet_set_store
            .load(parent_packet_set_id)?
            .ok_or_else(|| EvolutionGovernancePrepError::PacketSetNotFound {
                packet_set_id: parent_packet_set_id.to_string(),
            })?;
        let unique_ids = dedupe_packet_ids(packet_ids)?;
        let mut entries = Vec::with_capacity(unique_ids.len());
        for (index, packet_id) in unique_ids.into_iter().enumerate() {
            let entry = parent
                .report
                .entries
                .iter()
                .find(|entry| entry.packet_id == packet_id)
                .ok_or_else(|| EvolutionGovernancePrepError::PacketNotInSet {
                    packet_id: packet_id.clone(),
                    packet_set_id: parent_packet_set_id.to_string(),
                })?;
            entries.push(packet_set_entry_from_parent(index, entry));
        }

        let created_at_ms = now_ms();
        let report = EvolutionGovernancePacketSetReport {
            packet_set_id: packet_set_id(name, created_at_ms),
            packet_set_name: name.trim().to_string(),
            operator_rationale: rationale.trim().to_string(),
            created_at_ms,
            parent_packet_set_id: Some(parent.report.packet_set_id),
            entries,
        };
        let record = self.packet_set_store.persist(&report)?;
        Ok(EvolutionGovernancePacketSetLookup { record, report })
    }

    pub fn load_packet_set(
        &self,
        packet_set_id: &str,
    ) -> Result<Option<EvolutionGovernancePacketSetLookup>, EvolutionGovernancePrepError> {
        Ok(self.packet_set_store.load(packet_set_id)?)
    }

    pub fn list_packet_sets(
        &self,
        cohort: Option<&str>,
    ) -> Result<EvolutionGovernancePacketSetList, EvolutionGovernancePrepError> {
        Ok(self.packet_set_store.list(cohort)?)
    }

    pub fn create_portfolio_history(
        &self,
        packet_set_id: &str,
    ) -> Result<EvolutionPortfolioHistoryLookup, EvolutionGovernancePrepError> {
        let packet_set = self.packet_set_store.load(packet_set_id)?.ok_or_else(|| {
            EvolutionGovernancePrepError::PacketSetNotFound {
                packet_set_id: packet_set_id.to_string(),
            }
        })?;

        let mut entries = Vec::with_capacity(packet_set.report.entries.len());
        for entry in &packet_set.report.entries {
            validate_packet_history_entry(entry)?;
            let lookups = self.strategy_memory_store.history(&entry.strategy_id)?;
            let memory_ids = lookups
                .iter()
                .map(|lookup| lookup.report.memory_id.clone())
                .collect::<Vec<_>>();
            let latest_rollout_state = lookups.first().map(|lookup| StrategyRolloutStateSummary {
                source_kind: lookup.report.source_kind,
                source_artifact_id: lookup.report.source_artifact_id.clone(),
                outcome_kind: lookup.report.outcome_kind,
                observed_at_ms: lookup.report.observed_at_ms,
            });
            let outcome = history_outcome_from_latest(latest_rollout_state.as_ref());
            let review_debt = match (entry.ready_for_governance, outcome) {
                (true, EvolutionPortfolioHistoryOutcomeKind::NoObservedRollout) => {
                    Some(EvolutionPortfolioHistoryReviewDebtKind::PendingGovernanceFollowUp)
                }
                (true, EvolutionPortfolioHistoryOutcomeKind::ReadyForPromotionReview) => {
                    Some(EvolutionPortfolioHistoryReviewDebtKind::AwaitingStableOutcome)
                }
                _ => None,
            };
            entries.push(EvolutionPortfolioHistoryEntryReport {
                packet_set_entry_id: entry.packet_set_entry_id.clone(),
                packet_id: entry.packet_id.clone(),
                portfolio_id: entry.portfolio_id.clone(),
                portfolio_name: entry.portfolio_name.clone(),
                portfolio_entry_id: entry.portfolio_entry_id.clone(),
                cohort: entry.cohort.clone(),
                strategy_id: entry.strategy_id.clone(),
                strategy_description: entry.strategy_description.clone(),
                ready_for_governance: entry.ready_for_governance,
                blocking_reasons: entry.blocking_reasons.clone(),
                memory_ids,
                latest_rollout_state,
                outcome,
                survived_live_rollout: outcome_survived_live_rollout(outcome),
                review_debt,
            });
        }

        let created_at_ms = now_ms();
        let report = EvolutionPortfolioHistoryReport {
            history_id: portfolio_history_id(&packet_set.report.packet_set_id, created_at_ms),
            packet_set_id: packet_set.report.packet_set_id.clone(),
            packet_set_name: packet_set.report.packet_set_name.clone(),
            created_at_ms,
            outcomes: history_outcome_counts(&entries),
            cohorts: history_cohort_summaries(&entries),
            entries,
        };
        let record = self.history_store.persist(&report)?;
        Ok(EvolutionPortfolioHistoryLookup { record, report })
    }

    pub fn load_portfolio_history(
        &self,
        history_id: &str,
    ) -> Result<Option<EvolutionPortfolioHistoryLookup>, EvolutionGovernancePrepError> {
        Ok(self.history_store.load(history_id)?)
    }

    pub fn list_portfolio_history(
        &self,
        cohort: Option<&str>,
    ) -> Result<EvolutionPortfolioHistoryList, EvolutionGovernancePrepError> {
        Ok(self.history_store.list(cohort)?)
    }
}

pub fn render_evolution_governance_packet_set(
    report: &EvolutionGovernancePacketSetReport,
) -> String {
    let mut lines = vec![
        "Evolution Governance Packet Set".to_string(),
        format!("Packet set ID: {}", report.packet_set_id),
        format!("Name: {}", report.packet_set_name),
        format!("Created: {}", report.created_at_ms),
        format!(
            "Parent packet set: {}",
            report.parent_packet_set_id.as_deref().unwrap_or("none")
        ),
        format!("Operator rationale: {}", report.operator_rationale),
        format!("Entries: {}", report.entries.len()),
    ];

    if report.entries.is_empty() {
        lines.push("Packets: none".to_string());
    } else {
        lines.push("Packets:".to_string());
        for entry in &report.entries {
            lines.push(format!(
                "- {} | strategy={} | cohort={} | ready={} | portfolio={} | source={}",
                entry.packet_id,
                entry.strategy_id,
                entry.cohort,
                bool_label(entry.ready_for_governance),
                entry.portfolio_id,
                entry
                    .source_packet_set_entry_id
                    .as_deref()
                    .unwrap_or("packet")
            ));
        }
    }

    lines.join("\n")
}

pub fn render_evolution_governance_packet_set_list(
    list: &EvolutionGovernancePacketSetList,
) -> String {
    let mut lines = vec![
        "Evolution Governance Packet Sets".to_string(),
        format!("Total: {}", list.total_count),
        format!("Filter cohort: {}", list.cohort.as_deref().unwrap_or("any")),
    ];

    if list.packet_sets.is_empty() {
        lines.push("Entries: none".to_string());
    } else {
        lines.push("Entries:".to_string());
        for record in &list.packet_sets {
            lines.push(format!(
                "- {} | {} | packets={} | ready={} | blocked={} | cohorts={}",
                record.packet_set_id,
                record.packet_set_name,
                record.packet_count,
                record.ready_count,
                record.blocked_count,
                if record.cohorts.is_empty() {
                    "none".to_string()
                } else {
                    record.cohorts.join(",")
                }
            ));
        }
    }

    lines.join("\n")
}

pub fn render_evolution_portfolio_history(report: &EvolutionPortfolioHistoryReport) -> String {
    let mut lines = vec![
        "Evolution Portfolio History".to_string(),
        format!("History ID: {}", report.history_id),
        format!(
            "Packet set: {} ({})",
            report.packet_set_name, report.packet_set_id
        ),
        format!("Created: {}", report.created_at_ms),
        format!("Entries: {}", report.outcomes.entry_count),
        format!(
            "Outcomes: survived={} stable={} ready={} blocked={} halted={} unobserved={} debt={}",
            report.outcomes.survived_count,
            report.outcomes.stable_count,
            report.outcomes.ready_for_promotion_review_count,
            report.outcomes.blocked_count,
            report.outcomes.halted_count,
            report.outcomes.unobserved_count,
            report.outcomes.review_debt_count
        ),
    ];

    if report.cohorts.is_empty() {
        lines.push("Cohorts: none".to_string());
    } else {
        lines.push("Cohorts:".to_string());
        for cohort in &report.cohorts {
            lines.push(format!(
                "- {} | entries={} | survived={} | stable={} | blocked={} | halted={} | unobserved={} | debt={}",
                cohort.cohort,
                cohort.entry_count,
                cohort.survived_count,
                cohort.stable_count,
                cohort.blocked_count,
                cohort.halted_count,
                cohort.unobserved_count,
                cohort.review_debt_count
            ));
        }
    }

    if report.entries.is_empty() {
        lines.push("Packet entries: none".to_string());
    } else {
        lines.push("Packet entries:".to_string());
        for entry in &report.entries {
            lines.push(format!(
                "- {} | strategy={} | cohort={} | outcome={} | memories={} | debt={}",
                entry.packet_id,
                entry.strategy_id,
                entry.cohort,
                history_outcome_label(entry.outcome),
                entry.memory_ids.len(),
                history_review_debt_label(entry.review_debt)
            ));
        }
    }

    lines.join("\n")
}

pub fn render_evolution_portfolio_history_list(list: &EvolutionPortfolioHistoryList) -> String {
    let mut lines = vec![
        "Evolution Portfolio Histories".to_string(),
        format!("Total: {}", list.total_count),
        format!("Filter cohort: {}", list.cohort.as_deref().unwrap_or("any")),
    ];

    if list.histories.is_empty() {
        lines.push("Entries: none".to_string());
    } else {
        lines.push("Entries:".to_string());
        for record in &list.histories {
            lines.push(format!(
                "- {} | packet_set={} | entries={} | survived={} | stable={} | debt={}",
                record.history_id,
                record.packet_set_id,
                record.entry_count,
                record.survived_count,
                record.stable_count,
                record.review_debt_count
            ));
        }
    }

    lines.join("\n")
}

fn packet_set_entries_from_packets(
    store: &FileEvolutionGovernanceReviewPacketStore,
    packet_ids: Vec<String>,
) -> Result<Vec<EvolutionGovernancePacketSetEntryReport>, EvolutionGovernancePrepError> {
    validate_non_empty_packet_request(&packet_ids)?;
    let unique_ids = dedupe_packet_ids(packet_ids)?;
    let mut entries = Vec::with_capacity(unique_ids.len());
    for (index, packet_id) in unique_ids.into_iter().enumerate() {
        let packet = store.load(&packet_id)?.ok_or_else(|| {
            EvolutionGovernancePrepError::GovernancePacketNotFound {
                packet_id: packet_id.clone(),
            }
        })?;
        entries.push(packet_set_entry_from_packet(index, &packet.report));
    }
    Ok(entries)
}

fn validate_non_empty_packet_request(
    packet_ids: &[String],
) -> Result<(), EvolutionGovernancePrepError> {
    if packet_ids.is_empty() {
        return Err(EvolutionGovernancePrepError::InvalidPacketSetRequest {
            reason: "at least one governance review packet is required".to_string(),
        });
    }
    Ok(())
}

fn validate_packet_set_name(name: &str) -> Result<(), EvolutionGovernancePrepError> {
    if name.trim().is_empty() {
        return Err(EvolutionGovernancePrepError::InvalidPacketSetRequest {
            reason: "packet-set name cannot be empty".to_string(),
        });
    }
    Ok(())
}

fn dedupe_packet_ids(packet_ids: Vec<String>) -> Result<Vec<String>, EvolutionGovernancePrepError> {
    validate_non_empty_packet_request(&packet_ids)?;
    let mut seen = BTreeSet::new();
    let ids = packet_ids
        .into_iter()
        .filter(|packet_id| seen.insert(packet_id.clone()))
        .collect::<Vec<_>>();
    if ids.is_empty() {
        return Err(EvolutionGovernancePrepError::InvalidPacketSetRequest {
            reason: "no unique governance review packets were provided".to_string(),
        });
    }
    Ok(ids)
}

fn packet_set_entry_from_packet(
    index: usize,
    packet: &EvolutionGovernanceReviewPacketReport,
) -> EvolutionGovernancePacketSetEntryReport {
    EvolutionGovernancePacketSetEntryReport {
        packet_set_entry_id: packet_set_entry_id(&packet.packet_id, index),
        source_packet_set_entry_id: None,
        packet_id: packet.packet_id.clone(),
        source_packet_created_at_ms: packet.created_at_ms,
        operator_reason: packet.operator_reason.clone(),
        portfolio_id: packet.portfolio_id.clone(),
        portfolio_name: packet.portfolio_name.clone(),
        portfolio_entry_id: packet.entry_id.clone(),
        selection_id: packet.selection_id.clone(),
        ranking_id: packet.ranking_id.clone(),
        validation_batch_id: packet.validation_batch_id.clone(),
        mutation_spec_id: packet.mutation_spec_id.clone(),
        cohort: packet.cohort.clone(),
        rank: packet.rank,
        strategy_id: packet.strategy_id.clone(),
        strategy_description: packet.strategy_description.clone(),
        score: packet.score,
        summary: packet.summary.clone(),
        materialization_id: packet.materialization_id.clone(),
        validation_bundle_id: packet.validation_bundle_id.clone(),
        experiment_id: packet.experiment_id.clone(),
        experiment_name: packet.experiment_name.clone(),
        experiment_path: packet.experiment_path.clone(),
        lineage: packet.lineage.clone(),
        manifest_sha256: packet.manifest_sha256.clone(),
        lineage_sha256: packet.lineage_sha256.clone(),
        verification_id: packet.verification_id.clone(),
        verification_passed: packet.verification_passed,
        proof_status: packet.proof_status,
        proof: packet.proof.clone(),
        advisory: packet.advisory.clone(),
        shadow_id: packet.shadow_id.clone(),
        shadow_passed: packet.shadow_passed,
        validation_status: packet.validation_status,
        parent_queue_proposal_id: packet.parent_queue_proposal_id.clone(),
        parent_queue_review_state: packet.parent_queue_review_state,
        selection_review_state: packet.selection_review_state,
        portfolio_review_state: packet.portfolio_review_state,
        ready_for_governance: packet.ready_for_governance,
        blocking_reasons: packet.blocking_reasons.clone(),
    }
}

fn packet_set_entry_from_parent(
    index: usize,
    entry: &EvolutionGovernancePacketSetEntryReport,
) -> EvolutionGovernancePacketSetEntryReport {
    let mut next = entry.clone();
    next.source_packet_set_entry_id = Some(entry.packet_set_entry_id.clone());
    next.packet_set_entry_id = packet_set_entry_id(&entry.packet_id, index);
    next
}

fn validate_packet_history_entry(
    entry: &EvolutionGovernancePacketSetEntryReport,
) -> Result<(), EvolutionGovernancePrepError> {
    if entry.ready_for_governance
        && (!entry.blocking_reasons.is_empty()
            || !entry.verification_passed
            || !entry.shadow_passed
            || entry.validation_status != EvolutionValidationBundleStatus::ReadyForQueue
            || entry.proof_status != EvolutionProposalProofStatus::Proved)
    {
        return Err(EvolutionGovernancePrepError::InconsistentPacketEvidence {
            packet_id: entry.packet_id.clone(),
            reason: "ready packet carries failing validation, proof, shadow, or blocking state"
                .to_string(),
        });
    }
    if !entry.ready_for_governance && entry.blocking_reasons.is_empty() {
        return Err(EvolutionGovernancePrepError::InconsistentPacketEvidence {
            packet_id: entry.packet_id.clone(),
            reason: "blocked packet is missing preserved blocking reasons".to_string(),
        });
    }
    Ok(())
}

fn history_outcome_from_latest(
    latest_rollout_state: Option<&StrategyRolloutStateSummary>,
) -> EvolutionPortfolioHistoryOutcomeKind {
    match latest_rollout_state.map(|state| state.outcome_kind) {
        None => EvolutionPortfolioHistoryOutcomeKind::NoObservedRollout,
        Some(StrategyMemoryOutcomeKind::ReadyForPromotionReview) => {
            EvolutionPortfolioHistoryOutcomeKind::ReadyForPromotionReview
        }
        Some(StrategyMemoryOutcomeKind::StableInProduction) => {
            EvolutionPortfolioHistoryOutcomeKind::StableInProduction
        }
        Some(StrategyMemoryOutcomeKind::Blocked) => EvolutionPortfolioHistoryOutcomeKind::Blocked,
        Some(StrategyMemoryOutcomeKind::Halted) => EvolutionPortfolioHistoryOutcomeKind::Halted,
    }
}

fn outcome_survived_live_rollout(outcome: EvolutionPortfolioHistoryOutcomeKind) -> bool {
    matches!(
        outcome,
        EvolutionPortfolioHistoryOutcomeKind::ReadyForPromotionReview
            | EvolutionPortfolioHistoryOutcomeKind::StableInProduction
    )
}

fn history_outcome_counts(
    entries: &[EvolutionPortfolioHistoryEntryReport],
) -> EvolutionPortfolioHistoryOutcomeCounts {
    let mut counts = EvolutionPortfolioHistoryOutcomeCounts {
        entry_count: entries.len(),
        survived_count: 0,
        stable_count: 0,
        ready_for_promotion_review_count: 0,
        blocked_count: 0,
        halted_count: 0,
        unobserved_count: 0,
        review_debt_count: 0,
    };

    for entry in entries {
        if entry.survived_live_rollout {
            counts.survived_count += 1;
        }
        if entry.review_debt.is_some() {
            counts.review_debt_count += 1;
        }
        match entry.outcome {
            EvolutionPortfolioHistoryOutcomeKind::NoObservedRollout => {
                counts.unobserved_count += 1;
            }
            EvolutionPortfolioHistoryOutcomeKind::ReadyForPromotionReview => {
                counts.ready_for_promotion_review_count += 1;
            }
            EvolutionPortfolioHistoryOutcomeKind::StableInProduction => {
                counts.stable_count += 1;
            }
            EvolutionPortfolioHistoryOutcomeKind::Blocked => {
                counts.blocked_count += 1;
            }
            EvolutionPortfolioHistoryOutcomeKind::Halted => {
                counts.halted_count += 1;
            }
        }
    }

    counts
}

fn history_cohort_summaries(
    entries: &[EvolutionPortfolioHistoryEntryReport],
) -> Vec<EvolutionPortfolioHistoryCohortSummary> {
    let cohorts = entries
        .iter()
        .map(|entry| entry.cohort.clone())
        .collect::<BTreeSet<_>>();

    cohorts
        .into_iter()
        .map(|cohort| {
            let cohort_entries = entries
                .iter()
                .filter(|entry| entry.cohort == cohort)
                .collect::<Vec<_>>();
            EvolutionPortfolioHistoryCohortSummary {
                cohort,
                entry_count: cohort_entries.len(),
                survived_count: cohort_entries
                    .iter()
                    .filter(|entry| entry.survived_live_rollout)
                    .count(),
                stable_count: cohort_entries
                    .iter()
                    .filter(|entry| {
                        entry.outcome == EvolutionPortfolioHistoryOutcomeKind::StableInProduction
                    })
                    .count(),
                blocked_count: cohort_entries
                    .iter()
                    .filter(|entry| entry.outcome == EvolutionPortfolioHistoryOutcomeKind::Blocked)
                    .count(),
                halted_count: cohort_entries
                    .iter()
                    .filter(|entry| entry.outcome == EvolutionPortfolioHistoryOutcomeKind::Halted)
                    .count(),
                unobserved_count: cohort_entries
                    .iter()
                    .filter(|entry| {
                        entry.outcome == EvolutionPortfolioHistoryOutcomeKind::NoObservedRollout
                    })
                    .count(),
                review_debt_count: cohort_entries
                    .iter()
                    .filter(|entry| entry.review_debt.is_some())
                    .count(),
            }
        })
        .collect::<Vec<_>>()
}

fn bool_label(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn history_outcome_label(value: EvolutionPortfolioHistoryOutcomeKind) -> &'static str {
    match value {
        EvolutionPortfolioHistoryOutcomeKind::NoObservedRollout => "no_observed_rollout",
        EvolutionPortfolioHistoryOutcomeKind::ReadyForPromotionReview => {
            "ready_for_promotion_review"
        }
        EvolutionPortfolioHistoryOutcomeKind::StableInProduction => "stable_in_production",
        EvolutionPortfolioHistoryOutcomeKind::Blocked => "blocked",
        EvolutionPortfolioHistoryOutcomeKind::Halted => "halted",
    }
}

fn history_review_debt_label(
    value: Option<EvolutionPortfolioHistoryReviewDebtKind>,
) -> &'static str {
    match value {
        None => "none",
        Some(EvolutionPortfolioHistoryReviewDebtKind::PendingGovernanceFollowUp) => {
            "pending_governance_follow_up"
        }
        Some(EvolutionPortfolioHistoryReviewDebtKind::AwaitingStableOutcome) => {
            "awaiting_stable_outcome"
        }
    }
}

fn packet_set_id(name: &str, created_at_ms: i64) -> String {
    format!("packet_set:{}:{}", sanitize_id(name.trim()), created_at_ms)
}

fn packet_set_entry_id(packet_id: &str, index: usize) -> String {
    format!("packet_set_entry:{}:{}", sanitize_id(packet_id), index)
}

fn portfolio_history_id(packet_set_id: &str, created_at_ms: i64) -> String {
    format!(
        "portfolio_history:{}:{}",
        sanitize_id(packet_set_id),
        created_at_ms
    )
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .to_ascii_lowercase()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct EvolutionGovernancePacketSetIndex {
    entries: Vec<EvolutionGovernancePacketSetRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct EvolutionPortfolioHistoryIndex {
    entries: Vec<EvolutionPortfolioHistoryRecord>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        DefaultEvolutionGovernancePrepHarness, EvolutionGovernancePrepError,
        EvolutionPortfolioHistoryOutcomeKind, EvolutionPortfolioHistoryReviewDebtKind,
        render_evolution_governance_packet_set, render_evolution_governance_packet_set_list,
        render_evolution_portfolio_history, render_evolution_portfolio_history_list,
    };
    use crate::drafting::EvolutionValidationBundleStatus;
    use crate::evolution::{
        EvolutionProposalBlockingReason, EvolutionProposalProofStatus,
        EvolutionProposalProofSummary, EvolutionProposalReviewState,
    };
    use crate::portfolio::{
        EvolutionGovernanceReviewPacketReport, EvolutionPortfolioEntryReviewState,
        FileEvolutionGovernanceReviewPacketStore,
    };
    use crate::replay::ExperimentLineage;
    use crate::strategy::{
        FileStrategyMemoryStore, StrategyMemoryOutcomeKind, StrategyMemoryReport,
        StrategyMemorySourceKind,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

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

    fn sample_lineage(strategy_id: &str) -> ExperimentLineage {
        ExperimentLineage {
            parent_strategy_id: "office_baseline_control".to_string(),
            mutation: format!("mutation_for_{strategy_id}"),
            rationale: format!("rationale for {strategy_id}"),
        }
    }

    fn sample_packet(
        packet_id: &str,
        strategy_id: &str,
        cohort: &str,
        ready_for_governance: bool,
    ) -> EvolutionGovernanceReviewPacketReport {
        let blocking_reasons = if ready_for_governance {
            Vec::new()
        } else {
            vec![EvolutionProposalBlockingReason {
                source: "governance_packet".to_string(),
                name: "candidate_blocked".to_string(),
                details: "candidate remained blocked during governance packet preparation"
                    .to_string(),
                references: vec![packet_id.to_string()],
            }]
        };
        EvolutionGovernanceReviewPacketReport {
            packet_id: packet_id.to_string(),
            portfolio_id: format!("portfolio:{cohort}"),
            portfolio_name: format!("portfolio {cohort}"),
            entry_id: format!("entry:{packet_id}"),
            selection_id: format!("selection:{strategy_id}"),
            ranking_id: format!("ranking:{strategy_id}"),
            validation_batch_id: format!("validation_batch:{strategy_id}"),
            mutation_spec_id: format!("mutation_spec:{strategy_id}"),
            created_at_ms: 1_710_000_000_000,
            cohort: cohort.to_string(),
            rank: 1,
            strategy_id: strategy_id.to_string(),
            strategy_description: format!("strategy {strategy_id}"),
            score: 0.91,
            summary: format!("summary for {strategy_id}"),
            materialization_id: format!("materialization:{strategy_id}"),
            validation_bundle_id: format!("validation_bundle:{strategy_id}"),
            experiment_id: format!("experiment:{strategy_id}"),
            experiment_name: format!("experiment {strategy_id}"),
            experiment_path: format!("/tmp/{strategy_id}.yaml"),
            lineage: sample_lineage(strategy_id),
            manifest_sha256: format!("manifest_sha_for_{strategy_id}"),
            lineage_sha256: format!("lineage_sha_for_{strategy_id}"),
            verification_id: format!("verification:{strategy_id}"),
            verification_passed: ready_for_governance,
            proof_status: if ready_for_governance {
                EvolutionProposalProofStatus::Proved
            } else {
                EvolutionProposalProofStatus::Missing
            },
            proof: ready_for_governance.then(|| EvolutionProposalProofSummary {
                proof_id: format!("proof:{strategy_id}"),
                proof_system: "repo_owned".to_string(),
                attestation_sha256: format!("attestation_sha_for_{strategy_id}"),
                invariant_count: 4,
            }),
            advisory: None,
            shadow_id: format!("shadow:{strategy_id}"),
            shadow_passed: ready_for_governance,
            validation_status: if ready_for_governance {
                EvolutionValidationBundleStatus::ReadyForQueue
            } else {
                EvolutionValidationBundleStatus::Blocked
            },
            parent_queue_proposal_id: Some(format!("proposal:{strategy_id}")),
            parent_queue_review_state: Some(EvolutionProposalReviewState::AcceptedForCanary),
            selection_review_state: if ready_for_governance {
                EvolutionProposalReviewState::AcceptedForCanary
            } else {
                EvolutionProposalReviewState::Blocked
            },
            portfolio_review_state: if ready_for_governance {
                EvolutionPortfolioEntryReviewState::Included
            } else {
                EvolutionPortfolioEntryReviewState::Blocked
            },
            operator_reason: "prepare for governance-prep review".to_string(),
            ready_for_governance,
            blocking_reasons,
        }
    }

    fn sample_memory(
        strategy_id: &str,
        outcome_kind: StrategyMemoryOutcomeKind,
        observed_at_ms: i64,
    ) -> StrategyMemoryReport {
        let source_kind = match outcome_kind {
            StrategyMemoryOutcomeKind::StableInProduction => StrategyMemorySourceKind::Promotion,
            _ => StrategyMemorySourceKind::Canary,
        };
        StrategyMemoryReport {
            memory_id: format!("memory:{strategy_id}:{observed_at_ms}"),
            strategy_id: strategy_id.to_string(),
            strategy_description: format!("strategy {strategy_id}"),
            created_at_ms: observed_at_ms,
            observed_at_ms,
            source_kind,
            source_artifact_id: format!("artifact:{strategy_id}:{observed_at_ms}"),
            source_status: history_status_label(outcome_kind).to_string(),
            outcome_kind,
            suite_name: "hellcat-office-v1".to_string(),
            corpus_version: "v1".to_string(),
            reference_strategy_id: "office_baseline_control".to_string(),
            lineage: sample_lineage(strategy_id),
            rollout_stage_weight: 1.0,
            outcome_weight: 1.0,
            observed_events: 64,
            exclusive_detection_rate: 0.25,
            recovery_rate: 1.0,
            max_detect_latency_us: 32,
            total_detection_volume: 16,
            blocking_reasons: Vec::new(),
        }
    }

    fn history_status_label(value: StrategyMemoryOutcomeKind) -> &'static str {
        match value {
            StrategyMemoryOutcomeKind::ReadyForPromotionReview => "ready_for_promotion_review",
            StrategyMemoryOutcomeKind::StableInProduction => "stable_in_production",
            StrategyMemoryOutcomeKind::Blocked => "blocked",
            StrategyMemoryOutcomeKind::Halted => "halted",
        }
    }

    #[test]
    fn packet_set_merges_packets_and_split_preserves_parent_lineage() {
        let root = unique_temp_dir("governance-packet-set");
        let packet_dir = root.join("packets");
        let packet_set_dir = root.join("packet-sets");
        let strategy_memory_dir = root.join("strategy-memory");
        let history_dir = root.join("history");

        let packet_store = FileEvolutionGovernanceReviewPacketStore::open(&packet_dir).unwrap();
        packet_store
            .persist(&sample_packet(
                "packet:red:ready",
                "office_red_ready_v1",
                "red",
                true,
            ))
            .unwrap();
        packet_store
            .persist(&sample_packet(
                "packet:blue:blocked",
                "office_blue_blocked_v1",
                "blue",
                false,
            ))
            .unwrap();

        let harness = DefaultEvolutionGovernancePrepHarness::from_path(
            &packet_dir,
            &packet_set_dir,
            &strategy_memory_dir,
            &history_dir,
        )
        .unwrap();
        let merged = harness
            .create_packet_set(
                "office packet review set",
                "review ready and blocked governance packets together",
                vec![
                    "packet:red:ready".to_string(),
                    "packet:blue:blocked".to_string(),
                    "packet:red:ready".to_string(),
                ],
            )
            .unwrap();
        assert_eq!(merged.report.entries.len(), 2);
        assert_eq!(merged.record.ready_count, 1);
        assert_eq!(merged.record.blocked_count, 1);

        let split = harness
            .split_packet_set(
                &merged.report.packet_set_id,
                "office red subset",
                "focus only on the red cohort packet",
                vec!["packet:red:ready".to_string()],
            )
            .unwrap();

        assert_eq!(
            split.report.parent_packet_set_id.as_deref(),
            Some(merged.report.packet_set_id.as_str())
        );
        assert_eq!(split.report.entries.len(), 1);
        assert!(split.report.entries[0].source_packet_set_entry_id.is_some());

        let list = harness.list_packet_sets(Some("red")).unwrap();
        assert_eq!(list.total_count, 2);
        assert!(
            render_evolution_governance_packet_set(&split.report)
                .contains("Evolution Governance Packet Set")
        );
        assert!(
            render_evolution_governance_packet_set_list(&list)
                .contains("Evolution Governance Packet Sets")
        );
    }

    #[test]
    fn portfolio_history_tracks_outcomes_and_review_debt() {
        let root = unique_temp_dir("portfolio-history");
        let packet_dir = root.join("packets");
        let packet_set_dir = root.join("packet-sets");
        let strategy_memory_dir = root.join("strategy-memory");
        let history_dir = root.join("history");

        let packet_store = FileEvolutionGovernanceReviewPacketStore::open(&packet_dir).unwrap();
        let packets = vec![
            sample_packet("packet:red:stable", "office_red_stable_v1", "red", true),
            sample_packet("packet:red:ready", "office_red_ready_v1", "red", true),
            sample_packet(
                "packet:blue:pending",
                "office_blue_pending_v1",
                "blue",
                true,
            ),
            sample_packet(
                "packet:blue:blocked",
                "office_blue_blocked_v1",
                "blue",
                false,
            ),
        ];
        for packet in packets {
            packet_store.persist(&packet).unwrap();
        }

        let memory_store = FileStrategyMemoryStore::open(&strategy_memory_dir).unwrap();
        memory_store
            .persist(&sample_memory(
                "office_red_stable_v1",
                StrategyMemoryOutcomeKind::StableInProduction,
                1_710_000_000_100,
            ))
            .unwrap();
        memory_store
            .persist(&sample_memory(
                "office_red_ready_v1",
                StrategyMemoryOutcomeKind::ReadyForPromotionReview,
                1_710_000_000_200,
            ))
            .unwrap();
        memory_store
            .persist(&sample_memory(
                "office_blue_blocked_v1",
                StrategyMemoryOutcomeKind::Blocked,
                1_710_000_000_300,
            ))
            .unwrap();

        let harness = DefaultEvolutionGovernancePrepHarness::from_path(
            &packet_dir,
            &packet_set_dir,
            &strategy_memory_dir,
            &history_dir,
        )
        .unwrap();
        let packet_set = harness
            .create_packet_set(
                "office outcome cohort set",
                "track live outcomes across red and blue cohorts",
                vec![
                    "packet:red:stable".to_string(),
                    "packet:red:ready".to_string(),
                    "packet:blue:pending".to_string(),
                    "packet:blue:blocked".to_string(),
                ],
            )
            .unwrap();
        let history = harness
            .create_portfolio_history(&packet_set.report.packet_set_id)
            .unwrap();

        assert_eq!(history.report.outcomes.entry_count, 4);
        assert_eq!(history.report.outcomes.survived_count, 2);
        assert_eq!(history.report.outcomes.stable_count, 1);
        assert_eq!(history.report.outcomes.ready_for_promotion_review_count, 1);
        assert_eq!(history.report.outcomes.blocked_count, 1);
        assert_eq!(history.report.outcomes.unobserved_count, 1);
        assert_eq!(history.report.outcomes.review_debt_count, 2);

        let pending = history
            .report
            .entries
            .iter()
            .find(|entry| entry.packet_id == "packet:blue:pending")
            .unwrap();
        assert_eq!(
            pending.outcome,
            EvolutionPortfolioHistoryOutcomeKind::NoObservedRollout
        );
        assert_eq!(
            pending.review_debt,
            Some(EvolutionPortfolioHistoryReviewDebtKind::PendingGovernanceFollowUp)
        );

        let ready = history
            .report
            .entries
            .iter()
            .find(|entry| entry.packet_id == "packet:red:ready")
            .unwrap();
        assert_eq!(
            ready.outcome,
            EvolutionPortfolioHistoryOutcomeKind::ReadyForPromotionReview
        );
        assert_eq!(
            ready.review_debt,
            Some(EvolutionPortfolioHistoryReviewDebtKind::AwaitingStableOutcome)
        );

        let list = harness.list_portfolio_history(Some("red")).unwrap();
        assert_eq!(list.total_count, 1);
        assert!(
            render_evolution_portfolio_history(&history.report)
                .contains("Evolution Portfolio History")
        );
        assert!(
            render_evolution_portfolio_history_list(&list)
                .contains("Evolution Portfolio Histories")
        );
    }

    #[test]
    fn portfolio_history_fails_closed_on_inconsistent_ready_packet() {
        let root = unique_temp_dir("portfolio-history-inconsistent");
        let packet_dir = root.join("packets");
        let packet_set_dir = root.join("packet-sets");
        let strategy_memory_dir = root.join("strategy-memory");
        let history_dir = root.join("history");

        let packet_store = FileEvolutionGovernanceReviewPacketStore::open(&packet_dir).unwrap();
        let mut packet =
            sample_packet("packet:inconsistent", "office_inconsistent_v1", "red", true);
        packet
            .blocking_reasons
            .push(EvolutionProposalBlockingReason {
                source: "manual".to_string(),
                name: "inconsistent_block".to_string(),
                details: "corrupted packet ready state".to_string(),
                references: vec![packet.packet_id.clone()],
            });
        packet_store.persist(&packet).unwrap();

        let harness = DefaultEvolutionGovernancePrepHarness::from_path(
            &packet_dir,
            &packet_set_dir,
            &strategy_memory_dir,
            &history_dir,
        )
        .unwrap();
        let packet_set = harness
            .create_packet_set(
                "broken packet set",
                "show that history creation fails closed on inconsistent ready packets",
                vec!["packet:inconsistent".to_string()],
            )
            .unwrap();
        let error = harness
            .create_portfolio_history(&packet_set.report.packet_set_id)
            .unwrap_err();

        assert!(matches!(
            error,
            EvolutionGovernancePrepError::InconsistentPacketEvidence { .. }
        ));
    }
}
