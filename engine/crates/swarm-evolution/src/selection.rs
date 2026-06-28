use crate::drafting::{
    EvolutionValidationBundleStatus, EvolutionValidationBundleStoreError,
    FileEvolutionValidationBundleStore,
};
use crate::evolution::{
    EvolutionProposalAdvisorySummary, EvolutionProposalBlockingReason,
    EvolutionProposalDecisionAction, EvolutionProposalDecisionRecord, EvolutionProposalProofStatus,
    EvolutionProposalProofSummary, EvolutionProposalReport, EvolutionProposalReviewState,
    EvolutionProposalStoreError, FileEvolutionProposalStore,
};
use crate::mutation::{EvolutionMutationRankingStoreError, FileEvolutionMutationRankingStore};
use crate::replay::{ExperimentLineage, ReplayHarnessError, load_detector_experiment_manifest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Errors surfaced by the ranked-candidate selection workflow.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionSelectionError {
    #[error(transparent)]
    RankingStore(#[from] EvolutionMutationRankingStoreError),

    #[error(transparent)]
    ValidationStore(#[from] EvolutionValidationBundleStoreError),

    #[error(transparent)]
    ProposalStore(#[from] EvolutionProposalStoreError),

    #[error(transparent)]
    SelectionStore(#[from] EvolutionSelectionStoreError),

    #[error(transparent)]
    BridgeStore(#[from] EvolutionSelectionBridgeStoreError),

    #[error(transparent)]
    Replay(#[from] ReplayHarnessError),

    #[error(transparent)]
    Serialization(#[from] serde_json::Error),

    #[error("candidate ranking `{ranking_id}` was not found")]
    RankingNotFound { ranking_id: String },

    #[error("review packet `{packet_id}` was not found in ranking `{ranking_id}`")]
    ReviewPacketNotFound {
        ranking_id: String,
        packet_id: String,
    },

    #[error("validation bundle `{validation_bundle_id}` was not found")]
    ValidationBundleNotFound { validation_bundle_id: String },

    #[error("ranked-candidate selection `{selection_id}` was not found")]
    SelectionNotFound { selection_id: String },

    #[error("selection bridge `{bridge_id}` was not found")]
    BridgeNotFound { bridge_id: String },

    #[error(
        "selection `{selection_id}` cannot apply decision `{decision}` from state `{state}`: {reason}"
    )]
    InvalidDecision {
        selection_id: String,
        state: String,
        decision: String,
        reason: String,
    },
}

/// Durable ranked-candidate selection assembled from one shortlist review packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionRankedCandidateSelectionReport {
    pub selection_id: String,
    pub ranking_id: String,
    pub packet_id: String,
    pub created_at_ms: i64,
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
    pub review_state: EvolutionProposalReviewState,
    pub blocking_reasons: Vec<EvolutionProposalBlockingReason>,
    pub decision_history: Vec<EvolutionProposalDecisionRecord>,
}

/// Metadata surfaced for one persisted ranked-candidate selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionRankedCandidateSelectionRecord {
    pub selection_id: String,
    pub ranking_id: String,
    pub strategy_id: String,
    pub review_state: EvolutionProposalReviewState,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl EvolutionRankedCandidateSelectionRecord {
    fn from_report(report: &EvolutionRankedCandidateSelectionReport, bundle_path: String) -> Self {
        Self {
            selection_id: report.selection_id.clone(),
            ranking_id: report.ranking_id.clone(),
            strategy_id: report.strategy_id.clone(),
            review_state: report.review_state,
            created_at_ms: report.created_at_ms,
            bundle_path,
        }
    }
}

/// Persisted ranked-candidate selection loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionRankedCandidateSelectionLookup {
    pub record: EvolutionRankedCandidateSelectionRecord,
    pub report: EvolutionRankedCandidateSelectionReport,
}

/// Operator-facing selection listing with stable-ID filters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionRankedCandidateSelectionList {
    pub total_count: usize,
    pub strategy_id: Option<String>,
    pub review_state: Option<EvolutionProposalReviewState>,
    pub selections: Vec<EvolutionRankedCandidateSelectionRecord>,
}

/// Durable bridge artifact that feeds one accepted selection back into the queue/handoff lane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionRankedCandidateBridgeReport {
    pub bridge_id: String,
    pub selection_id: String,
    pub ranking_id: String,
    pub packet_id: String,
    pub created_at_ms: i64,
    pub strategy_id: String,
    pub experiment_id: String,
    pub experiment_name: String,
    pub experiment_path: String,
    pub validation_bundle_id: String,
    pub queue_proposal_id: Option<String>,
    pub resulting_review_state: EvolutionProposalReviewState,
    pub verification_id: String,
    pub proof_id: Option<String>,
    pub proof_status: EvolutionProposalProofStatus,
    pub shadow_id: String,
    pub advisory_scorecard_id: Option<String>,
    pub handoff_ready: bool,
    pub operator_reason: String,
    pub blocking_reasons: Vec<EvolutionProposalBlockingReason>,
}

/// Metadata surfaced for one persisted ranked-candidate bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionRankedCandidateBridgeRecord {
    pub bridge_id: String,
    pub selection_id: String,
    pub strategy_id: String,
    pub created_at_ms: i64,
    pub queue_proposal_id: Option<String>,
    pub resulting_review_state: EvolutionProposalReviewState,
    pub handoff_ready: bool,
    pub bundle_path: String,
}

impl EvolutionRankedCandidateBridgeRecord {
    fn from_report(report: &EvolutionRankedCandidateBridgeReport, bundle_path: String) -> Self {
        Self {
            bridge_id: report.bridge_id.clone(),
            selection_id: report.selection_id.clone(),
            strategy_id: report.strategy_id.clone(),
            created_at_ms: report.created_at_ms,
            queue_proposal_id: report.queue_proposal_id.clone(),
            resulting_review_state: report.resulting_review_state,
            handoff_ready: report.handoff_ready,
            bundle_path,
        }
    }
}

/// Persisted ranked-candidate bridge loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionRankedCandidateBridgeLookup {
    pub record: EvolutionRankedCandidateBridgeRecord,
    pub report: EvolutionRankedCandidateBridgeReport,
}

/// Errors raised by the persisted ranked-candidate selection store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionSelectionStoreError {
    #[error("failed to read ranked-candidate selection store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write ranked-candidate selection store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse ranked-candidate selection store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised by the persisted ranked-candidate bridge store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionSelectionBridgeStoreError {
    #[error("failed to read ranked-candidate bridge store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write ranked-candidate bridge store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse ranked-candidate bridge store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// File-backed store for ranked-candidate selections.
#[derive(Debug, Clone)]
pub struct FileEvolutionSelectionStore {
    root: PathBuf,
}

impl FileEvolutionSelectionStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionSelectionStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionSelectionStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, selection_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(selection_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<EvolutionSelectionIndex, EvolutionSelectionStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionSelectionIndex::default());
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| EvolutionSelectionStoreError::Read {
                path: path.clone(),
                source,
            })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionSelectionStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionSelectionIndex,
    ) -> Result<(), EvolutionSelectionStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionSelectionStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionSelectionStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionRankedCandidateSelectionReport,
    ) -> Result<EvolutionRankedCandidateSelectionRecord, EvolutionSelectionStoreError> {
        let path = self.report_path(&report.selection_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionSelectionStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionSelectionStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = EvolutionRankedCandidateSelectionRecord::from_report(
            report,
            path.display().to_string(),
        );
        index
            .entries
            .retain(|entry| entry.selection_id != record.selection_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        selection_id: &str,
    ) -> Result<Option<EvolutionRankedCandidateSelectionLookup>, EvolutionSelectionStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.selection_id == selection_id)
            .cloned()
        else {
            return Ok(None);
        };

        let path = PathBuf::from(&record.bundle_path);
        let raw =
            fs::read_to_string(&path).map_err(|source| EvolutionSelectionStoreError::Read {
                path: path.clone(),
                source,
            })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionSelectionStoreError::Parse { path, source })?;
        Ok(Some(EvolutionRankedCandidateSelectionLookup {
            record,
            report,
        }))
    }

    pub fn list(
        &self,
        strategy_id: Option<&str>,
        review_state: Option<EvolutionProposalReviewState>,
    ) -> Result<EvolutionRankedCandidateSelectionList, EvolutionSelectionStoreError> {
        let index = self.read_index()?;
        let selections = index
            .entries
            .into_iter()
            .filter(|entry| {
                strategy_id
                    .map(|expected| entry.strategy_id == expected)
                    .unwrap_or(true)
            })
            .filter(|entry| {
                review_state
                    .map(|expected| entry.review_state == expected)
                    .unwrap_or(true)
            })
            .collect::<Vec<_>>();
        Ok(EvolutionRankedCandidateSelectionList {
            total_count: selections.len(),
            strategy_id: strategy_id.map(ToOwned::to_owned),
            review_state,
            selections,
        })
    }
}

/// File-backed store for ranked-candidate bridges.
#[derive(Debug, Clone)]
pub struct FileEvolutionSelectionBridgeStore {
    root: PathBuf,
}

impl FileEvolutionSelectionBridgeStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionSelectionBridgeStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionSelectionBridgeStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, bridge_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(bridge_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(
        &self,
    ) -> Result<EvolutionSelectionBridgeIndex, EvolutionSelectionBridgeStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionSelectionBridgeIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionSelectionBridgeStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionSelectionBridgeStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionSelectionBridgeIndex,
    ) -> Result<(), EvolutionSelectionBridgeStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionSelectionBridgeStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| EvolutionSelectionBridgeStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionRankedCandidateBridgeReport,
    ) -> Result<EvolutionRankedCandidateBridgeRecord, EvolutionSelectionBridgeStoreError> {
        let path = self.report_path(&report.bridge_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionSelectionBridgeStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionSelectionBridgeStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record =
            EvolutionRankedCandidateBridgeRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.bridge_id != record.bridge_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        bridge_id: &str,
    ) -> Result<Option<EvolutionRankedCandidateBridgeLookup>, EvolutionSelectionBridgeStoreError>
    {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.bridge_id == bridge_id)
            .cloned()
        else {
            return Ok(None);
        };

        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionSelectionBridgeStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionSelectionBridgeStoreError::Parse { path, source })?;
        Ok(Some(EvolutionRankedCandidateBridgeLookup {
            record,
            report,
        }))
    }

    pub fn load_latest_for_selection(
        &self,
        selection_id: &str,
    ) -> Result<Option<EvolutionRankedCandidateBridgeLookup>, EvolutionSelectionBridgeStoreError>
    {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.selection_id == selection_id)
            .cloned()
        else {
            return Ok(None);
        };

        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionSelectionBridgeStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionSelectionBridgeStoreError::Parse { path, source })?;
        Ok(Some(EvolutionRankedCandidateBridgeLookup {
            record,
            report,
        }))
    }
}

/// Harness for ranked-candidate selection, review, and rollout bridging.
#[derive(Debug, Clone)]
pub struct DefaultEvolutionSelectionHarness {
    pub ranking_store: FileEvolutionMutationRankingStore,
    pub validation_store: FileEvolutionValidationBundleStore,
    pub selection_store: FileEvolutionSelectionStore,
    pub bridge_store: FileEvolutionSelectionBridgeStore,
}

impl DefaultEvolutionSelectionHarness {
    pub fn from_path(
        ranking_results_dir: impl AsRef<Path>,
        validation_results_dir: impl AsRef<Path>,
        selection_results_dir: impl AsRef<Path>,
        bridge_results_dir: impl AsRef<Path>,
    ) -> Result<Self, EvolutionSelectionError> {
        Ok(Self {
            ranking_store: FileEvolutionMutationRankingStore::open(ranking_results_dir)?,
            validation_store: FileEvolutionValidationBundleStore::open(validation_results_dir)?,
            selection_store: FileEvolutionSelectionStore::open(selection_results_dir)?,
            bridge_store: FileEvolutionSelectionBridgeStore::open(bridge_results_dir)?,
        })
    }

    pub fn create_selection(
        &self,
        ranking_id: &str,
        packet_id: &str,
    ) -> Result<EvolutionRankedCandidateSelectionLookup, EvolutionSelectionError> {
        let ranking = self.ranking_store.load(ranking_id)?.ok_or_else(|| {
            EvolutionSelectionError::RankingNotFound {
                ranking_id: ranking_id.to_string(),
            }
        })?;
        let packet = ranking
            .report
            .review_packets
            .iter()
            .find(|packet| packet.packet_id == packet_id)
            .cloned()
            .ok_or_else(|| EvolutionSelectionError::ReviewPacketNotFound {
                ranking_id: ranking_id.to_string(),
                packet_id: packet_id.to_string(),
            })?;
        let ranked_candidate = ranking.report.ranked_candidates.iter().find(|candidate| {
            candidate.rank == packet.rank
                && candidate.variant_id == packet.variant_id
                && candidate.materialization_id == packet.materialization_id
                && candidate.validation_bundle_id == packet.validation_bundle_id
        });
        let validation = self
            .validation_store
            .load(&packet.validation_bundle_id)?
            .ok_or_else(|| EvolutionSelectionError::ValidationBundleNotFound {
                validation_bundle_id: packet.validation_bundle_id.clone(),
            })?;

        let created_at_ms = now_ms();
        let mut blocking_reasons = validation.report.blocking_reasons.clone();
        match ranked_candidate {
            Some(candidate) if !candidate.ready_for_review => {
                blocking_reasons.push(EvolutionProposalBlockingReason {
                    source: "ranking".to_string(),
                    name: "review_packet_not_ready".to_string(),
                    details: format!(
                        "ranking packet `{}` is not ready for review and cannot enter the selection lane cleanly",
                        packet.packet_id
                    ),
                    references: vec![packet.packet_id.clone(), ranking.report.ranking_id.clone()],
                });
            }
            None => {
                blocking_reasons.push(EvolutionProposalBlockingReason {
                    source: "ranking".to_string(),
                    name: "ranking_entry_missing".to_string(),
                    details: format!(
                        "ranking packet `{}` no longer maps to a ranked candidate entry in ranking `{}`",
                        packet.packet_id, ranking.report.ranking_id
                    ),
                    references: vec![packet.packet_id.clone(), ranking.report.ranking_id.clone()],
                });
            }
            Some(_) => {}
        }
        if packet.strategy_id != validation.report.strategy_id {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "selection".to_string(),
                name: "strategy_mismatch".to_string(),
                details: format!(
                    "ranking packet strategy `{}` does not match validation strategy `{}`",
                    packet.strategy_id, validation.report.strategy_id
                ),
                references: vec![
                    packet.packet_id.clone(),
                    validation.report.validation_bundle_id.clone(),
                ],
            });
        }
        if packet.materialization_id != validation.report.materialization_id {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "selection".to_string(),
                name: "materialization_mismatch".to_string(),
                details: format!(
                    "ranking packet materialization `{}` does not match validation materialization `{}`",
                    packet.materialization_id, validation.report.materialization_id
                ),
                references: vec![
                    packet.packet_id.clone(),
                    validation.report.validation_bundle_id.clone(),
                ],
            });
        }
        if validation.report.status != EvolutionValidationBundleStatus::ReadyForQueue {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "selection".to_string(),
                name: "validation_not_ready_for_queue".to_string(),
                details: format!(
                    "validation bundle `{}` is in status `{}` instead of `ready_for_queue`",
                    validation.report.validation_bundle_id,
                    validation_status_label(validation.report.status)
                ),
                references: vec![validation.report.validation_bundle_id.clone()],
            });
        }
        if !validation.report.verification_passed {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "selection".to_string(),
                name: "verification_not_passed".to_string(),
                details: "selection still references a non-passing verification result".to_string(),
                references: vec![validation.report.validation_bundle_id.clone()],
            });
        }
        if validation.report.proof_status != EvolutionProposalProofStatus::Proved {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "selection".to_string(),
                name: "proof_not_proved".to_string(),
                details: "selection still references a non-proved proof artifact".to_string(),
                references: vec![validation.report.validation_bundle_id.clone()],
            });
        }
        if !validation.report.shadow_passed {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "selection".to_string(),
                name: "shadow_not_passed".to_string(),
                details: "selection still references a non-passing shadow artifact".to_string(),
                references: vec![validation.report.shadow_id.clone()],
            });
        }

        let report = EvolutionRankedCandidateSelectionReport {
            selection_id: selection_id(
                &ranking.report.ranking_id,
                &packet.packet_id,
                created_at_ms,
            ),
            ranking_id: ranking.report.ranking_id.clone(),
            packet_id: packet.packet_id.clone(),
            created_at_ms,
            rank: packet.rank,
            strategy_id: packet.strategy_id.clone(),
            strategy_description: validation.report.strategy_description.clone(),
            score: packet.score,
            summary: packet.summary.clone(),
            materialization_id: packet.materialization_id.clone(),
            validation_bundle_id: packet.validation_bundle_id.clone(),
            experiment_id: validation.report.experiment_id.clone(),
            experiment_name: validation.report.experiment_name.clone(),
            experiment_path: validation.report.experiment_path.clone(),
            lineage: validation.report.lineage.clone(),
            manifest_sha256: validation.report.manifest_sha256.clone(),
            lineage_sha256: validation.report.lineage_sha256.clone(),
            verification_id: validation.report.verification_id.clone(),
            verification_passed: validation.report.verification_passed,
            proof_status: validation.report.proof_status,
            proof: validation.report.proof.clone(),
            advisory: validation.report.advisory.clone(),
            shadow_id: validation.report.shadow_id.clone(),
            shadow_passed: validation.report.shadow_passed,
            validation_status: validation.report.status,
            parent_queue_proposal_id: packet.queue_proposal_id.clone(),
            parent_queue_review_state: packet.queue_review_state,
            review_state: if blocking_reasons.is_empty() {
                EvolutionProposalReviewState::PendingReview
            } else {
                EvolutionProposalReviewState::Blocked
            },
            blocking_reasons,
            decision_history: Vec::new(),
        };
        let record = self.selection_store.persist(&report)?;
        Ok(EvolutionRankedCandidateSelectionLookup { record, report })
    }

    pub fn load_selection(
        &self,
        selection_id: &str,
    ) -> Result<Option<EvolutionRankedCandidateSelectionLookup>, EvolutionSelectionError> {
        Ok(self.selection_store.load(selection_id)?)
    }

    pub fn list_selections(
        &self,
        strategy_id: Option<&str>,
        review_state: Option<EvolutionProposalReviewState>,
    ) -> Result<EvolutionRankedCandidateSelectionList, EvolutionSelectionError> {
        Ok(self.selection_store.list(strategy_id, review_state)?)
    }

    pub fn record_decision(
        &self,
        selection_id: &str,
        action: EvolutionProposalDecisionAction,
        reason: &str,
    ) -> Result<EvolutionRankedCandidateSelectionLookup, EvolutionSelectionError> {
        if action == EvolutionProposalDecisionAction::ApplyAssuranceWaiver {
            return Err(EvolutionSelectionError::InvalidDecision {
                selection_id: selection_id.to_string(),
                state: "n/a".to_string(),
                decision: decision_action_label(action).to_string(),
                reason:
                    "selection reviews do not accept assurance waivers; attach them on the queue proposal instead"
                        .to_string(),
            });
        }
        let mut lookup = self.selection_store.load(selection_id)?.ok_or_else(|| {
            EvolutionSelectionError::SelectionNotFound {
                selection_id: selection_id.to_string(),
            }
        })?;

        let new_state = match (lookup.report.review_state, action) {
            (
                EvolutionProposalReviewState::PendingReview,
                EvolutionProposalDecisionAction::ApplyAssuranceWaiver,
            )
            | (
                EvolutionProposalReviewState::Deferred,
                EvolutionProposalDecisionAction::ApplyAssuranceWaiver,
            )
            | (
                EvolutionProposalReviewState::Blocked,
                EvolutionProposalDecisionAction::ApplyAssuranceWaiver,
            )
            | (
                EvolutionProposalReviewState::AcceptedForCanary,
                EvolutionProposalDecisionAction::ApplyAssuranceWaiver,
            )
            | (
                EvolutionProposalReviewState::Rejected,
                EvolutionProposalDecisionAction::ApplyAssuranceWaiver,
            ) => unreachable!(
                "selection waiver decisions are rejected before state transition matching"
            ),
            (
                EvolutionProposalReviewState::PendingReview,
                EvolutionProposalDecisionAction::AcceptForCanary,
            )
            | (
                EvolutionProposalReviewState::Deferred,
                EvolutionProposalDecisionAction::AcceptForCanary,
            ) => {
                if lookup.report.proof_status != EvolutionProposalProofStatus::Proved
                    || !lookup.report.blocking_reasons.is_empty()
                    || !lookup.report.verification_passed
                    || !lookup.report.shadow_passed
                    || lookup.report.validation_status
                        != EvolutionValidationBundleStatus::ReadyForQueue
                {
                    return Err(EvolutionSelectionError::InvalidDecision {
                        selection_id: selection_id.to_string(),
                        state: review_state_label(lookup.report.review_state).to_string(),
                        decision: decision_action_label(action).to_string(),
                        reason: "only proved, unblocked, queue-ready selections can be accepted for canary"
                            .to_string(),
                    });
                }
                EvolutionProposalReviewState::AcceptedForCanary
            }
            (
                EvolutionProposalReviewState::PendingReview,
                EvolutionProposalDecisionAction::Defer,
            )
            | (EvolutionProposalReviewState::Deferred, EvolutionProposalDecisionAction::Defer) => {
                EvolutionProposalReviewState::Deferred
            }
            (
                EvolutionProposalReviewState::PendingReview,
                EvolutionProposalDecisionAction::Reject,
            )
            | (EvolutionProposalReviewState::Deferred, EvolutionProposalDecisionAction::Reject)
            | (EvolutionProposalReviewState::Blocked, EvolutionProposalDecisionAction::Reject) => {
                EvolutionProposalReviewState::Rejected
            }
            (EvolutionProposalReviewState::Blocked, _) => {
                return Err(EvolutionSelectionError::InvalidDecision {
                    selection_id: selection_id.to_string(),
                    state: review_state_label(lookup.report.review_state).to_string(),
                    decision: decision_action_label(action).to_string(),
                    reason: "blocked selections may only be explicitly rejected".to_string(),
                });
            }
            (EvolutionProposalReviewState::AcceptedForCanary, _)
            | (EvolutionProposalReviewState::Rejected, _) => {
                return Err(EvolutionSelectionError::InvalidDecision {
                    selection_id: selection_id.to_string(),
                    state: review_state_label(lookup.report.review_state).to_string(),
                    decision: decision_action_label(action).to_string(),
                    reason: "the selection is already in a terminal review state".to_string(),
                });
            }
        };

        lookup.report.review_state = new_state;
        lookup
            .report
            .decision_history
            .push(EvolutionProposalDecisionRecord {
                decided_at_ms: now_ms(),
                action,
                reason: reason.to_string(),
            });
        let record = self.selection_store.persist(&lookup.report)?;
        Ok(EvolutionRankedCandidateSelectionLookup {
            record,
            report: lookup.report,
        })
    }

    pub fn bridge_selection(
        &self,
        queue_results_dir: impl AsRef<Path>,
        selection_id: &str,
        reason: &str,
    ) -> Result<EvolutionRankedCandidateBridgeLookup, EvolutionSelectionError> {
        let selection = self.selection_store.load(selection_id)?.ok_or_else(|| {
            EvolutionSelectionError::SelectionNotFound {
                selection_id: selection_id.to_string(),
            }
        })?;
        if let Some(existing) = self.bridge_store.load_latest_for_selection(selection_id)?
            && existing.report.queue_proposal_id.is_some()
            && existing.report.blocking_reasons.is_empty()
        {
            return Ok(existing);
        }

        let mut blocking_reasons = Vec::new();
        if selection.report.review_state != EvolutionProposalReviewState::AcceptedForCanary {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "selection".to_string(),
                name: "selection_not_accepted_for_canary".to_string(),
                details: format!(
                    "selection `{}` is in state `{}` instead of `accepted_for_canary`",
                    selection.report.selection_id,
                    review_state_label(selection.report.review_state)
                ),
                references: vec![selection.report.selection_id.clone()],
            });
        }
        if !selection.report.blocking_reasons.is_empty() {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "selection".to_string(),
                name: "selection_already_blocked".to_string(),
                details: "selection still carries blocking reasons and cannot bridge cleanly"
                    .to_string(),
                references: vec![selection.report.selection_id.clone()],
            });
        }
        if selection.report.validation_status != EvolutionValidationBundleStatus::ReadyForQueue {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "selection".to_string(),
                name: "validation_not_ready_for_queue".to_string(),
                details: format!(
                    "selection validation status is `{}` instead of `ready_for_queue`",
                    validation_status_label(selection.report.validation_status)
                ),
                references: vec![selection.report.validation_bundle_id.clone()],
            });
        }
        if !selection.report.verification_passed {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "selection".to_string(),
                name: "verification_not_passed".to_string(),
                details: "selection still references a non-passing verification result".to_string(),
                references: vec![selection.report.verification_id.clone()],
            });
        }
        if selection.report.proof_status != EvolutionProposalProofStatus::Proved {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "selection".to_string(),
                name: "proof_not_proved".to_string(),
                details: "selection still references a non-proved proof artifact".to_string(),
                references: vec![selection.report.selection_id.clone()],
            });
        }
        if !selection.report.shadow_passed {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "selection".to_string(),
                name: "shadow_not_passed".to_string(),
                details: "selection still references a non-passing shadow artifact".to_string(),
                references: vec![selection.report.shadow_id.clone()],
            });
        }
        if selection.report.experiment_path.trim().is_empty() {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "selection".to_string(),
                name: "missing_experiment_path".to_string(),
                details: "selection does not preserve an experiment manifest path".to_string(),
                references: vec![selection.report.selection_id.clone()],
            });
        }

        if blocking_reasons.is_empty() {
            match load_detector_experiment_manifest(PathBuf::from(
                &selection.report.experiment_path,
            )) {
                Ok(manifest) => {
                    let current_manifest_sha256 = sha256_hex(&manifest)?;
                    let current_lineage_sha256 = sha256_hex(&manifest.lineage)?;
                    if experiment_id_for_manifest(&manifest) != selection.report.experiment_id {
                        blocking_reasons.push(EvolutionProposalBlockingReason {
                            source: "bridge".to_string(),
                            name: "experiment_id_drift".to_string(),
                            details: format!(
                                "current experiment id `{}` no longer matches selection experiment `{}`",
                                experiment_id_for_manifest(&manifest),
                                selection.report.experiment_id
                            ),
                            references: vec![selection.report.selection_id.clone()],
                        });
                    }
                    if manifest.candidate.strategy_id() != selection.report.strategy_id {
                        blocking_reasons.push(EvolutionProposalBlockingReason {
                            source: "bridge".to_string(),
                            name: "strategy_drift".to_string(),
                            details: format!(
                                "current experiment strategy `{}` no longer matches selection strategy `{}`",
                                manifest.candidate.strategy_id(),
                                selection.report.strategy_id
                            ),
                            references: vec![selection.report.selection_id.clone()],
                        });
                    }
                    if current_manifest_sha256 != selection.report.manifest_sha256 {
                        blocking_reasons.push(EvolutionProposalBlockingReason {
                            source: "bridge".to_string(),
                            name: "manifest_digest_drift".to_string(),
                            details: "current experiment manifest digest no longer matches the selected validation bundle"
                                .to_string(),
                            references: vec![selection.report.selection_id.clone()],
                        });
                    }
                    if current_lineage_sha256 != selection.report.lineage_sha256 {
                        blocking_reasons.push(EvolutionProposalBlockingReason {
                            source: "bridge".to_string(),
                            name: "lineage_digest_drift".to_string(),
                            details: "current experiment lineage digest no longer matches the selected validation bundle"
                                .to_string(),
                            references: vec![selection.report.selection_id.clone()],
                        });
                    }
                }
                Err(error) => blocking_reasons.push(EvolutionProposalBlockingReason {
                    source: "bridge".to_string(),
                    name: "experiment_manifest_unreadable".to_string(),
                    details: error.to_string(),
                    references: vec![selection.report.experiment_path.clone()],
                }),
            }
        }

        let created_at_ms = now_ms();
        let mut queue_proposal_id = None;
        let resulting_review_state = if blocking_reasons.is_empty() {
            let proposal_report = EvolutionProposalReport {
                proposal_id: queue_proposal_id_for_selection(
                    &selection.report.experiment_name,
                    &selection.report.strategy_id,
                    created_at_ms,
                ),
                experiment_id: selection.report.experiment_id.clone(),
                experiment_name: selection.report.experiment_name.clone(),
                experiment_path: selection.report.experiment_path.clone(),
                created_at_ms,
                strategy_id: selection.report.strategy_id.clone(),
                strategy_description: selection.report.strategy_description.clone(),
                lineage: selection.report.lineage.clone(),
                verification_id: Some(selection.report.verification_id.clone()),
                verification_passed: selection.report.verification_passed,
                proof_status: selection.report.proof_status,
                proof: selection.report.proof.clone(),
                advisory: selection.report.advisory.clone(),
                assurance: None,
                review_state: EvolutionProposalReviewState::AcceptedForCanary,
                blocking_reasons: Vec::new(),
                decision_history: vec![EvolutionProposalDecisionRecord {
                    decided_at_ms: created_at_ms,
                    action: EvolutionProposalDecisionAction::AcceptForCanary,
                    reason: reason.to_string(),
                }],
            };
            let queue_store = FileEvolutionProposalStore::open(queue_results_dir)?;
            let record = queue_store.persist(&proposal_report)?;
            queue_proposal_id = Some(record.proposal_id.clone());
            EvolutionProposalReviewState::AcceptedForCanary
        } else {
            EvolutionProposalReviewState::Blocked
        };

        let report = EvolutionRankedCandidateBridgeReport {
            bridge_id: bridge_id(&selection.report.selection_id, created_at_ms),
            selection_id: selection.report.selection_id.clone(),
            ranking_id: selection.report.ranking_id.clone(),
            packet_id: selection.report.packet_id.clone(),
            created_at_ms,
            strategy_id: selection.report.strategy_id.clone(),
            experiment_id: selection.report.experiment_id.clone(),
            experiment_name: selection.report.experiment_name.clone(),
            experiment_path: selection.report.experiment_path.clone(),
            validation_bundle_id: selection.report.validation_bundle_id.clone(),
            queue_proposal_id,
            resulting_review_state,
            verification_id: selection.report.verification_id.clone(),
            proof_id: selection
                .report
                .proof
                .as_ref()
                .map(|proof| proof.proof_id.clone()),
            proof_status: selection.report.proof_status,
            shadow_id: selection.report.shadow_id.clone(),
            advisory_scorecard_id: selection
                .report
                .advisory
                .as_ref()
                .map(|advisory| advisory.scorecard_id.clone()),
            handoff_ready: blocking_reasons.is_empty()
                && selection.report.proof_status == EvolutionProposalProofStatus::Proved
                && selection.report.verification_passed
                && selection.report.shadow_passed
                && selection.report.validation_status
                    == EvolutionValidationBundleStatus::ReadyForQueue,
            operator_reason: reason.to_string(),
            blocking_reasons,
        };
        let record = self.bridge_store.persist(&report)?;
        Ok(EvolutionRankedCandidateBridgeLookup { record, report })
    }

    pub fn load_bridge(
        &self,
        bridge_id: &str,
    ) -> Result<Option<EvolutionRankedCandidateBridgeLookup>, EvolutionSelectionError> {
        Ok(self.bridge_store.load(bridge_id)?)
    }
}

/// Render one ranked-candidate selection artifact.
pub fn render_evolution_ranked_candidate_selection(
    report: &EvolutionRankedCandidateSelectionReport,
) -> String {
    let mut lines = vec![
        "Evolution Ranked Candidate Selection".to_string(),
        format!("Selection ID: {}", report.selection_id),
        format!(
            "Ranking ID: {} | Packet: {}",
            report.ranking_id, report.packet_id
        ),
        format!(
            "Rank: {} | Strategy: {} | score={:.3}",
            report.rank, report.strategy_id, report.score
        ),
        format!(
            "Review state: {} | validation={} | proof={}",
            review_state_label(report.review_state),
            validation_status_label(report.validation_status),
            proof_status_label(report.proof_status)
        ),
        format!(
            "Experiment: {} ({})",
            report.experiment_name, report.experiment_id
        ),
        format!(
            "Materialization: {} | Validation: {} | Shadow: {} (passed={})",
            report.materialization_id,
            report.validation_bundle_id,
            report.shadow_id,
            report.shadow_passed
        ),
        format!(
            "Parent queue: {} ({})",
            report.parent_queue_proposal_id.as_deref().unwrap_or("none"),
            report
                .parent_queue_review_state
                .map(review_state_label)
                .unwrap_or("none")
        ),
        format!("Summary: {}", report.summary),
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

    if report.decision_history.is_empty() {
        lines.push("Decision history: none".to_string());
    } else {
        lines.push("Decision history:".to_string());
        for decision in &report.decision_history {
            lines.push(format!(
                "- {} at {}: {}",
                decision_action_label(decision.action),
                decision.decided_at_ms,
                decision.reason
            ));
        }
    }

    lines.join("\n")
}

/// Render a filtered ranked-candidate selection list for operator review.
pub fn render_evolution_ranked_candidate_selection_list(
    list: &EvolutionRankedCandidateSelectionList,
) -> String {
    let mut lines = vec![
        "Evolution Ranked Candidate Selections".to_string(),
        format!("Total selections: {}", list.total_count),
    ];
    if let Some(strategy_id) = &list.strategy_id {
        lines.push(format!("Strategy filter: {}", strategy_id));
    }
    if let Some(review_state) = list.review_state {
        lines.push(format!(
            "Review-state filter: {}",
            review_state_label(review_state)
        ));
    }
    if list.selections.is_empty() {
        lines.push("No ranked-candidate selections matched the requested filters.".to_string());
        return lines.join("\n");
    }
    for selection in &list.selections {
        lines.push(format!(
            "- {} | strategy={} | state={} | created_at={}",
            selection.selection_id,
            selection.strategy_id,
            review_state_label(selection.review_state),
            selection.created_at_ms
        ));
    }
    lines.join("\n")
}

/// Render one ranked-candidate rollout bridge artifact.
pub fn render_evolution_ranked_candidate_bridge(
    report: &EvolutionRankedCandidateBridgeReport,
) -> String {
    let mut lines = vec![
        "Evolution Ranked Candidate Bridge".to_string(),
        format!("Bridge ID: {}", report.bridge_id),
        format!(
            "Selection: {} | Ranking: {}",
            report.selection_id, report.ranking_id
        ),
        format!(
            "Strategy: {} | queue_proposal_id={}",
            report.strategy_id,
            report.queue_proposal_id.as_deref().unwrap_or("none")
        ),
        format!(
            "Resulting review state: {} | handoff_ready={}",
            review_state_label(report.resulting_review_state),
            report.handoff_ready
        ),
        format!(
            "Verification: {} | Proof: {} | Shadow: {}",
            report.verification_id,
            report.proof_id.as_deref().unwrap_or("none"),
            report.shadow_id
        ),
        format!("Reason: {}", report.operator_reason),
    ];
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

fn selection_id(ranking_id: &str, packet_id: &str, created_at_ms: i64) -> String {
    format!(
        "evolution_selection:{}:{}:{}",
        short_digest(ranking_id),
        short_digest(packet_id),
        created_at_ms
    )
}

fn bridge_id(selection_id: &str, created_at_ms: i64) -> String {
    format!(
        "evolution_selection_bridge:{}:{}",
        short_digest(selection_id),
        created_at_ms
    )
}

fn queue_proposal_id_for_selection(
    experiment_name: &str,
    strategy_id: &str,
    created_at_ms: i64,
) -> String {
    format!(
        "evolution_proposal:{}:{}:{}",
        short_digest(experiment_name),
        short_digest(strategy_id),
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

fn review_state_label(state: EvolutionProposalReviewState) -> &'static str {
    match state {
        EvolutionProposalReviewState::PendingReview => "pending_review",
        EvolutionProposalReviewState::AcceptedForCanary => "accepted_for_canary",
        EvolutionProposalReviewState::Deferred => "deferred",
        EvolutionProposalReviewState::Rejected => "rejected",
        EvolutionProposalReviewState::Blocked => "blocked",
    }
}

fn decision_action_label(action: EvolutionProposalDecisionAction) -> &'static str {
    match action {
        EvolutionProposalDecisionAction::AcceptForCanary => "accept_for_canary",
        EvolutionProposalDecisionAction::ApplyAssuranceWaiver => "apply_assurance_waiver",
        EvolutionProposalDecisionAction::Defer => "defer",
        EvolutionProposalDecisionAction::Reject => "reject",
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
struct EvolutionSelectionIndex {
    entries: Vec<EvolutionRankedCandidateSelectionRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct EvolutionSelectionBridgeIndex {
    entries: Vec<EvolutionRankedCandidateBridgeRecord>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        DefaultEvolutionSelectionHarness, render_evolution_ranked_candidate_bridge,
        render_evolution_ranked_candidate_selection,
        render_evolution_ranked_candidate_selection_list,
    };
    use crate::canary::DefaultCanaryHarness;
    use crate::drafting::{DefaultEvolutionDraftingHarness, EvolutionDraftCreateRequest};
    use crate::evolution::{
        DefaultEvolutionHandoffHarness, DefaultEvolutionProofHarness,
        EvolutionProposalAssuranceCoverageSummary, EvolutionProposalAssuranceDecision,
        EvolutionProposalAssuranceSolverSummary, EvolutionProposalAssuranceSummary,
        EvolutionProposalDecisionAction, EvolutionProposalReviewState, FileEvolutionProposalStore,
    };
    use crate::mutation::{
        DefaultEvolutionMutationHarness, EvolutionMutationProfileOverrides,
        EvolutionMutationSpecCreateRequest, EvolutionMutationVariantCreateRequest,
    };
    use crate::replay::DefaultReplayHarness;
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
            name: format!("selection-test-allow-{threat_class:?}"),
            decision: PolicyRuleDecision::Allow,
            threat_class,
            actions: Vec::new(),
            min_severity: Severity::Low,
            max_severity: Severity::Critical,
            time_window_utc: None,
            max_actions_per_agent_per_minute: None,
            reason: Some("selection tests allow replay and verification responses".to_string()),
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

    struct SelectionFixture {
        _root: PathBuf,
        queue_dir: PathBuf,
        verification_dir: PathBuf,
        shadow_dir: PathBuf,
        selection_harness: DefaultEvolutionSelectionHarness,
        handoff_harness: DefaultEvolutionHandoffHarness,
        canary_harness: DefaultCanaryHarness,
        ready_ranking_id: String,
        ready_packet_id: String,
        blocked_ranking_id: String,
        blocked_packet_id: String,
    }

    async fn build_fixture() -> SelectionFixture {
        let root = unique_temp_dir("selection");
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
        let queue_dir = root.join("queue");
        let handoff_dir = root.join("handoffs");
        let canary_dir = root.join("canaries");
        let base_experiment = copy_experiment_fixture(&root, "office-control-selection");

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
            config.clone(),
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
                strategy_description: "selection parent".to_string(),
                mutation: "guided_selection_seed".to_string(),
                rationale: "bridge ranked candidates back into rollout review".to_string(),
            })
            .unwrap();
        let promotion = drafting
            .promote_draft(
                &queue_dir,
                &draft.report.draft_id,
                "seed a reviewed queue parent for ranking selections",
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
                    rationale:
                        "compare a ready control branch against a blocked broadened-parent branch"
                            .to_string(),
                },
            )
            .unwrap();
        let spec = mutation
            .append_variant(
                &spec.report.mutation_spec_id,
                EvolutionMutationVariantCreateRequest {
                    variant_id: Some("control-copy".to_string()),
                    strategy_id: "office_selection_control_v1".to_string(),
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
                    strategy_id: "office_selection_python_parent_v1".to_string(),
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
        let blocked_ranking = mutation
            .rank_candidates(&queue_dir, &validation_batch.report.validation_batch_id, 2)
            .unwrap();
        let selection_harness = DefaultEvolutionSelectionHarness::from_path(
            &mutation_ranking_dir,
            &validation_dir,
            &selection_dir,
            &selection_bridge_dir,
        )
        .unwrap();
        let handoff_harness =
            DefaultEvolutionHandoffHarness::from_config("inline", config.clone(), &handoff_dir)
                .unwrap();
        let canary_harness =
            DefaultCanaryHarness::from_config("inline", config, &canary_dir).unwrap();

        assert_eq!(
            blocked_ranking.report.review_packets[0]
                .queue_proposal_id
                .as_deref(),
            Some(promotion.report.queue_proposal_id.as_str())
        );
        let ready_packet = blocked_ranking
            .report
            .review_packets
            .iter()
            .find(|packet| packet.strategy_id == "office_selection_control_v1")
            .expect("expected one ready packet in the ranking");
        let blocked_packet = blocked_ranking
            .report
            .review_packets
            .iter()
            .find(|packet| packet.strategy_id == "office_selection_python_parent_v1")
            .expect("expected one blocked packet in the ranking");

        SelectionFixture {
            _root: root,
            queue_dir,
            verification_dir,
            shadow_dir,
            selection_harness,
            handoff_harness,
            canary_harness,
            ready_ranking_id: blocked_ranking.report.ranking_id.clone(),
            ready_packet_id: ready_packet.packet_id.clone(),
            blocked_ranking_id: blocked_ranking.report.ranking_id.clone(),
            blocked_packet_id: blocked_packet.packet_id.clone(),
        }
    }

    #[tokio::test]
    async fn ranked_candidate_selection_persists_from_ready_packet() {
        let fixture = build_fixture().await;

        let selection = fixture
            .selection_harness
            .create_selection(&fixture.ready_ranking_id, &fixture.ready_packet_id)
            .unwrap();

        assert_eq!(
            selection.report.review_state,
            EvolutionProposalReviewState::PendingReview
        );
        assert_eq!(selection.report.strategy_id, "office_selection_control_v1");
        assert!(selection.report.blocking_reasons.is_empty());
        assert!(
            render_evolution_ranked_candidate_selection(&selection.report)
                .contains("Evolution Ranked Candidate Selection")
        );
    }

    #[tokio::test]
    async fn ranked_candidate_selection_supports_review_decisions_and_listing() {
        let fixture = build_fixture().await;
        let selection = fixture
            .selection_harness
            .create_selection(&fixture.ready_ranking_id, &fixture.ready_packet_id)
            .unwrap();

        let decided = fixture
            .selection_harness
            .record_decision(
                &selection.report.selection_id,
                EvolutionProposalDecisionAction::AcceptForCanary,
                "ready to bridge the selected candidate into rollout review",
            )
            .unwrap();

        assert_eq!(
            decided.report.review_state,
            EvolutionProposalReviewState::AcceptedForCanary
        );
        assert_eq!(decided.report.decision_history.len(), 1);

        let list = fixture
            .selection_harness
            .list_selections(
                Some("office_selection_control_v1"),
                Some(EvolutionProposalReviewState::AcceptedForCanary),
            )
            .unwrap();
        assert_eq!(list.total_count, 1);
        assert!(
            render_evolution_ranked_candidate_selection_list(&list)
                .contains("Evolution Ranked Candidate Selections")
        );
    }

    #[tokio::test]
    async fn accepted_selection_bridges_into_existing_handoff_path() {
        let fixture = build_fixture().await;
        let selection = fixture
            .selection_harness
            .create_selection(&fixture.ready_ranking_id, &fixture.ready_packet_id)
            .unwrap();
        let selection = fixture
            .selection_harness
            .record_decision(
                &selection.report.selection_id,
                EvolutionProposalDecisionAction::AcceptForCanary,
                "accept the selected ranked candidate for rollout bridging",
            )
            .unwrap();

        let bridge = fixture
            .selection_harness
            .bridge_selection(
                &fixture.queue_dir,
                &selection.report.selection_id,
                "bridge the accepted selection into the existing queue and handoff lane",
            )
            .unwrap();

        assert!(bridge.report.blocking_reasons.is_empty());
        assert!(bridge.report.handoff_ready);
        let queue_proposal_id = bridge.report.queue_proposal_id.as_ref().unwrap();
        let queue_store = FileEvolutionProposalStore::open(&fixture.queue_dir).unwrap();
        let proposal = queue_store.load(queue_proposal_id).unwrap().unwrap();
        assert_eq!(
            proposal.report.review_state,
            EvolutionProposalReviewState::AcceptedForCanary
        );

        // Supply assurance lineage so the proposal passes the v1.51 assurance gate.
        {
            let mut report = proposal.report;
            report.assurance = Some(passed_assurance_summary());
            queue_store.persist(&report).unwrap();
        }

        let handoff = fixture
            .handoff_harness
            .create_handoff(
                &fixture.queue_dir,
                queue_proposal_id,
                &fixture.shadow_dir,
                &bridge.report.shadow_id,
            )
            .unwrap();
        assert!(handoff.report.blocking_reasons.is_empty());
        let launched = fixture.handoff_harness.launch_canary(
            &fixture.canary_harness,
            &fixture.verification_dir,
            &fixture.shadow_dir,
            &handoff.report.handoff_id,
        );
        let launched = launched.unwrap();
        assert!(launched.report.canary_run_id.is_some());
        assert!(
            render_evolution_ranked_candidate_bridge(&bridge.report)
                .contains("Evolution Ranked Candidate Bridge")
        );
    }

    #[tokio::test]
    async fn blocked_selection_bridge_fails_closed_without_queue_mutation() {
        let fixture = build_fixture().await;
        let selection = fixture
            .selection_harness
            .create_selection(&fixture.blocked_ranking_id, &fixture.blocked_packet_id)
            .unwrap();

        assert_eq!(
            selection.report.review_state,
            EvolutionProposalReviewState::Blocked
        );
        let before = FileEvolutionProposalStore::open(&fixture.queue_dir)
            .unwrap()
            .list(None, None)
            .unwrap()
            .total_count;
        let bridge = fixture
            .selection_harness
            .bridge_selection(
                &fixture.queue_dir,
                &selection.report.selection_id,
                "attempt to bridge a blocked ranked candidate",
            )
            .unwrap();
        let after = FileEvolutionProposalStore::open(&fixture.queue_dir)
            .unwrap()
            .list(None, None)
            .unwrap()
            .total_count;

        assert_eq!(before, after);
        assert_eq!(bridge.report.queue_proposal_id, None);
        assert!(!bridge.report.handoff_ready);
        assert!(!bridge.report.blocking_reasons.is_empty());
    }
}
