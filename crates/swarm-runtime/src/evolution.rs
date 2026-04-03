use crate::canary::{CanaryError, DefaultCanaryHarness};
use crate::config::{RuntimeConfigError, load_config};
use crate::replay::{
    DefaultReplayHarness, DetectorVerificationLookup, DetectorVerificationReport,
    ExperimentLineage, FileShadowStore, FileVerificationStore, ReplayHarnessError,
    ShadowStoreError, StrategyShadowLookup, VerificationCounterexample, VerificationStoreError,
    load_detector_experiment_manifest,
};
use crate::strategy::{
    DefaultStrategyScorecardHarness, StrategyAdvisorError, StrategyAdvisoryRecommendation,
    StrategyRolloutStateSummary, StrategyScorecard,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::SwarmConfig;

/// Errors surfaced by the verified evolution queue.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionQueueError {
    #[error(transparent)]
    Config(#[from] RuntimeConfigError),

    #[error(transparent)]
    Replay(#[from] ReplayHarnessError),

    #[error(transparent)]
    VerificationStore(#[from] VerificationStoreError),

    #[error(transparent)]
    Strategy(#[from] StrategyAdvisorError),

    #[error(transparent)]
    ProofStore(#[from] EvolutionProofStoreError),

    #[error(transparent)]
    ProposalStore(#[from] EvolutionProposalStoreError),

    #[error(transparent)]
    HandoffStore(#[from] EvolutionHandoffStoreError),

    #[error(transparent)]
    ShadowStore(#[from] ShadowStoreError),

    #[error(transparent)]
    Canary(#[from] CanaryError),

    #[error(transparent)]
    Serialization(#[from] serde_json::Error),

    #[error("verification artifact `{verification_id}` was not found")]
    VerificationNotFound { verification_id: String },

    #[error("verification artifact `{verification_id}` did not pass")]
    VerificationFailed { verification_id: String },

    #[error("proof artifact `{proof_id}` was not found")]
    ProofNotFound { proof_id: String },

    #[error("evolution proposal `{proposal_id}` was not found")]
    ProposalNotFound { proposal_id: String },

    #[error("evolution handoff `{handoff_id}` was not found")]
    HandoffNotFound { handoff_id: String },

    #[error(
        "proposal `{proposal_id}` cannot apply decision `{decision}` from state `{state}`: {reason}"
    )]
    InvalidDecision {
        proposal_id: String,
        state: String,
        decision: String,
        reason: String,
    },

    #[error("handoff `{handoff_id}` cannot launch canary from state `{state}`: {reason}")]
    InvalidHandoffLaunch {
        handoff_id: String,
        state: String,
        reason: String,
    },
}

/// One proof-backed invariant captured for queue admission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionProofInvariant {
    pub name: String,
    pub claim: String,
    pub details: String,
    pub counterexamples: Vec<VerificationCounterexample>,
}

/// Durable proof-backed safety artifact derived from a passed verification run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionProofReport {
    pub proof_id: String,
    pub experiment_id: String,
    pub experiment_name: String,
    pub verification_id: String,
    pub created_at_ms: i64,
    pub strategy_id: String,
    pub candidate_description: String,
    pub lineage: ExperimentLineage,
    pub corpus_name: String,
    pub proof_system: String,
    pub experiment_manifest_sha256: String,
    pub verification_report_sha256: String,
    pub lineage_sha256: String,
    pub attestation_sha256: String,
    pub invariants: Vec<EvolutionProofInvariant>,
}

/// Metadata surfaced for one persisted proof artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionProofRecord {
    pub proof_id: String,
    pub experiment_id: String,
    pub strategy_id: String,
    pub verification_id: String,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl EvolutionProofRecord {
    fn from_report(report: &EvolutionProofReport, bundle_path: String) -> Self {
        Self {
            proof_id: report.proof_id.clone(),
            experiment_id: report.experiment_id.clone(),
            strategy_id: report.strategy_id.clone(),
            verification_id: report.verification_id.clone(),
            created_at_ms: report.created_at_ms,
            bundle_path,
        }
    }
}

/// Persisted proof artifact loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionProofLookup {
    pub record: EvolutionProofRecord,
    pub report: EvolutionProofReport,
}

/// Errors raised by the persisted proof store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionProofStoreError {
    #[error("failed to read evolution proof store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution proof store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution proof store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// File-backed store for proof-backed queue admission artifacts.
#[derive(Debug, Clone)]
pub struct FileEvolutionProofStore {
    root: PathBuf,
}

impl FileEvolutionProofStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionProofStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionProofStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, proof_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(proof_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<EvolutionProofIndex, EvolutionProofStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionProofIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| EvolutionProofStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionProofStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &EvolutionProofIndex) -> Result<(), EvolutionProofStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionProofStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionProofStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionProofReport,
    ) -> Result<EvolutionProofRecord, EvolutionProofStoreError> {
        let path = self.report_path(&report.proof_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionProofStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionProofStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = EvolutionProofRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.proof_id != record.proof_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        proof_id: &str,
    ) -> Result<Option<EvolutionProofLookup>, EvolutionProofStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.proof_id == proof_id)
            .cloned()
        else {
            return Ok(None);
        };

        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| EvolutionProofStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionProofStoreError::Parse { path, source })?;
        Ok(Some(EvolutionProofLookup { record, report }))
    }
}

/// Status of proof evidence attached to one queued proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionProposalProofStatus {
    Proved,
    Missing,
    Inconsistent,
}

/// Durable operator review state for one queued proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionProposalReviewState {
    PendingReview,
    AcceptedForCanary,
    Deferred,
    Rejected,
    Blocked,
}

/// Explicit operator decision that can be recorded on a queued proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionProposalDecisionAction {
    AcceptForCanary,
    Defer,
    Reject,
}

/// Request used to assemble one durable evolution proposal.
#[derive(Debug, Clone)]
pub struct EvolutionProposalCreateRequest {
    pub experiment_path: PathBuf,
    pub experiment_results_dir: PathBuf,
    pub verification_results_dir: PathBuf,
    pub verification_id: String,
    pub proof_results_dir: PathBuf,
    pub proof_id: String,
}

/// Summary of the attached proof artifact shown on queue records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionProposalProofSummary {
    pub proof_id: String,
    pub proof_system: String,
    pub attestation_sha256: String,
    pub invariant_count: usize,
}

/// Summary of advisory score evidence attached to one queued proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionProposalAdvisorySummary {
    pub scorecard_id: String,
    pub recommendation: StrategyAdvisoryRecommendation,
    pub score_delta: f64,
    pub baseline_strategy_id: String,
    pub baseline_final_score: f64,
    pub candidate_final_score: f64,
    pub candidate_matching_memory_count: usize,
    pub latest_rollout_state: Option<StrategyRolloutStateSummary>,
}

impl EvolutionProposalAdvisorySummary {
    fn from_scorecard(scorecard: &StrategyScorecard) -> Self {
        Self {
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
}

/// One blocking reason preserved on a blocked queue proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionProposalBlockingReason {
    pub source: String,
    pub name: String,
    pub details: String,
    pub references: Vec<String>,
}

/// One explicit operator decision recorded against a queue proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionProposalDecisionRecord {
    pub decided_at_ms: i64,
    pub action: EvolutionProposalDecisionAction,
    pub reason: String,
}

/// Durable evolution proposal assembled from verified detector evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionProposalReport {
    pub proposal_id: String,
    pub experiment_id: String,
    pub experiment_name: String,
    #[serde(default)]
    pub experiment_path: String,
    pub created_at_ms: i64,
    pub strategy_id: String,
    pub strategy_description: String,
    pub lineage: ExperimentLineage,
    pub verification_id: Option<String>,
    pub verification_passed: bool,
    pub proof_status: EvolutionProposalProofStatus,
    pub proof: Option<EvolutionProposalProofSummary>,
    pub advisory: Option<EvolutionProposalAdvisorySummary>,
    pub review_state: EvolutionProposalReviewState,
    pub blocking_reasons: Vec<EvolutionProposalBlockingReason>,
    pub decision_history: Vec<EvolutionProposalDecisionRecord>,
}

/// Metadata surfaced for one persisted evolution proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionProposalRecord {
    pub proposal_id: String,
    pub strategy_id: String,
    pub review_state: EvolutionProposalReviewState,
    pub created_at_ms: i64,
    pub verification_id: Option<String>,
    pub proof_status: EvolutionProposalProofStatus,
    pub bundle_path: String,
}

impl EvolutionProposalRecord {
    fn from_report(report: &EvolutionProposalReport, bundle_path: String) -> Self {
        Self {
            proposal_id: report.proposal_id.clone(),
            strategy_id: report.strategy_id.clone(),
            review_state: report.review_state,
            created_at_ms: report.created_at_ms,
            verification_id: report.verification_id.clone(),
            proof_status: report.proof_status,
            bundle_path,
        }
    }
}

/// Persisted queued proposal loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionProposalLookup {
    pub record: EvolutionProposalRecord,
    pub report: EvolutionProposalReport,
}

/// Operator-facing queue listing with stable-ID filters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionProposalList {
    pub total_count: usize,
    pub strategy_id: Option<String>,
    pub review_state: Option<EvolutionProposalReviewState>,
    pub proposals: Vec<EvolutionProposalRecord>,
}

/// Durable launch state for one queue-to-canary handoff packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionHandoffStatus {
    PendingLaunch,
    CanaryLaunched,
    Blocked,
}

/// Durable queue-to-canary handoff packet assembled from accepted queue review evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionHandoffReport {
    pub handoff_id: String,
    pub proposal_id: String,
    pub experiment_id: String,
    pub experiment_name: String,
    pub experiment_path: String,
    pub created_at_ms: i64,
    pub launched_at_ms: Option<i64>,
    pub strategy_id: String,
    pub strategy_description: String,
    pub lineage: ExperimentLineage,
    pub verification_id: String,
    pub proof: EvolutionProposalProofSummary,
    pub advisory: Option<EvolutionProposalAdvisorySummary>,
    pub shadow_id: String,
    pub shadow_passed: bool,
    pub suite_name: String,
    pub corpus_version: String,
    pub launch_status: EvolutionHandoffStatus,
    pub blocking_reasons: Vec<EvolutionProposalBlockingReason>,
    pub canary_run_id: Option<String>,
}

/// Metadata surfaced for one persisted handoff packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionHandoffRecord {
    pub handoff_id: String,
    pub proposal_id: String,
    pub strategy_id: String,
    pub created_at_ms: i64,
    pub launched_at_ms: Option<i64>,
    pub launch_status: EvolutionHandoffStatus,
    pub canary_run_id: Option<String>,
    pub bundle_path: String,
}

impl EvolutionHandoffRecord {
    fn from_report(report: &EvolutionHandoffReport, bundle_path: String) -> Self {
        Self {
            handoff_id: report.handoff_id.clone(),
            proposal_id: report.proposal_id.clone(),
            strategy_id: report.strategy_id.clone(),
            created_at_ms: report.created_at_ms,
            launched_at_ms: report.launched_at_ms,
            launch_status: report.launch_status,
            canary_run_id: report.canary_run_id.clone(),
            bundle_path,
        }
    }
}

/// Persisted handoff packet loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionHandoffLookup {
    pub record: EvolutionHandoffRecord,
    pub report: EvolutionHandoffReport,
}

/// Errors raised by the persisted evolution queue store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionProposalStoreError {
    #[error("failed to read evolution proposal store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution proposal store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution proposal store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised by the persisted queue-to-canary handoff store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionHandoffStoreError {
    #[error("failed to read evolution handoff store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution handoff store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution handoff store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// File-backed store for durable evolution proposals.
#[derive(Debug, Clone)]
pub struct FileEvolutionProposalStore {
    root: PathBuf,
}

impl FileEvolutionProposalStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionProposalStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionProposalStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, proposal_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(proposal_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<EvolutionProposalIndex, EvolutionProposalStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionProposalIndex::default());
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| EvolutionProposalStoreError::Read {
                path: path.clone(),
                source,
            })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionProposalStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionProposalIndex,
    ) -> Result<(), EvolutionProposalStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionProposalStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionProposalStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionProposalReport,
    ) -> Result<EvolutionProposalRecord, EvolutionProposalStoreError> {
        let path = self.report_path(&report.proposal_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionProposalStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionProposalStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = EvolutionProposalRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.proposal_id != record.proposal_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        proposal_id: &str,
    ) -> Result<Option<EvolutionProposalLookup>, EvolutionProposalStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.proposal_id == proposal_id)
            .cloned()
        else {
            return Ok(None);
        };

        let path = PathBuf::from(&record.bundle_path);
        let raw =
            fs::read_to_string(&path).map_err(|source| EvolutionProposalStoreError::Read {
                path: path.clone(),
                source,
            })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionProposalStoreError::Parse { path, source })?;
        Ok(Some(EvolutionProposalLookup { record, report }))
    }

    pub fn list(
        &self,
        strategy_id: Option<&str>,
        review_state: Option<EvolutionProposalReviewState>,
    ) -> Result<EvolutionProposalList, EvolutionProposalStoreError> {
        let index = self.read_index()?;
        let proposals = index
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
        Ok(EvolutionProposalList {
            total_count: proposals.len(),
            strategy_id: strategy_id.map(ToOwned::to_owned),
            review_state,
            proposals,
        })
    }
}

/// File-backed store for durable queue-to-canary handoff packets.
#[derive(Debug, Clone)]
pub struct FileEvolutionHandoffStore {
    root: PathBuf,
}

impl FileEvolutionHandoffStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionHandoffStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionHandoffStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, handoff_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(handoff_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<EvolutionHandoffIndex, EvolutionHandoffStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionHandoffIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| EvolutionHandoffStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionHandoffStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &EvolutionHandoffIndex) -> Result<(), EvolutionHandoffStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionHandoffStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionHandoffStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionHandoffReport,
    ) -> Result<EvolutionHandoffRecord, EvolutionHandoffStoreError> {
        let path = self.report_path(&report.handoff_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionHandoffStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionHandoffStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = EvolutionHandoffRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.handoff_id != record.handoff_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        handoff_id: &str,
    ) -> Result<Option<EvolutionHandoffLookup>, EvolutionHandoffStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.handoff_id == handoff_id)
            .cloned()
        else {
            return Ok(None);
        };

        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| EvolutionHandoffStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionHandoffStoreError::Parse { path, source })?;
        Ok(Some(EvolutionHandoffLookup { record, report }))
    }
}

/// Harness that creates proof artifacts from passed verification evidence.
pub struct DefaultEvolutionProofHarness {
    pub config_path: PathBuf,
    pub config: SwarmConfig,
    pub store: FileEvolutionProofStore,
}

impl DefaultEvolutionProofHarness {
    pub fn from_path(
        config_path: impl AsRef<Path>,
        results_dir: impl AsRef<Path>,
    ) -> Result<Self, EvolutionQueueError> {
        let config_path = config_path.as_ref();
        let config = load_config(config_path)?;
        Self::from_config(config_path, config, results_dir)
    }

    pub fn from_config(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
        results_dir: impl AsRef<Path>,
    ) -> Result<Self, EvolutionQueueError> {
        Ok(Self {
            config_path: config_path.into(),
            config,
            store: FileEvolutionProofStore::open(results_dir)?,
        })
    }

    pub fn create_proof(
        &self,
        experiment_path: impl AsRef<Path>,
        verification_results_dir: impl AsRef<Path>,
        verification_id: &str,
    ) -> Result<EvolutionProofLookup, EvolutionQueueError> {
        let experiment_path = experiment_path.as_ref();
        let manifest = load_detector_experiment_manifest(experiment_path)?;
        let experiment_id = experiment_id_for_manifest(&manifest);
        let verification_store = FileVerificationStore::open(verification_results_dir)?;
        let verification = verification_store.load(verification_id)?.ok_or_else(|| {
            EvolutionQueueError::VerificationNotFound {
                verification_id: verification_id.to_string(),
            }
        })?;

        if verification.report.experiment_id != experiment_id {
            return Err(EvolutionQueueError::Replay(
                ReplayHarnessError::ReviewValidation {
                    reason: format!(
                        "verification `{}` does not belong to experiment `{}`",
                        verification_id, experiment_id
                    ),
                },
            ));
        }
        if !verification.report.passed {
            return Err(EvolutionQueueError::VerificationFailed {
                verification_id: verification_id.to_string(),
            });
        }
        if verification
            .report
            .invariants
            .iter()
            .any(|invariant| !invariant.passed)
        {
            return Err(EvolutionQueueError::VerificationFailed {
                verification_id: verification_id.to_string(),
            });
        }

        let experiment_manifest_sha256 = sha256_hex(&manifest)?;
        let verification_report_sha256 = sha256_hex(&verification.report)?;
        let lineage_sha256 = sha256_hex(&manifest.lineage)?;
        let invariants = verification
            .report
            .invariants
            .iter()
            .map(|invariant| EvolutionProofInvariant {
                name: invariant.name.clone(),
                claim: format!("verification invariant `{}` passed", invariant.name),
                details: invariant.details.clone(),
                counterexamples: invariant.counterexamples.clone(),
            })
            .collect::<Vec<_>>();
        let attestation_sha256 = sha256_hex(&ProofAttestationPayload {
            experiment_manifest_sha256: experiment_manifest_sha256.clone(),
            verification_report_sha256: verification_report_sha256.clone(),
            lineage_sha256: lineage_sha256.clone(),
            invariant_names: invariants.iter().map(|entry| entry.name.clone()).collect(),
        })?;
        let created_at_ms = now_ms();
        let report = EvolutionProofReport {
            proof_id: proof_id(
                &manifest.name,
                manifest.candidate.strategy_id(),
                created_at_ms,
            ),
            experiment_id,
            experiment_name: manifest.name.clone(),
            verification_id: verification.report.verification_id.clone(),
            created_at_ms,
            strategy_id: manifest.candidate.strategy_id().to_string(),
            candidate_description: manifest.candidate.description().to_string(),
            lineage: manifest.lineage.clone(),
            corpus_name: verification.report.corpus_name.clone(),
            proof_system: "verification_attestation_v1".to_string(),
            experiment_manifest_sha256,
            verification_report_sha256,
            lineage_sha256,
            attestation_sha256,
            invariants,
        };
        let record = self.store.persist(&report)?;
        Ok(EvolutionProofLookup { record, report })
    }

    pub fn load_proof(
        &self,
        proof_id: &str,
    ) -> Result<Option<EvolutionProofLookup>, EvolutionQueueError> {
        Ok(self.store.load(proof_id)?)
    }
}

/// Harness that builds and manages the verified evolution proposal queue.
pub struct DefaultEvolutionQueueHarness {
    pub config_path: PathBuf,
    pub config: SwarmConfig,
    pub store: FileEvolutionProposalStore,
}

impl DefaultEvolutionQueueHarness {
    pub fn from_path(
        config_path: impl AsRef<Path>,
        results_dir: impl AsRef<Path>,
    ) -> Result<Self, EvolutionQueueError> {
        let config_path = config_path.as_ref();
        let config = load_config(config_path)?;
        Self::from_config(config_path, config, results_dir)
    }

    pub fn from_config(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
        results_dir: impl AsRef<Path>,
    ) -> Result<Self, EvolutionQueueError> {
        Ok(Self {
            config_path: config_path.into(),
            config,
            store: FileEvolutionProposalStore::open(results_dir)?,
        })
    }

    pub async fn create_proposal(
        &self,
        replay_harness: &DefaultReplayHarness,
        scorecard_harness: &DefaultStrategyScorecardHarness,
        request: EvolutionProposalCreateRequest,
    ) -> Result<EvolutionProposalLookup, EvolutionQueueError> {
        let experiment_path = request.experiment_path.as_path();
        let manifest = load_detector_experiment_manifest(experiment_path)?;
        let experiment_id = experiment_id_for_manifest(&manifest);
        let created_at_ms = now_ms();
        let mut blocking_reasons = Vec::new();

        let verification =
            load_verification_lookup(&request.verification_results_dir, &request.verification_id)?;
        let verification_valid = match verification.as_ref() {
            Some(lookup) if lookup.report.experiment_id != experiment_id => {
                blocking_reasons.push(EvolutionProposalBlockingReason {
                    source: "verification".to_string(),
                    name: "experiment_mismatch".to_string(),
                    details: format!(
                        "verification `{}` belongs to `{}` instead of `{}`",
                        request.verification_id, lookup.report.experiment_id, experiment_id
                    ),
                    references: vec![lookup.report.verification_id.clone()],
                });
                false
            }
            Some(lookup) if !lookup.report.passed => {
                blocking_reasons.push(EvolutionProposalBlockingReason {
                    source: "verification".to_string(),
                    name: "verification_failed".to_string(),
                    details: "verification invariants did not all pass".to_string(),
                    references: vec![lookup.report.verification_id.clone()],
                });
                false
            }
            Some(_) => true,
            None => {
                blocking_reasons.push(EvolutionProposalBlockingReason {
                    source: "verification".to_string(),
                    name: "missing_verification".to_string(),
                    details: format!(
                        "verification artifact `{}` could not be loaded",
                        request.verification_id
                    ),
                    references: vec![request.verification_id.clone()],
                });
                false
            }
        };

        let proof_store = FileEvolutionProofStore::open(&request.proof_results_dir)?;
        let proof = proof_store.load(&request.proof_id)?;
        let proof_status = assess_proof_status(
            &manifest,
            verification.as_ref().map(|lookup| &lookup.report),
            proof.as_ref().map(|lookup| &lookup.report),
            &mut blocking_reasons,
            &request.proof_id,
        )?;

        let advisory = if verification_valid {
            match scorecard_harness
                .create_scorecard(
                    replay_harness,
                    experiment_path,
                    &request.experiment_results_dir,
                    &request.verification_results_dir,
                    &request.verification_id,
                )
                .await
            {
                Ok(lookup) => Some(EvolutionProposalAdvisorySummary::from_scorecard(
                    &lookup.report,
                )),
                Err(error) => {
                    blocking_reasons.push(EvolutionProposalBlockingReason {
                        source: "advisory".to_string(),
                        name: "scorecard_generation_failed".to_string(),
                        details: error.to_string(),
                        references: vec![request.verification_id.clone()],
                    });
                    None
                }
            }
        } else {
            None
        };

        let review_state = if blocking_reasons.is_empty() {
            EvolutionProposalReviewState::PendingReview
        } else {
            EvolutionProposalReviewState::Blocked
        };
        let report = EvolutionProposalReport {
            proposal_id: proposal_id(
                &manifest.name,
                manifest.candidate.strategy_id(),
                created_at_ms,
            ),
            experiment_id,
            experiment_name: manifest.name.clone(),
            experiment_path: experiment_path.display().to_string(),
            created_at_ms,
            strategy_id: manifest.candidate.strategy_id().to_string(),
            strategy_description: manifest.candidate.description().to_string(),
            lineage: manifest.lineage.clone(),
            verification_id: verification
                .as_ref()
                .map(|lookup| lookup.report.verification_id.clone()),
            verification_passed: verification_valid,
            proof_status,
            proof: proof.map(|lookup| EvolutionProposalProofSummary {
                proof_id: lookup.report.proof_id,
                proof_system: lookup.report.proof_system,
                attestation_sha256: lookup.report.attestation_sha256,
                invariant_count: lookup.report.invariants.len(),
            }),
            advisory,
            review_state,
            blocking_reasons,
            decision_history: Vec::new(),
        };
        let record = self.store.persist(&report)?;
        Ok(EvolutionProposalLookup { record, report })
    }

    pub fn load_proposal(
        &self,
        proposal_id: &str,
    ) -> Result<Option<EvolutionProposalLookup>, EvolutionQueueError> {
        Ok(self.store.load(proposal_id)?)
    }

    pub fn list_proposals(
        &self,
        strategy_id: Option<&str>,
        review_state: Option<EvolutionProposalReviewState>,
    ) -> Result<EvolutionProposalList, EvolutionQueueError> {
        Ok(self.store.list(strategy_id, review_state)?)
    }

    pub fn record_decision(
        &self,
        proposal_id: &str,
        action: EvolutionProposalDecisionAction,
        reason: &str,
    ) -> Result<EvolutionProposalLookup, EvolutionQueueError> {
        let mut lookup =
            self.store
                .load(proposal_id)?
                .ok_or_else(|| EvolutionQueueError::ProposalNotFound {
                    proposal_id: proposal_id.to_string(),
                })?;

        let new_state = match (lookup.report.review_state, action) {
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
                {
                    return Err(EvolutionQueueError::InvalidDecision {
                        proposal_id: proposal_id.to_string(),
                        state: review_state_label(lookup.report.review_state).to_string(),
                        decision: decision_action_label(action).to_string(),
                        reason: "only proof-backed, unblocked proposals can be accepted for canary"
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
                return Err(EvolutionQueueError::InvalidDecision {
                    proposal_id: proposal_id.to_string(),
                    state: review_state_label(lookup.report.review_state).to_string(),
                    decision: decision_action_label(action).to_string(),
                    reason: "blocked proposals may only be explicitly rejected".to_string(),
                });
            }
            (EvolutionProposalReviewState::AcceptedForCanary, _)
            | (EvolutionProposalReviewState::Rejected, _) => {
                return Err(EvolutionQueueError::InvalidDecision {
                    proposal_id: proposal_id.to_string(),
                    state: review_state_label(lookup.report.review_state).to_string(),
                    decision: decision_action_label(action).to_string(),
                    reason: "the proposal is already in a terminal review state".to_string(),
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
        let record = self.store.persist(&lookup.report)?;
        Ok(EvolutionProposalLookup {
            record,
            report: lookup.report,
        })
    }
}

/// Harness that bridges accepted proposals into durable canary-launch handoff packets.
pub struct DefaultEvolutionHandoffHarness {
    pub config_path: PathBuf,
    pub config: SwarmConfig,
    pub store: FileEvolutionHandoffStore,
}

impl DefaultEvolutionHandoffHarness {
    pub fn from_path(
        config_path: impl AsRef<Path>,
        results_dir: impl AsRef<Path>,
    ) -> Result<Self, EvolutionQueueError> {
        let config_path = config_path.as_ref();
        let config = load_config(config_path)?;
        Self::from_config(config_path, config, results_dir)
    }

    pub fn from_config(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
        results_dir: impl AsRef<Path>,
    ) -> Result<Self, EvolutionQueueError> {
        Ok(Self {
            config_path: config_path.into(),
            config,
            store: FileEvolutionHandoffStore::open(results_dir)?,
        })
    }

    pub fn create_handoff(
        &self,
        queue_results_dir: impl AsRef<Path>,
        proposal_id: &str,
        shadow_results_dir: impl AsRef<Path>,
        shadow_id: &str,
    ) -> Result<EvolutionHandoffLookup, EvolutionQueueError> {
        let proposal_store = FileEvolutionProposalStore::open(queue_results_dir)?;
        let proposal = proposal_store.load(proposal_id)?.ok_or_else(|| {
            EvolutionQueueError::ProposalNotFound {
                proposal_id: proposal_id.to_string(),
            }
        })?;

        let mut blocking_reasons = Vec::new();
        if proposal.report.review_state != EvolutionProposalReviewState::AcceptedForCanary {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "proposal".to_string(),
                name: "proposal_not_accepted_for_canary".to_string(),
                details: format!(
                    "proposal `{}` is in state `{}` instead of `accepted_for_canary`",
                    proposal.report.proposal_id,
                    review_state_label(proposal.report.review_state)
                ),
                references: vec![proposal.report.proposal_id.clone()],
            });
        }
        if proposal.report.proof_status != EvolutionProposalProofStatus::Proved {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "proposal".to_string(),
                name: "proposal_not_proved".to_string(),
                details: "proposal proof status is not `proved`".to_string(),
                references: vec![proposal.report.proposal_id.clone()],
            });
        }
        if !proposal.report.blocking_reasons.is_empty() {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "proposal".to_string(),
                name: "proposal_already_blocked".to_string(),
                details: "proposal still carries blocking reasons and cannot enter handoff"
                    .to_string(),
                references: vec![proposal.report.proposal_id.clone()],
            });
        }
        if !proposal.report.verification_passed {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "proposal".to_string(),
                name: "verification_not_passed".to_string(),
                details: "proposal does not reference a passed verification result".to_string(),
                references: vec![proposal.report.proposal_id.clone()],
            });
        }
        if proposal.report.experiment_path.trim().is_empty() {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "proposal".to_string(),
                name: "missing_experiment_path".to_string(),
                details: "proposal does not preserve an experiment manifest path for canary entry"
                    .to_string(),
                references: vec![proposal.report.proposal_id.clone()],
            });
        }

        let shadow = load_shadow_lookup(shadow_results_dir, shadow_id)?;
        match shadow.as_ref() {
            Some(lookup) if lookup.report.experiment_id != proposal.report.experiment_id => {
                blocking_reasons.push(EvolutionProposalBlockingReason {
                    source: "shadow".to_string(),
                    name: "experiment_mismatch".to_string(),
                    details: format!(
                        "shadow `{}` belongs to `{}` instead of `{}`",
                        lookup.report.shadow_id,
                        lookup.report.experiment_id,
                        proposal.report.experiment_id
                    ),
                    references: vec![lookup.report.shadow_id.clone()],
                });
            }
            Some(lookup) if lookup.report.candidate_strategy_id != proposal.report.strategy_id => {
                blocking_reasons.push(EvolutionProposalBlockingReason {
                    source: "shadow".to_string(),
                    name: "strategy_mismatch".to_string(),
                    details: format!(
                        "shadow `{}` targets strategy `{}` instead of `{}`",
                        lookup.report.shadow_id,
                        lookup.report.candidate_strategy_id,
                        proposal.report.strategy_id
                    ),
                    references: vec![lookup.report.shadow_id.clone()],
                });
            }
            Some(lookup) if !lookup.report.passed => {
                blocking_reasons.push(EvolutionProposalBlockingReason {
                    source: "shadow".to_string(),
                    name: "shadow_failed".to_string(),
                    details: "shadow artifact did not pass its offline gates".to_string(),
                    references: vec![lookup.report.shadow_id.clone()],
                });
            }
            Some(_) => {}
            None => {
                blocking_reasons.push(EvolutionProposalBlockingReason {
                    source: "shadow".to_string(),
                    name: "missing_shadow".to_string(),
                    details: format!("shadow artifact `{shadow_id}` could not be loaded"),
                    references: vec![shadow_id.to_string()],
                });
            }
        }

        let created_at_ms = now_ms();
        let shadow = shadow.map(|lookup| lookup.report);
        let launch_status = if blocking_reasons.is_empty() {
            EvolutionHandoffStatus::PendingLaunch
        } else {
            EvolutionHandoffStatus::Blocked
        };
        let report = EvolutionHandoffReport {
            handoff_id: handoff_id(
                &proposal.report.proposal_id,
                &proposal.report.strategy_id,
                created_at_ms,
            ),
            proposal_id: proposal.report.proposal_id.clone(),
            experiment_id: proposal.report.experiment_id.clone(),
            experiment_name: proposal.report.experiment_name.clone(),
            experiment_path: proposal.report.experiment_path.clone(),
            created_at_ms,
            launched_at_ms: None,
            strategy_id: proposal.report.strategy_id.clone(),
            strategy_description: proposal.report.strategy_description.clone(),
            lineage: proposal.report.lineage.clone(),
            verification_id: proposal.report.verification_id.clone().unwrap_or_default(),
            proof: proposal
                .report
                .proof
                .clone()
                .unwrap_or(EvolutionProposalProofSummary {
                    proof_id: String::new(),
                    proof_system: String::new(),
                    attestation_sha256: String::new(),
                    invariant_count: 0,
                }),
            advisory: proposal.report.advisory.clone(),
            shadow_id: shadow
                .as_ref()
                .map(|report| report.shadow_id.clone())
                .unwrap_or_else(|| shadow_id.to_string()),
            shadow_passed: shadow.as_ref().map(|report| report.passed).unwrap_or(false),
            suite_name: shadow
                .as_ref()
                .map(|report| report.suite_name.clone())
                .unwrap_or_default(),
            corpus_version: shadow
                .as_ref()
                .map(|report| report.corpus_version.clone())
                .unwrap_or_default(),
            launch_status,
            blocking_reasons,
            canary_run_id: None,
        };
        let record = self.store.persist(&report)?;
        Ok(EvolutionHandoffLookup { record, report })
    }

    pub fn load_handoff(
        &self,
        handoff_id: &str,
    ) -> Result<Option<EvolutionHandoffLookup>, EvolutionQueueError> {
        Ok(self.store.load(handoff_id)?)
    }

    pub fn launch_canary(
        &self,
        canary_harness: &DefaultCanaryHarness,
        verification_results_dir: impl AsRef<Path>,
        shadow_results_dir: impl AsRef<Path>,
        handoff_id: &str,
    ) -> Result<EvolutionHandoffLookup, EvolutionQueueError> {
        let mut lookup =
            self.store
                .load(handoff_id)?
                .ok_or_else(|| EvolutionQueueError::HandoffNotFound {
                    handoff_id: handoff_id.to_string(),
                })?;

        if lookup.report.launch_status != EvolutionHandoffStatus::PendingLaunch {
            return Err(EvolutionQueueError::InvalidHandoffLaunch {
                handoff_id: handoff_id.to_string(),
                state: handoff_status_label(lookup.report.launch_status).to_string(),
                reason: "handoff is not in a launchable pending state".to_string(),
            });
        }
        if !lookup.report.blocking_reasons.is_empty() {
            return Err(EvolutionQueueError::InvalidHandoffLaunch {
                handoff_id: handoff_id.to_string(),
                state: handoff_status_label(lookup.report.launch_status).to_string(),
                reason: "handoff still carries blocking reasons".to_string(),
            });
        }
        if lookup.report.canary_run_id.is_some() {
            return Err(EvolutionQueueError::InvalidHandoffLaunch {
                handoff_id: handoff_id.to_string(),
                state: handoff_status_label(lookup.report.launch_status).to_string(),
                reason: "handoff already references a canary run".to_string(),
            });
        }

        let canary = canary_harness.start_run(
            PathBuf::from(&lookup.report.experiment_path),
            verification_results_dir,
            &lookup.report.verification_id,
            shadow_results_dir,
            &lookup.report.shadow_id,
        )?;
        lookup.report.launched_at_ms = Some(now_ms());
        lookup.report.launch_status = EvolutionHandoffStatus::CanaryLaunched;
        lookup.report.canary_run_id = Some(canary.report.run_id.clone());
        let record = self.store.persist(&lookup.report)?;
        Ok(EvolutionHandoffLookup {
            record,
            report: lookup.report,
        })
    }
}

/// Render one proof-backed safety artifact.
pub fn render_evolution_proof(report: &EvolutionProofReport) -> String {
    let mut lines = vec![
        "Evolution Safety Proof".to_string(),
        format!("Proof ID: {}", report.proof_id),
        format!(
            "Experiment: {} ({})",
            report.experiment_name, report.experiment_id
        ),
        format!("Verification: {}", report.verification_id),
        format!(
            "Strategy: {} | {}",
            report.strategy_id, report.candidate_description
        ),
        format!("Proof system: {}", report.proof_system),
        format!(
            "Digests: experiment={} verification={} lineage={}",
            report.experiment_manifest_sha256,
            report.verification_report_sha256,
            report.lineage_sha256
        ),
        format!("Attestation: {}", report.attestation_sha256),
        format!(
            "Lineage: parent={} mutation={} rationale={}",
            report.lineage.parent_strategy_id, report.lineage.mutation, report.lineage.rationale
        ),
        format!("Corpus: {}", report.corpus_name),
        format!("Invariant count: {}", report.invariants.len()),
    ];
    for invariant in &report.invariants {
        lines.push(format!("- {}: {}", invariant.name, invariant.details));
    }
    lines.join("\n")
}

/// Render one evolution proposal artifact.
pub fn render_evolution_proposal(report: &EvolutionProposalReport) -> String {
    let mut lines = vec![
        "Evolution Proposal".to_string(),
        format!("Proposal ID: {}", report.proposal_id),
        format!(
            "Experiment: {} ({})",
            report.experiment_name, report.experiment_id
        ),
        format!(
            "Strategy: {} | {}",
            report.strategy_id, report.strategy_description
        ),
        format!(
            "Review state: {} | proof status={}",
            review_state_label(report.review_state),
            proof_status_label(report.proof_status)
        ),
    ];

    if let Some(verification_id) = &report.verification_id {
        lines.push(format!(
            "Verification: {} | passed={}",
            verification_id, report.verification_passed
        ));
    } else {
        lines.push("Verification: missing".to_string());
    }

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
            "Advisory: scorecard={} recommendation={} delta={:.3}",
            advisory.scorecard_id,
            advisory_recommendation_label(advisory.recommendation),
            advisory.score_delta
        ));
        lines.push(format!(
            "Scores: baseline={:.3} candidate={:.3} candidate_matching_memories={}",
            advisory.baseline_final_score,
            advisory.candidate_final_score,
            advisory.candidate_matching_memory_count
        ));
        if let Some(latest) = &advisory.latest_rollout_state {
            lines.push(format!(
                "Latest rollout state: {:?} via {:?} {}",
                latest.outcome_kind, latest.source_kind, latest.source_artifact_id
            ));
        }
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

/// Render a filtered proposal list for operator review.
pub fn render_evolution_proposal_list(list: &EvolutionProposalList) -> String {
    let mut lines = vec![
        "Evolution Queue".to_string(),
        format!("Total proposals: {}", list.total_count),
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
    if list.proposals.is_empty() {
        lines.push("No queued proposals matched the requested filters.".to_string());
        return lines.join("\n");
    }
    for proposal in &list.proposals {
        lines.push(format!(
            "- {} | strategy={} | state={} | proof={} | created_at={}",
            proposal.proposal_id,
            proposal.strategy_id,
            review_state_label(proposal.review_state),
            proof_status_label(proposal.proof_status),
            proposal.created_at_ms
        ));
    }
    lines.join("\n")
}

/// Render one durable queue-to-canary handoff packet.
pub fn render_evolution_handoff(report: &EvolutionHandoffReport) -> String {
    let mut lines = vec![
        "Evolution Canary Handoff".to_string(),
        format!("Handoff ID: {}", report.handoff_id),
        format!("Proposal: {}", report.proposal_id),
        format!(
            "Experiment: {} ({})",
            report.experiment_name, report.experiment_id
        ),
        format!(
            "Strategy: {} | {}",
            report.strategy_id, report.strategy_description
        ),
        format!(
            "Launch status: {} | canary_run_id={}",
            handoff_status_label(report.launch_status),
            report.canary_run_id.as_deref().unwrap_or("none")
        ),
        format!(
            "Verification: {} | Proof: {} | Shadow: {} (passed={})",
            report.verification_id, report.proof.proof_id, report.shadow_id, report.shadow_passed
        ),
        format!(
            "Context: suite={} corpus={}",
            report.suite_name, report.corpus_version
        ),
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

fn load_verification_lookup(
    verification_results_dir: impl AsRef<Path>,
    verification_id: &str,
) -> Result<Option<DetectorVerificationLookup>, EvolutionQueueError> {
    let store = FileVerificationStore::open(verification_results_dir)?;
    Ok(store.load(verification_id)?)
}

fn load_shadow_lookup(
    shadow_results_dir: impl AsRef<Path>,
    shadow_id: &str,
) -> Result<Option<StrategyShadowLookup>, EvolutionQueueError> {
    let store = FileShadowStore::open(shadow_results_dir)?;
    Ok(store.load(shadow_id)?)
}

fn assess_proof_status(
    manifest: &crate::replay::DetectorExperimentManifest,
    verification: Option<&DetectorVerificationReport>,
    proof: Option<&EvolutionProofReport>,
    blocking_reasons: &mut Vec<EvolutionProposalBlockingReason>,
    requested_proof_id: &str,
) -> Result<EvolutionProposalProofStatus, EvolutionQueueError> {
    let Some(proof) = proof else {
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "proof".to_string(),
            name: "missing_proof".to_string(),
            details: format!(
                "proof artifact `{}` could not be loaded",
                requested_proof_id
            ),
            references: vec![requested_proof_id.to_string()],
        });
        return Ok(EvolutionProposalProofStatus::Missing);
    };

    let mut inconsistent = false;
    let expected_experiment_id = experiment_id_for_manifest(manifest);
    if proof.experiment_id != expected_experiment_id {
        inconsistent = true;
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "proof".to_string(),
            name: "experiment_mismatch".to_string(),
            details: format!(
                "proof `{}` belongs to `{}` instead of `{}`",
                proof.proof_id, proof.experiment_id, expected_experiment_id
            ),
            references: vec![proof.proof_id.clone()],
        });
    }
    if proof.strategy_id != manifest.candidate.strategy_id() {
        inconsistent = true;
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "proof".to_string(),
            name: "strategy_mismatch".to_string(),
            details: format!(
                "proof `{}` targets strategy `{}` instead of `{}`",
                proof.proof_id,
                proof.strategy_id,
                manifest.candidate.strategy_id()
            ),
            references: vec![proof.proof_id.clone()],
        });
    }
    if proof.experiment_manifest_sha256 != sha256_hex(manifest)? {
        inconsistent = true;
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "proof".to_string(),
            name: "experiment_digest_mismatch".to_string(),
            details: "proof digest does not match the current experiment manifest".to_string(),
            references: vec![proof.proof_id.clone()],
        });
    }
    if proof.lineage_sha256 != sha256_hex(&manifest.lineage)? {
        inconsistent = true;
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "proof".to_string(),
            name: "lineage_digest_mismatch".to_string(),
            details: "proof lineage digest does not match the current experiment lineage"
                .to_string(),
            references: vec![proof.proof_id.clone()],
        });
    }

    let Some(verification) = verification else {
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "proof".to_string(),
            name: "missing_verification_reference".to_string(),
            details: "proof could not be cross-checked because verification evidence is missing"
                .to_string(),
            references: vec![proof.proof_id.clone()],
        });
        return Ok(EvolutionProposalProofStatus::Inconsistent);
    };

    if proof.verification_id != verification.verification_id {
        inconsistent = true;
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "proof".to_string(),
            name: "verification_mismatch".to_string(),
            details: format!(
                "proof `{}` references verification `{}` instead of `{}`",
                proof.proof_id, proof.verification_id, verification.verification_id
            ),
            references: vec![proof.proof_id.clone(), verification.verification_id.clone()],
        });
    }
    if proof.verification_report_sha256 != sha256_hex(verification)? {
        inconsistent = true;
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "proof".to_string(),
            name: "verification_digest_mismatch".to_string(),
            details: "proof digest does not match the persisted verification report".to_string(),
            references: vec![proof.proof_id.clone(), verification.verification_id.clone()],
        });
    }
    let verification_invariants = verification
        .invariants
        .iter()
        .map(|invariant| invariant.name.as_str())
        .collect::<Vec<_>>();
    let proof_invariants = proof
        .invariants
        .iter()
        .map(|invariant| invariant.name.as_str())
        .collect::<Vec<_>>();
    if verification_invariants != proof_invariants {
        inconsistent = true;
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "proof".to_string(),
            name: "invariant_coverage_mismatch".to_string(),
            details: "proof invariants do not line up with the verification report".to_string(),
            references: vec![proof.proof_id.clone(), verification.verification_id.clone()],
        });
    }
    if proof.corpus_name != verification.corpus_name {
        inconsistent = true;
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "proof".to_string(),
            name: "corpus_mismatch".to_string(),
            details: format!(
                "proof corpus `{}` does not match verification corpus `{}`",
                proof.corpus_name, verification.corpus_name
            ),
            references: vec![proof.proof_id.clone(), verification.verification_id.clone()],
        });
    }

    Ok(if inconsistent {
        EvolutionProposalProofStatus::Inconsistent
    } else {
        EvolutionProposalProofStatus::Proved
    })
}

fn experiment_id_for_manifest(manifest: &crate::replay::DetectorExperimentManifest) -> String {
    format!(
        "experiment:{}:{}",
        manifest.name,
        manifest.candidate.strategy_id()
    )
}

fn proof_id(experiment_name: &str, strategy_id: &str, created_at_ms: i64) -> String {
    format!(
        "evolution_proof:{}:{}:{}",
        experiment_name, strategy_id, created_at_ms
    )
}

fn proposal_id(experiment_name: &str, strategy_id: &str, created_at_ms: i64) -> String {
    format!(
        "evolution_proposal:{}:{}:{}",
        experiment_name, strategy_id, created_at_ms
    )
}

fn handoff_id(proposal_id: &str, strategy_id: &str, created_at_ms: i64) -> String {
    format!(
        "evolution_handoff:{}:{}:{}",
        proposal_id, strategy_id, created_at_ms
    )
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

fn proof_status_label(status: EvolutionProposalProofStatus) -> &'static str {
    match status {
        EvolutionProposalProofStatus::Proved => "proved",
        EvolutionProposalProofStatus::Missing => "missing",
        EvolutionProposalProofStatus::Inconsistent => "inconsistent",
    }
}

fn decision_action_label(action: EvolutionProposalDecisionAction) -> &'static str {
    match action {
        EvolutionProposalDecisionAction::AcceptForCanary => "accept_for_canary",
        EvolutionProposalDecisionAction::Defer => "defer",
        EvolutionProposalDecisionAction::Reject => "reject",
    }
}

fn advisory_recommendation_label(recommendation: StrategyAdvisoryRecommendation) -> &'static str {
    match recommendation {
        StrategyAdvisoryRecommendation::RetainBaseline => "retain_baseline",
        StrategyAdvisoryRecommendation::CandidatePreferred => "candidate_preferred",
        StrategyAdvisoryRecommendation::CandidateAlreadyStableInProduction => {
            "candidate_already_stable_in_production"
        }
    }
}

fn handoff_status_label(status: EvolutionHandoffStatus) -> &'static str {
    match status {
        EvolutionHandoffStatus::PendingLaunch => "pending_launch",
        EvolutionHandoffStatus::CanaryLaunched => "canary_launched",
        EvolutionHandoffStatus::Blocked => "blocked",
    }
}

fn sha256_hex<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let raw = serde_json::to_vec(value)?;
    let digest = Sha256::digest(raw);
    Ok(format!("{digest:x}"))
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
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
        .expect("system time before unix epoch")
        .as_millis() as i64
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct EvolutionProofIndex {
    entries: Vec<EvolutionProofRecord>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct EvolutionProposalIndex {
    entries: Vec<EvolutionProposalRecord>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct EvolutionHandoffIndex {
    entries: Vec<EvolutionHandoffRecord>,
}

#[derive(Debug, Serialize)]
struct ProofAttestationPayload {
    experiment_manifest_sha256: String,
    verification_report_sha256: String,
    lineage_sha256: String,
    invariant_names: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::{
        DefaultEvolutionHandoffHarness, DefaultEvolutionProofHarness, DefaultEvolutionQueueHarness,
        EvolutionHandoffStatus, EvolutionProposalCreateRequest, EvolutionProposalDecisionAction,
        EvolutionProposalProofStatus, EvolutionProposalReviewState, render_evolution_handoff,
        render_evolution_proof, render_evolution_proposal, render_evolution_proposal_list,
    };
    use crate::canary::DefaultCanaryHarness;
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

    fn unique_temp_dir(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "swarm-runtime-evolution-{label}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[tokio::test]
    async fn evolution_proof_persists_for_passed_verification() {
        let root = unique_temp_dir("proof");
        let replay_dir = root.join("replay");
        let verification_dir = root.join("verification");
        let proofs_dir = root.join("proofs");
        let config = sample_config();
        let replay =
            DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
        let verification = replay
            .evaluate_verification_path(office_control_experiment(), &verification_dir)
            .await
            .unwrap();
        let harness =
            DefaultEvolutionProofHarness::from_config("inline", config, &proofs_dir).unwrap();

        let proof = harness
            .create_proof(
                office_control_experiment(),
                &verification_dir,
                &verification.report.verification_id,
            )
            .unwrap();

        assert_eq!(proof.report.strategy_id, "office_baseline_control");
        assert_eq!(
            proof.report.verification_id,
            verification.report.verification_id
        );
        assert!(!proof.report.attestation_sha256.is_empty());
        assert!(render_evolution_proof(&proof.report).contains("Evolution Safety Proof"));
    }

    #[tokio::test]
    async fn evolution_queue_creates_pending_review_proposal() {
        let root = unique_temp_dir("queue-create");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verification");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let proofs_dir = root.join("proofs");
        let queue_dir = root.join("queue");
        let config = sample_config();
        let replay =
            DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
        let verification = replay
            .evaluate_verification_path(office_control_experiment(), &verification_dir)
            .await
            .unwrap();
        let proof_harness =
            DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proofs_dir)
                .unwrap();
        let proof = proof_harness
            .create_proof(
                office_control_experiment(),
                &verification_dir,
                &verification.report.verification_id,
            )
            .unwrap();
        let scorecards = DefaultStrategyScorecardHarness::from_config(
            "inline",
            config.clone(),
            &memory_dir,
            &scorecard_dir,
        )
        .unwrap();
        let queue =
            DefaultEvolutionQueueHarness::from_config("inline", config, &queue_dir).unwrap();

        let proposal = queue
            .create_proposal(
                &replay,
                &scorecards,
                EvolutionProposalCreateRequest {
                    experiment_path: office_control_experiment(),
                    experiment_results_dir: experiment_dir.clone(),
                    verification_results_dir: verification_dir.clone(),
                    verification_id: verification.report.verification_id.clone(),
                    proof_results_dir: proofs_dir.clone(),
                    proof_id: proof.report.proof_id.clone(),
                },
            )
            .await
            .unwrap();

        assert_eq!(
            proposal.report.review_state,
            EvolutionProposalReviewState::PendingReview
        );
        assert_eq!(
            proposal.report.proof_status,
            EvolutionProposalProofStatus::Proved
        );
        assert!(proposal.report.advisory.is_some());
        assert!(render_evolution_proposal(&proposal.report).contains("Evolution Proposal"));
    }

    #[tokio::test]
    async fn evolution_queue_blocks_missing_proof() {
        let root = unique_temp_dir("queue-blocked");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verification");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let proofs_dir = root.join("proofs");
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
        let queue =
            DefaultEvolutionQueueHarness::from_config("inline", config, &queue_dir).unwrap();

        let proposal = queue
            .create_proposal(
                &replay,
                &scorecards,
                EvolutionProposalCreateRequest {
                    experiment_path: office_control_experiment(),
                    experiment_results_dir: experiment_dir.clone(),
                    verification_results_dir: verification_dir.clone(),
                    verification_id: verification.report.verification_id.clone(),
                    proof_results_dir: proofs_dir.clone(),
                    proof_id: "missing-proof".to_string(),
                },
            )
            .await
            .unwrap();

        assert_eq!(
            proposal.report.review_state,
            EvolutionProposalReviewState::Blocked
        );
        assert_eq!(
            proposal.report.proof_status,
            EvolutionProposalProofStatus::Missing
        );
        assert_eq!(proposal.report.blocking_reasons.len(), 1);
    }

    #[tokio::test]
    async fn evolution_queue_lists_and_accepts_pending_proposal() {
        let root = unique_temp_dir("queue-decide");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verification");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let proofs_dir = root.join("proofs");
        let queue_dir = root.join("queue");
        let config = sample_config();
        let replay =
            DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
        let verification = replay
            .evaluate_verification_path(office_control_experiment(), &verification_dir)
            .await
            .unwrap();
        let proof_harness =
            DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proofs_dir)
                .unwrap();
        let proof = proof_harness
            .create_proof(
                office_control_experiment(),
                &verification_dir,
                &verification.report.verification_id,
            )
            .unwrap();
        let scorecards = DefaultStrategyScorecardHarness::from_config(
            "inline",
            config.clone(),
            &memory_dir,
            &scorecard_dir,
        )
        .unwrap();
        let queue =
            DefaultEvolutionQueueHarness::from_config("inline", config, &queue_dir).unwrap();
        let proposal = queue
            .create_proposal(
                &replay,
                &scorecards,
                EvolutionProposalCreateRequest {
                    experiment_path: office_control_experiment(),
                    experiment_results_dir: experiment_dir.clone(),
                    verification_results_dir: verification_dir.clone(),
                    verification_id: verification.report.verification_id.clone(),
                    proof_results_dir: proofs_dir.clone(),
                    proof_id: proof.report.proof_id.clone(),
                },
            )
            .await
            .unwrap();

        let list = queue
            .list_proposals(
                Some("office_baseline_control"),
                Some(EvolutionProposalReviewState::PendingReview),
            )
            .unwrap();
        assert_eq!(list.total_count, 1);
        assert!(render_evolution_proposal_list(&list).contains("pending_review"));

        let decided = queue
            .record_decision(
                &proposal.report.proposal_id,
                EvolutionProposalDecisionAction::AcceptForCanary,
                "control candidate is ready for bounded canary",
            )
            .unwrap();
        assert_eq!(
            decided.report.review_state,
            EvolutionProposalReviewState::AcceptedForCanary
        );
        assert_eq!(decided.report.decision_history.len(), 1);
    }

    #[tokio::test]
    async fn evolution_handoff_persists_pending_launch_packet() {
        let root = unique_temp_dir("handoff-create");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verification");
        let shadow_dir = root.join("shadows");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let proofs_dir = root.join("proofs");
        let queue_dir = root.join("queue");
        let handoff_dir = root.join("handoffs");
        let config = sample_config();
        let replay =
            DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
        let verification = replay
            .evaluate_verification_path(office_control_experiment(), &verification_dir)
            .await
            .unwrap();
        let shadow = replay
            .evaluate_shadow_path(office_control_experiment(), &shadow_dir)
            .await
            .unwrap();
        let proof_harness =
            DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proofs_dir)
                .unwrap();
        let proof = proof_harness
            .create_proof(
                office_control_experiment(),
                &verification_dir,
                &verification.report.verification_id,
            )
            .unwrap();
        let scorecards = DefaultStrategyScorecardHarness::from_config(
            "inline",
            config.clone(),
            &memory_dir,
            &scorecard_dir,
        )
        .unwrap();
        let queue = DefaultEvolutionQueueHarness::from_config("inline", config.clone(), &queue_dir)
            .unwrap();
        let proposal = queue
            .create_proposal(
                &replay,
                &scorecards,
                EvolutionProposalCreateRequest {
                    experiment_path: office_control_experiment(),
                    experiment_results_dir: experiment_dir.clone(),
                    verification_results_dir: verification_dir.clone(),
                    verification_id: verification.report.verification_id.clone(),
                    proof_results_dir: proofs_dir.clone(),
                    proof_id: proof.report.proof_id.clone(),
                },
            )
            .await
            .unwrap();
        let accepted = queue
            .record_decision(
                &proposal.report.proposal_id,
                EvolutionProposalDecisionAction::AcceptForCanary,
                "ready for queue handoff",
            )
            .unwrap();
        let handoff =
            DefaultEvolutionHandoffHarness::from_config("inline", config, &handoff_dir).unwrap();

        let lookup = handoff
            .create_handoff(
                &queue_dir,
                &accepted.report.proposal_id,
                &shadow_dir,
                &shadow.report.shadow_id,
            )
            .unwrap();

        assert_eq!(
            lookup.report.launch_status,
            EvolutionHandoffStatus::PendingLaunch
        );
        assert!(lookup.report.blocking_reasons.is_empty());
        assert_eq!(lookup.report.shadow_id, shadow.report.shadow_id);
        assert!(render_evolution_handoff(&lookup.report).contains("Evolution Canary Handoff"));
    }

    #[tokio::test]
    async fn evolution_handoff_blocks_unaccepted_proposal() {
        let root = unique_temp_dir("handoff-blocked");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verification");
        let shadow_dir = root.join("shadows");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let proofs_dir = root.join("proofs");
        let queue_dir = root.join("queue");
        let handoff_dir = root.join("handoffs");
        let config = sample_config();
        let replay =
            DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
        let verification = replay
            .evaluate_verification_path(office_control_experiment(), &verification_dir)
            .await
            .unwrap();
        let shadow = replay
            .evaluate_shadow_path(office_control_experiment(), &shadow_dir)
            .await
            .unwrap();
        let proof_harness =
            DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proofs_dir)
                .unwrap();
        let proof = proof_harness
            .create_proof(
                office_control_experiment(),
                &verification_dir,
                &verification.report.verification_id,
            )
            .unwrap();
        let scorecards = DefaultStrategyScorecardHarness::from_config(
            "inline",
            config.clone(),
            &memory_dir,
            &scorecard_dir,
        )
        .unwrap();
        let queue = DefaultEvolutionQueueHarness::from_config("inline", config.clone(), &queue_dir)
            .unwrap();
        let proposal = queue
            .create_proposal(
                &replay,
                &scorecards,
                EvolutionProposalCreateRequest {
                    experiment_path: office_control_experiment(),
                    experiment_results_dir: experiment_dir.clone(),
                    verification_results_dir: verification_dir.clone(),
                    verification_id: verification.report.verification_id.clone(),
                    proof_results_dir: proofs_dir.clone(),
                    proof_id: proof.report.proof_id.clone(),
                },
            )
            .await
            .unwrap();
        let handoff =
            DefaultEvolutionHandoffHarness::from_config("inline", config, &handoff_dir).unwrap();

        let lookup = handoff
            .create_handoff(
                &queue_dir,
                &proposal.report.proposal_id,
                &shadow_dir,
                &shadow.report.shadow_id,
            )
            .unwrap();

        assert_eq!(lookup.report.launch_status, EvolutionHandoffStatus::Blocked);
        assert!(!lookup.report.blocking_reasons.is_empty());
        assert_eq!(lookup.report.canary_run_id, None);
    }

    #[tokio::test]
    async fn evolution_handoff_launches_canary_and_persists_run_id() {
        let root = unique_temp_dir("handoff-launch");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verification");
        let shadow_dir = root.join("shadows");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let proofs_dir = root.join("proofs");
        let queue_dir = root.join("queue");
        let handoff_dir = root.join("handoffs");
        let canary_dir = root.join("canaries");
        let config = sample_config();
        let replay =
            DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
        let verification = replay
            .evaluate_verification_path(office_control_experiment(), &verification_dir)
            .await
            .unwrap();
        let shadow = replay
            .evaluate_shadow_path(office_control_experiment(), &shadow_dir)
            .await
            .unwrap();
        let proof_harness =
            DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proofs_dir)
                .unwrap();
        let proof = proof_harness
            .create_proof(
                office_control_experiment(),
                &verification_dir,
                &verification.report.verification_id,
            )
            .unwrap();
        let scorecards = DefaultStrategyScorecardHarness::from_config(
            "inline",
            config.clone(),
            &memory_dir,
            &scorecard_dir,
        )
        .unwrap();
        let queue = DefaultEvolutionQueueHarness::from_config("inline", config.clone(), &queue_dir)
            .unwrap();
        let proposal = queue
            .create_proposal(
                &replay,
                &scorecards,
                EvolutionProposalCreateRequest {
                    experiment_path: office_control_experiment(),
                    experiment_results_dir: experiment_dir.clone(),
                    verification_results_dir: verification_dir.clone(),
                    verification_id: verification.report.verification_id.clone(),
                    proof_results_dir: proofs_dir.clone(),
                    proof_id: proof.report.proof_id.clone(),
                },
            )
            .await
            .unwrap();
        let accepted = queue
            .record_decision(
                &proposal.report.proposal_id,
                EvolutionProposalDecisionAction::AcceptForCanary,
                "ready for queue handoff",
            )
            .unwrap();
        let handoff_harness =
            DefaultEvolutionHandoffHarness::from_config("inline", config.clone(), &handoff_dir)
                .unwrap();
        let handoff = handoff_harness
            .create_handoff(
                &queue_dir,
                &accepted.report.proposal_id,
                &shadow_dir,
                &shadow.report.shadow_id,
            )
            .unwrap();
        let canary_harness =
            DefaultCanaryHarness::from_config("inline", config, &canary_dir).unwrap();

        let launched = handoff_harness
            .launch_canary(
                &canary_harness,
                &verification_dir,
                &shadow_dir,
                &handoff.report.handoff_id,
            )
            .unwrap();

        assert_eq!(
            launched.report.launch_status,
            EvolutionHandoffStatus::CanaryLaunched
        );
        assert!(launched.report.canary_run_id.is_some());
        let canary_run = canary_harness
            .load_run(launched.report.canary_run_id.as_deref().unwrap())
            .unwrap();
        assert!(canary_run.is_some());
    }
}
