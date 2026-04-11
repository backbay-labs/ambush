use crate::canary::{CanaryError, DefaultCanaryHarness};
use crate::config::{RuntimeConfigError, load_config};
use crate::evasion_coverage::{
    actionable_gaps_for_detector, evaluate_repo_evasion_coverage, resolve_repo_root,
};
use crate::replay::{
    DefaultReplayHarness, DetectorCandidateManifest, DetectorExperimentManifest,
    DetectorVerificationLookup, DetectorVerificationReport, ExperimentLineage, FileShadowStore,
    FileVerificationStore, ReplayExpectations, ReplayHarnessError, ReplayScenarioClass,
    ReplayScenarioInput, ReplayScenarioManifest, ReplayScenarioMetadata, ReplaySuiteManifest,
    ShadowStoreError, StrategyShadowLookup, StrategyShadowReport, VerificationCounterexample,
    VerificationStoreError, load_detector_experiment_manifest, load_replay_suite_manifest,
    load_scenario_manifest, load_verification_manifest, resolve_manifest_relative_path,
};
use crate::strategy::{
    DefaultStrategyScorecardHarness, StrategyAdvisorError, StrategyAdvisoryRecommendation,
    StrategyRolloutStateSummary, StrategyScorecard,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::{EvolutionAssuranceSolverStatusConfig, SwarmConfig};
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::AgentId;
use swarm_crypto::{
    DetachedSignature, Ed25519Signer, canonical_json_bytes, verify_detached_signature,
};
#[cfg(feature = "z3")]
use z3::{Config as Z3Config, Params as Z3Params, SatResult, Solver as Z3Solver, with_z3_config};

const DEFAULT_Z3_TIMEOUT_MS: u64 = 30_000;

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
    AssuranceCaseStore(#[from] EvolutionAssuranceCaseStoreError),

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

    #[error("proposal `{proposal_id}` cannot attach an assurance waiver: {reason}")]
    InvalidAssuranceWaiver { proposal_id: String, reason: String },

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

/// Durable status captured for one solver-backed invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionSolverProofStatus {
    Proved,
    Counterexample,
    Timeout,
    Disabled,
    Error,
}

/// One machine-readable solver model binding captured from a failing proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionSolverCounterexample {
    pub name: String,
    pub value: String,
}

/// Durable solver artifact for one `custom_z3` invariant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionSolverInvariantArtifact {
    pub invariant_name: String,
    pub solver: String,
    pub status: EvolutionSolverProofStatus,
    pub timeout_ms: u64,
    pub duration_ms: u64,
    pub compiled_query_sha256: String,
    pub attestation_sha256: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub counterexamples: Vec<EvolutionSolverCounterexample>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_unknown: Option<String>,
}

/// Aggregate solver proof summary persisted alongside the main proof artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionSolverProofSummary {
    pub status: EvolutionSolverProofStatus,
    pub invariant_count: usize,
    pub proved_count: usize,
    pub counterexample_invariant_count: usize,
    pub counterexample_binding_count: usize,
    pub timed_out_count: usize,
    pub disabled_count: usize,
    pub error_count: usize,
    pub timeout_ms: u64,
    pub proof_signature_sha256: String,
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
    pub strategy_genome_sha256: String,
    pub verification_report_sha256: String,
    pub lineage_sha256: String,
    pub attestation_sha256: String,
    pub invariants: Vec<EvolutionProofInvariant>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub formal_safety_bundle_sha256: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub solver_summary: Option<EvolutionSolverProofSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub solver_artifacts: Vec<EvolutionSolverInvariantArtifact>,
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

/// One repo-owned safety invariant bundle loaded for formal canary admission.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FormalSafetyInvariantBundle {
    pub schema_version: u32,
    pub name: String,
    pub description: String,
    pub invariants: Vec<FormalSafetyInvariantSpec>,
}

/// Deterministic safety invariant definitions used during admission.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FormalSafetyInvariantSpec {
    CoverageFloor {
        name: String,
        corpus_path: String,
        source: FormalSafetyCoverageSource,
        min_ratio: f64,
    },
    FpCeiling {
        name: String,
        corpus_path: String,
        max_rate: f64,
    },
    LatencyBudget {
        name: String,
        corpus_path: String,
        max_detect_latency_us: u64,
    },
    ParameterBounds {
        name: String,
        json_pointer: String,
        min: Option<f64>,
        max: Option<f64>,
    },
    CustomZ3 {
        name: String,
        query: String,
    },
}

/// Coverage source derived from the replay verification artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FormalSafetyCoverageSource {
    KnownBadCoverage,
    ThreatClassTemplates,
}

/// Candidate genome and supporting artifacts presented to the formal safety gate.
#[derive(Debug, Clone)]
pub struct StrategyGenome {
    pub strategy_id: String,
    pub experiment_path: PathBuf,
    pub experiment: DetectorExperimentManifest,
    pub verification: DetectorVerificationReport,
    pub shadow: StrategyShadowReport,
}

/// One evaluated formal-safety invariant verdict.
#[derive(Debug, Clone)]
pub struct FormalSafetyInvariantVerdict {
    pub name: String,
    pub passed: bool,
    pub details: String,
    pub counterexamples: Vec<VerificationCounterexample>,
}

/// Full formal-safety decision over one candidate genome.
#[derive(Debug, Clone)]
pub struct FormalSafetyVerificationReport {
    pub passed: bool,
    pub bundle_paths: Vec<String>,
    pub bundle_sha256: Vec<String>,
    pub invariants: Vec<FormalSafetyInvariantVerdict>,
    pub persisted_proof_id: Option<String>,
    pub solver_summary: Option<EvolutionSolverProofSummary>,
}

/// Errors raised while evaluating repo-owned formal safety bundles.
#[derive(Debug, thiserror::Error)]
pub enum FormalSafetyGateError {
    #[error(transparent)]
    Replay(#[from] ReplayHarnessError),

    #[error(transparent)]
    Serialization(#[from] serde_json::Error),

    #[error(transparent)]
    ProofStore(#[from] EvolutionProofStoreError),

    #[error("failed to read formal safety bundle `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse formal safety bundle `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("invalid formal safety bundle `{path}`: {reason}")]
    Validation { path: PathBuf, reason: String },
}

#[derive(Debug, Clone)]
struct FormalSafetyInvariantEvaluation {
    verdict: FormalSafetyInvariantVerdict,
    solver_artifact: Option<EvolutionSolverInvariantArtifact>,
}

/// Deterministic repo-owned gate used before canary admission.
pub trait FormalSafetyGate: Send + Sync {
    fn verify(
        &self,
        candidate: &StrategyGenome,
    ) -> Result<FormalSafetyVerificationReport, FormalSafetyGateError>;
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

    pub fn records(&self) -> Result<Vec<EvolutionProofRecord>, EvolutionProofStoreError> {
        Ok(self.read_index()?.entries)
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

    pub fn latest(&self) -> Result<Option<EvolutionProofLookup>, EvolutionProofStoreError> {
        let Some(record) = self.read_index()?.entries.into_iter().next() else {
            return Ok(None);
        };
        self.load(&record.proof_id)
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
    ApplyAssuranceWaiver,
    Defer,
    Reject,
}

/// Effective rollout state derived from assurance plus any active bounded waiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionAssuranceRolloutState {
    Clear,
    Waived,
    Blocked,
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

/// Assurance decision attached to one queued proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionProposalAssuranceDecision {
    Passed,
    Blocked,
}

/// Coverage-focused assurance evidence attached to a queued proposal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionProposalAssuranceCoverageSummary {
    pub detector: String,
    pub suite_name: Option<String>,
    pub corpus_version: Option<String>,
    pub required_catch_rate: f64,
    pub actual_catch_rate: Option<f64>,
    pub actionable_gap_count: usize,
}

/// Solver-focused assurance evidence attached to a queued proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionProposalAssuranceSolverSummary {
    pub required: bool,
    pub status: Option<EvolutionSolverProofStatus>,
    pub allowed_statuses: Vec<EvolutionSolverProofStatus>,
}

/// Shared assurance summary persisted alongside one queued proposal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionProposalAssuranceSummary {
    pub decision: EvolutionProposalAssuranceDecision,
    pub coverage: EvolutionProposalAssuranceCoverageSummary,
    pub solver: EvolutionProposalAssuranceSolverSummary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub harvested_case_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiver: Option<EvolutionAssuranceWaiverSummary>,
}

/// Signed bounded waiver attached to one blocked assurance decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionAssuranceWaiverSummary {
    pub waiver_id: String,
    pub operator_id: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub reason: String,
    pub waived_gap_count: usize,
    pub assurance_sha256: String,
    pub signature: DetachedSignature,
}

/// Signed waiver request that can override one blocked assurance decision.
#[derive(Debug, Clone)]
pub struct EvolutionAssuranceWaiverRequest {
    pub operator_id: String,
    pub secret_material: String,
    pub reason: String,
    pub ttl_secs: u64,
}

#[derive(Debug, Serialize)]
struct EvolutionAssuranceWaiverPayload<'a> {
    waiver_id: &'a str,
    operator_id: &'a str,
    issued_at_ms: i64,
    expires_at_ms: i64,
    reason: &'a str,
    waived_gap_count: usize,
    assurance_sha256: &'a str,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance: Option<EvolutionProposalAssuranceSummary>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance: Option<EvolutionProposalAssuranceSummary>,
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

/// Type of durable assurance case harvested from a blocked proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EvolutionAssuranceCaseKind {
    CoverageGap,
    SolverCounterexample,
}

/// Durable replay-ready assurance case persisted for one blocked proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EvolutionAssuranceCaseReport {
    case_id: String,
    proposal_id: String,
    created_at_ms: i64,
    strategy_id: String,
    detector: String,
    kind: EvolutionAssuranceCaseKind,
    scenario_name: String,
    scenario_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    suite_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    corpus_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verification_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof_id: Option<String>,
    reason_name: String,
    reason_details: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    threat_class: Option<ThreatClass>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    techniques: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    counterexample_bindings: Vec<EvolutionSolverCounterexample>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    source_references: Vec<String>,
}

/// Index metadata surfaced for one persisted assurance case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EvolutionAssuranceCaseRecord {
    case_id: String,
    proposal_id: String,
    detector: String,
    kind: EvolutionAssuranceCaseKind,
    created_at_ms: i64,
    scenario_path: String,
    bundle_path: String,
}

impl EvolutionAssuranceCaseRecord {
    fn from_report(report: &EvolutionAssuranceCaseReport, bundle_path: String) -> Self {
        Self {
            case_id: report.case_id.clone(),
            proposal_id: report.proposal_id.clone(),
            detector: report.detector.clone(),
            kind: report.kind,
            created_at_ms: report.created_at_ms,
            scenario_path: report.scenario_path.clone(),
            bundle_path,
        }
    }
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

/// Errors raised by the persisted assurance-case store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionAssuranceCaseStoreError {
    #[error("failed to read evolution assurance-case store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution assurance-case store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution assurance-case store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("failed to encode evolution assurance-case scenario `{path}`: {source}")]
    ScenarioEncode {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
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

/// File-backed store for durable replay-ready assurance cases.
#[derive(Debug, Clone)]
struct FileEvolutionAssuranceCaseStore {
    root: PathBuf,
}

impl FileEvolutionAssuranceCaseStore {
    fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionAssuranceCaseStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionAssuranceCaseStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        fs::create_dir_all(root.join("scenarios")).map_err(|source| {
            EvolutionAssuranceCaseStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, case_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(case_id)))
    }

    fn scenario_path(&self, case_id: &str) -> PathBuf {
        self.root
            .join("scenarios")
            .join(format!("{}.yaml", sanitize_id(case_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<EvolutionAssuranceCaseIndex, EvolutionAssuranceCaseStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionAssuranceCaseIndex::default());
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| EvolutionAssuranceCaseStoreError::Read {
                path: path.clone(),
                source,
            })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionAssuranceCaseStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionAssuranceCaseIndex,
    ) -> Result<(), EvolutionAssuranceCaseStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionAssuranceCaseStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| EvolutionAssuranceCaseStoreError::Write { path, source })
    }

    fn persist(
        &self,
        report: &EvolutionAssuranceCaseReport,
        scenario: &ReplayScenarioManifest,
    ) -> Result<EvolutionAssuranceCaseRecord, EvolutionAssuranceCaseStoreError> {
        let scenario_path = self.scenario_path(&report.case_id);
        let mut report = report.clone();
        report.scenario_path = scenario_path.display().to_string();

        let scenario_raw = serde_yaml::to_string(scenario).map_err(|source| {
            EvolutionAssuranceCaseStoreError::ScenarioEncode {
                path: scenario_path.clone(),
                source,
            }
        })?;
        fs::write(&scenario_path, scenario_raw).map_err(|source| {
            EvolutionAssuranceCaseStoreError::Write {
                path: scenario_path.clone(),
                source,
            }
        })?;

        let report_path = self.report_path(&report.case_id);
        let report_raw = serde_json::to_string_pretty(&report).map_err(|source| {
            EvolutionAssuranceCaseStoreError::Parse {
                path: report_path.clone(),
                source,
            }
        })?;
        fs::write(&report_path, report_raw).map_err(|source| {
            EvolutionAssuranceCaseStoreError::Write {
                path: report_path.clone(),
                source,
            }
        })?;

        let mut index = self.read_index()?;
        let record =
            EvolutionAssuranceCaseRecord::from_report(&report, report_path.display().to_string());
        index
            .entries
            .retain(|entry| entry.case_id != record.case_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
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
#[derive(Debug, Clone)]
pub struct DefaultFormalSafetyGate {
    config_path: PathBuf,
    config: SwarmConfig,
}

pub struct DefaultEvolutionProofHarness {
    pub config_path: PathBuf,
    pub config: SwarmConfig,
    pub store: FileEvolutionProofStore,
}

impl DefaultFormalSafetyGate {
    pub fn from_path(config_path: impl AsRef<Path>) -> Result<Self, FormalSafetyGateError> {
        let config_path = config_path.as_ref();
        let config =
            load_config(config_path).map_err(|error| FormalSafetyGateError::Validation {
                path: config_path.to_path_buf(),
                reason: error.to_string(),
            })?;
        Ok(Self {
            config_path: config_path.to_path_buf(),
            config,
        })
    }

    pub fn from_config(config_path: impl Into<PathBuf>, config: SwarmConfig) -> Self {
        Self {
            config_path: config_path.into(),
            config,
        }
    }

    fn load_bundles(
        &self,
    ) -> Result<Vec<(PathBuf, FormalSafetyInvariantBundle, String)>, FormalSafetyGateError> {
        let mut bundles = Vec::new();
        for bundle_path in &self.config.evolution.safety_gate.invariant_bundle_paths {
            let resolved = resolve_config_relative_path(&self.config_path, bundle_path);
            let raw =
                fs::read_to_string(&resolved).map_err(|source| FormalSafetyGateError::Read {
                    path: resolved.clone(),
                    source,
                })?;
            let bundle: FormalSafetyInvariantBundle =
                serde_yaml::from_str(&raw).map_err(|source| FormalSafetyGateError::Parse {
                    path: resolved.clone(),
                    source,
                })?;
            validate_formal_safety_bundle(&resolved, &bundle)?;
            let bundle_hash = sha256_hex(&bundle)?;
            bundles.push((resolved, bundle, bundle_hash));
        }
        Ok(bundles)
    }

    fn persist_formal_safety_proof(
        &self,
        candidate: &StrategyGenome,
        bundle_sha256: &[String],
        verdicts: &[FormalSafetyInvariantVerdict],
        solver_summary: Option<&EvolutionSolverProofSummary>,
        solver_artifacts: &[EvolutionSolverInvariantArtifact],
    ) -> Result<EvolutionProofLookup, FormalSafetyGateError> {
        let proofs_dir = resolve_config_relative_path(
            &self.config_path,
            &self.config.evolution.paths.evolution_proof_results_dir,
        );
        let store = FileEvolutionProofStore::open(&proofs_dir)?;
        let experiment_manifest_sha256 = sha256_hex(&candidate.experiment)?;
        let verification_report_sha256 = sha256_hex(&candidate.verification)?;
        let lineage_sha256 = sha256_hex(&candidate.experiment.lineage)?;
        let created_at_ms = now_ms();
        let invariants = verdicts
            .iter()
            .map(|verdict| EvolutionProofInvariant {
                name: verdict.name.clone(),
                claim: if verdict.passed {
                    format!("formal safety invariant `{}` passed", verdict.name)
                } else {
                    format!("formal safety invariant `{}` failed", verdict.name)
                },
                details: verdict.details.clone(),
                counterexamples: verdict.counterexamples.clone(),
            })
            .collect::<Vec<_>>();
        let attestation_sha256 = sha256_hex(&ProofAttestationPayload {
            experiment_manifest_sha256: experiment_manifest_sha256.clone(),
            verification_report_sha256: verification_report_sha256.clone(),
            lineage_sha256: lineage_sha256.clone(),
            invariant_names: invariants.iter().map(|entry| entry.name.clone()).collect(),
            solver_signature_sha256: solver_summary
                .map(|summary| summary.proof_signature_sha256.clone()),
            solver_artifact_attestations: solver_artifacts
                .iter()
                .map(|artifact| artifact.attestation_sha256.clone())
                .collect(),
        })?;
        let report = EvolutionProofReport {
            proof_id: proof_id(
                &candidate.experiment.name,
                candidate.experiment.candidate.strategy_id(),
                created_at_ms,
            ),
            experiment_id: experiment_id_for_manifest(&candidate.experiment),
            experiment_name: candidate.experiment.name.clone(),
            verification_id: candidate.verification.verification_id.clone(),
            created_at_ms,
            strategy_id: candidate.experiment.candidate.strategy_id().to_string(),
            candidate_description: candidate.experiment.candidate.description().to_string(),
            lineage: candidate.experiment.lineage.clone(),
            corpus_name: candidate.verification.corpus_name.clone(),
            proof_system: if solver_summary.is_some() {
                "formal_safety_gate_v2+z3_smt_v1".to_string()
            } else {
                "formal_safety_gate_v2".to_string()
            },
            experiment_manifest_sha256,
            strategy_genome_sha256: sha256_hex(&candidate.experiment.candidate)?,
            verification_report_sha256,
            lineage_sha256,
            attestation_sha256,
            invariants,
            formal_safety_bundle_sha256: bundle_sha256.to_vec(),
            solver_summary: solver_summary.cloned(),
            solver_artifacts: solver_artifacts.to_vec(),
        };
        let record = store.persist(&report)?;
        Ok(EvolutionProofLookup { record, report })
    }
}

impl FormalSafetyGate for DefaultFormalSafetyGate {
    fn verify(
        &self,
        candidate: &StrategyGenome,
    ) -> Result<FormalSafetyVerificationReport, FormalSafetyGateError> {
        let bundles = self.load_bundles()?;
        let verification_manifest =
            load_verification_manifest(&candidate.verification.corpus_path)?;
        let candidate_value = serde_json::to_value(&candidate.experiment)?;
        let mut verdicts = Vec::new();
        let mut solver_artifacts = Vec::new();
        let mut bundle_paths = Vec::new();
        let mut bundle_sha256 = Vec::new();

        for (bundle_path, bundle, bundle_hash) in bundles {
            bundle_paths.push(bundle_path.display().to_string());
            bundle_sha256.push(bundle_hash);
            for invariant in &bundle.invariants {
                let evaluation = evaluate_formal_safety_invariant(
                    &bundle_path,
                    invariant,
                    candidate,
                    &verification_manifest,
                    &candidate_value,
                    self.config.evolution.safety_gate.enable_z3,
                )?;
                if let Some(artifact) = evaluation.solver_artifact {
                    solver_artifacts.push(artifact);
                }
                verdicts.push(evaluation.verdict);
            }
        }

        let solver_summary = summarize_solver_artifacts(&solver_artifacts)?;
        let persisted_proof_id = if solver_summary.is_some() {
            Some(
                self.persist_formal_safety_proof(
                    candidate,
                    &bundle_sha256,
                    &verdicts,
                    solver_summary.as_ref(),
                    &solver_artifacts,
                )?
                .record
                .proof_id,
            )
        } else {
            None
        };

        Ok(FormalSafetyVerificationReport {
            passed: verdicts.iter().all(|verdict| verdict.passed),
            bundle_paths,
            bundle_sha256,
            invariants: verdicts,
            persisted_proof_id,
            solver_summary,
        })
    }
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
            solver_signature_sha256: None,
            solver_artifact_attestations: Vec::new(),
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
            experiment_manifest_sha256: experiment_manifest_sha256.clone(),
            strategy_genome_sha256: experiment_manifest_sha256,
            verification_report_sha256,
            lineage_sha256,
            attestation_sha256,
            invariants,
            formal_safety_bundle_sha256: Vec::new(),
            solver_summary: None,
            solver_artifacts: Vec::new(),
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
        let proposal_id = proposal_id(
            &manifest.name,
            manifest.candidate.strategy_id(),
            created_at_ms,
        );
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
        let mut assurance = evaluate_proposal_assurance(
            &self.config_path,
            &self.config,
            &manifest,
            proof.as_ref().map(|lookup| &lookup.report),
            &mut blocking_reasons,
        );
        assurance.harvested_case_ids = persist_harvested_assurance_cases(
            &self.config_path,
            &self.config,
            &proposal_id,
            created_at_ms,
            &manifest,
            verification.as_ref(),
            proof.as_ref().map(|lookup| &lookup.report),
            &assurance,
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
            proposal_id,
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
            assurance: Some(assurance),
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
        if action == EvolutionProposalDecisionAction::ApplyAssuranceWaiver {
            return Err(EvolutionQueueError::InvalidDecision {
                proposal_id: proposal_id.to_string(),
                state: "n/a".to_string(),
                decision: decision_action_label(action).to_string(),
                reason: "use apply_assurance_waiver to attach a signed bounded waiver".to_string(),
            });
        }
        let mut lookup =
            self.store
                .load(proposal_id)?
                .ok_or_else(|| EvolutionQueueError::ProposalNotFound {
                    proposal_id: proposal_id.to_string(),
                })?;
        let current_time_ms = now_ms();

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
            ) => unreachable!("waiver decisions are handled before state transition matching"),
            (
                EvolutionProposalReviewState::PendingReview,
                EvolutionProposalDecisionAction::AcceptForCanary,
            )
            | (
                EvolutionProposalReviewState::Deferred,
                EvolutionProposalDecisionAction::AcceptForCanary,
            )
            | (
                EvolutionProposalReviewState::Blocked,
                EvolutionProposalDecisionAction::AcceptForCanary,
            ) => {
                if lookup.report.proof_status != EvolutionProposalProofStatus::Proved
                    || proposal_has_active_blocking_reasons(
                        &lookup.report,
                        &self.config,
                        current_time_ms,
                    )
                {
                    return Err(EvolutionQueueError::InvalidDecision {
                        proposal_id: proposal_id.to_string(),
                        state: review_state_label(lookup.report.review_state).to_string(),
                        decision: decision_action_label(action).to_string(),
                        reason:
                            "only proof-backed proposals with satisfied or actively waived assurance and no active blocking reasons can be accepted for canary"
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
                    reason:
                        "blocked proposals may only be explicitly rejected unless an active assurance waiver clears rollout blockers"
                            .to_string(),
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

    pub fn apply_assurance_waiver(
        &self,
        proposal_id: &str,
        request: EvolutionAssuranceWaiverRequest,
    ) -> Result<EvolutionProposalLookup, EvolutionQueueError> {
        let mut lookup =
            self.store
                .load(proposal_id)?
                .ok_or_else(|| EvolutionQueueError::ProposalNotFound {
                    proposal_id: proposal_id.to_string(),
                })?;
        let assurance = lookup.report.assurance.as_mut().ok_or_else(|| {
            EvolutionQueueError::InvalidAssuranceWaiver {
                proposal_id: proposal_id.to_string(),
                reason: "proposal does not carry assurance lineage".to_string(),
            }
        })?;
        if assurance.decision != EvolutionProposalAssuranceDecision::Blocked {
            return Err(EvolutionQueueError::InvalidAssuranceWaiver {
                proposal_id: proposal_id.to_string(),
                reason: "only blocked assurance decisions can be waived".to_string(),
            });
        }
        if request.reason.trim().is_empty() {
            return Err(EvolutionQueueError::InvalidAssuranceWaiver {
                proposal_id: proposal_id.to_string(),
                reason: "waiver reason must not be empty".to_string(),
            });
        }
        if request.ttl_secs == 0 {
            return Err(EvolutionQueueError::InvalidAssuranceWaiver {
                proposal_id: proposal_id.to_string(),
                reason: "waiver ttl must be greater than zero".to_string(),
            });
        }
        if request.ttl_secs > self.config.evolution.assurance.waiver.max_ttl_secs {
            return Err(EvolutionQueueError::InvalidAssuranceWaiver {
                proposal_id: proposal_id.to_string(),
                reason: format!(
                    "waiver ttl {} exceeds configured maximum {}",
                    request.ttl_secs, self.config.evolution.assurance.waiver.max_ttl_secs
                ),
            });
        }
        if assurance.coverage.actionable_gap_count
            > self
                .config
                .evolution
                .assurance
                .waiver
                .max_actionable_gap_count
        {
            return Err(EvolutionQueueError::InvalidAssuranceWaiver {
                proposal_id: proposal_id.to_string(),
                reason: format!(
                    "assurance gap count {} exceeds configured waiver limit {}",
                    assurance.coverage.actionable_gap_count,
                    self.config
                        .evolution
                        .assurance
                        .waiver
                        .max_actionable_gap_count
                ),
            });
        }

        let signer = Ed25519Signer::from_secret_material(&request.secret_material);
        let expected_operator_id =
            AgentId::from_public_key_hex(signer.public_key_hex()).to_string();
        if request.operator_id != expected_operator_id {
            return Err(EvolutionQueueError::InvalidAssuranceWaiver {
                proposal_id: proposal_id.to_string(),
                reason: format!(
                    "waiver operator `{}` does not match signer identity `{}`",
                    request.operator_id, expected_operator_id
                ),
            });
        }
        if !self
            .config
            .evolution
            .assurance
            .waiver
            .allowed_operator_ids
            .iter()
            .any(|candidate| candidate == &request.operator_id)
        {
            return Err(EvolutionQueueError::InvalidAssuranceWaiver {
                proposal_id: proposal_id.to_string(),
                reason: format!(
                    "operator `{}` is not allowed to issue assurance waivers",
                    request.operator_id
                ),
            });
        }

        let waiver = build_assurance_waiver_summary(
            proposal_id,
            assurance,
            &request.operator_id,
            &signer,
            now_ms(),
            request.ttl_secs,
            &request.reason,
        )
        .map_err(|reason| EvolutionQueueError::InvalidAssuranceWaiver {
            proposal_id: proposal_id.to_string(),
            reason,
        })?;
        assurance.waiver = Some(waiver.clone());
        lookup
            .report
            .decision_history
            .push(EvolutionProposalDecisionRecord {
                decided_at_ms: now_ms(),
                action: EvolutionProposalDecisionAction::ApplyAssuranceWaiver,
                reason: format!(
                    "{} | operator={} | waiver_id={} | expires_at={}",
                    request.reason.trim(),
                    waiver.operator_id,
                    waiver.waiver_id,
                    waiver.expires_at_ms
                ),
            });

        let record = self.store.persist(&lookup.report)?;
        Ok(EvolutionProposalLookup {
            record,
            report: lookup.report,
        })
    }
}

fn evaluate_proposal_assurance(
    config_path: &Path,
    config: &SwarmConfig,
    manifest: &DetectorExperimentManifest,
    proof: Option<&EvolutionProofReport>,
    blocking_reasons: &mut Vec<EvolutionProposalBlockingReason>,
) -> EvolutionProposalAssuranceSummary {
    let detector = assurance_detector_id(&manifest.candidate).to_string();
    let required_catch_rate = config
        .evolution
        .assurance
        .coverage_overrides
        .iter()
        .find(|override_config| override_config.detector == detector)
        .map(|override_config| override_config.min_catch_rate)
        .unwrap_or(config.evolution.assurance.min_detector_catch_rate);
    let mut assurance_blocked = false;
    let (suite_name, corpus_version, actual_catch_rate, actionable_gap_count) =
        match evaluate_repo_evasion_coverage(config, &resolve_repo_root(config_path)) {
            Ok(snapshot) => {
                let actionable_gap_count = actionable_gaps_for_detector(&snapshot, &detector).len();
                match snapshot
                    .detectors
                    .iter()
                    .find(|entry| entry.detector == detector)
                {
                    Some(report) => {
                        if report.catch_rate < required_catch_rate {
                            assurance_blocked = true;
                            blocking_reasons.push(EvolutionProposalBlockingReason {
                                source: "assurance".to_string(),
                                name: "coverage_floor_not_met".to_string(),
                                details: format!(
                                    "detector `{}` catch rate {:.3} is below assurance floor {:.3}",
                                    detector, report.catch_rate, required_catch_rate
                                ),
                                references: vec![
                                    snapshot.suite_name.clone(),
                                    snapshot.corpus_version.clone(),
                                ],
                            });
                        }
                        (
                            Some(snapshot.suite_name),
                            Some(snapshot.corpus_version),
                            Some(report.catch_rate),
                            actionable_gap_count,
                        )
                    }
                    None => {
                        assurance_blocked = true;
                        blocking_reasons.push(EvolutionProposalBlockingReason {
                            source: "assurance".to_string(),
                            name: "missing_detector_coverage".to_string(),
                            details: format!(
                                "repo-owned evasion coverage does not include detector `{}`",
                                detector
                            ),
                            references: vec![detector.clone()],
                        });
                        (
                            Some(snapshot.suite_name),
                            Some(snapshot.corpus_version),
                            None,
                            actionable_gap_count,
                        )
                    }
                }
            }
            Err(error) => {
                assurance_blocked = true;
                blocking_reasons.push(EvolutionProposalBlockingReason {
                    source: "assurance".to_string(),
                    name: "coverage_evaluation_failed".to_string(),
                    details: error.to_string(),
                    references: vec![detector.clone()],
                });
                (None, None, None, 0)
            }
        };

    let allowed_solver_statuses = config
        .evolution
        .assurance
        .allowed_solver_statuses
        .iter()
        .copied()
        .map(map_assurance_solver_status)
        .collect::<Vec<_>>();
    let solver_status =
        proof.and_then(|report| report.solver_summary.as_ref().map(|summary| summary.status));
    if let Some(status) = solver_status {
        if !allowed_solver_statuses.contains(&status) {
            assurance_blocked = true;
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "assurance".to_string(),
                name: "solver_status_not_allowed".to_string(),
                details: format!(
                    "solver proof status `{}` is not allowed by assurance policy",
                    solver_proof_status_label(status)
                ),
                references: proof
                    .map(|report| report.proof_id.clone())
                    .into_iter()
                    .collect(),
            });
        }
    } else if config.evolution.assurance.require_solver_summary {
        assurance_blocked = true;
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "assurance".to_string(),
            name: "missing_solver_summary".to_string(),
            details: "assurance policy requires a solver proof summary".to_string(),
            references: proof
                .map(|report| report.proof_id.clone())
                .into_iter()
                .collect(),
        });
    }

    EvolutionProposalAssuranceSummary {
        decision: if assurance_blocked {
            EvolutionProposalAssuranceDecision::Blocked
        } else {
            EvolutionProposalAssuranceDecision::Passed
        },
        coverage: EvolutionProposalAssuranceCoverageSummary {
            detector,
            suite_name,
            corpus_version,
            required_catch_rate,
            actual_catch_rate,
            actionable_gap_count,
        },
        solver: EvolutionProposalAssuranceSolverSummary {
            required: config.evolution.assurance.require_solver_summary,
            status: solver_status,
            allowed_statuses: allowed_solver_statuses,
        },
        harvested_case_ids: Vec::new(),
        waiver: None,
    }
}

fn assurance_detector_id(candidate: &DetectorCandidateManifest) -> &'static str {
    match candidate {
        DetectorCandidateManifest::SuspiciousProcessTree { .. } => "suspicious_process_tree",
        DetectorCandidateManifest::FilelessExecution { .. } => "fileless_execution",
        DetectorCandidateManifest::BehavioralAnomaly { .. } => "behavioral_anomaly",
        DetectorCandidateManifest::DnsExfiltration { .. } => "dns_exfiltration",
        DetectorCandidateManifest::LateralMovement { .. } => "lateral_movement",
        DetectorCandidateManifest::CredentialAccess { .. } => "credential_access",
        DetectorCandidateManifest::SuspiciousScripting { .. } => "suspicious_scripting",
        DetectorCandidateManifest::Persistence { .. } => "persistence",
        DetectorCandidateManifest::SupplyChain { .. } => "supply_chain",
        DetectorCandidateManifest::NetworkConnect { .. } => "network_connect",
    }
}

#[allow(clippy::too_many_arguments)]
fn persist_harvested_assurance_cases(
    config_path: &Path,
    config: &SwarmConfig,
    proposal_id: &str,
    created_at_ms: i64,
    manifest: &DetectorExperimentManifest,
    verification: Option<&DetectorVerificationLookup>,
    proof: Option<&EvolutionProofReport>,
    assurance: &EvolutionProposalAssuranceSummary,
) -> Result<Vec<String>, EvolutionQueueError> {
    if assurance.decision != EvolutionProposalAssuranceDecision::Blocked {
        return Ok(Vec::new());
    }

    let store = FileEvolutionAssuranceCaseStore::open(resolve_config_relative_path(
        config_path,
        &config.evolution.assurance.harvest.results_dir,
    ))?;
    let mut harvested_case_ids = Vec::new();
    let mut remaining_budget = config.evolution.assurance.harvest.max_cases_per_proposal;

    if remaining_budget > 0 {
        let coverage_cases = harvest_coverage_gap_cases(
            &store,
            config_path,
            config,
            proposal_id,
            created_at_ms,
            manifest,
            verification,
            proof,
            assurance,
            remaining_budget,
        )?;
        remaining_budget = remaining_budget.saturating_sub(coverage_cases.len());
        harvested_case_ids.extend(coverage_cases);
    }

    if remaining_budget > 0 {
        harvested_case_ids.extend(harvest_solver_counterexample_cases(
            &store,
            proposal_id,
            created_at_ms,
            manifest,
            verification,
            proof,
            assurance,
            remaining_budget,
        )?);
    }

    Ok(harvested_case_ids)
}

#[allow(clippy::too_many_arguments)]
fn harvest_coverage_gap_cases(
    store: &FileEvolutionAssuranceCaseStore,
    config_path: &Path,
    config: &SwarmConfig,
    proposal_id: &str,
    created_at_ms: i64,
    manifest: &DetectorExperimentManifest,
    verification: Option<&DetectorVerificationLookup>,
    proof: Option<&EvolutionProofReport>,
    assurance: &EvolutionProposalAssuranceSummary,
    max_cases: usize,
) -> Result<Vec<String>, EvolutionQueueError> {
    let coverage_blocked = assurance
        .coverage
        .actual_catch_rate
        .map(|actual| actual < assurance.coverage.required_catch_rate)
        .unwrap_or(true);
    if !coverage_blocked || assurance.coverage.actionable_gap_count == 0 || max_cases == 0 {
        return Ok(Vec::new());
    }

    let snapshot = match evaluate_repo_evasion_coverage(config, &resolve_repo_root(config_path)) {
        Ok(snapshot) => snapshot,
        Err(_) => return Ok(Vec::new()),
    };
    let gaps = actionable_gaps_for_detector(&snapshot, &assurance.coverage.detector);
    if gaps.is_empty() {
        return Ok(Vec::new());
    }

    let suite_path = normalize_existing_path(PathBuf::from(&snapshot.suite_path));
    let suite = load_replay_suite_manifest(&suite_path)?;
    let mut harvested_case_ids = Vec::new();

    for gap in gaps {
        for scenario_ref in &suite.scenarios {
            if harvested_case_ids.len() >= max_cases {
                return Ok(harvested_case_ids);
            }
            let source_path = resolve_manifest_relative_path(&suite_path, scenario_ref);
            let loaded = load_scenario_manifest(&source_path)?;
            if loaded.manifest.metadata.class != ReplayScenarioClass::Adversarial {
                continue;
            }
            if loaded.manifest.metadata.threat_class.as_ref() != Some(&gap.threat_class) {
                continue;
            }
            if !has_actionable_technique(
                &loaded.manifest.metadata.techniques,
                &gap.actionable_techniques,
            ) {
                continue;
            }

            let case_id = assurance_case_id(
                proposal_id,
                EvolutionAssuranceCaseKind::CoverageGap,
                &loaded.manifest.name,
                harvested_case_ids.len(),
            );
            let scenario = harvested_coverage_gap_scenario(
                &case_id,
                created_at_ms,
                &loaded.manifest,
                proposal_id,
                verification.map(|lookup| lookup.report.verification_id.as_str()),
                proof.map(|report| report.proof_id.as_str()),
                &assurance.coverage.detector,
                config.evolution.assurance.harvest.max_events_per_case,
            );
            let report = EvolutionAssuranceCaseReport {
                case_id: case_id.clone(),
                proposal_id: proposal_id.to_string(),
                created_at_ms,
                strategy_id: manifest.candidate.strategy_id().to_string(),
                detector: assurance.coverage.detector.clone(),
                kind: EvolutionAssuranceCaseKind::CoverageGap,
                scenario_name: scenario.name.clone(),
                scenario_path: String::new(),
                suite_name: assurance.coverage.suite_name.clone(),
                corpus_version: assurance.coverage.corpus_version.clone(),
                verification_id: verification.map(|lookup| lookup.report.verification_id.clone()),
                proof_id: proof.map(|report| report.proof_id.clone()),
                reason_name: "coverage_gap".to_string(),
                reason_details: format!(
                    "scenario `{}` covers detector `{}` gap for {:?}",
                    loaded.manifest.name, assurance.coverage.detector, gap.threat_class
                ),
                threat_class: Some(gap.threat_class.clone()),
                techniques: loaded.manifest.metadata.techniques.clone(),
                counterexample_bindings: Vec::new(),
                source_references: coverage_case_references(
                    &source_path,
                    proposal_id,
                    verification,
                    proof,
                ),
            };
            store.persist(&report, &scenario)?;
            harvested_case_ids.push(case_id);
        }
    }

    Ok(harvested_case_ids)
}

#[allow(clippy::too_many_arguments)]
fn harvest_solver_counterexample_cases(
    store: &FileEvolutionAssuranceCaseStore,
    proposal_id: &str,
    created_at_ms: i64,
    manifest: &DetectorExperimentManifest,
    verification: Option<&DetectorVerificationLookup>,
    proof: Option<&EvolutionProofReport>,
    assurance: &EvolutionProposalAssuranceSummary,
    max_cases: usize,
) -> Result<Vec<String>, EvolutionQueueError> {
    let Some(verification) = verification else {
        return Ok(Vec::new());
    };
    let Some(proof) = proof else {
        return Ok(Vec::new());
    };
    if max_cases == 0 {
        return Ok(Vec::new());
    }

    let bundle_path = normalize_existing_path(PathBuf::from(&verification.record.bundle_path));
    let mut harvested_case_ids = Vec::new();
    for artifact in proof
        .solver_artifacts
        .iter()
        .filter(|artifact| !artifact.counterexamples.is_empty())
    {
        if harvested_case_ids.len() >= max_cases {
            break;
        }
        let case_id = assurance_case_id(
            proposal_id,
            EvolutionAssuranceCaseKind::SolverCounterexample,
            &artifact.invariant_name,
            harvested_case_ids.len(),
        );
        let scenario = harvested_solver_counterexample_scenario(
            &case_id,
            created_at_ms,
            &bundle_path,
            proposal_id,
            &proof.proof_id,
            &verification.report.verification_id,
            &assurance.coverage.detector,
            &artifact.invariant_name,
        );
        let report = EvolutionAssuranceCaseReport {
            case_id: case_id.clone(),
            proposal_id: proposal_id.to_string(),
            created_at_ms,
            strategy_id: manifest.candidate.strategy_id().to_string(),
            detector: assurance.coverage.detector.clone(),
            kind: EvolutionAssuranceCaseKind::SolverCounterexample,
            scenario_name: scenario.name.clone(),
            scenario_path: String::new(),
            suite_name: assurance.coverage.suite_name.clone(),
            corpus_version: assurance.coverage.corpus_version.clone(),
            verification_id: Some(verification.report.verification_id.clone()),
            proof_id: Some(proof.proof_id.clone()),
            reason_name: "solver_counterexample".to_string(),
            reason_details: format!(
                "solver invariant `{}` emitted {} counterexample bindings",
                artifact.invariant_name,
                artifact.counterexamples.len()
            ),
            threat_class: None,
            techniques: Vec::new(),
            counterexample_bindings: artifact.counterexamples.clone(),
            source_references: solver_case_references(&bundle_path, proposal_id, proof),
        };
        store.persist(&report, &scenario)?;
        harvested_case_ids.push(case_id);
    }

    Ok(harvested_case_ids)
}

#[allow(clippy::too_many_arguments)]
fn harvested_coverage_gap_scenario(
    case_id: &str,
    created_at_ms: i64,
    source: &ReplayScenarioManifest,
    proposal_id: &str,
    verification_id: Option<&str>,
    proof_id: Option<&str>,
    detector: &str,
    max_events_per_case: usize,
) -> ReplayScenarioManifest {
    let input = match &source.input {
        ReplayScenarioInput::Events { events } => ReplayScenarioInput::Events {
            events: events.iter().take(max_events_per_case).cloned().collect(),
        },
        ReplayScenarioInput::ReplayBundles { paths } => ReplayScenarioInput::ReplayBundles {
            paths: paths.clone(),
        },
    };
    let mut receipt_chain = source.receipt_chain.clone();
    push_unique_string(&mut receipt_chain, proposal_id.to_string());
    if let Some(verification_id) = verification_id {
        push_unique_string(&mut receipt_chain, verification_id.to_string());
    }
    if let Some(proof_id) = proof_id {
        push_unique_string(&mut receipt_chain, proof_id.to_string());
    }

    let mut metadata = source.metadata.clone();
    push_unique_string(&mut metadata.tags, "assurance_case".to_string());
    push_unique_string(&mut metadata.tags, "coverage_gap".to_string());
    push_unique_string(&mut metadata.tags, detector.to_string());
    push_unique_string(&mut metadata.tags, proposal_id.to_string());

    ReplayScenarioManifest {
        name: format!("{}-harvest", case_id),
        description: format!(
            "Harvested assurance coverage-gap replay derived from `{}`",
            source.name
        ),
        seed_time_ms: created_at_ms,
        requested_by: "evolution-assurance-harvest".to_string(),
        receipt_chain,
        metadata,
        input,
        expectations: source.expectations.clone(),
    }
}

#[allow(clippy::too_many_arguments)]
fn harvested_solver_counterexample_scenario(
    case_id: &str,
    created_at_ms: i64,
    bundle_path: &Path,
    proposal_id: &str,
    proof_id: &str,
    verification_id: &str,
    detector: &str,
    invariant_name: &str,
) -> ReplayScenarioManifest {
    let mut tags = Vec::new();
    push_unique_string(&mut tags, "assurance_case".to_string());
    push_unique_string(&mut tags, "solver_counterexample".to_string());
    push_unique_string(&mut tags, detector.to_string());
    push_unique_string(&mut tags, invariant_name.to_string());

    ReplayScenarioManifest {
        name: format!("{}-solver", case_id),
        description: format!(
            "Harvested solver counterexample replay for invariant `{}`",
            invariant_name
        ),
        seed_time_ms: created_at_ms,
        requested_by: "evolution-assurance-harvest".to_string(),
        receipt_chain: vec![
            proposal_id.to_string(),
            verification_id.to_string(),
            proof_id.to_string(),
        ],
        metadata: ReplayScenarioMetadata {
            class: ReplayScenarioClass::Mixed,
            threat_class: None,
            campaign: None,
            techniques: Vec::new(),
            tags,
        },
        input: ReplayScenarioInput::ReplayBundles {
            paths: vec![bundle_path.display().to_string()],
        },
        expectations: ReplayExpectations::default(),
    }
}

fn has_actionable_technique(candidate: &[String], actionable: &[String]) -> bool {
    candidate.is_empty()
        || actionable.is_empty()
        || candidate
            .iter()
            .any(|technique| actionable.iter().any(|expected| expected == technique))
}

fn coverage_case_references(
    source_path: &Path,
    proposal_id: &str,
    verification: Option<&DetectorVerificationLookup>,
    proof: Option<&EvolutionProofReport>,
) -> Vec<String> {
    let mut references = vec![
        normalize_existing_path(source_path.to_path_buf())
            .display()
            .to_string(),
    ];
    push_unique_string(&mut references, proposal_id.to_string());
    if let Some(verification) = verification {
        push_unique_string(&mut references, verification.report.verification_id.clone());
    }
    if let Some(proof) = proof {
        push_unique_string(&mut references, proof.proof_id.clone());
    }
    references
}

fn solver_case_references(
    bundle_path: &Path,
    proposal_id: &str,
    proof: &EvolutionProofReport,
) -> Vec<String> {
    let mut references = vec![bundle_path.display().to_string(), proposal_id.to_string()];
    push_unique_string(&mut references, proof.proof_id.clone());
    references
}

fn assurance_case_id(
    proposal_id: &str,
    kind: EvolutionAssuranceCaseKind,
    seed: &str,
    ordinal: usize,
) -> String {
    format!(
        "evolution_assurance_case:{}:{}:{}:{}",
        proposal_id,
        assurance_case_kind_label(kind),
        sanitize_id(seed),
        ordinal
    )
}

fn assurance_case_kind_label(kind: EvolutionAssuranceCaseKind) -> &'static str {
    match kind {
        EvolutionAssuranceCaseKind::CoverageGap => "coverage_gap",
        EvolutionAssuranceCaseKind::SolverCounterexample => "solver_counterexample",
    }
}

fn push_unique_string(values: &mut Vec<String>, candidate: String) {
    if candidate.is_empty() || values.iter().any(|existing| existing == &candidate) {
        return;
    }
    values.push(candidate);
}

fn assurance_sha256(summary: &EvolutionProposalAssuranceSummary) -> Result<String, String> {
    let mut canonical_summary = summary.clone();
    canonical_summary.waiver = None;
    let payload = canonical_json_bytes(&canonical_summary)
        .map_err(|error| format!("failed to canonicalize assurance lineage: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(payload)))
}

fn assurance_waiver_payload<'a>(
    waiver: &'a EvolutionAssuranceWaiverSummary,
) -> EvolutionAssuranceWaiverPayload<'a> {
    EvolutionAssuranceWaiverPayload {
        waiver_id: &waiver.waiver_id,
        operator_id: &waiver.operator_id,
        issued_at_ms: waiver.issued_at_ms,
        expires_at_ms: waiver.expires_at_ms,
        reason: &waiver.reason,
        waived_gap_count: waiver.waived_gap_count,
        assurance_sha256: &waiver.assurance_sha256,
    }
}

pub(crate) fn build_assurance_waiver_summary(
    proposal_id: &str,
    assurance: &EvolutionProposalAssuranceSummary,
    operator_id: &str,
    signer: &Ed25519Signer,
    issued_at_ms: i64,
    ttl_secs: u64,
    reason: &str,
) -> Result<EvolutionAssuranceWaiverSummary, String> {
    let expires_at_ms = issued_at_ms
        .checked_add((ttl_secs as i64).saturating_mul(1_000))
        .ok_or_else(|| "waiver ttl overflowed the supported timestamp range".to_string())?;
    let assurance_sha256 = assurance_sha256(assurance)?;
    let waiver_id = format!(
        "evolution_assurance_waiver:{}:{}:{}",
        proposal_id,
        sanitize_id(operator_id),
        issued_at_ms
    );
    let mut waiver = EvolutionAssuranceWaiverSummary {
        waiver_id,
        operator_id: operator_id.to_string(),
        issued_at_ms,
        expires_at_ms,
        reason: reason.trim().to_string(),
        waived_gap_count: assurance.coverage.actionable_gap_count,
        assurance_sha256,
        signature: DetachedSignature {
            algorithm: "ed25519".to_string(),
            key_id: String::new(),
            public_key_hex: String::new(),
            signature_hex: String::new(),
        },
    };
    let payload = canonical_json_bytes(&assurance_waiver_payload(&waiver))
        .map_err(|error| format!("failed to canonicalize assurance waiver payload: {error}"))?;
    waiver.signature = signer.sign(&payload);
    Ok(waiver)
}

pub(crate) fn validate_assurance_waiver<'a>(
    assurance: &'a EvolutionProposalAssuranceSummary,
    config: &SwarmConfig,
    current_time_ms: i64,
) -> Result<&'a EvolutionAssuranceWaiverSummary, String> {
    let waiver = assurance
        .waiver
        .as_ref()
        .ok_or_else(|| "assurance waiver is missing".to_string())?;
    if waiver.reason.trim().is_empty() {
        return Err("assurance waiver reason must not be empty".to_string());
    }
    if waiver.expires_at_ms <= waiver.issued_at_ms {
        return Err("assurance waiver expiry must be after its issuance time".to_string());
    }
    if current_time_ms < waiver.issued_at_ms {
        return Err(format!(
            "assurance waiver is not active until {}",
            waiver.issued_at_ms
        ));
    }
    if current_time_ms > waiver.expires_at_ms {
        return Err(format!(
            "assurance waiver expired at {}",
            waiver.expires_at_ms
        ));
    }
    if !config
        .evolution
        .assurance
        .waiver
        .allowed_operator_ids
        .iter()
        .any(|candidate| candidate == &waiver.operator_id)
    {
        return Err(format!(
            "operator `{}` is not allowed to issue assurance waivers",
            waiver.operator_id
        ));
    }
    if assurance.coverage.actionable_gap_count
        > config.evolution.assurance.waiver.max_actionable_gap_count
    {
        return Err(format!(
            "assurance gap count {} exceeds configured waiver limit {}",
            assurance.coverage.actionable_gap_count,
            config.evolution.assurance.waiver.max_actionable_gap_count
        ));
    }
    if waiver.waived_gap_count != assurance.coverage.actionable_gap_count {
        return Err(format!(
            "assurance waiver records {} waived gaps but the assurance lineage carries {} actionable gaps",
            waiver.waived_gap_count, assurance.coverage.actionable_gap_count
        ));
    }
    let expected_operator_id =
        AgentId::from_public_key_hex(&waiver.signature.public_key_hex).to_string();
    if waiver.operator_id != expected_operator_id {
        return Err(format!(
            "assurance waiver signer `{}` does not match recorded operator `{}`",
            expected_operator_id, waiver.operator_id
        ));
    }
    let expected_sha256 = assurance_sha256(assurance)?;
    if waiver.assurance_sha256 != expected_sha256 {
        return Err(
            "assurance waiver does not match the current assurance lineage digest".to_string(),
        );
    }
    let payload = canonical_json_bytes(&assurance_waiver_payload(waiver))
        .map_err(|error| format!("failed to canonicalize assurance waiver payload: {error}"))?;
    verify_detached_signature(&payload, &waiver.signature)
        .map_err(|error| format!("assurance waiver signature verification failed: {error}"))?;
    Ok(waiver)
}

pub(crate) fn active_assurance_waiver<'a>(
    assurance: Option<&'a EvolutionProposalAssuranceSummary>,
    config: &SwarmConfig,
    current_time_ms: i64,
) -> Option<&'a EvolutionAssuranceWaiverSummary> {
    let summary = assurance?;
    if summary.decision != EvolutionProposalAssuranceDecision::Blocked {
        return None;
    }
    validate_assurance_waiver(summary, config, current_time_ms).ok()
}

pub(crate) fn assurance_rollout_state(
    assurance: Option<&EvolutionProposalAssuranceSummary>,
    config: &SwarmConfig,
    current_time_ms: i64,
) -> EvolutionAssuranceRolloutState {
    match assurance {
        Some(summary) if summary.decision == EvolutionProposalAssuranceDecision::Passed => {
            EvolutionAssuranceRolloutState::Clear
        }
        Some(_) if active_assurance_waiver(assurance, config, current_time_ms).is_some() => {
            EvolutionAssuranceRolloutState::Waived
        }
        _ => EvolutionAssuranceRolloutState::Blocked,
    }
}

pub(crate) fn assurance_gate_block_reason(
    assurance: Option<&EvolutionProposalAssuranceSummary>,
    config: &SwarmConfig,
    current_time_ms: i64,
    target: &str,
) -> Option<String> {
    let Some(summary) = assurance else {
        return Some(format!("{target} is missing durable assurance lineage"));
    };
    if summary.decision == EvolutionProposalAssuranceDecision::Passed {
        return None;
    }
    if active_assurance_waiver(Some(summary), config, current_time_ms).is_some() {
        return None;
    }
    let suffix = match validate_assurance_waiver(summary, config, current_time_ms) {
        Ok(_) => String::new(),
        Err(reason) if summary.waiver.is_some() => format!(": {reason}"),
        Err(_) => String::new(),
    };
    Some(format!(
        "assurance decision `{}` does not permit {target}{suffix}",
        assurance_decision_label(summary.decision)
    ))
}

pub(crate) fn proposal_has_active_blocking_reasons(
    report: &EvolutionProposalReport,
    config: &SwarmConfig,
    current_time_ms: i64,
) -> bool {
    report
        .blocking_reasons
        .iter()
        .any(|reason| reason.source != "assurance")
        || assurance_rollout_state(report.assurance.as_ref(), config, current_time_ms)
            == EvolutionAssuranceRolloutState::Blocked
}

pub(crate) fn render_assurance_summary_lines(
    assurance: &EvolutionProposalAssuranceSummary,
) -> Vec<String> {
    let mut lines = vec![
        format!(
            "Assurance: {} | detector={} catch_rate={}/{} solver={}",
            assurance_decision_label(assurance.decision),
            assurance.coverage.detector,
            assurance
                .coverage
                .actual_catch_rate
                .map(|value| format!("{value:.3}"))
                .unwrap_or_else(|| "n/a".to_string()),
            format!("{:.3}", assurance.coverage.required_catch_rate),
            assurance
                .solver
                .status
                .map(solver_proof_status_label)
                .unwrap_or("missing")
        ),
        format!(
            "Assurance gaps: actionable={} suite={} corpus={}",
            assurance.coverage.actionable_gap_count,
            assurance.coverage.suite_name.as_deref().unwrap_or("n/a"),
            assurance
                .coverage
                .corpus_version
                .as_deref()
                .unwrap_or("n/a")
        ),
    ];
    if !assurance.harvested_case_ids.is_empty() {
        lines.push(format!(
            "Assurance harvested cases: {}",
            assurance.harvested_case_ids.join(", ")
        ));
    }
    if let Some(waiver) = &assurance.waiver {
        lines.push(format!(
            "Assurance waiver: {} | operator={} | expires_at={} | waived_gaps={}",
            waiver.waiver_id, waiver.operator_id, waiver.expires_at_ms, waiver.waived_gap_count
        ));
        lines.push(format!("Waiver reason: {}", waiver.reason));
    }
    lines
}

fn proposal_assurance_blocking_reason(
    report: &EvolutionProposalReport,
    config: &SwarmConfig,
    current_time_ms: i64,
) -> EvolutionProposalBlockingReason {
    let details = assurance_gate_block_reason(
        report.assurance.as_ref(),
        config,
        current_time_ms,
        "rollout progression",
    )
    .unwrap_or_else(|| "assurance gate unexpectedly evaluated as satisfied".to_string());
    EvolutionProposalBlockingReason {
        source: "assurance".to_string(),
        name: "assurance_gate_unsatisfied".to_string(),
        details,
        references: report
            .assurance
            .as_ref()
            .map(|summary| summary.harvested_case_ids.clone())
            .filter(|ids| !ids.is_empty())
            .unwrap_or_else(|| vec![report.proposal_id.clone()]),
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
        let current_time_ms = now_ms();

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
        if proposal_has_active_blocking_reasons(&proposal.report, &self.config, current_time_ms) {
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
        if assurance_rollout_state(
            proposal.report.assurance.as_ref(),
            &self.config,
            current_time_ms,
        ) == EvolutionAssuranceRolloutState::Blocked
        {
            blocking_reasons.push(proposal_assurance_blocking_reason(
                &proposal.report,
                &self.config,
                current_time_ms,
            ));
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
            assurance: proposal.report.assurance.clone(),
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
        if assurance_rollout_state(lookup.report.assurance.as_ref(), &self.config, now_ms())
            == EvolutionAssuranceRolloutState::Blocked
        {
            return Err(EvolutionQueueError::InvalidHandoffLaunch {
                handoff_id: handoff_id.to_string(),
                state: handoff_status_label(lookup.report.launch_status).to_string(),
                reason: assurance_gate_block_reason(
                    lookup.report.assurance.as_ref(),
                    &self.config,
                    now_ms(),
                    "rollout progression",
                )
                .unwrap_or_else(|| "handoff assurance lineage is missing or blocked".to_string()),
            });
        }

        let canary = canary_harness.start_run_with_assurance(
            PathBuf::from(&lookup.report.experiment_path),
            verification_results_dir,
            &lookup.report.verification_id,
            shadow_results_dir,
            &lookup.report.shadow_id,
            lookup.report.assurance.clone(),
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
    if let Some(solver) = &report.solver_summary {
        lines.push(format!(
            "Solver: {} | invariants={} | timeouts={} | counterexamples={}",
            solver_proof_status_label(solver.status),
            solver.invariant_count,
            solver.timed_out_count,
            solver.counterexample_invariant_count
        ));
    }
    for invariant in &report.invariants {
        lines.push(format!("- {}: {}", invariant.name, invariant.details));
    }
    for artifact in &report.solver_artifacts {
        lines.push(format!(
            "  solver:{} | status={} | timeout_ms={} | counterexamples={}",
            artifact.invariant_name,
            solver_proof_status_label(artifact.status),
            artifact.timeout_ms,
            artifact.counterexamples.len()
        ));
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

    if let Some(assurance) = &report.assurance {
        lines.extend(render_assurance_summary_lines(assurance));
    } else {
        lines.push("Assurance: unavailable".to_string());
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
    if let Some(assurance) = &report.assurance {
        lines.extend(render_assurance_summary_lines(assurance));
    } else {
        lines.push("Assurance: unavailable".to_string());
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

fn validate_formal_safety_bundle(
    path: &Path,
    bundle: &FormalSafetyInvariantBundle,
) -> Result<(), FormalSafetyGateError> {
    if bundle.schema_version == 0 {
        return Err(FormalSafetyGateError::Validation {
            path: path.to_path_buf(),
            reason: "schema_version must be greater than zero".to_string(),
        });
    }
    if bundle.name.trim().is_empty() {
        return Err(FormalSafetyGateError::Validation {
            path: path.to_path_buf(),
            reason: "name must not be empty".to_string(),
        });
    }
    if bundle.invariants.is_empty() {
        return Err(FormalSafetyGateError::Validation {
            path: path.to_path_buf(),
            reason: "invariants must include at least one rule".to_string(),
        });
    }
    for invariant in &bundle.invariants {
        match invariant {
            FormalSafetyInvariantSpec::CoverageFloor {
                name,
                corpus_path,
                min_ratio,
                ..
            } => {
                if name.trim().is_empty() || corpus_path.trim().is_empty() {
                    return Err(FormalSafetyGateError::Validation {
                        path: path.to_path_buf(),
                        reason: "coverage_floor invariants require non-empty name and corpus_path"
                            .to_string(),
                    });
                }
                if !(0.0..=1.0).contains(min_ratio) {
                    return Err(FormalSafetyGateError::Validation {
                        path: path.to_path_buf(),
                        reason: format!(
                            "coverage_floor invariant `{name}` min_ratio must be between 0.0 and 1.0"
                        ),
                    });
                }
            }
            FormalSafetyInvariantSpec::FpCeiling {
                name,
                corpus_path,
                max_rate,
            } => {
                if name.trim().is_empty() || corpus_path.trim().is_empty() {
                    return Err(FormalSafetyGateError::Validation {
                        path: path.to_path_buf(),
                        reason: "fp_ceiling invariants require non-empty name and corpus_path"
                            .to_string(),
                    });
                }
                if !(0.0..=1.0).contains(max_rate) {
                    return Err(FormalSafetyGateError::Validation {
                        path: path.to_path_buf(),
                        reason: format!(
                            "fp_ceiling invariant `{name}` max_rate must be between 0.0 and 1.0"
                        ),
                    });
                }
            }
            FormalSafetyInvariantSpec::LatencyBudget {
                name,
                corpus_path,
                max_detect_latency_us,
            } => {
                if name.trim().is_empty() || corpus_path.trim().is_empty() {
                    return Err(FormalSafetyGateError::Validation {
                        path: path.to_path_buf(),
                        reason: "latency_budget invariants require non-empty name and corpus_path"
                            .to_string(),
                    });
                }
                if *max_detect_latency_us == 0 {
                    return Err(FormalSafetyGateError::Validation {
                        path: path.to_path_buf(),
                        reason: format!(
                            "latency_budget invariant `{name}` max_detect_latency_us must be greater than zero"
                        ),
                    });
                }
            }
            FormalSafetyInvariantSpec::ParameterBounds {
                name,
                json_pointer,
                min,
                max,
            } => {
                if name.trim().is_empty() || json_pointer.trim().is_empty() {
                    return Err(FormalSafetyGateError::Validation {
                        path: path.to_path_buf(),
                        reason:
                            "parameter_bounds invariants require non-empty name and json_pointer"
                                .to_string(),
                    });
                }
                if let (Some(min), Some(max)) = (min, max)
                    && min > max
                {
                    return Err(FormalSafetyGateError::Validation {
                        path: path.to_path_buf(),
                        reason: format!(
                            "parameter_bounds invariant `{name}` min cannot exceed max"
                        ),
                    });
                }
            }
            FormalSafetyInvariantSpec::CustomZ3 { name, query } => {
                if name.trim().is_empty() || query.trim().is_empty() {
                    return Err(FormalSafetyGateError::Validation {
                        path: path.to_path_buf(),
                        reason: "custom_z3 invariants require non-empty name and query".to_string(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn evaluate_formal_safety_invariant(
    bundle_path: &Path,
    invariant: &FormalSafetyInvariantSpec,
    candidate: &StrategyGenome,
    verification_manifest: &crate::replay::VerificationCorpusManifest,
    candidate_value: &JsonValue,
    z3_enabled: bool,
) -> Result<FormalSafetyInvariantEvaluation, FormalSafetyGateError> {
    match invariant {
        FormalSafetyInvariantSpec::CoverageFloor {
            name,
            corpus_path,
            source,
            min_ratio,
        } => Ok(plain_invariant_evaluation(evaluate_coverage_floor(
            bundle_path,
            name,
            corpus_path,
            *source,
            *min_ratio,
            candidate,
            verification_manifest,
        )?)),
        FormalSafetyInvariantSpec::FpCeiling {
            name,
            corpus_path,
            max_rate,
        } => Ok(plain_invariant_evaluation(evaluate_fp_ceiling(
            bundle_path,
            name,
            corpus_path,
            *max_rate,
            candidate,
        )?)),
        FormalSafetyInvariantSpec::LatencyBudget {
            name,
            corpus_path,
            max_detect_latency_us,
        } => Ok(plain_invariant_evaluation(evaluate_latency_budget(
            bundle_path,
            name,
            corpus_path,
            *max_detect_latency_us,
            candidate,
        )?)),
        FormalSafetyInvariantSpec::ParameterBounds {
            name,
            json_pointer,
            min,
            max,
        } => Ok(plain_invariant_evaluation(evaluate_parameter_bounds(
            name,
            json_pointer,
            *min,
            *max,
            candidate_value,
        ))),
        FormalSafetyInvariantSpec::CustomZ3 { name, query } => evaluate_custom_z3_invariant(
            bundle_path,
            name,
            query,
            candidate,
            candidate_value,
            z3_enabled,
        ),
    }
}

fn plain_invariant_evaluation(
    verdict: FormalSafetyInvariantVerdict,
) -> FormalSafetyInvariantEvaluation {
    FormalSafetyInvariantEvaluation {
        verdict,
        solver_artifact: None,
    }
}

fn z3_timeout_ms() -> u64 {
    std::env::var("SWARM_EVOLUTION_Z3_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_Z3_TIMEOUT_MS)
}

fn compile_custom_z3_query(
    bundle_path: &Path,
    query: &str,
    candidate_value: &JsonValue,
) -> Result<String, FormalSafetyGateError> {
    let mut compiled = String::with_capacity(query.len());
    let mut cursor = 0usize;
    while let Some(start_offset) = query[cursor..].find("{{") {
        let start = cursor + start_offset;
        compiled.push_str(&query[cursor..start]);
        let replacement_start = start + 2;
        let Some(end_offset) = query[replacement_start..].find("}}") else {
            return Err(FormalSafetyGateError::Validation {
                path: bundle_path.to_path_buf(),
                reason: "custom_z3 query contains an unterminated `{{ ... }}` placeholder"
                    .to_string(),
            });
        };
        let end = replacement_start + end_offset;
        let pointer = query[replacement_start..end].trim();
        if pointer.is_empty() {
            return Err(FormalSafetyGateError::Validation {
                path: bundle_path.to_path_buf(),
                reason: "custom_z3 placeholders must reference a non-empty JSON pointer"
                    .to_string(),
            });
        }
        let Some(value) = candidate_value.pointer(pointer) else {
            return Err(FormalSafetyGateError::Validation {
                path: bundle_path.to_path_buf(),
                reason: format!("custom_z3 query references missing candidate pointer `{pointer}`"),
            });
        };
        compiled.push_str(&json_value_to_smt_literal(bundle_path, pointer, value)?);
        cursor = end + 2;
    }
    compiled.push_str(&query[cursor..]);
    if !compiled.contains("(check-sat") {
        compiled.push_str("\n(check-sat)\n");
    }
    Ok(compiled)
}

fn json_value_to_smt_literal(
    bundle_path: &Path,
    pointer: &str,
    value: &JsonValue,
) -> Result<String, FormalSafetyGateError> {
    match value {
        JsonValue::Bool(value) => Ok(if *value { "true" } else { "false" }.to_string()),
        JsonValue::Number(value) => Ok(value.to_string()),
        JsonValue::String(value) => Ok(format!("\"{}\"", value.replace('"', "\\\""))),
        JsonValue::Null | JsonValue::Array(_) | JsonValue::Object(_) => {
            Err(FormalSafetyGateError::Validation {
                path: bundle_path.to_path_buf(),
                reason: format!(
                    "custom_z3 query pointer `{pointer}` resolved to a non-scalar JSON value"
                ),
            })
        }
    }
}

fn build_solver_artifact(
    invariant_name: &str,
    status: EvolutionSolverProofStatus,
    timeout_ms: u64,
    duration_ms: u64,
    compiled_query: &str,
    counterexamples: Vec<EvolutionSolverCounterexample>,
    reason_unknown: Option<String>,
) -> Result<EvolutionSolverInvariantArtifact, FormalSafetyGateError> {
    let compiled_query_sha256 = sha256_hex(&compiled_query)?;
    let attestation_sha256 = sha256_hex(&SolverArtifactAttestationPayload {
        invariant_name: invariant_name.to_string(),
        status,
        timeout_ms,
        duration_ms,
        compiled_query_sha256: compiled_query_sha256.clone(),
        reason_unknown: reason_unknown.clone(),
        counterexamples: counterexamples.clone(),
    })?;
    Ok(EvolutionSolverInvariantArtifact {
        invariant_name: invariant_name.to_string(),
        solver: "z3".to_string(),
        status,
        timeout_ms,
        duration_ms,
        compiled_query_sha256,
        attestation_sha256,
        counterexamples,
        reason_unknown,
    })
}

fn summarize_solver_artifacts(
    artifacts: &[EvolutionSolverInvariantArtifact],
) -> Result<Option<EvolutionSolverProofSummary>, FormalSafetyGateError> {
    if artifacts.is_empty() {
        return Ok(None);
    }

    let proved_count = artifacts
        .iter()
        .filter(|artifact| artifact.status == EvolutionSolverProofStatus::Proved)
        .count();
    let counterexample_invariant_count = artifacts
        .iter()
        .filter(|artifact| artifact.status == EvolutionSolverProofStatus::Counterexample)
        .count();
    let counterexample_binding_count = artifacts
        .iter()
        .map(|artifact| artifact.counterexamples.len())
        .sum();
    let timed_out_count = artifacts
        .iter()
        .filter(|artifact| artifact.status == EvolutionSolverProofStatus::Timeout)
        .count();
    let disabled_count = artifacts
        .iter()
        .filter(|artifact| artifact.status == EvolutionSolverProofStatus::Disabled)
        .count();
    let error_count = artifacts
        .iter()
        .filter(|artifact| artifact.status == EvolutionSolverProofStatus::Error)
        .count();
    let status = if timed_out_count > 0 {
        EvolutionSolverProofStatus::Timeout
    } else if counterexample_invariant_count > 0 {
        EvolutionSolverProofStatus::Counterexample
    } else if error_count > 0 {
        EvolutionSolverProofStatus::Error
    } else if disabled_count > 0 {
        EvolutionSolverProofStatus::Disabled
    } else {
        EvolutionSolverProofStatus::Proved
    };
    let timeout_ms = artifacts
        .iter()
        .map(|artifact| artifact.timeout_ms)
        .max()
        .unwrap_or(DEFAULT_Z3_TIMEOUT_MS);
    let proof_signature_sha256 = sha256_hex(
        &artifacts
            .iter()
            .map(|artifact| artifact.attestation_sha256.clone())
            .collect::<Vec<_>>(),
    )?;

    Ok(Some(EvolutionSolverProofSummary {
        status,
        invariant_count: artifacts.len(),
        proved_count,
        counterexample_invariant_count,
        counterexample_binding_count,
        timed_out_count,
        disabled_count,
        error_count,
        timeout_ms,
        proof_signature_sha256,
    }))
}

fn evaluate_custom_z3_invariant(
    bundle_path: &Path,
    name: &str,
    query: &str,
    candidate: &StrategyGenome,
    candidate_value: &JsonValue,
    z3_enabled: bool,
) -> Result<FormalSafetyInvariantEvaluation, FormalSafetyGateError> {
    let timeout_ms = z3_timeout_ms();
    let compiled_query = compile_custom_z3_query(bundle_path, query, candidate_value)?;
    evaluate_custom_z3_invariant_impl(
        bundle_path,
        name,
        compiled_query,
        candidate,
        timeout_ms,
        z3_enabled,
    )
}

#[cfg(feature = "z3")]
fn evaluate_custom_z3_invariant_impl(
    bundle_path: &Path,
    name: &str,
    compiled_query: String,
    candidate: &StrategyGenome,
    timeout_ms: u64,
    z3_enabled: bool,
) -> Result<FormalSafetyInvariantEvaluation, FormalSafetyGateError> {
    if !z3_enabled {
        return disabled_custom_z3_evaluation(
            bundle_path,
            name,
            compiled_query,
            candidate,
            timeout_ms,
        );
    }

    let started_at = std::time::Instant::now();
    let mut config = Z3Config::new();
    config.set_timeout_msec(timeout_ms);
    with_z3_config(&config, || {
        let solver = Z3Solver::new();
        let mut params = Z3Params::new();
        params.set_u32("timeout", timeout_ms as u32);
        solver.set_params(&params);
        solver.from_string(compiled_query.clone());
        let result = solver.check();
        let duration_ms = started_at.elapsed().as_millis() as u64;

        match result {
            SatResult::Unsat => {
                let artifact = build_solver_artifact(
                    name,
                    EvolutionSolverProofStatus::Proved,
                    timeout_ms,
                    duration_ms,
                    &compiled_query,
                    Vec::new(),
                    None,
                )?;
                Ok(FormalSafetyInvariantEvaluation {
                    verdict: FormalSafetyInvariantVerdict {
                        name: name.to_string(),
                        passed: true,
                        details: format!(
                            "custom_z3 invariant proved with Z3 in {duration_ms}ms (timeout={}ms)",
                            timeout_ms
                        ),
                        counterexamples: Vec::new(),
                    },
                    solver_artifact: Some(artifact),
                })
            }
            SatResult::Sat => {
                let counterexamples = solver
                    .get_model()
                    .map(|model| extract_model_counterexamples(&model))
                    .unwrap_or_default();
                let artifact = build_solver_artifact(
                    name,
                    EvolutionSolverProofStatus::Counterexample,
                    timeout_ms,
                    duration_ms,
                    &compiled_query,
                    counterexamples.clone(),
                    None,
                )?;
                Ok(FormalSafetyInvariantEvaluation {
                    verdict: FormalSafetyInvariantVerdict {
                        name: name.to_string(),
                        passed: false,
                        details: format!(
                            "custom_z3 invariant produced a counterexample in {duration_ms}ms"
                        ),
                        counterexamples: counterexamples
                            .iter()
                            .map(|counterexample| VerificationCounterexample {
                                subject: counterexample.name.clone(),
                                reference: bundle_path.display().to_string(),
                                details: counterexample.value.clone(),
                            })
                            .collect(),
                    },
                    solver_artifact: Some(artifact),
                })
            }
            SatResult::Unknown => {
                let reason_unknown = solver.get_reason_unknown();
                let status = if reason_unknown
                    .as_deref()
                    .map(|reason| {
                        let normalized = reason.to_ascii_lowercase();
                        normalized.contains("timeout") || normalized.contains("canceled")
                    })
                    .unwrap_or(false)
                {
                    EvolutionSolverProofStatus::Timeout
                } else {
                    EvolutionSolverProofStatus::Error
                };
                let details = if status == EvolutionSolverProofStatus::Timeout {
                    format!(
                        "custom_z3 invariant timed out after {duration_ms}ms (timeout={}ms)",
                        timeout_ms
                    )
                } else {
                    format!(
                        "custom_z3 invariant returned unknown after {duration_ms}ms ({})",
                        reason_unknown
                            .clone()
                            .unwrap_or_else(|| "no solver reason provided".to_string())
                    )
                };
                let artifact = build_solver_artifact(
                    name,
                    status,
                    timeout_ms,
                    duration_ms,
                    &compiled_query,
                    Vec::new(),
                    reason_unknown.clone(),
                )?;
                Ok(FormalSafetyInvariantEvaluation {
                    verdict: FormalSafetyInvariantVerdict {
                        name: name.to_string(),
                        passed: false,
                        details: details.clone(),
                        counterexamples: vec![VerificationCounterexample {
                            subject: candidate.strategy_id.clone(),
                            reference: bundle_path.display().to_string(),
                            details,
                        }],
                    },
                    solver_artifact: Some(artifact),
                })
            }
        }
    })
}

#[cfg(not(feature = "z3"))]
fn evaluate_custom_z3_invariant_impl(
    bundle_path: &Path,
    name: &str,
    compiled_query: String,
    candidate: &StrategyGenome,
    timeout_ms: u64,
    _z3_enabled: bool,
) -> Result<FormalSafetyInvariantEvaluation, FormalSafetyGateError> {
    disabled_custom_z3_evaluation(bundle_path, name, compiled_query, candidate, timeout_ms)
}

fn disabled_custom_z3_evaluation(
    bundle_path: &Path,
    name: &str,
    compiled_query: String,
    candidate: &StrategyGenome,
    timeout_ms: u64,
) -> Result<FormalSafetyInvariantEvaluation, FormalSafetyGateError> {
    let artifact = build_solver_artifact(
        name,
        EvolutionSolverProofStatus::Disabled,
        timeout_ms,
        0,
        &compiled_query,
        Vec::new(),
        Some("the optional Z3-backed verifier is not enabled in this build or config".to_string()),
    )?;
    Ok(FormalSafetyInvariantEvaluation {
        verdict: FormalSafetyInvariantVerdict {
            name: name.to_string(),
            passed: false,
            details:
                "custom_z3 invariants require the optional Z3-backed verifier, which is not enabled in this build"
                    .to_string(),
            counterexamples: vec![VerificationCounterexample {
                subject: candidate.strategy_id.clone(),
                reference: bundle_path.display().to_string(),
                details:
                    "custom_z3 invariant cannot be evaluated without the optional solver lane"
                        .to_string(),
            }],
        },
        solver_artifact: Some(artifact),
    })
}

#[cfg(feature = "z3")]
fn extract_model_counterexamples(model: &z3::Model) -> Vec<EvolutionSolverCounterexample> {
    model
        .iter()
        .filter_map(|decl| {
            let applied = decl.apply(&[]);
            model
                .eval(&applied, true)
                .map(|value| EvolutionSolverCounterexample {
                    name: decl.name(),
                    value: value.to_string(),
                })
        })
        .collect()
}

fn evaluate_coverage_floor(
    bundle_path: &Path,
    name: &str,
    corpus_path: &str,
    source: FormalSafetyCoverageSource,
    min_ratio: f64,
    candidate: &StrategyGenome,
    verification_manifest: &crate::replay::VerificationCorpusManifest,
) -> Result<FormalSafetyInvariantVerdict, FormalSafetyGateError> {
    ensure_matching_corpus(
        bundle_path,
        corpus_path,
        &candidate.verification.corpus_path,
    )?;
    let (verification_invariant_name, total, details_suffix) = match source {
        FormalSafetyCoverageSource::KnownBadCoverage => {
            let known_bad_suite_path = resolve_relative_path_local(
                Path::new(&candidate.verification.corpus_path),
                &verification_manifest.known_bad.suite,
            );
            let raw = fs::read_to_string(&known_bad_suite_path).map_err(|source| {
                FormalSafetyGateError::Read {
                    path: known_bad_suite_path.clone(),
                    source,
                }
            })?;
            let suite: ReplaySuiteManifest =
                serde_yaml::from_str(&raw).map_err(|source| FormalSafetyGateError::Parse {
                    path: known_bad_suite_path.clone(),
                    source,
                })?;
            (
                "known_bad_coverage",
                suite.scenarios.len(),
                "verification adversarial scenarios",
            )
        }
        FormalSafetyCoverageSource::ThreatClassTemplates => (
            "threat_class_templates",
            verification_manifest.canonical_templates.len(),
            "canonical threat-class templates",
        ),
    };
    let invariant = candidate
        .verification
        .invariants
        .iter()
        .find(|entry| entry.name == verification_invariant_name);
    let missed = invariant
        .map(|entry| entry.counterexamples.len())
        .unwrap_or(total);
    let ratio = if total == 0 {
        0.0
    } else {
        (total.saturating_sub(missed)) as f64 / total as f64
    };
    let counterexamples = invariant
        .map(|entry| entry.counterexamples.clone())
        .unwrap_or_else(|| {
            vec![VerificationCounterexample {
                subject: candidate.strategy_id.clone(),
                reference: candidate.verification.verification_id.clone(),
                details: format!(
                    "verification invariant `{verification_invariant_name}` was not found while evaluating coverage floor"
                ),
            }]
        });
    Ok(FormalSafetyInvariantVerdict {
        name: name.to_string(),
        passed: ratio >= min_ratio,
        details: if ratio >= min_ratio {
            format!(
                "candidate preserved {:.2}% of the required {}",
                ratio * 100.0,
                details_suffix
            )
        } else {
            format!(
                "candidate preserved only {:.2}% of the required {}",
                ratio * 100.0,
                details_suffix
            )
        },
        counterexamples: if ratio >= min_ratio {
            Vec::new()
        } else {
            counterexamples
        },
    })
}

fn evaluate_fp_ceiling(
    bundle_path: &Path,
    name: &str,
    corpus_path: &str,
    max_rate: f64,
    candidate: &StrategyGenome,
) -> Result<FormalSafetyInvariantVerdict, FormalSafetyGateError> {
    ensure_matching_corpus(
        bundle_path,
        corpus_path,
        &candidate.verification.corpus_path,
    )?;
    let invariant = candidate
        .verification
        .invariants
        .iter()
        .find(|entry| entry.name == "false_positive_bound");
    let actual = invariant
        .and_then(|entry| entry.actual.as_f64())
        .unwrap_or(1.0);
    let counterexamples = invariant
        .map(|entry| entry.counterexamples.clone())
        .unwrap_or_else(|| {
            vec![VerificationCounterexample {
                subject: candidate.strategy_id.clone(),
                reference: candidate.verification.verification_id.clone(),
                details: "verification invariant `false_positive_bound` was not found".to_string(),
            }]
        });
    Ok(FormalSafetyInvariantVerdict {
        name: name.to_string(),
        passed: actual <= max_rate,
        details: if actual <= max_rate {
            format!(
                "candidate false-positive rate {:.4} stayed within ceiling {:.4}",
                actual, max_rate
            )
        } else {
            format!(
                "candidate false-positive rate {:.4} exceeded ceiling {:.4}",
                actual, max_rate
            )
        },
        counterexamples: if actual <= max_rate {
            Vec::new()
        } else {
            counterexamples
        },
    })
}

fn evaluate_latency_budget(
    bundle_path: &Path,
    name: &str,
    corpus_path: &str,
    max_detect_latency_us: u64,
    candidate: &StrategyGenome,
) -> Result<FormalSafetyInvariantVerdict, FormalSafetyGateError> {
    ensure_matching_corpus(
        bundle_path,
        corpus_path,
        &candidate.verification.corpus_path,
    )?;
    let invariant = candidate
        .verification
        .invariants
        .iter()
        .find(|entry| entry.name == "detect_latency_budget");
    let actual = invariant
        .and_then(|entry| entry.actual.as_u64())
        .unwrap_or(u64::MAX);
    let counterexamples = invariant
        .map(|entry| entry.counterexamples.clone())
        .unwrap_or_else(|| {
            vec![VerificationCounterexample {
                subject: candidate.strategy_id.clone(),
                reference: candidate.verification.verification_id.clone(),
                details: "verification invariant `detect_latency_budget` was not found".to_string(),
            }]
        });
    Ok(FormalSafetyInvariantVerdict {
        name: name.to_string(),
        passed: actual <= max_detect_latency_us,
        details: if actual <= max_detect_latency_us {
            format!(
                "candidate detect latency {}us stayed within budget {}us",
                actual, max_detect_latency_us
            )
        } else {
            format!(
                "candidate detect latency {}us exceeded budget {}us",
                actual, max_detect_latency_us
            )
        },
        counterexamples: if actual <= max_detect_latency_us {
            Vec::new()
        } else {
            counterexamples
        },
    })
}

fn evaluate_parameter_bounds(
    name: &str,
    json_pointer: &str,
    min: Option<f64>,
    max: Option<f64>,
    candidate_value: &JsonValue,
) -> FormalSafetyInvariantVerdict {
    let Some(value) = candidate_value.pointer(json_pointer) else {
        return FormalSafetyInvariantVerdict {
            name: name.to_string(),
            passed: false,
            details: format!("candidate genome does not contain json pointer `{json_pointer}`"),
            counterexamples: vec![VerificationCounterexample {
                subject: name.to_string(),
                reference: json_pointer.to_string(),
                details: "pointer was missing from the candidate genome".to_string(),
            }],
        };
    };
    let Some(number) = value.as_f64() else {
        return FormalSafetyInvariantVerdict {
            name: name.to_string(),
            passed: false,
            details: format!("candidate value at `{json_pointer}` is not numeric"),
            counterexamples: vec![VerificationCounterexample {
                subject: name.to_string(),
                reference: json_pointer.to_string(),
                details: format!("encountered non-numeric value `{value}`"),
            }],
        };
    };

    let mut details = Vec::new();
    let mut passed = true;
    if let Some(min) = min
        && number < min
    {
        passed = false;
        details.push(format!("value {number:.4} is below minimum {min:.4}"));
    }
    if let Some(max) = max
        && number > max
    {
        passed = false;
        details.push(format!("value {number:.4} exceeds maximum {max:.4}"));
    }

    FormalSafetyInvariantVerdict {
        name: name.to_string(),
        passed,
        details: if passed {
            let mut bounds = Vec::new();
            if let Some(min) = min {
                bounds.push(format!("min={min:.4}"));
            }
            if let Some(max) = max {
                bounds.push(format!("max={max:.4}"));
            }
            format!(
                "candidate value at `{json_pointer}` ({number:.4}) satisfied {}",
                bounds.join(", ")
            )
        } else {
            details.join("; ")
        },
        counterexamples: if passed {
            Vec::new()
        } else {
            vec![VerificationCounterexample {
                subject: name.to_string(),
                reference: json_pointer.to_string(),
                details: details.join("; "),
            }]
        },
    }
}

fn ensure_matching_corpus(
    bundle_path: &Path,
    expected_corpus_path: &str,
    actual_corpus_path: &str,
) -> Result<(), FormalSafetyGateError> {
    let expected = normalize_existing_path(resolve_relative_path_local(
        bundle_path,
        expected_corpus_path,
    ));
    let actual = normalize_existing_path(PathBuf::from(actual_corpus_path));
    if expected != actual {
        return Err(FormalSafetyGateError::Validation {
            path: bundle_path.to_path_buf(),
            reason: format!(
                "bundle references verification corpus `{}` but candidate used `{}`",
                expected.display(),
                actual.display()
            ),
        });
    }
    Ok(())
}

fn resolve_config_relative_path(config_path: &Path, referenced: &str) -> PathBuf {
    let candidate = PathBuf::from(referenced);
    if candidate.is_absolute() {
        candidate
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(candidate)
    }
}

fn resolve_relative_path_local(manifest_path: &Path, referenced: &str) -> PathBuf {
    let candidate = PathBuf::from(referenced);
    if candidate.is_absolute() {
        candidate
    } else {
        manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(candidate)
    }
}

fn normalize_existing_path(path: PathBuf) -> PathBuf {
    fs::canonicalize(&path).unwrap_or(path)
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

fn assurance_decision_label(decision: EvolutionProposalAssuranceDecision) -> &'static str {
    match decision {
        EvolutionProposalAssuranceDecision::Passed => "passed",
        EvolutionProposalAssuranceDecision::Blocked => "blocked",
    }
}

fn solver_proof_status_label(status: EvolutionSolverProofStatus) -> &'static str {
    match status {
        EvolutionSolverProofStatus::Proved => "proved",
        EvolutionSolverProofStatus::Counterexample => "counterexample",
        EvolutionSolverProofStatus::Timeout => "timeout",
        EvolutionSolverProofStatus::Disabled => "disabled",
        EvolutionSolverProofStatus::Error => "error",
    }
}

fn map_assurance_solver_status(
    status: EvolutionAssuranceSolverStatusConfig,
) -> EvolutionSolverProofStatus {
    match status {
        EvolutionAssuranceSolverStatusConfig::Proved => EvolutionSolverProofStatus::Proved,
        EvolutionAssuranceSolverStatusConfig::Counterexample => {
            EvolutionSolverProofStatus::Counterexample
        }
        EvolutionAssuranceSolverStatusConfig::Timeout => EvolutionSolverProofStatus::Timeout,
        EvolutionAssuranceSolverStatusConfig::Disabled => EvolutionSolverProofStatus::Disabled,
        EvolutionAssuranceSolverStatusConfig::Error => EvolutionSolverProofStatus::Error,
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
        .unwrap_or_default()
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
struct EvolutionAssuranceCaseIndex {
    entries: Vec<EvolutionAssuranceCaseRecord>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    solver_signature_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    solver_artifact_attestations: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SolverArtifactAttestationPayload {
    invariant_name: String,
    status: EvolutionSolverProofStatus,
    timeout_ms: u64,
    duration_ms: u64,
    compiled_query_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_unknown: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    counterexamples: Vec<EvolutionSolverCounterexample>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        DefaultEvolutionHandoffHarness, DefaultEvolutionProofHarness, DefaultEvolutionQueueHarness,
        DefaultFormalSafetyGate, EvolutionAssuranceRolloutState, EvolutionAssuranceWaiverSummary,
        EvolutionHandoffStatus, EvolutionProposalAssuranceCoverageSummary,
        EvolutionProposalAssuranceDecision, EvolutionProposalAssuranceSolverSummary,
        EvolutionProposalAssuranceSummary, EvolutionProposalBlockingReason,
        EvolutionProposalCreateRequest, EvolutionProposalDecisionAction,
        EvolutionProposalProofStatus, EvolutionProposalReviewState, EvolutionSolverProofStatus,
        FileEvolutionProofStore, FileEvolutionProposalStore, FormalSafetyGate, StrategyGenome,
        assurance_gate_block_reason, assurance_rollout_state, build_assurance_waiver_summary,
        render_evolution_handoff, render_evolution_proof, render_evolution_proposal,
        render_evolution_proposal_list, validate_assurance_waiver,
    };
    use crate::canary::DefaultCanaryHarness;
    use crate::replay::{DefaultReplayHarness, FileVerificationStore};
    use crate::strategy::DefaultStrategyScorecardHarness;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};
    use swarm_core::ThreatClass;
    use swarm_core::config::{PolicyRuleConfig, PolicyRuleDecision, SwarmConfig};
    use swarm_core::types::{AgentId, Severity};
    use swarm_crypto::Ed25519Signer;

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
            name: format!("evolution-test-allow-{threat_class:?}"),
            decision: PolicyRuleDecision::Allow,
            threat_class,
            actions: Vec::new(),
            min_severity: Severity::Low,
            max_severity: Severity::Critical,
            time_window_utc: None,
            max_actions_per_agent_per_minute: None,
            reason: Some("evolution tests allow replay and verification responses".to_string()),
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

    fn persist_passed_verification(
        verification_results_dir: &Path,
        report: &crate::replay::DetectorVerificationReport,
    ) -> crate::replay::DetectorVerificationReport {
        let mut report = report.clone();
        report.passed = true;
        FileVerificationStore::open(verification_results_dir)
            .unwrap()
            .persist(&report)
            .unwrap();
        report
    }

    fn operator_id_for_secret(secret_material: &str) -> String {
        let signer = Ed25519Signer::from_secret_material(secret_material);
        AgentId::from_public_key_hex(signer.public_key_hex()).to_string()
    }

    fn persist_blocked_assurance_proposal(queue_dir: &Path, proposal_id: &str) {
        let store = FileEvolutionProposalStore::open(queue_dir).unwrap();
        let mut tampered = store.load(proposal_id).unwrap().unwrap().report;
        let mut assurance = tampered.assurance.unwrap();
        assurance.decision = EvolutionProposalAssuranceDecision::Blocked;
        assurance.coverage.actual_catch_rate = Some(0.25);
        assurance.coverage.actionable_gap_count = 2;
        assurance.harvested_case_ids = vec!["case-a".to_string(), "case-b".to_string()];
        assurance.waiver = None;
        tampered.assurance = Some(assurance);
        tampered.review_state = EvolutionProposalReviewState::Blocked;
        tampered.blocking_reasons = vec![EvolutionProposalBlockingReason {
            source: "assurance".to_string(),
            name: "assurance_gate_unsatisfied".to_string(),
            details: "assurance decision `blocked` does not permit rollout progression".to_string(),
            references: vec![proposal_id.to_string()],
        }];
        store.persist(&tampered).unwrap();
    }

    fn write_custom_z3_bundle(root: &Path, name: &str, query: &str) -> PathBuf {
        let bundle_path = root.join(format!("{name}.yaml"));
        fs::write(
            &bundle_path,
            format!(
                "schema_version: 1\nname: {name}\ndescription: test custom z3 bundle\ninvariants:\n  - name: {name}\n    type: custom_z3\n    query: |\n{}\n",
                query
                    .lines()
                    .map(|line| format!("      {line}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        )
        .unwrap();
        bundle_path
    }

    async fn verified_strategy_genome(
        root: &Path,
        config_path: &Path,
        config: &SwarmConfig,
    ) -> StrategyGenome {
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verification");
        let shadow_dir = root.join("shadows");
        let replay =
            DefaultReplayHarness::from_config(config_path, config.clone(), &replay_dir).unwrap();
        let verification = replay
            .evaluate_verification_path(office_control_experiment(), &verification_dir)
            .await
            .unwrap();
        let (_, shadow) = replay
            .evaluate_experiment_and_shadow_path(
                office_control_experiment(),
                &experiment_dir,
                &shadow_dir,
            )
            .await
            .unwrap();
        let experiment =
            crate::replay::load_detector_experiment_manifest(office_control_experiment()).unwrap();

        StrategyGenome {
            strategy_id: experiment.candidate.strategy_id().to_string(),
            experiment_path: office_control_experiment(),
            experiment,
            verification: verification.report,
            shadow: shadow.report,
        }
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
    async fn formal_safety_gate_accepts_repo_owned_bundle_for_verified_candidate() {
        let root = unique_temp_dir("formal-safety-pass");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verification");
        let shadow_dir = root.join("shadows");
        let config = sample_config();
        let config_path = repo_root().join("rulesets/default.yaml");
        let replay =
            DefaultReplayHarness::from_config(&config_path, config.clone(), &replay_dir).unwrap();
        let verification = replay
            .evaluate_verification_path(office_control_experiment(), &verification_dir)
            .await
            .unwrap();
        let (_, shadow) = replay
            .evaluate_experiment_and_shadow_path(
                office_control_experiment(),
                &experiment_dir,
                &shadow_dir,
            )
            .await
            .unwrap();
        let experiment =
            crate::replay::load_detector_experiment_manifest(office_control_experiment()).unwrap();
        let gate = DefaultFormalSafetyGate::from_config(config_path, config);

        let report = gate
            .verify(&StrategyGenome {
                strategy_id: experiment.candidate.strategy_id().to_string(),
                experiment_path: office_control_experiment(),
                experiment,
                verification: verification.report.clone(),
                shadow: shadow.report.clone(),
            })
            .unwrap();

        assert!(report.passed);
        assert_eq!(report.bundle_paths.len(), 1);
        assert!(report.invariants.len() >= 5);
        assert!(report.invariants.iter().all(|invariant| invariant.passed));
    }

    #[tokio::test]
    async fn formal_safety_gate_rejects_candidate_when_parameter_bounds_violate_repo_policy() {
        let root = unique_temp_dir("formal-safety-bounds");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verification");
        let shadow_dir = root.join("shadows");
        let config = sample_config();
        let config_path = repo_root().join("rulesets/default.yaml");
        let replay =
            DefaultReplayHarness::from_config(&config_path, config.clone(), &replay_dir).unwrap();
        let verification = replay
            .evaluate_verification_path(office_control_experiment(), &verification_dir)
            .await
            .unwrap();
        let (_, shadow) = replay
            .evaluate_experiment_and_shadow_path(
                office_control_experiment(),
                &experiment_dir,
                &shadow_dir,
            )
            .await
            .unwrap();
        let mut experiment =
            crate::replay::load_detector_experiment_manifest(office_control_experiment()).unwrap();
        if let crate::replay::DetectorCandidateManifest::SuspiciousProcessTree { profile, .. } =
            &mut experiment.candidate
        {
            profile.medium_confidence_threshold = 0.10;
        } else {
            panic!("expected suspicious process tree fixture");
        }
        let gate = DefaultFormalSafetyGate::from_config(config_path, config);

        let report = gate
            .verify(&StrategyGenome {
                strategy_id: experiment.candidate.strategy_id().to_string(),
                experiment_path: office_control_experiment(),
                experiment,
                verification: verification.report.clone(),
                shadow: shadow.report.clone(),
            })
            .unwrap();

        assert!(!report.passed);
        assert!(report.invariants.iter().any(|invariant| {
            invariant.name == "medium_confidence_bounds" && !invariant.passed
        }));
    }

    #[cfg(not(feature = "z3"))]
    #[tokio::test]
    async fn z3_custom_invariant_fails_closed_without_feature() {
        let root = unique_temp_dir("z3-disabled");
        let proofs_dir = root.join("proofs");
        let config_path = repo_root().join("rulesets/default.yaml");
        let bundle_path = write_custom_z3_bundle(
            &root,
            "z3_disabled_guardrail",
            "(declare-const medium_confidence Real)\n(assert (= medium_confidence {{/candidate/profile/medium_confidence_threshold}}))\n(assert (> medium_confidence 1.5))",
        );
        let mut config = sample_config();
        config.evolution.safety_gate.enable_z3 = true;
        config.evolution.safety_gate.invariant_bundle_paths =
            vec![bundle_path.display().to_string()];
        config.evolution.paths.evolution_proof_results_dir = proofs_dir.display().to_string();
        let candidate = verified_strategy_genome(&root, &config_path, &config).await;
        let gate = DefaultFormalSafetyGate::from_config(config_path, config);

        let report = gate.verify(&candidate).unwrap();

        assert!(!report.passed);
        assert_eq!(
            report.solver_summary.as_ref().map(|summary| summary.status),
            Some(EvolutionSolverProofStatus::Disabled)
        );
        let proof_store = FileEvolutionProofStore::open(&proofs_dir).unwrap();
        let proof = proof_store
            .load(report.persisted_proof_id.as_deref().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(
            proof
                .report
                .solver_summary
                .as_ref()
                .map(|summary| summary.status),
            Some(EvolutionSolverProofStatus::Disabled)
        );
    }

    #[cfg(feature = "z3")]
    #[tokio::test]
    async fn z3_custom_invariant_proves_unsat_and_persists_proof() {
        let root = unique_temp_dir("z3-proved");
        let proofs_dir = root.join("proofs");
        let config_path = repo_root().join("rulesets/default.yaml");
        let bundle_path = write_custom_z3_bundle(
            &root,
            "z3_proved_guardrail",
            "(declare-const medium_confidence Real)\n(assert (= medium_confidence {{/candidate/profile/medium_confidence_threshold}}))\n(assert (> medium_confidence 1.5))",
        );
        let mut config = sample_config();
        config.evolution.safety_gate.enable_z3 = true;
        config.evolution.safety_gate.invariant_bundle_paths =
            vec![bundle_path.display().to_string()];
        config.evolution.paths.evolution_proof_results_dir = proofs_dir.display().to_string();
        let candidate = verified_strategy_genome(&root, &config_path, &config).await;
        let gate = DefaultFormalSafetyGate::from_config(config_path, config);

        let report = gate.verify(&candidate).unwrap();

        assert!(report.passed);
        assert_eq!(
            report.solver_summary.as_ref().map(|summary| summary.status),
            Some(EvolutionSolverProofStatus::Proved)
        );
        let proof_store = FileEvolutionProofStore::open(&proofs_dir).unwrap();
        let proof = proof_store
            .load(report.persisted_proof_id.as_deref().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(
            proof
                .report
                .solver_summary
                .as_ref()
                .map(|summary| summary.status),
            Some(EvolutionSolverProofStatus::Proved)
        );
        assert!(render_evolution_proof(&proof.report).contains("Solver: proved"));
    }

    #[cfg(feature = "z3")]
    #[tokio::test]
    async fn z3_proof_persists_machine_readable_counterexample() {
        let root = unique_temp_dir("z3-counterexample");
        let proofs_dir = root.join("proofs");
        let config_path = repo_root().join("rulesets/default.yaml");
        let bundle_path = write_custom_z3_bundle(
            &root,
            "z3_counterexample_guardrail",
            "(declare-const medium_confidence Real)\n(assert (= medium_confidence {{/candidate/profile/medium_confidence_threshold}}))\n(assert (< medium_confidence 1.5))",
        );
        let mut config = sample_config();
        config.evolution.safety_gate.enable_z3 = true;
        config.evolution.safety_gate.invariant_bundle_paths =
            vec![bundle_path.display().to_string()];
        config.evolution.paths.evolution_proof_results_dir = proofs_dir.display().to_string();
        let candidate = verified_strategy_genome(&root, &config_path, &config).await;
        let gate = DefaultFormalSafetyGate::from_config(config_path, config);

        let report = gate.verify(&candidate).unwrap();

        assert!(!report.passed);
        assert_eq!(
            report.solver_summary.as_ref().map(|summary| summary.status),
            Some(EvolutionSolverProofStatus::Counterexample)
        );
        let proof_store = FileEvolutionProofStore::open(&proofs_dir).unwrap();
        let proof = proof_store
            .load(report.persisted_proof_id.as_deref().unwrap())
            .unwrap()
            .unwrap();
        let artifact = proof.report.solver_artifacts.first().unwrap();
        assert_eq!(artifact.status, EvolutionSolverProofStatus::Counterexample);
        assert!(!artifact.counterexamples.is_empty());
        assert_eq!(artifact.counterexamples[0].name, "medium_confidence");
        assert!(!artifact.attestation_sha256.is_empty());
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
        assert_eq!(
            proposal
                .report
                .assurance
                .as_ref()
                .map(|summary| summary.decision),
            Some(EvolutionProposalAssuranceDecision::Passed)
        );
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
    async fn evolution_queue_blocks_when_assurance_coverage_floor_is_not_met() {
        let root = unique_temp_dir("queue-assurance-coverage");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verification");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let proofs_dir = root.join("proofs");
        let queue_dir = root.join("queue");
        let mut config = sample_config();
        config.evolution.assurance.coverage_overrides = vec![
            swarm_core::config::EvolutionAssuranceCoverageOverrideConfig {
                detector: "suspicious_process_tree".to_string(),
                min_catch_rate: 1.0,
            },
        ];
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
            EvolutionProposalReviewState::Blocked
        );
        assert_eq!(
            proposal
                .report
                .assurance
                .as_ref()
                .map(|summary| summary.decision),
            Some(EvolutionProposalAssuranceDecision::Blocked)
        );
        assert!(proposal.report.blocking_reasons.iter().any(|reason| {
            reason.source == "assurance" && reason.name == "coverage_floor_not_met"
        }));
    }

    #[tokio::test]
    async fn evolution_queue_blocks_when_solver_summary_is_required() {
        let root = unique_temp_dir("queue-assurance-solver");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verification");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let proofs_dir = root.join("proofs");
        let queue_dir = root.join("queue");
        let mut config = sample_config();
        config.evolution.assurance.require_solver_summary = true;
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
            EvolutionProposalReviewState::Blocked
        );
        assert_eq!(
            proposal
                .report
                .assurance
                .as_ref()
                .map(|summary| summary.decision),
            Some(EvolutionProposalAssuranceDecision::Blocked)
        );
        assert!(proposal.report.blocking_reasons.iter().any(|reason| {
            reason.source == "assurance" && reason.name == "missing_solver_summary"
        }));
        assert!(render_evolution_proposal(&proposal.report).contains("Assurance: blocked"));
    }

    #[tokio::test]
    async fn evolution_queue_harvests_replayable_coverage_gap_cases() {
        let root = unique_temp_dir("queue-assurance-harvest-coverage");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verification");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let proofs_dir = root.join("proofs");
        let queue_dir = root.join("queue");
        let harvest_dir = root.join("assurance-cases");
        let mut config = sample_config();
        config.evolution.assurance.harvest.results_dir = harvest_dir.display().to_string();
        config.evolution.assurance.harvest.max_cases_per_proposal = 2;
        config.evolution.assurance.harvest.max_events_per_case = 1;
        config.evolution.assurance.coverage_overrides = vec![
            swarm_core::config::EvolutionAssuranceCoverageOverrideConfig {
                detector: "suspicious_process_tree".to_string(),
                min_catch_rate: 1.0,
            },
        ];
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

        let harvested_case_ids = proposal
            .report
            .assurance
            .as_ref()
            .unwrap()
            .harvested_case_ids
            .clone();
        assert!(!harvested_case_ids.is_empty());
        let scenario_paths = fs::read_dir(harvest_dir.join("scenarios"))
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        assert_eq!(scenario_paths.len(), harvested_case_ids.len());
        let harvested = crate::replay::load_scenario_manifest(&scenario_paths[0]).unwrap();
        assert!(
            harvested
                .manifest
                .metadata
                .tags
                .contains(&"assurance_case".to_string())
        );
        assert!(
            harvested
                .manifest
                .receipt_chain
                .contains(&proposal.report.proposal_id)
        );
        match harvested.manifest.input {
            crate::replay::ReplayScenarioInput::Events { events } => {
                assert_eq!(events.len(), 1);
            }
            crate::replay::ReplayScenarioInput::ReplayBundles { .. } => {
                panic!("coverage harvest should regenerate event-based scenarios");
            }
        }
        assert!(render_evolution_proposal(&proposal.report).contains("Assurance harvested cases"));
    }

    #[cfg(feature = "z3")]
    #[tokio::test]
    async fn evolution_queue_harvests_solver_counterexample_cases() {
        let root = unique_temp_dir("queue-assurance-harvest-solver");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verification");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let proofs_dir = root.join("proofs");
        let queue_dir = root.join("queue");
        let harvest_dir = root.join("assurance-cases");
        let config_path = repo_root().join("rulesets/default.yaml");
        let bundle_path = write_custom_z3_bundle(
            &root,
            "z3_queue_counterexample_guardrail",
            "(declare-const medium_confidence Real)\n(assert (= medium_confidence {{/candidate/profile/medium_confidence_threshold}}))\n(assert (< medium_confidence 1.5))",
        );
        let mut config = sample_config();
        config.evolution.assurance.harvest.results_dir = harvest_dir.display().to_string();
        config.evolution.safety_gate.enable_z3 = true;
        config.evolution.safety_gate.invariant_bundle_paths =
            vec![bundle_path.display().to_string()];
        config.evolution.paths.evolution_proof_results_dir = proofs_dir.display().to_string();
        let replay =
            DefaultReplayHarness::from_config(&config_path, config.clone(), &replay_dir).unwrap();
        let verification = replay
            .evaluate_verification_path(office_control_experiment(), &verification_dir)
            .await
            .unwrap();
        let candidate = verified_strategy_genome(&root, &config_path, &config).await;
        let gate = DefaultFormalSafetyGate::from_config(&config_path, config.clone());
        let proof_report = gate.verify(&candidate).unwrap();
        let proof_store = FileEvolutionProofStore::open(&proofs_dir).unwrap();
        let proof = proof_store
            .load(proof_report.persisted_proof_id.as_deref().unwrap())
            .unwrap()
            .unwrap();
        assert!(
            proof
                .report
                .solver_artifacts
                .iter()
                .any(|artifact| !artifact.counterexamples.is_empty())
        );
        let scorecards = DefaultStrategyScorecardHarness::from_config(
            &config_path,
            config.clone(),
            &memory_dir,
            &scorecard_dir,
        )
        .unwrap();
        let queue =
            DefaultEvolutionQueueHarness::from_config(&config_path, config, &queue_dir).unwrap();

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

        let harvested_case_ids = proposal
            .report
            .assurance
            .as_ref()
            .unwrap()
            .harvested_case_ids
            .clone();
        assert!(!harvested_case_ids.is_empty());
        let scenario_paths = fs::read_dir(harvest_dir.join("scenarios"))
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        assert!(!scenario_paths.is_empty());
        let harvested = crate::replay::load_scenario_manifest(&scenario_paths[0]).unwrap();
        match harvested.manifest.input {
            crate::replay::ReplayScenarioInput::ReplayBundles { paths } => {
                assert_eq!(paths.len(), 1);
                assert!(PathBuf::from(&paths[0]).exists());
            }
            crate::replay::ReplayScenarioInput::Events { .. } => {
                panic!("solver harvest should preserve replay-bundle input");
            }
        }
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
        let verification_report =
            persist_passed_verification(&verification_dir, &verification.report);
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
                &verification_report.verification_id,
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
                    verification_id: verification_report.verification_id.clone(),
                    proof_results_dir: proofs_dir.clone(),
                    proof_id: proof.report.proof_id.clone(),
                },
            )
            .await
            .unwrap();

        // Supply assurance lineage so the proposal passes the v1.51 assurance gate.
        {
            let store = FileEvolutionProposalStore::open(&queue_dir).unwrap();
            let mut report = store
                .load(&proposal.report.proposal_id)
                .unwrap()
                .unwrap()
                .report;
            report.assurance = Some(passed_assurance_summary());
            report.blocking_reasons.retain(|r| r.source != "assurance");
            if report.blocking_reasons.is_empty() {
                report.review_state = EvolutionProposalReviewState::PendingReview;
            }
            store.persist(&report).unwrap();
        }

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
        assert!(render_evolution_handoff(&lookup.report).contains("Assurance: passed"));
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
        let verification_report =
            persist_passed_verification(&verification_dir, &verification.report);
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
                &verification_report.verification_id,
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
                    verification_id: verification_report.verification_id.clone(),
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
    async fn evolution_handoff_blocks_when_assurance_lineage_is_unsatisfied() {
        let root = unique_temp_dir("handoff-assurance-blocked");
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
        let verification_report =
            persist_passed_verification(&verification_dir, &verification.report);
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
                &verification_report.verification_id,
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
                    verification_id: verification_report.verification_id.clone(),
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
        let store = FileEvolutionProposalStore::open(&queue_dir).unwrap();
        let mut tampered = store
            .load(&accepted.report.proposal_id)
            .unwrap()
            .unwrap()
            .report;
        let mut assurance = tampered.assurance.unwrap();
        assurance.decision = EvolutionProposalAssuranceDecision::Blocked;
        assurance.harvested_case_ids = vec!["case-a".to_string()];
        tampered.assurance = Some(assurance);
        tampered.blocking_reasons = Vec::new();
        store.persist(&tampered).unwrap();
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

        assert_eq!(lookup.report.launch_status, EvolutionHandoffStatus::Blocked);
        assert!(
            lookup
                .report
                .blocking_reasons
                .iter()
                .any(|reason| reason.source == "assurance")
        );
    }

    #[tokio::test]
    async fn evolution_queue_applies_signed_assurance_waiver_and_allows_accept_for_canary() {
        let root = unique_temp_dir("queue-assurance-waiver");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verification");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let proofs_dir = root.join("proofs");
        let queue_dir = root.join("queue");
        let secret_material = "phase-175-waiver-operator";
        let operator_id = operator_id_for_secret(secret_material);
        let mut config = sample_config();
        config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
        let replay =
            DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
        let verification = replay
            .evaluate_verification_path(office_control_experiment(), &verification_dir)
            .await
            .unwrap();
        let verification_report =
            persist_passed_verification(&verification_dir, &verification.report);
        let proof_harness =
            DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proofs_dir)
                .unwrap();
        let proof = proof_harness
            .create_proof(
                office_control_experiment(),
                &verification_dir,
                &verification_report.verification_id,
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
                    verification_id: verification_report.verification_id.clone(),
                    proof_results_dir: proofs_dir.clone(),
                    proof_id: proof.report.proof_id.clone(),
                },
            )
            .await
            .unwrap();
        persist_blocked_assurance_proposal(&queue_dir, &proposal.report.proposal_id);

        let waived = queue
            .apply_assurance_waiver(
                &proposal.report.proposal_id,
                super::EvolutionAssuranceWaiverRequest {
                    operator_id,
                    secret_material: secret_material.to_string(),
                    reason: "bounded review waiver for assurance backlog".to_string(),
                    ttl_secs: 300,
                },
            )
            .unwrap();
        let waiver = waived
            .report
            .assurance
            .as_ref()
            .and_then(|summary| summary.waiver.as_ref())
            .unwrap();
        assert_eq!(
            waived.report.review_state,
            EvolutionProposalReviewState::Blocked
        );
        assert_eq!(
            waived.report.decision_history.last().unwrap().action,
            EvolutionProposalDecisionAction::ApplyAssuranceWaiver
        );
        assert!(render_evolution_proposal(&waived.report).contains("Assurance waiver:"));
        assert!(
            render_evolution_proposal(&waived.report)
                .contains("bounded review waiver for assurance backlog")
        );
        assert_eq!(waiver.waived_gap_count, 2);

        let accepted = queue
            .record_decision(
                &proposal.report.proposal_id,
                EvolutionProposalDecisionAction::AcceptForCanary,
                "waived assurance gaps are bounded and ready for canary",
            )
            .unwrap();
        assert_eq!(
            accepted.report.review_state,
            EvolutionProposalReviewState::AcceptedForCanary
        );
    }

    #[tokio::test]
    async fn evolution_handoff_preserves_waived_assurance_lineage() {
        let root = unique_temp_dir("handoff-waived-assurance");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verification");
        let shadow_dir = root.join("shadows");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let proofs_dir = root.join("proofs");
        let queue_dir = root.join("queue");
        let handoff_dir = root.join("handoffs");
        let secret_material = "phase-175-handoff-waiver";
        let operator_id = operator_id_for_secret(secret_material);
        let mut config = sample_config();
        config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
        let replay =
            DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
        let verification = replay
            .evaluate_verification_path(office_control_experiment(), &verification_dir)
            .await
            .unwrap();
        let verification_report =
            persist_passed_verification(&verification_dir, &verification.report);
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
                &verification_report.verification_id,
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
                    verification_id: verification_report.verification_id.clone(),
                    proof_results_dir: proofs_dir.clone(),
                    proof_id: proof.report.proof_id.clone(),
                },
            )
            .await
            .unwrap();
        persist_blocked_assurance_proposal(&queue_dir, &proposal.report.proposal_id);
        queue
            .apply_assurance_waiver(
                &proposal.report.proposal_id,
                super::EvolutionAssuranceWaiverRequest {
                    operator_id,
                    secret_material: secret_material.to_string(),
                    reason: "handoff lineage waiver".to_string(),
                    ttl_secs: 300,
                },
            )
            .unwrap();
        let accepted = queue
            .record_decision(
                &proposal.report.proposal_id,
                EvolutionProposalDecisionAction::AcceptForCanary,
                "waived assurance lineage is ready for handoff",
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
        assert!(
            lookup
                .report
                .assurance
                .as_ref()
                .and_then(|summary| summary.waiver.as_ref())
                .is_some()
        );
        assert!(render_evolution_handoff(&lookup.report).contains("Assurance waiver:"));
        assert!(
            render_evolution_handoff(&lookup.report)
                .contains("Waiver reason: handoff lineage waiver")
        );
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
        let verification_report =
            persist_passed_verification(&verification_dir, &verification.report);
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
                &verification_report.verification_id,
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
                    verification_id: verification_report.verification_id.clone(),
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

    #[tokio::test]
    async fn evolution_handoff_launch_rejects_missing_assurance_lineage() {
        let root = unique_temp_dir("handoff-launch-missing-assurance");
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
        let verification_report =
            persist_passed_verification(&verification_dir, &verification.report);
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
                &verification_report.verification_id,
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
                    verification_id: verification_report.verification_id.clone(),
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
        let mut tampered = handoff.report.clone();
        tampered.assurance = None;
        handoff_harness.store.persist(&tampered).unwrap();
        let canary_harness =
            DefaultCanaryHarness::from_config("inline", config, &canary_dir).unwrap();

        let error = handoff_harness
            .launch_canary(
                &canary_harness,
                &verification_dir,
                &shadow_dir,
                &handoff.report.handoff_id,
            )
            .unwrap_err();

        assert!(matches!(
            error,
            super::EvolutionQueueError::InvalidHandoffLaunch { .. }
        ));
    }

    // --- Assurance gate unit tests ---

    fn blocked_assurance_summary(gap_count: usize) -> EvolutionProposalAssuranceSummary {
        EvolutionProposalAssuranceSummary {
            decision: EvolutionProposalAssuranceDecision::Blocked,
            coverage: EvolutionProposalAssuranceCoverageSummary {
                detector: "office_baseline_control".to_string(),
                suite_name: Some("evasion-breadth-v1".to_string()),
                corpus_version: Some("2026-04-03".to_string()),
                required_catch_rate: 0.75,
                actual_catch_rate: Some(0.50),
                actionable_gap_count: gap_count,
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

    fn waiver_config() -> SwarmConfig {
        let mut config = sample_config();
        config.evolution.assurance.waiver.allowed_operator_ids =
            vec!["swarm:ed25519:waiver-test-operator".to_string()];
        config.evolution.assurance.waiver.max_actionable_gap_count = 5;
        config
    }

    fn build_valid_waiver(
        assurance: &EvolutionProposalAssuranceSummary,
        operator_id: &str,
        secret_material: &str,
        issued_at_ms: i64,
        ttl_secs: u64,
    ) -> EvolutionAssuranceWaiverSummary {
        let signer = Ed25519Signer::from_secret_material(secret_material);
        build_assurance_waiver_summary(
            "test-proposal-id",
            assurance,
            operator_id,
            &signer,
            issued_at_ms,
            ttl_secs,
            "justified test waiver",
        )
        .unwrap()
    }

    #[test]
    fn rollout_state_clear_when_assurance_passed() {
        let config = sample_config();
        let assurance = passed_assurance_summary();
        let state = assurance_rollout_state(Some(&assurance), &config, 1_000_000);
        assert_eq!(state, EvolutionAssuranceRolloutState::Clear);
    }

    #[test]
    fn rollout_state_blocked_when_no_assurance() {
        let config = sample_config();
        let state = assurance_rollout_state(None, &config, 1_000_000);
        assert_eq!(state, EvolutionAssuranceRolloutState::Blocked);
    }

    #[test]
    fn rollout_state_blocked_when_decision_blocked_without_waiver() {
        let config = sample_config();
        let assurance = blocked_assurance_summary(2);
        let state = assurance_rollout_state(Some(&assurance), &config, 1_000_000);
        assert_eq!(state, EvolutionAssuranceRolloutState::Blocked);
    }

    #[test]
    fn gate_block_reason_none_when_passed() {
        let config = sample_config();
        let assurance = passed_assurance_summary();
        let reason = assurance_gate_block_reason(Some(&assurance), &config, 1_000_000, "test");
        assert!(reason.is_none());
    }

    #[test]
    fn gate_block_reason_present_when_no_assurance() {
        let config = sample_config();
        let reason = assurance_gate_block_reason(None, &config, 1_000_000, "queue proposal");
        assert!(reason.is_some());
        assert!(
            reason
                .unwrap()
                .contains("missing durable assurance lineage")
        );
    }

    #[test]
    fn gate_block_reason_present_when_blocked_without_waiver() {
        let config = sample_config();
        let assurance = blocked_assurance_summary(2);
        let reason =
            assurance_gate_block_reason(Some(&assurance), &config, 1_000_000, "canary admission");
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("canary admission"));
    }

    #[test]
    fn validate_waiver_rejects_empty_reason() {
        let config = waiver_config();
        let signer = Ed25519Signer::from_secret_material("waiver-key");
        let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
        let mut wconfig = config.clone();
        wconfig.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
        let mut assurance = blocked_assurance_summary(2);
        let mut waiver = build_valid_waiver(&assurance, &operator_id, "waiver-key", 1000, 3600);
        waiver.reason = "   ".to_string();
        assurance.waiver = Some(waiver);
        let result = validate_assurance_waiver(&assurance, &wconfig, 2000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("reason must not be empty"));
    }

    #[test]
    fn validate_waiver_rejects_expired_waiver() {
        let signer = Ed25519Signer::from_secret_material("waiver-key");
        let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
        let mut config = waiver_config();
        config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
        let mut assurance = blocked_assurance_summary(2);
        let waiver = build_valid_waiver(&assurance, &operator_id, "waiver-key", 1000, 60);
        assurance.waiver = Some(waiver);
        // current_time well past expiry (1000 + 60*1000 = 61000, query at 100_000)
        let result = validate_assurance_waiver(&assurance, &config, 100_000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }

    #[test]
    fn validate_waiver_rejects_unauthorized_operator() {
        let signer = Ed25519Signer::from_secret_material("waiver-key");
        let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
        let config = waiver_config(); // allowed_operator_ids doesn't include our signer
        let mut assurance = blocked_assurance_summary(2);
        let waiver = build_valid_waiver(&assurance, &operator_id, "waiver-key", 1000, 3600);
        assurance.waiver = Some(waiver);
        let result = validate_assurance_waiver(&assurance, &config, 2000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not allowed"));
    }

    #[test]
    fn validate_waiver_rejects_gap_count_above_limit() {
        let signer = Ed25519Signer::from_secret_material("waiver-key");
        let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
        let mut config = waiver_config();
        config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
        config.evolution.assurance.waiver.max_actionable_gap_count = 1; // limit is 1
        let mut assurance = blocked_assurance_summary(3); // 3 gaps > 1
        let waiver = build_valid_waiver(&assurance, &operator_id, "waiver-key", 1000, 3600);
        assurance.waiver = Some(waiver);
        let result = validate_assurance_waiver(&assurance, &config, 2000);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("exceeds configured waiver limit")
        );
    }

    #[test]
    fn validate_waiver_rejects_mismatched_gap_count() {
        let signer = Ed25519Signer::from_secret_material("waiver-key");
        let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
        let mut config = waiver_config();
        config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
        let assurance_at_sign_time = blocked_assurance_summary(2);
        let mut waiver = build_valid_waiver(
            &assurance_at_sign_time,
            &operator_id,
            "waiver-key",
            1000,
            3600,
        );
        // Tamper: the waiver was signed for 2 gaps but lineage now carries 4
        let mut assurance = blocked_assurance_summary(4);
        waiver.waived_gap_count = 2; // stale from original signing
        assurance.waiver = Some(waiver);
        let result = validate_assurance_waiver(&assurance, &config, 2000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("waived gaps"));
    }

    #[test]
    fn validate_waiver_rejects_tampered_signature() {
        let signer = Ed25519Signer::from_secret_material("waiver-key");
        let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
        let mut config = waiver_config();
        config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
        let mut assurance = blocked_assurance_summary(2);
        let mut waiver = build_valid_waiver(&assurance, &operator_id, "waiver-key", 1000, 3600);
        // Tamper with the signature
        waiver.signature.signature_hex = "deadbeef".repeat(16);
        assurance.waiver = Some(waiver);
        let result = validate_assurance_waiver(&assurance, &config, 2000);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("signature verification failed")
        );
    }

    #[test]
    fn validate_waiver_accepts_valid_waiver_within_window() {
        let signer = Ed25519Signer::from_secret_material("waiver-key");
        let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
        let mut config = waiver_config();
        config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
        let mut assurance = blocked_assurance_summary(2);
        let waiver = build_valid_waiver(&assurance, &operator_id, "waiver-key", 1000, 3600);
        assurance.waiver = Some(waiver);
        let result = validate_assurance_waiver(&assurance, &config, 2000);
        assert!(result.is_ok());
    }

    #[test]
    fn rollout_state_waived_when_blocked_with_valid_waiver() {
        let signer = Ed25519Signer::from_secret_material("waiver-key");
        let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
        let mut config = waiver_config();
        config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
        let mut assurance = blocked_assurance_summary(2);
        let waiver = build_valid_waiver(&assurance, &operator_id, "waiver-key", 1000, 3600);
        assurance.waiver = Some(waiver);
        let state = assurance_rollout_state(Some(&assurance), &config, 2000);
        assert_eq!(state, EvolutionAssuranceRolloutState::Waived);
    }

    #[test]
    fn gate_allows_when_blocked_with_valid_waiver() {
        let signer = Ed25519Signer::from_secret_material("waiver-key");
        let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
        let mut config = waiver_config();
        config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
        let mut assurance = blocked_assurance_summary(2);
        let waiver = build_valid_waiver(&assurance, &operator_id, "waiver-key", 1000, 3600);
        assurance.waiver = Some(waiver);
        let reason = assurance_gate_block_reason(Some(&assurance), &config, 2000, "canary");
        assert!(reason.is_none());
    }

    #[test]
    fn gate_blocks_when_waiver_expired() {
        let signer = Ed25519Signer::from_secret_material("waiver-key");
        let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
        let mut config = waiver_config();
        config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
        let mut assurance = blocked_assurance_summary(2);
        let waiver = build_valid_waiver(&assurance, &operator_id, "waiver-key", 1000, 60);
        assurance.waiver = Some(waiver);
        // well past expiry
        let reason = assurance_gate_block_reason(Some(&assurance), &config, 200_000, "promotion");
        assert!(reason.is_some());
    }

    #[test]
    fn validate_waiver_rejects_not_yet_active() {
        let signer = Ed25519Signer::from_secret_material("waiver-key");
        let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
        let mut config = waiver_config();
        config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
        let mut assurance = blocked_assurance_summary(2);
        let waiver = build_valid_waiver(&assurance, &operator_id, "waiver-key", 10_000, 3600);
        assurance.waiver = Some(waiver);
        // current_time before issuance
        let result = validate_assurance_waiver(&assurance, &config, 5_000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not active until"));
    }
}
