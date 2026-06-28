use super::*;

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
    pub(crate) fn from_report(report: &EvolutionProofReport, bundle_path: String) -> Self {
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
pub(crate) struct FormalSafetyInvariantEvaluation {
    pub(crate) verdict: FormalSafetyInvariantVerdict,
    pub(crate) solver_artifact: Option<EvolutionSolverInvariantArtifact>,
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
    pub(crate) fn from_scorecard(scorecard: &StrategyScorecard) -> Self {
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
pub(crate) struct EvolutionAssuranceWaiverPayload<'a> {
    pub(crate) waiver_id: &'a str,
    pub(crate) operator_id: &'a str,
    pub(crate) issued_at_ms: i64,
    pub(crate) expires_at_ms: i64,
    pub(crate) reason: &'a str,
    pub(crate) waived_gap_count: usize,
    pub(crate) assurance_sha256: &'a str,
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
    pub(crate) fn from_report(report: &EvolutionProposalReport, bundle_path: String) -> Self {
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
    pub(crate) fn from_report(report: &EvolutionHandoffReport, bundle_path: String) -> Self {
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
pub(crate) enum EvolutionAssuranceCaseKind {
    CoverageGap,
    SolverCounterexample,
}

/// Durable replay-ready assurance case persisted for one blocked proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EvolutionAssuranceCaseReport {
    pub(crate) case_id: String,
    pub(crate) proposal_id: String,
    pub(crate) created_at_ms: i64,
    pub(crate) strategy_id: String,
    pub(crate) detector: String,
    pub(crate) kind: EvolutionAssuranceCaseKind,
    pub(crate) scenario_name: String,
    pub(crate) scenario_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) suite_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) corpus_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) verification_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) proof_id: Option<String>,
    pub(crate) reason_name: String,
    pub(crate) reason_details: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) threat_class: Option<ThreatClass>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) techniques: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) counterexample_bindings: Vec<EvolutionSolverCounterexample>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) source_references: Vec<String>,
}

/// Index metadata surfaced for one persisted assurance case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EvolutionAssuranceCaseRecord {
    pub(crate) case_id: String,
    pub(crate) proposal_id: String,
    pub(crate) detector: String,
    pub(crate) kind: EvolutionAssuranceCaseKind,
    pub(crate) created_at_ms: i64,
    pub(crate) scenario_path: String,
    pub(crate) bundle_path: String,
}

impl EvolutionAssuranceCaseRecord {
    pub(crate) fn from_report(report: &EvolutionAssuranceCaseReport, bundle_path: String) -> Self {
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
