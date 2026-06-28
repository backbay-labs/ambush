use crate::agent_identity::{
    FileAgentIdentityRegistry, FileAgentKeyStore, resolve_agent_key_dir,
    resolve_identity_registry_dir,
};
use crate::approval::{
    DefaultApprovalHarness, ThresholdRule, render_approval_ledger, render_approval_ledger_list,
    render_approval_receipt_pack, render_approval_receipt_pack_list, render_approval_set,
    render_approval_verdict, render_approval_verdict_list,
};
use crate::canary::{DefaultCanaryHarness, render_canary_run_report};
use crate::config::{CURRENT_SCHEMA_VERSION, load_config};
use crate::control::{
    DefaultControlPlane, FirstRunStatus, FirstRunWizardOptions, FirstRunWizardPaths,
    IncidentLookupSelector, InvestigationLookupSelector, OperatorControlOutput,
    ReplayLookupSelector, render_output, resolve_operator_api_schema_version,
};
use crate::drafting::{
    DefaultEvolutionDraftingHarness, EvolutionDraftCreateRequest,
    EvolutionDraftMaterializationRequest, render_evolution_draft, render_evolution_draft_promotion,
    render_evolution_materialization, render_evolution_pressure,
    render_evolution_queue_reconciliation, render_evolution_validation_bundle,
};
use crate::evidence::{
    DefaultEvidenceHarness, EvidenceExportRequest, EvidenceHarnessPaths, EvidenceSubjectKind,
    render_evidence_bundle, render_evidence_bundle_list, render_evidence_verification,
    render_promotion_evidence_packet,
};
use crate::evolution::{
    DefaultEvolutionHandoffHarness, DefaultEvolutionProofHarness, DefaultEvolutionQueueHarness,
    EvolutionProposalCreateRequest, EvolutionProposalDecisionAction, EvolutionProposalReviewState,
    render_evolution_handoff, render_evolution_proof, render_evolution_proposal,
    render_evolution_proposal_list,
};
use crate::evolution_status::{DefaultEvolutionStatusHarness, render_evolution_status};
use crate::governance_prep::{
    DefaultEvolutionGovernancePrepHarness, render_evolution_governance_packet_set,
    render_evolution_governance_packet_set_list, render_evolution_portfolio_history,
    render_evolution_portfolio_history_list,
};
use crate::mutation::{
    DefaultEvolutionMutationHarness, EvolutionMutationProfileOverrides,
    EvolutionMutationSpecCreateRequest, EvolutionMutationVariantCreateRequest,
    render_evolution_mutation_materialization_batch, render_evolution_mutation_ranking,
    render_evolution_mutation_spec, render_evolution_mutation_validation_batch,
};
use crate::operator_http::{LocalOperatorSurface, OperatorSurfacePaths};
use crate::portfolio::{
    DefaultEvolutionPortfolioHarness, EvolutionPortfolioDecisionAction,
    EvolutionPortfolioEntryCreateRequest, EvolutionPortfolioEntryReviewState,
    render_evolution_governance_review_packet, render_evolution_portfolio,
    render_evolution_portfolio_list,
};
use crate::promotion::{
    DefaultProductionPromotionHarness, ProductionPromotionStatus, PromotionApprovalVoteRef,
    render_production_promotion_list, render_production_promotion_report,
};
use crate::replay::{
    DefaultReplayHarness, render_evaluation_report, render_experiment_report,
    render_promotion_review_packet, render_replay_run, render_shadow_report, render_suite_report,
    render_verification_report,
};
use crate::review_workbench::{
    DefaultReviewWorkbenchHarness, ReviewArtifactRef, ReviewArtifactRefKind,
    ReviewCapsuleImportRequest, ReviewDelegationCreateRequest, ReviewSessionCreateRequest,
    ReviewSessionReverifyRequest, render_review_capsule, render_review_capsule_import,
    render_review_delegation_packet, render_review_session, render_review_session_export,
    render_review_session_handoff, render_review_session_list,
    render_review_session_promotion_readiness,
};
use crate::selection::{
    DefaultEvolutionSelectionHarness, render_evolution_ranked_candidate_bridge,
    render_evolution_ranked_candidate_selection, render_evolution_ranked_candidate_selection_list,
};
use crate::strategy::{
    DefaultStrategyMemoryHarness, DefaultStrategyScorecardHarness, render_strategy_memory,
    render_strategy_memory_history, render_strategy_scorecard,
};
use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use swarm_core::agent::{AgentRole, SwarmMode};
use swarm_core::config::{
    PheromoneBackendConfig, ResponseAdapterConfig, RuntimeMode, SiemForwardConfig, SwarmConfig,
};
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;
use swarm_crypto::{Ed25519Signer, canonical_json_bytes};
use swarm_runtime::service::ResponsePlaybookPreviewRequest;

#[derive(Debug, Parser)]
#[command(
    name = "swarmctl",
    about = "Repo-owned operator control surface for Swarm Team Six"
)]
pub struct Cli {
    #[arg(long, global = true, default_value = "rulesets/default.yaml")]
    config: std::path::PathBuf,

    #[arg(long = "output-schema-version", global = true)]
    output_schema_version: Option<u32>,

    #[arg(long, global = true, default_value = "data/replay-runs")]
    replay_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/experiments")]
    experiment_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/verifications")]
    verification_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/shadows")]
    shadow_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/promotion-reviews")]
    promotion_review_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/canaries")]
    canary_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/promotions")]
    promotion_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/strategy-memory")]
    strategy_memory_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/strategy-scorecards")]
    strategy_scorecard_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/evolution-proofs")]
    evolution_proof_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/evolution-queue")]
    evolution_queue_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/evolution-handoffs")]
    evolution_handoff_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/evolution-pressures")]
    evolution_pressure_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/evolution-drafts")]
    evolution_draft_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/evolution-draft-promotions")]
    evolution_draft_promotion_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/evolution-materializations")]
    evolution_materialization_results_dir: std::path::PathBuf,

    #[arg(
        long,
        global = true,
        default_value = "data/evolution-validation-bundles"
    )]
    evolution_validation_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/evolution-reconciliations")]
    evolution_reconciliation_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/evolution-mutations")]
    evolution_mutation_results_dir: std::path::PathBuf,

    #[arg(
        long,
        global = true,
        default_value = "data/evolution-mutation-materialization-batches"
    )]
    evolution_mutation_materialization_batch_results_dir: std::path::PathBuf,

    #[arg(
        long,
        global = true,
        default_value = "data/evolution-mutation-validation-batches"
    )]
    evolution_mutation_validation_batch_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/evolution-rankings")]
    evolution_ranking_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/evolution-selections")]
    evolution_selection_results_dir: std::path::PathBuf,

    #[arg(
        long,
        global = true,
        default_value = "data/evolution-selection-bridges"
    )]
    evolution_selection_bridge_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/evolution-portfolios")]
    evolution_portfolio_results_dir: std::path::PathBuf,

    #[arg(
        long,
        global = true,
        default_value = "data/evolution-governance-review-packets"
    )]
    evolution_governance_review_packet_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/evolution-packet-sets")]
    evolution_packet_set_results_dir: std::path::PathBuf,

    #[arg(
        long,
        global = true,
        default_value = "data/evolution-portfolio-history"
    )]
    evolution_portfolio_history_results_dir: std::path::PathBuf,

    #[arg(
        long,
        global = true,
        default_value = "data/operator-maintenance-actions"
    )]
    operator_maintenance_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/evidence-bundles")]
    evidence_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/evidence-verifications")]
    evidence_verification_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/promotion-evidence-packets")]
    promotion_evidence_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/review-sessions")]
    review_session_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/review-session-exports")]
    review_session_export_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/review-session-readiness")]
    review_session_readiness_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/review-session-handoffs")]
    review_session_handoff_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/review-capsules")]
    review_capsule_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/review-capsule-imports")]
    review_capsule_import_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/review-delegations")]
    review_delegation_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/approval-sets")]
    approval_set_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/approval-ledgers")]
    approval_ledger_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/approval-verdicts")]
    approval_verdict_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "data/approval-receipt-packs")]
    approval_receipt_pack_results_dir: std::path::PathBuf,

    #[arg(long, global = true, default_value = "local-evidence-signer")]
    evidence_signer_id: String,

    #[arg(long, global = true, default_value = "SWARM_EVIDENCE_SIGNING_KEY")]
    evidence_signing_key_env: String,

    #[arg(long, global = true)]
    json: bool,

    #[arg(long, global = true)]
    otlp_endpoint: Option<String>,

    #[command(subcommand)]
    command: Command,
}

impl Cli {
    pub fn otlp_endpoint(&self) -> Option<&str> {
        self.otlp_endpoint.as_deref()
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    Validate(ValidateArgs),
    Init(InitArgs),
    Readiness,
    FirstRun(FirstRunArgs),
    PlaybookPreview(PlaybookPreviewArgs),
    Identity(IdentityArgs),
    Serve,
    Status,
    Evolution(EvolutionArgs),
    Replay(ReplayArgs),
    Investigation(InvestigationArgs),
    Incident(IncidentArgs),
    ReplayRun(ReplayRunArgs),
    ReplayResult(ReplayResultArgs),
    EvidenceExport(EvidenceExportArgs),
    EvidenceResult(EvidenceResultArgs),
    EvidenceList(EvidenceListArgs),
    EvidenceVerify(EvidenceVerifyArgs),
    EvidenceVerificationResult(EvidenceVerificationResultArgs),
    PromotionEvidenceCreate(PromotionEvidenceCreateArgs),
    PromotionEvidenceResult(PromotionEvidenceResultArgs),
    ApprovalSetCreate(ApprovalSetCreateArgs),
    ApprovalSetResult(ApprovalSetResultArgs),
    ApprovalVoteAppend(ApprovalVoteAppendArgs),
    ApprovalLedgerResult(ApprovalLedgerResultArgs),
    ApprovalLedgerList(ApprovalLedgerListArgs),
    ApprovalVerdictCreate(ApprovalVerdictCreateArgs),
    ApprovalVerdictResult(ApprovalVerdictResultArgs),
    ApprovalVerdictList,
    ApprovalReceiptPackExport(ApprovalReceiptPackExportArgs),
    ApprovalReceiptPackResult(ApprovalReceiptPackResultArgs),
    ApprovalReceiptPackList,
    ApprovalReceiptPackVerify(ApprovalReceiptPackVerifyArgs),
    ReviewSessionCreate(ReviewSessionCreateArgs),
    ReviewSessionResult(ReviewSessionResultArgs),
    ReviewSessionList,
    ReviewSessionExport(ReviewSessionExportArgs),
    ReviewSessionExportResult(ReviewSessionExportResultArgs),
    ReviewCapsuleCreate(ReviewCapsuleCreateArgs),
    ReviewCapsuleResult(ReviewCapsuleResultArgs),
    ReviewCapsuleImport(ReviewCapsuleImportArgs),
    ReviewCapsuleImportResult(ReviewCapsuleImportResultArgs),
    ReviewDelegationCreate(ReviewDelegationCreateArgs),
    ReviewDelegationResult(ReviewDelegationResultArgs),
    ReviewSessionPromotionReadiness(ReviewSessionPromotionReadinessArgs),
    ReviewSessionPromotionReadinessResult(ReviewSessionPromotionReadinessResultArgs),
    ReviewSessionHandoffReverify(ReviewSessionHandoffReverifyArgs),
    ReviewSessionHandoffResult(ReviewSessionHandoffResultArgs),
    ReplayEvaluate(ReplayEvaluateArgs),
    ExperimentEvaluate(ExperimentEvaluateArgs),
    ExperimentResult(ExperimentResultArgs),
    VerificationEvaluate(VerificationEvaluateArgs),
    VerificationResult(VerificationResultArgs),
    ShadowEvaluate(ShadowEvaluateArgs),
    ShadowResult(ShadowResultArgs),
    PromotionReviewCreate(PromotionReviewCreateArgs),
    PromotionReviewResult(PromotionReviewResultArgs),
    CanaryStart(CanaryStartArgs),
    CanaryEvent(CanaryEventArgs),
    CanaryHalt(CanaryActionArgs),
    CanaryRollback(CanaryActionArgs),
    CanaryResult(CanaryResultArgs),
    PromotionStart(PromotionStartArgs),
    PromotionEvent(PromotionEventArgs),
    PromotionHalt(PromotionActionArgs),
    PromotionRollback(PromotionActionArgs),
    PromotionResult(PromotionResultArgs),
    PromotionApprove(PromotionApproveArgs),
    PromotionPending,
    StrategyMemoryCanary(StrategyMemoryCanaryArgs),
    StrategyMemoryPromotion(StrategyMemoryPromotionArgs),
    StrategyMemoryResult(StrategyMemoryResultArgs),
    StrategyMemoryHistory(StrategyMemoryHistoryArgs),
    StrategyScorecardCreate(StrategyScorecardCreateArgs),
    StrategyScorecardResult(StrategyScorecardResultArgs),
    EvolutionPressureCreate(EvolutionPressureCreateArgs),
    EvolutionPressureResult(EvolutionPressureResultArgs),
    EvolutionProofCreate(EvolutionProofCreateArgs),
    EvolutionProofResult(EvolutionProofResultArgs),
    EvolutionQueueCreate(EvolutionQueueCreateArgs),
    EvolutionQueueResult(EvolutionQueueResultArgs),
    EvolutionQueueList(EvolutionQueueListArgs),
    EvolutionQueueDecision(EvolutionQueueDecisionArgs),
    EvolutionDraftCreate(EvolutionDraftCreateArgs),
    EvolutionDraftResult(EvolutionDraftResultArgs),
    EvolutionDraftPromote(EvolutionDraftPromoteArgs),
    EvolutionDraftPromotionResult(EvolutionDraftPromotionResultArgs),
    EvolutionMutationCreate(EvolutionMutationCreateArgs),
    EvolutionMutationAddVariant(EvolutionMutationAddVariantArgs),
    EvolutionMutationResult(EvolutionMutationResultArgs),
    EvolutionMutationMaterializeBatch(EvolutionMutationMaterializeBatchArgs),
    EvolutionMutationMaterializationBatchResult(EvolutionMutationMaterializationBatchResultArgs),
    EvolutionMutationValidateBatch(EvolutionMutationValidateBatchArgs),
    EvolutionMutationValidationBatchResult(EvolutionMutationValidationBatchResultArgs),
    EvolutionRankCandidates(EvolutionRankCandidatesArgs),
    EvolutionRankingResult(EvolutionRankingResultArgs),
    EvolutionSelectionCreate(EvolutionSelectionCreateArgs),
    EvolutionSelectionResult(EvolutionSelectionResultArgs),
    EvolutionSelectionList(EvolutionSelectionListArgs),
    EvolutionSelectionDecision(EvolutionSelectionDecisionArgs),
    EvolutionSelectionBridge(EvolutionSelectionBridgeArgs),
    EvolutionSelectionBridgeResult(EvolutionSelectionBridgeResultArgs),
    EvolutionPortfolioCreate(EvolutionPortfolioCreateArgs),
    EvolutionPortfolioResult(EvolutionPortfolioResultArgs),
    EvolutionPortfolioList(EvolutionPortfolioListArgs),
    EvolutionPortfolioDecision(EvolutionPortfolioDecisionArgs),
    EvolutionGovernancePacketCreate(EvolutionGovernancePacketCreateArgs),
    EvolutionGovernancePacketResult(EvolutionGovernancePacketResultArgs),
    EvolutionPacketSetCreate(EvolutionPacketSetCreateArgs),
    EvolutionPacketSetResult(EvolutionPacketSetResultArgs),
    EvolutionPacketSetList(EvolutionPacketSetListArgs),
    EvolutionPacketSetSplit(EvolutionPacketSetSplitArgs),
    EvolutionPortfolioHistoryCreate(EvolutionPortfolioHistoryCreateArgs),
    EvolutionPortfolioHistoryResult(EvolutionPortfolioHistoryResultArgs),
    EvolutionPortfolioHistoryList(EvolutionPortfolioHistoryListArgs),
    EvolutionMaterialize(EvolutionMaterializeArgs),
    EvolutionMaterializationResult(EvolutionMaterializationResultArgs),
    EvolutionValidationRefresh(EvolutionValidationRefreshArgs),
    EvolutionValidationResult(EvolutionValidationResultArgs),
    EvolutionQueueReconcile(EvolutionQueueReconcileArgs),
    EvolutionQueueReconciliationResult(EvolutionQueueReconciliationResultArgs),
    EvolutionHandoffCreate(EvolutionHandoffCreateArgs),
    EvolutionHandoffResult(EvolutionHandoffResultArgs),
    EvolutionHandoffLaunchCanary(EvolutionHandoffLaunchCanaryArgs),
}

#[derive(Debug, Args)]
struct ValidateArgs {
    #[arg(long)]
    check_endpoints: bool,
}

#[derive(Debug, Args)]
struct InitArgs {
    #[arg(long, value_enum)]
    mode: InitMode,

    #[arg(long)]
    output: Option<std::path::PathBuf>,

    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct IdentityArgs {
    #[command(subcommand)]
    command: IdentityCommand,
}

#[derive(Debug, Args)]
struct FirstRunArgs {
    #[arg(long)]
    scenario: Option<std::path::PathBuf>,

    #[arg(long, default_value_t = 0)]
    pace_ms: u64,

    #[arg(long, default_value = "SWARM_VOTER_SIGNING_KEY")]
    voter_signing_key_env: String,
}

#[derive(Debug, Args)]
struct PlaybookPreviewArgs {
    #[arg(long, value_parser = parse_preview_threat_class)]
    threat_class: ThreatClass,

    #[arg(long, value_parser = parse_preview_severity)]
    severity: Severity,

    #[arg(long, value_parser = parse_preview_confidence)]
    confidence: f64,

    #[arg(long, value_parser = parse_preview_mode)]
    mode: SwarmMode,
}

#[derive(Debug, Subcommand)]
enum IdentityCommand {
    Rotate(IdentityRotateArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum IdentityRoleArg {
    Whisker,
    Stalker,
    Weaver,
    Pounce,
    Tom,
    Kitten,
    Sphinx,
    Calico,
}

impl IdentityRoleArg {
    fn as_agent_role(self) -> AgentRole {
        match self {
            Self::Whisker => AgentRole::Whisker,
            Self::Stalker => AgentRole::Stalker,
            Self::Weaver => AgentRole::Weaver,
            Self::Pounce => AgentRole::Pouncer,
            Self::Tom => AgentRole::Tom,
            Self::Kitten => AgentRole::Kitten,
            Self::Sphinx => AgentRole::Sphinx,
            Self::Calico => AgentRole::Calico,
        }
    }
}

#[derive(Debug, Args)]
struct IdentityRotateArgs {
    #[arg(long, value_enum)]
    role: IdentityRoleArg,

    #[arg(long, default_value = "primary")]
    slot: String,

    #[arg(long)]
    active_until_ms: Option<i64>,
}

#[derive(Debug, Args)]
struct EvolutionArgs {
    #[command(subcommand)]
    command: EvolutionCommand,
}

#[derive(Debug, Subcommand)]
enum EvolutionCommand {
    Status,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum InitMode {
    #[value(name = "detect_only")]
    DetectOnly,
    #[value(name = "live_response")]
    LiveResponse,
}

impl InitMode {
    fn as_config_value(self) -> &'static str {
        match self {
            Self::DetectOnly => "detect_only",
            Self::LiveResponse => "live_response",
        }
    }
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("selector")
        .required(true)
        .args(["bundle_id", "hunt_id", "receipt_id"]),
))]
struct ReplayArgs {
    #[arg(long)]
    bundle_id: Option<String>,

    #[arg(long)]
    hunt_id: Option<String>,

    #[arg(long)]
    receipt_id: Option<String>,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("selector")
        .required(true)
        .args(["investigation_id", "hunt_id", "receipt_id"]),
))]
struct InvestigationArgs {
    #[arg(long)]
    investigation_id: Option<String>,

    #[arg(long)]
    hunt_id: Option<String>,

    #[arg(long)]
    receipt_id: Option<String>,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("selector")
        .required(true)
        .args(["incident_id", "hunt_id"]),
))]
struct IncidentArgs {
    #[arg(long)]
    incident_id: Option<String>,

    #[arg(long)]
    hunt_id: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum EvidenceSubjectKindArg {
    ReplayBundle,
    InvestigationBundle,
    CorrelatedIncident,
    CanaryRun,
    ProductionPromotion,
    OperatorMaintenanceAction,
    DetectorVerification,
    StrategyShadow,
    PromotionReview,
}

impl From<EvidenceSubjectKindArg> for EvidenceSubjectKind {
    fn from(value: EvidenceSubjectKindArg) -> Self {
        match value {
            EvidenceSubjectKindArg::ReplayBundle => Self::ReplayBundle,
            EvidenceSubjectKindArg::InvestigationBundle => Self::InvestigationBundle,
            EvidenceSubjectKindArg::CorrelatedIncident => Self::CorrelatedIncident,
            EvidenceSubjectKindArg::CanaryRun => Self::CanaryRun,
            EvidenceSubjectKindArg::ProductionPromotion => Self::ProductionPromotion,
            EvidenceSubjectKindArg::OperatorMaintenanceAction => Self::OperatorMaintenanceAction,
            EvidenceSubjectKindArg::DetectorVerification => Self::DetectorVerification,
            EvidenceSubjectKindArg::StrategyShadow => Self::StrategyShadow,
            EvidenceSubjectKindArg::PromotionReview => Self::PromotionReview,
        }
    }
}

fn parse_preview_threat_class(value: &str) -> Result<ThreatClass, String> {
    let normalized = value.trim().to_lowercase();
    serde_json::from_value(serde_json::Value::String(normalized))
        .map_err(|_| format!("unsupported threat class `{value}`"))
}

fn parse_preview_severity(value: &str) -> Result<Severity, String> {
    let normalized = value.trim().to_uppercase();
    serde_json::from_value(serde_json::Value::String(normalized))
        .map_err(|_| format!("unsupported severity `{value}`"))
}

fn parse_preview_mode(value: &str) -> Result<SwarmMode, String> {
    let normalized = value.trim().to_lowercase();
    serde_json::from_value(serde_json::Value::String(normalized))
        .map_err(|_| format!("unsupported swarm mode `{value}`"))
}

fn parse_preview_confidence(value: &str) -> Result<f64, String> {
    let parsed = value
        .trim()
        .parse::<f64>()
        .map_err(|_| format!("invalid confidence `{value}`"))?;
    if !(0.0..=1.0).contains(&parsed) {
        return Err("confidence must be between 0.0 and 1.0".to_string());
    }
    Ok(parsed)
}

fn parse_review_artifact_ref_arg(value: &str) -> Result<ReviewArtifactRef, String> {
    let trimmed = value.trim();
    let (kind, id) = trimmed
        .split_once(':')
        .ok_or_else(|| format!("invalid artifact ref `{trimmed}`; expected kind:id"))?;
    let kind = kind
        .parse::<ReviewArtifactRefKind>()
        .map_err(|_| format!("unsupported review artifact kind `{kind}`"))?;
    let id = id.trim();
    if id.is_empty() {
        return Err(format!("invalid artifact ref `{trimmed}`; missing id"));
    }
    Ok(ReviewArtifactRef {
        kind,
        id: id.to_string(),
    })
}

#[derive(Debug, Args)]
struct EvidenceExportArgs {
    #[arg(long, value_enum)]
    kind: EvidenceSubjectKindArg,

    #[arg(long)]
    id: String,
}

#[derive(Debug, Args)]
struct EvidenceResultArgs {
    #[arg(long)]
    bundle_id: String,
}

#[derive(Debug, Args)]
struct EvidenceListArgs {
    #[arg(long, value_enum)]
    kind: Option<EvidenceSubjectKindArg>,
}

#[derive(Debug, Args)]
struct EvidenceVerifyArgs {
    #[arg(long)]
    bundle_id: String,

    #[arg(long)]
    expected_key_id: Option<String>,
}

#[derive(Debug, Args)]
struct EvidenceVerificationResultArgs {
    #[arg(long)]
    verification_id: String,
}

#[derive(Debug, Args)]
struct PromotionEvidenceCreateArgs {
    #[arg(long)]
    promotion_id: String,
}

#[derive(Debug, Args)]
struct PromotionEvidenceResultArgs {
    #[arg(long)]
    packet_id: String,
}

#[derive(Debug, Args)]
struct ApprovalSetCreateArgs {
    #[arg(long, value_delimiter = ',', required = true)]
    voters: Vec<String>,

    #[arg(long)]
    threshold: usize,

    #[arg(long)]
    promotion_evidence_ref: String,
}

#[derive(Debug, Args)]
struct ApprovalSetResultArgs {
    #[arg(long)]
    set_id: String,
}

#[derive(Debug, Args)]
struct ApprovalVoteAppendArgs {
    #[arg(long)]
    set_id: String,

    #[arg(long)]
    voter_id: String,

    #[arg(long, default_value = "SWARM_VOTER_SIGNING_KEY")]
    voter_signing_key_env: String,
}

#[derive(Debug, Args)]
struct ApprovalLedgerResultArgs {
    #[arg(long)]
    ledger_id: String,
}

#[derive(Debug, Args)]
struct ApprovalLedgerListArgs {
    #[arg(long)]
    approval_set_id: Option<String>,
}

#[derive(Debug, Args)]
struct ApprovalVerdictCreateArgs {
    #[arg(long)]
    approval_set_id: String,

    #[arg(long)]
    ledger_id: String,
}

#[derive(Debug, Args)]
struct ApprovalVerdictResultArgs {
    #[arg(long)]
    verdict_id: String,
}

#[derive(Debug, Args)]
struct ApprovalReceiptPackExportArgs {
    #[arg(long)]
    verdict_id: String,
}

#[derive(Debug, Args)]
struct ApprovalReceiptPackResultArgs {
    #[arg(long)]
    pack_id: String,
}

#[derive(Debug, Args)]
struct ApprovalReceiptPackVerifyArgs {
    #[arg(long)]
    pack_id: String,
}

#[derive(Debug, Args)]
struct ReviewSessionCreateArgs {
    #[arg(long)]
    title: Option<String>,

    #[arg(long)]
    notes: Option<String>,

    #[arg(long = "artifact-ref", required = true, value_parser = parse_review_artifact_ref_arg)]
    artifact_refs: Vec<ReviewArtifactRef>,
}

#[derive(Debug, Args)]
struct ReviewSessionResultArgs {
    #[arg(long)]
    session_id: String,
}

#[derive(Debug, Args)]
struct ReviewSessionExportArgs {
    #[arg(long)]
    session_id: String,
}

#[derive(Debug, Args)]
struct ReviewSessionExportResultArgs {
    #[arg(long)]
    export_id: String,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("selector")
        .required(true)
        .args(["session_id", "readiness_id"])
))]
struct ReviewCapsuleCreateArgs {
    #[arg(long)]
    session_id: Option<String>,

    #[arg(long)]
    readiness_id: Option<String>,
}

#[derive(Debug, Args)]
struct ReviewCapsuleResultArgs {
    #[arg(long)]
    capsule_id: String,
}

#[derive(Debug, Args)]
struct ReviewCapsuleImportArgs {
    #[arg(long)]
    source_path: std::path::PathBuf,

    #[arg(long)]
    expected_key_id: Option<String>,
}

#[derive(Debug, Args)]
struct ReviewCapsuleImportResultArgs {
    #[arg(long)]
    import_id: String,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("selector")
        .required(true)
        .args(["capsule_id", "import_id"])
))]
struct ReviewDelegationCreateArgs {
    #[arg(long)]
    capsule_id: Option<String>,

    #[arg(long)]
    import_id: Option<String>,

    #[arg(long)]
    reason: String,

    #[arg(long)]
    delegate_label: Option<String>,
}

#[derive(Debug, Args)]
struct ReviewDelegationResultArgs {
    #[arg(long)]
    delegation_id: String,
}

#[derive(Debug, Args)]
struct ReviewSessionPromotionReadinessArgs {
    #[arg(long)]
    session_id: String,
}

#[derive(Debug, Args)]
struct ReviewSessionPromotionReadinessResultArgs {
    #[arg(long)]
    readiness_id: String,
}

#[derive(Debug, Args)]
struct ReviewSessionHandoffReverifyArgs {
    #[arg(long)]
    session_id: String,

    #[arg(long)]
    reason: String,

    #[arg(long)]
    expected_key_id: Option<String>,

    #[arg(long = "artifact-ref", value_parser = parse_review_artifact_ref_arg)]
    artifact_refs: Vec<ReviewArtifactRef>,
}

#[derive(Debug, Args)]
struct ReviewSessionHandoffResultArgs {
    #[arg(long)]
    handoff_id: String,
}

#[derive(Debug, Args)]
struct ReplayRunArgs {
    #[arg(long)]
    scenario: std::path::PathBuf,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("selector")
        .required(true)
        .args(["run_id", "scenario"]),
))]
struct ReplayResultArgs {
    #[arg(long)]
    run_id: Option<String>,

    #[arg(long)]
    scenario: Option<std::path::PathBuf>,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("selector")
        .required(true)
        .args(["run_id", "scenario", "scenarios_dir", "suite"]),
))]
struct ReplayEvaluateArgs {
    #[arg(long)]
    run_id: Option<String>,

    #[arg(long)]
    scenario: Option<std::path::PathBuf>,

    #[arg(long)]
    scenarios_dir: Option<std::path::PathBuf>,

    #[arg(long)]
    suite: Option<std::path::PathBuf>,
}

#[derive(Debug, Args)]
struct ExperimentEvaluateArgs {
    #[arg(long)]
    experiment: std::path::PathBuf,
}

#[derive(Debug, Args)]
struct ExperimentResultArgs {
    #[arg(long)]
    experiment_id: String,
}

#[derive(Debug, Args)]
struct VerificationEvaluateArgs {
    #[arg(long)]
    experiment: std::path::PathBuf,
}

#[derive(Debug, Args)]
struct VerificationResultArgs {
    #[arg(long)]
    verification_id: String,
}

#[derive(Debug, Args)]
struct ShadowEvaluateArgs {
    #[arg(long)]
    experiment: std::path::PathBuf,
}

#[derive(Debug, Args)]
struct ShadowResultArgs {
    #[arg(long)]
    shadow_id: String,
}

#[derive(Debug, Args)]
struct PromotionReviewCreateArgs {
    #[arg(long)]
    experiment: std::path::PathBuf,

    #[arg(long)]
    verification_id: String,

    #[arg(long)]
    shadow_id: String,
}

#[derive(Debug, Args)]
struct PromotionReviewResultArgs {
    #[arg(long)]
    review_id: String,
}

#[derive(Debug, Args)]
struct CanaryStartArgs {
    #[arg(long)]
    experiment: std::path::PathBuf,

    #[arg(long)]
    verification_id: String,

    #[arg(long)]
    shadow_id: String,
}

#[derive(Debug, Args)]
struct CanaryEventArgs {
    #[arg(long)]
    run_id: String,

    #[arg(long)]
    event: std::path::PathBuf,
}

#[derive(Debug, Args)]
struct CanaryActionArgs {
    #[arg(long)]
    run_id: String,

    #[arg(long)]
    reason: String,
}

#[derive(Debug, Args)]
struct CanaryResultArgs {
    #[arg(long)]
    run_id: String,
}

#[derive(Debug, Args)]
struct PromotionStartArgs {
    #[arg(long)]
    canary_run_id: String,
}

#[derive(Debug, Args)]
struct PromotionEventArgs {
    #[arg(long)]
    promotion_id: String,

    #[arg(long)]
    event: std::path::PathBuf,
}

#[derive(Debug, Args)]
struct PromotionActionArgs {
    #[arg(long)]
    promotion_id: String,

    #[arg(long)]
    reason: String,
}

#[derive(Debug, Args)]
struct PromotionResultArgs {
    #[arg(long)]
    promotion_id: String,
}

#[derive(Debug, Args)]
struct PromotionApproveArgs {
    #[arg(long)]
    promotion_id: String,

    #[arg(long)]
    reason: String,

    #[arg(long)]
    voter_id: String,

    #[arg(long)]
    secret_material: String,
}

#[derive(Debug, Args)]
struct StrategyMemoryCanaryArgs {
    #[arg(long)]
    run_id: String,
}

#[derive(Debug, Args)]
struct StrategyMemoryPromotionArgs {
    #[arg(long)]
    promotion_id: String,
}

#[derive(Debug, Args)]
struct StrategyMemoryResultArgs {
    #[arg(long)]
    memory_id: String,
}

#[derive(Debug, Args)]
struct StrategyMemoryHistoryArgs {
    #[arg(long)]
    strategy_id: String,
}

#[derive(Debug, Args)]
struct StrategyScorecardCreateArgs {
    #[arg(long)]
    experiment: std::path::PathBuf,

    #[arg(long)]
    verification_id: String,
}

#[derive(Debug, Args)]
struct StrategyScorecardResultArgs {
    #[arg(long)]
    scorecard_id: String,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("selector")
        .required(true)
        .args(["experiment_id", "verification_id", "scorecard_id"]),
))]
struct EvolutionPressureCreateArgs {
    #[arg(long)]
    experiment_id: Option<String>,

    #[arg(long)]
    verification_id: Option<String>,

    #[arg(long)]
    scorecard_id: Option<String>,
}

#[derive(Debug, Args)]
struct EvolutionPressureResultArgs {
    #[arg(long)]
    pressure_id: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum EvolutionQueueReviewStateArg {
    PendingReview,
    AcceptedForCanary,
    Deferred,
    Rejected,
    Blocked,
}

impl From<EvolutionQueueReviewStateArg> for EvolutionProposalReviewState {
    fn from(value: EvolutionQueueReviewStateArg) -> Self {
        match value {
            EvolutionQueueReviewStateArg::PendingReview => Self::PendingReview,
            EvolutionQueueReviewStateArg::AcceptedForCanary => Self::AcceptedForCanary,
            EvolutionQueueReviewStateArg::Deferred => Self::Deferred,
            EvolutionQueueReviewStateArg::Rejected => Self::Rejected,
            EvolutionQueueReviewStateArg::Blocked => Self::Blocked,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum EvolutionQueueDecisionArg {
    AcceptForCanary,
    Defer,
    Reject,
}

impl From<EvolutionQueueDecisionArg> for EvolutionProposalDecisionAction {
    fn from(value: EvolutionQueueDecisionArg) -> Self {
        match value {
            EvolutionQueueDecisionArg::AcceptForCanary => Self::AcceptForCanary,
            EvolutionQueueDecisionArg::Defer => Self::Defer,
            EvolutionQueueDecisionArg::Reject => Self::Reject,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum EvolutionPortfolioReviewStateArg {
    PendingReview,
    Included,
    Deferred,
    Dropped,
    Blocked,
}

impl From<EvolutionPortfolioReviewStateArg> for EvolutionPortfolioEntryReviewState {
    fn from(value: EvolutionPortfolioReviewStateArg) -> Self {
        match value {
            EvolutionPortfolioReviewStateArg::PendingReview => Self::PendingReview,
            EvolutionPortfolioReviewStateArg::Included => Self::Included,
            EvolutionPortfolioReviewStateArg::Deferred => Self::Deferred,
            EvolutionPortfolioReviewStateArg::Dropped => Self::Dropped,
            EvolutionPortfolioReviewStateArg::Blocked => Self::Blocked,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum EvolutionPortfolioDecisionArg {
    Include,
    Defer,
    Drop,
}

impl From<EvolutionPortfolioDecisionArg> for EvolutionPortfolioDecisionAction {
    fn from(value: EvolutionPortfolioDecisionArg) -> Self {
        match value {
            EvolutionPortfolioDecisionArg::Include => Self::Include,
            EvolutionPortfolioDecisionArg::Defer => Self::Defer,
            EvolutionPortfolioDecisionArg::Drop => Self::Drop,
        }
    }
}

#[derive(Debug, Args)]
struct EvolutionProofCreateArgs {
    #[arg(long)]
    experiment: std::path::PathBuf,

    #[arg(long)]
    verification_id: String,
}

#[derive(Debug, Args)]
struct EvolutionProofResultArgs {
    #[arg(long)]
    proof_id: String,
}

#[derive(Debug, Args)]
struct EvolutionQueueCreateArgs {
    #[arg(long)]
    experiment: std::path::PathBuf,

    #[arg(long)]
    verification_id: String,

    #[arg(long)]
    proof_id: String,
}

#[derive(Debug, Args)]
struct EvolutionQueueResultArgs {
    #[arg(long)]
    proposal_id: String,
}

#[derive(Debug, Args)]
struct EvolutionQueueListArgs {
    #[arg(long)]
    strategy_id: Option<String>,

    #[arg(long, value_enum)]
    review_state: Option<EvolutionQueueReviewStateArg>,
}

#[derive(Debug, Args)]
struct EvolutionQueueDecisionArgs {
    #[arg(long)]
    proposal_id: String,

    #[arg(long, value_enum)]
    decision: EvolutionQueueDecisionArg,

    #[arg(long)]
    reason: String,
}

#[derive(Debug, Args)]
struct EvolutionDraftCreateArgs {
    #[arg(long)]
    pressure_id: String,

    #[arg(long)]
    strategy_id: String,

    #[arg(long)]
    strategy_description: String,

    #[arg(long)]
    mutation: String,

    #[arg(long)]
    rationale: String,
}

#[derive(Debug, Args)]
struct EvolutionDraftResultArgs {
    #[arg(long)]
    draft_id: String,
}

#[derive(Debug, Args)]
struct EvolutionDraftPromoteArgs {
    #[arg(long)]
    draft_id: String,

    #[arg(long)]
    reason: String,
}

#[derive(Debug, Args)]
struct EvolutionDraftPromotionResultArgs {
    #[arg(long)]
    promotion_id: String,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("selector")
        .required(true)
        .args(["draft_id", "materialization_id"]),
))]
struct EvolutionMutationCreateArgs {
    #[arg(long)]
    draft_id: Option<String>,

    #[arg(long)]
    materialization_id: Option<String>,

    #[arg(long)]
    base_experiment: Option<std::path::PathBuf>,

    #[arg(long)]
    rationale: String,
}

#[derive(Debug, Args)]
struct EvolutionMutationAddVariantArgs {
    #[arg(long)]
    mutation_spec_id: String,

    #[arg(long)]
    variant_id: Option<String>,

    #[arg(long)]
    strategy_id: String,

    #[arg(long)]
    strategy_description: String,

    #[arg(long)]
    mutation: String,

    #[arg(long)]
    rationale: String,

    #[arg(long)]
    add_suspicious_parent: Vec<String>,

    #[arg(long)]
    remove_suspicious_parent: Vec<String>,

    #[arg(long)]
    add_suspicious_child: Vec<String>,

    #[arg(long)]
    remove_suspicious_child: Vec<String>,

    #[arg(long)]
    high_confidence_threshold: Option<String>,

    #[arg(long)]
    medium_confidence_threshold: Option<String>,
}

#[derive(Debug, Args)]
struct EvolutionMutationResultArgs {
    #[arg(long)]
    mutation_spec_id: String,
}

#[derive(Debug, Args)]
struct EvolutionMutationMaterializeBatchArgs {
    #[arg(long)]
    mutation_spec_id: String,
}

#[derive(Debug, Args)]
struct EvolutionMutationMaterializationBatchResultArgs {
    #[arg(long)]
    batch_id: String,
}

#[derive(Debug, Args)]
struct EvolutionMutationValidateBatchArgs {
    #[arg(long)]
    batch_id: String,
}

#[derive(Debug, Args)]
struct EvolutionMutationValidationBatchResultArgs {
    #[arg(long)]
    validation_batch_id: String,
}

#[derive(Debug, Args)]
struct EvolutionRankCandidatesArgs {
    #[arg(long)]
    validation_batch_id: String,

    #[arg(long, default_value_t = 3)]
    shortlist_count: usize,
}

#[derive(Debug, Args)]
struct EvolutionRankingResultArgs {
    #[arg(long)]
    ranking_id: String,
}

#[derive(Debug, Args)]
struct EvolutionSelectionCreateArgs {
    #[arg(long)]
    ranking_id: String,

    #[arg(long)]
    packet_id: String,
}

#[derive(Debug, Args)]
struct EvolutionSelectionResultArgs {
    #[arg(long)]
    selection_id: String,
}

#[derive(Debug, Args)]
struct EvolutionSelectionListArgs {
    #[arg(long)]
    strategy_id: Option<String>,

    #[arg(long, value_enum)]
    review_state: Option<EvolutionQueueReviewStateArg>,
}

#[derive(Debug, Args)]
struct EvolutionSelectionDecisionArgs {
    #[arg(long)]
    selection_id: String,

    #[arg(long, value_enum)]
    decision: EvolutionQueueDecisionArg,

    #[arg(long)]
    reason: String,
}

#[derive(Debug, Args)]
struct EvolutionSelectionBridgeArgs {
    #[arg(long)]
    selection_id: String,

    #[arg(long)]
    reason: String,
}

#[derive(Debug, Args)]
struct EvolutionSelectionBridgeResultArgs {
    #[arg(long)]
    bridge_id: String,
}

#[derive(Debug, Args)]
struct EvolutionPortfolioCreateArgs {
    #[arg(long)]
    name: String,

    #[arg(long)]
    rationale: String,

    #[arg(long, required = true)]
    selection_id: Vec<String>,

    #[arg(long)]
    cohort: Vec<String>,
}

#[derive(Debug, Args)]
struct EvolutionPortfolioResultArgs {
    #[arg(long)]
    portfolio_id: String,
}

#[derive(Debug, Args)]
struct EvolutionPortfolioListArgs {
    #[arg(long)]
    cohort: Option<String>,

    #[arg(long, value_enum)]
    review_state: Option<EvolutionPortfolioReviewStateArg>,
}

#[derive(Debug, Args)]
struct EvolutionPortfolioDecisionArgs {
    #[arg(long)]
    portfolio_id: String,

    #[arg(long)]
    entry_id: String,

    #[arg(long, value_enum)]
    decision: EvolutionPortfolioDecisionArg,

    #[arg(long)]
    reason: String,
}

#[derive(Debug, Args)]
struct EvolutionGovernancePacketCreateArgs {
    #[arg(long)]
    portfolio_id: String,

    #[arg(long)]
    entry_id: String,

    #[arg(long)]
    reason: String,
}

#[derive(Debug, Args)]
struct EvolutionGovernancePacketResultArgs {
    #[arg(long)]
    packet_id: String,
}

#[derive(Debug, Args)]
struct EvolutionPacketSetCreateArgs {
    #[arg(long)]
    name: String,

    #[arg(long)]
    rationale: String,

    #[arg(long, required = true)]
    packet_id: Vec<String>,
}

#[derive(Debug, Args)]
struct EvolutionPacketSetResultArgs {
    #[arg(long)]
    packet_set_id: String,
}

#[derive(Debug, Args)]
struct EvolutionPacketSetListArgs {
    #[arg(long)]
    cohort: Option<String>,
}

#[derive(Debug, Args)]
struct EvolutionPacketSetSplitArgs {
    #[arg(long)]
    packet_set_id: String,

    #[arg(long)]
    name: String,

    #[arg(long)]
    rationale: String,

    #[arg(long, required = true)]
    packet_id: Vec<String>,
}

#[derive(Debug, Args)]
struct EvolutionPortfolioHistoryCreateArgs {
    #[arg(long)]
    packet_set_id: String,
}

#[derive(Debug, Args)]
struct EvolutionPortfolioHistoryResultArgs {
    #[arg(long)]
    history_id: String,
}

#[derive(Debug, Args)]
struct EvolutionPortfolioHistoryListArgs {
    #[arg(long)]
    cohort: Option<String>,
}

#[derive(Debug, Args)]
struct EvolutionMaterializeArgs {
    #[arg(long)]
    draft_id: String,

    #[arg(long)]
    base_experiment: Option<std::path::PathBuf>,

    #[arg(long)]
    add_suspicious_parent: Vec<String>,

    #[arg(long)]
    remove_suspicious_parent: Vec<String>,

    #[arg(long)]
    add_suspicious_child: Vec<String>,

    #[arg(long)]
    remove_suspicious_child: Vec<String>,

    #[arg(long)]
    high_confidence_threshold: Option<f64>,

    #[arg(long)]
    medium_confidence_threshold: Option<f64>,
}

#[derive(Debug, Args)]
struct EvolutionMaterializationResultArgs {
    #[arg(long)]
    materialization_id: String,
}

#[derive(Debug, Args)]
struct EvolutionValidationRefreshArgs {
    #[arg(long)]
    materialization_id: String,
}

#[derive(Debug, Args)]
struct EvolutionValidationResultArgs {
    #[arg(long)]
    validation_bundle_id: String,
}

#[derive(Debug, Args)]
struct EvolutionQueueReconcileArgs {
    #[arg(long)]
    promotion_id: String,

    #[arg(long)]
    validation_bundle_id: String,
}

#[derive(Debug, Args)]
struct EvolutionQueueReconciliationResultArgs {
    #[arg(long)]
    reconciliation_id: String,
}

#[derive(Debug, Args)]
struct EvolutionHandoffCreateArgs {
    #[arg(long)]
    proposal_id: String,

    #[arg(long)]
    shadow_id: String,
}

#[derive(Debug, Args)]
struct EvolutionHandoffResultArgs {
    #[arg(long)]
    handoff_id: String,
}

#[derive(Debug, Args)]
struct EvolutionHandoffLaunchCanaryArgs {
    #[arg(long)]
    handoff_id: String,
}

#[derive(Debug, serde::Serialize)]
struct PromotionApproveSignaturePayload<'a> {
    promotion_id: &'a str,
    voter_id: &'a str,
    approved_at_ms: i64,
    ledger_entry_id: &'a str,
}

#[derive(Debug, serde::Serialize)]
struct ValidateCommandReport {
    config_path: String,
    passed: bool,
    config_valid: bool,
    endpoint_checks_requested: bool,
    config: Option<ValidateConfigSummary>,
    endpoint_checks: Vec<EndpointCheckReport>,
    errors: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
struct ValidateConfigSummary {
    mode: String,
    strategies: Vec<String>,
    pheromone_backend: String,
    response_adapter: String,
    siem_forward: Option<String>,
    notification_channel_count: usize,
    platform_api_key_count: usize,
}

#[derive(Debug, serde::Serialize)]
struct EndpointCheckReport {
    target: String,
    url: String,
    host: Option<String>,
    port: Option<u16>,
    reachable: bool,
    error: Option<String>,
}

#[derive(Debug)]
struct EndpointTarget {
    target: String,
    url: String,
}

#[derive(Debug, serde::Serialize)]
struct InitCommandReport {
    output_path: String,
    mode: String,
    overwritten: bool,
    readiness_command: String,
}

#[derive(Debug, Serialize)]
struct IdentityRotateCommandReport {
    role: String,
    slot: String,
    previous_agent_id: String,
    next_agent_id: String,
    continuity_proof_id: String,
    registry_dir: String,
}

fn default_init_output_path() -> std::path::PathBuf {
    std::path::PathBuf::from("rulesets/custom.yaml")
}

fn render_init_template(mode: InitMode) -> String {
    match mode {
        InitMode::DetectOnly => format!(
            r#"# Repo-owned bootstrap configuration for a detect-only deployment.
schema_version: {schema_version}
name: custom-detect-only
description: Custom configuration generated by `swarmctl init --mode detect_only`

runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic-process
      subject: telemetry.synthetic.process
  max_in_flight_actions: 4
  drain_timeout_ms: 30000
  require_durable_live_response: true
  max_heap_pressure: 0.90
  governance_degraded_tick_threshold: 3
  # Set secret_dir when using file-backed `@secret:file-name` references.
  secret_dir:
  anti_tamper:
    enabled: true
    check_interval_ms: 5000
    fail_closed_live_response: false
    allowed_library_prefixes:
      - /lib
      - /lib64
      - /usr/lib
      - /usr/local/lib
      - /nix/store

detection:
  # Supported strategies: suspicious_process_tree, dns_exfiltration,
  # lateral_movement, credential_access, suspicious_scripting,
  # persistence, supply_chain, network_connect, infrastructure_anomaly,
  # fileless_execution
  strategy: suspicious_process_tree
  # Multi-strategy mode takes precedence when populated.
  # strategies:
  #   - suspicious_process_tree
  #   - network_connect
  high_confidence_threshold: 0.90
  medium_confidence_threshold: 0.70

pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
  deescalation_cooldown_secs: 300
  response_playbook:
    rules:
      - threat_class: execution
        severity: HIGH
        min_confidence: 0.90
        max_confidence: 1.00
        actions:
          - type: deploy_decoy
            decoy_type: honeypot
            target_zone: dmz
          - type: escalate
            summary: execution spike crossed the high-confidence autonomous threshold
            urgency: HIGH
  backend:
    kind: in_memory

policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
  max_actions_per_scope_per_minute: 5
  rules:
    - name: execution-after-hours-autorespond
      decision: allow
      threat_class: execution
      actions: [deploy_decoy, escalate]
      min_severity: HIGH
      max_severity: CRITICAL
      time_window_utc:
        start_hour_utc: 0
        end_hour_utc: 24
      max_actions_per_agent_per_minute: 4
      reason: execution playbook actions are allowed for elevated execution findings

response_adapter:
  kind: sandbox

# Optional canonical finding forwarding for external SIEM sinks.
# siem_forward:
#   kind: splunk_hec
#   endpoint: https://splunk.example/services/collector/event
#   auth_token: replace-me
#   timeout_ms: 5000
#   dead_letter_path: data/siem-dead-letter.jsonl

# Optional routed notification channels for operator-facing alerts.
# notification_channels:
#   pager:
#     target_url: https://hooks.example/swarm/pager
#     auth_token: replace-me
#     timeout_ms: 5000
#     rate_limit:
#       max_notifications: 5
#       window_ms: 60000
#     dead_letter_path: data/notification-pager.jsonl
#
# notification_routing:
#   dedup_window_ms: 1000
#   rules:
#     - min_severity: HIGH
#       threat_class: execution
#       channels: [pager]

audit:
  bundle_store:
    kind: memory
  recent_decisions_limit: 20

investigation:
  enabled: false
  worker_count: 1
  max_pending_jobs: 16
  time_budget_ms: 250
  bundle_store:
    kind: memory

correlation:
  enabled: false
  time_window_ms: 300000
  min_shared_keys: 1
  candidate_limit: 32
  incident_store:
    kind: memory

canary:
  enabled: true
  slot_id: canary-primary
  strategy_id:
  observation_window_events: 2
  max_candidate_only_rate: 0.25
  max_baseline_miss_rate: 0.25
  max_detect_latency_us: 10000
  max_total_detections: 8

promotion:
  enabled: true
  window_id: production-primary
  strategy_id:
  observation_window_events: 2
  max_promoted_only_rate: 0.20
  max_fallback_recovery_rate: 0.20
  max_detect_latency_us: 10000
  max_total_detections: 12

platform_api:
  # Add SHA-256 digests of raw API keys to expose `/v2/api/*`.
  keys: []

operator_surface:
  enabled: false
  bind_addr: "127.0.0.1:7766"
  runtime_base_url: "http://127.0.0.1:9090"
  public_base_url: "http://127.0.0.1:7766"
  max_list_results: 50
  auth:
    operator_id: local-operator
    token_env: SWARM_OPERATOR_TOKEN
"#,
            schema_version = CURRENT_SCHEMA_VERSION
        ),
        InitMode::LiveResponse => format!(
            r#"# Repo-owned bootstrap configuration for a live-response deployment.
schema_version: {schema_version}
name: custom-live-response
description: Custom configuration generated by `swarmctl init --mode live_response`

runtime:
  mode: live_response
  telemetry_sources:
    - name: synthetic-process
      subject: telemetry.synthetic.process
  max_in_flight_actions: 4
  drain_timeout_ms: 30000
  require_durable_live_response: true
  max_heap_pressure: 0.90
  governance_degraded_tick_threshold: 3
  # File-backed `@secret:file-name` references resolve relative to this directory.
  secret_dir: /var/run/swarm-secrets
  anti_tamper:
    enabled: true
    check_interval_ms: 5000
    fail_closed_live_response: true
    allowed_library_prefixes:
      - /lib
      - /lib64
      - /usr/lib
      - /usr/local/lib
      - /nix/store

detection:
  # Supported strategies: suspicious_process_tree, dns_exfiltration,
  # lateral_movement, credential_access, suspicious_scripting,
  # persistence, supply_chain, network_connect, infrastructure_anomaly,
  # fileless_execution
  strategy: suspicious_process_tree
  # Multi-strategy mode takes precedence when populated.
  # strategies:
  #   - suspicious_process_tree
  #   - network_connect
  high_confidence_threshold: 0.90
  medium_confidence_threshold: 0.70

pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
  deescalation_cooldown_secs: 300
  response_playbook:
    rules:
      - threat_class: execution
        severity: HIGH
        min_confidence: 0.90
        max_confidence: 1.00
        actions:
          - type: deploy_decoy
            decoy_type: honeypot
            target_zone: dmz
          - type: escalate
            summary: execution spike crossed the high-confidence autonomous threshold
            urgency: HIGH
      - threat_class: command_and_control
        severity: CRITICAL
        min_confidence: 0.95
        max_confidence: 1.00
        actions:
          - type: block_egress
            target: 203.0.113.10
          - type: escalate
            summary: critical C2 activity matched the emergency response playbook
            urgency: CRITICAL
  # Local journal is the smallest durable backend for live response.
  # Switch to `kind: jet_stream` and a NATS URL for shared multi-node state.
  backend:
    kind: local_journal
    path: data/pheromones.jsonl

policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
  max_actions_per_scope_per_minute: 5
  rules:
    - name: execution-after-hours-autorespond
      decision: allow
      threat_class: execution
      actions: [deploy_decoy, escalate]
      min_severity: HIGH
      max_severity: CRITICAL
      time_window_utc:
        start_hour_utc: 0
        end_hour_utc: 24
      max_actions_per_agent_per_minute: 4
      reason: execution playbook actions are allowed for elevated execution findings
    - name: command-and-control-emergency-block
      decision: allow
      threat_class: command_and_control
      actions: [block_egress, escalate]
      min_severity: CRITICAL
      max_severity: CRITICAL
      time_window_utc:
        start_hour_utc: 0
        end_hour_utc: 24
      max_actions_per_agent_per_minute: 2
      reason: critical C2 traffic can trigger immediate containment and escalation

response_adapter:
  # Replace the placeholder URL and token before deploying to production.
  kind: webhook
  url: https://response.example/swarm
  auth_token: replace-me
  timeout_ms: 5000
  dead_letter_path: data/dead-letter.jsonl

# Optional canonical finding forwarding for external SIEM sinks.
# siem_forward:
#   kind: splunk_hec
#   endpoint: https://splunk.example/services/collector/event
#   auth_token: replace-me
#   timeout_ms: 5000
#   dead_letter_path: data/siem-dead-letter.jsonl

# Optional routed notification channels for operator-facing alerts.
# notification_channels:
#   pager:
#     target_url: https://hooks.example/swarm/pager
#     auth_token: replace-me
#     timeout_ms: 5000
#     rate_limit:
#       max_notifications: 5
#       window_ms: 60000
#     dead_letter_path: data/notification-pager.jsonl
#
# notification_routing:
#   dedup_window_ms: 1000
#   rules:
#     - min_severity: HIGH
#       threat_class: execution
#       channels: [pager]

audit:
  bundle_store:
    kind: local_files
    directory: data/replay
  recent_decisions_limit: 20

investigation:
  enabled: true
  worker_count: 2
  max_pending_jobs: 32
  time_budget_ms: 250
  bundle_store:
    kind: local_files
    directory: data/investigations

correlation:
  enabled: true
  time_window_ms: 300000
  min_shared_keys: 1
  candidate_limit: 64
  incident_store:
    kind: local_files
    directory: data/incidents

canary:
  enabled: true
  slot_id: canary-primary
  strategy_id:
  observation_window_events: 2
  max_candidate_only_rate: 0.25
  max_baseline_miss_rate: 0.25
  max_detect_latency_us: 10000
  max_total_detections: 8

promotion:
  enabled: true
  window_id: production-primary
  strategy_id:
  observation_window_events: 2
  max_promoted_only_rate: 0.20
  max_fallback_recovery_rate: 0.20
  max_detect_latency_us: 10000
  max_total_detections: 12

platform_api:
  # Add SHA-256 digests of raw API keys to expose `/v2/api/*`.
  keys: []

operator_surface:
  enabled: false
  bind_addr: "127.0.0.1:7766"
  runtime_base_url: "http://127.0.0.1:9090"
  public_base_url: "http://127.0.0.1:7766"
  max_list_results: 50
  auth:
    operator_id: local-operator
    token_env: SWARM_OPERATOR_TOKEN
"#,
            schema_version = CURRENT_SCHEMA_VERSION
        ),
    }
}

fn pheromone_backend_kind(config: &PheromoneBackendConfig) -> &'static str {
    match config {
        PheromoneBackendConfig::InMemory => "in_memory",
        PheromoneBackendConfig::LocalJournal { .. } => "local_journal",
        PheromoneBackendConfig::JetStream { .. } => "jet_stream",
    }
}

fn response_adapter_kind(config: &ResponseAdapterConfig) -> &'static str {
    match config {
        ResponseAdapterConfig::Sandbox => "sandbox",
        ResponseAdapterConfig::HttpEdr { .. } => "http_edr",
        ResponseAdapterConfig::Webhook { .. } => "webhook",
    }
}

fn siem_forward_kind(config: &Option<SiemForwardConfig>) -> Option<&'static str> {
    match config {
        Some(SiemForwardConfig::SplunkHec { .. }) => Some("splunk_hec"),
        Some(SiemForwardConfig::ElkBulk { .. }) => Some("elk_bulk"),
        Some(SiemForwardConfig::Chronicle { .. }) => Some("chronicle"),
        None => None,
    }
}

fn collect_endpoint_targets(config: &SwarmConfig) -> Vec<EndpointTarget> {
    let mut targets = Vec::new();
    match &config.response_adapter {
        ResponseAdapterConfig::Sandbox => {}
        ResponseAdapterConfig::HttpEdr { config } => targets.push(EndpointTarget {
            target: "response_adapter".to_string(),
            url: config.endpoint.clone(),
        }),
        ResponseAdapterConfig::Webhook { config } => targets.push(EndpointTarget {
            target: "response_adapter".to_string(),
            url: config.url.clone(),
        }),
    }
    if let Some(siem) = &config.siem_forward {
        let endpoint = match siem {
            SiemForwardConfig::SplunkHec { endpoint, .. }
            | SiemForwardConfig::ElkBulk { endpoint, .. }
            | SiemForwardConfig::Chronicle { endpoint, .. } => endpoint.clone(),
        };
        targets.push(EndpointTarget {
            target: "siem_forward".to_string(),
            url: endpoint,
        });
    }
    for (name, channel) in &config.notification_channels {
        targets.push(EndpointTarget {
            target: format!("notification_channels.{name}"),
            url: channel.target_url.clone(),
        });
    }
    targets
}

async fn probe_endpoint(target: EndpointTarget) -> EndpointCheckReport {
    let mut report = EndpointCheckReport {
        target: target.target,
        url: target.url,
        host: None,
        port: None,
        reachable: false,
        error: None,
    };

    let parsed = match reqwest::Url::parse(&report.url) {
        Ok(parsed) => parsed,
        Err(error) => {
            report.error = Some(format!("invalid URL: {error}"));
            return report;
        }
    };

    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            report.error = Some(format!("unsupported endpoint scheme `{other}`"));
            return report;
        }
    }

    let Some(host) = parsed.host_str() else {
        report.error = Some("endpoint URL is missing a host".to_string());
        return report;
    };
    let Some(port) = parsed.port_or_known_default() else {
        report.error = Some("endpoint URL is missing a resolvable port".to_string());
        return report;
    };
    report.host = Some(host.to_string());
    report.port = Some(port);

    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect((host, port)),
    )
    .await
    {
        Ok(Ok(_stream)) => {
            report.reachable = true;
        }
        Ok(Err(error)) => {
            report.error = Some(error.to_string());
        }
        Err(_elapsed) => {
            report.error = Some("timed out after 5s".to_string());
        }
    }

    report
}

async fn build_validate_report(
    config_path: &std::path::Path,
    check_endpoints: bool,
) -> ValidateCommandReport {
    let config_path_string = config_path.display().to_string();
    let config = match load_config(config_path) {
        Ok(config) => config,
        Err(error) => {
            return ValidateCommandReport {
                config_path: config_path_string,
                passed: false,
                config_valid: false,
                endpoint_checks_requested: check_endpoints,
                config: None,
                endpoint_checks: Vec::new(),
                errors: vec![error.to_string()],
            };
        }
    };

    let mut endpoint_checks = Vec::new();
    if check_endpoints {
        for target in collect_endpoint_targets(&config) {
            endpoint_checks.push(probe_endpoint(target).await);
        }
    }

    let mut errors = Vec::new();
    for check in &endpoint_checks {
        if !check.reachable {
            errors.push(format!(
                "{} ({}) failed: {}",
                check.target,
                check.url,
                check.error.as_deref().unwrap_or("unknown error")
            ));
        }
    }

    ValidateCommandReport {
        config_path: config_path_string,
        passed: errors.is_empty(),
        config_valid: true,
        endpoint_checks_requested: check_endpoints,
        config: Some(ValidateConfigSummary {
            mode: match config.runtime.mode {
                RuntimeMode::DetectOnly => "detect_only".to_string(),
                RuntimeMode::LiveResponse => "live_response".to_string(),
            },
            strategies: config.detection.active_strategies(),
            pheromone_backend: pheromone_backend_kind(&config.pheromone.backend).to_string(),
            response_adapter: response_adapter_kind(&config.response_adapter).to_string(),
            siem_forward: siem_forward_kind(&config.siem_forward).map(str::to_string),
            notification_channel_count: config.notification_channels.len(),
            platform_api_key_count: config.platform_api.keys.len(),
        }),
        endpoint_checks,
        errors,
    }
}

fn render_validate_report(report: &ValidateCommandReport) -> String {
    let mut rendered = String::new();
    rendered.push_str(&format!("Config: {}\n", report.config_path));
    rendered.push_str(&format!(
        "Status: {}\n",
        if report.passed { "valid" } else { "invalid" }
    ));

    if let Some(config) = &report.config {
        rendered.push_str(&format!("Mode: {}\n", config.mode));
        rendered.push_str(&format!("Strategies: {}\n", config.strategies.join(", ")));
        rendered.push_str(&format!(
            "Pheromone backend: {}\n",
            config.pheromone_backend
        ));
        rendered.push_str(&format!("Response adapter: {}\n", config.response_adapter));
        rendered.push_str(&format!(
            "SIEM forward: {}\n",
            config.siem_forward.as_deref().unwrap_or("disabled")
        ));
        rendered.push_str(&format!(
            "Notification channels: {}\n",
            config.notification_channel_count
        ));
        rendered.push_str(&format!(
            "Platform API keys: {}\n",
            config.platform_api_key_count
        ));
    }

    if report.endpoint_checks_requested {
        if report.endpoint_checks.is_empty() {
            rendered.push_str("Endpoint checks: no HTTP endpoints configured\n");
        } else {
            let reachable = report
                .endpoint_checks
                .iter()
                .filter(|entry| entry.reachable)
                .count();
            rendered.push_str(&format!(
                "Endpoint checks: {reachable}/{} reachable\n",
                report.endpoint_checks.len()
            ));
            for check in &report.endpoint_checks {
                let detail = if check.reachable {
                    format!(
                        "{}:{} reachable",
                        check.host.as_deref().unwrap_or("unknown"),
                        check.port.unwrap_or_default()
                    )
                } else {
                    check
                        .error
                        .clone()
                        .unwrap_or_else(|| "unknown error".to_string())
                };
                rendered.push_str(&format!("- {}: {}\n", check.target, detail));
            }
        }
    } else {
        rendered.push_str("Endpoint checks: skipped\n");
    }

    if !report.errors.is_empty() {
        rendered.push_str("Errors:\n");
        for error in &report.errors {
            rendered.push_str(&format!("- {error}\n"));
        }
    }

    rendered.trim_end().to_string()
}

fn render_init_report(report: &InitCommandReport) -> String {
    format!(
        "Wrote {} template to {}\nNext: {}",
        report.mode, report.output_path, report.readiness_command
    )
}

fn current_time_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

fn render_identity_rotate_report(report: &IdentityRotateCommandReport) -> String {
    format!(
        "Rotated {}:{}\nprevious_agent_id: {}\nnext_agent_id: {}\ncontinuity_proof_id: {}\nregistry_dir: {}",
        report.role,
        report.slot,
        report.previous_agent_id,
        report.next_agent_id,
        report.continuity_proof_id,
        report.registry_dir
    )
}

async fn run_validate_command(
    config_path: &std::path::Path,
    args: &ValidateArgs,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let report = build_validate_report(config_path, args.check_endpoints).await;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", render_validate_report(&report));
    }
    if report.passed {
        Ok(())
    } else {
        Err(
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "config validation failed")
                .into(),
        )
    }
}

async fn run_readiness_command(
    config_path: &std::path::Path,
    output_schema_version: Option<u32>,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_output_schema_version(output_schema_version)?;
    let plane = DefaultControlPlane::from_path(config_path)?;
    let output = OperatorControlOutput::Readiness(Box::new(plane.readiness().await?));
    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}", render_output(&output));
    }

    let ready = match &output {
        OperatorControlOutput::Readiness(envelope) => envelope.data.ready,
        _ => unreachable!("readiness command always renders a readiness envelope"),
    };
    if ready {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "readiness diagnostic failed",
        )
        .into())
    }
}

async fn run_first_run_command(
    cli: &Cli,
    args: &FirstRunArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_output_schema_version(cli.output_schema_version)?;
    let plane = DefaultControlPlane::from_path(&cli.config)?;
    let output = OperatorControlOutput::FirstRun(Box::new(
        plane
            .first_run(FirstRunWizardOptions {
                scenario_path: args.scenario.clone(),
                pace_ms: args.pace_ms,
                voter_signing_key_env: args.voter_signing_key_env.clone(),
                evidence_signer_id: cli.evidence_signer_id.clone(),
                evidence_signing_key_env: cli.evidence_signing_key_env.clone(),
                paths: FirstRunWizardPaths {
                    approval_verdict_results_dir: cli.approval_verdict_results_dir.clone(),
                    approval_receipt_pack_results_dir: cli
                        .approval_receipt_pack_results_dir
                        .clone(),
                    approval_set_results_dir: cli.approval_set_results_dir.clone(),
                    approval_ledger_results_dir: cli.approval_ledger_results_dir.clone(),
                },
            })
            .await?,
    ));

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}", render_output(&output));
    }

    let completed = matches!(
        &output,
        OperatorControlOutput::FirstRun(envelope)
            if matches!(envelope.data.status, FirstRunStatus::Completed)
    );
    if completed {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "first-run wizard is blocked by readiness failures",
        )
        .into())
    }
}

fn run_playbook_preview_command(
    config_path: &std::path::Path,
    args: &PlaybookPreviewArgs,
    output_schema_version: Option<u32>,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_output_schema_version(output_schema_version)?;
    let plane = DefaultControlPlane::from_path(config_path)?;
    let output = OperatorControlOutput::PlaybookPreview(Box::new(plane.playbook_preview(
        ResponsePlaybookPreviewRequest {
            threat_class: args.threat_class.clone(),
            severity: args.severity,
            confidence: args.confidence,
            mode: args.mode,
        },
    )?));

    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}", render_output(&output));
    }

    Ok(())
}

fn ensure_output_schema_version(
    output_schema_version: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    resolve_operator_api_schema_version(output_schema_version)
        .map(|_| ())
        .map_err(|reason| std::io::Error::new(std::io::ErrorKind::InvalidInput, reason).into())
}

fn run_init_command(args: &InitArgs, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let output_path = args.output.clone().unwrap_or_else(default_init_output_path);
    let existed = output_path.exists();
    if existed && !args.force {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "{} already exists; pass --force to overwrite",
                output_path.display()
            ),
        )
        .into());
    }
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&output_path, render_init_template(args.mode))?;

    let report = InitCommandReport {
        output_path: output_path.display().to_string(),
        mode: args.mode.as_config_value().to_string(),
        overwritten: existed,
        readiness_command: format!("swarmctl readiness --config {}", output_path.display()),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", render_init_report(&report));
    }

    Ok(())
}

fn run_identity_command(
    config_path: &std::path::Path,
    args: &IdentityArgs,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match &args.command {
        IdentityCommand::Rotate(args) => run_identity_rotate_command(config_path, args, json),
    }
}

fn run_identity_rotate_command(
    config_path: &std::path::Path,
    args: &IdentityRotateArgs,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(config_path)?;
    let key_store = FileAgentKeyStore::open(resolve_agent_key_dir(config_path, &config.identity))?;
    let registry_dir = resolve_identity_registry_dir(config_path, &config.identity);
    let registry = FileAgentIdentityRegistry::open(&registry_dir)?;
    let now_ms = current_time_ms();
    let outcome = registry.rotate_identity(
        &key_store,
        args.role.as_agent_role(),
        &args.slot,
        args.active_until_ms.unwrap_or(now_ms),
        now_ms,
    )?;
    let report = IdentityRotateCommandReport {
        role: format!("{:?}", args.role.as_agent_role()).to_lowercase(),
        slot: args.slot.clone(),
        previous_agent_id: outcome.previous_agent_id.to_string(),
        next_agent_id: outcome.next_identity.id.to_string(),
        continuity_proof_id: outcome.proof.proof_id,
        registry_dir: registry_dir.display().to_string(),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", render_identity_rotate_report(&report));
    }
    Ok(())
}

pub async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match &cli.command {
        Command::Validate(args) => return run_validate_command(&cli.config, args, cli.json).await,
        Command::Init(args) => return run_init_command(args, cli.json),
        Command::Readiness => {
            return run_readiness_command(&cli.config, cli.output_schema_version, cli.json).await;
        }
        Command::FirstRun(args) => return run_first_run_command(&cli, args).await,
        Command::PlaybookPreview(args) => {
            return run_playbook_preview_command(
                &cli.config,
                args,
                cli.output_schema_version,
                cli.json,
            );
        }
        Command::Identity(args) => return run_identity_command(&cli.config, args, cli.json),
        _ => {}
    }

    let repo_config = load_config(&cli.config)?;
    let plane = DefaultControlPlane::from_path(&cli.config)?;
    let replay_harness = DefaultReplayHarness::from_path(&cli.config, &cli.replay_results_dir)?;
    let canary_harness = DefaultCanaryHarness::from_path(&cli.config, &cli.canary_results_dir)?;
    let promotion_harness =
        DefaultProductionPromotionHarness::from_path(&cli.config, &cli.promotion_results_dir)?;
    let strategy_memory_harness =
        DefaultStrategyMemoryHarness::from_path(&cli.config, &cli.strategy_memory_results_dir)?;
    let strategy_scorecard_harness = DefaultStrategyScorecardHarness::from_path(
        &cli.config,
        &cli.strategy_memory_results_dir,
        &cli.strategy_scorecard_results_dir,
    )?;
    let evolution_proof_harness =
        DefaultEvolutionProofHarness::from_path(&cli.config, &cli.evolution_proof_results_dir)?;
    let evolution_queue_harness =
        DefaultEvolutionQueueHarness::from_path(&cli.config, &cli.evolution_queue_results_dir)?;
    let evolution_handoff_harness =
        DefaultEvolutionHandoffHarness::from_path(&cli.config, &cli.evolution_handoff_results_dir)?;
    let evolution_drafting_harness = DefaultEvolutionDraftingHarness::from_path(
        &cli.config,
        &cli.evolution_pressure_results_dir,
        &cli.evolution_draft_results_dir,
        &cli.evolution_draft_promotion_results_dir,
        &cli.evolution_materialization_results_dir,
        &cli.evolution_validation_results_dir,
        &cli.evolution_reconciliation_results_dir,
    )?;
    let evolution_mutation_harness = DefaultEvolutionMutationHarness::from_path(
        &cli.evolution_mutation_results_dir,
        &cli.evolution_mutation_materialization_batch_results_dir,
        &cli.evolution_mutation_validation_batch_results_dir,
        &cli.evolution_ranking_results_dir,
    )?;
    let evolution_selection_harness = DefaultEvolutionSelectionHarness::from_path(
        &cli.evolution_ranking_results_dir,
        &cli.evolution_validation_results_dir,
        &cli.evolution_selection_results_dir,
        &cli.evolution_selection_bridge_results_dir,
    )?;
    let evolution_portfolio_harness = DefaultEvolutionPortfolioHarness::from_path(
        &cli.evolution_ranking_results_dir,
        &cli.evolution_selection_results_dir,
        &cli.evolution_portfolio_results_dir,
        &cli.evolution_governance_review_packet_results_dir,
    )?;
    let evolution_governance_prep_harness = DefaultEvolutionGovernancePrepHarness::from_path(
        &cli.evolution_governance_review_packet_results_dir,
        &cli.evolution_packet_set_results_dir,
        &cli.strategy_memory_results_dir,
        &cli.evolution_portfolio_history_results_dir,
    )?;
    let evidence_paths = EvidenceHarnessPaths {
        verification_results_dir: cli.verification_results_dir.clone(),
        shadow_results_dir: cli.shadow_results_dir.clone(),
        promotion_review_results_dir: cli.promotion_review_results_dir.clone(),
        canary_results_dir: cli.canary_results_dir.clone(),
        promotion_results_dir: cli.promotion_results_dir.clone(),
        operator_maintenance_results_dir: cli.operator_maintenance_results_dir.clone(),
        evidence_results_dir: cli.evidence_results_dir.clone(),
        evidence_verification_results_dir: cli.evidence_verification_results_dir.clone(),
        promotion_evidence_results_dir: cli.promotion_evidence_results_dir.clone(),
    };
    let evidence_harness = DefaultEvidenceHarness::from_path(&cli.config, evidence_paths.clone())?;
    let approval_harness = DefaultApprovalHarness::from_path(
        &cli.config,
        &cli.approval_verdict_results_dir,
        &cli.approval_receipt_pack_results_dir,
        &cli.approval_set_results_dir,
        &cli.approval_ledger_results_dir,
    )?;
    let review_workbench_harness =
        DefaultReviewWorkbenchHarness::from_paths(&OperatorSurfacePaths {
            evidence_signer_id: cli.evidence_signer_id.clone(),
            evidence_signing_key_env: cli.evidence_signing_key_env.clone(),
            verification_results_dir: cli.verification_results_dir.clone(),
            shadow_results_dir: cli.shadow_results_dir.clone(),
            promotion_review_results_dir: cli.promotion_review_results_dir.clone(),
            canary_results_dir: cli.canary_results_dir.clone(),
            promotion_results_dir: cli.promotion_results_dir.clone(),
            evolution_ranking_results_dir: cli.evolution_ranking_results_dir.clone(),
            evolution_selection_results_dir: cli.evolution_selection_results_dir.clone(),
            evolution_portfolio_results_dir: cli.evolution_portfolio_results_dir.clone(),
            evolution_governance_review_packet_results_dir: cli
                .evolution_governance_review_packet_results_dir
                .clone(),
            evolution_packet_set_results_dir: cli.evolution_packet_set_results_dir.clone(),
            strategy_memory_results_dir: cli.strategy_memory_results_dir.clone(),
            evolution_portfolio_history_results_dir: cli
                .evolution_portfolio_history_results_dir
                .clone(),
            operator_maintenance_results_dir: cli.operator_maintenance_results_dir.clone(),
            evidence_results_dir: cli.evidence_results_dir.clone(),
            evidence_verification_results_dir: cli.evidence_verification_results_dir.clone(),
            promotion_evidence_results_dir: cli.promotion_evidence_results_dir.clone(),
            review_session_results_dir: cli.review_session_results_dir.clone(),
            review_session_export_results_dir: cli.review_session_export_results_dir.clone(),
            review_session_readiness_results_dir: cli.review_session_readiness_results_dir.clone(),
            review_session_handoff_results_dir: cli.review_session_handoff_results_dir.clone(),
            review_capsule_results_dir: cli.review_capsule_results_dir.clone(),
            review_capsule_import_results_dir: cli.review_capsule_import_results_dir.clone(),
            review_delegation_results_dir: cli.review_delegation_results_dir.clone(),
            approval_set_results_dir: cli.approval_set_results_dir.clone(),
            approval_ledger_results_dir: cli.approval_ledger_results_dir.clone(),
            approval_verdict_results_dir: cli.approval_verdict_results_dir.clone(),
            approval_receipt_pack_results_dir: cli.approval_receipt_pack_results_dir.clone(),
        })?;
    let review_workbench_actor = repo_config
        .operator
        .auth
        .effective_principals()
        .into_iter()
        .next()
        .map(|principal| principal.operator_id)
        .unwrap_or_else(|| repo_config.operator.auth.operator_id.clone());

    if matches!(
        cli.command,
        Command::Status | Command::Replay(_) | Command::Investigation(_) | Command::Incident(_)
    ) {
        ensure_output_schema_version(cli.output_schema_version)?;
    }

    let output = match cli.command {
        Command::Validate(_)
        | Command::Init(_)
        | Command::Readiness
        | Command::FirstRun(_)
        | Command::PlaybookPreview(_)
        | Command::Identity(_) => {
            unreachable!("handled before harness bootstrap")
        }
        Command::Serve => {
            let surface = LocalOperatorSurface::from_paths(
                &cli.config,
                OperatorSurfacePaths {
                    evidence_signer_id: cli.evidence_signer_id.clone(),
                    evidence_signing_key_env: cli.evidence_signing_key_env.clone(),
                    verification_results_dir: cli.verification_results_dir.clone(),
                    shadow_results_dir: cli.shadow_results_dir.clone(),
                    promotion_review_results_dir: cli.promotion_review_results_dir.clone(),
                    canary_results_dir: cli.canary_results_dir.clone(),
                    promotion_results_dir: cli.promotion_results_dir.clone(),
                    evolution_ranking_results_dir: cli.evolution_ranking_results_dir.clone(),
                    evolution_selection_results_dir: cli.evolution_selection_results_dir.clone(),
                    evolution_portfolio_results_dir: cli.evolution_portfolio_results_dir.clone(),
                    evolution_governance_review_packet_results_dir: cli
                        .evolution_governance_review_packet_results_dir
                        .clone(),
                    evolution_packet_set_results_dir: cli.evolution_packet_set_results_dir.clone(),
                    strategy_memory_results_dir: cli.strategy_memory_results_dir.clone(),
                    evolution_portfolio_history_results_dir: cli
                        .evolution_portfolio_history_results_dir
                        .clone(),
                    operator_maintenance_results_dir: cli.operator_maintenance_results_dir.clone(),
                    evidence_results_dir: cli.evidence_results_dir.clone(),
                    evidence_verification_results_dir: cli
                        .evidence_verification_results_dir
                        .clone(),
                    promotion_evidence_results_dir: cli.promotion_evidence_results_dir.clone(),
                    review_session_results_dir: cli.review_session_results_dir.clone(),
                    review_session_export_results_dir: cli
                        .review_session_export_results_dir
                        .clone(),
                    review_session_readiness_results_dir: cli
                        .review_session_readiness_results_dir
                        .clone(),
                    review_session_handoff_results_dir: cli
                        .review_session_handoff_results_dir
                        .clone(),
                    review_capsule_results_dir: cli.review_capsule_results_dir.clone(),
                    review_capsule_import_results_dir: cli
                        .review_capsule_import_results_dir
                        .clone(),
                    review_delegation_results_dir: cli.review_delegation_results_dir.clone(),
                    approval_set_results_dir: cli.approval_set_results_dir.clone(),
                    approval_ledger_results_dir: cli.approval_ledger_results_dir.clone(),
                    approval_verdict_results_dir: cli.approval_verdict_results_dir.clone(),
                    approval_receipt_pack_results_dir: cli
                        .approval_receipt_pack_results_dir
                        .clone(),
                },
            )?;
            eprintln!(
                "serving authenticated operator surface on http://{}",
                surface.bind_addr()
            );
            surface.serve().await?;
            return Ok(());
        }
        Command::Status => OperatorControlOutput::Status(Box::new(plane.status().await?)),
        Command::Evolution(args) => match args.command {
            EvolutionCommand::Status => {
                let report =
                    DefaultEvolutionStatusHarness::from_config(&cli.config, repo_config.clone())?
                        .status()?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!("{}", render_evolution_status(&report));
                }
                return Ok(());
            }
        },
        Command::Replay(args) => OperatorControlOutput::Replay(Box::new(plane.replay_lookup(
            if let Some(bundle_id) = args.bundle_id.as_deref() {
                ReplayLookupSelector::BundleId(bundle_id)
            } else if let Some(hunt_id) = args.hunt_id.as_deref() {
                ReplayLookupSelector::HuntId(hunt_id)
            } else if let Some(receipt_id) = args.receipt_id.as_deref() {
                ReplayLookupSelector::ReceiptId(receipt_id)
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "replay lookup requires exactly one of bundle_id, hunt_id, or receipt_id",
                )
                .into());
            },
        )?)),
        Command::Investigation(args) => {
            OperatorControlOutput::Investigation(Box::new(plane.investigation_lookup(
                if let Some(investigation_id) = args.investigation_id.as_deref() {
                    InvestigationLookupSelector::InvestigationId(investigation_id)
                } else if let Some(hunt_id) = args.hunt_id.as_deref() {
                    InvestigationLookupSelector::HuntId(hunt_id)
                } else if let Some(receipt_id) = args.receipt_id.as_deref() {
                    InvestigationLookupSelector::ReceiptId(receipt_id)
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "investigation lookup requires exactly one of investigation_id, hunt_id, or receipt_id",
                    )
                    .into());
                },
            )?))
        }
        Command::Incident(args) => OperatorControlOutput::Incident(Box::new(
            plane.incident_lookup(if let Some(incident_id) = args.incident_id.as_deref() {
                IncidentLookupSelector::IncidentId(incident_id)
            } else if let Some(hunt_id) = args.hunt_id.as_deref() {
                IncidentLookupSelector::HuntId(hunt_id)
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "incident lookup requires exactly one of incident_id or hunt_id",
                )
                .into());
            })?,
        )),
        Command::ReplayRun(args) => {
            let run = replay_harness.run_scenario_path(args.scenario).await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&run.bundle)?);
            } else {
                println!("{}", render_replay_run(&run.bundle));
            }
            return Ok(());
        }
        Command::ReplayResult(args) => {
            let maybe_run = if let Some(run_id) = args.run_id.as_deref() {
                replay_harness.load_run(run_id)?
            } else {
                let scenario = args.scenario.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "replay result lookup requires either run_id or scenario",
                    )
                })?;
                replay_harness.load_run_for_scenario_path(scenario)?
            };
            let run = maybe_run.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "offline replay result was not found",
                )
            })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&run.bundle)?);
            } else {
                println!("{}", render_replay_run(&run.bundle));
            }
            return Ok(());
        }
        Command::EvidenceExport(args) => {
            let secret_material = std::env::var(&cli.evidence_signing_key_env)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "evidence signing key env `{}` is missing or empty",
                            cli.evidence_signing_key_env
                        ),
                    )
                })?;
            let lookup = evidence_harness.export_bundle(EvidenceExportRequest {
                subject_kind: args.kind.into(),
                stable_id: args.id,
                signer_id: cli.evidence_signer_id.clone(),
                secret_material,
            })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.bundle)?);
            } else {
                println!("{}", render_evidence_bundle(&lookup.bundle));
            }
            return Ok(());
        }
        Command::EvidenceResult(args) => {
            let lookup = evidence_harness
                .load_bundle(&args.bundle_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "signed evidence bundle was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.bundle)?);
            } else {
                println!("{}", render_evidence_bundle(&lookup.bundle));
            }
            return Ok(());
        }
        Command::EvidenceList(args) => {
            let list = evidence_harness.list_bundles(args.kind.map(Into::into))?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                println!("{}", render_evidence_bundle_list(&list));
            }
            return Ok(());
        }
        Command::EvidenceVerify(args) => {
            let lookup =
                evidence_harness.verify_bundle(&args.bundle_id, args.expected_key_id.as_deref())?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evidence_verification(&lookup.report));
            }
            if lookup.report.status == crate::evidence::EvidenceVerificationStatus::Failed {
                std::process::exit(1);
            }
            return Ok(());
        }
        Command::EvidenceVerificationResult(args) => {
            let lookup = evidence_harness
                .load_verification(&args.verification_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "evidence verification result was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evidence_verification(&lookup.report));
            }
            return Ok(());
        }
        Command::PromotionEvidenceCreate(args) => {
            let lookup = evidence_harness.create_promotion_evidence_packet(&args.promotion_id)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.packet)?);
            } else {
                println!("{}", render_promotion_evidence_packet(&lookup.packet));
            }
            if lookup.packet.recommendation
                == crate::evidence::PromotionEvidenceRecommendation::Blocked
            {
                std::process::exit(1);
            }
            return Ok(());
        }
        Command::PromotionEvidenceResult(args) => {
            let lookup = evidence_harness
                .load_promotion_evidence_packet(&args.packet_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "promotion evidence packet was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.packet)?);
            } else {
                println!("{}", render_promotion_evidence_packet(&lookup.packet));
            }
            return Ok(());
        }
        Command::ApprovalSetCreate(args) => {
            let record = approval_harness.create_approval_set(
                args.voters,
                ThresholdRule::AtLeast {
                    required: args.threshold,
                },
                &args.promotion_evidence_ref,
            )?;
            let lookup = approval_harness
                .load_approval_set(&record.set_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "approval set was created but could not be reloaded",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_approval_set(&lookup.report));
            }
            return Ok(());
        }
        Command::ApprovalSetResult(args) => {
            let lookup = approval_harness
                .load_approval_set(&args.set_id)?
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "approval set was not found")
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_approval_set(&lookup.report));
            }
            return Ok(());
        }
        Command::ApprovalVoteAppend(args) => {
            let secret_material = std::env::var(&args.voter_signing_key_env)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "approval voter signing key env `{}` is missing or empty",
                            args.voter_signing_key_env
                        ),
                    )
                })?;
            let signer = Ed25519Signer::from_secret_material(&secret_material);
            approval_harness.append_vote(&args.set_id, &args.voter_id, &signer)?;
            let ledger_id = approval_harness
                .list_ledgers(Some(&args.set_id))?
                .ledgers
                .into_iter()
                .next()
                .map(|record| record.ledger_id)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "approval ledger was not found for the approval set",
                    )
                })?;
            let lookup = approval_harness.load_ledger(&ledger_id)?.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "approval ledger was updated but could not be reloaded",
                )
            })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup)?);
            } else {
                println!(
                    "{}",
                    render_approval_ledger(&lookup.report, &lookup.quorum_state)
                );
            }
            return Ok(());
        }
        Command::ApprovalLedgerResult(args) => {
            let lookup = approval_harness
                .load_ledger(&args.ledger_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "approval ledger was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup)?);
            } else {
                println!(
                    "{}",
                    render_approval_ledger(&lookup.report, &lookup.quorum_state)
                );
            }
            return Ok(());
        }
        Command::ApprovalLedgerList(args) => {
            let list = approval_harness.list_ledgers(args.approval_set_id.as_deref())?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                println!("{}", render_approval_ledger_list(&list));
            }
            return Ok(());
        }
        Command::ApprovalVerdictCreate(args) => {
            let lookup = approval_harness.create_verdict(&args.approval_set_id, &args.ledger_id)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_approval_verdict(&lookup.report));
            }
            return Ok(());
        }
        Command::ApprovalVerdictResult(args) => {
            let lookup = approval_harness
                .load_verdict(&args.verdict_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "approval verdict was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_approval_verdict(&lookup.report));
            }
            return Ok(());
        }
        Command::ApprovalVerdictList => {
            let list = approval_harness.list_verdicts()?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                println!("{}", render_approval_verdict_list(&list));
            }
            return Ok(());
        }
        Command::ApprovalReceiptPackExport(args) => {
            let lookup = approval_harness.export_receipt_pack(
                &args.verdict_id,
                &cli.evidence_signer_id,
                &cli.evidence_signing_key_env,
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_approval_receipt_pack(&lookup.report));
            }
            return Ok(());
        }
        Command::ApprovalReceiptPackResult(args) => {
            let lookup = approval_harness
                .load_receipt_pack(&args.pack_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "approval receipt pack was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_approval_receipt_pack(&lookup.report));
            }
            return Ok(());
        }
        Command::ApprovalReceiptPackList => {
            let list = approval_harness.list_receipt_packs()?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                println!("{}", render_approval_receipt_pack_list(&list));
            }
            return Ok(());
        }
        Command::ApprovalReceiptPackVerify(args) => {
            let valid = approval_harness.verify_receipt_pack(&args.pack_id)?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "pack_id": args.pack_id,
                        "valid": valid,
                    }))?
                );
            } else if valid {
                println!("approval receipt pack verified");
            } else {
                println!("approval receipt pack verification failed");
                std::process::exit(1);
            }
            return Ok(());
        }
        Command::ReviewSessionCreate(args) => {
            let lookup = review_workbench_harness.create_session(ReviewSessionCreateRequest {
                title: args.title,
                notes: args.notes,
                artifact_refs: args.artifact_refs,
            })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                let resolved =
                    review_workbench_harness.resolve_session(&lookup.report.session_id)?;
                println!("{}", render_review_session(&resolved));
            }
            return Ok(());
        }
        Command::ReviewSessionResult(args) => {
            let resolved = review_workbench_harness.resolve_session(&args.session_id)?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&resolved.session.report)?
                );
            } else {
                println!("{}", render_review_session(&resolved));
            }
            return Ok(());
        }
        Command::ReviewSessionList => {
            let list = review_workbench_harness.list_sessions()?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                println!("{}", render_review_session_list(&list));
            }
            return Ok(());
        }
        Command::ReviewSessionExport(args) => {
            let lookup = review_workbench_harness.export_session(&args.session_id)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.export)?);
            } else {
                println!("{}", render_review_session_export(&lookup.export));
            }
            return Ok(());
        }
        Command::ReviewSessionExportResult(args) => {
            let lookup = review_workbench_harness
                .load_export(&args.export_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "review session export was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.export)?);
            } else {
                println!("{}", render_review_session_export(&lookup.export));
            }
            return Ok(());
        }
        Command::ReviewCapsuleCreate(args) => {
            let lookup = if let Some(session_id) = args.session_id.as_deref() {
                review_workbench_harness.create_capsule_from_session(session_id)?
            } else {
                let readiness_id = args.readiness_id.as_deref().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "review capsule create requires either session_id or readiness_id",
                    )
                })?;
                review_workbench_harness.create_capsule_from_readiness(
                    readiness_id,
                )?
            };
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.capsule)?);
            } else {
                println!("{}", render_review_capsule(&lookup.capsule));
            }
            return Ok(());
        }
        Command::ReviewCapsuleResult(args) => {
            let lookup = review_workbench_harness
                .load_capsule(&args.capsule_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "review capsule was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.capsule)?);
            } else {
                println!("{}", render_review_capsule(&lookup.capsule));
            }
            return Ok(());
        }
        Command::ReviewCapsuleImport(args) => {
            let lookup = review_workbench_harness.import_capsule(ReviewCapsuleImportRequest {
                source_path: args.source_path.display().to_string(),
                expected_key_id: args.expected_key_id,
            })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.import)?);
            } else {
                println!("{}", render_review_capsule_import(&lookup.import));
            }
            if lookup.import.trust_status
                == crate::review_workbench::ReviewCapsuleImportTrustStatus::Invalid
            {
                std::process::exit(1);
            }
            return Ok(());
        }
        Command::ReviewCapsuleImportResult(args) => {
            let lookup = review_workbench_harness
                .load_capsule_import(&args.import_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "review capsule import was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.import)?);
            } else {
                println!("{}", render_review_capsule_import(&lookup.import));
            }
            return Ok(());
        }
        Command::ReviewDelegationCreate(args) => {
            let lookup = review_workbench_harness.create_delegation_packet(
                ReviewDelegationCreateRequest {
                    capsule_id: args.capsule_id,
                    import_id: args.import_id,
                    reason: args.reason,
                    delegate_label: args.delegate_label,
                },
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.packet)?);
            } else {
                println!("{}", render_review_delegation_packet(&lookup.packet));
            }
            return Ok(());
        }
        Command::ReviewDelegationResult(args) => {
            let lookup = review_workbench_harness
                .load_delegation(&args.delegation_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "review delegation was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.packet)?);
            } else {
                println!("{}", render_review_delegation_packet(&lookup.packet));
            }
            return Ok(());
        }
        Command::ReviewSessionPromotionReadiness(args) => {
            let lookup =
                review_workbench_harness.create_promotion_readiness_review(&args.session_id)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!(
                    "{}",
                    render_review_session_promotion_readiness(&lookup.report)
                );
            }
            return Ok(());
        }
        Command::ReviewSessionPromotionReadinessResult(args) => {
            let lookup = review_workbench_harness
                .load_promotion_readiness(&args.readiness_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "review session readiness was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!(
                    "{}",
                    render_review_session_promotion_readiness(&lookup.report)
                );
            }
            return Ok(());
        }
        Command::ReviewSessionHandoffReverify(args) => {
            let lookup = review_workbench_harness.create_reverify_handoff(
                &review_workbench_actor,
                ReviewSessionReverifyRequest {
                    session_id: args.session_id,
                    selected_artifact_refs: args.artifact_refs,
                    expected_key_id: args.expected_key_id,
                    reason: args.reason,
                },
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.handoff)?);
            } else {
                println!("{}", render_review_session_handoff(&lookup.handoff));
            }
            if lookup.handoff.status
                != crate::operator_maintenance::OperatorMaintenanceStatus::Applied
            {
                std::process::exit(1);
            }
            return Ok(());
        }
        Command::ReviewSessionHandoffResult(args) => {
            let lookup = review_workbench_harness
                .load_handoff(&args.handoff_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "review session handoff was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.handoff)?);
            } else {
                println!("{}", render_review_session_handoff(&lookup.handoff));
            }
            return Ok(());
        }
        Command::ReplayEvaluate(args) => {
            if let Some(scenarios_dir) = args.scenarios_dir {
                let suite = replay_harness.evaluate_scenarios_dir(scenarios_dir).await?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&suite)?);
                } else {
                    println!("{}", render_suite_report(&suite));
                }
                if !suite.passed {
                    std::process::exit(1);
                }
                return Ok(());
            }

            if let Some(suite_path) = args.suite {
                let suite = replay_harness.evaluate_suite_path(suite_path).await?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&suite)?);
                } else {
                    println!("{}", render_suite_report(&suite));
                }
                if !suite.passed {
                    std::process::exit(1);
                }
                return Ok(());
            }

            let report = if let Some(run_id) = args.run_id.as_deref() {
                let run = replay_harness.load_run(run_id)?.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "offline replay result was not found",
                    )
                })?;
                replay_harness.evaluate_run(&run.bundle)
            } else {
                let scenario = args.scenario.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "replay evaluation requires either run_id or scenario",
                    )
                })?;
                replay_harness.evaluate_scenario_path(scenario).await?
            };
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", render_evaluation_report(&report));
            }
            if !report.passed {
                std::process::exit(1);
            }
            return Ok(());
        }
        Command::ExperimentEvaluate(args) => {
            let lookup = replay_harness
                .evaluate_experiment_path(args.experiment, &cli.experiment_results_dir)
                .await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_experiment_report(&lookup.report));
            }
            if !lookup.report.passed {
                std::process::exit(1);
            }
            return Ok(());
        }
        Command::ExperimentResult(args) => {
            let lookup = replay_harness
                .load_experiment(&cli.experiment_results_dir, &args.experiment_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "offline detector experiment result was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_experiment_report(&lookup.report));
            }
            return Ok(());
        }
        Command::VerificationEvaluate(args) => {
            let lookup = replay_harness
                .evaluate_verification_path(args.experiment, &cli.verification_results_dir)
                .await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_verification_report(&lookup.report));
            }
            if !lookup.report.passed {
                std::process::exit(1);
            }
            return Ok(());
        }
        Command::VerificationResult(args) => {
            let lookup = replay_harness
                .load_verification(&cli.verification_results_dir, &args.verification_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "offline verification result was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_verification_report(&lookup.report));
            }
            return Ok(());
        }
        Command::ShadowEvaluate(args) => {
            let lookup = replay_harness
                .evaluate_shadow_path(args.experiment, &cli.shadow_results_dir)
                .await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_shadow_report(&lookup.report));
            }
            if !lookup.report.passed {
                std::process::exit(1);
            }
            return Ok(());
        }
        Command::ShadowResult(args) => {
            let lookup = replay_harness
                .load_shadow(&cli.shadow_results_dir, &args.shadow_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "offline shadow result was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_shadow_report(&lookup.report));
            }
            return Ok(());
        }
        Command::PromotionReviewCreate(args) => {
            let lookup = replay_harness.create_promotion_review_packet(
                args.experiment,
                &cli.verification_results_dir,
                &args.verification_id,
                &cli.shadow_results_dir,
                &args.shadow_id,
                &cli.promotion_review_results_dir,
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.packet)?);
            } else {
                println!("{}", render_promotion_review_packet(&lookup.packet));
            }
            return Ok(());
        }
        Command::PromotionReviewResult(args) => {
            let lookup = replay_harness
                .load_promotion_review(&cli.promotion_review_results_dir, &args.review_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "promotion review packet was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.packet)?);
            } else {
                println!("{}", render_promotion_review_packet(&lookup.packet));
            }
            return Ok(());
        }
        Command::CanaryStart(args) => {
            let lookup = canary_harness.start_run(
                args.experiment,
                &cli.verification_results_dir,
                &args.verification_id,
                &cli.shadow_results_dir,
                &args.shadow_id,
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_canary_run_report(&lookup.report));
            }
            return Ok(());
        }
        Command::CanaryEvent(args) => {
            let lookup = canary_harness.ingest_event_path(&args.run_id, args.event)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_canary_run_report(&lookup.report));
            }
            if matches!(
                lookup.report.status,
                crate::canary::CanaryRunStatus::RolledBack
            ) {
                std::process::exit(1);
            }
            return Ok(());
        }
        Command::CanaryHalt(args) => {
            let lookup = canary_harness.halt_run(&args.run_id, &args.reason)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_canary_run_report(&lookup.report));
            }
            return Ok(());
        }
        Command::CanaryRollback(args) => {
            let lookup = canary_harness.rollback_run(&args.run_id, &args.reason)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_canary_run_report(&lookup.report));
            }
            return Ok(());
        }
        Command::CanaryResult(args) => {
            let lookup = canary_harness.load_run(&args.run_id)?.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "canary run was not found")
            })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_canary_run_report(&lookup.report));
            }
            return Ok(());
        }
        Command::PromotionStart(args) => {
            let lookup =
                promotion_harness.start_run(&cli.canary_results_dir, &args.canary_run_id)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_production_promotion_report(&lookup.report));
            }
            return Ok(());
        }
        Command::PromotionEvent(args) => {
            let lookup = promotion_harness.ingest_event_path(&args.promotion_id, args.event)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_production_promotion_report(&lookup.report));
            }
            if matches!(lookup.report.status, ProductionPromotionStatus::RolledBack) {
                std::process::exit(1);
            }
            return Ok(());
        }
        Command::PromotionHalt(args) => {
            let lookup = promotion_harness.halt_run(&args.promotion_id, &args.reason)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_production_promotion_report(&lookup.report));
            }
            return Ok(());
        }
        Command::PromotionRollback(args) => {
            let lookup = promotion_harness.rollback_run(&args.promotion_id, &args.reason)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_production_promotion_report(&lookup.report));
            }
            return Ok(());
        }
        Command::PromotionResult(args) => {
            let lookup = promotion_harness
                .load_run(&args.promotion_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "production promotion was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_production_promotion_report(&lookup.report));
            }
            return Ok(());
        }
        Command::PromotionApprove(args) => {
            let approved_at_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            let signer = Ed25519Signer::from_secret_material(&args.secret_material);
            let detached = signer.sign(&canonical_json_bytes(&PromotionApproveSignaturePayload {
                promotion_id: &args.promotion_id,
                voter_id: &args.voter_id,
                approved_at_ms,
                ledger_entry_id: "",
            })?);
            let vote = PromotionApprovalVoteRef {
                voter_id: args.voter_id,
                public_key_hex: signer.public_key_hex().to_string(),
                signature_hex: detached.signature_hex,
                approved_at_ms,
                ledger_entry_id: String::new(),
            };
            let lookup = promotion_harness.approve_pending_run(
                &args.promotion_id,
                vec![vote],
                None,
                &args.reason,
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_production_promotion_report(&lookup.report));
            }
            return Ok(());
        }
        Command::PromotionPending => {
            let list = promotion_harness
                .list_runs(Some(ProductionPromotionStatus::HumanApprovalPending))?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                println!("{}", render_production_promotion_list(&list));
            }
            return Ok(());
        }
        Command::StrategyMemoryCanary(args) => {
            let lookup =
                strategy_memory_harness.ingest_canary(&cli.canary_results_dir, &args.run_id)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_strategy_memory(&lookup.report));
            }
            return Ok(());
        }
        Command::StrategyMemoryPromotion(args) => {
            let lookup = strategy_memory_harness
                .ingest_promotion(&cli.promotion_results_dir, &args.promotion_id)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_strategy_memory(&lookup.report));
            }
            return Ok(());
        }
        Command::StrategyMemoryResult(args) => {
            let lookup = strategy_memory_harness
                .load_memory(&args.memory_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "strategy memory was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_strategy_memory(&lookup.report));
            }
            return Ok(());
        }
        Command::StrategyMemoryHistory(args) => {
            let history = strategy_memory_harness.history(&args.strategy_id)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&history)?);
            } else {
                println!("{}", render_strategy_memory_history(&history));
            }
            return Ok(());
        }
        Command::StrategyScorecardCreate(args) => {
            let lookup = strategy_scorecard_harness
                .create_scorecard(
                    &replay_harness,
                    args.experiment,
                    &cli.experiment_results_dir,
                    &cli.verification_results_dir,
                    &args.verification_id,
                )
                .await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_strategy_scorecard(&lookup.report));
            }
            return Ok(());
        }
        Command::StrategyScorecardResult(args) => {
            let lookup = strategy_scorecard_harness
                .load_scorecard(&args.scorecard_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "strategy scorecard was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_strategy_scorecard(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionPressureCreate(args) => {
            let lookup = if let Some(experiment_id) = args.experiment_id.as_deref() {
                evolution_drafting_harness.create_pressure_from_experiment(
                    &replay_harness,
                    &cli.experiment_results_dir,
                    experiment_id,
                )?
            } else if let Some(verification_id) = args.verification_id.as_deref() {
                evolution_drafting_harness.create_pressure_from_verification(
                    &replay_harness,
                    &cli.verification_results_dir,
                    verification_id,
                )?
            } else {
                let scorecard_id = args.scorecard_id.as_deref().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "create-pressure requires one of manual_packet_set_id, verification_id, or scorecard_id",
                    )
                })?;
                evolution_drafting_harness.create_pressure_from_scorecard(
                    &strategy_scorecard_harness,
                    scorecard_id,
                )?
            };
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_pressure(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionPressureResult(args) => {
            let lookup = evolution_drafting_harness
                .load_pressure(&args.pressure_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "evolution selection pressure report was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_pressure(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionProofCreate(args) => {
            let lookup = evolution_proof_harness.create_proof(
                args.experiment,
                &cli.verification_results_dir,
                &args.verification_id,
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_proof(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionProofResult(args) => {
            let lookup = evolution_proof_harness
                .load_proof(&args.proof_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "evolution proof was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_proof(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionQueueCreate(args) => {
            let lookup = evolution_queue_harness
                .create_proposal(
                    &replay_harness,
                    &strategy_scorecard_harness,
                    EvolutionProposalCreateRequest {
                        experiment_path: args.experiment,
                        experiment_results_dir: cli.experiment_results_dir.clone(),
                        verification_results_dir: cli.verification_results_dir.clone(),
                        verification_id: args.verification_id.clone(),
                        proof_results_dir: cli.evolution_proof_results_dir.clone(),
                        proof_id: args.proof_id.clone(),
                    },
                )
                .await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_proposal(&lookup.report));
            }
            if lookup.report.review_state == EvolutionProposalReviewState::Blocked {
                std::process::exit(1);
            }
            return Ok(());
        }
        Command::EvolutionQueueResult(args) => {
            let lookup = evolution_queue_harness
                .load_proposal(&args.proposal_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "evolution proposal was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_proposal(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionQueueList(args) => {
            let list = evolution_queue_harness.list_proposals(
                args.strategy_id.as_deref(),
                args.review_state.map(Into::into),
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                println!("{}", render_evolution_proposal_list(&list));
            }
            return Ok(());
        }
        Command::EvolutionQueueDecision(args) => {
            let lookup = evolution_queue_harness.record_decision(
                &args.proposal_id,
                args.decision.into(),
                &args.reason,
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_proposal(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionDraftCreate(args) => {
            let lookup = evolution_drafting_harness.create_draft(EvolutionDraftCreateRequest {
                pressure_id: args.pressure_id,
                strategy_id: args.strategy_id,
                strategy_description: args.strategy_description,
                mutation: args.mutation,
                rationale: args.rationale,
            })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_draft(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionDraftResult(args) => {
            let lookup = evolution_drafting_harness
                .load_draft(&args.draft_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "evolution proposal draft was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_draft(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionDraftPromote(args) => {
            let lookup = evolution_drafting_harness.promote_draft(
                &cli.evolution_queue_results_dir,
                &args.draft_id,
                &args.reason,
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_draft_promotion(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionDraftPromotionResult(args) => {
            let lookup = evolution_drafting_harness
                .load_draft_promotion(&args.promotion_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "evolution draft promotion record was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_draft_promotion(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionMutationCreate(args) => {
            let lookup = evolution_mutation_harness.create_mutation_spec(
                &evolution_drafting_harness,
                EvolutionMutationSpecCreateRequest {
                    draft_id: args.draft_id,
                    materialization_id: args.materialization_id,
                    base_experiment_path: args.base_experiment,
                    rationale: args.rationale,
                },
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_mutation_spec(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionMutationAddVariant(args) => {
            let lookup = evolution_mutation_harness.append_variant(
                &args.mutation_spec_id,
                EvolutionMutationVariantCreateRequest {
                    variant_id: args.variant_id,
                    strategy_id: args.strategy_id,
                    strategy_description: args.strategy_description,
                    mutation: args.mutation,
                    rationale: args.rationale,
                    overrides: EvolutionMutationProfileOverrides {
                        add_suspicious_parents: args.add_suspicious_parent,
                        remove_suspicious_parents: args.remove_suspicious_parent,
                        add_suspicious_children: args.add_suspicious_child,
                        remove_suspicious_children: args.remove_suspicious_child,
                        high_confidence_threshold: args.high_confidence_threshold,
                        medium_confidence_threshold: args.medium_confidence_threshold,
                    },
                },
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_mutation_spec(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionMutationResult(args) => {
            let lookup = evolution_mutation_harness
                .load_mutation_spec(&args.mutation_spec_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "evolution mutation spec was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_mutation_spec(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionMutationMaterializeBatch(args) => {
            let lookup = evolution_mutation_harness
                .materialize_batch(&evolution_drafting_harness, &args.mutation_spec_id)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!(
                    "{}",
                    render_evolution_mutation_materialization_batch(&lookup.report)
                );
            }
            return Ok(());
        }
        Command::EvolutionMutationMaterializationBatchResult(args) => {
            let lookup = evolution_mutation_harness
                .load_materialization_batch(&args.batch_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "evolution mutation materialization batch was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!(
                    "{}",
                    render_evolution_mutation_materialization_batch(&lookup.report)
                );
            }
            return Ok(());
        }
        Command::EvolutionMutationValidateBatch(args) => {
            let lookup = evolution_mutation_harness
                .refresh_validation_batch(
                    &evolution_drafting_harness,
                    &replay_harness,
                    &evolution_proof_harness,
                    &strategy_scorecard_harness,
                    &cli.experiment_results_dir,
                    &cli.verification_results_dir,
                    &cli.shadow_results_dir,
                    &args.batch_id,
                )
                .await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!(
                    "{}",
                    render_evolution_mutation_validation_batch(&lookup.report)
                );
            }
            if lookup.report.blocked_count > 0 {
                std::process::exit(1);
            }
            return Ok(());
        }
        Command::EvolutionMutationValidationBatchResult(args) => {
            let lookup = evolution_mutation_harness
                .load_validation_batch(&args.validation_batch_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "evolution mutation validation batch was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!(
                    "{}",
                    render_evolution_mutation_validation_batch(&lookup.report)
                );
            }
            return Ok(());
        }
        Command::EvolutionRankCandidates(args) => {
            let lookup = evolution_mutation_harness.rank_candidates(
                &cli.evolution_queue_results_dir,
                &args.validation_batch_id,
                args.shortlist_count,
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_mutation_ranking(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionRankingResult(args) => {
            let lookup = evolution_mutation_harness
                .load_ranking(&args.ranking_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "evolution mutation ranking was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_mutation_ranking(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionSelectionCreate(args) => {
            let lookup =
                evolution_selection_harness.create_selection(&args.ranking_id, &args.packet_id)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!(
                    "{}",
                    render_evolution_ranked_candidate_selection(&lookup.report)
                );
            }
            if lookup.report.review_state == EvolutionProposalReviewState::Blocked {
                std::process::exit(1);
            }
            return Ok(());
        }
        Command::EvolutionSelectionResult(args) => {
            let lookup = evolution_selection_harness
                .load_selection(&args.selection_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "evolution ranked-candidate selection was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!(
                    "{}",
                    render_evolution_ranked_candidate_selection(&lookup.report)
                );
            }
            return Ok(());
        }
        Command::EvolutionSelectionList(args) => {
            let list = evolution_selection_harness.list_selections(
                args.strategy_id.as_deref(),
                args.review_state.map(Into::into),
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                println!(
                    "{}",
                    render_evolution_ranked_candidate_selection_list(&list)
                );
            }
            return Ok(());
        }
        Command::EvolutionSelectionDecision(args) => {
            let lookup = evolution_selection_harness.record_decision(
                &args.selection_id,
                args.decision.into(),
                &args.reason,
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!(
                    "{}",
                    render_evolution_ranked_candidate_selection(&lookup.report)
                );
            }
            return Ok(());
        }
        Command::EvolutionSelectionBridge(args) => {
            let lookup = evolution_selection_harness.bridge_selection(
                &cli.evolution_queue_results_dir,
                &args.selection_id,
                &args.reason,
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!(
                    "{}",
                    render_evolution_ranked_candidate_bridge(&lookup.report)
                );
            }
            if !lookup.report.blocking_reasons.is_empty() || !lookup.report.handoff_ready {
                std::process::exit(1);
            }
            return Ok(());
        }
        Command::EvolutionSelectionBridgeResult(args) => {
            let lookup = evolution_selection_harness
                .load_bridge(&args.bridge_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "evolution ranked-candidate bridge was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!(
                    "{}",
                    render_evolution_ranked_candidate_bridge(&lookup.report)
                );
            }
            return Ok(());
        }
        Command::EvolutionPortfolioCreate(args) => {
            if !args.cohort.is_empty() && args.cohort.len() != args.selection_id.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "--cohort count ({}) must match --selection-id count ({}) when cohorts are supplied",
                        args.cohort.len(),
                        args.selection_id.len()
                    ),
                )
                .into());
            }
            let entries = args
                .selection_id
                .into_iter()
                .enumerate()
                .map(
                    |(index, selection_id)| EvolutionPortfolioEntryCreateRequest {
                        selection_id,
                        cohort: args.cohort.get(index).cloned(),
                    },
                )
                .collect::<Vec<_>>();
            let lookup = evolution_portfolio_harness.create_portfolio(
                &args.name,
                &args.rationale,
                entries,
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_portfolio(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionPortfolioResult(args) => {
            let lookup = evolution_portfolio_harness
                .load_portfolio(&args.portfolio_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "evolution portfolio was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_portfolio(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionPortfolioList(args) => {
            let list = evolution_portfolio_harness
                .list_portfolios(args.cohort.as_deref(), args.review_state.map(Into::into))?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                println!("{}", render_evolution_portfolio_list(&list));
            }
            return Ok(());
        }
        Command::EvolutionPortfolioDecision(args) => {
            let lookup = evolution_portfolio_harness.record_decision(
                &args.portfolio_id,
                &args.entry_id,
                args.decision.into(),
                &args.reason,
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_portfolio(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionGovernancePacketCreate(args) => {
            let lookup = evolution_portfolio_harness.create_governance_review_packet(
                &args.portfolio_id,
                &args.entry_id,
                &args.reason,
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!(
                    "{}",
                    render_evolution_governance_review_packet(&lookup.report)
                );
            }
            if !lookup.report.ready_for_governance || !lookup.report.blocking_reasons.is_empty() {
                std::process::exit(1);
            }
            return Ok(());
        }
        Command::EvolutionGovernancePacketResult(args) => {
            let lookup = evolution_portfolio_harness
                .load_governance_review_packet(&args.packet_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "evolution governance review packet was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!(
                    "{}",
                    render_evolution_governance_review_packet(&lookup.report)
                );
            }
            return Ok(());
        }
        Command::EvolutionPacketSetCreate(args) => {
            let lookup = evolution_governance_prep_harness.create_packet_set(
                &args.name,
                &args.rationale,
                args.packet_id,
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_governance_packet_set(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionPacketSetResult(args) => {
            let lookup = evolution_governance_prep_harness
                .load_packet_set(&args.packet_set_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "evolution governance packet set was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_governance_packet_set(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionPacketSetList(args) => {
            let list =
                evolution_governance_prep_harness.list_packet_sets(args.cohort.as_deref())?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                println!("{}", render_evolution_governance_packet_set_list(&list));
            }
            return Ok(());
        }
        Command::EvolutionPacketSetSplit(args) => {
            let lookup = evolution_governance_prep_harness.split_packet_set(
                &args.packet_set_id,
                &args.name,
                &args.rationale,
                args.packet_id,
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_governance_packet_set(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionPortfolioHistoryCreate(args) => {
            let lookup =
                evolution_governance_prep_harness.create_portfolio_history(&args.packet_set_id)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_portfolio_history(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionPortfolioHistoryResult(args) => {
            let lookup = evolution_governance_prep_harness
                .load_portfolio_history(&args.history_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "evolution portfolio history was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_portfolio_history(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionPortfolioHistoryList(args) => {
            let list =
                evolution_governance_prep_harness.list_portfolio_history(args.cohort.as_deref())?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                println!("{}", render_evolution_portfolio_history_list(&list));
            }
            return Ok(());
        }
        Command::EvolutionMaterialize(args) => {
            let lookup = evolution_drafting_harness.materialize_draft(
                EvolutionDraftMaterializationRequest {
                    draft_id: args.draft_id,
                    base_experiment_path: args.base_experiment,
                    add_suspicious_parents: args.add_suspicious_parent,
                    remove_suspicious_parents: args.remove_suspicious_parent,
                    add_suspicious_children: args.add_suspicious_child,
                    remove_suspicious_children: args.remove_suspicious_child,
                    high_confidence_threshold: args.high_confidence_threshold,
                    medium_confidence_threshold: args.medium_confidence_threshold,
                },
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_materialization(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionMaterializationResult(args) => {
            let lookup = evolution_drafting_harness
                .load_materialization(&args.materialization_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "evolution draft materialization was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_materialization(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionValidationRefresh(args) => {
            let lookup = evolution_drafting_harness
                .refresh_validation_bundle(
                    &replay_harness,
                    &evolution_proof_harness,
                    &strategy_scorecard_harness,
                    &cli.experiment_results_dir,
                    &cli.verification_results_dir,
                    &cli.shadow_results_dir,
                    &args.materialization_id,
                )
                .await?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_validation_bundle(&lookup.report));
            }
            if lookup.report.status
                == crate::drafting::EvolutionValidationBundleStatus::Blocked
            {
                std::process::exit(1);
            }
            return Ok(());
        }
        Command::EvolutionValidationResult(args) => {
            let lookup = evolution_drafting_harness
                .load_validation_bundle(&args.validation_bundle_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "evolution validation bundle was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_validation_bundle(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionQueueReconcile(args) => {
            let lookup = evolution_drafting_harness.reconcile_queue_proposal(
                &cli.evolution_queue_results_dir,
                &args.promotion_id,
                &args.validation_bundle_id,
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_queue_reconciliation(&lookup.report));
            }
            if lookup.report.resulting_review_state == EvolutionProposalReviewState::Blocked {
                std::process::exit(1);
            }
            return Ok(());
        }
        Command::EvolutionQueueReconciliationResult(args) => {
            let lookup = evolution_drafting_harness
                .load_queue_reconciliation(&args.reconciliation_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "evolution queue reconciliation was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_queue_reconciliation(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionHandoffCreate(args) => {
            let lookup = evolution_handoff_harness.create_handoff(
                &cli.evolution_queue_results_dir,
                &args.proposal_id,
                &cli.shadow_results_dir,
                &args.shadow_id,
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_handoff(&lookup.report));
            }
            if !lookup.report.blocking_reasons.is_empty() {
                std::process::exit(1);
            }
            return Ok(());
        }
        Command::EvolutionHandoffResult(args) => {
            let lookup = evolution_handoff_harness
                .load_handoff(&args.handoff_id)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "evolution handoff was not found",
                    )
                })?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_handoff(&lookup.report));
            }
            return Ok(());
        }
        Command::EvolutionHandoffLaunchCanary(args) => {
            let lookup = evolution_handoff_harness.launch_canary(
                &canary_harness,
                &cli.verification_results_dir,
                &cli.shadow_results_dir,
                &args.handoff_id,
            )?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&lookup.report)?);
            } else {
                println!("{}", render_evolution_handoff(&lookup.report));
            }
            return Ok(());
        }
    };

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}", render_output(&output));
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        Cli, Command, EvolutionArgs, EvolutionCommand, InitArgs, InitMode, build_validate_report,
        default_init_output_path, parse_review_artifact_ref_arg, render_init_template,
        run_init_command, run_playbook_preview_command, run_readiness_command,
    };
    use crate::config::write_debug_test_config_signature;
    use clap::Parser;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};
    use swarm_core::agent::SwarmMode;
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::Severity;

    fn unique_temp_dir(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("swarmctl-{label}-{suffix}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn current_dir_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn cli_parses_global_json_flag_for_status() {
        let cli = Cli::parse_from(["swarmctl", "--json", "status"]);
        assert!(cli.json);
        assert!(matches!(cli.command, Command::Status));
    }

    #[test]
    fn cli_parses_evolution_status_command() {
        let cli = Cli::parse_from(["swarmctl", "evolution", "status"]);
        match cli.command {
            Command::Evolution(EvolutionArgs {
                command: EvolutionCommand::Status,
            }) => {}
            other => panic!("expected evolution status command, got {other:?}"),
        }
    }

    #[test]
    fn cli_parses_global_otlp_endpoint_flag() {
        let cli = Cli::parse_from([
            "swarmctl",
            "--otlp-endpoint",
            "http://127.0.0.1:4318/v1/traces",
            "status",
        ]);
        assert_eq!(
            cli.otlp_endpoint.as_deref(),
            Some("http://127.0.0.1:4318/v1/traces")
        );
        assert!(matches!(cli.command, Command::Status));
    }

    #[test]
    fn cli_parses_validate_command() {
        let cli = Cli::parse_from(["swarmctl", "validate", "--check-endpoints"]);
        assert!(matches!(cli.command, Command::Validate(_)));
    }

    #[test]
    fn cli_parses_init_command() {
        let cli = Cli::parse_from(["swarmctl", "init", "--mode", "live_response"]);
        assert!(matches!(cli.command, Command::Init(_)));
    }

    #[test]
    fn cli_parses_readiness_command() {
        let cli = Cli::parse_from(["swarmctl", "--output-schema-version", "1", "readiness"]);
        assert_eq!(cli.output_schema_version, Some(1));
        assert!(matches!(cli.command, Command::Readiness));
    }

    #[test]
    fn cli_parses_first_run_command() {
        let cli = Cli::parse_from(["swarmctl", "first-run", "--pace-ms", "25"]);
        assert!(matches!(cli.command, Command::FirstRun(_)));
    }

    #[test]
    fn cli_parses_playbook_preview_command() {
        let cli = Cli::parse_from([
            "swarmctl",
            "playbook-preview",
            "--threat-class",
            "execution",
            "--severity",
            "HIGH",
            "--confidence",
            "0.97",
            "--mode",
            "incident",
        ]);
        assert!(matches!(cli.command, Command::PlaybookPreview(_)));
    }

    #[test]
    fn cli_parses_identity_rotate_command() {
        let cli = Cli::parse_from([
            "swarmctl", "identity", "rotate", "--role", "tom", "--slot", "primary",
        ]);
        assert!(matches!(cli.command, Command::Identity(_)));
    }

    #[test]
    fn review_artifact_ref_arg_parses_kind_and_id() {
        let artifact = parse_review_artifact_ref_arg("evidence_bundle:bundle-1").unwrap();
        assert_eq!(artifact.kind.as_str(), "evidence_bundle");
        assert_eq!(artifact.id, "bundle-1");
    }

    #[test]
    fn review_artifact_ref_arg_rejects_unknown_kind() {
        let error = parse_review_artifact_ref_arg("unknown:bundle-1").unwrap_err();
        assert!(error.contains("unsupported review artifact kind"));
    }

    #[tokio::test]
    async fn validate_command_reports_structured_json_and_endpoint_failures() {
        let dir = unique_temp_dir("validate");
        let config_path = dir.join("config.yaml");
        let template = render_init_template(InitMode::DetectOnly).replace(
            "response_adapter:\n  kind: sandbox",
            "response_adapter:\n  kind: webhook\n  url: http://127.0.0.1:1/hook\n  auth_token: replace-me\n  timeout_ms: 5000\n  dead_letter_path: data/dead-letter.jsonl",
        );
        fs::write(&config_path, template).unwrap();
        write_debug_test_config_signature(&config_path).unwrap();

        let report = build_validate_report(&config_path, true).await;
        assert!(!report.passed);
        assert!(report.config_valid);
        assert_eq!(
            report.config.as_ref().unwrap().response_adapter,
            "webhook".to_string()
        );
        assert_eq!(report.endpoint_checks.len(), 1);
        assert_eq!(report.endpoint_checks[0].target, "response_adapter");
        assert!(!report.endpoint_checks[0].reachable);

        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["endpoint_checks_requested"], true);
        assert_eq!(json["endpoint_checks"][0]["target"], "response_adapter");
        assert_eq!(json["endpoint_checks"][0]["reachable"], false);
    }

    #[tokio::test]
    async fn readiness_command_accepts_signed_init_template() {
        let dir = unique_temp_dir("readiness");
        let config_path = dir.join("config.yaml");
        fs::write(&config_path, render_init_template(InitMode::DetectOnly)).unwrap();
        write_debug_test_config_signature(&config_path).unwrap();

        let result = run_readiness_command(&config_path, Some(1), true).await;
        assert!(result.is_ok());
    }

    #[test]
    fn playbook_preview_command_accepts_signed_init_template() {
        let dir = unique_temp_dir("playbook-preview");
        let config_path = dir.join("config.yaml");
        fs::write(&config_path, render_init_template(InitMode::DetectOnly)).unwrap();
        write_debug_test_config_signature(&config_path).unwrap();

        let result = run_playbook_preview_command(
            &config_path,
            &super::PlaybookPreviewArgs {
                threat_class: ThreatClass::Execution,
                severity: Severity::High,
                confidence: 0.97,
                mode: SwarmMode::Incident,
            },
            Some(1),
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn playbook_preview_command_rejects_unsupported_output_schema_version() {
        let dir = unique_temp_dir("playbook-preview-schema");
        let config_path = dir.join("config.yaml");
        fs::write(&config_path, render_init_template(InitMode::DetectOnly)).unwrap();
        write_debug_test_config_signature(&config_path).unwrap();

        let error = run_playbook_preview_command(
            &config_path,
            &super::PlaybookPreviewArgs {
                threat_class: ThreatClass::Execution,
                severity: Severity::High,
                confidence: 0.97,
                mode: SwarmMode::Incident,
            },
            Some(99),
            true,
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("unsupported operator API schema version")
        );
    }

    #[test]
    fn init_command_writes_live_response_template_to_default_output() {
        let _guard = current_dir_lock().lock().unwrap();
        let original_dir = std::env::current_dir().unwrap();
        let temp_dir = unique_temp_dir("init");
        std::env::set_current_dir(&temp_dir).unwrap();

        let result = run_init_command(
            &InitArgs {
                mode: InitMode::LiveResponse,
                output: None,
                force: false,
            },
            false,
        );

        std::env::set_current_dir(&original_dir).unwrap();
        result.unwrap();

        let output_path = temp_dir.join(default_init_output_path());
        let rendered = fs::read_to_string(output_path).unwrap();
        assert!(rendered.contains("mode: live_response"));
        assert!(rendered.contains("kind: local_journal"));
        assert!(rendered.contains("response_adapter:\n  # Replace the placeholder URL and token before deploying to production."));
    }
}
