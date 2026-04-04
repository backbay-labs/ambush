use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use swarm_runtime::canary::{DefaultCanaryHarness, render_canary_run_report};
use swarm_runtime::control::{
    DefaultControlPlane, IncidentLookupSelector, InvestigationLookupSelector,
    OperatorControlOutput, ReplayLookupSelector, render_output,
};
use swarm_runtime::drafting::{
    DefaultEvolutionDraftingHarness, EvolutionDraftCreateRequest,
    EvolutionDraftMaterializationRequest, render_evolution_draft, render_evolution_draft_promotion,
    render_evolution_materialization, render_evolution_pressure,
    render_evolution_queue_reconciliation, render_evolution_validation_bundle,
};
use swarm_runtime::evolution::{
    DefaultEvolutionHandoffHarness, DefaultEvolutionProofHarness, DefaultEvolutionQueueHarness,
    EvolutionProposalCreateRequest, EvolutionProposalDecisionAction, EvolutionProposalReviewState,
    render_evolution_handoff, render_evolution_proof, render_evolution_proposal,
    render_evolution_proposal_list,
};
use swarm_runtime::mutation::{
    DefaultEvolutionMutationHarness, EvolutionMutationProfileOverrides,
    EvolutionMutationSpecCreateRequest, EvolutionMutationVariantCreateRequest,
    render_evolution_mutation_materialization_batch, render_evolution_mutation_ranking,
    render_evolution_mutation_spec, render_evolution_mutation_validation_batch,
};
use swarm_runtime::promotion::{
    DefaultProductionPromotionHarness, ProductionPromotionStatus,
    render_production_promotion_report,
};
use swarm_runtime::replay::{
    DefaultReplayHarness, render_evaluation_report, render_experiment_report,
    render_promotion_review_packet, render_replay_run, render_shadow_report, render_suite_report,
    render_verification_report,
};
use swarm_runtime::selection::{
    DefaultEvolutionSelectionHarness, render_evolution_ranked_candidate_bridge,
    render_evolution_ranked_candidate_selection, render_evolution_ranked_candidate_selection_list,
};
use swarm_runtime::strategy::{
    DefaultStrategyMemoryHarness, DefaultStrategyScorecardHarness, render_strategy_memory,
    render_strategy_memory_history, render_strategy_scorecard,
};

#[derive(Debug, Parser)]
#[command(
    name = "swarmctl",
    about = "Repo-owned operator control surface for Swarm Team Six"
)]
struct Cli {
    #[arg(long, global = true, default_value = "rulesets/default.yaml")]
    config: std::path::PathBuf,

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

    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Status,
    Replay(ReplayArgs),
    Investigation(InvestigationArgs),
    Incident(IncidentArgs),
    ReplayRun(ReplayRunArgs),
    ReplayResult(ReplayResultArgs),
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
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

    let output = match cli.command {
        Command::Status => OperatorControlOutput::Status(Box::new(plane.status().await?)),
        Command::Replay(args) => OperatorControlOutput::Replay(Box::new(plane.replay_lookup(
            if let Some(bundle_id) = args.bundle_id.as_deref() {
                ReplayLookupSelector::BundleId(bundle_id)
            } else if let Some(hunt_id) = args.hunt_id.as_deref() {
                ReplayLookupSelector::HuntId(hunt_id)
            } else {
                ReplayLookupSelector::ReceiptId(args.receipt_id.as_deref().expect("receipt id"))
            },
        )?)),
        Command::Investigation(args) => {
            OperatorControlOutput::Investigation(Box::new(plane.investigation_lookup(
                if let Some(investigation_id) = args.investigation_id.as_deref() {
                    InvestigationLookupSelector::InvestigationId(investigation_id)
                } else if let Some(hunt_id) = args.hunt_id.as_deref() {
                    InvestigationLookupSelector::HuntId(hunt_id)
                } else {
                    InvestigationLookupSelector::ReceiptId(
                        args.receipt_id.as_deref().expect("receipt id"),
                    )
                },
            )?))
        }
        Command::Incident(args) => OperatorControlOutput::Incident(Box::new(
            plane.incident_lookup(if let Some(incident_id) = args.incident_id.as_deref() {
                IncidentLookupSelector::IncidentId(incident_id)
            } else {
                IncidentLookupSelector::HuntId(args.hunt_id.as_deref().expect("hunt id"))
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
                replay_harness.load_run_for_scenario_path(args.scenario.expect("scenario path"))?
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
                replay_harness
                    .evaluate_scenario_path(args.scenario.expect("scenario path"))
                    .await?
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
                swarm_runtime::canary::CanaryRunStatus::RolledBack
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
                evolution_drafting_harness.create_pressure_from_scorecard(
                    &strategy_scorecard_harness,
                    args.scorecard_id.as_deref().expect("scorecard id"),
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
                == swarm_runtime::drafting::EvolutionValidationBundleStatus::Blocked
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
