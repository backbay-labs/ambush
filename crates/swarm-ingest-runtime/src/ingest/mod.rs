mod demo;
mod governance_resume;
mod health;
mod platform_api;
mod providence_handlers;
mod soar_verdict_handlers;

// Re-export the public API that was previously accessible as `crate::ingest::*`
pub use demo::{
    DemoApprovalResumeRequest, DemoApprovalResumeResponse, DemoDashboardSnapshot, DemoProofLeaf,
    DemoProofPackage, DemoProofQuery, DemoReplayRequest, DemoReplayResponse, DemoRunApprovalReport,
    DemoRunReport, DemoTimelineEntry, FirstRunWizardArtifacts, FirstRunWizardError,
    FirstRunWizardReport, FirstRunWizardRequest, FirstRunWizardStatus, run_first_run_wizard,
};

use crate::anti_tamper::AntiTamperReport;
use crate::bridge_runtime::{SharedBridgeHealth, bridge_health_report};
use crate::control::{ControlError, build_composite_detector};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use axum::extract::{Json, State, rejection::JsonRejection};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, response::Json as ResponseJson};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use swarm_core::ThreatClass;
use swarm_core::agent::{AgentHealthEntry, SwarmModeState};
use swarm_core::config::{
    OperatorScope, OperatorSurfaceConfig, ResponseAdapterConfig, RuntimeAntiTamperConfig,
    RuntimeMode, SwarmConfig,
};
use swarm_core::http_rate_limit::HttpRateLimiter;
use swarm_core::pheromone::EscalationRecord;
use swarm_core::types::AgentId;
use swarm_governance::GovernanceAuthority;
use swarm_pheromone::PheromoneSubstrate;
use swarm_policy::configurable_gate::ConfigurableApprovalGate;
use swarm_policy::governance::GovernedHumanAuthorizationHold;
use swarm_policy::{ActionRequest, ApprovalContext};
use swarm_response::DispatchingExecutor;
use swarm_runtime::approval::{
    ApprovalError, ApprovalReceiptPackReport, DefaultApprovalHarness, ThresholdRule,
};
use swarm_runtime::canary::DefaultCanaryHarness;
use swarm_runtime::config::{
    RuntimeConfigError, load_config_unresolved, resolve_outbound_secrets, resolve_secret_dir_path,
};
use swarm_runtime::correlation::CorrelationEngine;
use swarm_runtime::detection::metrics::CriticalPathMetrics;
use swarm_runtime::dispatcher::{
    DispatcherPolicyPermit, DispatcherPolicyPreflight, GovernanceVetoRoute, GovernedHumanHoldRoute,
    HumanApprovalChallenge, RequestResponseRouter, RoutedActionRequest,
};
use swarm_runtime::dispatcher::{
    StrategyProposalOutcome, StrategyProposalRoute, StrategyProposalRouteReport,
    StrategyProposalRouter,
};
use swarm_runtime::drafting::DefaultEvolutionDraftingHarness;
use swarm_runtime::evasion_coverage::{
    EvasionCoverageError, EvasionCoverageSnapshot, evaluate_repo_evasion_coverage,
    resolve_repo_root,
};
use swarm_runtime::evolution::{
    DefaultEvolutionHandoffHarness, DefaultEvolutionProofHarness, DefaultEvolutionQueueHarness,
    DefaultFormalSafetyGate, EvolutionProposalAssuranceDecision, EvolutionProposalDecisionAction,
    EvolutionProposalReviewState, FormalSafetyGate, StrategyGenome,
};
use swarm_runtime::evolution_status::DefaultEvolutionStatusHarness;
use swarm_runtime::investigation::{InvestigationCoordinator, SummaryInvestigator};
use swarm_runtime::mutation::DefaultEvolutionMutationHarness;
use swarm_runtime::providence::{
    PROVIDENCE_CHANNEL, ProvidenceContextScope, ProvidenceHealthStatus, ProvidenceIncidentAdapter,
    ProvidenceRuntimeContext, verify_providence_context_token,
};
use swarm_runtime::runtime_events::{
    AsyncLaneStatusSnapshot, RuntimeEvent, RuntimeEventBroadcaster, RuntimeThreatConcentration,
    now_ms,
};
use swarm_runtime::selection::DefaultEvolutionSelectionHarness;
use swarm_runtime::service::{
    ConfiguredRuntimeStack, RuntimeDegradationSignals, RuntimeDegradationStatus, ServiceError,
    derive_runtime_degradation_status,
};
use swarm_runtime::startup_attestation::StartupAttestationReport;
use swarm_runtime::threat_intel_runtime::SharedThreatIntelFeedHealth;
use swarm_runtime::{RuntimeError, StrategyProposalRouteError, SwarmRuntime};
use swarm_spine::{
    AuditResponseRecord, AuditTrail, ConfiguredIncidentStore, ConfiguredInvestigationBundleStore,
    ConfiguredReplayBundleStore, CorrelatedIncident, ReplayBundleStore,
};
use swarm_whisker::{CompositeDetector, DetectionFinding, TelemetryEvent};
use tracing::Instrument;
use uuid::Uuid;

// Re-import from sub-modules for internal use
use demo::{
    DemoApprovalDecisionRecord, DemoRunRegistry, DemoRunState, DemoScopeQuery, PendingDemoApproval,
};
use health::{
    DetectorRuntimeStatus, HeapPressureSnapshot, IngestLifecycleState, IngestRequestGuard,
    active_agent_counts, sample_heap_pressure,
};
use providence_handlers::{build_providence_notification_payload, publish_runtime_findings};

type IngestRuntimeStack =
    ConfiguredRuntimeStack<ConfigurableApprovalGate, DispatchingExecutor, SummaryInvestigator>;
type IngestRequestRuntime = SwarmRuntime<ConfigurableApprovalGate, DispatchingExecutor>;
type IngestBuiltRuntime = (
    Arc<IngestRuntimeStack>,
    Arc<IngestRequestRuntime>,
    Arc<CompositeDetector>,
);

const MAX_INGEST_FUTURE_SKEW_MS: i64 = 5 * 60 * 1_000;
const TIMESTAMP_MILLISECONDS_CUTOFF: i64 = 100_000_000_000;

type HeapSnapshotProvider = Arc<dyn Fn() -> Option<HeapPressureSnapshot> + Send + Sync>;

struct IngestRuntimeRequestResponseRouter {
    stack: Arc<ArcSwap<IngestRuntimeStack>>,
    runtime: Arc<ArcSwap<IngestRequestRuntime>>,
    approval_harness: Option<Arc<DefaultApprovalHarness>>,
}

/// Moved verbatim from `swarm_runtime::dispatcher::approval_context_now` in SPLIT-05.
///
/// It was `pub(crate)` on the root and these two routes were its only callers, so
/// it followed them across the crate line rather than becoming permanent public
/// API on a crate this phase is dismantling. The one substitution is the clock:
/// the original called `dispatcher`'s private `unix_timestamp_millis`, and
/// `runtime_events::now_ms` -- already imported here, and already `pub` -- has a
/// byte-identical body.
fn approval_context_now(live_mode: bool) -> ApprovalContext {
    ApprovalContext {
        live_mode,
        receipt_chain: Vec::new(),
        correlation_id: None,
        now_ms: now_ms(),
    }
}

#[async_trait]
impl RequestResponseRouter for IngestRuntimeRequestResponseRouter {
    async fn preflight_request(
        &self,
        request: ActionRequest,
    ) -> Result<DispatcherPolicyPreflight, RuntimeError> {
        let runtime = self.runtime.load_full();
        let context = approval_context_now(runtime.mode() == RuntimeMode::LiveResponse);
        let detection = routed_detection_from_request(&request);
        runtime.preflight_dispatcher_request(request, detection, context)
    }

    async fn route_preflight_audit(
        &self,
        audit: swarm_spine::AuditTrail,
    ) -> Result<swarm_spine::AuditTrail, RuntimeError> {
        Ok(audit)
    }

    async fn route_request(
        &self,
        admitted: RoutedActionRequest,
    ) -> Result<swarm_spine::AuditTrail, RuntimeError> {
        let runtime = self.runtime.load_full();
        runtime.audit_authorize_and_execute_admitted(admitted).await
    }

    async fn route_human_hold(
        &self,
        route: GovernedHumanHoldRoute,
    ) -> Result<HumanApprovalChallenge, RuntimeError> {
        let harness = self.approval_harness.as_ref().ok_or_else(|| {
            RuntimeError::GovernanceAuthorization("human approval harness is not configured".into())
        })?;
        let eligible_voters = configured_approval_voters(&self.stack.load_full().service.config)
            .map_err(|error| RuntimeError::GovernanceAuthorization(error.to_string()))?;
        let record = harness
            .create_or_load_approval_set(
                eligible_voters,
                ThresholdRule::AtLeast { required: 1 },
                &route.hold().approval_evidence_ref(),
            )
            .map_err(|error| RuntimeError::GovernanceAuthorization(error.to_string()))?;
        let report = harness
            .load_approval_set(&record.set_id)
            .map_err(|error| RuntimeError::GovernanceAuthorization(error.to_string()))?
            .ok_or_else(|| {
                RuntimeError::GovernanceAuthorization(
                    "persisted human approval set could not be reloaded".into(),
                )
            })?;
        route.challenge_for_persisted_set(&report.report)
    }

    async fn load_persisted_human_approval(
        &self,
        pack_id: &str,
    ) -> Result<Option<ApprovalReceiptPackReport>, RuntimeError> {
        let harness = self.approval_harness.as_ref().ok_or_else(|| {
            RuntimeError::GovernanceAuthorization("human approval harness is not configured".into())
        })?;
        Ok(harness
            .load_receipt_pack(pack_id)
            .map_err(|error| RuntimeError::GovernanceAuthorization(error.to_string()))?
            .map(|lookup| lookup.report))
    }

    async fn load_human_resume_outcome(
        &self,
        pack_id: &str,
    ) -> Result<Option<swarm_spine::AuditTrail>, RuntimeError> {
        let harness = self.approval_harness.as_ref().ok_or_else(|| {
            RuntimeError::GovernanceAuthorization("human approval harness is not configured".into())
        })?;
        harness
            .load_human_resume_outcome(pack_id)
            .map_err(|error| RuntimeError::GovernanceAuthorization(error.to_string()))
    }

    async fn persist_human_resume_outcome(
        &self,
        pack_id: &str,
        audit: &swarm_spine::AuditTrail,
    ) -> Result<(), RuntimeError> {
        let harness = self.approval_harness.as_ref().ok_or_else(|| {
            RuntimeError::GovernanceAuthorization("human approval harness is not configured".into())
        })?;
        harness
            .persist_human_resume_outcome(pack_id, audit)
            .map_err(|error| RuntimeError::GovernanceAuthorization(error.to_string()))
    }

    async fn restore_human_preflight(
        &self,
        hold: &GovernedHumanAuthorizationHold,
        approval_pack_id: &str,
    ) -> Result<DispatcherPolicyPermit, RuntimeError> {
        let runtime = self.runtime.load_full();
        let context = approval_context_now(runtime.mode() == RuntimeMode::LiveResponse);
        let detection = routed_detection_from_request(&hold.request);
        runtime.restore_human_dispatcher_preflight(hold, detection, context, approval_pack_id)
    }

    async fn route_governance_veto(
        &self,
        veto: GovernanceVetoRoute,
    ) -> Result<swarm_spine::AuditTrail, RuntimeError> {
        let runtime = self.runtime.load_full();
        let context = approval_context_now(runtime.mode() == RuntimeMode::LiveResponse);
        let detection = routed_detection_from_request(veto.request());
        Ok(runtime.audit_admitted_governance_veto(&detection, &veto, &context))
    }
}

struct IngestRuntimeStrategyProposalRouter {
    stack: Arc<ArcSwap<IngestRuntimeStack>>,
    config_path: Arc<PathBuf>,
    signing_key: ed25519_dalek::SigningKey,
    runtime_events: Option<RuntimeEventBroadcaster>,
}

#[derive(Debug, Deserialize)]
struct KittenProposalPayload {
    source: Option<String>,
    ranking_id: String,
    validation_bundle_id: String,
    materialization_id: String,
    experiment_path: String,
}

#[derive(Debug, Clone)]
struct StrategyProposalPaths {
    verification_results_dir: PathBuf,
    shadow_results_dir: PathBuf,
    evolution_proof_results_dir: PathBuf,
    evolution_queue_results_dir: PathBuf,
    evolution_selection_results_dir: PathBuf,
    evolution_bridge_results_dir: PathBuf,
    evolution_handoff_results_dir: PathBuf,
    evolution_pressure_results_dir: PathBuf,
    evolution_draft_results_dir: PathBuf,
    evolution_draft_promotion_results_dir: PathBuf,
    evolution_materialization_results_dir: PathBuf,
    evolution_validation_results_dir: PathBuf,
    evolution_reconciliation_results_dir: PathBuf,
    evolution_mutation_results_dir: PathBuf,
    evolution_mutation_materialization_batch_results_dir: PathBuf,
    evolution_mutation_validation_batch_results_dir: PathBuf,
    evolution_ranking_results_dir: PathBuf,
    evolution_population_results_dir: PathBuf,
    canary_results_dir: PathBuf,
}

#[async_trait]
impl StrategyProposalRouter for IngestRuntimeStrategyProposalRouter {
    async fn route_proposal(
        &self,
        proposal: StrategyProposalRoute,
    ) -> Result<StrategyProposalRouteReport, StrategyProposalRouteError> {
        let stack = self.stack.load_full();
        let config = stack.service.config.clone();
        let paths = resolve_strategy_proposal_paths(self.config_path.as_ref(), &config);
        let payload: KittenProposalPayload = serde_json::from_value(proposal.strategy.clone())
            .map_err(StrategyProposalRouteError::InvalidPayload)?;
        if payload.source.as_deref() != Some("kitten_population_candidate") {
            return Err(StrategyProposalRouteError::UnsupportedSource {
                proposal_source: payload.source.unwrap_or_else(|| "unknown".to_string()),
            });
        }

        let drafting = DefaultEvolutionDraftingHarness::from_config(
            self.config_path.as_ref().clone(),
            config.clone(),
            &paths.evolution_pressure_results_dir,
            &paths.evolution_draft_results_dir,
            &paths.evolution_draft_promotion_results_dir,
            &paths.evolution_materialization_results_dir,
            &paths.evolution_validation_results_dir,
            &paths.evolution_reconciliation_results_dir,
        )?;
        let validation = drafting
            .load_validation_bundle(&payload.validation_bundle_id)?
            .ok_or_else(|| StrategyProposalRouteError::MissingArtifact {
                artifact: "validation_bundle",
                artifact_id: payload.validation_bundle_id.clone(),
                strategy_id: proposal.strategy_id.clone(),
            })?;
        if validation.report.strategy_id != proposal.strategy_id {
            return Err(StrategyProposalRouteError::ValidationStrategyMismatch {
                proposal_strategy_id: proposal.strategy_id.clone(),
                validation_strategy_id: validation.report.strategy_id.clone(),
            });
        }
        if validation.report.materialization_id != payload.materialization_id {
            return Err(
                StrategyProposalRouteError::ValidationMaterializationMismatch {
                    proposal_materialization_id: payload.materialization_id.clone(),
                    validation_materialization_id: validation.report.materialization_id.clone(),
                },
            );
        }

        let mutation = DefaultEvolutionMutationHarness::from_path(
            &paths.evolution_mutation_results_dir,
            &paths.evolution_mutation_materialization_batch_results_dir,
            &paths.evolution_mutation_validation_batch_results_dir,
            &paths.evolution_ranking_results_dir,
            self.signing_key.clone(),
        )?;
        let ranking = mutation.load_ranking(&payload.ranking_id)?.ok_or_else(|| {
            StrategyProposalRouteError::MissingArtifact {
                artifact: "ranking",
                artifact_id: payload.ranking_id.clone(),
                strategy_id: proposal.strategy_id.clone(),
            }
        })?;
        let packet = ranking
            .report
            .review_packets
            .iter()
            .find(|packet| {
                packet.validation_bundle_id == validation.report.validation_bundle_id
                    && packet.materialization_id == validation.report.materialization_id
                    && packet.strategy_id == proposal.strategy_id
            })
            .ok_or_else(|| StrategyProposalRouteError::RankingPacketNotFound {
                ranking_id: payload.ranking_id.clone(),
                strategy_id: proposal.strategy_id.clone(),
                validation_bundle_id: validation.report.validation_bundle_id.clone(),
            })?;

        let selection = DefaultEvolutionSelectionHarness::from_path(
            &paths.evolution_ranking_results_dir,
            &paths.evolution_validation_results_dir,
            &paths.evolution_selection_results_dir,
            &paths.evolution_bridge_results_dir,
        )?;
        let selection_lookup =
            selection.create_selection(&payload.ranking_id, &packet.packet_id)?;

        let experiment =
            swarm_runtime::replay::load_detector_experiment_manifest(&payload.experiment_path)?;
        let verification_store =
            swarm_runtime::replay::FileVerificationStore::open(&paths.verification_results_dir)?;
        let verification = verification_store
            .load(&validation.report.verification_id)?
            .ok_or_else(|| StrategyProposalRouteError::MissingArtifact {
                artifact: "verification",
                artifact_id: validation.report.verification_id.clone(),
                strategy_id: proposal.strategy_id.clone(),
            })?;
        let shadow_store = swarm_runtime::replay::FileShadowStore::open(&paths.shadow_results_dir)?;
        let shadow = shadow_store
            .load(&validation.report.shadow_id)?
            .ok_or_else(|| StrategyProposalRouteError::MissingArtifact {
                artifact: "shadow",
                artifact_id: validation.report.shadow_id.clone(),
                strategy_id: proposal.strategy_id.clone(),
            })?;

        let safety_gate =
            DefaultFormalSafetyGate::from_config(self.config_path.as_ref().clone(), config.clone());
        let safety = safety_gate.verify(&StrategyGenome {
            strategy_id: proposal.strategy_id.clone(),
            experiment_path: PathBuf::from(&payload.experiment_path),
            experiment,
            verification: verification.report.clone(),
            shadow: shadow.report.clone(),
        })?;

        if !safety.passed {
            let reasons = safety
                .invariants
                .iter()
                .filter(|invariant| !invariant.passed())
                .map(|invariant| invariant.name.clone())
                .collect::<Vec<_>>();
            let summary = safety_rejection_summary(&safety);
            let _ = selection.record_decision(
                &selection_lookup.report.selection_id,
                EvolutionProposalDecisionAction::Reject,
                &summary,
            )?;
            let _ = mutation.record_population_candidate_review_outcome(
                &paths.evolution_population_results_dir,
                &proposal.strategy_id,
                EvolutionProposalReviewState::Rejected,
                &summary,
                &reasons,
                now_ms(),
            )?;
            self.publish_evolution_status(&config, "formal_safety_rejected");
            return Ok(StrategyProposalRouteReport {
                strategy_id: proposal.strategy_id,
                outcome: StrategyProposalOutcome::Rejected,
                selection_id: Some(selection_lookup.report.selection_id),
                bridge_id: None,
                handoff_id: None,
                canary_run_id: None,
            });
        }

        attach_formal_safety_bundle_hashes(
            self.config_path.as_ref(),
            &config,
            &paths.evolution_proof_results_dir,
            validation
                .report
                .proof
                .as_ref()
                .map(|proof| proof.proof_id.as_str()),
            &safety.bundle_sha256,
        )?;

        let accepted = selection.record_decision(
            &selection_lookup.report.selection_id,
            EvolutionProposalDecisionAction::AcceptForCanary,
            "formal safety gate accepted candidate for canary admission",
        )?;
        let bridge = selection.bridge_selection(
            &paths.evolution_queue_results_dir,
            &accepted.report.selection_id,
            "formal safety gate accepted candidate for canary admission",
        )?;

        if !bridge.report.handoff_ready {
            let reasons = bridge
                .report
                .blocking_reasons
                .iter()
                .map(|reason| reason.name.clone())
                .collect::<Vec<_>>();
            let summary = format!(
                "selection bridge remained blocked: {}",
                bridge
                    .report
                    .blocking_reasons
                    .iter()
                    .map(|reason| reason.details.clone())
                    .collect::<Vec<_>>()
                    .join("; ")
            );
            let _ = mutation.record_population_candidate_review_outcome(
                &paths.evolution_population_results_dir,
                &proposal.strategy_id,
                EvolutionProposalReviewState::Blocked,
                &summary,
                &reasons,
                now_ms(),
            )?;
            self.publish_evolution_status(&config, "canary_admission_blocked");
            return Ok(StrategyProposalRouteReport {
                strategy_id: proposal.strategy_id,
                outcome: StrategyProposalOutcome::Blocked,
                selection_id: Some(accepted.report.selection_id),
                bridge_id: Some(bridge.report.bridge_id),
                handoff_id: None,
                canary_run_id: None,
            });
        }

        let queue_proposal_id = bridge.report.queue_proposal_id.clone().ok_or_else(|| {
            StrategyProposalRouteError::MissingQueueProposalId {
                bridge_id: bridge.report.bridge_id.clone(),
            }
        })?;

        // RUN the assurance gate over the queued proposal. This block used to
        // FABRICATE a `decision: Passed` summary with `solver: { status: None }`
        // whenever `assurance` was absent -- which it always is on this route,
        // because `bridge_selection` mints the proposal with `assurance: None`.
        // Promotion authorizes on that recorded decision and nothing else
        // (`assurance_gate_block_reason` reads only `summary.decision`), so the
        // fabrication both skipped the gate and wrote down that it had passed.
        //
        // The summary type can no longer be written down outside its evaluator, so
        // the only way to fill `assurance` is to evaluate. If a future caller drops
        // this call entirely the route fails CLOSED rather than open:
        // `assurance: None` makes `assurance_rollout_state` return `Blocked`, and
        // `create_handoff` refuses on that.
        let queue_harness = DefaultEvolutionQueueHarness::from_config(
            self.config_path.as_ref().clone(),
            config.clone(),
            &paths.evolution_queue_results_dir,
        )?;
        let assured = queue_harness.evaluate_and_persist_proposal_assurance(
            &queue_proposal_id,
            &paths.evolution_proof_results_dir,
        )?;
        let assurance_decision = assured
            .report
            .assurance
            .as_ref()
            .map(|summary| summary.decision());
        if assurance_decision != Some(EvolutionProposalAssuranceDecision::Passed) {
            let reasons = assured
                .report
                .blocking_reasons
                .iter()
                .filter(|reason| reason.source == "assurance")
                .map(|reason| reason.name.clone())
                .collect::<Vec<_>>();
            let summary = format!(
                "assurance gate blocked the candidate: {}",
                assured
                    .report
                    .blocking_reasons
                    .iter()
                    .filter(|reason| reason.source == "assurance")
                    .map(|reason| reason.details.clone())
                    .collect::<Vec<_>>()
                    .join("; ")
            );
            let _ = mutation.record_population_candidate_review_outcome(
                &paths.evolution_population_results_dir,
                &proposal.strategy_id,
                EvolutionProposalReviewState::Blocked,
                &summary,
                &reasons,
                now_ms(),
            )?;
            self.publish_evolution_status(&config, "assurance_gate_blocked");
            return Ok(StrategyProposalRouteReport {
                strategy_id: proposal.strategy_id,
                outcome: StrategyProposalOutcome::Blocked,
                selection_id: Some(accepted.report.selection_id),
                bridge_id: Some(bridge.report.bridge_id),
                handoff_id: None,
                canary_run_id: None,
            });
        }

        let handoff_harness = DefaultEvolutionHandoffHarness::from_config(
            self.config_path.as_ref().clone(),
            config.clone(),
            &paths.evolution_handoff_results_dir,
        )?;
        let handoff = handoff_harness.create_handoff(
            &paths.evolution_queue_results_dir,
            &queue_proposal_id,
            &paths.shadow_results_dir,
            &validation.report.shadow_id,
        )?;
        let canary_harness = DefaultCanaryHarness::from_config(
            self.config_path.as_ref().clone(),
            config.clone(),
            &paths.canary_results_dir,
        )?;
        let canary = handoff_harness.launch_canary(
            &canary_harness,
            &paths.verification_results_dir,
            &paths.shadow_results_dir,
            &handoff.report.handoff_id,
        )?;
        let _ = mutation.record_population_candidate_review_outcome(
            &paths.evolution_population_results_dir,
            &proposal.strategy_id,
            EvolutionProposalReviewState::AcceptedForCanary,
            "formal safety gate accepted candidate and launched canary admission",
            &Vec::new(),
            now_ms(),
        )?;
        self.publish_evolution_status(&config, "canary_admission_launched");

        Ok(StrategyProposalRouteReport {
            strategy_id: proposal.strategy_id,
            outcome: StrategyProposalOutcome::Accepted,
            selection_id: Some(accepted.report.selection_id),
            bridge_id: Some(bridge.report.bridge_id),
            handoff_id: Some(handoff.report.handoff_id),
            canary_run_id: canary.report.canary_run_id,
        })
    }
}

impl IngestRuntimeStrategyProposalRouter {
    fn publish_evolution_status(&self, config: &SwarmConfig, source: &str) {
        let Some(runtime_events) = &self.runtime_events else {
            return;
        };

        match DefaultEvolutionStatusHarness::from_config(self.config_path.as_ref(), config.clone())
            .and_then(|harness| harness.status())
        {
            Ok(status) => runtime_events.publish(RuntimeEvent::EvolutionStatus {
                emitted_at_ms: now_ms(),
                source: source.to_string(),
                status,
            }),
            Err(error) => tracing::warn!(
                source = %source,
                reason = %error,
                module = module_path!(),
                "failed to publish evolution status event"
            ),
        }
    }
}

// --- Shared helpers used by multiple sub-modules ---

fn sanitize_id(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn operator_secret_material(
    operator: &OperatorSurfaceConfig,
) -> Result<String, IngestRequestError> {
    std::env::var(operator.auth.context_token_env())
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| IngestRequestError::MissingOperatorContextTokenEnv {
            env_name: operator.auth.context_token_env().to_string(),
        })
}

fn merge_context_scope(
    token_scope: ProvidenceContextScope,
    requested_scope: ProvidenceContextScope,
) -> Result<ProvidenceContextScope, IngestRequestError> {
    fn field_matches(
        field: &'static str,
        token_value: Option<&str>,
        requested_value: Option<&str>,
    ) -> Result<Option<String>, IngestRequestError> {
        match (token_value, requested_value) {
            (Some(token), Some(requested)) if token != requested => {
                Err(IngestRequestError::ContextScopeMismatch { field })
            }
            (_, Some(requested)) => Ok(Some(requested.to_string())),
            (Some(token), None) => Ok(Some(token.to_string())),
            (None, None) => Ok(None),
        }
    }

    let threat_class = match (
        token_scope.threat_class.as_ref(),
        requested_scope.threat_class.as_ref(),
    ) {
        (Some(token), Some(requested)) if token != requested => {
            return Err(IngestRequestError::ThreatClassScopeMismatch);
        }
        (_, Some(requested)) => Some(requested.clone()),
        (Some(token), None) => Some(token.clone()),
        (None, None) => None,
    };

    Ok(ProvidenceContextScope {
        incident_id: field_matches(
            "incident_id",
            token_scope.incident_id.as_deref(),
            requested_scope.incident_id.as_deref(),
        )?,
        hunt_id: field_matches(
            "hunt_id",
            token_scope.hunt_id.as_deref(),
            requested_scope.hunt_id.as_deref(),
        )?,
        finding_id: field_matches(
            "finding_id",
            token_scope.finding_id.as_deref(),
            requested_scope.finding_id.as_deref(),
        )?,
        strategy_id: field_matches(
            "strategy_id",
            token_scope.strategy_id.as_deref(),
            requested_scope.strategy_id.as_deref(),
        )?,
        threat_class,
    })
}

fn resolve_demo_scope(
    operator: &OperatorSurfaceConfig,
    query: &DemoScopeQuery,
) -> Result<ProvidenceContextScope, IngestRequestError> {
    let requested_scope = query.raw_scope();
    let Some(raw_token) = query
        .context_token
        .as_deref()
        .filter(|value| !value.is_empty())
    else {
        return Ok(requested_scope);
    };
    let secret_material = operator_secret_material(operator)?;
    let claims = verify_providence_context_token(&secret_material, raw_token, now_ms())
        .map_err(|reason| IngestRequestError::ProvidenceContextToken { reason })?;
    merge_context_scope(claims.scope, requested_scope)
}

fn widget_threat_class_slug(scope: &ProvidenceContextScope) -> Option<String> {
    scope.threat_class.as_ref().map(threat_class_slug)
}

fn filter_concentrations_for_scope(
    concentrations: Vec<RuntimeThreatConcentration>,
    scope: &ProvidenceContextScope,
) -> Vec<RuntimeThreatConcentration> {
    match scope.threat_class.as_ref() {
        Some(threat_class) => concentrations
            .into_iter()
            .filter(|entry| entry.threat_class == *threat_class)
            .collect(),
        None if scope.hunt_id.is_some()
            || scope.incident_id.is_some()
            || scope.finding_id.is_some()
            || scope.strategy_id.is_some() =>
        {
            Vec::new()
        }
        None => concentrations,
    }
}

fn filter_escalations_for_scope(
    escalations: Vec<EscalationRecord>,
    scope: &ProvidenceContextScope,
) -> Vec<EscalationRecord> {
    match scope.threat_class.as_ref() {
        Some(threat_class) => escalations
            .into_iter()
            .filter(|entry| entry.threat_class == *threat_class)
            .collect(),
        None if scope.hunt_id.is_some()
            || scope.incident_id.is_some()
            || scope.finding_id.is_some()
            || scope.strategy_id.is_some() =>
        {
            Vec::new()
        }
        None => escalations,
    }
}

fn runtime_event_matches_scope(event: &RuntimeEvent, scope: &ProvidenceContextScope) -> bool {
    if scope.is_empty() {
        return true;
    }
    match event {
        RuntimeEvent::Finding { finding, .. } => {
            scope
                .finding_id
                .as_deref()
                .is_none_or(|value| finding.finding_id == value)
                && scope
                    .hunt_id
                    .as_deref()
                    .is_none_or(|value| finding.event_id == value)
                && scope
                    .strategy_id
                    .as_deref()
                    .is_none_or(|value| finding.strategy_id == value)
                && scope
                    .threat_class
                    .as_ref()
                    .is_none_or(|value| finding.threat_class == *value)
        }
        RuntimeEvent::AgentAction {
            hunt_id, details, ..
        } => {
            scope
                .hunt_id
                .as_deref()
                .is_none_or(|value| hunt_id.as_deref() == Some(value))
                && !scope.strategy_id.as_deref().is_some_and(|value| {
                    details
                        .get("strategy_id")
                        .and_then(Value::as_str)
                        .map(|candidate| candidate != value)
                        .unwrap_or(true)
                })
        }
        RuntimeEvent::ResponseExecution { hunt_id, .. } => scope
            .hunt_id
            .as_deref()
            .is_none_or(|value| hunt_id == value),
        RuntimeEvent::ConcentrationSnapshot { concentrations, .. } => {
            scope.threat_class.as_ref().is_none_or(|threat_class| {
                concentrations
                    .iter()
                    .any(|entry| entry.threat_class == *threat_class)
            })
        }
        RuntimeEvent::Escalation { threat_class, .. } => scope
            .threat_class
            .as_ref()
            .is_none_or(|value| threat_class == value),
        RuntimeEvent::ModeTransition {
            triggering_threat_class,
            ..
        } => scope
            .threat_class
            .as_ref()
            .is_none_or(|value| triggering_threat_class.as_ref() == Some(value)),
        RuntimeEvent::Replay { event_id, .. } => scope
            .hunt_id
            .as_deref()
            .is_none_or(|value| event_id.as_deref() == Some(value)),
        RuntimeEvent::Ingest { event_id, .. } => scope
            .hunt_id
            .as_deref()
            .is_none_or(|value| event_id == value),
        RuntimeEvent::EvolutionStatus { .. }
        | RuntimeEvent::AgentHealth { .. }
        | RuntimeEvent::TamperAlert { .. } => false,
    }
}

fn filter_runtime_event_for_scope(
    event: RuntimeEvent,
    scope: &ProvidenceContextScope,
) -> Option<RuntimeEvent> {
    if !runtime_event_matches_scope(&event, scope) {
        return None;
    }
    match event {
        RuntimeEvent::ConcentrationSnapshot {
            emitted_at_ms,
            current_mode,
            concentrations,
        } => Some(RuntimeEvent::ConcentrationSnapshot {
            emitted_at_ms,
            current_mode,
            concentrations: filter_concentrations_for_scope(concentrations, scope),
        }),
        other => Some(other),
    }
}

fn widget_embed_headers(
    operator: &OperatorSurfaceConfig,
) -> Result<(HeaderValue, HeaderValue), IngestRequestError> {
    let mut ancestors = vec!["'self'".to_string()];
    let mut external = Vec::new();
    for origin in &operator.allowed_embed_origins {
        let trimmed = origin.trim();
        if trimmed.is_empty() || trimmed == "'self'" {
            continue;
        }
        ancestors.push(trimmed.to_string());
        external.push(trimmed.to_string());
    }
    let csp = HeaderValue::from_str(&format!("frame-ancestors {}", ancestors.join(" ")))?;
    let x_frame_options = if let Some(first_origin) = external.first() {
        HeaderValue::from_str(&format!("ALLOW-FROM {first_origin}"))?
    } else {
        HeaderValue::from_static("SAMEORIGIN")
    };
    Ok((csp, x_frame_options))
}

fn with_widget_headers(response: Response, operator: &OperatorSurfaceConfig) -> Response {
    match widget_embed_headers(operator) {
        Ok((csp, x_frame_options)) => {
            let mut response = response;
            let headers = response.headers_mut();
            headers.insert(header::CONTENT_SECURITY_POLICY, csp);
            headers.insert(header::X_FRAME_OPTIONS, x_frame_options);
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(_) => response,
    }
}

fn resolve_repo_relative_path_local(config_path: &Path, referenced: &str) -> PathBuf {
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

fn resolve_strategy_proposal_paths(
    config_path: &Path,
    config: &SwarmConfig,
) -> StrategyProposalPaths {
    let paths = &config.evolution.paths;
    StrategyProposalPaths {
        verification_results_dir: resolve_repo_relative_path_local(
            config_path,
            &paths.verification_results_dir,
        ),
        shadow_results_dir: resolve_repo_relative_path_local(
            config_path,
            &paths.shadow_results_dir,
        ),
        evolution_proof_results_dir: resolve_repo_relative_path_local(
            config_path,
            &paths.evolution_proof_results_dir,
        ),
        evolution_queue_results_dir: resolve_repo_relative_path_local(
            config_path,
            &paths.evolution_queue_results_dir,
        ),
        evolution_selection_results_dir: resolve_repo_relative_path_local(
            config_path,
            &paths.evolution_selection_results_dir,
        ),
        evolution_bridge_results_dir: resolve_repo_relative_path_local(
            config_path,
            &paths.evolution_bridge_results_dir,
        ),
        evolution_handoff_results_dir: resolve_repo_relative_path_local(
            config_path,
            &paths.evolution_handoff_results_dir,
        ),
        evolution_pressure_results_dir: resolve_repo_relative_path_local(
            config_path,
            &paths.evolution_pressure_results_dir,
        ),
        evolution_draft_results_dir: resolve_repo_relative_path_local(
            config_path,
            &paths.evolution_draft_results_dir,
        ),
        evolution_draft_promotion_results_dir: resolve_repo_relative_path_local(
            config_path,
            &paths.evolution_draft_promotion_results_dir,
        ),
        evolution_materialization_results_dir: resolve_repo_relative_path_local(
            config_path,
            &paths.evolution_materialization_results_dir,
        ),
        evolution_validation_results_dir: resolve_repo_relative_path_local(
            config_path,
            &paths.evolution_validation_results_dir,
        ),
        evolution_reconciliation_results_dir: resolve_repo_relative_path_local(
            config_path,
            &paths.evolution_reconciliation_results_dir,
        ),
        evolution_mutation_results_dir: resolve_repo_relative_path_local(
            config_path,
            &paths.evolution_mutation_results_dir,
        ),
        evolution_mutation_materialization_batch_results_dir: resolve_repo_relative_path_local(
            config_path,
            &paths.evolution_mutation_materialization_batch_results_dir,
        ),
        evolution_mutation_validation_batch_results_dir: resolve_repo_relative_path_local(
            config_path,
            &paths.evolution_mutation_validation_batch_results_dir,
        ),
        evolution_ranking_results_dir: resolve_repo_relative_path_local(
            config_path,
            &paths.evolution_ranking_results_dir,
        ),
        evolution_population_results_dir: resolve_repo_relative_path_local(
            config_path,
            &paths.evolution_population_results_dir,
        ),
        canary_results_dir: resolve_repo_relative_path_local(
            config_path,
            &paths.canary_results_dir,
        ),
    }
}

fn safety_rejection_summary(
    report: &swarm_runtime::evolution::FormalSafetyVerificationReport,
) -> String {
    let reasons = report
        .invariants
        .iter()
        .filter(|invariant| !invariant.passed())
        .map(|invariant| {
            let counterexamples = invariant
                .counterexamples
                .iter()
                .take(2)
                .map(|counterexample| {
                    format!("{} ({})", counterexample.subject, counterexample.details)
                })
                .collect::<Vec<_>>();
            if counterexamples.is_empty() {
                format!("{}: {}", invariant.name, invariant.details)
            } else {
                format!(
                    "{}: {} [{}]",
                    invariant.name,
                    invariant.details,
                    counterexamples.join("; ")
                )
            }
        })
        .collect::<Vec<_>>();
    format!(
        "formal safety gate rejected candidate: {}",
        reasons.join(" | ")
    )
}

fn attach_formal_safety_bundle_hashes(
    config_path: &Path,
    config: &SwarmConfig,
    proof_results_dir: &Path,
    proof_id: Option<&str>,
    bundle_sha256: &[String],
) -> Result<(), swarm_runtime::evolution::EvolutionQueueError> {
    let Some(proof_id) = proof_id else {
        return Ok(());
    };
    let proof_harness = DefaultEvolutionProofHarness::from_config(
        config_path.to_path_buf(),
        config.clone(),
        proof_results_dir,
    )?;
    let Some(mut lookup) = proof_harness.load_proof(proof_id)? else {
        return Ok(());
    };
    lookup.report.formal_safety_bundle_sha256 = bundle_sha256.to_vec();
    proof_harness.store.persist(&lookup.report)?;
    Ok(())
}

fn threat_class_slug(threat_class: &ThreatClass) -> String {
    serde_json::to_value(threat_class)
        .ok()
        .and_then(|value| value.as_str().map(ToString::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn unix_timestamp_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

fn event_id_from_raw(value: &Value) -> Option<String> {
    value
        .get("event_id")
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn strategy_status_label(config: &SwarmConfig) -> String {
    config.detection.active_strategies().join(", ")
}

fn routed_detection_from_request(request: &ActionRequest) -> DetectionFinding {
    let event_id = request
        .evidence
        .get("lineage")
        .and_then(|value| value.get("event_id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or(request.hunt_id.0.as_str())
        .to_string();
    let threat_class = request
        .evidence
        .get("escalation")
        .and_then(|value| value.get("threat_class"))
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or(ThreatClass::Execution);
    let severity = request
        .evidence
        .get("escalation")
        .and_then(|value| value.get("severity"))
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or(request.severity);
    let confidence = request
        .evidence
        .get("escalation")
        .and_then(|value| value.get("confidence"))
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(1.0);

    DetectionFinding {
        finding_id: format!("pounceagent:{event_id}"),
        event_id,
        threat_class,
        severity,
        confidence,
        evidence: request.evidence.clone(),
        strategy_id: "pounce_agent".to_string(),
    }
}

async fn process_runtime_event(
    state: &IngestState,
    requested_by: &AgentId,
    correlation_id: &str,
    event: TelemetryEvent,
) -> Result<(), IngestProcessingError> {
    let observed_now_ms = now_ms();
    if let Err(error) = validate_live_event_timestamp(event.timestamp, observed_now_ms) {
        let reason = error.to_string();
        state.publish_runtime_event(RuntimeEvent::Ingest {
            emitted_at_ms: observed_now_ms,
            correlation_id: correlation_id.to_string(),
            event_id: event.event_id.clone(),
            source: event.source.clone(),
            host_id: event.host_id.clone(),
            accepted: false,
            reason: Some(reason),
        });
        return Err(error);
    }
    let trace_id = correlation_id.to_string();
    let span = tracing::info_span!(
        "ingest.process_runtime_event",
        trace_id = %trace_id,
        event_id = %event.event_id,
        requested_by = %requested_by.0
    );

    let degradation = state.current_runtime_degradation().await;
    swarm_core::observability::with_trace_id(
        trace_id,
        async {
            let live_mode = state.stack.load_full().service.mode() == RuntimeMode::LiveResponse
                && degradation.capabilities.allows_live_response;
            let approval = ApprovalContext {
                live_mode,
                receipt_chain: Vec::new(),
                correlation_id: Some(correlation_id.to_string()),
                now_ms: observed_now_ms,
            };
            let signing_agent_id = AgentId::from_verifying_key(&state.signing_key.verifying_key());
            let stack = state.stack.load_full();
            let detector = state.detector.load_full();
            let swarm_mode = state.current_mode_state().current;
            match stack
                .process_event_with_finding_observer(
                    detector.as_ref(),
                    &event,
                    swarm_runtime::service::EventExecutionContext {
                        agent_id: &signing_agent_id,
                        approval: &approval,
                        signing_key: &state.signing_key,
                    },
                    |finding| {
                        if live_mode {
                            stack
                                .service
                                .playbook_action_for_finding(finding, swarm_mode)
                                .filter(|action| !action.requires_governance_receipt())
                        } else {
                            None
                        }
                    },
                    |event, findings| publish_runtime_findings(state, event, findings),
                )
                .await
            {
                Ok(_) => {
                    if let Some(tx) = &state.telemetry_tx {
                        match tx.try_send(event.clone()) {
                            Ok(()) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                tracing::warn!(
                                    correlation_id = %correlation_id,
                                    event_id = %event.event_id,
                                    module = module_path!(),
                                    "telemetry buffer full; skipping agent dispatch copy"
                                );
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                tracing::warn!(
                                    correlation_id = %correlation_id,
                                    event_id = %event.event_id,
                                    module = module_path!(),
                                    "telemetry buffer closed; skipping agent dispatch copy"
                                );
                            }
                        }
                    }
                    state.publish_runtime_event(RuntimeEvent::Ingest {
                        emitted_at_ms: now_ms(),
                        correlation_id: correlation_id.to_string(),
                        event_id: event.event_id.clone(),
                        source: event.source.clone(),
                        host_id: event.host_id.clone(),
                        accepted: true,
                        reason: None,
                    });
                    Ok(())
                }
                Err(error) => {
                    let reason = error.to_string();
                    state.publish_runtime_event(RuntimeEvent::Ingest {
                        emitted_at_ms: now_ms(),
                        correlation_id: correlation_id.to_string(),
                        event_id: event.event_id.clone(),
                        source: event.source.clone(),
                        host_id: event.host_id.clone(),
                        accepted: false,
                        reason: Some(reason.clone()),
                    });
                    Err(error.into())
                }
            }
        }
        .instrument(span),
    )
    .await
}

fn response_receipt_details(audit: &AuditTrail) -> (Option<String>, Option<String>) {
    match &audit.response {
        AuditResponseRecord::Success(receipt) => (Some(receipt.receipt_id.clone()), None),
        AuditResponseRecord::Failure(failure) => (
            Some(failure.receipt_id.clone()),
            Some(failure.message.clone()),
        ),
        AuditResponseRecord::Skipped { .. } | AuditResponseRecord::GuardRejected { .. } => {
            (None, None)
        }
    }
}

async fn process_demo_replay_step(
    state: &IngestState,
    run_id: &str,
    requested_by: &AgentId,
    step_index: usize,
    step: swarm_runtime::replay::ReplayScenarioStep,
) -> Result<(), IngestProcessingError> {
    let stack = state.stack.load_full();
    let approval = ApprovalContext {
        live_mode: stack.service.mode() == RuntimeMode::LiveResponse,
        receipt_chain: Vec::new(),
        correlation_id: Some(run_id.to_string()),
        // Demo replay re-evaluates historical scenarios at the recorded event
        // time so approval correlation stays deterministic across re-runs.
        // Live ingest uses wall-clock `now_ms()` in `process_runtime_event`.
        now_ms: step.event.timestamp,
    };
    let replay_action = step.action.clone();
    let live_governed_action = stack.service.mode() == RuntimeMode::LiveResponse
        && replay_action.requires_governance_receipt();
    let signing_agent_id = AgentId::from_verifying_key(&state.signing_key.verifying_key());
    let detector = state.detector.load_full();
    let outcome = stack
        .process_event_with_finding_observer(
            detector.as_ref(),
            &step.event,
            swarm_runtime::service::EventExecutionContext {
                agent_id: &signing_agent_id,
                approval: &approval,
                signing_key: &state.signing_key,
            },
            |_| {
                if live_governed_action {
                    None
                } else {
                    Some(replay_action.clone())
                }
            },
            |event, findings| publish_runtime_findings(state, event, findings),
        )
        .await?;

    state.publish_runtime_event(RuntimeEvent::Ingest {
        emitted_at_ms: now_ms(),
        correlation_id: run_id.to_string(),
        event_id: step.event.event_id.clone(),
        source: step.event.source.clone(),
        host_id: step.event.host_id.clone(),
        accepted: true,
        reason: None,
    });

    let Some(bundle) = outcome else {
        state.append_demo_timeline(
            run_id,
            if live_governed_action {
                "governance_deferred"
            } else {
                "replay_step_without_findings"
            },
            json!({
                "step_index": step_index,
                "event_id": step.event.event_id,
                "action_kind": step.action.kind(),
                "reason": live_governed_action.then_some(
                    "live governed actions require Pouncer issuance and dispatcher admission; human approval alone cannot authorize execution"
                ),
            }),
            now_ms(),
        );
        return Ok(());
    };

    let audit = bundle.replay.bundle.audit.clone();
    let action_request = bundle.replay.bundle.action_request.clone();
    let (receipt_id, response_error) = response_receipt_details(&audit);
    state.publish_runtime_event(RuntimeEvent::ResponseExecution {
        emitted_at_ms: now_ms(),
        agent_id: requested_by.to_string(),
        hunt_id: audit.hunt_id.clone(),
        action_kind: action_request.action.kind().to_string(),
        response_kind: audit.response_kind().to_string(),
        policy_verdict: audit.policy.verdict,
        rule_name: audit.policy.rule_name.clone(),
        reason: audit.policy.reason.clone(),
        receipt_id,
        governing_agent_id: None,
        error: response_error,
    });
    state.append_demo_timeline(
        run_id,
        "replay_step_decision",
        json!({
            "step_index": step_index,
            "event_id": bundle.replay.bundle.event.event_id,
            "action_kind": action_request.action.kind(),
            "policy_verdict": audit.policy.verdict,
            "response_kind": audit.response_kind(),
            "investigation_id": bundle
                .investigation
                .as_ref()
                .map(|record| record.investigation_id.clone()),
            "response_receipt_id": audit.response_receipt_id(),
        }),
        audit.created_at_ms,
    );

    if let Some(outcome) = stack.correlate_hunt(&bundle.replay.bundle.action_request.hunt_id.0)? {
        state.update_demo_incident(run_id, outcome.incident.clone());
        state.append_demo_timeline(
            run_id,
            "incident_correlated",
            json!({
                "incident_id": outcome.record.incident_id,
                "hunt_id": bundle.replay.bundle.action_request.hunt_id.0,
                "included_hunt_ids": outcome.record.included_hunt_ids,
            }),
            outcome.incident.created_at_ms,
        );
    }

    if matches!(
        audit.policy.verdict,
        swarm_policy::PolicyVerdict::RequireHuman
    ) && matches!(audit.response, AuditResponseRecord::Skipped { .. })
    {
        state.register_pending_demo_approval(run_id, step_index, &action_request, &audit)?;
    }

    Ok(())
}

// --- Public types ---

#[derive(Debug, thiserror::Error)]
pub enum IngestBuildError {
    #[error(transparent)]
    Control(#[from] ControlError),

    #[error(transparent)]
    Service(#[from] ServiceError),

    #[error(transparent)]
    Config(#[from] RuntimeConfigError),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum IngestRequestError {
    #[error(transparent)]
    InvalidPayload(#[from] serde_json::Error),

    #[error("operator surface context token env `{env_name}` is missing or empty")]
    MissingOperatorContextTokenEnv { env_name: String },

    #[error("requested `{field}` does not match token scope")]
    ContextScopeMismatch { field: &'static str },

    #[error("requested `threat_class` does not match token scope")]
    ThreatClassScopeMismatch,

    #[error("{reason}")]
    ProvidenceContextToken { reason: String },

    #[error(transparent)]
    InvalidHeaderValue(#[from] axum::http::header::InvalidHeaderValue),
}

#[derive(Debug, thiserror::Error)]
enum DemoApprovalError {
    #[error(transparent)]
    Approval(#[from] ApprovalError),

    #[error("demo approval harness is not configured")]
    HarnessNotConfigured,

    #[error("approval set `{set_id}` was created without an associated ledger")]
    MissingLedger { set_id: String },

    #[error("demo run `{run_id}` was not found")]
    RunNotFound { run_id: String },

    #[error("demo run `{run_id}` does not contain approval `{approval_set_id}`")]
    ApprovalNotFound {
        run_id: String,
        approval_set_id: String,
    },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
enum ApprovalVoterConfigError {
    #[error(
        "governed approvals require at least one eligible approve principal with a canonical swarm:ed25519 public-key identity"
    )]
    NoEligibleApprover,
}

/// Resolve the effective, signable principals that may vote on a governed hold.
/// An explicit principal list never falls back to the legacy operator ID.
fn configured_approval_voters(
    config: &SwarmConfig,
) -> Result<Vec<String>, ApprovalVoterConfigError> {
    let voters = config
        .operator
        .auth
        .effective_principals()
        .into_iter()
        .filter(|principal| principal.scopes.contains(&OperatorScope::Approve))
        .filter_map(|principal| canonical_approval_voter_id(&principal.operator_id))
        .collect::<BTreeSet<_>>();

    if voters.is_empty() {
        return Err(ApprovalVoterConfigError::NoEligibleApprover);
    }
    Ok(voters.into_iter().collect())
}

fn canonical_approval_voter_id(operator_id: &str) -> Option<String> {
    const PREFIX: &str = "swarm:ed25519:";

    let public_key_hex = operator_id.strip_prefix(PREFIX)?;
    if public_key_hex.len() != 64
        || !public_key_hex
            .chars()
            .all(|character| character.is_ascii_hexdigit())
        || public_key_hex
            .chars()
            .any(|character| character.is_ascii_uppercase())
    {
        return None;
    }
    let public_key = swarm_crypto::PublicKey::from_hex(public_key_hex).ok()?;
    let canonical = format!("{PREFIX}{}", public_key.to_hex());
    (operator_id == canonical).then_some(canonical)
}

#[derive(Debug, thiserror::Error)]
enum IngestProcessingError {
    #[error("event timestamp {timestamp} must be a nonnegative Unix timestamp")]
    InvalidEventTimestamp { timestamp: i64 },

    #[error(
        "event timestamp {timestamp} normalizes to {normalized_timestamp_ms}ms, beyond the trusted ingest ceiling {maximum_timestamp_ms}ms"
    )]
    FutureEventTimestamp {
        timestamp: i64,
        normalized_timestamp_ms: i64,
        maximum_timestamp_ms: i64,
    },

    #[error(transparent)]
    Service(#[from] ServiceError),

    #[error(transparent)]
    DemoApproval(#[from] DemoApprovalError),
}

impl IngestProcessingError {
    fn is_event_rejection(&self) -> bool {
        matches!(
            self,
            Self::InvalidEventTimestamp { .. } | Self::FutureEventTimestamp { .. }
        )
    }
}

fn normalized_ingest_timestamp_ms(timestamp: i64) -> Result<i64, IngestProcessingError> {
    if timestamp < 0 {
        return Err(IngestProcessingError::InvalidEventTimestamp { timestamp });
    }
    if timestamp < TIMESTAMP_MILLISECONDS_CUTOFF {
        timestamp
            .checked_mul(1_000)
            .ok_or(IngestProcessingError::InvalidEventTimestamp { timestamp })
    } else {
        Ok(timestamp)
    }
}

fn validate_live_event_timestamp(
    timestamp: i64,
    observed_now_ms: i64,
) -> Result<(), IngestProcessingError> {
    let normalized_timestamp_ms = normalized_ingest_timestamp_ms(timestamp)?;
    let maximum_timestamp_ms = observed_now_ms.saturating_add(MAX_INGEST_FUTURE_SKEW_MS);
    if normalized_timestamp_ms > maximum_timestamp_ms {
        return Err(IngestProcessingError::FutureEventTimestamp {
            timestamp,
            normalized_timestamp_ms,
            maximum_timestamp_ms,
        });
    }
    Ok(())
}

#[derive(Clone)]
pub struct IngestState {
    stack: Arc<ArcSwap<IngestRuntimeStack>>,
    platform_api_auth: Arc<ArcSwap<crate::ingest::platform_api::PlatformApiAuthState>>,
    platform_api_rate_limiter: HttpRateLimiter,
    request_runtime: Arc<ArcSwap<IngestRequestRuntime>>,
    detector: Arc<ArcSwap<CompositeDetector>>,
    detector_status: Arc<ArcSwap<DetectorRuntimeStatus>>,
    config_path: Arc<PathBuf>,
    config_template: Arc<ArcSwap<SwarmConfig>>,
    lifecycle: Arc<IngestLifecycleState>,
    telemetry_tx: Option<tokio::sync::mpsc::Sender<TelemetryEvent>>,
    agent_dispatcher_health: Option<Arc<ArcSwap<Vec<AgentHealthEntry>>>>,
    mode_state: Option<Arc<ArcSwap<SwarmModeState>>>,
    bridge_health: Option<SharedBridgeHealth>,
    threat_intel_feed_health: Option<SharedThreatIntelFeedHealth>,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    heap_snapshot_provider: HeapSnapshotProvider,
    signing_key: ed25519_dalek::SigningKey,
    runtime_events: Option<RuntimeEventBroadcaster>,
    approval_harness: Option<Arc<DefaultApprovalHarness>>,
    demo_runs: Arc<Mutex<DemoRunRegistry>>,
    providence_adapter: Arc<ArcSwap<Option<Arc<ProvidenceIncidentAdapter>>>>,
    providence_task_started: Arc<AtomicBool>,
    governance_authority: Option<GovernanceAuthority>,
    startup_attestation: Option<Arc<StartupAttestationReport>>,
    anti_tamper_report: Arc<ArcSwap<AntiTamperReport>>,
    runtime_degradation: Arc<ArcSwap<RuntimeDegradationStatus>>,
}

impl IngestState {
    fn build_runtime(config: SwarmConfig) -> Result<IngestBuiltRuntime, IngestBuildError> {
        let detector = Arc::new(build_composite_detector(&config.detection)?);
        let stack = Arc::new(ConfiguredRuntimeStack::from_config(
            config,
            SummaryInvestigator,
        )?);
        let request_runtime = stack.service.shared_runtime();
        Ok((stack, request_runtime, detector))
    }

    pub fn from_config(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
    ) -> Result<Self, IngestBuildError> {
        Self::from_config_with_signing_key(
            config_path,
            config,
            ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng),
        )
    }

    pub fn from_config_with_signing_key(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
        signing_key: ed25519_dalek::SigningKey,
    ) -> Result<Self, IngestBuildError> {
        let config_path = config_path.into();
        let template = config.clone();
        let configured_mode = template.runtime.mode;
        let resolved = resolve_outbound_secrets(config, Some(&config_path)).map_err(|source| {
            RuntimeConfigError::Validation {
                source_name: config_path.display().to_string(),
                source,
            }
        })?;
        let providence_adapter = resolved
            .notification_channels
            .get(PROVIDENCE_CHANNEL)
            .cloned()
            .map(|channel| {
                ProvidenceIncidentAdapter::new(channel, resolved.runtime.max_dead_letter_bytes)
            })
            .transpose()?
            .map(Arc::new);
        let strategy = strategy_status_label(&resolved);
        let (stack, request_runtime, detector) = Self::build_runtime(resolved)?;
        let detector_status = Arc::new(ArcSwap::from(Arc::new(DetectorRuntimeStatus::loaded(
            strategy,
        ))));
        let initial_platform_auth = crate::ingest::platform_api::PlatformApiAuthState::from_config(
            &template.platform_api,
            &template.operator,
        );
        let state = Self {
            stack: Arc::new(ArcSwap::from(stack)),
            platform_api_auth: Arc::new(ArcSwap::from_pointee(initial_platform_auth)),
            platform_api_rate_limiter: HttpRateLimiter::new(
                "platform_api",
                template.platform_api.rate_limit.clone(),
            ),
            request_runtime: Arc::new(ArcSwap::from(request_runtime)),
            detector: Arc::new(ArcSwap::from(detector)),
            detector_status,
            config_path: Arc::new(config_path),
            config_template: Arc::new(ArcSwap::from(Arc::new(template))),
            lifecycle: Arc::new(IngestLifecycleState::default()),
            telemetry_tx: None,
            agent_dispatcher_health: None,
            mode_state: None,
            bridge_health: None,
            threat_intel_feed_health: None,
            shutdown_tx: None,
            heap_snapshot_provider: Arc::new(sample_heap_pressure),
            signing_key,
            runtime_events: None,
            approval_harness: None,
            demo_runs: Arc::new(Mutex::new(DemoRunRegistry::default())),
            providence_adapter: Arc::new(ArcSwap::from_pointee(providence_adapter)),
            providence_task_started: Arc::new(AtomicBool::new(false)),
            governance_authority: None,
            startup_attestation: None,
            anti_tamper_report: Arc::new(ArcSwap::from_pointee(AntiTamperReport::disabled())),
            runtime_degradation: Arc::new(ArcSwap::from_pointee(
                derive_runtime_degradation_status(RuntimeDegradationSignals {
                    configured_mode,
                    detector_ready: true,
                    substrate_ready: true,
                    replay_store_ready: true,
                    startup_attestation_ready: true,
                    anti_tamper_ready: true,
                    heap_ready: true,
                    draining: false,
                    degraded_agents: 0,
                    failed_agents: 0,
                    transitioned_at_ms: now_ms(),
                }),
            )),
        };
        state.install_notification_payload_builder();
        Ok(state)
    }

    pub fn from_path(config_path: impl Into<PathBuf>) -> Result<Self, IngestBuildError> {
        let config_path = config_path.into();
        let config = load_config_unresolved(&config_path)?;
        Self::from_config(config_path, config)
    }

    pub fn reload(&self, config: SwarmConfig) -> Result<(), IngestBuildError> {
        let strategy = strategy_status_label(&config);
        let platform_rate_limit = config.platform_api.rate_limit.clone();
        let new_platform_auth = crate::ingest::platform_api::PlatformApiAuthState::from_config(
            &config.platform_api,
            &config.operator,
        );
        let new_providence_adapter = config
            .notification_channels
            .get(PROVIDENCE_CHANNEL)
            .cloned()
            .map(|channel| {
                ProvidenceIncidentAdapter::new(channel, config.runtime.max_dead_letter_bytes)
            })
            .transpose()?
            .map(Arc::new);
        match Self::build_runtime(config) {
            Ok((stack, request_runtime, detector)) => {
                // Reload is not atomic across the ArcSwap stores. Storing auth and
                // rate-limit thresholds first prioritizes revocation: a request
                // arriving after this point cannot authenticate against revoked keys
                // even if it would still be served by the OLD detector. The remaining
                // race (a request that read OLD auth before the swap and then sees
                // NEW stack on dispatch) is accepted; both halves are valid snapshots
                // and the platform API is read-only.
                self.platform_api_auth.store(Arc::new(new_platform_auth));
                self.platform_api_rate_limiter
                    .update_config(platform_rate_limit);
                self.providence_adapter
                    .store(Arc::new(new_providence_adapter));
                self.detector.store(detector);
                self.request_runtime.store(request_runtime);
                self.stack.store(stack);
                self.detector_status
                    .store(Arc::new(DetectorRuntimeStatus::loaded(strategy)));
                self.install_notification_payload_builder();
                Ok(())
            }
            Err(error) => {
                let current = self.detector_status.load_full();
                self.detector_status
                    .store(Arc::new(DetectorRuntimeStatus::reload_failed(
                        current.strategy.clone(),
                        &error,
                    )));
                Err(error)
            }
        }
    }

    pub fn reload_secrets_only(&self) -> Result<(), IngestBuildError> {
        let template = self.config_template.load_full();
        let config = resolve_outbound_secrets(template.as_ref().clone(), Some(self.config_path()))
            .map_err(|source| RuntimeConfigError::Validation {
                source_name: self.config_path().display().to_string(),
                source,
            })?;

        self.reload(config)?;

        tracing::info!(
            module = module_path!(),
            "reloaded secrets without full config reload"
        );
        Ok(())
    }

    pub fn reload_from_disk(&self) -> Result<(), IngestBuildError> {
        let template = match load_config_unresolved(self.config_path()) {
            Ok(config) => config,
            Err(error) => {
                let current = self.detector_status.load_full();
                self.detector_status
                    .store(Arc::new(DetectorRuntimeStatus::reload_failed(
                        current.strategy.clone(),
                        &error,
                    )));
                return Err(error.into());
            }
        };
        let resolved = resolve_outbound_secrets(template.clone(), Some(self.config_path()))
            .map_err(|source| RuntimeConfigError::Validation {
                source_name: self.config_path().display().to_string(),
                source,
            })?;
        self.config_template.store(Arc::new(template));
        self.reload(resolved)
    }

    pub fn config_path(&self) -> &Path {
        self.config_path.as_ref().as_path()
    }

    fn install_notification_payload_builder(&self) {
        let stack = self.stack.load_full();
        let Some(router) = stack.service.notification_router().cloned() else {
            return;
        };
        let operator = stack.service.config.operator.clone();
        let agent_health = self.agent_dispatcher_health.clone();
        let mode_state = self.mode_state.clone();
        let bridge_health = self.bridge_health.clone();
        router.set_payload_builder(move |channel, aggregate| {
            (channel == "providence_webhook").then(|| {
                build_providence_notification_payload(
                    aggregate,
                    &operator,
                    agent_health.as_ref(),
                    mode_state.as_ref(),
                    bridge_health.as_ref(),
                )
            })
        });
    }

    fn maybe_start_providence_sync_task(&self) {
        let Some(mode_state) = self.mode_state.clone() else {
            return;
        };
        let Some(shutdown_tx) = self.shutdown_tx.clone() else {
            return;
        };
        if self
            .providence_task_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        let stack = Arc::clone(&self.stack);
        let providence_adapter = Arc::clone(&self.providence_adapter);
        let agent_health = self.agent_dispatcher_health.clone();
        let bridge_health = self.bridge_health.clone();
        tokio::spawn(async move {
            let mut shutdown = shutdown_tx.subscribe();
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                    _ = interval.tick() => {
                        // Load the adapter from the live ArcSwap each tick so reload
                        // additions/rotations of `providence_webhook` propagate without
                        // restarting the task; skip the tick when Providence is not
                        // currently configured.
                        let Some(adapter) =
                            providence_adapter.load_full().as_ref().clone()
                        else {
                            continue;
                        };
                        let stack = stack.load_full();
                        let runtime = ProvidenceRuntimeContext {
                            operator: stack.service.config.operator.clone(),
                            mode_state: mode_state.load_full().as_ref().clone(),
                            agent_health: agent_health
                                .as_ref()
                                .map(|health| health.load_full().as_ref().clone())
                                .unwrap_or_default(),
                            bridge_health: bridge_health
                                .as_ref()
                                .map(bridge_health_report)
                                .unwrap_or_default(),
                        };
                        if let Err(error) = adapter
                            .sync_incidents(
                                &stack.incident_store,
                                &runtime,
                                stack.service.config.audit.recent_decisions_limit.max(32),
                            )
                            .await
                        {
                            tracing::warn!(reason = %error, "Providence incident sync degraded");
                        }
                    }
                }
            }
        });
    }

    pub fn with_telemetry_channel(mut self, tx: tokio::sync::mpsc::Sender<TelemetryEvent>) -> Self {
        self.telemetry_tx = Some(tx);
        self
    }

    pub fn with_agent_health(mut self, health: Arc<ArcSwap<Vec<AgentHealthEntry>>>) -> Self {
        self.agent_dispatcher_health = Some(health);
        self.install_notification_payload_builder();
        self
    }

    pub fn with_mode_state(mut self, mode_state: Arc<ArcSwap<SwarmModeState>>) -> Self {
        self.mode_state = Some(mode_state);
        self.install_notification_payload_builder();
        self.maybe_start_providence_sync_task();
        self
    }

    pub fn with_bridge_health(mut self, health: SharedBridgeHealth) -> Self {
        self.bridge_health = Some(health);
        self.install_notification_payload_builder();
        self
    }

    pub fn with_threat_intel_feed_health(mut self, health: SharedThreatIntelFeedHealth) -> Self {
        self.threat_intel_feed_health = Some(health);
        self
    }

    pub fn with_shutdown_channel(mut self, tx: tokio::sync::watch::Sender<bool>) -> Self {
        self.shutdown_tx = Some(tx);
        self.maybe_start_providence_sync_task();
        self
    }

    pub fn with_runtime_events(mut self, runtime_events: RuntimeEventBroadcaster) -> Self {
        self.runtime_events = Some(runtime_events);
        self
    }

    /// Install the governance authority whose quorum health `/healthz` reports.
    ///
    /// Install the concrete opaque authority minted by an authenticated persisted
    /// governance policy. There is no generic backend installation surface.
    pub fn with_governance_authority(mut self, governance_authority: GovernanceAuthority) -> Self {
        self.governance_authority = Some(governance_authority);
        self
    }

    /// Process-local identity of the configured authority, for composition checks.
    ///
    /// This exposes no authority reference and cannot authorize an action.
    pub fn governance_authority_identity(
        &self,
    ) -> Option<swarm_governance::GovernanceAuthorityIdentity> {
        self.governance_authority
            .as_ref()
            .map(GovernanceAuthority::identity)
    }

    pub(crate) fn human_approval_resume_dispatcher(
        &self,
    ) -> Option<swarm_runtime::dispatcher::HumanApprovalResumeDispatcher> {
        let governance = self.governance_authority.clone()?;
        let eligible_voters =
            configured_approval_voters(&self.stack.load_full().service.config).ok()?;
        Some(
            swarm_runtime::dispatcher::HumanApprovalResumeDispatcher::new(
                governance,
                self.current_request_response_router(),
                eligible_voters,
                ThresholdRule::AtLeast { required: 1 },
            ),
        )
    }

    /// Process-local identity used by shipped composition tests to prove that
    /// the real human-resume dispatcher receives the configured authority.
    pub fn human_resume_governance_authority_identity(
        &self,
    ) -> Option<swarm_governance::GovernanceAuthorityIdentity> {
        self.human_approval_resume_dispatcher()
            .map(|dispatcher| dispatcher.governance_authority_identity())
    }

    pub fn with_startup_attestation(mut self, report: StartupAttestationReport) -> Self {
        self.startup_attestation = Some(Arc::new(report));
        self
    }

    pub fn with_anti_tamper_report(self, report: AntiTamperReport) -> Self {
        self.anti_tamper_report.store(Arc::new(report));
        self
    }

    pub fn with_approval_harness(mut self, approval_harness: DefaultApprovalHarness) -> Self {
        self.approval_harness = Some(Arc::new(approval_harness));
        self
    }

    #[cfg(test)]
    fn with_heap_snapshot_provider<F>(mut self, provider: F) -> Self
    where
        F: Fn() -> Option<HeapPressureSnapshot> + Send + Sync + 'static,
    {
        self.heap_snapshot_provider = Arc::new(provider);
        self
    }

    pub fn current_detector(&self) -> Arc<CompositeDetector> {
        self.detector.load_full()
    }

    pub fn current_substrate(&self) -> swarm_pheromone::ConfiguredPheromoneSubstrate {
        self.stack.load_full().substrate.clone()
    }

    pub fn current_pheromone_config(&self) -> swarm_core::config::PheromoneConfig {
        self.stack.load_full().service.config.pheromone.clone()
    }

    /// The lease store the CURRENT runtime writes containment leases to.
    ///
    /// Must be read from the runtime rather than rebuilt from config: for an
    /// in-memory store a second instance is a different map, so a sweep built
    /// beside the runtime would find nothing and silently release nothing.
    ///
    /// KNOWN LIMITATION, and it is the in-memory case only. `stack` is an
    /// `ArcSwap`, so `reload_from_disk()` replaces the runtime and with it the
    /// store. A file-backed store reopens the same document and loses nothing; an
    /// in-memory one starts empty, so any containment open at reload time is
    /// orphaned and no sweep will ever release it. That is one of the reasons
    /// `docs/CONFIGURATION.md` tells a `live_response` deployment to configure
    /// `runtime.containment.lease_store_path`.
    pub fn current_containment_store(
        &self,
    ) -> Option<Arc<dyn swarm_response::containment::ContainmentLeaseStore>> {
        self.stack
            .load_full()
            .service
            .runtime
            .containment_store()
            .cloned()
    }

    /// Whether the current runtime enforces or simulates. The sweep needs this
    /// so a `detect_only` daemon never issues a real inverse.
    pub fn current_execution_mode(&self) -> swarm_response::ExecutionMode {
        match self.stack.load_full().service.config.runtime.mode {
            swarm_core::config::RuntimeMode::DetectOnly => swarm_response::ExecutionMode::DryRun,
            swarm_core::config::RuntimeMode::LiveResponse => {
                swarm_response::ExecutionMode::Enforced
            }
        }
    }

    /// Containment bounds from the current config.
    pub fn current_containment_settings(&self) -> swarm_core::config::ContainmentSettings {
        self.stack
            .load_full()
            .service
            .config
            .runtime
            .containment
            .clone()
    }

    pub fn current_response_adapter_config(&self) -> ResponseAdapterConfig {
        self.stack
            .load_full()
            .service
            .config
            .response_adapter
            .clone()
    }

    pub fn current_request_response_router(&self) -> Arc<dyn RequestResponseRouter> {
        Arc::new(IngestRuntimeRequestResponseRouter {
            stack: Arc::clone(&self.stack),
            runtime: Arc::clone(&self.request_runtime),
            approval_harness: self.approval_harness.clone(),
        })
    }

    pub fn current_strategy_proposal_router(&self) -> Arc<dyn StrategyProposalRouter> {
        Arc::new(IngestRuntimeStrategyProposalRouter {
            stack: Arc::clone(&self.stack),
            config_path: Arc::clone(&self.config_path),
            signing_key: self.signing_key.clone(),
            runtime_events: self.runtime_events.clone(),
        })
    }

    pub fn current_agent_health(&self) -> Vec<AgentHealthEntry> {
        self.agent_dispatcher_health
            .as_ref()
            .map(|health| health.load_full().as_ref().clone())
            .unwrap_or_default()
    }

    pub fn current_mode_state(&self) -> SwarmModeState {
        self.mode_state
            .as_ref()
            .map(|mode_state| mode_state.load_full().as_ref().clone())
            .unwrap_or_default()
    }

    pub fn current_governance_status(&self) -> Option<Value> {
        self.governance_authority.as_ref().map(|policy| {
            let report = policy.status_report();
            json!({
                "ready": true,
                "status": report.partition_state,
                "total_governors": report.total_governors,
                "healthy_governors": report.healthy_governors,
                "quorum_threshold": report.quorum_threshold,
                "active_contingency_leases": report.active_contingency_leases,
                "unauthorized_partition_actions": report.unauthorized_partition_actions,
                "last_transition_at_ms": report.last_transition_at_ms,
                "last_reconciliation_report_id": report.last_reconciliation_report_id,
            })
        })
    }

    pub async fn current_providence_health(&self) -> Option<ProvidenceHealthStatus> {
        match self.providence_adapter.load_full().as_ref().clone() {
            Some(adapter) => Some(adapter.probe_health().await),
            None => None,
        }
    }

    pub fn demo_mode_enabled(&self) -> bool {
        self.stack.load_full().service.config.runtime.demo_mode
    }

    pub fn subscribe_runtime_events(
        &self,
    ) -> Option<tokio::sync::broadcast::Receiver<RuntimeEvent>> {
        self.runtime_events
            .as_ref()
            .map(RuntimeEventBroadcaster::subscribe)
    }

    pub async fn process_bridge_event(&self, event: TelemetryEvent) -> Result<(), String> {
        let degradation = self.current_runtime_degradation().await;
        if !degradation.capabilities.accepts_ingest {
            tracing::warn!(
                module = module_path!(),
                source = %event.source,
                event_id = %event.event_id,
                level = degradation.level.as_str(),
                summary = %degradation.summary,
                "bridge event rejected by runtime degradation gate"
            );
            return Err(format!(
                "runtime degradation level `{}` is not accepting ingest: {}",
                degradation.level.as_str(),
                degradation.summary
            ));
        }
        // Hold an IngestRequestGuard for the duration so /prestop's wait_for_drain
        // sees this bridge event in active_requests; without it the runtime can
        // report drained while bridge processing is still mid-flight.
        let _guard = self
            .try_begin_ingest_request()
            .map_err(|_| "runtime is draining and cannot accept bridge events".to_string())?;
        let requested_by = AgentId::from_verifying_key(&self.signing_key.verifying_key());
        let correlation_id = format!("bridge:{}:{}", event.source, event.event_id);
        process_runtime_event(self, &requested_by, &correlation_id, event)
            .await
            .map_err(|error| error.to_string())
    }

    pub fn publish_runtime_event(&self, event: RuntimeEvent) {
        if let Some(runtime_events) = &self.runtime_events {
            runtime_events.publish(event);
        }
    }

    pub fn detector_strategy_name(&self) -> String {
        self.detector_status().strategy
    }

    pub fn current_prometheus_metrics(&self) -> Option<CriticalPathMetrics> {
        self.stack.load_full().service.prometheus_metrics().cloned()
    }

    pub(in crate::ingest) fn platform_api_auth(
        &self,
    ) -> Arc<crate::ingest::platform_api::PlatformApiAuthState> {
        self.platform_api_auth.load_full()
    }

    pub(in crate::ingest) fn platform_api_rate_limiter(&self) -> &HttpRateLimiter {
        &self.platform_api_rate_limiter
    }

    pub fn current_runtime_mode(&self) -> RuntimeMode {
        self.request_runtime.load_full().mode()
    }

    pub fn current_anti_tamper_config(&self) -> RuntimeAntiTamperConfig {
        self.stack
            .load_full()
            .service
            .config
            .runtime
            .anti_tamper
            .clone()
    }

    pub fn current_startup_attestation(&self) -> Option<StartupAttestationReport> {
        self.startup_attestation
            .as_ref()
            .map(|report| report.as_ref().clone())
    }

    pub fn current_anti_tamper_report(&self) -> AntiTamperReport {
        self.anti_tamper_report.load_full().as_ref().clone()
    }

    pub fn update_anti_tamper_report(&self, report: AntiTamperReport) {
        self.anti_tamper_report.store(Arc::new(report));
    }

    pub async fn current_runtime_degradation(&self) -> RuntimeDegradationStatus {
        let stack = self.stack.load_full();
        let substrate_ready = match stack.substrate.health().await {
            Ok(health) => {
                health.ready
                    && (!stack.service.config.runtime.require_durable_live_response
                        || stack.service.mode() != RuntimeMode::LiveResponse
                        || health.durable)
            }
            Err(_) => false,
        };
        let replay_store_ready = stack
            .replay_store
            .health()
            .map(|health| health.ready)
            .unwrap_or(false);
        let startup_attestation_ready = self
            .current_startup_attestation()
            .map(|report| report.ready_for_mode(stack.service.mode()))
            .unwrap_or(!matches!(stack.service.mode(), RuntimeMode::LiveResponse));
        let anti_tamper_ready = self.current_anti_tamper_report().effective_ready();
        let heap_ready = self.sample_heap_pressure().as_ref().is_none_or(|snapshot| {
            snapshot.pressure_ratio <= stack.service.config.runtime.max_heap_pressure
        });
        let agent_health = self.current_agent_health();
        let (_, degraded_agents, failed_agents) = active_agent_counts(&agent_health);
        let detector_ready = self.detector_status().ready;
        let previous = self.runtime_degradation.load_full();
        let candidate = derive_runtime_degradation_status(RuntimeDegradationSignals {
            configured_mode: stack.service.mode(),
            detector_ready,
            substrate_ready,
            replay_store_ready,
            startup_attestation_ready,
            anti_tamper_ready,
            heap_ready,
            draining: self.is_draining(),
            degraded_agents,
            failed_agents,
            transitioned_at_ms: now_ms(),
        });
        let degradation = if candidate.same_state_as(previous.as_ref()) {
            RuntimeDegradationStatus {
                transitioned_at_ms: previous.transitioned_at_ms,
                ..candidate
            }
        } else {
            candidate
        };
        self.runtime_degradation
            .store(Arc::new(degradation.clone()));
        degradation
    }

    pub fn request_shutdown(&self) {
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(true);
        }
    }

    pub fn current_evasion_coverage(
        &self,
    ) -> Result<EvasionCoverageSnapshot, EvasionCoverageError> {
        let stack = self.stack.load_full();
        let repo_root = resolve_repo_root(self.config_path());
        evaluate_repo_evasion_coverage(&stack.service.config, &repo_root)
    }

    pub fn current_replay_store(&self) -> ConfiguredReplayBundleStore {
        self.stack.load_full().replay_store.clone()
    }

    pub fn current_investigation(
        &self,
    ) -> InvestigationCoordinator<SummaryInvestigator, ConfiguredInvestigationBundleStore> {
        self.stack.load_full().investigation.clone()
    }

    pub fn current_investigation_store(&self) -> ConfiguredInvestigationBundleStore {
        self.stack.load_full().investigation_store.clone()
    }

    pub fn current_correlation_engine(&self) -> CorrelationEngine {
        self.stack.load_full().correlation.clone()
    }

    pub fn current_incident_store(&self) -> ConfiguredIncidentStore {
        self.stack.load_full().incident_store.clone()
    }

    pub async fn current_async_lane_status(&self) -> Result<AsyncLaneStatusSnapshot, ServiceError> {
        let stack = self.stack.load_full();
        let detector = self.detector.load_full();
        Ok(stack
            .operator_review_status(detector.as_ref())
            .await?
            .async_lane)
    }

    fn operator_id(&self) -> String {
        self.stack
            .load_full()
            .service
            .config
            .operator
            .auth
            .operator_id
            .clone()
    }

    fn detector_status(&self) -> DetectorRuntimeStatus {
        self.detector_status.load_full().as_ref().clone()
    }

    pub fn begin_drain(&self) -> bool {
        self.lifecycle.begin_drain()
    }

    fn is_draining(&self) -> bool {
        self.lifecycle.is_draining()
    }

    pub fn active_requests(&self) -> usize {
        self.lifecycle.active_requests()
    }

    fn try_begin_ingest_request(&self) -> Result<IngestRequestGuard, ()> {
        self.lifecycle.try_begin_request()
    }

    pub fn drain_timeout(&self) -> Duration {
        Duration::from_millis(
            self.stack
                .load_full()
                .service
                .config
                .runtime
                .drain_timeout_ms,
        )
    }

    pub fn secret_dir_path(&self) -> Option<PathBuf> {
        let stack = self.stack.load_full();
        resolve_secret_dir_path(
            stack.service.config.runtime.secret_dir.as_deref(),
            Some(self.config_path()),
        )
    }

    pub async fn wait_for_drain(&self) -> bool {
        self.lifecycle.wait_for_zero(self.drain_timeout()).await
    }

    fn sample_heap_pressure(&self) -> Option<HeapPressureSnapshot> {
        (self.heap_snapshot_provider)()
    }

    fn begin_demo_run(
        &self,
        run_id: &str,
        scenario_name: &str,
        scenario_path: &str,
        requested_by: &str,
        pace_ms: u64,
        total_steps: usize,
    ) {
        let mut registry = self
            .demo_runs
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        registry.runs.insert(
            run_id.to_string(),
            DemoRunState {
                run_id: run_id.to_string(),
                scenario_name: scenario_name.to_string(),
                scenario_path: scenario_path.to_string(),
                requested_by: requested_by.to_string(),
                pace_ms,
                total_steps,
                created_at_ms: now_ms(),
                completed_at_ms: None,
                timeline: vec![DemoTimelineEntry {
                    occurred_at_ms: now_ms(),
                    stage: "replay_started".to_string(),
                    details: json!({
                        "scenario_name": scenario_name,
                        "scenario_path": scenario_path,
                        "requested_by": requested_by,
                        "pace_ms": pace_ms,
                        "total_steps": total_steps,
                    }),
                }],
                approvals: Vec::new(),
                final_incident: None,
            },
        );
    }

    fn append_demo_timeline(&self, run_id: &str, stage: &str, details: Value, occurred_at_ms: i64) {
        let mut registry = self
            .demo_runs
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(run) = registry.runs.get_mut(run_id) {
            run.timeline.push(DemoTimelineEntry {
                occurred_at_ms,
                stage: stage.to_string(),
                details,
            });
        }
    }

    fn mark_demo_completed(&self, run_id: &str) {
        let mut registry = self
            .demo_runs
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(run) = registry.runs.get_mut(run_id) {
            run.completed_at_ms = Some(now_ms());
        }
    }

    fn update_demo_incident(&self, run_id: &str, incident: CorrelatedIncident) {
        let mut registry = self
            .demo_runs
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(run) = registry.runs.get_mut(run_id) {
            run.final_incident = Some(incident);
        }
    }

    fn register_pending_demo_approval(
        &self,
        run_id: &str,
        step_index: usize,
        request: &ActionRequest,
        audit: &AuditTrail,
    ) -> Result<(), DemoApprovalError> {
        let Some(harness) = &self.approval_harness else {
            return Err(DemoApprovalError::HarnessNotConfigured);
        };

        let set_record = harness.create_approval_set(
            vec![self.operator_id()],
            ThresholdRule::AtLeast { required: 1 },
            &format!(
                "demo_approval:{}:{}:{}",
                run_id, step_index, request.hunt_id.0
            ),
        )?;
        let approval_set_id = set_record.set_id.clone();
        let ledgers = harness.list_ledgers(Some(&approval_set_id))?;
        let ledger =
            ledgers
                .ledgers
                .into_iter()
                .next()
                .ok_or_else(|| DemoApprovalError::MissingLedger {
                    set_id: approval_set_id.clone(),
                })?;
        let approval_ledger_id = ledger.ledger_id.clone();

        let action_kind = request.action.kind().to_string();
        let occurred_at_ms = now_ms();
        let mut registry = self
            .demo_runs
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let run = registry
            .runs
            .get_mut(run_id)
            .ok_or_else(|| DemoApprovalError::RunNotFound {
                run_id: run_id.to_string(),
            })?;
        run.approvals.push(DemoApprovalDecisionRecord {
            approval_set_id: approval_set_id.clone(),
            approval_ledger_id: approval_ledger_id.clone(),
            step_index,
            action_kind: action_kind.clone(),
            initial_audit: audit.clone(),
            receipt_pack: None,
            resumed_audit: None,
        });
        run.timeline.push(DemoTimelineEntry {
            occurred_at_ms,
            stage: "approval_paused".to_string(),
            details: json!({
                "step_index": step_index,
                "approval_set_id": approval_set_id,
                "approval_ledger_id": approval_ledger_id,
                "action_kind": action_kind,
                "hunt_id": request.hunt_id.0.clone(),
                "reason": audit.policy.reason.clone(),
            }),
        });
        registry.pending_approvals.insert(
            approval_set_id.clone(),
            PendingDemoApproval {
                run_id: run_id.to_string(),
                approval_set_id,
                approval_ledger_id,
                request: request.clone(),
                detection: audit.detection.clone(),
            },
        );
        Ok(())
    }

    fn load_demo_run(&self, run_id: &str) -> Option<DemoRunState> {
        self.demo_runs
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .runs
            .get(run_id)
            .cloned()
    }

    fn take_pending_demo_approval(&self, approval_set_id: &str) -> Option<PendingDemoApproval> {
        self.demo_runs
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .pending_approvals
            .remove(approval_set_id)
    }

    fn complete_demo_approval(
        &self,
        pending: &PendingDemoApproval,
        receipt_pack: ApprovalReceiptPackReport,
        resumed_audit: AuditTrail,
    ) -> Result<(), DemoApprovalError> {
        let mut registry = self
            .demo_runs
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let run = registry.runs.get_mut(&pending.run_id).ok_or_else(|| {
            DemoApprovalError::RunNotFound {
                run_id: pending.run_id.clone(),
            }
        })?;
        let approval = run
            .approvals
            .iter_mut()
            .find(|record| record.approval_set_id.as_str() == pending.approval_set_id.as_str())
            .ok_or_else(|| DemoApprovalError::ApprovalNotFound {
                run_id: pending.run_id.clone(),
                approval_set_id: pending.approval_set_id.clone(),
            })?;
        approval.receipt_pack = Some(receipt_pack.clone());
        approval.resumed_audit = Some(resumed_audit.clone());
        run.timeline.push(DemoTimelineEntry {
            occurred_at_ms: now_ms(),
            stage: "approval_resumed".to_string(),
            details: json!({
                "step_index": approval.step_index,
                "approval_set_id": pending.approval_set_id.clone(),
                "approval_ledger_id": pending.approval_ledger_id.clone(),
                "receipt_pack_id": receipt_pack.pack_id.clone(),
                "verdict_id": receipt_pack.verdict.verdict_id.clone(),
                "response_kind": resumed_audit.response_kind(),
                "response_receipt_id": resumed_audit.response_receipt_id(),
            }),
        });
        Ok(())
    }
}

// --- Public types for request/response ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IngestRequest(pub Vec<Value>);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestEventStatus {
    Accepted,
    Rejected,
    ProcessingError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestEventResult {
    pub event_id: Option<String>,
    pub status: IngestEventStatus,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestResponse {
    pub correlation_id: String,
    pub accepted: Vec<IngestEventResult>,
    pub rejected: Vec<IngestEventResult>,
}

#[derive(Debug, Clone, Serialize)]
struct IngestErrorBody {
    error: String,
    correlation_id: String,
}

pub fn validate_and_parse(value: Value) -> Result<TelemetryEvent, IngestRequestError> {
    serde_json::from_value::<TelemetryEvent>(value).map_err(IngestRequestError::from)
}

// --- Core ingest handler ---

pub async fn ingest_events_handler(
    State(state): State<IngestState>,
    payload: Result<Json<IngestRequest>, JsonRejection>,
) -> Response {
    let correlation_id = Uuid::new_v4().to_string();
    let degradation = state.current_runtime_degradation().await;
    if !degradation.capabilities.accepts_ingest {
        tracing::warn!(
            correlation_id = %correlation_id,
            module = module_path!(),
            level = degradation.level.as_str(),
            summary = %degradation.summary,
            "ingest rejected by runtime degradation gate"
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            ResponseJson(IngestErrorBody {
                error: if degradation.capabilities.drains_ingest {
                    "runtime is draining and not accepting new ingest requests".to_string()
                } else {
                    format!(
                        "runtime degradation level `{}` is not accepting ingest requests: {}",
                        degradation.level.as_str(),
                        degradation.summary
                    )
                },
                correlation_id,
            }),
        )
            .into_response();
    }
    let request_guard = match state.try_begin_ingest_request() {
        Ok(guard) => guard,
        Err(()) => {
            tracing::warn!(
                correlation_id = %correlation_id,
                module = module_path!(),
                "ingest rejected while runtime is draining"
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                ResponseJson(IngestErrorBody {
                    error: "runtime is draining and not accepting new ingest requests".to_string(),
                    correlation_id,
                }),
            )
                .into_response();
        }
    };
    let Json(request) = match payload {
        Ok(payload) => payload,
        Err(rejection) => {
            tracing::warn!(
                correlation_id = %correlation_id,
                module = module_path!(),
                reason = %rejection.body_text(),
                "invalid ingest payload"
            );
            return (
                StatusCode::BAD_REQUEST,
                ResponseJson(IngestErrorBody {
                    error: rejection.body_text(),
                    correlation_id,
                }),
            )
                .into_response();
        }
    };

    let events = request.0;
    let event_count = events.len();
    let span_correlation_id = correlation_id.clone();
    let request_started = Instant::now();
    async move {
        let _request_guard = request_guard;
        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        for raw_event in events {
            let event_id = event_id_from_raw(&raw_event);
            match validate_and_parse(raw_event) {
                Ok(event) => {
                    tracing::info!(
                        correlation_id = %correlation_id,
                        event_id = ?event_id,
                        module = module_path!(),
                        "processing ingest event"
                    );
                    let agent_id = AgentId("ingest".to_string());
                    match process_runtime_event(&state, &agent_id, &correlation_id, event).await {
                        Ok(_) => {
                            tracing::info!(
                                correlation_id = %correlation_id,
                                event_id = ?event_id,
                                module = module_path!(),
                                "event accepted"
                            );
                            accepted.push(IngestEventResult {
                                event_id,
                                status: IngestEventStatus::Accepted,
                                reason: None,
                            });
                        }
                        Err(error) => {
                            tracing::error!(
                                correlation_id = %correlation_id,
                                event_id = ?event_id,
                                reason = %error,
                                module = module_path!(),
                                "event processing error"
                            );
                            rejected.push(IngestEventResult {
                                event_id,
                                status: if error.is_event_rejection() {
                                    IngestEventStatus::Rejected
                                } else {
                                    IngestEventStatus::ProcessingError
                                },
                                reason: Some(error.to_string()),
                            });
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        correlation_id = %correlation_id,
                        event_id = ?event_id,
                        reason = %error,
                        module = module_path!(),
                        "event rejected"
                    );
                    rejected.push(IngestEventResult {
                        event_id,
                        status: IngestEventStatus::Rejected,
                        reason: Some(error.to_string()),
                    });
                }
            }
        }
        if let Some(prometheus) = state.stack.load_full().service.prometheus_metrics() {
            prometheus
                .observe_ingest_request(request_started.elapsed().as_secs_f64() * 1_000_000.0);
            prometheus.observe_ingest_events("accepted", accepted.len() as u64);
            prometheus.observe_ingest_events("rejected", rejected.len() as u64);
        }

        ResponseJson(IngestResponse {
            correlation_id,
            accepted,
            rejected,
        })
        .into_response()
    }
    .instrument(tracing::info_span!(
        "ingest_request",
        correlation_id = %span_correlation_id,
        event_count,
    ))
    .await
}

// --- Router constructors ---

pub fn ingest_router(state: IngestState) -> Router {
    Router::new()
        .route("/v1/ingest/events", post(ingest_events_handler))
        .with_state(state)
}

pub fn detect_http_router(state: IngestState) -> Router {
    Router::new()
        .route("/startupz", get(health::startupz_handler))
        .route("/livez", get(health::livez_handler))
        .route("/readyz", get(health::readyz_handler))
        .route("/healthz", get(health::healthz_handler))
        .route("/prestop", get(health::prestop_handler))
        .route("/metrics", get(health::metrics_handler))
        .route("/v1/ingest/events", post(ingest_events_handler))
        .route("/v1/demo/replay", post(demo::demo_replay_handler))
        .route("/v1/demo/widget", get(demo::demo_widget_handler))
        .route(
            "/v1/demo/dashboard",
            get(demo::demo_dashboard_snapshot_handler),
        )
        .route(
            "/v1/demo/approvals/{approval_set_id}/resume",
            post(demo::demo_approval_resume_handler),
        )
        .route("/v1/demo/proof", get(demo::demo_proof_handler))
        .route(
            "/v1/providence/callback",
            post(providence_handlers::providence_callback_handler),
        )
        .route(
            "/v1/providence/feedback",
            post(providence_handlers::providence_feedback_handler),
        )
        .route(
            "/v1/soar/verdicts",
            post(soar_verdict_handlers::soar_verdict_handler),
        )
        .route("/v1/events/stream", get(demo::runtime_events_handler))
        .merge(governance_resume::governed_resume_router(&state))
        .nest("/api/v1", platform_api::legacy_evasion_api_router(&state))
        .nest("/v2/api", platform_api::platform_api_router(&state))
        .with_state(state)
}

// --- Tests ---

#[cfg(test)]
#[path = "tests.rs"]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
