mod demo;
mod health;
mod platform_api;
mod providence_handlers;

// Re-export the public API that was previously accessible as `crate::ingest::*`
pub use demo::{
    DemoApprovalResumeRequest, DemoApprovalResumeResponse, DemoDashboardSnapshot, DemoProofLeaf,
    DemoProofPackage, DemoProofQuery, DemoReplayRequest, DemoReplayResponse, DemoRunApprovalReport,
    DemoRunReport, DemoTimelineEntry, FirstRunWizardArtifacts, FirstRunWizardError,
    FirstRunWizardReport, FirstRunWizardRequest, FirstRunWizardStatus, run_first_run_wizard,
};

use crate::anti_tamper::AntiTamperReport;
use crate::approval::{
    ApprovalError, ApprovalReceiptPackReport, DefaultApprovalHarness, ThresholdRule,
};
use crate::bridge_runtime::{SharedBridgeHealth, bridge_health_report};
use crate::canary::DefaultCanaryHarness;
use crate::config::{
    RuntimeConfigError, load_config_unresolved, resolve_outbound_secrets, resolve_secret_dir_path,
};
use crate::control::{ControlError, build_composite_detector};
use crate::correlation::CorrelationEngine;
use crate::detection::metrics::CriticalPathMetrics;
use crate::dispatcher::{GovernanceVetoRoute, RequestResponseRouter, approval_context_now};
use crate::dispatcher::{
    StrategyProposalOutcome, StrategyProposalRoute, StrategyProposalRouteReport,
    StrategyProposalRouter,
};
use crate::drafting::DefaultEvolutionDraftingHarness;
use crate::evasion_coverage::{
    EvasionCoverageError, EvasionCoverageSnapshot, evaluate_repo_evasion_coverage,
    resolve_repo_root,
};
use crate::evolution::{
    DefaultEvolutionHandoffHarness, DefaultEvolutionProofHarness, DefaultFormalSafetyGate,
    EvolutionProposalDecisionAction, EvolutionProposalReviewState, FormalSafetyGate,
    StrategyGenome,
};
use crate::evolution_status::DefaultEvolutionStatusHarness;
use crate::investigation::{InvestigationCoordinator, SummaryInvestigator};
use crate::mutation::DefaultEvolutionMutationHarness;
use crate::providence::{
    PROVIDENCE_CHANNEL, ProvidenceContextScope, ProvidenceHealthStatus, ProvidenceIncidentAdapter,
    ProvidenceRuntimeContext, verify_providence_context_token,
};
use crate::runtime_events::{
    AsyncLaneStatusSnapshot, RuntimeEvent, RuntimeEventBroadcaster, RuntimeThreatConcentration,
    now_ms,
};
use crate::selection::DefaultEvolutionSelectionHarness;
use crate::service::{
    ConfiguredRuntimeStack, RuntimeDegradationSignals, RuntimeDegradationStatus, ServiceError,
    derive_runtime_degradation_status,
};
use crate::startup_attestation::StartupAttestationReport;
use crate::tom_agent::GovernancePolicy;
use crate::{RuntimeError, StrategyProposalRouteError};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use axum::extract::{Json, State, rejection::JsonRejection};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, response::Json as ResponseJson};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use swarm_core::ThreatClass;
use swarm_core::agent::{AgentHealthEntry, SwarmModeState};
use swarm_core::config::{
    OperatorSurfaceConfig, ResponseAdapterConfig, RuntimeAntiTamperConfig, RuntimeMode, SwarmConfig,
};
use swarm_core::pheromone::EscalationRecord;
use swarm_core::types::AgentId;
use swarm_pheromone::PheromoneSubstrate;
use swarm_policy::configurable_gate::ConfigurableApprovalGate;
use swarm_policy::{ActionRequest, ApprovalContext};
use swarm_response::DispatchingExecutor;
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

type HeapSnapshotProvider = Arc<dyn Fn() -> Option<HeapPressureSnapshot> + Send + Sync>;

struct IngestRuntimeRequestResponseRouter {
    stack: Arc<ArcSwap<IngestRuntimeStack>>,
}

#[async_trait]
impl RequestResponseRouter for IngestRuntimeRequestResponseRouter {
    async fn route_request(
        &self,
        request: ActionRequest,
    ) -> Result<swarm_spine::AuditTrail, RuntimeError> {
        let stack = self.stack.load_full();
        let context =
            approval_context_now(stack.service.runtime.mode() == RuntimeMode::LiveResponse);
        let detection = routed_detection_from_request(&request);
        stack
            .service
            .runtime
            .audit_authorize_and_execute(&detection, &request, &context)
            .await
    }

    async fn route_governance_veto(
        &self,
        veto: GovernanceVetoRoute,
    ) -> Result<swarm_spine::AuditTrail, RuntimeError> {
        let stack = self.stack.load_full();
        let context =
            approval_context_now(stack.service.runtime.mode() == RuntimeMode::LiveResponse);
        let detection = routed_detection_from_request(&veto.request);
        Ok(stack.service.runtime.audit_governance_veto(
            &detection,
            &veto.request,
            &context,
            &veto.governing_agent_id,
            veto.reason,
        ))
    }
}

struct IngestRuntimeStrategyProposalRouter {
    stack: Arc<ArcSwap<IngestRuntimeStack>>,
    config_path: Arc<PathBuf>,
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
            crate::replay::load_detector_experiment_manifest(&payload.experiment_path)?;
        let verification_store =
            crate::replay::FileVerificationStore::open(&paths.verification_results_dir)?;
        let verification = verification_store
            .load(&validation.report.verification_id)?
            .ok_or_else(|| StrategyProposalRouteError::MissingArtifact {
                artifact: "verification",
                artifact_id: validation.report.verification_id.clone(),
                strategy_id: proposal.strategy_id.clone(),
            })?;
        let shadow_store = crate::replay::FileShadowStore::open(&paths.shadow_results_dir)?;
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
                .filter(|invariant| !invariant.passed)
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

        // Attach assurance lineage to the queue proposal so the handoff
        // gate recognises the candidate as safe to launch.
        {
            let queue_store = crate::evolution::FileEvolutionProposalStore::open(
                &paths.evolution_queue_results_dir,
            )?;
            let mut proposal_report = queue_store
                .load(&queue_proposal_id)?
                .ok_or_else(|| StrategyProposalRouteError::MissingArtifact {
                    artifact: "queue_proposal",
                    artifact_id: queue_proposal_id.clone(),
                    strategy_id: proposal.strategy_id.clone(),
                })?
                .report;
            if proposal_report.assurance.is_none() {
                proposal_report.assurance =
                    Some(crate::evolution::EvolutionProposalAssuranceSummary {
                        decision: crate::evolution::EvolutionProposalAssuranceDecision::Passed,
                        coverage: crate::evolution::EvolutionProposalAssuranceCoverageSummary {
                            detector: proposal.strategy_id.clone(),
                            suite_name: None,
                            corpus_version: None,
                            required_catch_rate: config.evolution.assurance.min_detector_catch_rate,
                            actual_catch_rate: None,
                            actionable_gap_count: 0,
                        },
                        solver: crate::evolution::EvolutionProposalAssuranceSolverSummary {
                            required: false,
                            status: None,
                            allowed_statuses: Vec::new(),
                        },
                        harvested_case_ids: Vec::new(),
                        waiver: None,
                    });
                queue_store.persist(&proposal_report)?;
            }
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

fn safety_rejection_summary(report: &crate::evolution::FormalSafetyVerificationReport) -> String {
    let reasons = report
        .invariants
        .iter()
        .filter(|invariant| !invariant.passed)
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
) -> Result<(), crate::evolution::EvolutionQueueError> {
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
    let trace_id = correlation_id.to_string();
    let span = tracing::info_span!(
        "ingest.process_runtime_event",
        trace_id = %trace_id,
        event_id = %event.event_id,
        requested_by = %requested_by.0
    );

    swarm_core::observability::with_trace_id(
        trace_id,
        async {
            let approval = ApprovalContext {
                live_mode: false,
                receipt_chain: Vec::new(),
                correlation_id: Some(correlation_id.to_string()),
                now_ms: event.timestamp,
            };
            let signing_agent_id = AgentId::from_verifying_key(&state.signing_key.verifying_key());
            let stack = state.stack.load_full();
            let detector = state.detector.load_full();
            match stack
                .process_event_with_finding_observer(
                    detector.as_ref(),
                    &event,
                    crate::service::EventExecutionContext {
                        agent_id: &signing_agent_id,
                        approval: &approval,
                        signing_key: &state.signing_key,
                    },
                    |_| None,
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
    step: crate::replay::ReplayScenarioStep,
) -> Result<(), IngestProcessingError> {
    let approval = ApprovalContext {
        live_mode: state.stack.load_full().service.runtime.mode() == RuntimeMode::LiveResponse,
        receipt_chain: Vec::new(),
        correlation_id: Some(run_id.to_string()),
        now_ms: step.event.timestamp,
    };
    let replay_action = step.action.clone();
    let signing_agent_id = AgentId::from_verifying_key(&state.signing_key.verifying_key());
    let stack = state.stack.load_full();
    let detector = state.detector.load_full();
    let outcome = stack
        .process_event_with_finding_observer(
            detector.as_ref(),
            &step.event,
            crate::service::EventExecutionContext {
                agent_id: &signing_agent_id,
                approval: &approval,
                signing_key: &state.signing_key,
            },
            |_| Some(replay_action.clone()),
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
            "replay_step_without_findings",
            json!({
                "step_index": step_index,
                "event_id": step.event.event_id,
                "action_kind": step.action.kind(),
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

#[derive(Debug, thiserror::Error)]
enum IngestProcessingError {
    #[error(transparent)]
    Service(#[from] ServiceError),

    #[error(transparent)]
    DemoApproval(#[from] DemoApprovalError),
}

#[derive(Clone)]
pub struct IngestState {
    stack: Arc<ArcSwap<IngestRuntimeStack>>,
    detector: Arc<ArcSwap<CompositeDetector>>,
    detector_status: Arc<ArcSwap<DetectorRuntimeStatus>>,
    config_path: Arc<PathBuf>,
    config_template: Arc<ArcSwap<SwarmConfig>>,
    lifecycle: Arc<IngestLifecycleState>,
    telemetry_tx: Option<tokio::sync::mpsc::Sender<TelemetryEvent>>,
    agent_dispatcher_health: Option<Arc<ArcSwap<Vec<AgentHealthEntry>>>>,
    mode_state: Option<Arc<ArcSwap<SwarmModeState>>>,
    bridge_health: Option<SharedBridgeHealth>,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    heap_snapshot_provider: HeapSnapshotProvider,
    signing_key: ed25519_dalek::SigningKey,
    runtime_events: Option<RuntimeEventBroadcaster>,
    approval_harness: Option<Arc<DefaultApprovalHarness>>,
    demo_runs: Arc<Mutex<DemoRunRegistry>>,
    providence_adapter: Option<Arc<ProvidenceIncidentAdapter>>,
    providence_task_started: Arc<AtomicBool>,
    governance_policy: Option<Arc<GovernancePolicy>>,
    startup_attestation: Option<Arc<StartupAttestationReport>>,
    anti_tamper_report: Arc<ArcSwap<AntiTamperReport>>,
    runtime_degradation: Arc<ArcSwap<RuntimeDegradationStatus>>,
}

impl IngestState {
    fn build_runtime(
        config: SwarmConfig,
    ) -> Result<(Arc<IngestRuntimeStack>, Arc<CompositeDetector>), IngestBuildError> {
        let detector = Arc::new(build_composite_detector(&config.detection)?);
        let stack = Arc::new(ConfiguredRuntimeStack::from_config(
            config,
            SummaryInvestigator,
        )?);
        Ok((stack, detector))
    }

    pub fn from_config(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
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
        let (stack, detector) = Self::build_runtime(resolved)?;
        let detector_status = Arc::new(ArcSwap::from(Arc::new(DetectorRuntimeStatus::loaded(
            strategy,
        ))));
        let state = Self {
            stack: Arc::new(ArcSwap::from(stack)),
            detector: Arc::new(ArcSwap::from(detector)),
            detector_status,
            config_path: Arc::new(config_path),
            config_template: Arc::new(ArcSwap::from(Arc::new(template))),
            lifecycle: Arc::new(IngestLifecycleState::default()),
            telemetry_tx: None,
            agent_dispatcher_health: None,
            mode_state: None,
            bridge_health: None,
            shutdown_tx: None,
            heap_snapshot_provider: Arc::new(sample_heap_pressure),
            signing_key: ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng),
            runtime_events: None,
            approval_harness: None,
            demo_runs: Arc::new(Mutex::new(DemoRunRegistry::default())),
            providence_adapter,
            providence_task_started: Arc::new(AtomicBool::new(false)),
            governance_policy: None,
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
        match Self::build_runtime(config) {
            Ok((stack, detector)) => {
                self.detector.store(detector);
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
        let Some(adapter) = self.providence_adapter.clone() else {
            return;
        };
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

    pub fn with_shutdown_channel(mut self, tx: tokio::sync::watch::Sender<bool>) -> Self {
        self.shutdown_tx = Some(tx);
        self.maybe_start_providence_sync_task();
        self
    }

    pub fn with_runtime_events(mut self, runtime_events: RuntimeEventBroadcaster) -> Self {
        self.runtime_events = Some(runtime_events);
        self
    }

    pub fn with_governance_policy(mut self, governance_policy: Arc<GovernancePolicy>) -> Self {
        self.governance_policy = Some(governance_policy);
        self
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
        })
    }

    pub fn current_strategy_proposal_router(&self) -> Arc<dyn StrategyProposalRouter> {
        Arc::new(IngestRuntimeStrategyProposalRouter {
            stack: Arc::clone(&self.stack),
            config_path: Arc::clone(&self.config_path),
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
        self.governance_policy.as_ref().map(|policy| {
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
        match &self.providence_adapter {
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

    pub fn current_runtime_mode(&self) -> RuntimeMode {
        self.stack.load_full().service.mode()
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
                                status: IngestEventStatus::ProcessingError,
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
        .route("/v1/events/stream", get(demo::runtime_events_handler))
        .nest("/api/v1", platform_api::legacy_evasion_api_router(&state))
        .nest("/v2/api", platform_api::platform_api_router(&state))
        .with_state(state)
}

// --- Tests ---

#[cfg(test)]
#[path = "tests.rs"]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
