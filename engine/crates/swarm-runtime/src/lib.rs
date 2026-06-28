//! Rust-first runtime orchestration for Swarm Team Six.
//!
//! This crate is the intended composition root for the production runtime:
//! detection stays in Rust, policy stays deterministic, and live response
//! execution is capability-scoped.
#![allow(clippy::result_large_err)]

extern crate self as swarm_runtime;

pub mod agent_identity;
pub mod alert_tuning;
pub mod anti_tamper;
pub mod approval;
pub mod bridge_runtime;
pub mod calico_agent;
#[path = "../../swarm-evolution/src/canary.rs"]
pub mod canary;
pub mod cli;
pub mod config;
pub mod control;
pub mod correlation;
pub mod detection;
pub mod detector_factory;
pub mod dispatcher;
#[path = "../../swarm-evolution/src/drafting.rs"]
pub mod drafting;
pub mod escalation;
pub mod evasion_coverage;
#[path = "../../swarm-evolution/src/evidence.rs"]
pub mod evidence;
#[path = "../../swarm-evolution/src/evolution.rs"]
pub mod evolution;
pub mod evolution_status;
#[path = "../../swarm-evolution/src/governance_prep.rs"]
pub mod governance_prep;
pub mod http;
pub mod ingest;
pub mod investigation;
pub mod kitten_agent;
#[path = "../../swarm-evolution/src/mutation.rs"]
pub mod mutation;
pub mod operator_http;
pub mod operator_maintenance;
#[path = "../../swarm-evolution/src/portfolio.rs"]
pub mod portfolio;
pub mod pounce_agent;
#[path = "../../swarm-evolution/src/promotion.rs"]
pub mod promotion;
pub mod providence;
pub mod red_swarm;
pub mod replay;
pub mod review_workbench;
pub mod runtime_events;
#[path = "../../swarm-evolution/src/selection.rs"]
pub mod selection;
pub mod sequence_detector;
pub mod serve;
pub mod service;
pub mod sphinx_agent;
pub mod stalker_agent;
pub mod startup_attestation;
#[path = "../../swarm-evolution/src/strategy.rs"]
pub mod strategy;
pub mod tom_agent;
pub mod weaver_agent;
pub mod whisker_agent;
pub mod workbench;

use std::any::Any;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use swarm_consensus::ConsensusGovernanceReceipt;
use swarm_core::agent::{AgentRole, SwarmError};
pub use swarm_core::config::RuntimeMode;
use swarm_core::config::TemporalEventWindowConfig;
use swarm_core::types::AgentId;
use swarm_guard::{GuardAction, GuardContext, GuardPipeline};
use swarm_policy::{ActionRequest, ApprovalContext, ApprovalError, ApprovalGate};
use swarm_response::{
    ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt, ResponseStatus,
};
use swarm_spine::{AuditResponseRecord, AuditTrail, PolicyRecord};
use swarm_whisker::{DetectionFinding, TelemetryEvent, TelemetryEventPredicate};

/// Runtime errors surfaced while authorizing or executing actions.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Approval(#[from] ApprovalError),

    #[error("guard rejected: {guard_name}: {reason}")]
    GuardRejected { guard_name: String, reason: String },

    #[error(transparent)]
    Response(#[from] ResponseError),
}

/// Typed boundary errors surfaced from runtime-owned agent ticks.
#[derive(Debug, thiserror::Error)]
pub enum AgentTickBoundaryError {
    #[error(transparent)]
    Panic(#[from] AgentPanicBoundaryError),

    #[error(transparent)]
    Sphinx(#[from] crate::sphinx_agent::SphinxAgentTickError),

    #[error(transparent)]
    Stalker(#[from] crate::stalker_agent::StalkerAgentTickError),
}

impl AgentTickBoundaryError {
    pub fn boundary(&self) -> &'static str {
        match self {
            Self::Panic(_) => "panic",
            Self::Sphinx(error) => error.boundary(),
            Self::Stalker(error) => error.boundary(),
        }
    }

    pub fn role(&self) -> AgentRole {
        match self {
            Self::Panic(error) => error.role,
            Self::Sphinx(_) => AgentRole::Sphinx,
            Self::Stalker(_) => AgentRole::Stalker,
        }
    }
}

pub fn agent_tick_error_boundary(error: &SwarmError) -> Option<&'static str> {
    match error {
        SwarmError::Internal(error) => error
            .downcast_ref::<AgentTickBoundaryError>()
            .map(AgentTickBoundaryError::boundary),
        _ => None,
    }
}

pub fn agent_tick_error_role(error: &SwarmError) -> Option<AgentRole> {
    match error {
        SwarmError::Internal(error) => error
            .downcast_ref::<AgentTickBoundaryError>()
            .map(AgentTickBoundaryError::role),
        _ => None,
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("agent `{agent_id}` ({role:?}) panicked during tick: {message}")]
pub struct AgentPanicBoundaryError {
    pub agent_id: AgentId,
    pub role: AgentRole,
    pub message: String,
}

impl AgentPanicBoundaryError {
    pub fn new(agent_id: AgentId, role: AgentRole, payload: Box<dyn Any + Send>) -> Self {
        Self {
            agent_id,
            role,
            message: panic_payload_message(payload.as_ref()),
        }
    }
}

fn panic_payload_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        return (*message).to_string();
    }
    "non-string panic payload".to_string()
}

pub fn agent_tick_panic_error(
    agent_id: &AgentId,
    role: AgentRole,
    payload: Box<dyn Any + Send>,
) -> SwarmError {
    SwarmError::Internal(
        AgentTickBoundaryError::from(AgentPanicBoundaryError::new(
            agent_id.clone(),
            role,
            payload,
        ))
        .into(),
    )
}

/// Typed boundary errors surfaced while routing Kitten strategy proposals.
#[derive(Debug, thiserror::Error)]
pub enum StrategyProposalRouteError {
    #[error("invalid kitten proposal payload: {0}")]
    InvalidPayload(#[source] serde_json::Error),

    #[error("unsupported strategy proposal source `{proposal_source}`")]
    UnsupportedSource { proposal_source: String },

    #[error(transparent)]
    Drafting(#[from] crate::drafting::EvolutionDraftingError),

    #[error(transparent)]
    Mutation(#[from] crate::mutation::EvolutionMutationError),

    #[error(transparent)]
    Selection(#[from] crate::selection::EvolutionSelectionError),

    #[error(transparent)]
    FormalSafety(#[from] crate::evolution::FormalSafetyGateError),

    #[error(transparent)]
    Queue(#[from] crate::evolution::EvolutionQueueError),

    #[error(transparent)]
    ProposalStore(#[from] crate::evolution::EvolutionProposalStoreError),

    #[error(transparent)]
    Replay(#[from] crate::replay::ReplayHarnessError),

    #[error(transparent)]
    VerificationStore(#[from] crate::replay::VerificationStoreError),

    #[error(transparent)]
    ShadowStore(#[from] crate::replay::ShadowStoreError),

    #[error(transparent)]
    Canary(#[from] crate::canary::CanaryError),

    #[error(
        "proposal strategy `{proposal_strategy_id}` did not match validation bundle strategy `{validation_strategy_id}`"
    )]
    ValidationStrategyMismatch {
        proposal_strategy_id: String,
        validation_strategy_id: String,
    },

    #[error(
        "proposal materialization `{proposal_materialization_id}` did not match validation bundle materialization `{validation_materialization_id}`"
    )]
    ValidationMaterializationMismatch {
        proposal_materialization_id: String,
        validation_materialization_id: String,
    },

    #[error(
        "ranking `{ranking_id}` has no review packet for strategy `{strategy_id}` and validation bundle `{validation_bundle_id}`"
    )]
    RankingPacketNotFound {
        ranking_id: String,
        strategy_id: String,
        validation_bundle_id: String,
    },

    #[error(
        "{artifact} `{artifact_id}` was not found while routing strategy proposal `{strategy_id}`"
    )]
    MissingArtifact {
        artifact: &'static str,
        artifact_id: String,
        strategy_id: String,
    },

    #[error("selection bridge `{bridge_id}` did not persist a queue proposal id")]
    MissingQueueProposalId { bridge_id: String },
}

impl StrategyProposalRouteError {
    pub fn boundary(&self) -> &'static str {
        match self {
            Self::InvalidPayload(_) => "payload",
            Self::UnsupportedSource { .. } => "proposal_source",
            Self::Drafting(_) => "drafting",
            Self::Mutation(_) => "mutation",
            Self::Selection(_) => "selection",
            Self::FormalSafety(_) => "formal_safety",
            Self::Queue(_) => "queue",
            Self::ProposalStore(_) => "proposal_store",
            Self::Replay(_) => "replay",
            Self::VerificationStore(_) => "verification_store",
            Self::ShadowStore(_) => "shadow_store",
            Self::Canary(_) => "canary",
            Self::ValidationStrategyMismatch { .. } => "validation_bundle",
            Self::ValidationMaterializationMismatch { .. } => "validation_bundle",
            Self::RankingPacketNotFound { .. } => "ranking",
            Self::MissingArtifact { artifact, .. } => artifact,
            Self::MissingQueueProposalId { .. } => "selection_bridge",
        }
    }
}

const TIMESTAMP_MILLISECOND_THRESHOLD: i64 = 100_000_000_000;

fn normalized_event_timestamp_ms(timestamp: i64) -> i64 {
    if timestamp.abs() < TIMESTAMP_MILLISECOND_THRESHOLD {
        timestamp.saturating_mul(1_000)
    } else {
        timestamp
    }
}

#[derive(Debug, Clone)]
struct BufferedTelemetryEvent {
    sequence: u64,
    timestamp_ms: i64,
    event: TelemetryEvent,
}

#[derive(Debug, Default)]
struct TemporalEventWindowState {
    next_sequence: u64,
    watermark_ms: Option<i64>,
    events: Vec<BufferedTelemetryEvent>,
}

impl TemporalEventWindowState {
    fn record(&mut self, config: &TemporalEventWindowConfig, event: &TelemetryEvent) {
        let timestamp_ms = normalized_event_timestamp_ms(event.timestamp);
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.watermark_ms = Some(
            self.watermark_ms
                .map_or(timestamp_ms, |watermark| watermark.max(timestamp_ms)),
        );

        let insert_at = self.events.partition_point(|candidate| {
            candidate.timestamp_ms < timestamp_ms
                || (candidate.timestamp_ms == timestamp_ms && candidate.sequence < sequence)
        });
        self.events.insert(
            insert_at,
            BufferedTelemetryEvent {
                sequence,
                timestamp_ms,
                event: event.clone(),
            },
        );
        self.prune(config);
    }

    fn prune(&mut self, config: &TemporalEventWindowConfig) {
        let Some(watermark_ms) = self.watermark_ms else {
            return;
        };
        let oldest_allowed_ms = watermark_ms.saturating_sub(config.retention_ms);
        self.events
            .retain(|candidate| candidate.timestamp_ms >= oldest_allowed_ms);
        if self.events.len() > config.max_events {
            let overflow = self.events.len() - config.max_events;
            self.events.drain(..overflow);
        }
    }
}

/// Stable window-state summary exposed for focused tests and later sequence surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemporalEventWindowSnapshot {
    pub retained_events: usize,
    pub retention_ms: i64,
    pub max_events: usize,
    pub max_match_span_ms: i64,
    pub max_predicates_per_match: usize,
    pub oldest_timestamp_ms: Option<i64>,
    pub newest_timestamp_ms: Option<i64>,
    pub watermark_ms: Option<i64>,
}

/// Ordered match result over retained telemetry without emitting a detector finding.
#[derive(Debug, Clone)]
pub struct OrderedTemporalEventMatch {
    pub matched_events: Vec<TelemetryEvent>,
    pub started_at_ms: i64,
    pub ended_at_ms: i64,
    pub span_ms: i64,
}

/// Errors surfaced when querying the bounded temporal event window.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TemporalEventWindowError {
    #[error("ordered predicate match requires at least one predicate")]
    EmptyPredicateSet,

    #[error("requested match span `{requested_ms}` must be greater than zero")]
    RequestedSpanNonPositive { requested_ms: i64 },

    #[error("requested match span `{requested_ms}` exceeds configured limit `{max_allowed_ms}`")]
    RequestedSpanExceedsConfiguredLimit {
        requested_ms: i64,
        max_allowed_ms: i64,
    },

    #[error("requested predicate count `{requested}` exceeds configured limit `{max_allowed}`")]
    TooManyPredicates {
        requested: usize,
        max_allowed: usize,
    },
}

/// Runtime-owned bounded telemetry retention for later multi-event sequence detectors.
#[derive(Debug)]
struct TemporalEventWindowInner {
    config: TemporalEventWindowConfig,
    state: Mutex<TemporalEventWindowState>,
}

/// Runtime-owned bounded telemetry retention for later multi-event sequence detectors.
#[derive(Debug, Clone)]
pub struct TemporalEventWindow {
    inner: Arc<TemporalEventWindowInner>,
}

impl TemporalEventWindow {
    pub fn new(config: TemporalEventWindowConfig) -> Self {
        Self {
            inner: Arc::new(TemporalEventWindowInner {
                config,
                state: Mutex::new(TemporalEventWindowState::default()),
            }),
        }
    }

    pub fn record(&self, event: &TelemetryEvent) {
        let mut guard = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        guard.record(&self.inner.config, event);
    }

    pub fn snapshot(&self) -> TemporalEventWindowSnapshot {
        let guard = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        TemporalEventWindowSnapshot {
            retained_events: guard.events.len(),
            retention_ms: self.inner.config.retention_ms,
            max_events: self.inner.config.max_events,
            max_match_span_ms: self.inner.config.max_match_span_ms,
            max_predicates_per_match: self.inner.config.max_predicates_per_match,
            oldest_timestamp_ms: guard.events.first().map(|event| event.timestamp_ms),
            newest_timestamp_ms: guard.events.last().map(|event| event.timestamp_ms),
            watermark_ms: guard.watermark_ms,
        }
    }

    pub fn match_ordered(
        &self,
        predicates: &[&dyn TelemetryEventPredicate],
        requested_span_ms: Option<i64>,
    ) -> Result<Option<OrderedTemporalEventMatch>, TemporalEventWindowError> {
        if predicates.is_empty() {
            return Err(TemporalEventWindowError::EmptyPredicateSet);
        }
        if predicates.len() > self.inner.config.max_predicates_per_match {
            return Err(TemporalEventWindowError::TooManyPredicates {
                requested: predicates.len(),
                max_allowed: self.inner.config.max_predicates_per_match,
            });
        }

        let requested_span_ms = requested_span_ms.unwrap_or(self.inner.config.max_match_span_ms);
        if requested_span_ms <= 0 {
            return Err(TemporalEventWindowError::RequestedSpanNonPositive {
                requested_ms: requested_span_ms,
            });
        }
        if requested_span_ms > self.inner.config.max_match_span_ms {
            return Err(
                TemporalEventWindowError::RequestedSpanExceedsConfiguredLimit {
                    requested_ms: requested_span_ms,
                    max_allowed_ms: self.inner.config.max_match_span_ms,
                },
            );
        }

        let events = {
            let guard = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            guard.events.clone()
        };

        for (start_index, start_event) in events.iter().enumerate() {
            if !predicates[0].matches(&start_event.event) {
                continue;
            }

            let start_timestamp_ms = start_event.timestamp_ms;
            let mut matched = vec![start_event.clone()];
            let mut next_search_index = start_index + 1;
            let mut step_index = 1;

            while step_index < predicates.len() {
                let mut found = None;
                while next_search_index < events.len() {
                    let candidate = &events[next_search_index];
                    if candidate.timestamp_ms.saturating_sub(start_timestamp_ms) > requested_span_ms
                    {
                        break;
                    }
                    if predicates[step_index].matches(&candidate.event) {
                        found = Some(candidate.clone());
                        next_search_index += 1;
                        break;
                    }
                    next_search_index += 1;
                }

                let Some(candidate) = found else {
                    break;
                };
                matched.push(candidate);
                step_index += 1;
            }

            if matched.len() == predicates.len() {
                let ended_at_ms = matched
                    .last()
                    .map(|event| event.timestamp_ms)
                    .unwrap_or(start_timestamp_ms);
                return Ok(Some(OrderedTemporalEventMatch {
                    matched_events: matched.into_iter().map(|event| event.event).collect(),
                    started_at_ms: start_timestamp_ms,
                    ended_at_ms,
                    span_ms: ended_at_ms.saturating_sub(start_timestamp_ms),
                }));
            }
        }

        Ok(None)
    }
}

/// Swarm runtime wiring detection, policy, and response into one Rust service.
pub struct SwarmRuntime<P, E> {
    mode: RuntimeMode,
    policy: P,
    response: E,
    guard_pipeline: Option<GuardPipeline>,
    temporal_event_window: TemporalEventWindow,
}

/// Timing and outcome details for one audited execution.
#[derive(Debug, Clone)]
pub struct RuntimeExecutionReport {
    pub audit: AuditTrail,
    pub policy_elapsed_us: u64,
    pub response_elapsed_us: Option<u64>,
    pub response_attempted: bool,
    pub response_succeeded: bool,
}

impl<P, E> SwarmRuntime<P, E> {
    /// Create a runtime with the supplied components.
    pub fn new(mode: RuntimeMode, policy: P, response: E) -> Self {
        Self {
            mode,
            policy,
            response,
            guard_pipeline: None,
            temporal_event_window: TemporalEventWindow::new(TemporalEventWindowConfig::default()),
        }
    }

    /// Current runtime mode.
    pub fn mode(&self) -> RuntimeMode {
        self.mode
    }

    /// Attach a guard pipeline that evaluates actions before execution.
    pub fn with_guard_pipeline(mut self, pipeline: GuardPipeline) -> Self {
        self.guard_pipeline = Some(pipeline);
        self
    }

    /// Override the bounded temporal event window settings attached to this runtime.
    pub fn with_temporal_event_window_config(mut self, config: TemporalEventWindowConfig) -> Self {
        self.temporal_event_window = TemporalEventWindow::new(config);
        self
    }

    /// Apply bounded temporal event window settings from runtime configuration.
    pub fn configure_temporal_event_window(&mut self, config: TemporalEventWindowConfig) {
        self.temporal_event_window = TemporalEventWindow::new(config);
    }

    /// Retain one accepted telemetry event for later sequence matching.
    pub fn record_temporal_event(&self, event: &TelemetryEvent) {
        self.temporal_event_window.record(event);
    }

    /// Snapshot the current retained temporal event window.
    pub fn temporal_event_window_snapshot(&self) -> TemporalEventWindowSnapshot {
        self.temporal_event_window.snapshot()
    }

    /// Shared bounded temporal event window used by later sequence detectors.
    pub fn temporal_event_window(&self) -> TemporalEventWindow {
        self.temporal_event_window.clone()
    }

    /// Match ordered event predicates over the retained bounded window.
    pub fn match_temporal_sequence(
        &self,
        predicates: &[&dyn TelemetryEventPredicate],
        requested_span_ms: Option<i64>,
    ) -> Result<Option<OrderedTemporalEventMatch>, TemporalEventWindowError> {
        self.temporal_event_window
            .match_ordered(predicates, requested_span_ms)
    }

    pub fn audit_governance_veto(
        &self,
        detection: &DetectionFinding,
        request: &ActionRequest,
        context: &ApprovalContext,
        governing_agent_id: &AgentId,
        reason: impl Into<String>,
    ) -> AuditTrail {
        let reason = reason.into();
        let receipt = ResponseReceipt {
            receipt_id: format!(
                "veto:{}:{}:{}",
                request.hunt_id.0,
                request.action.kind(),
                context.now_ms
            ),
            action: request.action.kind().to_string(),
            mode: self.execution_mode(),
            status: ResponseStatus::Failed,
            summary: format!("governance veto: {reason}"),
            details: serde_json::json!({
                "status": "vetoed",
                "lineage": request.evidence.get("lineage").cloned(),
                "requested_by": request.requested_by,
                "evidence": request.evidence.clone(),
            }),
            audit: Default::default(),
        }
        .with_policy_audit(
            swarm_policy::PolicyVerdict::Deny,
            "governance.veto",
            reason.clone(),
        )
        .with_governance_audit(
            governing_agent_id.clone(),
            reason.clone(),
            Self::verified_governance_receipt(request).map(|(_, receipt_value)| receipt_value),
        );

        AuditTrail {
            trail_id: format!("trail:{}:{}", request.hunt_id.0, context.now_ms),
            hunt_id: request.hunt_id.0.clone(),
            related_receipt_ids: context.receipt_chain.clone(),
            detection: detection.clone(),
            policy: PolicyRecord {
                verdict: swarm_policy::PolicyVerdict::Deny,
                rule_name: "governance.veto".to_string(),
                reason,
                lease: None,
            },
            response: AuditResponseRecord::Failure(receipt.into_failure()),
            created_at_ms: context.now_ms,
        }
    }

    fn evaluate_guard_rejection(&self, request: &ActionRequest) -> Option<(String, String)> {
        let pipeline = self.guard_pipeline.as_ref()?;
        let context = GuardContext::new()
            .with_agent_id(request.requested_by.0.clone())
            .with_metadata(serde_json::json!({
                "hunt_id": request.hunt_id.0,
                "severity": request.severity,
            }));
        let result = pipeline.evaluate(&GuardAction::ResponseAction(&request.action), &context);

        if result.allowed {
            None
        } else {
            Some((result.guard, result.message))
        }
    }

    fn correlation_id(context: &ApprovalContext) -> &str {
        context.correlation_id.as_deref().unwrap_or("unknown")
    }

    fn execution_mode(&self) -> ExecutionMode {
        match self.mode {
            RuntimeMode::DetectOnly => ExecutionMode::DryRun,
            RuntimeMode::LiveResponse => ExecutionMode::Enforced,
        }
    }

    fn verified_governance_receipt(
        request: &ActionRequest,
    ) -> Option<(ConsensusGovernanceReceipt, serde_json::Value)> {
        let receipt_value = request.evidence.get("governance_receipt")?.clone();
        let receipt: ConsensusGovernanceReceipt =
            match serde_json::from_value(receipt_value.clone()) {
                Ok(receipt) => receipt,
                Err(error) => {
                    tracing::warn!(
                        hunt_id = %request.hunt_id.0,
                        requested_by = %request.requested_by,
                        reason = %error,
                        module = module_path!(),
                        "ignoring malformed governance receipt embedded in request evidence"
                    );
                    return None;
                }
            };
        if let Err(error) = receipt.verify() {
            tracing::warn!(
                hunt_id = %request.hunt_id.0,
                requested_by = %request.requested_by,
                reason = %error,
                module = module_path!(),
                "ignoring unverifiable governance receipt embedded in request evidence"
            );
            return None;
        }
        Some((receipt, receipt_value))
    }

    fn decorate_receipt_with_governance(
        receipt: ResponseReceipt,
        request: &ActionRequest,
        reason: impl Into<String>,
    ) -> ResponseReceipt {
        let Some((governance_receipt, receipt_value)) = Self::verified_governance_receipt(request)
        else {
            return receipt;
        };
        receipt.with_governance_audit(
            governance_receipt.payload.issued_by,
            reason.into(),
            Some(receipt_value),
        )
    }
}

impl<P, E> SwarmRuntime<P, E>
where
    P: ApprovalGate,
    E: ResponseExecutor,
{
    /// Evaluate a response request and execute it if authorized.
    pub async fn authorize_and_execute(
        &self,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<ResponseReceipt, RuntimeError> {
        let decision = self.policy.evaluate(request, context)?;
        tracing::info!(
            correlation_id = %Self::correlation_id(context),
            hunt_id = %request.hunt_id.0,
            verdict = ?decision.verdict,
            rule_name = %decision.rule_name,
            reason = %decision.reason,
            mode = ?self.mode,
            module = module_path!(),
            "policy evaluated response request"
        );

        match decision.verdict {
            swarm_policy::PolicyVerdict::Deny => {
                return Err(ApprovalError::Denied(decision.reason.clone()).into());
            }
            swarm_policy::PolicyVerdict::RequireHuman if self.mode == RuntimeMode::LiveResponse => {
                return Err(ApprovalError::Denied(decision.reason.clone()).into());
            }
            swarm_policy::PolicyVerdict::Allow | swarm_policy::PolicyVerdict::RequireHuman => {}
        }

        if let Some((guard_name, reason)) = self.evaluate_guard_rejection(request) {
            tracing::warn!(
                correlation_id = %Self::correlation_id(context),
                hunt_id = %request.hunt_id.0,
                guard_name = %guard_name,
                reason = %reason,
                module = module_path!(),
                "guard rejected response request"
            );
            return Err(RuntimeError::GuardRejected { guard_name, reason });
        }

        let lease = self.policy.issue_lease(request, context)?;
        ensure_active_lease(&lease, context.now_ms)?;
        let receipt = self
            .response
            .execute(request, &lease, self.execution_mode())
            .await
            .map_err(RuntimeError::from)?
            .with_policy_audit(
                decision.verdict,
                decision.rule_name.clone(),
                decision.reason.clone(),
            );
        let receipt = Self::decorate_receipt_with_governance(
            receipt,
            request,
            "consensus approved response action",
        );
        if !receipt.status.indicates_success() {
            return Err(RuntimeError::Response(ResponseError {
                failure: receipt.into_failure(),
            }));
        }
        tracing::info!(
            correlation_id = %Self::correlation_id(context),
            hunt_id = %request.hunt_id.0,
            action = %receipt.action,
            mode = ?receipt.mode,
            status = ?receipt.status,
            rule_name = %decision.rule_name,
            reason = %decision.reason,
            module = module_path!(),
            "response executed"
        );
        Ok(receipt)
    }

    /// Evaluate, execute, and record the full response decision for one detection finding.
    pub async fn audit_authorize_and_execute(
        &self,
        detection: &DetectionFinding,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<AuditTrail, RuntimeError> {
        Ok(self
            .audit_authorize_and_execute_instrumented(detection, request, context)
            .await?
            .audit)
    }

    /// Evaluate, execute, and record the full response decision with stage timings.
    pub async fn audit_authorize_and_execute_instrumented(
        &self,
        detection: &DetectionFinding,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<RuntimeExecutionReport, RuntimeError> {
        self.audit_authorize_and_execute_instrumented_internal(
            detection, request, context, false, None,
        )
        .await
    }

    /// Execute a rehearsal through the normal policy lane while forcing a dry-run receipt.
    pub async fn audit_rehearse_authorize_and_execute_instrumented(
        &self,
        detection: &DetectionFinding,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<RuntimeExecutionReport, RuntimeError> {
        self.audit_authorize_and_execute_instrumented_internal(
            detection,
            request,
            context,
            true,
            Some(ExecutionMode::DryRun),
        )
        .await
    }

    /// Execute a previously human-approved request through the normal runtime lane.
    pub async fn audit_authorize_and_execute_human_approved_instrumented(
        &self,
        detection: &DetectionFinding,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<RuntimeExecutionReport, RuntimeError> {
        self.audit_authorize_and_execute_instrumented_internal(
            detection, request, context, true, None,
        )
        .await
    }

    async fn audit_authorize_and_execute_instrumented_internal(
        &self,
        detection: &DetectionFinding,
        request: &ActionRequest,
        context: &ApprovalContext,
        allow_human_approved_execution: bool,
        execution_mode_override: Option<ExecutionMode>,
    ) -> Result<RuntimeExecutionReport, RuntimeError> {
        let policy_started = Instant::now();
        let decision = self.policy.evaluate(request, context)?;
        let policy_elapsed_us = policy_started.elapsed().as_micros() as u64;
        let execution_mode = execution_mode_override.unwrap_or_else(|| self.execution_mode());
        tracing::info!(
            correlation_id = %Self::correlation_id(context),
            hunt_id = %request.hunt_id.0,
            event_id = %detection.event_id,
            verdict = ?decision.verdict,
            rule_name = %decision.rule_name,
            reason = %decision.reason,
            mode = ?self.mode,
            execution_mode = ?execution_mode,
            module = module_path!(),
            "building audit trail for response decision"
        );

        let (lease, response, response_elapsed_us, response_attempted, response_succeeded) =
            match decision.verdict {
                swarm_policy::PolicyVerdict::Deny => (
                    None,
                    AuditResponseRecord::Skipped {
                        reason: decision.reason.clone(),
                    },
                    None,
                    false,
                    false,
                ),
                swarm_policy::PolicyVerdict::RequireHuman
                    if self.mode == RuntimeMode::LiveResponse
                        && !allow_human_approved_execution =>
                {
                    (
                        None,
                        AuditResponseRecord::Skipped {
                            reason: decision.reason.clone(),
                        },
                        None,
                        false,
                        false,
                    )
                }
                swarm_policy::PolicyVerdict::Allow | swarm_policy::PolicyVerdict::RequireHuman => {
                    if let Some((guard_name, reason)) = self.evaluate_guard_rejection(request) {
                        tracing::warn!(
                            correlation_id = %Self::correlation_id(context),
                            hunt_id = %request.hunt_id.0,
                            guard_name = %guard_name,
                            reason = %reason,
                            module = module_path!(),
                            "guard rejected response request"
                        );
                        (
                            None,
                            AuditResponseRecord::GuardRejected { guard_name, reason },
                            None,
                            false,
                            false,
                        )
                    } else {
                        let lease = self.policy.issue_lease(request, context)?;
                        match ensure_active_lease(&lease, context.now_ms) {
                            Ok(()) => {
                                let response_started = Instant::now();
                                let response = match self
                                    .response
                                    .execute(request, &lease, execution_mode)
                                    .await
                                {
                                    Ok(receipt) if receipt.status.indicates_success() => {
                                        AuditResponseRecord::Success(
                                            Self::decorate_receipt_with_governance(
                                                receipt.with_policy_audit(
                                                    decision.verdict,
                                                    decision.rule_name.clone(),
                                                    decision.reason.clone(),
                                                ),
                                                request,
                                                "consensus approved response action",
                                            ),
                                        )
                                    }
                                    Ok(receipt) => AuditResponseRecord::Failure(
                                        Self::decorate_receipt_with_governance(
                                            receipt.with_policy_audit(
                                                decision.verdict,
                                                decision.rule_name.clone(),
                                                decision.reason.clone(),
                                            ),
                                            request,
                                            "consensus approved response action",
                                        )
                                        .into_failure(),
                                    ),
                                    Err(error) => AuditResponseRecord::Failure(error.failure),
                                };
                                let response_elapsed_us =
                                    response_started.elapsed().as_micros() as u64;
                                let response_succeeded =
                                    matches!(response, AuditResponseRecord::Success(_));
                                (
                                    Some(lease),
                                    response,
                                    Some(response_elapsed_us),
                                    true,
                                    response_succeeded,
                                )
                            }
                            Err(ApprovalError::Denied(reason)) => {
                                let receipt = ResponseReceipt {
                                    receipt_id: format!(
                                        "lease-denied:{}:{}:{}",
                                        request.hunt_id.0,
                                        request.action.kind(),
                                        context.now_ms
                                    ),
                                    action: request.action.kind().to_string(),
                                    mode: execution_mode,
                                    status: ResponseStatus::Failed,
                                    summary: reason.clone(),
                                    details: serde_json::json!({
                                        "status": "lease_expired",
                                        "reason": reason,
                                        "lineage": request.evidence.get("lineage").cloned(),
                                        "requested_by": request.requested_by,
                                        "lease": {
                                            "capability_id": lease.capability_id.clone(),
                                            "expires_at_ms": lease.expires_at_ms,
                                            "scope": lease.scope.clone(),
                                        },
                                        "evidence": request.evidence.clone(),
                                    }),
                                    audit: Default::default(),
                                }
                                .with_policy_audit(
                                    decision.verdict,
                                    decision.rule_name.clone(),
                                    decision.reason.clone(),
                                );
                                let receipt = Self::decorate_receipt_with_governance(
                                    receipt,
                                    request,
                                    "consensus approved response action",
                                );
                                (
                                    Some(lease),
                                    AuditResponseRecord::Failure(receipt.into_failure()),
                                    None,
                                    false,
                                    false,
                                )
                            }
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
            };

        tracing::info!(
            correlation_id = %Self::correlation_id(context),
            hunt_id = %request.hunt_id.0,
            event_id = %detection.event_id,
            action = %request.action.kind(),
            response_kind = match &response {
                AuditResponseRecord::Success(_) => "success",
                AuditResponseRecord::Failure(_) => "failure",
                AuditResponseRecord::Skipped { .. } => "skipped",
                AuditResponseRecord::GuardRejected { .. } => "guard_rejected",
            },
            response_attempted,
            response_succeeded,
            module = module_path!(),
            "response stage completed"
        );

        Ok(RuntimeExecutionReport {
            audit: AuditTrail {
                trail_id: format!("trail:{}:{}", request.hunt_id.0, context.now_ms),
                hunt_id: request.hunt_id.0.clone(),
                related_receipt_ids: context.receipt_chain.clone(),
                detection: detection.clone(),
                policy: PolicyRecord {
                    verdict: decision.verdict,
                    rule_name: decision.rule_name,
                    reason: decision.reason,
                    lease,
                },
                response,
                created_at_ms: context.now_ms,
            },
            policy_elapsed_us,
            response_elapsed_us,
            response_attempted,
            response_succeeded,
        })
    }
}

fn ensure_active_lease(
    lease: &swarm_policy::CapabilityLease,
    now_ms: i64,
) -> Result<(), ApprovalError> {
    if lease.expires_at_ms <= now_ms {
        return Err(ApprovalError::Denied(
            "capability lease expired".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{RuntimeMode, SwarmRuntime, TemporalEventWindowConfig, TemporalEventWindowError};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use swarm_core::ThreatClass;
    use swarm_core::telemetry::{ProcessStartEvent, TelemetryEvent, TelemetryPayload};
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
    use swarm_guard::{
        Guard, GuardAction, GuardContext, GuardPipeline, GuardResult, Severity as GuardSeverity,
    };
    use swarm_policy::static_gate::StaticApprovalGate;
    use swarm_policy::{ActionRequest, ApprovalContext, PolicyVerdict};
    use swarm_response::{
        ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt, ResponseStatus,
        adapters::SandboxExecutor,
    };
    use swarm_spine::AuditResponseRecord;
    use swarm_whisker::TelemetryEventPredicate;

    #[derive(Clone)]
    struct RecordingExecutor {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ResponseExecutor for RecordingExecutor {
        async fn execute(
            &self,
            request: &ActionRequest,
            _lease: &swarm_policy::CapabilityLease,
            mode: ExecutionMode,
        ) -> Result<ResponseReceipt, ResponseError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ResponseReceipt {
                receipt_id: format!("receipt:{}", request.hunt_id.0),
                action: request.action.kind().to_string(),
                mode,
                status: if matches!(mode, ExecutionMode::DryRun) {
                    ResponseStatus::Simulated
                } else {
                    ResponseStatus::Executed
                },
                summary: "executed".to_string(),
                details: serde_json::json!({}),
                audit: Default::default(),
            })
        }
    }

    struct FixedGuard {
        allow: bool,
        name: &'static str,
        message: &'static str,
    }

    impl Guard for FixedGuard {
        fn name(&self) -> &str {
            self.name
        }

        fn handles(&self, _action: &GuardAction<'_>) -> bool {
            true
        }

        fn check(&self, _action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
            if self.allow {
                GuardResult::allow(self.name)
            } else {
                GuardResult::block(self.name, GuardSeverity::Critical, self.message)
            }
        }
    }

    fn sample_context() -> ApprovalContext {
        ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-1".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_000_000,
        }
    }

    fn process_event_at(
        event_id: &str,
        timestamp: i64,
        parent_process: &str,
        process_name: &str,
    ) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: event_id.to_string(),
            timestamp,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: parent_process.to_string(),
                process_name: process_name.to_string(),
                command_line: format!("{process_name}.exe"),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        }
    }

    #[test]
    fn temporal_event_window_prunes_by_retention_and_count() {
        let runtime = SwarmRuntime::new(
            RuntimeMode::DetectOnly,
            StaticApprovalGate::default(),
            SandboxExecutor,
        )
        .with_temporal_event_window_config(TemporalEventWindowConfig {
            retention_ms: 60_000,
            max_events: 2,
            max_match_span_ms: 60_000,
            max_predicates_per_match: 4,
        });

        runtime.record_temporal_event(&process_event_at("evt-1", 1_700_000_000, "explorer", "cmd"));
        runtime.record_temporal_event(&process_event_at(
            "evt-2",
            1_700_000_030,
            "explorer",
            "whoami",
        ));
        runtime.record_temporal_event(&process_event_at("evt-3", 1_700_000_061, "explorer", "net"));

        let snapshot = runtime.temporal_event_window_snapshot();
        assert_eq!(snapshot.retained_events, 2);
        assert_eq!(snapshot.oldest_timestamp_ms, Some(1_700_000_030_000));
        assert_eq!(snapshot.newest_timestamp_ms, Some(1_700_000_061_000));
        assert_eq!(snapshot.watermark_ms, Some(1_700_000_061_000));
    }

    #[test]
    fn temporal_event_window_matches_ordered_predicates_within_span() {
        let runtime = SwarmRuntime::new(
            RuntimeMode::DetectOnly,
            StaticApprovalGate::default(),
            SandboxExecutor,
        )
        .with_temporal_event_window_config(TemporalEventWindowConfig {
            retention_ms: 300_000,
            max_events: 8,
            max_match_span_ms: 120_000,
            max_predicates_per_match: 4,
        });

        runtime.record_temporal_event(&process_event_at(
            "evt-seq-2",
            1_700_000_060,
            "powershell",
            "cmd",
        ));
        runtime.record_temporal_event(&process_event_at(
            "evt-seq-1",
            1_700_000_000,
            "winword",
            "powershell",
        ));
        runtime.record_temporal_event(&process_event_at(
            "evt-seq-3",
            1_700_000_090,
            "services",
            "sc",
        ));

        let step_one = |event: &TelemetryEvent| {
            matches!(
                &event.payload,
                TelemetryPayload::ProcessStart(process)
                    if process.parent_process.eq_ignore_ascii_case("winword")
                        && process.process_name.eq_ignore_ascii_case("powershell")
            )
        };
        let step_two = |event: &TelemetryEvent| {
            matches!(
                &event.payload,
                TelemetryPayload::ProcessStart(process)
                    if process.parent_process.eq_ignore_ascii_case("powershell")
                        && process.process_name.eq_ignore_ascii_case("cmd")
            )
        };
        let predicates: [&dyn TelemetryEventPredicate; 2] = [&step_one, &step_two];

        let matched = runtime
            .match_temporal_sequence(&predicates, Some(90_000))
            .unwrap()
            .unwrap();
        assert_eq!(matched.matched_events.len(), 2);
        assert_eq!(matched.matched_events[0].event_id, "evt-seq-1");
        assert_eq!(matched.matched_events[1].event_id, "evt-seq-2");
        assert_eq!(matched.started_at_ms, 1_700_000_000_000);
        assert_eq!(matched.ended_at_ms, 1_700_000_060_000);
        assert_eq!(matched.span_ms, 60_000);
    }

    #[test]
    fn temporal_event_window_rejects_query_outside_bounds() {
        let runtime = SwarmRuntime::new(
            RuntimeMode::DetectOnly,
            StaticApprovalGate::default(),
            SandboxExecutor,
        )
        .with_temporal_event_window_config(TemporalEventWindowConfig {
            retention_ms: 300_000,
            max_events: 8,
            max_match_span_ms: 30_000,
            max_predicates_per_match: 2,
        });

        let any_event = |_: &TelemetryEvent| true;
        let predicates: [&dyn TelemetryEventPredicate; 3] = [&any_event, &any_event, &any_event];
        let error = runtime
            .match_temporal_sequence(&predicates, Some(45_000))
            .unwrap_err();
        assert_eq!(
            error,
            TemporalEventWindowError::TooManyPredicates {
                requested: 3,
                max_allowed: 2,
            }
        );

        let predicates: [&dyn TelemetryEventPredicate; 1] = [&any_event];
        let error = runtime
            .match_temporal_sequence(&predicates, Some(45_000))
            .unwrap_err();
        assert_eq!(
            error,
            TemporalEventWindowError::RequestedSpanExceedsConfiguredLimit {
                requested_ms: 45_000,
                max_allowed_ms: 30_000,
            }
        );
    }

    #[tokio::test]
    async fn detect_only_runtime_executes_as_dry_run() {
        let runtime = SwarmRuntime::new(
            RuntimeMode::DetectOnly,
            StaticApprovalGate::default(),
            SandboxExecutor,
        );
        let request = ActionRequest {
            hunt_id: HuntId("hunt-1".to_string()),
            requested_by: AgentId("whisker-a".to_string()),
            action: ResponseAction::BlockEgress {
                target: "203.0.113.5".to_string(),
            },
            severity: Severity::Critical,
            evidence: serde_json::json!({"signal": "suspicious-egress"}),
        };

        let receipt = runtime
            .authorize_and_execute(&request, &sample_context())
            .await
            .unwrap();
        assert_eq!(receipt.mode, ExecutionMode::DryRun);
        assert_eq!(receipt.status, ResponseStatus::Simulated);
    }

    #[tokio::test]
    async fn live_runtime_blocks_human_gated_actions() {
        let runtime = SwarmRuntime::new(
            RuntimeMode::LiveResponse,
            StaticApprovalGate::default(),
            SandboxExecutor,
        );
        let request = ActionRequest {
            hunt_id: HuntId("hunt-1".to_string()),
            requested_by: AgentId("whisker-a".to_string()),
            action: ResponseAction::IsolateHost {
                host_id: "host-1".to_string(),
            },
            severity: Severity::Critical,
            evidence: serde_json::json!({"signal": "active-exploit"}),
        };

        let error = runtime
            .authorize_and_execute(&request, &sample_context())
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("authorized but held for human approval")
        );
    }

    #[tokio::test]
    async fn human_approved_live_runtime_executes_human_gated_action() {
        let calls = Arc::new(AtomicUsize::new(0));
        let runtime = SwarmRuntime::new(
            RuntimeMode::LiveResponse,
            StaticApprovalGate::default(),
            RecordingExecutor {
                calls: Arc::clone(&calls),
            },
        );
        let request = ActionRequest {
            hunt_id: HuntId("hunt-approved".to_string()),
            requested_by: AgentId("whisker-a".to_string()),
            action: ResponseAction::IsolateHost {
                host_id: "host-1".to_string(),
            },
            severity: Severity::Critical,
            evidence: serde_json::json!({"signal": "active-exploit"}),
        };
        let detection = swarm_whisker::DetectionFinding {
            finding_id: "finding-approved".to_string(),
            event_id: "evt-approved".to_string(),
            threat_class: ThreatClass::Execution,
            severity: Severity::Critical,
            confidence: 0.99,
            evidence: request.evidence.clone(),
            strategy_id: "test".to_string(),
        };

        let report = runtime
            .audit_authorize_and_execute_human_approved_instrumented(
                &detection,
                &request,
                &sample_context(),
            )
            .await
            .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        match report.audit.response {
            AuditResponseRecord::Success(receipt) => {
                assert_eq!(receipt.status, ResponseStatus::Executed);
                assert_eq!(receipt.mode, ExecutionMode::Enforced);
            }
            other => panic!("expected success response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn live_runtime_rehearsal_executes_human_gated_action_as_dry_run() {
        let calls = Arc::new(AtomicUsize::new(0));
        let runtime = SwarmRuntime::new(
            RuntimeMode::LiveResponse,
            StaticApprovalGate::default(),
            RecordingExecutor {
                calls: Arc::clone(&calls),
            },
        );
        let request = ActionRequest {
            hunt_id: HuntId("hunt-rehearsal".to_string()),
            requested_by: AgentId("whisker-a".to_string()),
            action: ResponseAction::IsolateHost {
                host_id: "host-1".to_string(),
            },
            severity: Severity::Critical,
            evidence: serde_json::json!({"signal": "active-exploit"}),
        };
        let detection = swarm_whisker::DetectionFinding {
            finding_id: "finding-rehearsal".to_string(),
            event_id: "evt-rehearsal".to_string(),
            threat_class: ThreatClass::Execution,
            severity: Severity::Critical,
            confidence: 0.99,
            evidence: request.evidence.clone(),
            strategy_id: "test".to_string(),
        };

        let report = runtime
            .audit_rehearse_authorize_and_execute_instrumented(
                &detection,
                &request,
                &sample_context(),
            )
            .await
            .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(report.audit.policy.verdict, PolicyVerdict::RequireHuman);
        match report.audit.response {
            AuditResponseRecord::Success(receipt) => {
                assert_eq!(receipt.status, ResponseStatus::Simulated);
                assert_eq!(receipt.mode, ExecutionMode::DryRun);
            }
            other => panic!("expected success response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn live_runtime_executes_allowed_action() {
        let runtime = SwarmRuntime::new(
            RuntimeMode::LiveResponse,
            StaticApprovalGate::default(),
            SandboxExecutor,
        );
        let request = ActionRequest {
            hunt_id: HuntId("hunt-1".to_string()),
            requested_by: AgentId("whisker-a".to_string()),
            action: ResponseAction::DeployDecoy {
                decoy_type: "honeypot".to_string(),
                target_zone: "dmz".to_string(),
            },
            severity: Severity::Medium,
            evidence: serde_json::json!({"signal": "lure"}),
        };

        let receipt = runtime
            .authorize_and_execute(&request, &sample_context())
            .await
            .unwrap();
        assert_eq!(receipt.mode, ExecutionMode::Enforced);
        assert_eq!(receipt.status, ResponseStatus::Executed);
    }

    #[tokio::test]
    async fn live_runtime_denies_low_severity_destructive_action() {
        let runtime = SwarmRuntime::new(
            RuntimeMode::LiveResponse,
            StaticApprovalGate::default(),
            SandboxExecutor,
        );
        let request = ActionRequest {
            hunt_id: HuntId("hunt-2".to_string()),
            requested_by: AgentId("whisker-a".to_string()),
            action: ResponseAction::IsolateHost {
                host_id: "host-2".to_string(),
            },
            severity: Severity::Low,
            evidence: serde_json::json!({"signal": "weak-indicator"}),
        };

        let error = runtime
            .authorize_and_execute(&request, &sample_context())
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("destructive actions require at least medium severity")
        );
    }

    #[tokio::test]
    async fn guard_rejection_prevents_execution() {
        let calls = Arc::new(AtomicUsize::new(0));
        let runtime = SwarmRuntime::new(
            RuntimeMode::DetectOnly,
            StaticApprovalGate::default(),
            RecordingExecutor {
                calls: Arc::clone(&calls),
            },
        )
        .with_guard_pipeline(GuardPipeline::new(vec![Box::new(FixedGuard {
            allow: false,
            name: "test_guard",
            message: "blocked by test",
        })]));
        let request = ActionRequest {
            hunt_id: HuntId("hunt-guard".to_string()),
            requested_by: AgentId("whisker-a".to_string()),
            action: ResponseAction::DeployDecoy {
                decoy_type: "honeypot".to_string(),
                target_zone: "dmz".to_string(),
            },
            severity: Severity::High,
            evidence: serde_json::json!({"signal": "guard-test"}),
        };
        let detection = swarm_whisker::DetectionFinding {
            finding_id: "finding-guard".to_string(),
            event_id: "evt-guard".to_string(),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence: 0.9,
            evidence: serde_json::json!({"signal": "guard-test"}),
            strategy_id: "strategy-1".to_string(),
        };

        let report = runtime
            .audit_authorize_and_execute_instrumented(&detection, &request, &sample_context())
            .await
            .unwrap();

        assert!(!report.response_attempted);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            report.audit.response,
            AuditResponseRecord::GuardRejected { .. }
        ));
    }

    #[tokio::test]
    async fn guard_allows_execution_proceeds() {
        let calls = Arc::new(AtomicUsize::new(0));
        let runtime = SwarmRuntime::new(
            RuntimeMode::DetectOnly,
            StaticApprovalGate::default(),
            RecordingExecutor {
                calls: Arc::clone(&calls),
            },
        )
        .with_guard_pipeline(GuardPipeline::new(vec![Box::new(FixedGuard {
            allow: true,
            name: "test_guard",
            message: "allowed",
        })]));
        let request = ActionRequest {
            hunt_id: HuntId("hunt-allow".to_string()),
            requested_by: AgentId("whisker-a".to_string()),
            action: ResponseAction::DeployDecoy {
                decoy_type: "honeypot".to_string(),
                target_zone: "dmz".to_string(),
            },
            severity: Severity::High,
            evidence: serde_json::json!({"signal": "guard-test"}),
        };
        let detection = swarm_whisker::DetectionFinding {
            finding_id: "finding-allow".to_string(),
            event_id: "evt-allow".to_string(),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence: 0.9,
            evidence: serde_json::json!({"signal": "guard-test"}),
            strategy_id: "strategy-1".to_string(),
        };

        let report = runtime
            .audit_authorize_and_execute_instrumented(&detection, &request, &sample_context())
            .await
            .unwrap();

        assert!(report.response_attempted);
        assert!(report.response_succeeded);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(matches!(
            report.audit.response,
            AuditResponseRecord::Success(_)
        ));
    }
}
