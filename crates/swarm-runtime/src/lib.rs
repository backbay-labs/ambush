//! Rust-first runtime orchestration for Ambush.
//!
//! This crate is the intended composition root for the production runtime:
//! detection stays in Rust, policy stays deterministic, and live response
//! execution is capability-scoped.
//!
//! # Three agent roles are still declared here (SPLIT-03, phase 282)
//!
//! **Not because of `ingest/` any more. See ADR 0007.**
//!
//! SPLIT-03 moved the `*_agent` role implementations to `swarm-agents`, so that
//! consumers of the composition root stop compiling behaviour they never call.
//! Five of the eight have gone: `pounce`, `stalker`, `weaver`, `whisker`, and now
//! `tom`. Three did not, and are declared below with a marker on each --
//! `calico_agent`, `kitten_agent`, `sphinx_agent`.
//!
//! `ingest/` NO LONGER HOLDS THEM. It was the pin ADR 0004 recorded, and SPLIT-05
//! took it out of this crate. The one non-test back-edge ADR 0004 named --
//! `ingest/providence_handlers.rs` -> `kitten_agent::route_feedback_signal` --
//! is now a forward edge from `swarm-ingest-runtime` into this crate, which is
//! the direction Cargo permits. Nothing outside the three files names them here
//! at all, in test code or otherwise:
//!
//! ```text
//! $ grep -rn --include='*.rs' 'crate::\(calico\|kitten\|sphinx\)_agent' \
//!     crates/swarm-runtime/src/ | grep -v '_agent.rs:' | grep -v '//!'
//! $
//! ```
//!
//! SOMETHING ELSE HOLDS THEM. `kitten_agent.rs:828`, inside
//! `fn build_population_proposal` and 1,697 lines above the file's
//! `#[cfg(test)]` module, calls `EvolutionDetectorGenome::strategy()` --
//! `pub(crate)` at `mutation/types.rs:137`. Moving the file produces
//! `error[E0624]: method 'strategy' is private`, and the only mechanical fix is
//! a FOURTH widening against a baseline of three. ADR 0007 records why that is
//! not taken here.
//!
//! A PATH GREP CANNOT SEE THAT PIN, which is why the grep above reads clean.
//! `strategy()` is called as a method on a value of an already-`pub` type
//! obtained from an already-`pub` accessor, so no `crate::` path appears at the
//! call site or in the import block. Only the compiler finds this class of pin:
//! `git mv` the three files, repoint their `crate::` paths, and read
//! `cargo check -p swarm-agents --all-targets`.
//!
//! The three also have to move as ONE commit whenever they do move. `sphinx` and
//! `kitten` read `calico`, `kitten`'s test module reads `sphinx`, and nothing
//! else in this crate reads any of them. Moving `calico` first puts
//! `swarm_agents::calico_agent` in this crate's non-test code and Cargo rejects
//! the manifest; moving either reader first widens all nine of `calico_agent`'s
//! `pub(crate)` items to permanent public API. Together they stay `pub(crate)`,
//! which was the whole reason ADR 0004 said to wait.
//!
//! `tom` did not have to wait for the group. It named nothing in this crate --
//! `grep -oE '(crate|super)::[A-Za-z_:]+' src/tom_agent.rs` printed only its own
//! file-local `super::now_ms` -- and its `GovernanceAuthority` and
//! `SealedGovernanceAuthority` impls name `swarm-policy` directly, so the seal is
//! satisfied from `swarm-agents` unchanged. `dispatcher.rs`'s one reference to it
//! was `#[cfg(test)]` and now reaches `swarm_agents::tom_agent` through the
//! dev-dependency edge this crate already carries.
//!
//! IF THIS CHANGES: SPLIT-03 unblocks when SPLIT-04 moves `mutation/` to
//! `swarm-evolution`, which puts `strategy()` and its 12 remaining callers on
//! the far side of the same crate line and leaves `kitten` reading ordinary
//! public API of a leaf crate. The alternative is a recorded decision to widen
//! `strategy()`, with an allowlist line in
//! `tools/check-visibility-baseline.sh`. The progress measure is
//! `ls crates/swarm-runtime/src/*_agent.rs | wc -l`: it prints 3 today, printed
//! 4 before `tom` moved, and has to reach 0.
//! `docs/decisions/0004-split-03-four-of-eight-agents-pinned-by-ingest.md`
//! records the original `ingest/` pin,
//! `docs/decisions/0006-split-05-ingest-extraction-and-its-three-widenings.md`
//! its removal, and
//! `docs/decisions/0007-split-03-kitten-pinned-by-a-private-method-not-by-ingest.md`
//! the pin that replaced it.
//!
//! # Seven evolution modules are still declared here (SPLIT-04, phase 282)
//!
//! SPLIT-04 moved the evolution lane's leaf modules to `swarm-evolution`:
//! `evidence`, `governance_prep`, `operator_maintenance` and `portfolio`. Seven
//! of the ten modules it named did not go -- `canary`, `drafting`, `evolution`,
//! `mutation`, `promotion`, `selection`, `strategy` -- because the edge runs
//! `swarm-evolution -> swarm-runtime` (the lane reads `crate::replay`, which
//! stays), so anything this crate still names cannot move.
//!
//! Three other files here name those seven (`kitten_agent.rs`,
//! `sphinx_agent.rs`, `evolution_status.rs` -- `ingest/mod.rs` and
//! `ingest/tests.rs` left with SPLIT-05), but they are
//! corroborating, not load-bearing: **this file alone pins all seven**, in
//! three steps. `StrategyProposalRouteError` below names `drafting`,
//! `mutation`, `selection`, `evolution` and `canary` by `#[from]`; `strategy`
//! is named by four of those five; `promotion` is named by `strategy.rs` and
//! by nothing else in the crate. Reversing the crate edge instead is rejected
//! outright:
//!
//! ```text
//! error: cyclic package dependency: package `swarm-runtime` depends on itself.
//! ```
//!
//! IF THIS CHANGES: SPLIT-04 does NOT unblock when `ingest/` leaves -- the
//! crate root outlives every extraction in phase 282. It unblocks when
//! `StrategyProposalRouteError` stops naming the lane's concrete error types,
//! which needs the sealed-boundary inversion SPLIT-03 applied to
//! `swarm_core::agent::AgentTickError`, because `dispatcher.rs`'s
//! `StrategyProposalRouter` trait keeps the enum here too. The progress measure
//! is
//! `grep -rcE 'crate::(canary|drafting|evolution|mutation|promotion|selection|strategy)::'
//! src/lib.rs src/kitten_agent.rs src/sphinx_agent.rs src/evolution_status.rs`:
//! it sums to 38 today and has to reach 0. It read 58 over five files before
//! SPLIT-05; the 20 that went are `ingest/`'s, and they left the crate rather
//! than being removed, so the drop measures the extraction and not progress on
//! SPLIT-04's blocker. The full argument, and what SPLIT-04
//! did and did not buy for replay, is in
//! `docs/decisions/0005-split-04-evolution-lane-pinned-by-the-crate-root.md`.
#![allow(clippy::result_large_err)]

extern crate self as swarm_runtime;

pub mod agent_identity;
pub mod alert_tuning;
pub mod approval;
pub mod calico_agent; // SPLIT-03: pinned by `mutation::EvolutionDetectorGenome::strategy`, ADR 0007
pub mod canary;
pub mod config;
pub mod containment;
pub mod correlation;
pub mod detection;
pub mod detector_factory;
pub mod dispatcher;
pub mod drafting;
pub mod escalation;
pub mod evasion_coverage;
pub mod evolution;
pub mod evolution_status;
pub mod http;
pub mod investigation;
pub mod kitten_agent; // SPLIT-03: pinned by `mutation::EvolutionDetectorGenome::strategy`, ADR 0007
pub mod mutation;
pub mod promotion;
pub mod providence;
pub mod red_swarm;
pub mod replay;
pub mod runtime_events;
pub mod selection;
pub mod sequence_detector;
pub mod service;
pub mod sphinx_agent; // SPLIT-03: pinned by `mutation::EvolutionDetectorGenome::strategy`, ADR 0007
pub mod startup_attestation;
pub mod strategy;
pub mod threat_intel_runtime;

use std::sync::{Arc, Mutex};
use std::time::Instant;
use swarm_consensus::ConsensusGovernanceReceipt;
// Re-exported so `crate::AgentTickBoundaryError` and friends keep resolving inside
// this crate. The definitions moved to `swarm_core::agent` in SPLIT-03: the
// composition root must not name concrete agent types, and the agents must not
// import back out of the root. See `swarm_core::agent::AgentTickError`.
pub use swarm_core::agent::{
    AgentPanicBoundaryError, AgentTickBoundaryError, AgentTickError, agent_tick_error_boundary,
    agent_tick_error_role, agent_tick_panic_error,
};
pub use swarm_core::config::RuntimeMode;
use swarm_core::config::TemporalEventWindowConfig;
use swarm_core::types::AgentId;
use swarm_guard::{GuardAction, GuardContext, GuardPipeline};
use swarm_policy::{ActionRequest, ApprovalContext, ApprovalError, ApprovalGate};
use swarm_response::{
    ExecutionMode, ResponseError, ResponseExecutor, ResponseFailure, ResponseReceipt,
    ResponseStatus,
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

    #[error(
        "governed action `{action}` refused in enforced mode: dispatcher governance admission is required"
    )]
    GovernedActionRequiresAdmission { action: &'static str },

    #[error("governance authorization refused: {0}")]
    GovernanceAuthorization(String),

    /// A containment was refused BEFORE it executed because it could not have
    /// been leased. The world is unchanged.
    #[error("containment `{action}` refused: {reason}")]
    ContainmentRefused {
        action: &'static str,
        reason: String,
    },

    /// A containment EXECUTED and its lease could not be persisted. The world IS
    /// changed and nothing bounds it.
    ///
    /// This is a distinct variant from [`RuntimeError::ContainmentRefused`] on
    /// purpose. Both are failures, but only one of them leaves a host contained,
    /// and an operator reading the log has to be able to tell which without
    /// parsing prose.
    #[error(
        "containment `{action}` EXECUTED (receipt `{receipt_id}`) but its lease could not be \
         recorded: {reason}. The containment is now unbounded and must be released manually."
    )]
    ContainmentLeaseNotRecorded {
        action: &'static str,
        receipt_id: String,
        reason: String,
    },
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

/// A configured containment lease store, and the lifetime every lease it holds
/// is opened with.
///
/// ONE binding rather than two `Option`s. A store with no TTL would open
/// unbounded leases and a TTL with no store would bound nothing; neither is a
/// configuration this runtime can act on, so neither is representable.
#[derive(Clone)]
pub struct ContainmentBinding {
    store: Arc<dyn swarm_response::containment::ContainmentLeaseStore>,
    ttl: swarm_response::containment::ContainmentTtl,
}

impl std::fmt::Debug for ContainmentBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContainmentBinding")
            .field("store", &self.store)
            .field("ttl_ms", &self.ttl.get())
            .finish()
    }
}

/// Everything needed to open a lease, derived before the containment runs.
///
/// Derived BEFORE rather than after because deriving it can fail (the inverse
/// plan needs a non-empty host/file/session), and a containment whose inverse
/// cannot even be described must not execute.
struct PreparedContainment {
    store: Arc<dyn swarm_response::containment::ContainmentLeaseStore>,
    ttl: swarm_response::containment::ContainmentTtl,
    preview: swarm_core::types::ResponseRehearsalPreview,
    issued_at_ms: i64,
}

/// Swarm runtime wiring detection, policy, and response into one Rust service.
pub struct SwarmRuntime<P, E> {
    mode: RuntimeMode,
    policy: P,
    response: E,
    guard_pipeline: Option<GuardPipeline>,
    temporal_event_window: TemporalEventWindow,
    containment: Option<ContainmentBinding>,
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

struct EvaluatedExecution<'a> {
    detection: &'a DetectionFinding,
    request: &'a ActionRequest,
    context: &'a ApprovalContext,
    decision: swarm_policy::PolicyDecision,
    policy_elapsed_us: u64,
    execution_mode: ExecutionMode,
    allow_human_approved_execution: bool,
    verified_governance_receipt: Option<(&'a ConsensusGovernanceReceipt, &'a serde_json::Value)>,
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
            containment: None,
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

    /// Attach the store that will hold a lease for every enforced containment,
    /// and the lifetime each lease gets.
    ///
    /// Without this, an ENFORCED containment is refused (see
    /// [`SwarmRuntime::prepare_containment`]). Detect-only runtimes need no
    /// store: nothing they do takes effect, so there is nothing to undo.
    pub fn with_containment_store(
        mut self,
        store: Arc<dyn swarm_response::containment::ContainmentLeaseStore>,
        ttl: swarm_response::containment::ContainmentTtl,
    ) -> Self {
        self.containment = Some(ContainmentBinding { store, ttl });
        self
    }

    /// The configured containment lease store, if any.
    pub fn containment_store(
        &self,
    ) -> Option<&Arc<dyn swarm_response::containment::ContainmentLeaseStore>> {
        self.containment.as_ref().map(|binding| &binding.store)
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
        self.audit_governance_veto_with_receipt(
            detection,
            request,
            context,
            governing_agent_id,
            reason,
            None,
        )
    }

    pub fn audit_admitted_governance_veto(
        &self,
        detection: &DetectionFinding,
        veto: &crate::dispatcher::GovernanceVetoRoute,
        context: &ApprovalContext,
    ) -> AuditTrail {
        self.audit_governance_veto_with_receipt(
            detection,
            veto.request(),
            context,
            veto.governing_agent_id(),
            veto.reason(),
            veto.verified_governance_receipt(),
        )
    }

    fn audit_governance_veto_with_receipt(
        &self,
        detection: &DetectionFinding,
        request: &ActionRequest,
        context: &ApprovalContext,
        governing_agent_id: &AgentId,
        reason: impl Into<String>,
        verified_governance_receipt: Option<&serde_json::Value>,
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
            verified_governance_receipt.cloned(),
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

    fn require_dispatcher_admission(
        request: &ActionRequest,
        execution_mode: ExecutionMode,
        admitted: bool,
    ) -> Result<(), RuntimeError> {
        if execution_mode == ExecutionMode::Enforced
            && request.action.requires_governance_receipt()
            && !admitted
        {
            return Err(RuntimeError::GovernedActionRequiresAdmission {
                action: request.action.kind(),
            });
        }
        Ok(())
    }

    /// Decide, BEFORE anything executes, whether this action needs a containment
    /// lease and whether one can be opened.
    ///
    /// FAIL CLOSED, AND SCOPED TO WHAT ACTUALLY TAKES EFFECT. An enforced
    /// containment with no lease store is refused here rather than executed and
    /// forgotten: an executed containment with no lease is exactly the unbounded
    /// containment this lane exists to remove, and refusing before
    /// `self.response.execute` is the only point at which the world is still
    /// unchanged. The gate keys on the EXECUTION mode, not the runtime mode, so
    /// a dry run opens no lease -- a lease over a simulated containment would
    /// later have the sweep issue a real inverse for something that never
    /// happened.
    ///
    /// Non-containment actions never reach the store at all.
    fn prepare_containment(
        &self,
        request: &ActionRequest,
        context: &ApprovalContext,
        execution_mode: ExecutionMode,
    ) -> Result<Option<PreparedContainment>, RuntimeError> {
        if !crate::containment::is_containment_action(&request.action) {
            return Ok(None);
        }
        if execution_mode == ExecutionMode::DryRun {
            return Ok(None);
        }

        // INVARIANT: RUNTIME-CONTAINMENT-NEEDS-STORE
        let Some(binding) = self.containment.as_ref() else {
            return Err(RuntimeError::ContainmentRefused {
                action: request.action.kind(),
                reason: "no containment lease store is configured, so this containment could not \
                         be bounded or undone; attach one with \
                         `SwarmRuntime::with_containment_store`"
                    .to_string(),
            });
        };

        // The same derivation the operator-facing rehearsal uses, so the plan on
        // the lease is the plan a human was shown.
        // INVARIANT: RUNTIME-CONTAINMENT-PREVIEW-REQUIRED
        let preview = crate::service::preview::build_rehearsal_preview(
            request,
            &format!("containment-lease:{}", request.hunt_id.0),
            context.now_ms,
        )
        .map_err(|error| RuntimeError::ContainmentRefused {
            action: request.action.kind(),
            reason: format!("its inverse plan could not be derived: {error}"),
        })?;

        Ok(Some(PreparedContainment {
            store: binding.store.clone(),
            ttl: binding.ttl,
            preview,
            issued_at_ms: context.now_ms,
        }))
    }

    /// Persist the lease for a containment that just took effect.
    ///
    /// Called AFTER execution because the lease chains to the response receipt,
    /// which does not exist until then. The failure path is therefore loud
    /// rather than silent: see [`RuntimeError::ContainmentLeaseNotRecorded`].
    fn record_containment_lease(
        prepared: &PreparedContainment,
        request: &ActionRequest,
        receipt: &ResponseReceipt,
        governance_receipt: Option<&ConsensusGovernanceReceipt>,
    ) -> Result<(), RuntimeError> {
        let lease_id = format!(
            "containment:{}:{}:{}",
            request.hunt_id.0,
            request.action.kind(),
            receipt.receipt_id
        );
        let governance_receipt_id =
            governance_receipt.map(|governance| governance.payload.receipt_id.clone());

        let lease = swarm_response::containment::ContainmentLease::open(
            lease_id,
            request.action.clone(),
            receipt.receipt_id.clone(),
            governance_receipt_id,
            &prepared.preview,
            prepared.issued_at_ms,
            prepared.ttl,
        )
        .map_err(|error| RuntimeError::ContainmentLeaseNotRecorded {
            action: request.action.kind(),
            receipt_id: receipt.receipt_id.clone(),
            reason: error.to_string(),
        })?;

        if !swarm_response::rollback::plan_is_reversible(&lease) {
            // Recorded rather than refused: refusing here would leave the
            // containment executed AND unleased, which is strictly worse. The
            // lease still bounds it, and its rollback receipt will say plainly
            // that nothing was restored.
            tracing::warn!(
                module = module_path!(),
                lease_id = %lease.lease_id(),
                action = request.action.kind(),
                receipt_id = %receipt.receipt_id,
                "containment leased but its planned inverse cannot restore the pre-containment \
                 state; expiry will close the lease without undoing the effect"
            );
        }

        prepared.store.open_lease(&lease).map_err(|error| {
            RuntimeError::ContainmentLeaseNotRecorded {
                action: request.action.kind(),
                receipt_id: receipt.receipt_id.clone(),
                reason: error.to_string(),
            }
        })?;

        tracing::info!(
            module = module_path!(),
            lease_id = %lease.lease_id(),
            action = request.action.kind(),
            origin_receipt_id = %lease.origin_receipt_id(),
            scope = %lease.blast_radius().scope_value,
            expires_at_ms = lease.expires_at_ms(),
            "containment leased"
        );
        Ok(())
    }

    fn decorate_receipt_with_governance(
        receipt: ResponseReceipt,
        governance_receipt: Option<(&ConsensusGovernanceReceipt, &serde_json::Value)>,
        reason: impl Into<String>,
    ) -> ResponseReceipt {
        let Some((governance_receipt, receipt_value)) = governance_receipt else {
            return receipt;
        };
        receipt.with_governance_audit(
            governance_receipt.payload.issued_by.clone(),
            reason.into(),
            Some(receipt_value.clone()),
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
        let execution_mode = self.execution_mode();
        Self::require_dispatcher_admission(request, execution_mode, false)?;
        // INVARIANT: RUNTIME-POLICY-ERROR-BLOCKS-EXECUTION
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
            // INVARIANT: RUNTIME-DENY-BLOCKS-EXECUTION
            swarm_policy::PolicyVerdict::Deny => {
                return Err(ApprovalError::Denied(decision.reason.clone()).into());
            }
            // INVARIANT: RUNTIME-HUMAN-GATE-BLOCKS-LIVE
            swarm_policy::PolicyVerdict::RequireHuman if self.mode == RuntimeMode::LiveResponse => {
                return Err(ApprovalError::Denied(decision.reason.clone()).into());
            }
            swarm_policy::PolicyVerdict::Allow | swarm_policy::PolicyVerdict::RequireHuman => {}
        }

        // INVARIANT: RUNTIME-GUARD-REJECTION-BLOCKS-EXECUTION
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

        // Before `execute`, so a containment that cannot be leased never
        // reaches a host.
        let prepared_containment =
            self.prepare_containment(request, context, self.execution_mode())?;

        // INVARIANT: RUNTIME-LEASE-ISSUE-ERROR-BLOCKS-EXECUTION
        let lease = self.policy.issue_lease(request, context)?;
        ensure_active_lease(&lease, context.now_ms)?;
        // INVARIANT: RUNTIME-ADAPTER-ERROR-NOT-SUCCESS
        let receipt = self
            .response
            .execute(request, &lease, execution_mode)
            .await
            .map_err(RuntimeError::from)?
            .with_policy_audit(
                decision.verdict,
                decision.rule_name.clone(),
                decision.reason.clone(),
            );
        let receipt = Self::decorate_receipt_with_governance(
            receipt,
            None,
            "consensus approved response action",
        );
        // INVARIANT: RUNTIME-FAILED-RECEIPT-NOT-SUCCESS
        if !receipt.status.indicates_success() {
            return Err(RuntimeError::Response(ResponseError {
                failure: receipt.into_failure(),
            }));
        }
        if let Some(prepared) = prepared_containment.as_ref() {
            Self::record_containment_lease(prepared, request, &receipt, None)?;
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

    /// Execute a request carrying the dispatcher's opaque, already-consumed
    /// governance admission. The runtime trusts the type boundary and never parses or
    /// verifies the bearer receipt again.
    pub async fn audit_authorize_and_execute_admitted(
        &self,
        admitted: crate::dispatcher::RoutedActionRequest,
    ) -> Result<AuditTrail, RuntimeError> {
        let (permit, governance, human_approval) = admitted.into_parts();
        let (request, detection, context, decision, policy_elapsed_us) =
            permit.into_execution_parts();
        let governance = governance.as_ref().map(|(receipt, value)| (receipt, value));
        Ok(self
            .audit_execute_evaluated(EvaluatedExecution {
                detection: &detection,
                request: &request,
                context: &context,
                decision,
                policy_elapsed_us,
                execution_mode: self.execution_mode(),
                allow_human_approved_execution: human_approval.is_some(),
                verified_governance_receipt: governance,
            })
            .await?
            .audit)
    }

    /// Evaluate ordinary policy once for the dispatcher without consuming
    /// governance and without reaching guards, leases, or the executor.
    pub fn preflight_dispatcher_request(
        &self,
        request: ActionRequest,
        detection: DetectionFinding,
        context: ApprovalContext,
    ) -> Result<crate::dispatcher::DispatcherPolicyPreflight, RuntimeError> {
        let policy_started = Instant::now();
        let decision = self.policy.evaluate(&request, &context)?;
        let policy_elapsed_us = policy_started.elapsed().as_micros() as u64;
        let audit = || AuditTrail {
            trail_id: format!("trail:{}:{}", request.hunt_id.0, context.now_ms),
            hunt_id: request.hunt_id.0.clone(),
            related_receipt_ids: context.receipt_chain.clone(),
            detection: detection.clone(),
            policy: PolicyRecord {
                verdict: decision.verdict,
                rule_name: decision.rule_name.clone(),
                reason: decision.reason.clone(),
                lease: None,
            },
            response: AuditResponseRecord::Skipped {
                reason: decision.reason.clone(),
            },
            created_at_ms: context.now_ms,
        };
        match decision.verdict {
            swarm_policy::PolicyVerdict::Deny => {
                Ok(crate::dispatcher::DispatcherPolicyPreflight::deny(audit()))
            }
            swarm_policy::PolicyVerdict::RequireHuman if self.mode == RuntimeMode::LiveResponse => {
                let skipped = audit();
                Ok(crate::dispatcher::DispatcherPolicyPreflight::require_human(
                    crate::dispatcher::DispatcherPolicyPermit::new(
                        request,
                        detection,
                        context,
                        decision,
                        policy_elapsed_us,
                    ),
                    skipped,
                ))
            }
            swarm_policy::PolicyVerdict::Allow | swarm_policy::PolicyVerdict::RequireHuman => {
                Ok(crate::dispatcher::DispatcherPolicyPreflight::allow(
                    crate::dispatcher::DispatcherPolicyPermit::new(
                        request,
                        detection,
                        context,
                        decision,
                        policy_elapsed_us,
                    ),
                ))
            }
        }
    }

    /// Restore the original require-human decision after restart without a
    /// second mutable policy evaluation.
    pub fn restore_human_dispatcher_preflight(
        &self,
        hold: &swarm_policy::governance::GovernedHumanAuthorizationHold,
        detection: DetectionFinding,
        mut context: ApprovalContext,
        approval_pack_id: &str,
    ) -> Result<crate::dispatcher::DispatcherPolicyPermit, RuntimeError> {
        if self.mode != RuntimeMode::LiveResponse
            || hold.policy_decision.verdict != swarm_policy::PolicyVerdict::RequireHuman
        {
            return Err(RuntimeError::GovernanceAuthorization(
                "persisted human hold is not a live require_human decision".into(),
            ));
        }
        context.receipt_chain.push(approval_pack_id.to_string());
        Ok(crate::dispatcher::DispatcherPolicyPermit::new(
            hold.request.clone(),
            detection,
            context,
            hold.policy_decision.clone(),
            0,
        ))
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
        let execution_mode = execution_mode_override.unwrap_or_else(|| self.execution_mode());
        Self::require_dispatcher_admission(request, execution_mode, false)?;
        let policy_started = Instant::now();
        let decision = self.policy.evaluate(request, context)?;
        let policy_elapsed_us = policy_started.elapsed().as_micros() as u64;
        self.audit_execute_evaluated(EvaluatedExecution {
            detection,
            request,
            context,
            decision,
            policy_elapsed_us,
            execution_mode,
            allow_human_approved_execution,
            verified_governance_receipt: None,
        })
        .await
    }

    async fn audit_execute_evaluated(
        &self,
        execution: EvaluatedExecution<'_>,
    ) -> Result<RuntimeExecutionReport, RuntimeError> {
        let EvaluatedExecution {
            detection,
            request,
            context,
            decision,
            policy_elapsed_us,
            execution_mode,
            allow_human_approved_execution,
            verified_governance_receipt,
        } = execution;
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
                    let guard_rejection = self.evaluate_guard_rejection(request);
                    // Evaluated BEFORE `execute`, so a containment that cannot
                    // be leased never reaches a host, and only when no guard has
                    // already rejected the request.
                    let containment = match &guard_rejection {
                        Some(_) => Ok(None),
                        None => self.prepare_containment(request, context, execution_mode),
                    };

                    match (guard_rejection, containment) {
                        (Some((guard_name, reason)), _) => {
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
                        }
                        (None, Err(error)) => {
                            // Recorded as Skipped with the reason: the world is
                            // unchanged, and the audit trail must not read as
                            // though a containment happened.
                            tracing::warn!(
                                correlation_id = %Self::correlation_id(context),
                                hunt_id = %request.hunt_id.0,
                                action = request.action.kind(),
                                reason = %error,
                                module = module_path!(),
                                "containment refused before execution"
                            );
                            (
                                None,
                                AuditResponseRecord::Skipped {
                                    reason: error.to_string(),
                                },
                                None,
                                false,
                                false,
                            )
                        }
                        (None, Ok(prepared_containment)) => {
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
                                            let receipt = Self::decorate_receipt_with_governance(
                                                receipt.with_policy_audit(
                                                    decision.verdict,
                                                    decision.rule_name.clone(),
                                                    decision.reason.clone(),
                                                ),
                                                verified_governance_receipt,
                                                "consensus approved response action",
                                            );
                                            match prepared_containment.as_ref().map(|prepared| {
                                                Self::record_containment_lease(
                                                    prepared,
                                                    request,
                                                    &receipt,
                                                    verified_governance_receipt
                                                        .map(|(receipt, _)| receipt),
                                                )
                                            }) {
                                                Some(Err(error)) => {
                                                    // The containment DID execute.
                                                    // Recording it as a success
                                                    // would hide an unbounded
                                                    // containment from every reader
                                                    // of the audit trail.
                                                    tracing::error!(
                                                        correlation_id = %Self::correlation_id(context),
                                                        hunt_id = %request.hunt_id.0,
                                                        action = request.action.kind(),
                                                        receipt_id = %receipt.receipt_id,
                                                        reason = %error,
                                                        module = module_path!(),
                                                        "containment executed but could not be leased"
                                                    );
                                                    AuditResponseRecord::Failure(ResponseFailure {
                                                        receipt_id: receipt.receipt_id.clone(),
                                                        action: receipt.action.clone(),
                                                        mode: receipt.mode,
                                                        message: error.to_string(),
                                                        details: serde_json::json!({
                                                            "status": "containment_lease_not_recorded",
                                                            "containment_executed": true,
                                                            "response_receipt": receipt.details,
                                                        }),
                                                    })
                                                }
                                                _ => AuditResponseRecord::Success(receipt),
                                            }
                                        }
                                        Ok(receipt) => AuditResponseRecord::Failure(
                                            Self::decorate_receipt_with_governance(
                                                receipt.with_policy_audit(
                                                    decision.verdict,
                                                    decision.rule_name.clone(),
                                                    decision.reason.clone(),
                                                ),
                                                verified_governance_receipt,
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
                                        verified_governance_receipt,
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
    // INVARIANT: RUNTIME-EXPIRED-LEASE-REFUSED
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
    use super::{
        RuntimeError, RuntimeMode, SwarmRuntime, TemporalEventWindowConfig,
        TemporalEventWindowError,
    };
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
    use swarm_response::containment::ContainmentLeaseStore as _;
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
    async fn raw_live_runtime_refuses_governed_action_before_human_policy() {
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
                .contains("dispatcher governance admission")
        );
    }

    #[tokio::test]
    async fn raw_human_approved_live_runtime_cannot_replace_governance_admission() {
        let calls = Arc::new(AtomicUsize::new(0));
        // A lease store is now required for an ENFORCED containment, and
        // `IsolateHost` is one. Attaching it is not test scaffolding: a live
        // deployment must attach one too, or this action is refused. See
        // `SwarmRuntime::prepare_containment`.
        let store = Arc::new(swarm_response::containment::MemoryContainmentLeaseStore::new());
        let runtime = SwarmRuntime::new(
            RuntimeMode::LiveResponse,
            StaticApprovalGate::default(),
            RecordingExecutor {
                calls: Arc::clone(&calls),
            },
        )
        .with_containment_store(
            store.clone(),
            swarm_response::containment::ContainmentTtl::from_config_ms(900_000).unwrap(),
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

        let error = runtime
            .audit_authorize_and_execute_human_approved_instrumented(
                &detection,
                &request,
                &sample_context(),
            )
            .await
            .expect_err("human approval alone must not admit a governed action");

        assert!(
            error
                .to_string()
                .contains("dispatcher governance admission")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(store.open_leases().unwrap().is_empty());
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
    async fn raw_live_runtime_refuses_low_severity_governed_action_before_policy() {
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
                .contains("dispatcher governance admission")
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

    fn sample_detection() -> swarm_whisker::DetectionFinding {
        swarm_whisker::DetectionFinding {
            finding_id: "finding-contain".to_string(),
            event_id: "evt-contain".to_string(),
            threat_class: ThreatClass::Execution,
            severity: Severity::Low,
            confidence: 0.99,
            evidence: serde_json::json!({"signal": "test"}),
            strategy_id: "test".to_string(),
        }
    }

    /// `Medium` is deliberate: the static gate refuses destructive actions below
    /// medium, and holds anything at or above `human_gate_severity` (`High` by
    /// default) for a human. Medium is the band where policy allows outright, so
    /// the only thing that can refuse these requests is the containment gate
    /// under test.
    fn containment_request(action: ResponseAction) -> ActionRequest {
        ActionRequest {
            hunt_id: HuntId("hunt-contain".to_string()),
            requested_by: AgentId("whisker-a".to_string()),
            action,
            severity: Severity::Medium,
            evidence: serde_json::json!({"signal": "test"}),
        }
    }

    fn quarantine_request() -> ActionRequest {
        containment_request(ResponseAction::QuarantineFile {
            host_id: "host-1".to_string(),
            file_path: "/tmp/a".to_string(),
        })
    }

    #[tokio::test]
    async fn raw_live_containment_is_refused_before_checking_for_a_lease_store() {
        let calls = Arc::new(AtomicUsize::new(0));
        let runtime = SwarmRuntime::new(
            RuntimeMode::LiveResponse,
            StaticApprovalGate::default(),
            RecordingExecutor {
                calls: calls.clone(),
            },
        );

        let error = runtime
            .authorize_and_execute(&quarantine_request(), &sample_context())
            .await
            .expect_err("an unbounded live containment must be refused");
        assert!(matches!(
            error,
            RuntimeError::GovernedActionRequiresAdmission {
                action: "quarantine_file"
            }
        ));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "the refusal must land BEFORE execution; a contained host cannot be un-contained by \
             returning an error"
        );

        // Scope check 1: a non-containment action in the same runtime, with the
        // same absent store, still executes. Without this the test would pass
        // against a runtime that refused everything.
        let scan = containment_request(ResponseAction::TriggerEdrScan {
            host_id: "host-1".to_string(),
            scan_profile: "quick".to_string(),
        });
        let receipt = runtime
            .authorize_and_execute(&scan, &sample_context())
            .await
            .unwrap();
        assert_eq!(receipt.status, ResponseStatus::Executed);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_detect_only_containment_needs_no_lease_store() {
        // Scope check 2: nothing takes effect in a dry run, so there is nothing
        // to bound and nothing to undo. A gate that fired here would break every
        // detect-only deployment for no safety gain.
        let calls = Arc::new(AtomicUsize::new(0));
        let runtime = SwarmRuntime::new(
            RuntimeMode::DetectOnly,
            StaticApprovalGate::default(),
            RecordingExecutor {
                calls: calls.clone(),
            },
        );

        let receipt = runtime
            .authorize_and_execute(&quarantine_request(), &sample_context())
            .await
            .unwrap();
        assert_eq!(receipt.mode, ExecutionMode::DryRun);
        assert_eq!(receipt.status, ResponseStatus::Simulated);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            runtime.containment_store().is_none(),
            "no store was attached, so no lease could have been opened"
        );
    }

    #[tokio::test]
    async fn raw_live_containment_is_refused_even_when_a_lease_store_exists() {
        let calls = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(swarm_response::containment::MemoryContainmentLeaseStore::new());
        let runtime = SwarmRuntime::new(
            RuntimeMode::LiveResponse,
            StaticApprovalGate::default(),
            RecordingExecutor {
                calls: calls.clone(),
            },
        )
        .with_containment_store(
            store.clone(),
            swarm_response::containment::ContainmentTtl::from_config_ms(900_000).unwrap(),
        );

        let error = runtime
            .authorize_and_execute(&quarantine_request(), &sample_context())
            .await
            .expect_err("a lease store must not replace dispatcher admission");
        assert!(
            error
                .to_string()
                .contains("dispatcher governance admission")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(store.open_leases().unwrap().is_empty());
    }

    #[tokio::test]
    async fn raw_audited_containment_is_refused_before_lease_store_checks() {
        let detection = sample_detection();

        // Refused: recorded as Skipped, not as a containment that happened.
        let calls = Arc::new(AtomicUsize::new(0));
        let unbounded = SwarmRuntime::new(
            RuntimeMode::LiveResponse,
            StaticApprovalGate::default(),
            RecordingExecutor {
                calls: calls.clone(),
            },
        );
        let error = unbounded
            .audit_authorize_and_execute_instrumented(
                &detection,
                &quarantine_request(),
                &sample_context(),
            )
            .await
            .expect_err("raw audited containment must require dispatcher admission");
        assert!(
            error
                .to_string()
                .contains("dispatcher governance admission")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        // A configured store is deliberately not consulted either.
        let calls = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(swarm_response::containment::MemoryContainmentLeaseStore::new());
        let bounded = SwarmRuntime::new(
            RuntimeMode::LiveResponse,
            StaticApprovalGate::default(),
            RecordingExecutor {
                calls: calls.clone(),
            },
        )
        .with_containment_store(
            store.clone(),
            swarm_response::containment::ContainmentTtl::from_config_ms(60_000).unwrap(),
        );
        let error = bounded
            .audit_authorize_and_execute_instrumented(
                &detection,
                &quarantine_request(),
                &sample_context(),
            )
            .await
            .expect_err("a lease store must not replace dispatcher admission");
        assert!(
            error
                .to_string()
                .contains("dispatcher governance admission")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(store.open_leases().unwrap().is_empty());
    }

    #[tokio::test]
    async fn raw_live_containment_cannot_reach_lease_persistence() {
        let calls = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(swarm_response::containment::MemoryContainmentLeaseStore::new());
        let runtime = SwarmRuntime::new(
            RuntimeMode::LiveResponse,
            StaticApprovalGate::default(),
            RecordingExecutor {
                calls: calls.clone(),
            },
        )
        .with_containment_store(
            store.clone(),
            swarm_response::containment::ContainmentTtl::from_config_ms(60_000).unwrap(),
        );

        let error = runtime
            .authorize_and_execute(&quarantine_request(), &sample_context())
            .await
            .expect_err("raw execution must stop before lease persistence");
        assert!(
            error
                .to_string()
                .contains("dispatcher governance admission")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(store.open_leases().unwrap().is_empty());

        let detection = sample_detection();
        let error = runtime
            .audit_authorize_and_execute_instrumented(
                &detection,
                &quarantine_request(),
                &sample_context(),
            )
            .await
            .expect_err("raw audited execution must stop before lease persistence");
        assert!(
            error
                .to_string()
                .contains("dispatcher governance admission")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
