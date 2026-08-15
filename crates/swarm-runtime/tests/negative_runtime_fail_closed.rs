//! Negative falsifiability tests for the `swarm-runtime` rows of
//! `docs/assurance/MAPPING.md` (FALSIFY-02).
//!
//! See the header of `crates/swarm-policy/tests/negative_policy_gates.rs` for
//! the three-step shape every test in this family follows (real function
//! refuses; unmutated mirror reproduces it; mutated mirror permits).
//!
//! # What "permits" means on this crate's rows, and why it is stronger here
//!
//! In `swarm-policy` a broken gate returns a different verdict. Here a broken
//! runtime CALLS THE EXECUTOR. Every mirror below drives the same
//! `RecordingExecutor` the real runtime is given, and the assertions are on its
//! call count -- so "permits" is not a verdict enum, it is a response adapter
//! having been reached with a live request. That is the difference between a
//! host being contained and not.

#![allow(clippy::unwrap_used, clippy::expect_used)]

extern crate swarm_runtime as __phase285_swarm_runtime;

#[path = "../../../tests/negative_protocol.rs"]
mod negative_protocol;

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use swarm_agents::tom_agent::{GovernancePolicy, GovernancePolicyConfig};
use swarm_consensus::{
    ConsensusCommit, ConsensusCommittee, ConsensusGovernanceReceipt, ConsensusProposal,
    GovernanceReceiptDecision,
};
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_crypto::{canonical_json_bytes, sha256_hex};
use swarm_guard::{Guard, GuardAction, GuardContext, GuardPipeline, GuardResult};
use swarm_policy::{
    ActionRequest, ApprovalContext, ApprovalError, ApprovalGate, CapabilityLease, PolicyDecision,
    PolicyVerdict, governance::GovernanceAuthority,
};
use swarm_response::containment::{
    ContainmentLease, ContainmentLeaseStore, ContainmentTtl, MemoryContainmentLeaseStore,
};
use swarm_response::rollback::{
    RollbackExecutor, RollbackReceipt, RollbackStepOutcome, RollbackStepStatus, RollbackTrigger,
};
use swarm_response::{
    ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt, ResponseStatus,
};
use swarm_runtime::containment::{
    is_containment_action, release_lease, verify_release_attestation,
};
use swarm_runtime::{RuntimeError, RuntimeMode, SwarmRuntime};

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

/// Counts how many times a response adapter was actually reached.
#[derive(Debug, Default)]
struct RecordingExecutor {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl ResponseExecutor for RecordingExecutor {
    async fn execute(
        &self,
        request: &ActionRequest,
        _lease: &CapabilityLease,
        mode: ExecutionMode,
    ) -> Result<ResponseReceipt, ResponseError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ResponseReceipt {
            receipt_id: format!("receipt:{}", request.hunt_id.0),
            action: request.action.kind().to_string(),
            mode,
            status: match mode {
                ExecutionMode::DryRun => ResponseStatus::Simulated,
                ExecutionMode::Enforced => ResponseStatus::Executed,
            },
            summary: "recorded".to_string(),
            details: json!({}),
            audit: Default::default(),
        })
    }
}

fn context(now_ms: i64) -> ApprovalContext {
    ApprovalContext {
        live_mode: true,
        receipt_chain: vec!["receipt-1".to_string()],
        correlation_id: None,
        now_ms,
    }
}

fn request(action: ResponseAction, severity: Severity) -> ActionRequest {
    ActionRequest {
        hunt_id: HuntId("hunt-negative".to_string()),
        requested_by: AgentId("pounce-1".to_string()),
        action,
        severity,
        evidence: json!({"escalation": {"severity": severity}}),
    }
}

/// The downstream runtime rows must reach the guard they name. A governed
/// action would be refused by the raw admission guard first, so these probes use
/// a non-governed, non-containment action. The admission differential below is
/// the only raw-runtime row that intentionally uses a governed action.
fn trigger_edr_scan(severity: Severity) -> ActionRequest {
    request(
        ResponseAction::TriggerEdrScan {
            host_id: "host-1".to_string(),
            scan_profile: "deep".to_string(),
        },
        severity,
    )
}

fn block_egress(severity: Severity) -> ActionRequest {
    request(
        ResponseAction::BlockEgress {
            target: "10.0.0.9".to_string(),
        },
        severity,
    )
}

fn quarantine_file(severity: Severity) -> ActionRequest {
    request(
        ResponseAction::QuarantineFile {
            host_id: "host-1".to_string(),
            file_path: "/tmp/evil".to_string(),
        },
        severity,
    )
}

// ---------------------------------------------------------------------------
// The mirror of `SwarmRuntime::authorize_and_execute`
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeMutation {
    /// No mutation. The control.
    None,
    /// The enforced governed-action admission guard deleted.
    SkipDispatcherAdmission,
    /// The `PolicyVerdict::Deny => return Err(..)` arm deleted.
    SkipDenyVerdict,
    /// The `RequireHuman if LiveResponse => return Err(..)` arm deleted.
    SkipHumanGateVerdict,
    /// The `ensure_active_lease` call deleted.
    SkipLeaseExpiry,
    /// An `ApprovalGate::evaluate` error is replaced by Allow.
    SkipPolicyError,
    /// An `ApprovalGate::issue_lease` error is replaced by a synthesized lease.
    SkipLeaseIssueError,
    /// A response-adapter error is replaced by a synthesized success receipt.
    SkipAdapterError,
    /// A failed receipt is returned as if it were successful.
    SkipFailedReceiptStatus,
}

/// Mirror of `SwarmRuntime::authorize_and_execute`, copied from
/// `crates/swarm-runtime/src/lib.rs` with one guard removable.
///
/// WHAT IS AND IS NOT MIRRORED. The real function starts with raw governance
/// admission, then evaluates policy, gates on the verdict, runs guards and
/// containment preflight, issues and checks a lease, executes, decorates, and
/// records. This mirror covers admission through response status. Guard has its
/// own exact mirror below; containment has the direct preflight mirror below;
/// governance decoration is unreachable on the raw route. All downstream rows
/// use a non-governed, non-containment action, while the admission row alone
/// uses governed `BlockEgress` and mutates only admission.
///
/// The `RuntimeMutation::None` control asserts the mirror and the real function
/// agree on both the result and the executor call count, which is what makes
/// that claim checkable rather than a promise in a comment.
async fn mirrored_authorize_and_execute(
    mode: RuntimeMode,
    policy: &dyn ApprovalGate,
    response: &dyn ResponseExecutor,
    request: &ActionRequest,
    context: &ApprovalContext,
    mutation: RuntimeMutation,
) -> Result<ResponseReceipt, RuntimeError> {
    let execution_mode = match mode {
        RuntimeMode::DetectOnly => ExecutionMode::DryRun,
        RuntimeMode::LiveResponse => ExecutionMode::Enforced,
    };
    if execution_mode == ExecutionMode::Enforced
        && request.action.requires_governance_receipt()
        && mutation != RuntimeMutation::SkipDispatcherAdmission
    {
        return Err(RuntimeError::GovernedActionRequiresAdmission {
            action: request.action.kind(),
        });
    }

    let decision = match policy.evaluate(request, context) {
        Ok(decision) => decision,
        Err(_) if mutation == RuntimeMutation::SkipPolicyError => {
            PolicyDecision::allow_with_rule("mutated.policy_error", "mutated to allow")
        }
        Err(error) => return Err(error.into()),
    };

    match decision.verdict {
        PolicyVerdict::Deny if mutation != RuntimeMutation::SkipDenyVerdict => {
            return Err(ApprovalError::Denied(decision.reason.clone()).into());
        }
        PolicyVerdict::RequireHuman
            if mode == RuntimeMode::LiveResponse
                && mutation != RuntimeMutation::SkipHumanGateVerdict =>
        {
            return Err(ApprovalError::Denied(decision.reason.clone()).into());
        }
        _ => {}
    }

    let lease = match policy.issue_lease(request, context) {
        Ok(lease) => lease,
        Err(_) if mutation == RuntimeMutation::SkipLeaseIssueError => CapabilityLease {
            capability_id: "mutated-lease".to_string(),
            expires_at_ms: context.now_ms.saturating_add(60_000),
            action: request.action.kind().to_string(),
            scope: None,
        },
        Err(error) => return Err(error.into()),
    };
    if mutation != RuntimeMutation::SkipLeaseExpiry && lease.expires_at_ms <= context.now_ms {
        return Err(ApprovalError::Denied("capability lease expired".to_string()).into());
    }

    let receipt = match response.execute(request, &lease, execution_mode).await {
        Ok(receipt) => receipt,
        Err(_) if mutation == RuntimeMutation::SkipAdapterError => ResponseReceipt {
            receipt_id: "mutated-adapter-error".to_string(),
            action: request.action.kind().to_string(),
            mode: execution_mode,
            status: ResponseStatus::Executed,
            summary: "mutated adapter error to success".to_string(),
            details: json!({}),
            audit: Default::default(),
        },
        Err(error) => return Err(error.into()),
    };
    if mutation != RuntimeMutation::SkipFailedReceiptStatus && !receipt.status.indicates_success() {
        return Err(RuntimeError::Response(ResponseError {
            failure: receipt.into_failure(),
        }));
    }
    Ok(receipt)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateFailure {
    Evaluate,
    IssueLease,
}

#[derive(Debug, Clone)]
struct FailingGate(GateFailure);

impl ApprovalGate for FailingGate {
    fn evaluate(
        &self,
        _request: &ActionRequest,
        _context: &ApprovalContext,
    ) -> Result<PolicyDecision, ApprovalError> {
        if self.0 == GateFailure::Evaluate {
            Err(ApprovalError::InvalidRequest(
                "policy unavailable".to_string(),
            ))
        } else {
            Ok(PolicyDecision::allow("evaluation succeeded"))
        }
    }

    fn issue_lease(
        &self,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<CapabilityLease, ApprovalError> {
        if self.0 == GateFailure::IssueLease {
            Err(ApprovalError::InvalidRequest(
                "lease unavailable".to_string(),
            ))
        } else {
            Ok(CapabilityLease {
                capability_id: "failure-fixture-live-lease".to_string(),
                expires_at_ms: context.now_ms.saturating_add(60_000),
                action: request.action.kind().to_string(),
                scope: None,
            })
        }
    }
}

#[derive(Debug)]
struct FixedOutcomeExecutor {
    calls: Arc<AtomicUsize>,
    outcome: Result<ResponseStatus, &'static str>,
}

#[derive(Debug, Clone)]
struct CountingAllowGate {
    evaluations: Arc<AtomicUsize>,
}

impl ApprovalGate for CountingAllowGate {
    fn evaluate(
        &self,
        _request: &ActionRequest,
        _context: &ApprovalContext,
    ) -> Result<PolicyDecision, ApprovalError> {
        self.evaluations.fetch_add(1, Ordering::SeqCst);
        Ok(PolicyDecision::allow_with_rule(
            "counting.allow",
            "allowed after admission",
        ))
    }

    fn issue_lease(
        &self,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<CapabilityLease, ApprovalError> {
        Ok(CapabilityLease {
            capability_id: "counting-live-lease".to_string(),
            expires_at_ms: context.now_ms.saturating_add(60_000),
            action: request.action.kind().to_string(),
            scope: None,
        })
    }
}

#[async_trait]
impl ResponseExecutor for FixedOutcomeExecutor {
    async fn execute(
        &self,
        request: &ActionRequest,
        _lease: &CapabilityLease,
        mode: ExecutionMode,
    ) -> Result<ResponseReceipt, ResponseError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let status = self
            .outcome
            .map_err(|message| ResponseError::unavailable(request.action.kind(), mode, message))?;
        Ok(ResponseReceipt {
            receipt_id: "fixed-outcome".to_string(),
            action: request.action.kind().to_string(),
            mode,
            status,
            summary: "fixed outcome".to_string(),
            details: json!({}),
            audit: Default::default(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeProtocolResult {
    Success(ResponseStatus),
    GovernanceRefused,
    ApprovalRefused,
    GuardRefused,
    ContainmentRefused,
    ResponseRefused,
}

fn runtime_protocol_outcome(
    result: Result<ResponseReceipt, RuntimeError>,
    calls: &AtomicUsize,
) -> (RuntimeProtocolResult, usize) {
    let result = match result {
        Ok(receipt) => RuntimeProtocolResult::Success(receipt.status),
        Err(RuntimeError::GovernedActionRequiresAdmission { .. }) => {
            RuntimeProtocolResult::GovernanceRefused
        }
        Err(RuntimeError::Approval(_)) => RuntimeProtocolResult::ApprovalRefused,
        Err(RuntimeError::GuardRejected { .. }) => RuntimeProtocolResult::GuardRefused,
        Err(RuntimeError::ContainmentRefused { .. }) => RuntimeProtocolResult::ContainmentRefused,
        Err(RuntimeError::Response(_)) => RuntimeProtocolResult::ResponseRefused,
        Err(other) => panic!("unexpected runtime outcome: {other}"),
    };
    (result, calls.load(Ordering::SeqCst))
}

// ---------------------------------------------------------------------------
// RUNTIME-GOVERNED-ACTION-REQUIRES-ADMISSION
// ---------------------------------------------------------------------------

#[test]
fn broken_raw_admission_guard_evaluates_policy_and_executes_a_governed_action() {
    let policy_calls = Arc::new(AtomicUsize::new(0));
    let executor_calls = Arc::new(AtomicUsize::new(0));
    let gate = CountingAllowGate {
        evaluations: policy_calls.clone(),
    };
    let probe = block_egress(Severity::High);
    let context = context(1_700_000_000_000);

    negative_protocol::assert_registered_negative_case! {
        case: RUNTIME_GOVERNED_ACTION_REQUIRES_ADMISSION,
        mutation: RuntimeMutation,
        control: RuntimeMutation::None,
        broken: RuntimeMutation::SkipDispatcherAdmission,
        state: {
            gate: CountingAllowGate = gate,
            context: ApprovalContext = context,
            policy_calls: Arc<AtomicUsize> = policy_calls,
            executor_calls: Arc<AtomicUsize> = executor_calls,
        },
        probe: ActionRequest = probe,
        outcome: (RuntimeProtocolResult, usize, usize),
        real_probe: probe,
        production: crate::__phase285_swarm_runtime::SwarmRuntime::authorize_and_execute,
        arguments: (&(SwarmRuntime::new(RuntimeMode::LiveResponse, gate.clone(), RecordingExecutor { calls: executor_calls.clone() })), probe, context),
        call: awaited,
        normalize: |production_result| {
            let (outcome, executions) = runtime_protocol_outcome(production_result, executor_calls);
            (outcome, policy_calls.load(Ordering::SeqCst), executions)
        },
        mirror: |_state, probe, mutation| {
            let policy_calls = Arc::new(AtomicUsize::new(0));
            let executor_calls = Arc::new(AtomicUsize::new(0));
            let gate = CountingAllowGate { evaluations: policy_calls.clone() };
            let result = mirrored_authorize_and_execute(
                RuntimeMode::LiveResponse,
                &gate,
                &RecordingExecutor { calls: executor_calls.clone() },
                probe,
                context,
                mutation,
            ).await;
            let (outcome, executions) = runtime_protocol_outcome(result, &executor_calls);
            (outcome, policy_calls.load(Ordering::SeqCst), executions)
        },
        denied: |result| result == &(RuntimeProtocolResult::GovernanceRefused, 0, 0),
        permitted: |result| matches!(result, (RuntimeProtocolResult::Success(_), 1, 1)),
    }
}

#[test]
fn broken_policy_error_fallback_executes_when_evaluation_failed() {
    let gate = FailingGate(GateFailure::Evaluate);
    let probe = trigger_edr_scan(Severity::Medium);
    let context = context(1_700_000_000_000);
    negative_protocol::assert_registered_negative_case! {
        case: RUNTIME_POLICY_ERROR_BLOCKS_EXECUTION,
        mutation: RuntimeMutation,
        control: RuntimeMutation::None,
        broken: RuntimeMutation::SkipPolicyError,
        state: {
            gate: FailingGate = gate.clone(),
            context: ApprovalContext = context.clone(),
            calls: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0)),
        },
        probe: ActionRequest = probe,
        outcome: (RuntimeProtocolResult, usize),
        real_probe: probe,
        production: crate::__phase285_swarm_runtime::SwarmRuntime::authorize_and_execute,
        arguments: (&(SwarmRuntime::new(RuntimeMode::LiveResponse, gate.clone(), RecordingExecutor { calls: calls.clone() })), probe, context),
        call: awaited,
        normalize: |production_result| runtime_protocol_outcome(production_result, calls),
        mirror: |_state, probe, mutation| {
            let calls = Arc::new(AtomicUsize::new(0));
            let result = mirrored_authorize_and_execute(RuntimeMode::LiveResponse, gate, &RecordingExecutor { calls: calls.clone() }, probe, context, mutation).await;
            runtime_protocol_outcome(result, &calls)
        },
        denied: |result| result == &(RuntimeProtocolResult::ApprovalRefused, 0),
        permitted: |result| matches!(result, (RuntimeProtocolResult::Success(_), 1)),
    }
}

#[test]
fn broken_lease_issue_error_fallback_executes_without_a_real_lease() {
    let gate = FailingGate(GateFailure::IssueLease);
    let probe = trigger_edr_scan(Severity::Medium);
    let context = context(1_700_000_000_000);
    negative_protocol::assert_registered_negative_case! {
        case: RUNTIME_LEASE_ISSUE_ERROR_BLOCKS_EXECUTION,
        mutation: RuntimeMutation,
        control: RuntimeMutation::None,
        broken: RuntimeMutation::SkipLeaseIssueError,
        state: {
            gate: FailingGate = gate.clone(),
            context: ApprovalContext = context.clone(),
            calls: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0)),
        },
        probe: ActionRequest = probe,
        outcome: (RuntimeProtocolResult, usize),
        real_probe: probe,
        production: crate::__phase285_swarm_runtime::SwarmRuntime::authorize_and_execute,
        arguments: (&(SwarmRuntime::new(RuntimeMode::LiveResponse, gate.clone(), RecordingExecutor { calls: calls.clone() })), probe, context),
        call: awaited,
        normalize: |production_result| runtime_protocol_outcome(production_result, calls),
        mirror: |_state, probe, mutation| {
            let calls = Arc::new(AtomicUsize::new(0));
            let result = mirrored_authorize_and_execute(RuntimeMode::LiveResponse, gate, &RecordingExecutor { calls: calls.clone() }, probe, context, mutation).await;
            runtime_protocol_outcome(result, &calls)
        },
        denied: |result| result == &(RuntimeProtocolResult::ApprovalRefused, 0),
        permitted: |result| matches!(result, (RuntimeProtocolResult::Success(_), 1)),
    }
}

#[test]
fn broken_adapter_error_conversion_returns_false_success() {
    let gate = FixedVerdictGate {
        verdict: PolicyVerdict::Allow,
        lease_ttl_ms: 60_000,
    };
    let probe = trigger_edr_scan(Severity::Medium);
    let context = context(1_700_000_000_000);
    negative_protocol::assert_registered_negative_case! {
        case: RUNTIME_ADAPTER_ERROR_NOT_SUCCESS,
        mutation: RuntimeMutation,
        control: RuntimeMutation::None,
        broken: RuntimeMutation::SkipAdapterError,
        state: {
            gate: FixedVerdictGate = gate.clone(),
            context: ApprovalContext = context.clone(),
            calls: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0)),
        },
        probe: ActionRequest = probe,
        outcome: (RuntimeProtocolResult, usize),
        real_probe: probe,
        production: crate::__phase285_swarm_runtime::SwarmRuntime::authorize_and_execute,
        arguments: (&(SwarmRuntime::new(RuntimeMode::LiveResponse, gate.clone(), FixedOutcomeExecutor { calls: calls.clone(), outcome: Err("offline") })), probe, context),
        call: awaited,
        normalize: |production_result| runtime_protocol_outcome(production_result, calls),
        mirror: |_state, probe, mutation| {
            let calls = Arc::new(AtomicUsize::new(0));
            let executor = FixedOutcomeExecutor { calls: calls.clone(), outcome: Err("offline") };
            let result = mirrored_authorize_and_execute(RuntimeMode::LiveResponse, gate, &executor, probe, context, mutation).await;
            runtime_protocol_outcome(result, &calls)
        },
        denied: |result| result == &(RuntimeProtocolResult::ResponseRefused, 1),
        permitted: |result| result == &(RuntimeProtocolResult::Success(ResponseStatus::Executed), 1),
    }
}

#[test]
fn broken_failed_receipt_check_returns_a_failure_as_success() {
    let gate = FixedVerdictGate {
        verdict: PolicyVerdict::Allow,
        lease_ttl_ms: 60_000,
    };
    let probe = trigger_edr_scan(Severity::Medium);
    let context = context(1_700_000_000_000);
    negative_protocol::assert_registered_negative_case! {
        case: RUNTIME_FAILED_RECEIPT_NOT_SUCCESS,
        mutation: RuntimeMutation,
        control: RuntimeMutation::None,
        broken: RuntimeMutation::SkipFailedReceiptStatus,
        state: {
            gate: FixedVerdictGate = gate.clone(),
            context: ApprovalContext = context.clone(),
            calls: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0)),
        },
        probe: ActionRequest = probe,
        outcome: (RuntimeProtocolResult, usize),
        real_probe: probe,
        production: crate::__phase285_swarm_runtime::SwarmRuntime::authorize_and_execute,
        arguments: (&(SwarmRuntime::new(RuntimeMode::LiveResponse, gate.clone(), FixedOutcomeExecutor { calls: calls.clone(), outcome: Ok(ResponseStatus::Failed) })), probe, context),
        call: awaited,
        normalize: |production_result| runtime_protocol_outcome(production_result, calls),
        mirror: |_state, probe, mutation| {
            let calls = Arc::new(AtomicUsize::new(0));
            let executor = FixedOutcomeExecutor { calls: calls.clone(), outcome: Ok(ResponseStatus::Failed) };
            let result = mirrored_authorize_and_execute(RuntimeMode::LiveResponse, gate, &executor, probe, context, mutation).await;
            runtime_protocol_outcome(result, &calls)
        },
        denied: |result| result == &(RuntimeProtocolResult::ResponseRefused, 1),
        permitted: |result| result == &(RuntimeProtocolResult::Success(ResponseStatus::Failed), 1),
    }
}

#[derive(Debug)]
struct RejectingGuard;

impl Guard for RejectingGuard {
    fn name(&self) -> &str {
        "negative-reject"
    }
    fn handles(&self, _action: &GuardAction<'_>) -> bool {
        true
    }
    fn check(&self, _action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        GuardResult::block(
            "negative-reject",
            swarm_guard::Severity::Critical,
            "blocked",
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuardMutation {
    None,
    SkipGuardRejection,
}

async fn mirrored_guard_authorize(
    policy: &dyn ApprovalGate,
    response: &dyn ResponseExecutor,
    request: &ActionRequest,
    context: &ApprovalContext,
    mutation: GuardMutation,
) -> Result<ResponseReceipt, RuntimeError> {
    let decision = policy.evaluate(request, context)?;
    if decision.verdict != PolicyVerdict::Allow {
        return Err(ApprovalError::Denied(decision.reason).into());
    }
    if mutation != GuardMutation::SkipGuardRejection {
        return Err(RuntimeError::GuardRejected {
            guard_name: "negative-reject".to_string(),
            reason: "blocked".to_string(),
        });
    }
    let lease = policy.issue_lease(request, context)?;
    response
        .execute(request, &lease, ExecutionMode::Enforced)
        .await
        .map_err(Into::into)
}

#[test]
fn broken_guard_rejection_reaches_the_executor() {
    let gate = FixedVerdictGate {
        verdict: PolicyVerdict::Allow,
        lease_ttl_ms: 60_000,
    };
    let probe = trigger_edr_scan(Severity::Medium);
    let context = context(1_700_000_000_000);
    negative_protocol::assert_registered_negative_case! {
        case: RUNTIME_GUARD_REJECTION_BLOCKS_EXECUTION,
        mutation: GuardMutation,
        control: GuardMutation::None,
        broken: GuardMutation::SkipGuardRejection,
        state: {
            gate: FixedVerdictGate = gate.clone(),
            context: ApprovalContext = context.clone(),
            calls: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0)),
        },
        probe: ActionRequest = probe,
        outcome: (RuntimeProtocolResult, usize),
        real_probe: probe,
        production: crate::__phase285_swarm_runtime::SwarmRuntime::authorize_and_execute,
        arguments: (&(SwarmRuntime::new(RuntimeMode::LiveResponse, gate.clone(), RecordingExecutor { calls: calls.clone() })
                .with_guard_pipeline(GuardPipeline::new(vec![Box::new(RejectingGuard)]))), probe, context),
        call: awaited,
        normalize: |production_result| runtime_protocol_outcome(production_result, calls),
        mirror: |_state, probe, mutation| {
            let calls = Arc::new(AtomicUsize::new(0));
            let result = mirrored_guard_authorize(gate, &RecordingExecutor { calls: calls.clone() }, probe, context, mutation).await;
            runtime_protocol_outcome(result, &calls)
        },
        denied: |result| result == &(RuntimeProtocolResult::GuardRefused, 0),
        permitted: |result| matches!(result, (RuntimeProtocolResult::Success(_), 1)),
    }
}

/// A gate that renders one fixed verdict and mints a live lease, so a test can
/// choose the verdict without also choosing a severity that another arm reacts
/// to.
#[derive(Debug, Clone)]
struct FixedVerdictGate {
    verdict: PolicyVerdict,
    lease_ttl_ms: i64,
}

impl ApprovalGate for FixedVerdictGate {
    fn evaluate(
        &self,
        _request: &ActionRequest,
        _context: &ApprovalContext,
    ) -> Result<PolicyDecision, ApprovalError> {
        Ok(match self.verdict {
            PolicyVerdict::Deny => {
                PolicyDecision::deny_with_rule("fixed.deny", "denied by fixture")
            }
            PolicyVerdict::Allow => {
                PolicyDecision::allow_with_rule("fixed.allow", "allowed by fixture")
            }
            PolicyVerdict::RequireHuman => {
                PolicyDecision::require_human_with_rule("fixed.human", "held by fixture")
            }
        })
    }

    fn issue_lease(
        &self,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<CapabilityLease, ApprovalError> {
        Ok(CapabilityLease {
            capability_id: format!("lease:{}", request.hunt_id.0),
            expires_at_ms: context.now_ms + self.lease_ttl_ms,
            action: request.action.kind().to_string(),
            scope: None,
        })
    }
}

// ---------------------------------------------------------------------------
// RUNTIME-DENY-BLOCKS-EXECUTION
// ---------------------------------------------------------------------------

#[test]
fn broken_deny_arm_reaches_the_executor_the_real_runtime_never_calls() {
    let gate = FixedVerdictGate {
        verdict: PolicyVerdict::Deny,
        lease_ttl_ms: 60_000,
    };
    let probe = trigger_edr_scan(Severity::High);
    let context = context(1_700_000_000_000);

    negative_protocol::assert_registered_negative_case! {
        case: RUNTIME_DENY_BLOCKS_EXECUTION,
        mutation: RuntimeMutation,
        control: RuntimeMutation::None,
        broken: RuntimeMutation::SkipDenyVerdict,
        state: {
            gate: FixedVerdictGate = gate.clone(),
            context: ApprovalContext = context.clone(),
            calls: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0)),
        },
        probe: ActionRequest = probe,
        outcome: (RuntimeProtocolResult, usize),
        real_probe: probe,
        production: crate::__phase285_swarm_runtime::SwarmRuntime::authorize_and_execute,
        arguments: (&(SwarmRuntime::new(RuntimeMode::LiveResponse, gate.clone(), RecordingExecutor { calls: calls.clone() })), probe, context),
        call: awaited,
        normalize: |production_result| runtime_protocol_outcome(production_result, calls),
        mirror: |_state, probe, mutation| {
            let calls = Arc::new(AtomicUsize::new(0));
            let result = mirrored_authorize_and_execute(RuntimeMode::LiveResponse, gate, &RecordingExecutor { calls: calls.clone() }, probe, context, mutation).await;
            runtime_protocol_outcome(result, &calls)
        },
        denied: |result| result == &(RuntimeProtocolResult::ApprovalRefused, 0),
        permitted: |result| matches!(result, (RuntimeProtocolResult::Success(_), 1)),
    }
}

// ---------------------------------------------------------------------------
// RUNTIME-HUMAN-GATE-BLOCKS-LIVE
// ---------------------------------------------------------------------------

#[test]
fn broken_human_gate_arm_executes_in_live_mode_what_the_real_runtime_holds() {
    let gate = FixedVerdictGate {
        verdict: PolicyVerdict::RequireHuman,
        lease_ttl_ms: 60_000,
    };
    let probe = trigger_edr_scan(Severity::Critical);
    let context = context(1_700_000_000_000);

    negative_protocol::assert_registered_negative_case! {
        case: RUNTIME_HUMAN_GATE_BLOCKS_LIVE,
        mutation: RuntimeMutation,
        control: RuntimeMutation::None,
        broken: RuntimeMutation::SkipHumanGateVerdict,
        state: {
            gate: FixedVerdictGate = gate.clone(),
            context: ApprovalContext = context.clone(),
            calls: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0)),
        },
        probe: ActionRequest = probe.clone(),
        outcome: (RuntimeProtocolResult, usize),
        real_probe: probe,
        production: crate::__phase285_swarm_runtime::SwarmRuntime::authorize_and_execute,
        arguments: (&(SwarmRuntime::new(RuntimeMode::LiveResponse, gate.clone(), RecordingExecutor { calls: calls.clone() })), probe, context),
        call: awaited,
        normalize: |production_result| runtime_protocol_outcome(production_result, calls),
        mirror: |_state, probe, mutation| {
            let calls = Arc::new(AtomicUsize::new(0));
            let result = mirrored_authorize_and_execute(RuntimeMode::LiveResponse, gate, &RecordingExecutor { calls: calls.clone() }, probe, context, mutation).await;
            runtime_protocol_outcome(result, &calls)
        },
        denied: |result| result == &(RuntimeProtocolResult::ApprovalRefused, 0),
        permitted: |result| matches!(result, (RuntimeProtocolResult::Success(_), 1)),
    }

    // The mode is load bearing: in DetectOnly the same verdict is allowed
    // through by the real runtime, so this row is about LiveResponse and the
    // mirror must not be reading the verdict alone.
    let detect_calls = Arc::new(AtomicUsize::new(0));
    let detect_runtime = SwarmRuntime::new(
        RuntimeMode::DetectOnly,
        gate.clone(),
        RecordingExecutor {
            calls: detect_calls.clone(),
        },
    );
    let detect =
        negative_protocol::block_on_ready(detect_runtime.authorize_and_execute(&probe, &context));
    assert_eq!(
        detect.expect("DetectOnly proceeds to a dry run").mode,
        ExecutionMode::DryRun
    );
    assert_eq!(detect_calls.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------------------
// RUNTIME-EXPIRED-LEASE-REFUSED
// ---------------------------------------------------------------------------

#[test]
fn broken_lease_expiry_check_executes_under_the_dead_lease_the_real_runtime_refuses() {
    // A gate that mints a lease which expired one millisecond before the
    // request is evaluated. `ensure_active_lease` is the only thing between it
    // and the adapter.
    let gate = FixedVerdictGate {
        verdict: PolicyVerdict::Allow,
        lease_ttl_ms: -1,
    };
    let probe = trigger_edr_scan(Severity::Medium);
    let context = context(1_700_000_000_000);

    negative_protocol::assert_registered_negative_case! {
        case: RUNTIME_EXPIRED_LEASE_REFUSED,
        mutation: RuntimeMutation,
        control: RuntimeMutation::None,
        broken: RuntimeMutation::SkipLeaseExpiry,
        state: {
            gate: FixedVerdictGate = gate.clone(),
            context: ApprovalContext = context.clone(),
            calls: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0)),
        },
        probe: ActionRequest = probe.clone(),
        outcome: (RuntimeProtocolResult, usize),
        real_probe: probe,
        production: crate::__phase285_swarm_runtime::SwarmRuntime::authorize_and_execute,
        arguments: (&(SwarmRuntime::new(RuntimeMode::LiveResponse, gate.clone(), RecordingExecutor { calls: calls.clone() })), probe, context),
        call: awaited,
        normalize: |production_result| runtime_protocol_outcome(production_result, calls),
        mirror: |_state, probe, mutation| {
            let calls = Arc::new(AtomicUsize::new(0));
            let result = mirrored_authorize_and_execute(RuntimeMode::LiveResponse, gate, &RecordingExecutor { calls: calls.clone() }, probe, context, mutation).await;
            runtime_protocol_outcome(result, &calls)
        },
        denied: |result| result == &(RuntimeProtocolResult::ApprovalRefused, 0),
        permitted: |result| matches!(result, (RuntimeProtocolResult::Success(_), 1)),
    }

    // Control the other way: a live lease reaches the adapter on both paths, so
    // neither is refusing every request.
    let live_gate = FixedVerdictGate {
        verdict: PolicyVerdict::Allow,
        lease_ttl_ms: 60_000,
    };
    let live_calls = Arc::new(AtomicUsize::new(0));
    let live_runtime = SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        live_gate,
        RecordingExecutor {
            calls: live_calls.clone(),
        },
    );
    negative_protocol::block_on_ready(live_runtime.authorize_and_execute(&probe, &context))
        .expect("a live lease executes");
    assert_eq!(live_calls.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------------------
// RUNTIME-CONTAINMENT-NEEDS-STORE
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContainmentPreflightMutation {
    None,
    SkipContainmentStore,
    SkipContainmentPreviewError,
}

fn mirrored_preflight_containment(
    has_store: bool,
    request: &ActionRequest,
    execution_mode: ExecutionMode,
    mutation: ContainmentPreflightMutation,
) -> Result<(), RuntimeError> {
    if !is_containment_action(&request.action) || execution_mode == ExecutionMode::DryRun {
        return Ok(());
    }
    if !has_store && mutation != ContainmentPreflightMutation::SkipContainmentStore {
        return Err(RuntimeError::ContainmentRefused {
            action: request.action.kind(),
            reason: "no containment lease store is configured".to_string(),
        });
    }
    if mutation != ContainmentPreflightMutation::SkipContainmentPreviewError
        && matches!(
            &request.action,
            ResponseAction::QuarantineFile { host_id, file_path }
                if host_id.trim().is_empty() || file_path.trim().is_empty()
        )
    {
        return Err(RuntimeError::ContainmentRefused {
            action: request.action.kind(),
            reason: "its inverse plan could not be derived".to_string(),
        });
    }
    Ok(())
}

#[test]
fn broken_containment_store_check_accepts_an_unbounded_preflight() {
    let gate = FixedVerdictGate {
        verdict: PolicyVerdict::Allow,
        lease_ttl_ms: 60_000,
    };
    let probe = quarantine_file(Severity::High);
    let context = context(1_700_000_000_000);

    negative_protocol::assert_registered_negative_case! {
        case: RUNTIME_CONTAINMENT_NEEDS_STORE,
        mutation: ContainmentPreflightMutation,
        control: ContainmentPreflightMutation::None,
        broken: ContainmentPreflightMutation::SkipContainmentStore,
        state: {
            gate: FixedVerdictGate = gate,
            context: ApprovalContext = context,
        },
        probe: ActionRequest = probe,
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_runtime::SwarmRuntime::preflight_containment,
        arguments: (&(SwarmRuntime::new(RuntimeMode::LiveResponse, gate.clone(), RecordingExecutor::default())), probe, context, ExecutionMode::Enforced),
        call: sync,
        normalize: |production_result| production_result.is_ok(),
        mirror: |_state, probe, mutation| mirrored_preflight_containment(false, probe, ExecutionMode::Enforced, mutation).is_ok(),
        denied: |result| !result,
        permitted: |result| *result,
    }
}

// ---------------------------------------------------------------------------
// RUNTIME-CONTAINMENT-PREVIEW-REQUIRED
// ---------------------------------------------------------------------------

#[test]
fn broken_preview_error_guard_dispatches_a_containment_with_no_inverse_plan() {
    let gate = FixedVerdictGate {
        verdict: PolicyVerdict::Allow,
        lease_ttl_ms: 60_000,
    };
    let probe = request(
        ResponseAction::QuarantineFile {
            host_id: "host-1".to_string(),
            file_path: "   ".to_string(),
        },
        Severity::High,
    );
    let context = context(1_700_000_000_000);
    let store = Arc::new(MemoryContainmentLeaseStore::new());
    let ttl = ContainmentTtl::from_config_ms(900_000).unwrap();

    negative_protocol::assert_registered_negative_case! {
        case: RUNTIME_CONTAINMENT_PREVIEW_REQUIRED,
        mutation: ContainmentPreflightMutation,
        control: ContainmentPreflightMutation::None,
        broken: ContainmentPreflightMutation::SkipContainmentPreviewError,
        state: {
            gate: FixedVerdictGate = gate,
            context: ApprovalContext = context,
            store: Arc<MemoryContainmentLeaseStore> = store,
            ttl: ContainmentTtl = ttl,
        },
        probe: ActionRequest = probe,
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_runtime::SwarmRuntime::preflight_containment,
        arguments: (&(SwarmRuntime::new(RuntimeMode::LiveResponse, gate.clone(), RecordingExecutor::default())
                .with_containment_store(store.clone(), *ttl)), probe, context, ExecutionMode::Enforced),
        call: sync,
        normalize: |production_result| production_result.is_ok(),
        mirror: |_state, probe, mutation| mirrored_preflight_containment(true, probe, ExecutionMode::Enforced, mutation).is_ok(),
        denied: |result| !result,
        permitted: |result| *result,
    }
}

// ---------------------------------------------------------------------------
// RUNTIME-RELEASE-SUBJECT-BOUND
// ---------------------------------------------------------------------------

fn sample_rollback_receipt(step_status: RollbackStepStatus) -> RollbackReceipt {
    RollbackReceipt {
        rollback_id: "rollback:negative".to_string(),
        lease_id: "containment:negative".to_string(),
        origin_receipt_id: "resp:negative".to_string(),
        governance_receipt_id: Some("gov:negative".to_string()),
        trigger: RollbackTrigger::Expiry,
        mode: ExecutionMode::Enforced,
        status: ResponseStatus::Failed,
        steps: vec![RollbackStepOutcome {
            kind: swarm_core::types::ResponseRollbackStepKind::RestoreHostConnectivity,
            status: step_status,
            detail: "the containment stays in effect".to_string(),
        }],
        completed_at_ms: 2_000,
        summary: "expiry trigger on `isolate_host`".to_string(),
        governance_attestation: None,
    }
}

fn governance_anchor() -> Arc<GovernancePolicy> {
    let policy = Arc::new(GovernancePolicy::new(GovernancePolicyConfig::default()));
    policy
        .register_governor(
            AgentId::new("tom", "negative-runtime"),
            SigningKey::from_bytes(&[41; 32]),
        )
        .expect("the first fixture governor key registers");
    policy
}

fn release_subject_value(receipt: &RollbackReceipt) -> serde_json::Value {
    let mut subject = receipt.clone();
    subject.governance_attestation = None;
    serde_json::to_value(subject).unwrap()
}

/// Use the real sealed governance authority's release-signing path.
fn attest(receipt: &RollbackReceipt, governance: &GovernancePolicy) -> serde_json::Value {
    serde_json::to_value(
        governance
            .attest_release(&release_subject_value(receipt), 2_000)
            .expect("the registered fixture governor attests the release"),
    )
    .unwrap()
}

/// Produce an internally valid, subject-bound attestation from a key that is
/// deliberately absent from `governance_anchor()`.
fn foreign_attest(receipt: &RollbackReceipt) -> serde_json::Value {
    let signing_key = SigningKey::from_bytes(&[251; 32]);
    let issued_by = AgentId::from_verifying_key(&signing_key.verifying_key());
    let committee = ConsensusCommittee::new(vec![issued_by.clone()], 0).unwrap();
    let mut subject = receipt.clone();
    subject.governance_attestation = None;
    let proposal_id = sha256_hex(&canonical_json_bytes(&subject).unwrap());
    let commit = ConsensusCommit {
        height: 1,
        round: 0,
        committee_id: committee.committee_id().to_string(),
        proposal: ConsensusProposal {
            proposal_id,
            payload: json!({"foreign": true}),
        },
        prevote_tally: 1,
        precommit_tally: 1,
        commit_hash: "foreign-commit".to_string(),
    };
    serde_json::to_value(
        ConsensusGovernanceReceipt::issue(
            &commit,
            "foreign-previous-commit",
            &committee,
            GovernanceReceiptDecision::Approve,
            issued_by,
            &signing_key,
            9_999,
        )
        .unwrap(),
    )
    .unwrap()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleaseAttestationMutation {
    None,
    SkipAttestationRequired,
    SkipMalformedAttestation,
    SkipSignatureValidation,
    SkipTrustedSigner,
    SkipSubjectBinding,
}

/// Mirror of `verify_release_attestation`, copied from
/// `crates/swarm-runtime/src/containment.rs`, with the subject binding
/// selectively removable -- mutation M2 from ce1ddd1, made permanent as a test.
fn mirrored_verify_release_attestation(
    receipt: &RollbackReceipt,
    governance: &dyn GovernanceAuthority,
    mutation: ReleaseAttestationMutation,
) -> Result<(), String> {
    let Some(raw) = receipt.governance_attestation.as_ref().cloned() else {
        return if mutation == ReleaseAttestationMutation::SkipAttestationRequired {
            Ok(())
        } else {
            Err("unattested".to_string())
        };
    };
    let attestation: ConsensusGovernanceReceipt = match serde_json::from_value(raw) {
        Ok(attestation) => attestation,
        Err(_) if mutation == ReleaseAttestationMutation::SkipMalformedAttestation => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    if mutation != ReleaseAttestationMutation::SkipSignatureValidation {
        attestation.verify().map_err(|error| error.to_string())?;
    }
    if mutation != ReleaseAttestationMutation::SkipTrustedSigner
        && !governance
            .governor_public_keys()
            .contains(&attestation.payload.issued_by)
    {
        return Err(format!(
            "untrusted signer: {}",
            attestation.payload.issued_by
        ));
    }
    let mut subject = receipt.clone();
    subject.governance_attestation = None;
    let derived = sha256_hex(&canonical_json_bytes(&subject).map_err(|error| error.to_string())?);
    if mutation != ReleaseAttestationMutation::SkipSubjectBinding
        && attestation.payload.proposal_id != derived
    {
        return Err(format!(
            "subject mismatch: attested {}, derived {derived}",
            attestation.payload.proposal_id
        ));
    }
    Ok(())
}

#[test]
fn broken_attestation_requirement_accepts_an_unattested_release() {
    let governance = governance_anchor();
    let receipt = sample_rollback_receipt(RollbackStepStatus::Reversed);
    negative_protocol::assert_registered_negative_case! {
        case: RUNTIME_RELEASE_ATTESTATION_REQUIRED,
        mutation: ReleaseAttestationMutation,
        control: ReleaseAttestationMutation::None,
        broken: ReleaseAttestationMutation::SkipAttestationRequired,
        state: {
            governance: Arc<GovernancePolicy> = governance,
        },
        probe: RollbackReceipt = receipt,
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_runtime::containment::verify_release_attestation,
        arguments: (probe, Some(governance.as_ref())),
        call: sync,
        normalize: |production_result| production_result.is_ok(),
        mirror: |_state, probe, mutation| mirrored_verify_release_attestation(probe, governance.as_ref(), mutation).is_ok(),
        denied: |value| !value,
        permitted: |value| *value,
    }
}

#[test]
fn broken_attestation_shape_guard_accepts_malformed_governance_json() {
    let governance = governance_anchor();
    let mut receipt = sample_rollback_receipt(RollbackStepStatus::Reversed);
    receipt.governance_attestation = Some(json!({"broken": true}));
    negative_protocol::assert_registered_negative_case! {
        case: RUNTIME_RELEASE_ATTESTATION_WELL_FORMED,
        mutation: ReleaseAttestationMutation,
        control: ReleaseAttestationMutation::None,
        broken: ReleaseAttestationMutation::SkipMalformedAttestation,
        state: {
            governance: Arc<GovernancePolicy> = governance,
        },
        probe: RollbackReceipt = receipt,
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_runtime::containment::verify_release_attestation,
        arguments: (probe, Some(governance.as_ref())),
        call: sync,
        normalize: |production_result| production_result.is_ok(),
        mirror: |_state, probe, mutation| mirrored_verify_release_attestation(probe, governance.as_ref(), mutation).is_ok(),
        denied: |value| !value,
        permitted: |value| *value,
    }
}

#[test]
fn broken_release_signature_guard_accepts_a_bad_governor_signature() {
    let governance = governance_anchor();
    let mut receipt = sample_rollback_receipt(RollbackStepStatus::Reversed);
    let mut attestation: ConsensusGovernanceReceipt =
        serde_json::from_value(attest(&receipt, governance.as_ref())).unwrap();
    let replacement = if attestation.signature.signature_hex.starts_with('0') {
        "1"
    } else {
        "0"
    };
    attestation
        .signature
        .signature_hex
        .replace_range(0..1, replacement);
    receipt.governance_attestation = Some(serde_json::to_value(attestation).unwrap());
    negative_protocol::assert_registered_negative_case! {
        case: RUNTIME_RELEASE_SIGNATURE_VALID,
        mutation: ReleaseAttestationMutation,
        control: ReleaseAttestationMutation::None,
        broken: ReleaseAttestationMutation::SkipSignatureValidation,
        state: {
            governance: Arc<GovernancePolicy> = governance,
        },
        probe: RollbackReceipt = receipt,
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_runtime::containment::verify_release_attestation,
        arguments: (probe, Some(governance.as_ref())),
        call: sync,
        normalize: |production_result| production_result.is_ok(),
        mirror: |_state, probe, mutation| mirrored_verify_release_attestation(probe, governance.as_ref(), mutation).is_ok(),
        denied: |value| !value,
        permitted: |value| *value,
    }
}

#[test]
fn broken_release_signer_trust_accepts_a_valid_foreign_attestation() {
    let governance = governance_anchor();
    let mut receipt = sample_rollback_receipt(RollbackStepStatus::Reversed);
    receipt.governance_attestation = Some(foreign_attest(&receipt));
    let attestation: ConsensusGovernanceReceipt = serde_json::from_value(
        receipt
            .governance_attestation
            .clone()
            .expect("the foreign fixture carries an attestation"),
    )
    .unwrap();
    attestation
        .verify()
        .expect("the foreign attestation is internally valid");
    let mut subject = receipt.clone();
    subject.governance_attestation = None;
    assert_eq!(
        attestation.payload.proposal_id,
        sha256_hex(&canonical_json_bytes(&subject).unwrap()),
        "the foreign attestation remains bound to this release"
    );

    negative_protocol::assert_registered_negative_case! {
        case: RUNTIME_RELEASE_SIGNER_TRUSTED,
        mutation: ReleaseAttestationMutation,
        control: ReleaseAttestationMutation::None,
        broken: ReleaseAttestationMutation::SkipTrustedSigner,
        state: {
            governance: Arc<GovernancePolicy> = governance,
        },
        probe: RollbackReceipt = receipt,
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_runtime::containment::verify_release_attestation,
        arguments: (probe, Some(governance.as_ref())),
        call: sync,
        normalize: |production_result| production_result.is_ok(),
        mirror: |_state, probe, mutation| mirrored_verify_release_attestation(probe, governance.as_ref(), mutation).is_ok(),
        denied: |value| !value,
        permitted: |value| *value,
    }
}

#[test]
fn broken_subject_binding_accepts_the_rewritten_receipt_the_real_verifier_refuses() {
    let governance = governance_anchor();
    // A release that did NOT land: the inverse failed and the host is still
    // contained. A governor attested that fact.
    let mut attested = sample_rollback_receipt(RollbackStepStatus::Failed);
    attested.governance_attestation = Some(attest(&attested, governance.as_ref()));
    verify_release_attestation(&attested, Some(governance.as_ref()))
        .expect("the genuine attestation verifies");

    // Now the stored artifact is rewritten to claim the host was restored. The
    // ed25519 signature is NOT touched and still verifies on its own -- it
    // covers the governance payload, which says nothing about these steps.
    let mut rewritten = attested.clone();
    rewritten.steps[0].status = RollbackStepStatus::Reversed;
    assert!(rewritten.fully_reversed());

    negative_protocol::assert_registered_negative_case! {
        case: RUNTIME_RELEASE_SUBJECT_BOUND,
        mutation: ReleaseAttestationMutation,
        control: ReleaseAttestationMutation::None,
        broken: ReleaseAttestationMutation::SkipSubjectBinding,
        state: {
            governance: Arc<GovernancePolicy> = governance,
        },
        probe: RollbackReceipt = rewritten,
        outcome: bool,
        real_probe: probe,
        production: crate::__phase285_swarm_runtime::containment::verify_release_attestation,
        arguments: (probe, Some(governance.as_ref())),
        call: sync,
        normalize: |production_result| production_result.is_ok(),
        mirror: |_state, probe, mutation| mirrored_verify_release_attestation(probe, governance.as_ref(), mutation).is_ok(),
        denied: |value| !value,
        permitted: |value| *value,
    }
}

// ---------------------------------------------------------------------------
// RUNTIME-FAILED-ROLLBACK-KEEPS-LEASE
// ---------------------------------------------------------------------------

/// A rollback executor that reports the shape a real transport failure takes:
/// `Ok` with a `Failed` step, NOT `Err`. `HttpEdrRollbackExecutor` returns `Err`
/// only for an empty step list, so a fake that errors would exercise a shape
/// production never emits -- which is how the original test for this contract
/// managed to be green over the region it was meant to guard.
#[derive(Debug)]
struct FailingRollbackExecutor;

#[async_trait]
impl RollbackExecutor for FailingRollbackExecutor {
    async fn rollback(
        &self,
        lease: &ContainmentLease,
        trigger: RollbackTrigger,
        mode: ExecutionMode,
        completed_at_ms: i64,
    ) -> Result<RollbackReceipt, ResponseError> {
        Ok(RollbackReceipt::from_steps(
            lease,
            trigger,
            mode,
            completed_at_ms,
            vec![RollbackStepOutcome {
                kind: swarm_core::types::ResponseRollbackStepKind::ReleaseQuarantinedFile,
                status: RollbackStepStatus::Failed,
                detail: "could not be issued; the containment stays in effect".to_string(),
            }],
        ))
    }
}

fn containment_lease() -> ContainmentLease {
    use swarm_core::types::{
        ResponseBlastRadiusImpact, ResponseBlastRadiusPreview, ResponseRehearsalPreview,
        ResponseRehearsalScopeKind, ResponseRollbackPreview, ResponseRollbackStep,
        ResponseRollbackStepKind,
    };
    ContainmentLease::open(
        "containment:negative",
        ResponseAction::QuarantineFile {
            host_id: "host-1".to_string(),
            file_path: "/tmp/evil".to_string(),
        },
        "resp:negative",
        Some("gov:negative".to_string()),
        &ResponseRehearsalPreview {
            rehearsal_id: "rehearsal:negative".to_string(),
            source_bundle_id: "bundle:negative".to_string(),
            prepared_at_ms: 1_000,
            simulated_only: true,
            blast_radius: ResponseBlastRadiusPreview {
                scope_kind: ResponseRehearsalScopeKind::File,
                scope_value: "host-1:/tmp/evil".to_string(),
                impact: ResponseBlastRadiusImpact::FileQuarantined,
                max_affected_scopes: 1,
                affected_capabilities: vec!["file_access".to_string()],
                summary: "one quarantined file".to_string(),
            },
            rollback: ResponseRollbackPreview {
                required: true,
                summary: "release the quarantined file".to_string(),
                steps: vec![ResponseRollbackStep {
                    kind: ResponseRollbackStepKind::ReleaseQuarantinedFile,
                    summary: "release".to_string(),
                }],
            },
        },
        1_000,
        ContainmentTtl::from_config_ms(4_000).unwrap(),
    )
    .expect("the fixture lease is bounded")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleaseLeaseMutation {
    None,
    SkipFailedStepRetention,
}

/// Mirror of `release_lease`, copied from
/// `crates/swarm-runtime/src/containment.rs`, with the `attempt_failed` early
/// return selectively removable -- the pre-cc5b169 shape, which read "could
/// not be issued" as `Err` and therefore never saw this case.
async fn mirrored_release_lease(
    store: &dyn ContainmentLeaseStore,
    executor: &dyn RollbackExecutor,
    mode: ExecutionMode,
    lease_id: &str,
    now_ms: i64,
    mutation: ReleaseLeaseMutation,
) -> Result<RollbackReceipt, String> {
    let lease = store
        .get(lease_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("no open containment lease `{lease_id}`"))?;
    let receipt = executor
        .rollback(&lease, RollbackTrigger::Expiry, mode, now_ms)
        .await
        .map_err(|error| error.to_string())?;
    let attempt_failed = receipt
        .steps
        .iter()
        .any(|step| step.status == RollbackStepStatus::Failed);
    if mutation != ReleaseLeaseMutation::SkipFailedStepRetention && attempt_failed {
        return Ok(receipt);
    }
    store.close(&receipt).map_err(|error| error.to_string())?;
    Ok(receipt)
}

#[test]
fn broken_failed_step_check_abandons_the_still_contained_host_the_real_release_retains() {
    let lease = containment_lease();
    let store = MemoryContainmentLeaseStore::new();
    store.open_lease(&lease).unwrap();
    negative_protocol::assert_registered_negative_case! {
        case: RUNTIME_FAILED_ROLLBACK_KEEPS_LEASE,
        mutation: ReleaseLeaseMutation,
        control: ReleaseLeaseMutation::None,
        broken: ReleaseLeaseMutation::SkipFailedStepRetention,
        state: { store: MemoryContainmentLeaseStore = store },
        probe: ContainmentLease = lease.clone(),
        outcome: (RollbackStepStatus, usize, usize),
        real_probe: probe,
        production: crate::__phase285_swarm_runtime::containment::release_lease,
        arguments: (&*store, &FailingRollbackExecutor, ExecutionMode::Enforced, probe.lease_id(), RollbackTrigger::Expiry, 6_000, None),
        call: awaited,
        normalize: |production_result| {
            let receipt = production_result.expect("receipt");
            (receipt.steps[0].status, store.open_leases().unwrap().len(), store.closed_receipts().unwrap().len())
        },
        mirror: |_state, probe, mutation| {
            let store = MemoryContainmentLeaseStore::new();
            store.open_lease(probe).unwrap();
            let receipt = mirrored_release_lease(&store, &FailingRollbackExecutor, ExecutionMode::Enforced, probe.lease_id(), 6_000, mutation).await.expect("receipt");
            (receipt.steps[0].status, store.open_leases().unwrap().len(), store.closed_receipts().unwrap().len())
        },
        denied: |result| result == &(RollbackStepStatus::Failed, 1, 0),
        permitted: |result| result == &(RollbackStepStatus::Failed, 0, 1),
    }

    // Control: a rollback that DOES land closes the lease on the real path, so
    // the retention above is about the failure and not about `release_lease`
    // never closing anything.
    #[derive(Debug)]
    struct ReversingExecutor;

    #[async_trait]
    impl RollbackExecutor for ReversingExecutor {
        async fn rollback(
            &self,
            lease: &ContainmentLease,
            trigger: RollbackTrigger,
            mode: ExecutionMode,
            completed_at_ms: i64,
        ) -> Result<RollbackReceipt, ResponseError> {
            Ok(RollbackReceipt::from_steps(
                lease,
                trigger,
                mode,
                completed_at_ms,
                vec![RollbackStepOutcome {
                    kind: swarm_core::types::ResponseRollbackStepKind::ReleaseQuarantinedFile,
                    status: RollbackStepStatus::Reversed,
                    detail: "released".to_string(),
                }],
            ))
        }
    }

    let ok_store = MemoryContainmentLeaseStore::new();
    ok_store.open_lease(&lease).unwrap();
    let reversed = negative_protocol::block_on_ready(release_lease(
        &ok_store,
        &ReversingExecutor,
        ExecutionMode::Enforced,
        lease.lease_id(),
        RollbackTrigger::Expiry,
        6_000,
        None,
    ))
    .expect("a landed rollback");
    assert!(reversed.fully_reversed());
    assert_eq!(ok_store.open_leases().unwrap().len(), 0);
    assert_eq!(ok_store.closed_receipts().unwrap().len(), 1);
}
