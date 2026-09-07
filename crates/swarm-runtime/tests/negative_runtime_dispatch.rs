//! Differential controls for the two production dispatch-journal invariants.
//! The broken variant preserves the real policy gate, active lease and executor
//! but omits the journal boundary. It is deliberately test-local and is not a
//! substitute for the persistent crash/recovery DST and production mutations.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use swarm_core::config::RuntimeMode;
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_policy::static_gate::StaticApprovalGate;
use swarm_policy::{
    ActionRequest, ApprovalContext, ApprovalError, ApprovalGate, CapabilityLease, PolicyVerdict,
};
use swarm_response::{
    ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt, ResponseStatus,
};
use swarm_runtime::dispatch_journal::DispatchJournal;
use swarm_runtime::{RuntimeError, SwarmRuntime};

#[derive(Clone, Default)]
struct RecordingExecutor {
    calls: Arc<AtomicUsize>,
}

impl RecordingExecutor {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ResponseExecutor for RecordingExecutor {
    async fn execute(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        mode: ExecutionMode,
    ) -> Result<ResponseReceipt, ResponseError> {
        assert_eq!(mode, ExecutionMode::Enforced);
        assert_eq!(lease.action, request.action.kind());
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ResponseReceipt {
            receipt_id: format!("negative-dispatch:{}:{call}", request.hunt_id.0),
            action: request.action.kind().into(),
            mode,
            status: ResponseStatus::Executed,
            summary: "recorded enforced invocation".into(),
            details: serde_json::json!({"request": request, "call": call}),
            audit: Default::default(),
        })
    }
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        for _ in 0..128 {
            let path = std::env::temp_dir().join(format!(
                "ambush-negative-dispatch-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create isolated negative-test directory: {error}"),
            }
        }
        panic!("unable to allocate isolated negative-test directory");
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn request() -> ActionRequest {
    ActionRequest {
        hunt_id: HuntId("negative-dispatch-request".into()),
        requested_by: AgentId("negative-dispatch-principal".into()),
        action: ResponseAction::Escalate {
            summary: "exercise the dispatch journal boundary".into(),
            urgency: Severity::Medium,
        },
        severity: Severity::Medium,
        evidence: serde_json::json!({"signal": "negative-dispatch-control"}),
    }
}

fn context() -> ApprovalContext {
    ApprovalContext {
        live_mode: true,
        receipt_chain: Vec::new(),
        correlation_id: Some("negative-dispatch-control".into()),
        now_ms: 1_700_000_000_000,
    }
}

/// Deliberate regression: evaluate the actual policy and mint its actual lease,
/// then dispatch without either the mandatory journal or its identity reserve.
/// The fixture is Escalate/Medium: no optional guard or containment preparation
/// is needed. Deny and RequireHuman still refuse, as in the real live runtime.
async fn broken_dispatch_without_journal(
    policy: &StaticApprovalGate,
    executor: &RecordingExecutor,
    request: &ActionRequest,
    context: &ApprovalContext,
) -> Result<ResponseReceipt, RuntimeError> {
    let decision = policy.evaluate(request, context)?;
    if decision.verdict != PolicyVerdict::Allow {
        return Err(ApprovalError::Denied(decision.reason).into());
    }
    let lease = policy.issue_lease(request, context)?;
    if lease.expires_at_ms <= context.now_ms {
        return Err(ApprovalError::Denied("capability lease expired".into()).into());
    }
    Ok(executor
        .execute(request, &lease, ExecutionMode::Enforced)
        .await?)
}

#[tokio::test]
async fn negative_runtime_dispatch_intent_required() {
    let request = request();
    let context = context();
    assert_eq!(
        StaticApprovalGate::default()
            .evaluate(&request, &context)
            .unwrap()
            .verdict,
        PolicyVerdict::Allow,
    );
    let real_executor = RecordingExecutor::default();
    let runtime = SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        StaticApprovalGate::default(),
        real_executor.clone(),
    );

    // The identical allowed request cannot reach the real enforced executor
    // when its runtime has no durable journal configured.
    let error = runtime
        .authorize_and_execute(&request, &context)
        .await
        .unwrap_err();
    let RuntimeError::Response(error) = error else {
        panic!("expected missing-journal response refusal, got {error}");
    };
    assert_eq!(error.failure.details["status"], "dispatch_refused");
    assert_eq!(error.failure.details["prior_reservation"], false);
    assert!(error.failure.message.contains("journal is not configured"));
    assert_eq!(real_executor.calls(), 0);

    let broken_executor = RecordingExecutor::default();
    let broken_policy = StaticApprovalGate::default();
    let receipt =
        broken_dispatch_without_journal(&broken_policy, &broken_executor, &request, &context)
            .await
            .unwrap();
    assert_eq!(receipt.status, ResponseStatus::Executed);
    assert_eq!(
        receipt.details["request"],
        serde_json::to_value(&request).unwrap()
    );
    assert_eq!(broken_executor.calls(), 1);

    // The broken variant omits the journal, not policy authorization. Check
    // actual Deny and RequireHuman inputs so an always-allow helper cannot
    // masquerade as a differential control for the dispatch-intent boundary.
    for (severity, expected) in [
        (Severity::Low, PolicyVerdict::Deny),
        (Severity::High, PolicyVerdict::RequireHuman),
    ] {
        let mut denied = request.clone();
        denied.action = ResponseAction::IsolateHost {
            host_id: "negative-control.invalid".into(),
        };
        denied.severity = severity;
        assert_eq!(
            StaticApprovalGate::default()
                .evaluate(&denied, &context)
                .unwrap()
                .verdict,
            expected,
        );
        let error =
            broken_dispatch_without_journal(&broken_policy, &broken_executor, &denied, &context)
                .await
                .unwrap_err();
        assert!(matches!(
            error,
            RuntimeError::Approval(ApprovalError::Denied(_))
        ));
        assert_eq!(broken_executor.calls(), 1);
    }
}

#[tokio::test]
async fn negative_runtime_dispatch_identity_consumed_once() {
    let scratch = Scratch::new();
    let journal = Arc::new(DispatchJournal::open(scratch.0.join("journal")).unwrap());
    let request = request();
    let context = context();
    let real_executor = RecordingExecutor::default();
    let runtime = SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        StaticApprovalGate::default(),
        real_executor.clone(),
    )
    .with_dispatch_journal(journal);

    let first = runtime
        .authorize_and_execute(&request, &context)
        .await
        .unwrap();
    assert_eq!(first.status, ResponseStatus::Executed);
    assert_eq!(real_executor.calls(), 1);
    let error = runtime
        .authorize_and_execute(&request, &context)
        .await
        .unwrap_err();
    let RuntimeError::Response(error) = error else {
        panic!("expected consumed-identity response refusal, got {error}");
    };
    assert_eq!(error.failure.details["status"], "dispatch_refused");
    assert_eq!(error.failure.details["prior_reservation"], true);
    assert!(error.failure.message.contains("already reserved"));
    assert_eq!(real_executor.calls(), 1);

    // Same two requests and real gate/executor, with only the journal boundary
    // omitted: the second effect now occurs instead of being refused.
    let broken_executor = RecordingExecutor::default();
    let broken_policy = StaticApprovalGate::default();
    for expected_calls in 1..=2 {
        let receipt =
            broken_dispatch_without_journal(&broken_policy, &broken_executor, &request, &context)
                .await
                .unwrap();
        assert_eq!(receipt.status, ResponseStatus::Executed);
        assert_eq!(
            receipt.details["request"],
            serde_json::to_value(&request).unwrap()
        );
        assert_eq!(broken_executor.calls(), expected_calls);
    }
    assert_eq!(real_executor.calls(), 1);
    assert_eq!(broken_executor.calls(), 2);
}
