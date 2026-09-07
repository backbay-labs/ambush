//! FALSIFY-02 negative-falsifiability test for
//! `RuntimeRequireHumanBlocksLiveExecution` (docs/assurance/MAPPING.md).
//!
//! `SwarmRuntime::authorize_and_execute` (crates/swarm-runtime/src/lib.rs:972-1046)
//! denies executing a request whose policy verdict is `RequireHuman` while
//! the runtime is running in `RuntimeMode::LiveResponse` -- no destructive
//! action auto-executes live without a human-approved path
//! (lib.rs:993-995). `authorize_and_execute` is `pub`, so this test calls it
//! directly.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use swarm_core::config::RuntimeMode;
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_policy::static_gate::StaticApprovalGate;
use swarm_policy::{ActionRequest, ApprovalContext, ApprovalError, PolicyVerdict};
use swarm_response::adapters::SandboxExecutor;
use swarm_runtime::{RuntimeError, SwarmRuntime};

fn sample_context() -> ApprovalContext {
    ApprovalContext {
        live_mode: true,
        receipt_chain: vec![],
        correlation_id: None,
        now_ms: 1_700_000_000_000,
    }
}

/// A deliberately broken re-implementation of `authorize_and_execute`'s
/// verdict routing (crates/swarm-runtime/src/lib.rs:990-996) with the
/// live-mode `RequireHuman` guard removed: a `RequireHuman` verdict is
/// routed the same as `Allow` in every runtime mode, including
/// `LiveResponse`.
fn broken_route_verdict(verdict: PolicyVerdict, _mode: RuntimeMode) -> Result<(), String> {
    match verdict {
        PolicyVerdict::Deny => Err("denied".to_string()),
        PolicyVerdict::Allow | PolicyVerdict::RequireHuman => Ok(()),
    }
}

#[tokio::test]
async fn negative_runtime_require_human_blocks_live_execution() {
    // `StaticApprovalGate::default()` sets `human_gate_severity = High`; a
    // Critical BlockEgress is destructive and at/above that severity, so
    // `evaluate` returns `RequireHuman`.
    let gate = StaticApprovalGate::default();
    let runtime = SwarmRuntime::new(RuntimeMode::LiveResponse, gate, SandboxExecutor);

    let request = ActionRequest {
        hunt_id: HuntId("hunt-negative-4".to_string()),
        requested_by: AgentId("whisker-a".to_string()),
        action: ResponseAction::BlockEgress {
            target: "203.0.113.10".to_string(),
        },
        severity: Severity::Critical,
        evidence: serde_json::json!({"signal": "egress"}),
    };

    // 1. The REAL runtime denies executing the RequireHuman-verdict request
    // while running live.
    let real_error = runtime
        .authorize_and_execute(&request, &sample_context())
        .await
        .unwrap_err();
    assert!(
        matches!(real_error, RuntimeError::Approval(ApprovalError::Denied(_))),
        "real authorize_and_execute must deny RequireHuman under LiveResponse, got {real_error}"
    );

    // 2. The broken variant permits the identical (verdict, mode) pair.
    assert!(
        broken_route_verdict(PolicyVerdict::RequireHuman, RuntimeMode::LiveResponse).is_ok(),
        "broken variant is expected to (wrongly) permit RequireHuman under LiveResponse"
    );
}
