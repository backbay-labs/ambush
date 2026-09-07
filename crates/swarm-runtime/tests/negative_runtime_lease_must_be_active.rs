//! FALSIFY-02 negative-falsifiability test for `RuntimeLeaseMustBeActive`
//! (docs/assurance/MAPPING.md).
//!
//! `ensure_active_lease` (crates/swarm-runtime/src/lib.rs:1417-1424) denies
//! executing a response through a `CapabilityLease` whose `expires_at_ms`
//! has already passed. The function itself is private; `authorize_and_execute`
//! (lib.rs:1029) calls it right after minting the lease, and is the `pub`
//! entry point this test reaches it through.
//!
//! Per task-1-report.md section 5, the shipped default lease TTL never lets
//! a freshly issued lease already be expired within the same call (`issue_lease`
//! and `ensure_active_lease` are evaluated against the SAME `context.now_ms`),
//! so the only way to drive the real denial from outside the crate is a
//! `PolicyConfig.lease_ttl_ms <= 0`, which makes `expires_at_ms == now_ms`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use swarm_core::config::{PolicyConfig, RuntimeMode};
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_policy::static_gate::StaticApprovalGate;
use swarm_policy::{ActionRequest, ApprovalContext, ApprovalError};
use swarm_response::adapters::SandboxExecutor;
use swarm_runtime::{RuntimeError, SwarmRuntime};

/// A deliberately weakened re-implementation of `ensure_active_lease`
/// (crates/swarm-runtime/src/lib.rs:1418-1424) with the boundary condition
/// weakened from `<=` to `<`: a lease that expires AT exactly `now_ms` is
/// wrongly treated as still active.
fn broken_ensure_active_lease(expires_at_ms: i64, now_ms: i64) -> Result<(), String> {
    if expires_at_ms < now_ms {
        return Err("capability lease expired".to_string());
    }
    Ok(())
}

#[tokio::test]
async fn negative_runtime_lease_must_be_active() {
    let config = PolicyConfig {
        lease_ttl_ms: 0,
        ..PolicyConfig::default()
    };
    let gate = StaticApprovalGate::from_config(&config);
    let runtime = SwarmRuntime::new(RuntimeMode::LiveResponse, gate, SandboxExecutor);

    let now_ms = 1_700_000_000_000;
    let context = ApprovalContext {
        live_mode: true,
        receipt_chain: vec![],
        correlation_id: None,
        now_ms,
    };
    // Escalate is non-destructive (skips the human gate) and not a
    // containment action (needs no lease store), so the lease-expiry check
    // under test is the ONLY thing that can deny it.
    let request = ActionRequest {
        hunt_id: HuntId("hunt-negative-5".to_string()),
        requested_by: AgentId("whisker-a".to_string()),
        action: ResponseAction::Escalate {
            summary: "review needed".to_string(),
            urgency: Severity::Medium,
        },
        severity: Severity::Medium,
        evidence: serde_json::json!({"signal": "example"}),
    };

    // 1. The REAL runtime denies executing through the already-expired
    // (expires_at_ms == now_ms) lease.
    let real_error = runtime
        .authorize_and_execute(&request, &context)
        .await
        .unwrap_err();
    let RuntimeError::Approval(ApprovalError::Denied(reason)) = &real_error else {
        panic!("real authorize_and_execute must deny via ApprovalError::Denied, got {real_error}");
    };
    assert!(
        reason.contains("expired"),
        "expected an expiry-related denial reason, got `{reason}`"
    );

    // 2. The broken variant, given the SAME boundary case, wrongly treats
    // the lease as still active.
    assert!(
        broken_ensure_active_lease(now_ms, now_ms).is_ok(),
        "broken variant is expected to (wrongly) permit a lease expiring exactly now"
    );
}
