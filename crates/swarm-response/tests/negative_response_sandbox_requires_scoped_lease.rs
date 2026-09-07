//! FALSIFY-02 negative-falsifiability test for
//! `ResponseSandboxRequiresScopedLease` (docs/assurance/MAPPING.md).
//!
//! `SandboxExecutor::execute` (crates/swarm-response/src/adapters.rs:12-47)
//! denies executing a destructive/containment-class response action when its
//! `CapabilityLease` carries no `scope` -- an unbounded blast radius. Both
//! the trait method and the executor are `pub`, so this test calls it
//! directly, the same way `sandbox_executor_returns_structured_failure_when_scope_missing`
//! in adapters.rs's own `#[cfg(test)]` module already does for positive
//! coverage.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_policy::{ActionRequest, CapabilityLease};
use swarm_response::adapters::SandboxExecutor;
use swarm_response::{ExecutionMode, ResponseExecutor};

/// A deliberately broken re-implementation of `SandboxExecutor::execute`'s
/// scope guard (crates/swarm-response/src/adapters.rs:20-48) with the
/// `lease.scope.is_none()` half of the check removed: a destructive action
/// executes through an unscoped lease regardless.
fn broken_requires_scoped_lease(
    _is_destructive_or_containment: bool,
    _lease_scope: &Option<String>,
) -> Result<(), String> {
    Ok(())
}

#[tokio::test]
async fn negative_response_sandbox_requires_scoped_lease() {
    let executor = SandboxExecutor;
    let request = ActionRequest {
        hunt_id: HuntId("hunt-negative-13".to_string()),
        requested_by: AgentId("whisker-a".to_string()),
        action: ResponseAction::IsolateHost {
            host_id: "host-1".to_string(),
        },
        severity: Severity::High,
        evidence: serde_json::json!({"signal": "contain"}),
    };
    let lease = CapabilityLease {
        capability_id: "lease-negative-13".to_string(),
        expires_at_ms: 1_700_000_060_000,
        action: "isolate_host".to_string(),
        scope: None,
    };

    // 1. The REAL executor denies a destructive action carried on an
    // unscoped lease.
    let real_result = executor
        .execute(&request, &lease, ExecutionMode::Enforced)
        .await;
    assert!(
        real_result.is_err(),
        "real SandboxExecutor::execute must deny a destructive action with no lease scope"
    );

    // 2. The broken variant permits the identical (action, lease) pair.
    assert!(
        broken_requires_scoped_lease(true, &lease.scope).is_ok(),
        "broken variant is expected to (wrongly) permit the unscoped destructive action"
    );
}
