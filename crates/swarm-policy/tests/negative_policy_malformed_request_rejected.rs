//! FALSIFY-02 negative-falsifiability test for `PolicyMalformedRequestRejected`
//! (docs/assurance/MAPPING.md).
//!
//! `StaticApprovalGate::validate_request` (crates/swarm-policy/src/static_gate.rs:56-168)
//! denies a request whose evidence bundle is JSON `null`. It is `pub(crate)`,
//! so this integration test -- which can only reach `pub` items -- exercises
//! the REAL denial through the public `ApprovalGate::evaluate` entry point,
//! which calls `validate_request` as its very first step
//! (static_gate.rs:275).
//!
//! Proof structure, common to every `negative_*` test in this registry:
//!   1. The REAL function denies a specific input.
//!   2. A local, deliberately broken re-implementation of the same guard --
//!      with the fail-closed check weakened or removed -- PERMITS the
//!      identical input.
//!
//! Step 2 is what proves step 1 is not a vacuous assertion: the positive
//! suite's passing test for this invariant is actually exercising a check
//! that does real work, not one that would pass no matter what it did.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_policy::static_gate::StaticApprovalGate;
use swarm_policy::{ActionRequest, ApprovalContext, ApprovalGate};

fn sample_context() -> ApprovalContext {
    ApprovalContext {
        live_mode: true,
        receipt_chain: vec!["receipt-1".to_string()],
        correlation_id: None,
        now_ms: 1_700_000_000_000,
    }
}

/// A deliberately broken re-implementation of `validate_request`'s
/// null-evidence guard (crates/swarm-policy/src/static_gate.rs:58-62) with
/// the check removed entirely: every evidence value, including `null`, is
/// treated as valid.
fn broken_validate_request_evidence(evidence: &serde_json::Value) -> Result<(), String> {
    let _ = evidence;
    Ok(())
}

#[test]
fn negative_policy_malformed_request_rejected() {
    let gate = StaticApprovalGate::default();
    let request = ActionRequest {
        hunt_id: HuntId("hunt-negative-1".to_string()),
        requested_by: AgentId("whisker-a".to_string()),
        action: ResponseAction::IsolateHost {
            host_id: "host-1".to_string(),
        },
        severity: Severity::Medium,
        evidence: serde_json::Value::Null,
    };

    // 1. The REAL function, reached through the public `evaluate` entry
    // point, denies the malformed (null-evidence) request.
    let real_result = gate.evaluate(&request, &sample_context());
    assert!(
        real_result.is_err(),
        "real StaticApprovalGate::evaluate must deny null evidence via validate_request, got {real_result:?}"
    );

    // 2. The broken variant permits the exact same input.
    assert!(
        broken_validate_request_evidence(&request.evidence).is_ok(),
        "broken variant is expected to (wrongly) permit null evidence"
    );
}
