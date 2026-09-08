//! FALSIFY-02 negative-falsifiability test for
//! `PolicyHumanGateOnDestructiveAction` (docs/assurance/MAPPING.md).
//!
//! `StaticApprovalGate::evaluate` (now `swarm_policy::formal_core::human_gate_decision`, crates/swarm-policy/src/formal_core.rs:344,351, reached through `evaluate`)
//! holds a destructive action at or above the configured human-gate severity
//! for human approval (`RequireHuman`) instead of letting it auto-execute.
//! `evaluate` is `pub` via the `ApprovalGate` trait, so this test calls it
//! directly.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_policy::static_gate::StaticApprovalGate;
use swarm_policy::{ActionRequest, ApprovalContext, ApprovalGate, PolicyVerdict};

fn sample_context() -> ApprovalContext {
    ApprovalContext {
        live_mode: true,
        receipt_chain: vec!["receipt-1".to_string()],
        correlation_id: None,
        now_ms: 1_700_000_000_000,
    }
}

/// A deliberately broken re-implementation of the human-gate branch inside
/// `StaticApprovalGate::evaluate` (now `swarm_policy::formal_core::human_gate_decision`, crates/swarm-policy/src/formal_core.rs:344,351, reached through `evaluate`)
/// with the destructive-action-at-or-above-gate-severity guard removed:
/// every request that reaches this point is routed straight to allow, never
/// held for a human.
fn broken_route_decision(_is_destructive: bool, _severity_at_or_above_gate: bool) -> &'static str {
    "allow"
}

#[test]
fn negative_policy_human_gate_on_destructive_action() {
    // `StaticApprovalGate::default()` sets `human_gate_severity = Severity::High`.
    let gate = StaticApprovalGate::default();
    let request = ActionRequest {
        hunt_id: HuntId("hunt-negative-2".to_string()),
        requested_by: AgentId("whisker-a".to_string()),
        action: ResponseAction::BlockEgress {
            target: "203.0.113.10".to_string(),
        },
        severity: Severity::Critical,
        evidence: serde_json::json!({"signal": "egress"}),
    };

    // 1. The REAL function holds a Critical BlockEgress for human approval
    // rather than auto-executing it.
    let decision = gate.evaluate(&request, &sample_context()).unwrap();
    assert_eq!(
        decision.verdict,
        PolicyVerdict::RequireHuman,
        "real evaluate must hold a Critical BlockEgress for human approval"
    );
    assert_eq!(decision.rule_name, "static.human_gate");

    // 2. The broken variant auto-allows the identical request.
    assert_eq!(
        broken_route_decision(true, true),
        "allow",
        "broken variant is expected to (wrongly) auto-allow the same request"
    );
}
