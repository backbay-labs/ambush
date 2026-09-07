//! FALSIFY-02 negative-falsifiability test for
//! `PolicyScopeRateLimitDeniesBurst` (docs/assurance/MAPPING.md).
//!
//! `scope_rate_limit_decision` (crates/swarm-policy/src/static_gate.rs:211-231)
//! denies an action once its target scope has already issued
//! `max_actions_per_scope_per_minute` actions inside the trailing 60 seconds
//! of wall-clock time. The function itself is private; `evaluate`
//! (static_gate.rs:291-293) calls it and is the `pub` entry point this test
//! reaches it through -- the same path
//! `scope_rate_limit_denies_burst_for_same_scope` in static_gate.rs's own
//! `#[cfg(test)]` module already uses for positive coverage.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use swarm_core::config::PolicyConfig;
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_policy::static_gate::StaticApprovalGate;
use swarm_policy::{ActionRequest, ApprovalContext, ApprovalGate, PolicyVerdict};

fn sample_context_at(now_ms: i64) -> ApprovalContext {
    ApprovalContext {
        live_mode: true,
        receipt_chain: vec![],
        correlation_id: None,
        now_ms,
    }
}

/// A deliberately broken re-implementation of `scope_rate_limit_decision`'s
/// budget check (crates/swarm-policy/src/static_gate.rs:220-227) with the
/// `window.len() >= max_actions_per_scope_per_minute` comparison removed: a
/// scope may burst without limit no matter how many actions it already
/// issued inside the trailing window.
fn broken_scope_rate_limit_permits(
    _window_len_before_this_action: usize,
    _max_per_minute: usize,
) -> bool {
    true
}

#[test]
fn negative_policy_scope_rate_limit_denies_burst() {
    let gate = StaticApprovalGate::from_config(&PolicyConfig {
        max_actions_per_scope_per_minute: 1,
        ..PolicyConfig::default()
    });
    let request = ActionRequest {
        hunt_id: HuntId("hunt-negative-3".to_string()),
        requested_by: AgentId("whisker-a".to_string()),
        action: ResponseAction::BlockEgress {
            target: "203.0.113.10".to_string(),
        },
        severity: Severity::Medium,
        evidence: serde_json::json!({"signal": "egress"}),
    };

    // 1. The REAL function allows the first action in the scope's window,
    // then denies the second action 100ms later -- still inside the
    // trailing 60s window, over the configured budget of 1.
    let first = gate
        .evaluate(&request, &sample_context_at(1_700_000_000_000))
        .unwrap();
    let second = gate
        .evaluate(&request, &sample_context_at(1_700_000_000_100))
        .unwrap();
    assert_eq!(first.verdict, PolicyVerdict::Allow);
    assert_eq!(
        second.verdict,
        PolicyVerdict::Deny,
        "real evaluate must deny the second action in the same scope's burst"
    );
    assert_eq!(second.rule_name, "static.scope_rate_limit");

    // 2. The broken variant permits the same burst: after the first action
    // fills the scope's one-action budget, it is asked whether a second
    // action may proceed and (wrongly) says yes.
    assert!(
        broken_scope_rate_limit_permits(1, 1),
        "broken variant is expected to (wrongly) permit the burst"
    );
}
