//! Hold fixtures shared across crate lines, behind `#[cfg(test)]` here and the
//! `test-fixtures` feature elsewhere.
//!
//! `held_action`'s own tests are `#[cfg(test)]`, so `swarm-runtime-http` and
//! `swarm-ingest-runtime` cannot see them: a `#[cfg(test)]` module is compiled
//! only into its own crate's test target. Rather than each of those crates
//! hand-rolling a `HeldAction` — which drifts, and drifted fixtures are how a
//! route test ends up asserting against a record the daemon would never
//! produce — the builders live here once.
//!
//! The gate is `#[cfg(any(test, feature = "test-fixtures"))]` and the feature
//! is declared by dev-dependencies only, so nothing here reaches the daemon.

#![cfg(any(test, feature = "test-fixtures"))]

use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_policy::{ActionRequest, PolicyDecision, PolicyVerdict};

use crate::held_action::{HeldAction, mint_hold_id};

/// A fixed instant, so a test's arithmetic is readable rather than relative.
pub const T0: i64 = 1_773_739_200_000;

/// One `ActionRequest` carrying the escalation evidence `HoldRationale::derive`
/// reads: a threat class and a level.
pub fn fixture_request(action: ResponseAction) -> ActionRequest {
    ActionRequest {
        hunt_id: HuntId("hunt-evt-1".to_string()),
        requested_by: AgentId::from_public_key_hex(&"18".repeat(32)),
        action,
        severity: Severity::Critical,
        evidence: serde_json::json!({
            "escalation": { "threat_class": "execution", "level": "alert" }
        }),
    }
}

/// A `created` hold with a one-hour TTL, built the way `HoldCapture` builds one.
pub fn fixture_hold(action: ResponseAction, held_at_ms: i64) -> HeldAction {
    let request = fixture_request(action);
    let detection = routed_detection_for_fixture(&request);
    HeldAction::new(
        mint_hold_id(),
        request,
        detection,
        PolicyDecision {
            verdict: PolicyVerdict::RequireHuman,
            rule_name: "static.human_gate".to_string(),
            reason: "authorized but held for human approval".to_string(),
        },
        None,
        held_at_ms,
        held_at_ms + 3_600_000,
        Some("trail-1".to_string()),
    )
}

/// The ingest crate's `routed_detection_from_request`, mirrored so a fixture
/// needs no dependency on the crate that depends on this one.
pub fn routed_detection_for_fixture(request: &ActionRequest) -> swarm_whisker::DetectionFinding {
    swarm_whisker::DetectionFinding {
        finding_id: format!("finding:{}", request.hunt_id.0),
        event_id: request.hunt_id.0.clone(),
        strategy_id: "test".to_string(),
        threat_class: swarm_core::pheromone::ThreatClass::Execution,
        severity: request.severity,
        confidence: 1.0,
        evidence: request.evidence.clone(),
    }
}
