//! The read behind `/policy`. Rules in file order, and the per-triple evaluation
//! the daemon computes with the gate's own predicate so no client re-implements it.
//!
//! Shadowing is a property of a triple, not of a rule: the same rule decides
//! one triple and is `not_matched` for another. So the evaluation is always
//! for a named triple, and every rule gets one of three words — `decides`,
//! `not_matched` (looked at, did not select), `not_reached` (after the one
//! that decided). When nothing matches, the static gate's answer is spelled
//! out rather than left to the reader.

use serde::{Deserialize, Serialize};
use swarm_core::config::{PolicyConfig, PolicyRuleConfig, PolicyRuleDecision};
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_policy::ActionRequest;
use swarm_policy::configurable_gate::ConfigurableApprovalGate;
use swarm_policy::static_gate::destructive_action_kinds;

/// The triple a policy decision is a function of.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyTriple {
    pub threat_class: ThreatClass,
    pub severity: Severity,
    /// A `ResponseAction::kind()` slug, e.g. `block_egress`.
    pub action: String,
}

/// What one rule did for one triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleVerdict {
    /// First match in file order; this rule's decision is the answer.
    Decides,
    /// Looked at and did not select the triple.
    NotMatched,
    /// After the deciding rule; never looked at.
    NotReached,
}

/// One rule's verdict, by its index in file order.
#[derive(Debug, Clone, Serialize)]
pub struct RuleVerdictView {
    pub rule_index: usize,
    pub verdict: RuleVerdict,
}

/// Where a triple no rule matched ends up.
#[derive(Debug, Clone, Serialize)]
pub struct Fallthrough {
    pub gate: &'static str,
    pub verdict: &'static str,
    pub reason: &'static str,
}

/// The triple, echoed back so a response cannot be read against the wrong ask.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyTripleEcho {
    pub threat_class: ThreatClass,
    pub severity: Severity,
    pub action: String,
}

/// The daemon's own evaluation of one triple against the configured rules.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyEvaluation {
    pub triple: PolicyTripleEcho,
    pub verdicts: Vec<RuleVerdictView>,
    pub fallthrough: Option<Fallthrough>,
    /// True when the deciding rule is `allow` and the action is one of the
    /// twelve destructive kinds at or above `human_gate_severity` — a rule
    /// that lets a destructive action through without the human the static
    /// gate would have asked.
    pub outranks_human_gate: bool,
    /// The permanent caveat: `threat_class` and `severity` are carried by the
    /// requesting agent, so this evaluation reads what a request would SAY.
    pub warning: &'static str,
}

const WARNING: &str = "request_carried_selectors";
const STATIC_HOLD_REASON: &str = "authorized but held for human approval";

/// Build the minimal `ActionRequest` `selector_matches` reads: severity, the
/// action, and the threat class inside `evidence["escalation"]` — the
/// request-carried fields the warning is about. `None` when `action` is not a
/// kind the response enum knows.
fn request_for(triple: &PolicyTriple) -> Option<ActionRequest> {
    // Every field any variant of the tagged enum requires; the untagged
    // extras are ignored, so one object serves all fifteen kinds.
    let action: ResponseAction = serde_json::from_value(serde_json::json!({
        "type": triple.action,
        "target": "evaluator",
        "host_id": "evaluator",
        "credential_id": "evaluator",
        "domain": "evaluator",
        "session_id": "evaluator",
        "scan_profile": "evaluator",
        "rule_name": "evaluator",
        "direction": "evaluator",
        "cidr": "0.0.0.0/0",
        "port": null,
        "file_path": "evaluator",
        "process_name": "evaluator",
        "user_id": "evaluator",
        "task_name": "evaluator",
        "decoy_type": "evaluator",
        "target_zone": "evaluator",
        "summary": "evaluator",
        "urgency": "LOW"
    }))
    .ok()?;
    Some(ActionRequest {
        hunt_id: HuntId("perch-policy-evaluator".into()),
        requested_by: AgentId("perch-policy-evaluator".into()),
        action,
        severity: triple.severity,
        evidence: serde_json::json!({ "escalation": { "threat_class": triple.threat_class } }),
    })
}

/// First match in file order decides. Everything after it is `not_reached`;
/// everything before it is `not_matched`.
pub fn evaluate_triple(policy: &PolicyConfig, triple: &PolicyTriple) -> PolicyEvaluation {
    let echo = PolicyTripleEcho {
        threat_class: triple.threat_class.clone(),
        severity: triple.severity,
        action: triple.action.clone(),
    };
    let Some(request) = request_for(triple) else {
        return PolicyEvaluation {
            triple: echo,
            verdicts: Vec::new(),
            fallthrough: None,
            outranks_human_gate: false,
            warning: WARNING,
        };
    };
    let mut verdicts = Vec::with_capacity(policy.rules.len());
    let mut decided: Option<&PolicyRuleConfig> = None;
    for (index, rule) in policy.rules.iter().enumerate() {
        let verdict = if decided.is_some() {
            RuleVerdict::NotReached
        } else if ConfigurableApprovalGate::selector_matches(rule, &request, &triple.threat_class) {
            decided = Some(rule);
            RuleVerdict::Decides
        } else {
            RuleVerdict::NotMatched
        };
        verdicts.push(RuleVerdictView {
            rule_index: index,
            verdict,
        });
    }
    let destructive = destructive_action_kinds().contains(&triple.action.as_str());
    let at_or_above_gate = triple.severity >= policy.human_gate_severity;
    let fallthrough = if decided.is_none() {
        Some(if destructive && at_or_above_gate {
            Fallthrough {
                gate: "static",
                verdict: "require_human",
                reason: STATIC_HOLD_REASON,
            }
        } else {
            Fallthrough {
                gate: "static",
                verdict: "allow",
                reason: "static.default_allow",
            }
        })
    } else {
        None
    };
    let outranks_human_gate = matches!(decided, Some(rule) if rule.decision == PolicyRuleDecision::Allow)
        && destructive
        && at_or_above_gate;
    PolicyEvaluation {
        triple: echo,
        verdicts,
        fallthrough,
        outranks_human_gate,
        warning: WARNING,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn shipped_policy() -> PolicyConfig {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../rulesets/default.yaml"
        ))
        .unwrap();
        let config: swarm_core::config::SwarmConfig = serde_yaml::from_str(&raw).unwrap();
        config.policy
    }

    #[test]
    fn the_shipped_c2_rule_outranks_the_human_gate_at_critical() {
        let policy = shipped_policy();
        let evaluation = evaluate_triple(
            &policy,
            &PolicyTriple {
                threat_class: ThreatClass::CommandAndControl,
                severity: Severity::Critical,
                action: "block_egress".into(),
            },
        );
        let decides: Vec<_> = evaluation
            .verdicts
            .iter()
            .filter(|v| v.verdict == RuleVerdict::Decides)
            .collect();
        assert_eq!(decides.len(), 1);
        assert_eq!(
            decides[0].rule_index, 1,
            "command-and-control-emergency-block is the second rule in file order"
        );
        assert_eq!(evaluation.verdicts[0].verdict, RuleVerdict::NotMatched);
        assert_eq!(evaluation.verdicts[2].verdict, RuleVerdict::NotReached);
        assert!(evaluation.fallthrough.is_none());
        assert!(
            evaluation.outranks_human_gate,
            "block_egress is destructive and human_gate_severity is HIGH, yet this triple is allowed outright"
        );
    }

    #[test]
    fn an_unmatched_triple_falls_through_to_the_static_gate() {
        let policy = shipped_policy();
        let evaluation = evaluate_triple(
            &policy,
            &PolicyTriple {
                threat_class: ThreatClass::Impact,
                severity: Severity::High,
                action: "isolate_host".into(),
            },
        );
        assert!(
            evaluation
                .verdicts
                .iter()
                .all(|v| v.verdict == RuleVerdict::NotMatched)
        );
        let fallthrough = evaluation.fallthrough.unwrap();
        assert_eq!(fallthrough.verdict, "require_human");
        assert_eq!(fallthrough.reason, STATIC_HOLD_REASON);
        assert!(!evaluation.outranks_human_gate);
    }

    #[test]
    fn a_non_destructive_unmatched_triple_is_allowed_by_default() {
        let policy = shipped_policy();
        let evaluation = evaluate_triple(
            &policy,
            &PolicyTriple {
                threat_class: ThreatClass::Impact,
                severity: Severity::Low,
                action: "escalate".into(),
            },
        );
        assert_eq!(evaluation.fallthrough.unwrap().verdict, "allow");
    }

    #[test]
    fn an_unknown_action_kind_evaluates_nothing() {
        let policy = shipped_policy();
        let evaluation = evaluate_triple(
            &policy,
            &PolicyTriple {
                threat_class: ThreatClass::Execution,
                severity: Severity::High,
                action: "not_an_action".into(),
            },
        );
        assert!(evaluation.verdicts.is_empty());
        assert!(evaluation.fallthrough.is_none());
    }

    #[test]
    fn every_destructive_kind_slug_is_a_response_action_kind() {
        for kind in destructive_action_kinds() {
            let triple = PolicyTriple {
                threat_class: ThreatClass::Execution,
                severity: Severity::Critical,
                action: (*kind).to_string(),
            };
            let request = request_for(&triple).unwrap_or_else(|| panic!("{kind} deserializes"));
            assert_eq!(request.action.kind(), *kind);
        }
        assert_eq!(destructive_action_kinds().len(), 12);
    }
}
