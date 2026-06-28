use crate::{
    ActionRequest, ApprovalContext, ApprovalError, ApprovalGate, CapabilityLease, PolicyDecision,
};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use swarm_core::config::{PolicyConfig, PolicyRuleConfig, PolicyRuleDecision};
use swarm_core::pheromone::ThreatClass;

use crate::static_gate::StaticApprovalGate;

/// Ordered YAML-backed policy evaluator composed with static fallback behavior.
#[derive(Debug, Clone)]
pub struct ConfigurableApprovalGate {
    static_gate: StaticApprovalGate,
    rules: Vec<PolicyRuleConfig>,
    agent_windows: Arc<Mutex<HashMap<String, VecDeque<i64>>>>,
}

impl Default for ConfigurableApprovalGate {
    fn default() -> Self {
        Self::from_config(&PolicyConfig::default())
    }
}

impl ConfigurableApprovalGate {
    pub fn from_config(config: &PolicyConfig) -> Self {
        Self {
            static_gate: StaticApprovalGate::from_config(config),
            rules: config.rules.clone(),
            agent_windows: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn threat_class_from_request(request: &ActionRequest) -> Option<ThreatClass> {
        request
            .evidence
            .get("escalation")
            .and_then(|value| value.get("threat_class"))
            .cloned()
            .or_else(|| request.evidence.get("threat_class").cloned())
            .and_then(|value| serde_json::from_value(value).ok())
    }

    fn selector_matches(
        rule: &PolicyRuleConfig,
        request: &ActionRequest,
        threat_class: &ThreatClass,
    ) -> bool {
        rule.threat_class == *threat_class
            && request.severity >= rule.min_severity
            && request.severity <= rule.max_severity
            && (rule.actions.is_empty()
                || rule
                    .actions
                    .iter()
                    .any(|action| action.matches(&request.action)))
    }

    fn current_hour_utc(now_ms: i64) -> u8 {
        now_ms.div_euclid(1_000).div_euclid(3_600).rem_euclid(24) as u8
    }

    fn agent_window_key(rule: &PolicyRuleConfig, request: &ActionRequest) -> String {
        format!("{}:{}", rule.name, request.requested_by.0)
    }

    fn lock_windows(&self) -> MutexGuard<'_, HashMap<String, VecDeque<i64>>> {
        self.agent_windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn prune_window(window: &mut VecDeque<i64>, now_ms: i64) {
        while window
            .front()
            .is_some_and(|timestamp| *timestamp <= now_ms.saturating_sub(60_000))
        {
            window.pop_front();
        }
    }

    fn agent_limit_exceeded(
        &self,
        rule: &PolicyRuleConfig,
        request: &ActionRequest,
        now_ms: i64,
        limit: usize,
    ) -> bool {
        let key = Self::agent_window_key(rule, request);
        let mut windows = self.lock_windows();
        let window = windows.entry(key).or_default();
        Self::prune_window(window, now_ms);
        if window.len() >= limit {
            return true;
        }
        window.push_back(now_ms);
        false
    }

    fn allow_reason(rule: &PolicyRuleConfig) -> String {
        rule.reason
            .clone()
            .unwrap_or_else(|| format!("authorized by policy rule `{}`", rule.name))
    }

    fn deny_reason(rule: &PolicyRuleConfig) -> String {
        rule.reason
            .clone()
            .unwrap_or_else(|| format!("denied by policy rule `{}`", rule.name))
    }
}

impl ApprovalGate for ConfigurableApprovalGate {
    fn evaluate(
        &self,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<PolicyDecision, ApprovalError> {
        let trace_id = context
            .correlation_id
            .clone()
            .or_else(swarm_core::observability::current_trace_id)
            .unwrap_or_else(|| "unknown".to_string());
        let span = tracing::info_span!(
            "policy.configurable.evaluate",
            trace_id = %trace_id,
            hunt_id = %request.hunt_id.0,
            requested_by = %request.requested_by.0,
            action = %request.action.kind(),
            severity = ?request.severity
        );
        let _guard = span.enter();

        self.static_gate.validate_request(request)?;

        if self.rules.is_empty() {
            return Ok(PolicyDecision::deny_with_rule(
                "configurable.fail_closed.empty_ruleset",
                "no configurable policy rules loaded; failing closed",
            ));
        }

        let threat_class = Self::threat_class_from_request(request);
        if let Some(threat_class) = threat_class.as_ref() {
            for rule in &self.rules {
                if !Self::selector_matches(rule, request, threat_class) {
                    continue;
                }

                if let Some(window) = rule.time_window_utc {
                    let hour = Self::current_hour_utc(context.now_ms);
                    if !window.contains_hour(hour) {
                        return Ok(PolicyDecision::deny_with_rule(
                            rule.name.clone(),
                            format!("rule `{}` is inactive at {:02}:00 UTC", rule.name, hour),
                        ));
                    }
                }

                if let Some(limit) = rule.max_actions_per_agent_per_minute
                    && self.agent_limit_exceeded(rule, request, context.now_ms, limit)
                {
                    return Ok(PolicyDecision::deny_with_rule(
                        rule.name.clone(),
                        format!(
                            "agent `{}` exceeded rule limit of {} actions per minute",
                            request.requested_by.0, limit
                        ),
                    ));
                }

                return Ok(match rule.decision {
                    PolicyRuleDecision::Allow => {
                        PolicyDecision::allow_with_rule(rule.name.clone(), Self::allow_reason(rule))
                    }
                    PolicyRuleDecision::Deny => {
                        PolicyDecision::deny_with_rule(rule.name.clone(), Self::deny_reason(rule))
                    }
                });
            }
        }

        self.static_gate.evaluate(request, context)
    }

    fn issue_lease(
        &self,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<CapabilityLease, ApprovalError> {
        self.static_gate.issue_lease(request, context)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::ConfigurableApprovalGate;
    use crate::{ActionRequest, ApprovalContext, ApprovalGate, PolicyVerdict};
    use serde_json::json;
    use swarm_core::config::{
        PolicyActionSelector, PolicyConfig, PolicyRuleConfig, PolicyRuleDecision,
        PolicyTimeWindowConfig,
    };
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};

    fn sample_context(now_ms: i64) -> ApprovalContext {
        ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-1".to_string()],
            correlation_id: None,
            now_ms,
        }
    }

    fn sample_request(
        action: ResponseAction,
        severity: Severity,
        threat_class: ThreatClass,
    ) -> ActionRequest {
        ActionRequest {
            hunt_id: HuntId("hunt-1".to_string()),
            requested_by: AgentId("pounce-1".to_string()),
            action,
            severity,
            evidence: json!({
                "escalation": {
                    "threat_class": threat_class,
                    "severity": severity,
                }
            }),
        }
    }

    fn matching_rule() -> PolicyRuleConfig {
        PolicyRuleConfig {
            name: "execution-allow".to_string(),
            decision: PolicyRuleDecision::Allow,
            threat_class: ThreatClass::Execution,
            actions: vec![PolicyActionSelector::DeployDecoy],
            min_severity: Severity::High,
            max_severity: Severity::Critical,
            time_window_utc: None,
            max_actions_per_agent_per_minute: None,
            reason: Some("execution response is approved".to_string()),
        }
    }

    #[test]
    fn configurable_gate_denies_when_rules_are_empty() {
        let gate = ConfigurableApprovalGate::from_config(&PolicyConfig::default());
        let request = sample_request(
            ResponseAction::Escalate {
                summary: "review".to_string(),
                urgency: Severity::High,
            },
            Severity::High,
            ThreatClass::Execution,
        );

        let decision = gate
            .evaluate(&request, &sample_context(1_700_000_000_000))
            .unwrap();
        assert_eq!(decision.verdict, PolicyVerdict::Deny);
        assert_eq!(decision.rule_name, "configurable.fail_closed.empty_ruleset");
    }

    #[test]
    fn configurable_gate_applies_matching_allow_rule() {
        let mut config = PolicyConfig::default();
        config.rules.push(matching_rule());
        let gate = ConfigurableApprovalGate::from_config(&config);
        let request = sample_request(
            ResponseAction::DeployDecoy {
                decoy_type: "honeypot".to_string(),
                target_zone: "dmz".to_string(),
            },
            Severity::High,
            ThreatClass::Execution,
        );

        let decision = gate
            .evaluate(&request, &sample_context(1_700_000_000_000))
            .unwrap();
        assert_eq!(decision.verdict, PolicyVerdict::Allow);
        assert_eq!(decision.rule_name, "execution-allow");
    }

    #[test]
    fn configurable_gate_denies_outside_allowed_hours() {
        let mut config = PolicyConfig::default();
        let mut rule = matching_rule();
        rule.time_window_utc = Some(PolicyTimeWindowConfig {
            start_hour_utc: 18,
            end_hour_utc: 24,
        });
        config.rules.push(rule);
        let gate = ConfigurableApprovalGate::from_config(&config);
        let request = sample_request(
            ResponseAction::DeployDecoy {
                decoy_type: "honeypot".to_string(),
                target_zone: "dmz".to_string(),
            },
            Severity::High,
            ThreatClass::Execution,
        );

        let decision = gate
            .evaluate(&request, &sample_context(1_700_020_800_000))
            .unwrap();
        assert_eq!(decision.verdict, PolicyVerdict::Deny);
        assert_eq!(decision.rule_name, "execution-allow");
    }

    #[test]
    fn configurable_gate_enforces_per_agent_rate_limit() {
        let mut config = PolicyConfig::default();
        let mut rule = matching_rule();
        rule.max_actions_per_agent_per_minute = Some(1);
        config.rules.push(rule);
        let gate = ConfigurableApprovalGate::from_config(&config);
        let request = sample_request(
            ResponseAction::DeployDecoy {
                decoy_type: "honeypot".to_string(),
                target_zone: "dmz".to_string(),
            },
            Severity::High,
            ThreatClass::Execution,
        );

        let first = gate
            .evaluate(&request, &sample_context(1_700_000_000_000))
            .unwrap();
        let second = gate
            .evaluate(&request, &sample_context(1_700_000_000_100))
            .unwrap();
        assert_eq!(first.verdict, PolicyVerdict::Allow);
        assert_eq!(second.verdict, PolicyVerdict::Deny);
        assert_eq!(second.rule_name, "execution-allow");
    }

    #[test]
    fn configurable_gate_falls_back_to_static_gate_when_no_rule_matches() {
        let mut config = PolicyConfig::default();
        config.rules.push(PolicyRuleConfig {
            name: "c2-only".to_string(),
            decision: PolicyRuleDecision::Deny,
            threat_class: ThreatClass::CommandAndControl,
            actions: vec![PolicyActionSelector::BlockEgress],
            min_severity: Severity::Critical,
            max_severity: Severity::Critical,
            time_window_utc: None,
            max_actions_per_agent_per_minute: None,
            reason: None,
        });
        let gate = ConfigurableApprovalGate::from_config(&config);
        let request = sample_request(
            ResponseAction::Escalate {
                summary: "review".to_string(),
                urgency: Severity::High,
            },
            Severity::High,
            ThreatClass::Execution,
        );

        let decision = gate
            .evaluate(&request, &sample_context(1_700_000_000_000))
            .unwrap();
        assert_eq!(decision.verdict, PolicyVerdict::Allow);
        assert_eq!(decision.rule_name, "static.default_allow");
    }
}
