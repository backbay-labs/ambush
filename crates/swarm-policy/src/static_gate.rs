use crate::{
    ActionRequest, ApprovalContext, ApprovalError, ApprovalGate, CapabilityLease, PolicyDecision,
};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use swarm_core::config::PolicyConfig;
use swarm_core::types::{ResponseAction, Severity};

/// Minimal deterministic gate for the first live-response slice.
#[derive(Debug, Clone)]
pub struct StaticApprovalGate {
    /// Severity at or above which destructive actions require human confirmation.
    pub human_gate_severity: Severity,
    /// Lease TTL for authorized requests.
    pub lease_ttl_ms: i64,
    /// Per-scope one-minute action budget.
    pub max_actions_per_scope_per_minute: usize,
    scope_windows: Arc<Mutex<HashMap<String, VecDeque<i64>>>>,
}

impl Default for StaticApprovalGate {
    fn default() -> Self {
        Self::from_config(&PolicyConfig::default())
    }
}

impl StaticApprovalGate {
    pub fn from_config(config: &PolicyConfig) -> Self {
        Self {
            human_gate_severity: config.human_gate_severity,
            lease_ttl_ms: config.lease_ttl_ms,
            max_actions_per_scope_per_minute: config.max_actions_per_scope_per_minute,
            scope_windows: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn destructive_action(request: &ActionRequest) -> bool {
        matches!(
            request.action,
            ResponseAction::BlockEgress { .. }
                | ResponseAction::IsolateHost { .. }
                | ResponseAction::RevokeCredential { .. }
                | ResponseAction::SinkholeDns { .. }
                | ResponseAction::TerminateUserSession { .. }
                | ResponseAction::InjectFirewallRule { .. }
                | ResponseAction::QuarantineFile { .. }
                | ResponseAction::KillProcess { .. }
                | ResponseAction::SuspendProcess { .. }
                | ResponseAction::DisableUserAccount { .. }
                | ResponseAction::ForcePasswordReset { .. }
                | ResponseAction::RemoveScheduledTask { .. }
        )
    }

    pub(crate) fn validate_request(&self, request: &ActionRequest) -> Result<(), ApprovalError> {
        if request.evidence.is_null() {
            return Err(ApprovalError::InvalidRequest(
                "evidence bundle must not be null".to_string(),
            ));
        }

        match &request.action {
            ResponseAction::BlockEgress { target } if target.trim().is_empty() => {
                return Err(ApprovalError::InvalidRequest(
                    "block target must not be empty".to_string(),
                ));
            }
            ResponseAction::IsolateHost { host_id } if host_id.trim().is_empty() => {
                return Err(ApprovalError::InvalidRequest(
                    "host_id must not be empty".to_string(),
                ));
            }
            ResponseAction::RevokeCredential { credential_id }
                if credential_id.trim().is_empty() =>
            {
                return Err(ApprovalError::InvalidRequest(
                    "credential_id must not be empty".to_string(),
                ));
            }
            ResponseAction::SinkholeDns { domain } if domain.trim().is_empty() => {
                return Err(ApprovalError::InvalidRequest(
                    "domain must not be empty".to_string(),
                ));
            }
            ResponseAction::TerminateUserSession {
                host_id,
                session_id,
            } if host_id.trim().is_empty() || session_id.trim().is_empty() => {
                return Err(ApprovalError::InvalidRequest(
                    "host_id and session_id must not be empty".to_string(),
                ));
            }
            ResponseAction::TriggerEdrScan {
                host_id,
                scan_profile,
            } if host_id.trim().is_empty() || scan_profile.trim().is_empty() => {
                return Err(ApprovalError::InvalidRequest(
                    "host_id and scan_profile must not be empty".to_string(),
                ));
            }
            ResponseAction::InjectFirewallRule {
                host_id,
                rule_name,
                direction,
                cidr,
                ..
            } if host_id.trim().is_empty()
                || rule_name.trim().is_empty()
                || direction.trim().is_empty()
                || cidr.trim().is_empty() =>
            {
                return Err(ApprovalError::InvalidRequest(
                    "host_id, rule_name, direction, and cidr must not be empty".to_string(),
                ));
            }
            ResponseAction::QuarantineFile { host_id, file_path }
                if host_id.trim().is_empty() || file_path.trim().is_empty() =>
            {
                return Err(ApprovalError::InvalidRequest(
                    "host_id and file_path must not be empty".to_string(),
                ));
            }
            ResponseAction::KillProcess {
                host_id,
                process_name,
            }
            | ResponseAction::SuspendProcess {
                host_id,
                process_name,
            } if host_id.trim().is_empty() || process_name.trim().is_empty() => {
                return Err(ApprovalError::InvalidRequest(
                    "host_id and process_name must not be empty".to_string(),
                ));
            }
            ResponseAction::DisableUserAccount { user_id }
            | ResponseAction::ForcePasswordReset { user_id }
                if user_id.trim().is_empty() =>
            {
                return Err(ApprovalError::InvalidRequest(
                    "user_id must not be empty".to_string(),
                ));
            }
            ResponseAction::RemoveScheduledTask { host_id, task_name }
                if host_id.trim().is_empty() || task_name.trim().is_empty() =>
            {
                return Err(ApprovalError::InvalidRequest(
                    "host_id and task_name must not be empty".to_string(),
                ));
            }
            ResponseAction::DeployDecoy {
                decoy_type,
                target_zone,
            } if decoy_type.trim().is_empty() || target_zone.trim().is_empty() => {
                return Err(ApprovalError::InvalidRequest(
                    "decoy_type and target_zone must not be empty".to_string(),
                ));
            }
            ResponseAction::Escalate { summary, .. } if summary.trim().is_empty() => {
                return Err(ApprovalError::InvalidRequest(
                    "summary must not be empty".to_string(),
                ));
            }
            _ => {}
        }
        Ok(())
    }

    fn action_name(&self, action: &ResponseAction) -> &'static str {
        match action {
            ResponseAction::BlockEgress { .. } => "block_egress",
            ResponseAction::IsolateHost { .. } => "isolate_host",
            ResponseAction::RevokeCredential { .. } => "revoke_credential",
            ResponseAction::SinkholeDns { .. } => "sinkhole_dns",
            ResponseAction::TerminateUserSession { .. } => "terminate_user_session",
            ResponseAction::TriggerEdrScan { .. } => "trigger_edr_scan",
            ResponseAction::InjectFirewallRule { .. } => "inject_firewall_rule",
            ResponseAction::QuarantineFile { .. } => "quarantine_file",
            ResponseAction::KillProcess { .. } => "kill_process",
            ResponseAction::SuspendProcess { .. } => "suspend_process",
            ResponseAction::DisableUserAccount { .. } => "disable_user_account",
            ResponseAction::ForcePasswordReset { .. } => "force_password_reset",
            ResponseAction::RemoveScheduledTask { .. } => "remove_scheduled_task",
            ResponseAction::DeployDecoy { .. } => "deploy_decoy",
            ResponseAction::Escalate { .. } => "escalate",
        }
    }

    fn scope_bucket(request: &ActionRequest) -> String {
        scope_for_response_action(&request.action)
            .unwrap_or_else(|| format!("unscoped:{}", request.action.kind()))
    }

    fn lock_windows(&self) -> MutexGuard<'_, HashMap<String, VecDeque<i64>>> {
        self.scope_windows
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

    fn scope_rate_limit_decision(
        &self,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Option<PolicyDecision> {
        let scope = Self::scope_bucket(request);
        let mut windows = self.lock_windows();
        let window = windows.entry(scope.clone()).or_default();
        Self::prune_window(window, context.now_ms);
        if window.len() >= self.max_actions_per_scope_per_minute {
            return Some(PolicyDecision::deny_with_rule(
                "static.scope_rate_limit",
                format!(
                    "scope `{scope}` exceeded {} actions per minute",
                    self.max_actions_per_scope_per_minute
                ),
            ));
        }
        window.push_back(context.now_ms);
        None
    }
}

pub fn scope_for_response_action(action: &ResponseAction) -> Option<String> {
    match action {
        ResponseAction::BlockEgress { target } => Some(target.clone()),
        ResponseAction::IsolateHost { host_id } => Some(host_id.clone()),
        ResponseAction::RevokeCredential { credential_id } => Some(credential_id.clone()),
        ResponseAction::SinkholeDns { domain } => Some(domain.clone()),
        ResponseAction::TerminateUserSession {
            host_id,
            session_id,
        } => Some(format!("{host_id}:{session_id}")),
        ResponseAction::TriggerEdrScan { host_id, .. } => Some(host_id.clone()),
        ResponseAction::InjectFirewallRule {
            host_id, rule_name, ..
        } => Some(format!("{host_id}:{rule_name}")),
        ResponseAction::QuarantineFile { host_id, file_path } => {
            Some(format!("{host_id}:{file_path}"))
        }
        ResponseAction::KillProcess {
            host_id,
            process_name,
        }
        | ResponseAction::SuspendProcess {
            host_id,
            process_name,
        } => Some(format!("{host_id}:{process_name}")),
        ResponseAction::DisableUserAccount { user_id }
        | ResponseAction::ForcePasswordReset { user_id } => Some(user_id.clone()),
        ResponseAction::RemoveScheduledTask { host_id, task_name } => {
            Some(format!("{host_id}:{task_name}"))
        }
        ResponseAction::DeployDecoy { target_zone, .. } => Some(target_zone.clone()),
        ResponseAction::Escalate { .. } => None,
    }
}

impl ApprovalGate for StaticApprovalGate {
    fn evaluate(
        &self,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<PolicyDecision, ApprovalError> {
        self.validate_request(request)?;

        if Self::destructive_action(request) && request.severity == Severity::Low {
            return Ok(PolicyDecision::deny_with_rule(
                "static.minimum_severity",
                "destructive actions require at least medium severity",
            ));
        }

        if matches!(request.action, ResponseAction::DeployDecoy { .. })
            && request.severity == Severity::Low
        {
            return Ok(PolicyDecision::deny_with_rule(
                "static.deploy_decoy_min_severity",
                "deploy_decoy requires at least medium severity",
            ));
        }

        if let Some(decision) = self.scope_rate_limit_decision(request, context) {
            return Ok(decision);
        }

        if Self::destructive_action(request) && request.severity >= self.human_gate_severity {
            return Ok(PolicyDecision::require_human_with_rule(
                "static.human_gate",
                "authorized but held for human approval",
            ));
        }

        Ok(PolicyDecision::allow_with_rule(
            "static.default_allow",
            "authorized for immediate execution",
        ))
    }

    fn issue_lease(
        &self,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<CapabilityLease, ApprovalError> {
        self.validate_request(request)?;
        Ok(CapabilityLease {
            capability_id: format!(
                "lease:{}:{}:{}",
                request.hunt_id.0,
                self.action_name(&request.action),
                context.now_ms
            ),
            expires_at_ms: context.now_ms + self.lease_ttl_ms,
            action: self.action_name(&request.action).to_string(),
            scope: scope_for_response_action(&request.action),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::StaticApprovalGate;
    use crate::{ActionRequest, ApprovalContext, ApprovalGate, PolicyVerdict};
    use serde_json::json;
    use swarm_core::config::PolicyConfig;
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};

    fn sample_request(action: ResponseAction, severity: Severity) -> ActionRequest {
        ActionRequest {
            hunt_id: HuntId("hunt-1".to_string()),
            requested_by: AgentId("whisker-a".to_string()),
            action,
            severity,
            evidence: json!({"signal": "example"}),
        }
    }

    fn sample_context() -> ApprovalContext {
        sample_context_at(1_700_000_000_000)
    }

    fn sample_context_at(now_ms: i64) -> ApprovalContext {
        ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-1".to_string()],
            correlation_id: None,
            now_ms,
        }
    }

    #[test]
    fn critical_block_requires_human() {
        let gate = StaticApprovalGate::default();
        let request = sample_request(
            ResponseAction::BlockEgress {
                target: "203.0.113.10".to_string(),
            },
            Severity::Critical,
        );

        let decision = gate.evaluate(&request, &sample_context()).unwrap();
        assert_eq!(decision.verdict, PolicyVerdict::RequireHuman);
        assert_eq!(decision.rule_name, "static.human_gate");
    }

    #[test]
    fn escalate_can_execute_without_human_gate() {
        let gate = StaticApprovalGate::default();
        let request = sample_request(
            ResponseAction::Escalate {
                summary: "review needed".to_string(),
                urgency: Severity::High,
            },
            Severity::High,
        );

        let decision = gate.evaluate(&request, &sample_context()).unwrap();
        assert_eq!(decision.verdict, PolicyVerdict::Allow);
        assert_eq!(decision.rule_name, "static.default_allow");
    }

    #[test]
    fn low_severity_isolation_is_denied() {
        let gate = StaticApprovalGate::default();
        let request = sample_request(
            ResponseAction::IsolateHost {
                host_id: "host-1".to_string(),
            },
            Severity::Low,
        );

        let decision = gate.evaluate(&request, &sample_context()).unwrap();
        assert_eq!(decision.verdict, PolicyVerdict::Deny);
        assert_eq!(decision.rule_name, "static.minimum_severity");
    }

    #[test]
    fn issued_lease_carries_scope_and_action() {
        let gate = StaticApprovalGate::default();
        let request = sample_request(
            ResponseAction::DeployDecoy {
                decoy_type: "honeypot".to_string(),
                target_zone: "dmz".to_string(),
            },
            Severity::Medium,
        );

        let lease = gate.issue_lease(&request, &sample_context()).unwrap();
        assert_eq!(lease.action, "deploy_decoy");
        assert_eq!(lease.scope.as_deref(), Some("dmz"));
    }

    #[test]
    fn null_evidence_is_rejected() {
        let gate = StaticApprovalGate::default();
        let mut request = sample_request(
            ResponseAction::DeployDecoy {
                decoy_type: "honeypot".to_string(),
                target_zone: "dmz".to_string(),
            },
            Severity::Medium,
        );
        request.evidence = serde_json::Value::Null;

        assert!(gate.evaluate(&request, &sample_context()).is_err());
    }

    #[test]
    fn scope_rate_limit_denies_burst_for_same_scope() {
        let gate = StaticApprovalGate::from_config(&PolicyConfig {
            max_actions_per_scope_per_minute: 1,
            ..PolicyConfig::default()
        });
        let request = sample_request(
            ResponseAction::BlockEgress {
                target: "203.0.113.10".to_string(),
            },
            Severity::Medium,
        );

        let first = gate
            .evaluate(&request, &sample_context_at(1_700_000_000_000))
            .unwrap();
        let second = gate
            .evaluate(&request, &sample_context_at(1_700_000_000_100))
            .unwrap();

        assert_eq!(first.verdict, PolicyVerdict::Allow);
        assert_eq!(second.verdict, PolicyVerdict::Deny);
        assert_eq!(second.rule_name, "static.scope_rate_limit");
    }

    #[test]
    fn scope_rate_limit_prunes_old_entries() {
        let gate = StaticApprovalGate::from_config(&PolicyConfig {
            max_actions_per_scope_per_minute: 1,
            ..PolicyConfig::default()
        });
        let request = sample_request(
            ResponseAction::BlockEgress {
                target: "203.0.113.10".to_string(),
            },
            Severity::Medium,
        );

        let first = gate
            .evaluate(&request, &sample_context_at(1_700_000_000_000))
            .unwrap();
        let second = gate
            .evaluate(&request, &sample_context_at(1_700_000_060_001))
            .unwrap();

        assert_eq!(first.verdict, PolicyVerdict::Allow);
        assert_eq!(second.verdict, PolicyVerdict::Allow);
    }
}
