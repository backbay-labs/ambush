use crate::{
    ActionRequest, ApprovalContext, ApprovalError, ApprovalGate, CapabilityLease, PolicyDecision,
};
use swarm_core::types::{ResponseAction, Severity};

/// Minimal deterministic gate for the first live-response slice.
#[derive(Debug, Clone)]
pub struct StaticApprovalGate {
    /// Severity at or above which destructive actions require human confirmation.
    pub human_gate_severity: Severity,
    /// Lease TTL for authorized requests.
    pub lease_ttl_ms: i64,
}

impl Default for StaticApprovalGate {
    fn default() -> Self {
        Self {
            human_gate_severity: Severity::High,
            lease_ttl_ms: 60_000,
        }
    }
}

impl StaticApprovalGate {
    fn destructive_action(request: &ActionRequest) -> bool {
        matches!(
            request.action,
            ResponseAction::BlockEgress { .. }
                | ResponseAction::IsolateHost { .. }
                | ResponseAction::RevokeCredential { .. }
        )
    }

    fn validate_request(&self, request: &ActionRequest) -> Result<(), ApprovalError> {
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
            ResponseAction::DeployDecoy { .. } => "deploy_decoy",
            ResponseAction::Escalate { .. } => "escalate",
        }
    }

    fn scope_for_action(&self, action: &ResponseAction) -> Option<String> {
        match action {
            ResponseAction::BlockEgress { target } => Some(target.clone()),
            ResponseAction::IsolateHost { host_id } => Some(host_id.clone()),
            ResponseAction::RevokeCredential { credential_id } => Some(credential_id.clone()),
            ResponseAction::DeployDecoy { target_zone, .. } => Some(target_zone.clone()),
            ResponseAction::Escalate { .. } => None,
        }
    }
}

impl ApprovalGate for StaticApprovalGate {
    fn evaluate(
        &self,
        request: &ActionRequest,
        _context: &ApprovalContext,
    ) -> Result<PolicyDecision, ApprovalError> {
        self.validate_request(request)?;

        if Self::destructive_action(request) && request.severity == Severity::Low {
            return Ok(PolicyDecision::deny(
                "destructive actions require at least medium severity",
            ));
        }

        if matches!(request.action, ResponseAction::DeployDecoy { .. })
            && request.severity == Severity::Low
        {
            return Ok(PolicyDecision::deny(
                "deploy_decoy requires at least medium severity",
            ));
        }

        if Self::destructive_action(request) && request.severity >= self.human_gate_severity {
            return Ok(PolicyDecision::require_human(
                "authorized but held for human approval",
            ));
        }

        Ok(PolicyDecision::allow("authorized for immediate execution"))
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
            scope: self.scope_for_action(&request.action),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::StaticApprovalGate;
    use crate::{ActionRequest, ApprovalContext, ApprovalGate, PolicyVerdict};
    use serde_json::json;
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
        ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-1".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_000_000,
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
}
