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
    fn requires_human(&self, request: &ActionRequest) -> bool {
        matches!(
            request.action,
            ResponseAction::BlockEgress { .. }
                | ResponseAction::IsolateHost { .. }
                | ResponseAction::RevokeCredential { .. }
        ) && request.severity >= self.human_gate_severity
    }

    fn validate_request(&self, request: &ActionRequest) -> Result<(), ApprovalError> {
        if request.evidence.is_null() {
            return Err(ApprovalError::InvalidRequest(
                "evidence bundle must not be null".to_string(),
            ));
        }
        Ok(())
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
        let requires_human = self.requires_human(request);
        let reason = if requires_human {
            "authorized but held for human approval".to_string()
        } else {
            "authorized for immediate execution".to_string()
        };

        Ok(PolicyDecision {
            authorized: true,
            reason,
            requires_human,
        })
    }

    fn issue_lease(
        &self,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<CapabilityLease, ApprovalError> {
        self.validate_request(request)?;
        Ok(CapabilityLease {
            capability_id: format!("lease:{}:{}", request.hunt_id.0, context.now_ms),
            expires_at_ms: context.now_ms + self.lease_ttl_ms,
            scope: self.scope_for_action(&request.action),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::StaticApprovalGate;
    use crate::{ActionRequest, ApprovalContext, ApprovalGate};
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
        assert!(decision.authorized);
        assert!(decision.requires_human);
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
        assert!(decision.authorized);
        assert!(!decision.requires_human);
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
