use crate::{ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt, ResponseStatus};
use async_trait::async_trait;
use serde_json::json;
use swarm_policy::{ActionRequest, CapabilityLease};

/// Minimal executor used for dry-run and sandbox integration tests.
#[derive(Debug, Default)]
pub struct SandboxExecutor;

#[async_trait]
impl ResponseExecutor for SandboxExecutor {
    async fn execute(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        mode: ExecutionMode,
    ) -> Result<ResponseReceipt, ResponseError> {
        let action = request.action.kind();
        if matches!(
            request.action,
            swarm_core::types::ResponseAction::BlockEgress { .. }
                | swarm_core::types::ResponseAction::IsolateHost { .. }
                | swarm_core::types::ResponseAction::RevokeCredential { .. }
                | swarm_core::types::ResponseAction::SinkholeDns { .. }
                | swarm_core::types::ResponseAction::TerminateUserSession { .. }
                | swarm_core::types::ResponseAction::TriggerEdrScan { .. }
                | swarm_core::types::ResponseAction::InjectFirewallRule { .. }
                | swarm_core::types::ResponseAction::QuarantineFile { .. }
                | swarm_core::types::ResponseAction::KillProcess { .. }
                | swarm_core::types::ResponseAction::SuspendProcess { .. }
                | swarm_core::types::ResponseAction::DisableUserAccount { .. }
                | swarm_core::types::ResponseAction::ForcePasswordReset { .. }
                | swarm_core::types::ResponseAction::RemoveScheduledTask { .. }
                | swarm_core::types::ResponseAction::DeployDecoy { .. }
        ) && lease.scope.is_none()
        {
            return Err(ResponseError::execution_failed(
                format!("resp:{}:{}", request.hunt_id.0, lease.capability_id),
                action,
                mode,
                "sandbox execution requires a scoped lease",
                json!({
                    "capability_id": lease.capability_id,
                    "scope": lease.scope,
                }),
            ));
        }

        Ok(ResponseReceipt {
            receipt_id: format!("resp:{}:{}", request.hunt_id.0, lease.capability_id),
            action: action.to_string(),
            mode,
            status: match mode {
                ExecutionMode::DryRun => ResponseStatus::Simulated,
                ExecutionMode::Enforced => ResponseStatus::Executed,
            },
            summary: format!("sandbox {:?} for {}", mode, action),
            details: json!({
                "mode": mode,
                "capability_id": lease.capability_id,
                "scope": lease.scope,
                "requested_by": request.requested_by,
            }),
            audit: Default::default(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::SandboxExecutor;
    use crate::{ExecutionMode, ResponseExecutor, ResponseStatus};
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
    use swarm_policy::{ActionRequest, CapabilityLease};

    #[tokio::test]
    async fn sandbox_executor_returns_receipt() {
        let executor = SandboxExecutor;
        let request = ActionRequest {
            hunt_id: HuntId("hunt-1".to_string()),
            requested_by: AgentId("whisker-a".to_string()),
            action: ResponseAction::BlockEgress {
                target: "198.51.100.4".to_string(),
            },
            severity: Severity::High,
            evidence: serde_json::json!({"signal": "egress"}),
        };
        let lease = CapabilityLease {
            capability_id: "lease-1".to_string(),
            expires_at_ms: 1000,
            action: "block_egress".to_string(),
            scope: Some("198.51.100.4".to_string()),
        };

        let receipt = executor
            .execute(&request, &lease, ExecutionMode::DryRun)
            .await
            .unwrap();
        assert!(receipt.receipt_id.contains("hunt-1"));
        assert_eq!(receipt.status, ResponseStatus::Simulated);
    }

    #[tokio::test]
    async fn sandbox_executor_returns_structured_failure_when_scope_missing() {
        let executor = SandboxExecutor;
        let request = ActionRequest {
            hunt_id: HuntId("hunt-1".to_string()),
            requested_by: AgentId("whisker-a".to_string()),
            action: ResponseAction::IsolateHost {
                host_id: "host-1".to_string(),
            },
            severity: Severity::High,
            evidence: serde_json::json!({"signal": "contain"}),
        };
        let lease = CapabilityLease {
            capability_id: "lease-1".to_string(),
            expires_at_ms: 1000,
            action: "isolate_host".to_string(),
            scope: None,
        };

        let error = executor
            .execute(&request, &lease, ExecutionMode::Enforced)
            .await
            .unwrap_err();
        assert_eq!(error.failure.action, "isolate_host");
    }
}
