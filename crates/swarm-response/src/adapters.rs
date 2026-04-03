use crate::{ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt};
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
        Ok(ResponseReceipt {
            receipt_id: format!("resp:{}:{}", request.hunt_id.0, lease.capability_id),
            summary: format!("sandbox {:?} for {:?}", mode, request.action),
            details: json!({
                "mode": mode,
                "capability_id": lease.capability_id,
                "scope": lease.scope,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::SandboxExecutor;
    use crate::{ExecutionMode, ResponseExecutor};
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
            scope: Some("198.51.100.4".to_string()),
        };

        let receipt = executor
            .execute(&request, &lease, ExecutionMode::DryRun)
            .await
            .unwrap();
        assert!(receipt.receipt_id.contains("hunt-1"));
    }
}
