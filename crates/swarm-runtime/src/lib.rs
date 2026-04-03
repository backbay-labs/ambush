//! Rust-first runtime orchestration for Swarm Team Six.
//!
//! This crate is the intended composition root for the production runtime:
//! detection stays in Rust, policy stays deterministic, and live response
//! execution is capability-scoped.

pub mod config;
pub mod pipeline;
pub mod service;

pub use swarm_core::config::RuntimeMode;
use swarm_policy::{ActionRequest, ApprovalContext, ApprovalError, ApprovalGate};
use swarm_response::{ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt};

/// Runtime errors surfaced while authorizing or executing actions.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Approval(#[from] ApprovalError),

    #[error(transparent)]
    Response(#[from] ResponseError),
}

/// Swarm runtime wiring detection, policy, and response into one Rust service.
pub struct SwarmRuntime<P, E> {
    mode: RuntimeMode,
    policy: P,
    response: E,
}

impl<P, E> SwarmRuntime<P, E> {
    /// Create a runtime with the supplied components.
    pub fn new(mode: RuntimeMode, policy: P, response: E) -> Self {
        Self {
            mode,
            policy,
            response,
        }
    }

    /// Current runtime mode.
    pub fn mode(&self) -> RuntimeMode {
        self.mode
    }
}

impl<P, E> SwarmRuntime<P, E>
where
    P: ApprovalGate,
    E: ResponseExecutor,
{
    /// Evaluate a response request and execute it if authorized.
    pub async fn authorize_and_execute(
        &self,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<ResponseReceipt, RuntimeError> {
        let decision = self.policy.evaluate(request, context)?;

        match decision.verdict {
            swarm_policy::PolicyVerdict::Deny => {
                return Err(ApprovalError::Denied(decision.reason).into());
            }
            swarm_policy::PolicyVerdict::RequireHuman if self.mode == RuntimeMode::LiveResponse => {
                return Err(ApprovalError::Denied(decision.reason).into());
            }
            swarm_policy::PolicyVerdict::Allow | swarm_policy::PolicyVerdict::RequireHuman => {}
        }

        let lease = self.policy.issue_lease(request, context)?;
        let execution_mode = match self.mode {
            RuntimeMode::DetectOnly => ExecutionMode::DryRun,
            RuntimeMode::LiveResponse => ExecutionMode::Enforced,
        };

        self.response
            .execute(request, &lease, execution_mode)
            .await
            .map_err(RuntimeError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::{RuntimeMode, SwarmRuntime};
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
    use swarm_policy::static_gate::StaticApprovalGate;
    use swarm_policy::{ActionRequest, ApprovalContext};
    use swarm_response::{adapters::SandboxExecutor, ExecutionMode, ResponseStatus};

    fn sample_context() -> ApprovalContext {
        ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-1".to_string()],
            now_ms: 1_700_000_000_000,
        }
    }

    #[tokio::test]
    async fn detect_only_runtime_executes_as_dry_run() {
        let runtime = SwarmRuntime::new(
            RuntimeMode::DetectOnly,
            StaticApprovalGate::default(),
            SandboxExecutor,
        );
        let request = ActionRequest {
            hunt_id: HuntId("hunt-1".to_string()),
            requested_by: AgentId("whisker-a".to_string()),
            action: ResponseAction::BlockEgress {
                target: "203.0.113.5".to_string(),
            },
            severity: Severity::Critical,
            evidence: serde_json::json!({"signal": "suspicious-egress"}),
        };

        let receipt = runtime
            .authorize_and_execute(&request, &sample_context())
            .await
            .unwrap();
        assert_eq!(receipt.mode, ExecutionMode::DryRun);
        assert_eq!(receipt.status, ResponseStatus::Simulated);
    }

    #[tokio::test]
    async fn live_runtime_blocks_human_gated_actions() {
        let runtime = SwarmRuntime::new(
            RuntimeMode::LiveResponse,
            StaticApprovalGate::default(),
            SandboxExecutor,
        );
        let request = ActionRequest {
            hunt_id: HuntId("hunt-1".to_string()),
            requested_by: AgentId("whisker-a".to_string()),
            action: ResponseAction::IsolateHost {
                host_id: "host-1".to_string(),
            },
            severity: Severity::Critical,
            evidence: serde_json::json!({"signal": "active-exploit"}),
        };

        let error = runtime
            .authorize_and_execute(&request, &sample_context())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("authorized but held for human approval"));
    }

    #[tokio::test]
    async fn live_runtime_executes_allowed_action() {
        let runtime = SwarmRuntime::new(
            RuntimeMode::LiveResponse,
            StaticApprovalGate::default(),
            SandboxExecutor,
        );
        let request = ActionRequest {
            hunt_id: HuntId("hunt-1".to_string()),
            requested_by: AgentId("whisker-a".to_string()),
            action: ResponseAction::DeployDecoy {
                decoy_type: "honeypot".to_string(),
                target_zone: "dmz".to_string(),
            },
            severity: Severity::Medium,
            evidence: serde_json::json!({"signal": "lure"}),
        };

        let receipt = runtime
            .authorize_and_execute(&request, &sample_context())
            .await
            .unwrap();
        assert_eq!(receipt.mode, ExecutionMode::Enforced);
        assert_eq!(receipt.status, ResponseStatus::Executed);
    }

    #[tokio::test]
    async fn live_runtime_denies_low_severity_destructive_action() {
        let runtime = SwarmRuntime::new(
            RuntimeMode::LiveResponse,
            StaticApprovalGate::default(),
            SandboxExecutor,
        );
        let request = ActionRequest {
            hunt_id: HuntId("hunt-2".to_string()),
            requested_by: AgentId("whisker-a".to_string()),
            action: ResponseAction::IsolateHost {
                host_id: "host-2".to_string(),
            },
            severity: Severity::Low,
            evidence: serde_json::json!({"signal": "weak-indicator"}),
        };

        let error = runtime
            .authorize_and_execute(&request, &sample_context())
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("destructive actions require at least medium severity"));
    }
}
