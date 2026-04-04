//! Rust-first runtime orchestration for Swarm Team Six.
//!
//! This crate is the intended composition root for the production runtime:
//! detection stays in Rust, policy stays deterministic, and live response
//! execution is capability-scoped.

pub mod canary;
pub mod config;
pub mod control;
pub mod correlation;
pub mod drafting;
pub mod evolution;
pub mod investigation;
pub mod mutation;
pub mod pipeline;
pub mod portfolio;
pub mod promotion;
pub mod replay;
pub mod selection;
pub mod service;
pub mod strategy;

use std::time::Instant;
pub use swarm_core::config::RuntimeMode;
use swarm_policy::{ActionRequest, ApprovalContext, ApprovalError, ApprovalGate};
use swarm_response::{ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt};
use swarm_spine::{AuditResponseRecord, AuditTrail, PolicyRecord};
use swarm_whisker::DetectionFinding;

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

/// Timing and outcome details for one audited execution.
#[derive(Debug, Clone)]
pub struct RuntimeExecutionReport {
    pub audit: AuditTrail,
    pub policy_elapsed_us: u64,
    pub response_elapsed_us: Option<u64>,
    pub response_attempted: bool,
    pub response_succeeded: bool,
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
        tracing::info!(
            hunt_id = %request.hunt_id.0,
            verdict = ?decision.verdict,
            mode = ?self.mode,
            "policy evaluated response request"
        );

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

        let receipt = self
            .response
            .execute(request, &lease, execution_mode)
            .await
            .map_err(RuntimeError::from)?;
        tracing::info!(
            hunt_id = %request.hunt_id.0,
            action = %receipt.action,
            mode = ?receipt.mode,
            status = ?receipt.status,
            "response executed"
        );
        Ok(receipt)
    }

    /// Evaluate, execute, and record the full response decision for one detection finding.
    pub async fn audit_authorize_and_execute(
        &self,
        detection: &DetectionFinding,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<AuditTrail, RuntimeError> {
        Ok(self
            .audit_authorize_and_execute_instrumented(detection, request, context)
            .await?
            .audit)
    }

    /// Evaluate, execute, and record the full response decision with stage timings.
    pub async fn audit_authorize_and_execute_instrumented(
        &self,
        detection: &DetectionFinding,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<RuntimeExecutionReport, RuntimeError> {
        let policy_started = Instant::now();
        let decision = self.policy.evaluate(request, context)?;
        let policy_elapsed_us = policy_started.elapsed().as_micros() as u64;
        tracing::info!(
            hunt_id = %request.hunt_id.0,
            event_id = %detection.event_id,
            verdict = ?decision.verdict,
            mode = ?self.mode,
            "building audit trail for response decision"
        );

        let execution_mode = match self.mode {
            RuntimeMode::DetectOnly => ExecutionMode::DryRun,
            RuntimeMode::LiveResponse => ExecutionMode::Enforced,
        };

        let (lease, response, response_elapsed_us, response_attempted, response_succeeded) =
            match decision.verdict {
                swarm_policy::PolicyVerdict::Deny => (
                    None,
                    AuditResponseRecord::Skipped {
                        reason: decision.reason.clone(),
                    },
                    None,
                    false,
                    false,
                ),
                swarm_policy::PolicyVerdict::RequireHuman
                    if self.mode == RuntimeMode::LiveResponse =>
                {
                    (
                        None,
                        AuditResponseRecord::Skipped {
                            reason: decision.reason.clone(),
                        },
                        None,
                        false,
                        false,
                    )
                }
                swarm_policy::PolicyVerdict::Allow | swarm_policy::PolicyVerdict::RequireHuman => {
                    let lease = self.policy.issue_lease(request, context)?;
                    let response_started = Instant::now();
                    let response =
                        match self.response.execute(request, &lease, execution_mode).await {
                            Ok(receipt) => AuditResponseRecord::Success(receipt),
                            Err(error) => AuditResponseRecord::Failure(error.failure),
                        };
                    let response_elapsed_us = response_started.elapsed().as_micros() as u64;
                    let response_succeeded = matches!(response, AuditResponseRecord::Success(_));
                    (
                        Some(lease),
                        response,
                        Some(response_elapsed_us),
                        true,
                        response_succeeded,
                    )
                }
            };

        Ok(RuntimeExecutionReport {
            audit: AuditTrail {
                trail_id: format!("trail:{}:{}", request.hunt_id.0, context.now_ms),
                hunt_id: request.hunt_id.0.clone(),
                related_receipt_ids: context.receipt_chain.clone(),
                detection: detection.clone(),
                policy: PolicyRecord {
                    verdict: decision.verdict,
                    reason: decision.reason,
                    lease,
                },
                response,
                created_at_ms: context.now_ms,
            },
            policy_elapsed_us,
            response_elapsed_us,
            response_attempted,
            response_succeeded,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{RuntimeMode, SwarmRuntime};
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
    use swarm_policy::static_gate::StaticApprovalGate;
    use swarm_policy::{ActionRequest, ApprovalContext};
    use swarm_response::{ExecutionMode, ResponseStatus, adapters::SandboxExecutor};

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
        assert!(
            error
                .to_string()
                .contains("authorized but held for human approval")
        );
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
        assert!(
            error
                .to_string()
                .contains("destructive actions require at least medium severity")
        );
    }
}
