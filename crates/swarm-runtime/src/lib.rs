//! Rust-first runtime orchestration for Swarm Team Six.
//!
//! This crate is the intended composition root for the production runtime:
//! detection stays in Rust, policy stays deterministic, and live response
//! execution is capability-scoped.

pub mod approval;
pub mod bridge_runtime;
pub mod canary;
pub mod cli;
pub mod config;
pub mod control;
pub mod correlation;
pub mod detection;
pub mod detector_factory;
pub mod dispatcher;
pub mod drafting;
pub mod escalation;
pub mod evidence;
pub mod evolution;
pub mod governance_prep;
pub mod http;
pub mod ingest;
pub mod investigation;
pub mod mutation;
pub mod operator_http;
pub mod operator_maintenance;
pub mod portfolio;
pub mod pounce_agent;
pub mod promotion;
pub mod replay;
pub mod review_workbench;
pub mod selection;
pub mod service;
pub mod stalker_agent;
pub mod strategy;
pub mod tom_agent;
pub mod weaver_agent;
pub mod whisker_agent;
pub mod workbench;

use std::time::Instant;
pub use swarm_core::config::RuntimeMode;
use swarm_core::types::AgentId;
use swarm_guard::{GuardAction, GuardContext, GuardPipeline};
use swarm_policy::{ActionRequest, ApprovalContext, ApprovalError, ApprovalGate};
use swarm_response::{
    ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt, ResponseStatus,
};
use swarm_spine::{AuditResponseRecord, AuditTrail, PolicyRecord};
use swarm_whisker::DetectionFinding;

/// Runtime errors surfaced while authorizing or executing actions.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Approval(#[from] ApprovalError),

    #[error("guard rejected: {guard_name}: {reason}")]
    GuardRejected { guard_name: String, reason: String },

    #[error(transparent)]
    Response(#[from] ResponseError),
}

/// Swarm runtime wiring detection, policy, and response into one Rust service.
pub struct SwarmRuntime<P, E> {
    mode: RuntimeMode,
    policy: P,
    response: E,
    guard_pipeline: Option<GuardPipeline>,
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
            guard_pipeline: None,
        }
    }

    /// Current runtime mode.
    pub fn mode(&self) -> RuntimeMode {
        self.mode
    }

    /// Attach a guard pipeline that evaluates actions before execution.
    pub fn with_guard_pipeline(mut self, pipeline: GuardPipeline) -> Self {
        self.guard_pipeline = Some(pipeline);
        self
    }

    pub fn audit_governance_veto(
        &self,
        detection: &DetectionFinding,
        request: &ActionRequest,
        context: &ApprovalContext,
        governing_agent_id: &AgentId,
        reason: impl Into<String>,
    ) -> AuditTrail {
        let reason = reason.into();
        let receipt = ResponseReceipt {
            receipt_id: format!(
                "veto:{}:{}:{}",
                request.hunt_id.0,
                request.action.kind(),
                context.now_ms
            ),
            action: request.action.kind().to_string(),
            mode: self.execution_mode(),
            status: ResponseStatus::Failed,
            summary: format!("governance veto: {reason}"),
            details: serde_json::json!({
                "status": "vetoed",
                "lineage": request.evidence.get("lineage").cloned(),
                "requested_by": request.requested_by,
                "evidence": request.evidence.clone(),
            }),
            audit: Default::default(),
        }
        .with_policy_audit(
            swarm_policy::PolicyVerdict::Deny,
            "governance.veto",
            reason.clone(),
        )
        .with_governance_audit(governing_agent_id.clone(), reason.clone());

        AuditTrail {
            trail_id: format!("trail:{}:{}", request.hunt_id.0, context.now_ms),
            hunt_id: request.hunt_id.0.clone(),
            related_receipt_ids: context.receipt_chain.clone(),
            detection: detection.clone(),
            policy: PolicyRecord {
                verdict: swarm_policy::PolicyVerdict::Deny,
                rule_name: "governance.veto".to_string(),
                reason,
                lease: None,
            },
            response: AuditResponseRecord::Failure(receipt.into_failure()),
            created_at_ms: context.now_ms,
        }
    }

    fn evaluate_guard_rejection(&self, request: &ActionRequest) -> Option<(String, String)> {
        let pipeline = self.guard_pipeline.as_ref()?;
        let context = GuardContext::new()
            .with_agent_id(request.requested_by.0.clone())
            .with_metadata(serde_json::json!({
                "hunt_id": request.hunt_id.0,
                "severity": request.severity,
            }));
        let result = pipeline.evaluate(&GuardAction::ResponseAction(&request.action), &context);

        if result.allowed {
            None
        } else {
            Some((result.guard, result.message))
        }
    }

    fn correlation_id(context: &ApprovalContext) -> &str {
        context.correlation_id.as_deref().unwrap_or("unknown")
    }

    fn execution_mode(&self) -> ExecutionMode {
        match self.mode {
            RuntimeMode::DetectOnly => ExecutionMode::DryRun,
            RuntimeMode::LiveResponse => ExecutionMode::Enforced,
        }
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
            correlation_id = %Self::correlation_id(context),
            hunt_id = %request.hunt_id.0,
            verdict = ?decision.verdict,
            rule_name = %decision.rule_name,
            reason = %decision.reason,
            mode = ?self.mode,
            module = module_path!(),
            "policy evaluated response request"
        );

        match decision.verdict {
            swarm_policy::PolicyVerdict::Deny => {
                return Err(ApprovalError::Denied(decision.reason.clone()).into());
            }
            swarm_policy::PolicyVerdict::RequireHuman if self.mode == RuntimeMode::LiveResponse => {
                return Err(ApprovalError::Denied(decision.reason.clone()).into());
            }
            swarm_policy::PolicyVerdict::Allow | swarm_policy::PolicyVerdict::RequireHuman => {}
        }

        if let Some((guard_name, reason)) = self.evaluate_guard_rejection(request) {
            tracing::warn!(
                correlation_id = %Self::correlation_id(context),
                hunt_id = %request.hunt_id.0,
                guard_name = %guard_name,
                reason = %reason,
                module = module_path!(),
                "guard rejected response request"
            );
            return Err(RuntimeError::GuardRejected { guard_name, reason });
        }

        let lease = self.policy.issue_lease(request, context)?;
        ensure_active_lease(&lease, context.now_ms)?;
        let receipt = self
            .response
            .execute(request, &lease, self.execution_mode())
            .await
            .map_err(RuntimeError::from)?
            .with_policy_audit(
                decision.verdict,
                decision.rule_name.clone(),
                decision.reason.clone(),
            );
        if !receipt.status.indicates_success() {
            return Err(RuntimeError::Response(ResponseError {
                failure: receipt.into_failure(),
            }));
        }
        tracing::info!(
            correlation_id = %Self::correlation_id(context),
            hunt_id = %request.hunt_id.0,
            action = %receipt.action,
            mode = ?receipt.mode,
            status = ?receipt.status,
            rule_name = %decision.rule_name,
            reason = %decision.reason,
            module = module_path!(),
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
            correlation_id = %Self::correlation_id(context),
            hunt_id = %request.hunt_id.0,
            event_id = %detection.event_id,
            verdict = ?decision.verdict,
            rule_name = %decision.rule_name,
            reason = %decision.reason,
            mode = ?self.mode,
            module = module_path!(),
            "building audit trail for response decision"
        );

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
                    if let Some((guard_name, reason)) = self.evaluate_guard_rejection(request) {
                        tracing::warn!(
                            correlation_id = %Self::correlation_id(context),
                            hunt_id = %request.hunt_id.0,
                            guard_name = %guard_name,
                            reason = %reason,
                            module = module_path!(),
                            "guard rejected response request"
                        );
                        (
                            None,
                            AuditResponseRecord::GuardRejected { guard_name, reason },
                            None,
                            false,
                            false,
                        )
                    } else {
                        let lease = self.policy.issue_lease(request, context)?;
                        ensure_active_lease(&lease, context.now_ms)?;
                        let response_started = Instant::now();
                        let response = match self
                            .response
                            .execute(request, &lease, self.execution_mode())
                            .await
                        {
                            Ok(receipt) if receipt.status.indicates_success() => {
                                AuditResponseRecord::Success(receipt.with_policy_audit(
                                    decision.verdict,
                                    decision.rule_name.clone(),
                                    decision.reason.clone(),
                                ))
                            }
                            Ok(receipt) => AuditResponseRecord::Failure(
                                receipt
                                    .with_policy_audit(
                                        decision.verdict,
                                        decision.rule_name.clone(),
                                        decision.reason.clone(),
                                    )
                                    .into_failure(),
                            ),
                            Err(error) => AuditResponseRecord::Failure(error.failure),
                        };
                        let response_elapsed_us = response_started.elapsed().as_micros() as u64;
                        let response_succeeded =
                            matches!(response, AuditResponseRecord::Success(_));
                        (
                            Some(lease),
                            response,
                            Some(response_elapsed_us),
                            true,
                            response_succeeded,
                        )
                    }
                }
            };

        tracing::info!(
            correlation_id = %Self::correlation_id(context),
            hunt_id = %request.hunt_id.0,
            event_id = %detection.event_id,
            action = %request.action.kind(),
            response_kind = match &response {
                AuditResponseRecord::Success(_) => "success",
                AuditResponseRecord::Failure(_) => "failure",
                AuditResponseRecord::Skipped { .. } => "skipped",
                AuditResponseRecord::GuardRejected { .. } => "guard_rejected",
            },
            response_attempted,
            response_succeeded,
            module = module_path!(),
            "response stage completed"
        );

        Ok(RuntimeExecutionReport {
            audit: AuditTrail {
                trail_id: format!("trail:{}:{}", request.hunt_id.0, context.now_ms),
                hunt_id: request.hunt_id.0.clone(),
                related_receipt_ids: context.receipt_chain.clone(),
                detection: detection.clone(),
                policy: PolicyRecord {
                    verdict: decision.verdict,
                    rule_name: decision.rule_name,
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

fn ensure_active_lease(
    lease: &swarm_policy::CapabilityLease,
    now_ms: i64,
) -> Result<(), ApprovalError> {
    if lease.expires_at_ms <= now_ms {
        return Err(ApprovalError::Denied(
            "capability lease expired".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{RuntimeMode, SwarmRuntime};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use swarm_core::ThreatClass;
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
    use swarm_guard::{
        Guard, GuardAction, GuardContext, GuardPipeline, GuardResult, Severity as GuardSeverity,
    };
    use swarm_policy::static_gate::StaticApprovalGate;
    use swarm_policy::{ActionRequest, ApprovalContext};
    use swarm_response::{
        ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt, ResponseStatus,
        adapters::SandboxExecutor,
    };
    use swarm_spine::AuditResponseRecord;

    #[derive(Clone)]
    struct RecordingExecutor {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ResponseExecutor for RecordingExecutor {
        async fn execute(
            &self,
            request: &ActionRequest,
            _lease: &swarm_policy::CapabilityLease,
            mode: ExecutionMode,
        ) -> Result<ResponseReceipt, ResponseError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ResponseReceipt {
                receipt_id: format!("receipt:{}", request.hunt_id.0),
                action: request.action.kind().to_string(),
                mode,
                status: if matches!(mode, ExecutionMode::DryRun) {
                    ResponseStatus::Simulated
                } else {
                    ResponseStatus::Executed
                },
                summary: "executed".to_string(),
                details: serde_json::json!({}),
                audit: Default::default(),
            })
        }
    }

    struct FixedGuard {
        allow: bool,
        name: &'static str,
        message: &'static str,
    }

    impl Guard for FixedGuard {
        fn name(&self) -> &str {
            self.name
        }

        fn handles(&self, _action: &GuardAction<'_>) -> bool {
            true
        }

        fn check(&self, _action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
            if self.allow {
                GuardResult::allow(self.name)
            } else {
                GuardResult::block(self.name, GuardSeverity::Critical, self.message)
            }
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

    #[tokio::test]
    async fn guard_rejection_prevents_execution() {
        let calls = Arc::new(AtomicUsize::new(0));
        let runtime = SwarmRuntime::new(
            RuntimeMode::DetectOnly,
            StaticApprovalGate::default(),
            RecordingExecutor {
                calls: Arc::clone(&calls),
            },
        )
        .with_guard_pipeline(GuardPipeline::new(vec![Box::new(FixedGuard {
            allow: false,
            name: "test_guard",
            message: "blocked by test",
        })]));
        let request = ActionRequest {
            hunt_id: HuntId("hunt-guard".to_string()),
            requested_by: AgentId("whisker-a".to_string()),
            action: ResponseAction::DeployDecoy {
                decoy_type: "honeypot".to_string(),
                target_zone: "dmz".to_string(),
            },
            severity: Severity::High,
            evidence: serde_json::json!({"signal": "guard-test"}),
        };
        let detection = swarm_whisker::DetectionFinding {
            finding_id: "finding-guard".to_string(),
            event_id: "evt-guard".to_string(),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence: 0.9,
            evidence: serde_json::json!({"signal": "guard-test"}),
            strategy_id: "strategy-1".to_string(),
        };

        let report = runtime
            .audit_authorize_and_execute_instrumented(&detection, &request, &sample_context())
            .await
            .unwrap();

        assert!(!report.response_attempted);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            report.audit.response,
            AuditResponseRecord::GuardRejected { .. }
        ));
    }

    #[tokio::test]
    async fn guard_allows_execution_proceeds() {
        let calls = Arc::new(AtomicUsize::new(0));
        let runtime = SwarmRuntime::new(
            RuntimeMode::DetectOnly,
            StaticApprovalGate::default(),
            RecordingExecutor {
                calls: Arc::clone(&calls),
            },
        )
        .with_guard_pipeline(GuardPipeline::new(vec![Box::new(FixedGuard {
            allow: true,
            name: "test_guard",
            message: "allowed",
        })]));
        let request = ActionRequest {
            hunt_id: HuntId("hunt-allow".to_string()),
            requested_by: AgentId("whisker-a".to_string()),
            action: ResponseAction::DeployDecoy {
                decoy_type: "honeypot".to_string(),
                target_zone: "dmz".to_string(),
            },
            severity: Severity::High,
            evidence: serde_json::json!({"signal": "guard-test"}),
        };
        let detection = swarm_whisker::DetectionFinding {
            finding_id: "finding-allow".to_string(),
            event_id: "evt-allow".to_string(),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence: 0.9,
            evidence: serde_json::json!({"signal": "guard-test"}),
            strategy_id: "strategy-1".to_string(),
        };

        let report = runtime
            .audit_authorize_and_execute_instrumented(&detection, &request, &sample_context())
            .await
            .unwrap();

        assert!(report.response_attempted);
        assert!(report.response_succeeded);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(matches!(
            report.audit.response,
            AuditResponseRecord::Success(_)
        ));
    }
}
