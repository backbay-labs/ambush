use axum::{Json, Router, routing::post};
use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;
use swarm_core::ThreatClass;
use swarm_core::config::{
    CircuitBreakerConfig, ResponseAdapterConfig, RetryConfig, RuntimeMode, SwarmConfig,
    WebhookConfig,
};
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_guard::{
    Guard, GuardAction, GuardContext, GuardPipeline, GuardResult, Severity as GuardSeverity,
};
use swarm_policy::static_gate::StaticApprovalGate;
use swarm_policy::{ActionRequest, ApprovalContext};
use swarm_response::{DispatchingExecutor, ExecutionMode, ResponseStatus};
use swarm_runtime::{SwarmRuntime, config::load_config};
use swarm_spine::AuditResponseRecord;
use swarm_whisker::DetectionFinding;
use tokio::net::TcpListener;

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

fn repo_config_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rulesets/default.yaml")
}

fn sample_config() -> Result<SwarmConfig, Box<dyn Error>> {
    Ok(load_config(repo_config_path())?)
}

fn sample_context() -> ApprovalContext {
    ApprovalContext {
        live_mode: true,
        receipt_chain: vec!["receipt-1".to_string()],
        correlation_id: None,
        now_ms: 1_700_000_000_000,
    }
}

fn sample_detection() -> DetectionFinding {
    DetectionFinding {
        finding_id: "finding-1".to_string(),
        event_id: "evt-1".to_string(),
        threat_class: ThreatClass::Execution,
        severity: Severity::High,
        confidence: 0.97,
        evidence: serde_json::json!({"signal": "integration-test"}),
        strategy_id: "strategy-1".to_string(),
    }
}

fn sample_request(action: ResponseAction, severity: Severity) -> ActionRequest {
    ActionRequest {
        hunt_id: HuntId("hunt-1".to_string()),
        requested_by: AgentId("whisker-a".to_string()),
        action,
        severity,
        evidence: serde_json::json!({"signal": "integration-test"}),
    }
}

async fn spawn_delayed_webhook(
    delay_ms: u64,
) -> Result<(String, tokio::task::JoinHandle<()>), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let delay = Duration::from_millis(delay_ms);
    let app = Router::new().route(
        "/",
        post(move || async move {
            tokio::time::sleep(delay).await;
            Json(serde_json::json!({"ok": true}))
        }),
    );

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Ok((format!("http://{addr}/"), handle))
}

#[tokio::test]
async fn dispatch_sandbox_via_config_records_success_receipt() -> Result<(), Box<dyn Error>> {
    let mut config = sample_config()?;
    config.runtime.mode = RuntimeMode::DetectOnly;
    config.response_adapter = ResponseAdapterConfig::Sandbox;

    let runtime = SwarmRuntime::new(
        config.runtime.mode,
        StaticApprovalGate::default(),
        DispatchingExecutor::from_config(config.response_adapter.clone())?,
    );
    let request = sample_request(
        ResponseAction::DeployDecoy {
            decoy_type: "honeypot".to_string(),
            target_zone: "dmz".to_string(),
        },
        Severity::High,
    );
    let report = runtime
        .audit_authorize_and_execute_instrumented(&sample_detection(), &request, &sample_context())
        .await?;

    assert!(report.response_attempted);
    assert!(report.response_succeeded);

    let AuditResponseRecord::Success(receipt) = &report.audit.response else {
        panic!("expected success receipt, got {:?}", report.audit.response);
    };
    assert_eq!(receipt.mode, ExecutionMode::DryRun);
    assert_eq!(receipt.status, ResponseStatus::Simulated);
    Ok(())
}

#[tokio::test]
async fn guard_blocks_dispatched_executor_before_execution() -> Result<(), Box<dyn Error>> {
    let runtime = SwarmRuntime::new(
        RuntimeMode::DetectOnly,
        StaticApprovalGate::default(),
        DispatchingExecutor::from_config(ResponseAdapterConfig::Sandbox)?,
    )
    .with_guard_pipeline(GuardPipeline::new(vec![Box::new(FixedGuard {
        allow: false,
        name: "fixed_guard",
        message: "guard blocked",
    })]));
    let request = sample_request(
        ResponseAction::DeployDecoy {
            decoy_type: "honeypot".to_string(),
            target_zone: "dmz".to_string(),
        },
        Severity::High,
    );
    let report = runtime
        .audit_authorize_and_execute_instrumented(&sample_detection(), &request, &sample_context())
        .await?;

    assert!(!report.response_attempted);
    assert!(!report.response_succeeded);
    assert!(matches!(
        report.audit.response,
        AuditResponseRecord::GuardRejected { .. }
    ));
    Ok(())
}

#[tokio::test]
async fn policy_deny_skips_dispatched_executor() -> Result<(), Box<dyn Error>> {
    let runtime = SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        StaticApprovalGate::default(),
        DispatchingExecutor::from_config(ResponseAdapterConfig::Sandbox)?,
    );
    let request = sample_request(
        ResponseAction::IsolateHost {
            host_id: "host-1".to_string(),
        },
        Severity::Low,
    );
    let report = runtime
        .audit_authorize_and_execute_instrumented(&sample_detection(), &request, &sample_context())
        .await?;

    assert!(!report.response_attempted);
    assert!(!report.response_succeeded);
    assert!(matches!(
        report.audit.response,
        AuditResponseRecord::Skipped { .. }
    ));
    Ok(())
}

#[tokio::test]
async fn timeout_from_dispatched_webhook_records_failure() -> Result<(), Box<dyn Error>> {
    let (url, server) = spawn_delayed_webhook(75).await?;

    let runtime = SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        StaticApprovalGate::default(),
        DispatchingExecutor::from_config(ResponseAdapterConfig::Webhook {
            config: WebhookConfig {
                url,
                timeout_ms: 10,
                channel: None,
                auth_token: None,
                retry: RetryConfig::default(),
                circuit_breaker: CircuitBreakerConfig::default(),
                dead_letter_path: "./dead-letter.jsonl".to_string(),
            },
        })?,
    );
    let request = sample_request(
        ResponseAction::DeployDecoy {
            decoy_type: "honeypot".to_string(),
            target_zone: "dmz".to_string(),
        },
        Severity::Medium,
    );
    let report = runtime
        .audit_authorize_and_execute_instrumented(&sample_detection(), &request, &sample_context())
        .await?;

    server.abort();

    assert!(report.response_attempted);
    assert!(!report.response_succeeded);

    let AuditResponseRecord::Failure(failure) = &report.audit.response else {
        panic!("expected failure record, got {:?}", report.audit.response);
    };
    assert!(failure.message.contains("timed out"));
    assert_eq!(failure.details["status"], serde_json::json!("timeout"));
    Ok(())
}
