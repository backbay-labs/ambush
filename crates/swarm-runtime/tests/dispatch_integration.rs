use arc_swap::ArcSwap;
use async_trait::async_trait;
use axum::{Json, Router, routing::post};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::error::Error;
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use swarm_core::ThreatClass;
use swarm_core::agent::{
    AgentHealth, AgentHealthEntry, AgentRole, SwarmAgent, SwarmEnvironment, SwarmError,
};
use swarm_core::config::{
    CircuitBreakerConfig, PheromoneBackendConfig, PheromoneConfig, ResponseAdapterConfig,
    RetryConfig, RuntimeMode, SwarmConfig, WebhookConfig,
};
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity, SwarmAction};
use swarm_guard::{
    Guard, GuardAction, GuardContext, GuardPipeline, GuardResult, Severity as GuardSeverity,
};
use swarm_pheromone::{ConfiguredPheromoneSubstrate, InMemoryPheromoneSubstrate};
use swarm_policy::static_gate::{StaticApprovalGate, scope_for_response_action};
use swarm_policy::{
    ActionRequest, ApprovalContext, ApprovalError, ApprovalGate, CapabilityLease, PolicyDecision,
    PolicyVerdict,
};
use swarm_response::{
    DispatchingExecutor, ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt,
    ResponseStatus,
};
use swarm_runtime::{
    RuntimeError, SwarmRuntime,
    config::load_config,
    dispatcher::{
        AgentDispatcher, AgentDispatcherConfig, GovernanceVetoRoute, RequestResponseRouter,
    },
};
use swarm_spine::{AuditResponseRecord, AuditTrail};
use swarm_whisker::DetectionFinding;
use tokio::net::TcpListener;
use tokio::sync::watch;

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

struct CountingGuard {
    calls: Arc<AtomicUsize>,
}

impl Guard for CountingGuard {
    fn name(&self) -> &str {
        "counting_guard"
    }

    fn handles(&self, _action: &GuardAction<'_>) -> bool {
        true
    }

    fn check(&self, _action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        GuardResult::allow(self.name())
    }
}

#[derive(Clone, Copy)]
enum LeaseExpiry {
    Relative(i64),
    Absolute(i64),
}

#[derive(Clone)]
struct CountingApprovalGate {
    verdict: PolicyVerdict,
    evaluate_calls: Arc<AtomicUsize>,
    issue_lease_calls: Arc<AtomicUsize>,
    lease_expiry: LeaseExpiry,
}

impl CountingApprovalGate {
    fn allow_with_ttl(ttl_ms: i64) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let evaluate_calls = Arc::new(AtomicUsize::new(0));
        let issue_lease_calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                verdict: PolicyVerdict::Allow,
                evaluate_calls: Arc::clone(&evaluate_calls),
                issue_lease_calls: Arc::clone(&issue_lease_calls),
                lease_expiry: LeaseExpiry::Relative(ttl_ms),
            },
            evaluate_calls,
            issue_lease_calls,
        )
    }

    fn allow_with_expiry(expires_at_ms: i64) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let evaluate_calls = Arc::new(AtomicUsize::new(0));
        let issue_lease_calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                verdict: PolicyVerdict::Allow,
                evaluate_calls: Arc::clone(&evaluate_calls),
                issue_lease_calls: Arc::clone(&issue_lease_calls),
                lease_expiry: LeaseExpiry::Absolute(expires_at_ms),
            },
            evaluate_calls,
            issue_lease_calls,
        )
    }
}

impl ApprovalGate for CountingApprovalGate {
    fn evaluate(
        &self,
        _request: &ActionRequest,
        _context: &ApprovalContext,
    ) -> Result<PolicyDecision, ApprovalError> {
        self.evaluate_calls.fetch_add(1, Ordering::SeqCst);
        let decision = match self.verdict {
            PolicyVerdict::Deny => PolicyDecision::deny_with_rule("test.deny", "denied in test"),
            PolicyVerdict::Allow => {
                PolicyDecision::allow_with_rule("test.allow", "allowed in test")
            }
            PolicyVerdict::RequireHuman => {
                PolicyDecision::require_human_with_rule("test.human", "held in test")
            }
        };
        Ok(decision)
    }

    fn issue_lease(
        &self,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<CapabilityLease, ApprovalError> {
        self.issue_lease_calls.fetch_add(1, Ordering::SeqCst);
        let expires_at_ms = match self.lease_expiry {
            LeaseExpiry::Relative(ttl_ms) => context.now_ms + ttl_ms,
            LeaseExpiry::Absolute(expires_at_ms) => expires_at_ms,
        };
        Ok(CapabilityLease {
            capability_id: format!("lease:{}:{}", request.hunt_id.0, context.now_ms),
            expires_at_ms,
            action: request.action.kind().to_string(),
            scope: scope_for_response_action(&request.action),
        })
    }
}

#[derive(Clone, Default)]
struct RecordingExecutor {
    calls: Arc<AtomicUsize>,
    modes: Arc<Mutex<Vec<ExecutionMode>>>,
}

#[async_trait]
impl ResponseExecutor for RecordingExecutor {
    async fn execute(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        mode: ExecutionMode,
    ) -> Result<ResponseReceipt, ResponseError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.modes.lock().unwrap().push(mode);
        Ok(ResponseReceipt {
            receipt_id: format!("receipt:{}:{}", request.hunt_id.0, lease.capability_id),
            action: request.action.kind().to_string(),
            mode,
            status: match mode {
                ExecutionMode::DryRun => ResponseStatus::Simulated,
                ExecutionMode::Enforced => ResponseStatus::Executed,
            },
            summary: "recorded in test".to_string(),
            details: serde_json::json!({
                "lineage": request.evidence.get("lineage").cloned(),
                "requested_by": request.requested_by,
                "scope": lease.scope,
            }),
            audit: Default::default(),
        })
    }
}

struct OneShotRequestAgent {
    id: AgentId,
    verifying_key: VerifyingKey,
    actions: Option<Vec<SwarmAction>>,
}

impl OneShotRequestAgent {
    fn new(id: AgentId, actions: Vec<SwarmAction>) -> Self {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        Self {
            id,
            verifying_key: signing_key.verifying_key(),
            actions: Some(actions),
        }
    }
}

#[async_trait]
impl SwarmAgent for OneShotRequestAgent {
    fn identity(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    fn id(&self) -> &AgentId {
        &self.id
    }

    fn role(&self) -> AgentRole {
        AgentRole::Pouncer
    }

    fn observe_event(&mut self, _event: &swarm_core::agent::SwarmEvent) -> Result<(), SwarmError> {
        Ok(())
    }

    async fn tick(&mut self, _env: &SwarmEnvironment) -> Result<Vec<SwarmAction>, SwarmError> {
        Ok(self.actions.take().unwrap_or_default())
    }

    fn health(&self) -> AgentHealth {
        AgentHealth::Healthy
    }
}

struct RuntimeBackedRouter<P, E> {
    runtime: Arc<SwarmRuntime<P, E>>,
    context: ApprovalContext,
    audits: Arc<Mutex<Vec<AuditTrail>>>,
}

impl<P, E> RuntimeBackedRouter<P, E> {
    fn new(
        runtime: Arc<SwarmRuntime<P, E>>,
        context: ApprovalContext,
        audits: Arc<Mutex<Vec<AuditTrail>>>,
    ) -> Self {
        Self {
            runtime,
            context,
            audits,
        }
    }
}

#[async_trait]
impl<P, E> RequestResponseRouter for RuntimeBackedRouter<P, E>
where
    P: ApprovalGate + Send + Sync + 'static,
    E: ResponseExecutor + Send + Sync + 'static,
{
    async fn route_request(&self, request: ActionRequest) -> Result<AuditTrail, RuntimeError> {
        let detection = detection_from_request(&request);
        let audit = self
            .runtime
            .audit_authorize_and_execute(&detection, &request, &self.context)
            .await?;
        self.audits.lock().unwrap().push(audit.clone());
        Ok(audit)
    }

    async fn route_governance_veto(
        &self,
        veto: GovernanceVetoRoute,
    ) -> Result<AuditTrail, RuntimeError> {
        let detection = detection_from_request(&veto.request);
        let audit = self.runtime.audit_governance_veto(
            &detection,
            &veto.request,
            &self.context,
            &veto.governing_agent_id,
            veto.reason,
        );
        self.audits.lock().unwrap().push(audit.clone());
        Ok(audit)
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

fn test_health_state() -> Arc<ArcSwap<Vec<AgentHealthEntry>>> {
    Arc::new(ArcSwap::from_pointee(Vec::new()))
}

fn test_substrate() -> ConfiguredPheromoneSubstrate {
    ConfiguredPheromoneSubstrate::InMemory(InMemoryPheromoneSubstrate::new(PheromoneConfig {
        default_half_life_secs: 3600.0,
        evaporation_threshold: 0.01,
        min_sources_for_escalation: 2,
        alert_threshold: 2.0,
        incident_threshold: 5.0,
        deescalation_cooldown_secs: 300,
        response_playbook: Default::default(),
        backend: PheromoneBackendConfig::InMemory,
    }))
}

fn sample_request_response_action(
    hunt_id: &str,
    event_id: &str,
    action: ResponseAction,
    severity: Severity,
) -> SwarmAction {
    SwarmAction::RequestResponse {
        hunt_id: HuntId(hunt_id.to_string()),
        action,
        evidence: serde_json::json!({
            "lineage": {
                "hunt_id": hunt_id,
                "event_id": event_id,
                "indicator": {
                    "event_id": event_id,
                    "hunt_id": hunt_id,
                    "sensor": "dispatch_integration"
                }
            },
            "escalation": {
                "mode": "alert",
                "mode_transition_at": 1_700_000_000,
                "timestamp": 1_700_000_010,
                "threat_class": ThreatClass::Execution,
                "severity": severity,
                "confidence": 0.97
            },
            "playbook_match": {
                "threat_class": ThreatClass::Execution,
                "severity": severity,
                "min_confidence": 0.90,
                "max_confidence": 1.0
            }
        }),
    }
}

fn sample_governance_veto_action(
    hunt_id: &str,
    event_id: &str,
    action: ResponseAction,
    severity: Severity,
    governing_agent_id: AgentId,
    reason: &str,
) -> SwarmAction {
    SwarmAction::GovernanceVeto {
        hunt_id: HuntId(hunt_id.to_string()),
        action,
        evidence: serde_json::json!({
            "lineage": {
                "hunt_id": hunt_id,
                "event_id": event_id,
                "indicator": {
                    "event_id": event_id,
                    "hunt_id": hunt_id,
                    "sensor": "dispatch_integration"
                }
            },
            "escalation": {
                "mode": "incident",
                "mode_transition_at": 1_700_000_000,
                "timestamp": 1_700_000_010,
                "threat_class": ThreatClass::CommandAndControl,
                "severity": severity,
                "confidence": 0.99
            },
            "playbook_match": {
                "threat_class": ThreatClass::CommandAndControl,
                "severity": severity,
                "min_confidence": 0.95,
                "max_confidence": 1.0
            }
        }),
        governing_agent_id,
        reason: reason.to_string(),
    }
}

fn detection_from_request(request: &ActionRequest) -> DetectionFinding {
    let event_id = request
        .evidence
        .get("lineage")
        .and_then(|value| value.get("event_id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or(request.hunt_id.0.as_str())
        .to_string();
    let threat_class = request
        .evidence
        .get("escalation")
        .and_then(|value| value.get("threat_class"))
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or(ThreatClass::Execution);
    let severity = request
        .evidence
        .get("escalation")
        .and_then(|value| value.get("severity"))
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or(request.severity);
    let confidence = request
        .evidence
        .get("escalation")
        .and_then(|value| value.get("confidence"))
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(1.0);

    DetectionFinding {
        finding_id: format!("pounceagent:{event_id}"),
        event_id,
        threat_class,
        severity,
        confidence,
        evidence: request.evidence.clone(),
        strategy_id: "pounce_agent".to_string(),
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
        DispatchingExecutor::from_config(config.response_adapter.clone(), None)?,
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
        DispatchingExecutor::from_config(ResponseAdapterConfig::Sandbox, None)?,
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
        DispatchingExecutor::from_config(ResponseAdapterConfig::Sandbox, None)?,
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
        DispatchingExecutor::from_config(
            ResponseAdapterConfig::Webhook {
                config: WebhookConfig {
                    url,
                    timeout_ms: 10,
                    channel: None,
                    auth_token: None,
                    retry: RetryConfig::default(),
                    circuit_breaker: CircuitBreakerConfig::default(),
                    dead_letter_path: "./dead-letter.jsonl".to_string(),
                },
            },
            None,
        )?,
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

#[tokio::test]
async fn request_response_routes_through_authorize_and_execute() -> Result<(), Box<dyn Error>> {
    let (gate, evaluate_calls, issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let guard_calls = Arc::new(AtomicUsize::new(0));
    let runtime = Arc::new(
        SwarmRuntime::new(RuntimeMode::LiveResponse, gate, executor.clone()).with_guard_pipeline(
            GuardPipeline::new(vec![Box::new(CountingGuard {
                calls: Arc::clone(&guard_calls),
            })]),
        ),
    );
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        Arc::clone(&runtime),
        sample_context(),
        Arc::clone(&audits),
    ));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router);
    dispatcher.register(Box::new(OneShotRequestAgent::new(
        AgentId::new("pounce", "primary"),
        vec![sample_request_response_action(
            "hunt-route-1",
            "evt-route-1",
            ResponseAction::DeployDecoy {
                decoy_type: "honeypot".to_string(),
                target_zone: "dmz".to_string(),
            },
            Severity::High,
        )],
    )))?;

    dispatcher.tick_once().await;

    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 1);
    assert_eq!(guard_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);

    let audits = audits.lock().unwrap();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].hunt_id, "hunt-route-1");
    let AuditResponseRecord::Success(receipt) = &audits[0].response else {
        panic!("expected success receipt, got {:?}", audits[0].response);
    };
    assert_eq!(receipt.mode, ExecutionMode::Enforced);
    assert_eq!(receipt.status, ResponseStatus::Executed);
    Ok(())
}

#[tokio::test]
async fn pounceagent_dry_run_routes_through_runtime_path() -> Result<(), Box<dyn Error>> {
    let (gate, evaluate_calls, issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let guard_calls = Arc::new(AtomicUsize::new(0));
    let runtime = Arc::new(
        SwarmRuntime::new(RuntimeMode::DetectOnly, gate, executor.clone()).with_guard_pipeline(
            GuardPipeline::new(vec![Box::new(CountingGuard {
                calls: Arc::clone(&guard_calls),
            })]),
        ),
    );
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        Arc::clone(&runtime),
        sample_context(),
        Arc::clone(&audits),
    ));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router);
    dispatcher.register(Box::new(OneShotRequestAgent::new(
        AgentId::new("pounce", "primary"),
        vec![sample_request_response_action(
            "hunt-dry-run-1",
            "evt-dry-run-1",
            ResponseAction::DeployDecoy {
                decoy_type: "honeypot".to_string(),
                target_zone: "dmz".to_string(),
            },
            Severity::High,
        )],
    )))?;

    dispatcher.tick_once().await;

    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 1);
    assert_eq!(guard_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        executor.modes.lock().unwrap().as_slice(),
        &[ExecutionMode::DryRun]
    );

    let audits = audits.lock().unwrap();
    let AuditResponseRecord::Success(receipt) = &audits[0].response else {
        panic!("expected success receipt, got {:?}", audits[0].response);
    };
    assert_eq!(receipt.mode, ExecutionMode::DryRun);
    assert_eq!(receipt.status, ResponseStatus::Simulated);
    Ok(())
}

#[tokio::test]
async fn expired_capability_lease_fails_closed_before_execution() -> Result<(), Box<dyn Error>> {
    let context = sample_context();
    let (gate, evaluate_calls, issue_lease_calls) =
        CountingApprovalGate::allow_with_expiry(context.now_ms);
    let executor = RecordingExecutor::default();
    let runtime = SwarmRuntime::new(RuntimeMode::LiveResponse, gate, executor.clone());
    let request = sample_request(
        ResponseAction::DeployDecoy {
            decoy_type: "honeypot".to_string(),
            target_zone: "dmz".to_string(),
        },
        Severity::High,
    );

    let error = runtime
        .authorize_and_execute(&request, &context)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        RuntimeError::Approval(ApprovalError::Denied(ref reason))
        if reason == "capability lease expired"
    ));
    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn receipt_preserves_original_hunt_id_and_lineage_evidence() -> Result<(), Box<dyn Error>> {
    let (gate, _evaluate_calls, _issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(RuntimeMode::DetectOnly, gate, executor));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        Arc::clone(&runtime),
        sample_context(),
        Arc::clone(&audits),
    ));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router);
    dispatcher.register(Box::new(OneShotRequestAgent::new(
        AgentId::new("pounce", "primary"),
        vec![sample_request_response_action(
            "hunt-lineage-1",
            "evt-lineage-1",
            ResponseAction::DeployDecoy {
                decoy_type: "honeypot".to_string(),
                target_zone: "dmz".to_string(),
            },
            Severity::High,
        )],
    )))?;

    dispatcher.tick_once().await;

    let audits = audits.lock().unwrap();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].hunt_id, "hunt-lineage-1");
    assert_eq!(audits[0].detection.event_id, "evt-lineage-1");
    assert_eq!(
        audits[0].detection.evidence["lineage"]["event_id"],
        serde_json::json!("evt-lineage-1")
    );
    assert_eq!(
        audits[0].detection.evidence["lineage"]["hunt_id"],
        serde_json::json!("hunt-lineage-1")
    );

    let AuditResponseRecord::Success(receipt) = &audits[0].response else {
        panic!("expected success receipt, got {:?}", audits[0].response);
    };
    assert!(receipt.receipt_id.contains("hunt-lineage-1"));
    assert_eq!(
        receipt.details["lineage"]["event_id"],
        serde_json::json!("evt-lineage-1")
    );
    assert_eq!(
        receipt.details["lineage"]["hunt_id"],
        serde_json::json!("hunt-lineage-1")
    );
    assert_eq!(
        receipt
            .audit
            .policy
            .as_ref()
            .map(|policy| policy.rule_name.as_str()),
        Some("test.allow")
    );
    Ok(())
}

#[tokio::test]
async fn audit_trail_records_rule_name_and_reason() -> Result<(), Box<dyn Error>> {
    let (gate, _evaluate_calls, _issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = SwarmRuntime::new(RuntimeMode::DetectOnly, gate, executor);
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

    assert_eq!(report.audit.policy.rule_name, "test.allow");
    assert_eq!(report.audit.policy.reason, "allowed in test");
    Ok(())
}

#[tokio::test]
async fn successful_receipts_embed_policy_audit() -> Result<(), Box<dyn Error>> {
    let (gate, _evaluate_calls, _issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = SwarmRuntime::new(RuntimeMode::DetectOnly, gate, executor);
    let request = sample_request(
        ResponseAction::DeployDecoy {
            decoy_type: "honeypot".to_string(),
            target_zone: "dmz".to_string(),
        },
        Severity::High,
    );

    let receipt = runtime
        .authorize_and_execute(&request, &sample_context())
        .await?;
    let policy = receipt.audit.policy.expect("policy audit missing");

    assert_eq!(policy.verdict, PolicyVerdict::Allow);
    assert_eq!(policy.rule_name, "test.allow");
    assert_eq!(policy.reason, "allowed in test");
    Ok(())
}

#[tokio::test]
async fn governance_veto_records_failure_receipt_without_execution() -> Result<(), Box<dyn Error>> {
    let (gate, evaluate_calls, issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        gate,
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        Arc::clone(&runtime),
        sample_context(),
        Arc::clone(&audits),
    ));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router);
    dispatcher.register(Box::new(OneShotRequestAgent::new(
        AgentId::new("pounce", "primary"),
        vec![sample_governance_veto_action(
            "hunt-veto-1",
            "evt-veto-1",
            ResponseAction::BlockEgress {
                target: "203.0.113.10".to_string(),
            },
            Severity::Critical,
            AgentId::new("tom", "primary"),
            "blocked destructive action while swarm unhealthy: whisker-primary:Degraded",
        )],
    )))?;

    dispatcher.tick_once().await;

    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 0);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);

    let audits = audits.lock().unwrap();
    assert_eq!(audits.len(), 1);
    let AuditResponseRecord::Failure(failure) = &audits[0].response else {
        panic!("expected failure receipt, got {:?}", audits[0].response);
    };
    assert_eq!(audits[0].policy.rule_name, "governance.veto");
    assert_eq!(failure.action, "block_egress");
    assert!(failure.receipt_id.contains("hunt-veto-1"));
    assert_eq!(
        failure.details["audit"]["governance"]["governing_agent_id"],
        serde_json::json!("tom-primary")
    );
    assert_eq!(
        failure.details["audit"]["governance"]["reason"],
        serde_json::json!(
            "blocked destructive action while swarm unhealthy: whisker-primary:Degraded"
        )
    );
    assert!(
        audits[0]
            .all_receipt_ids()
            .iter()
            .any(|receipt_id| receipt_id == &failure.receipt_id)
    );
    Ok(())
}
