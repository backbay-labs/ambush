use crate::config::HttpEdrConfig;
use crate::containment::ContainmentLease;
use crate::rollback::{
    ContainmentInverse, InverseGap, RollbackExecutor, RollbackReceipt, RollbackStepOutcome,
    RollbackStepStatus, RollbackTrigger, resolve_inverse,
};
use crate::{ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt, ResponseStatus};
use async_trait::async_trait;
use reqwest::Client;
use reqwest::redirect::Policy;
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use swarm_core::types::{ResponseAction, ResponseRollbackStepKind};
use swarm_policy::{ActionRequest, CapabilityLease};

#[derive(Clone)]
pub struct HttpEdrAdapter {
    config: HttpEdrConfig,
    client: Client,
}

impl HttpEdrAdapter {
    pub fn new(config: HttpEdrConfig) -> Result<Self, ResponseError> {
        if config.endpoint.trim().is_empty() {
            return Err(ResponseError::unavailable(
                "http_edr",
                ExecutionMode::Enforced,
                "http edr endpoint must not be empty",
            ));
        }

        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .redirect(Policy::none())
            .build()
            .map_err(|error| {
                ResponseError::unavailable(
                    "http_edr",
                    ExecutionMode::Enforced,
                    format!("failed to build reqwest client: {error}"),
                )
            })?;

        Ok(Self { config, client })
    }

    fn receipt_id(&self, request: &ActionRequest, lease: &CapabilityLease) -> String {
        format!("resp-edr:{}:{}", request.hunt_id.0, lease.capability_id)
    }

    fn payload(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
    ) -> Result<Value, Box<ResponseReceipt>> {
        let base = json!({
            "action": request.action.kind(),
            "hunt_id": request.hunt_id.0,
            "lease_id": lease.capability_id,
            "scope": lease.scope,
            "severity": request.severity,
            "evidence": request.evidence,
        });

        match &request.action {
            ResponseAction::BlockEgress { target } => {
                let mut payload = base;
                if let Some(object) = payload.as_object_mut() {
                    object.insert("target".to_string(), json!(target));
                }
                Ok(payload)
            }
            ResponseAction::IsolateHost { host_id } => {
                let mut payload = base;
                if let Some(object) = payload.as_object_mut() {
                    object.insert("host_id".to_string(), json!(host_id));
                }
                Ok(payload)
            }
            ResponseAction::RevokeCredential { credential_id } => {
                let mut payload = base;
                if let Some(object) = payload.as_object_mut() {
                    object.insert("credential_id".to_string(), json!(credential_id));
                }
                Ok(payload)
            }
            ResponseAction::SinkholeDns { domain } => {
                let mut payload = base;
                if let Some(object) = payload.as_object_mut() {
                    object.insert("domain".to_string(), json!(domain));
                }
                Ok(payload)
            }
            ResponseAction::TerminateUserSession {
                host_id,
                session_id,
            } => {
                let mut payload = base;
                if let Some(object) = payload.as_object_mut() {
                    object.insert("host_id".to_string(), json!(host_id));
                    object.insert("session_id".to_string(), json!(session_id));
                }
                Ok(payload)
            }
            ResponseAction::TriggerEdrScan {
                host_id,
                scan_profile,
            } => {
                let mut payload = base;
                if let Some(object) = payload.as_object_mut() {
                    object.insert("host_id".to_string(), json!(host_id));
                    object.insert("scan_profile".to_string(), json!(scan_profile));
                }
                Ok(payload)
            }
            ResponseAction::InjectFirewallRule {
                host_id,
                rule_name,
                direction,
                cidr,
                port,
            } => {
                let mut payload = base;
                if let Some(object) = payload.as_object_mut() {
                    object.insert("host_id".to_string(), json!(host_id));
                    object.insert("rule_name".to_string(), json!(rule_name));
                    object.insert("direction".to_string(), json!(direction));
                    object.insert("cidr".to_string(), json!(cidr));
                    object.insert("port".to_string(), json!(port));
                }
                Ok(payload)
            }
            ResponseAction::QuarantineFile { host_id, file_path } => {
                let mut payload = base;
                if let Some(object) = payload.as_object_mut() {
                    object.insert("host_id".to_string(), json!(host_id));
                    object.insert("file_path".to_string(), json!(file_path));
                }
                Ok(payload)
            }
            ResponseAction::KillProcess {
                host_id,
                process_name,
            }
            | ResponseAction::SuspendProcess {
                host_id,
                process_name,
            } => {
                let mut payload = base;
                if let Some(object) = payload.as_object_mut() {
                    object.insert("host_id".to_string(), json!(host_id));
                    object.insert("process_name".to_string(), json!(process_name));
                }
                Ok(payload)
            }
            ResponseAction::DisableUserAccount { user_id }
            | ResponseAction::ForcePasswordReset { user_id } => {
                let mut payload = base;
                if let Some(object) = payload.as_object_mut() {
                    object.insert("user_id".to_string(), json!(user_id));
                }
                Ok(payload)
            }
            ResponseAction::RemoveScheduledTask { host_id, task_name } => {
                let mut payload = base;
                if let Some(object) = payload.as_object_mut() {
                    object.insert("host_id".to_string(), json!(host_id));
                    object.insert("task_name".to_string(), json!(task_name));
                }
                Ok(payload)
            }
            _ => Err(Box::new(ResponseReceipt {
                receipt_id: self.receipt_id(request, lease),
                action: request.action.kind().to_string(),
                mode: ExecutionMode::Enforced,
                status: ResponseStatus::Failed,
                summary: format!(
                    "http edr adapter does not support action `{}`",
                    request.action.kind()
                ),
                details: json!({
                    "adapter": "http_edr",
                    "endpoint": self.config.endpoint,
                    "lease_id": lease.capability_id,
                }),
                audit: Default::default(),
            })),
        }
    }
}

impl std::fmt::Debug for HttpEdrAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpEdrAdapter")
            .field("endpoint", &self.config.endpoint)
            .field("timeout_ms", &self.config.timeout_ms)
            .finish()
    }
}

#[async_trait]
impl ResponseExecutor for HttpEdrAdapter {
    async fn execute(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        mode: ExecutionMode,
    ) -> Result<ResponseReceipt, ResponseError> {
        let receipt_id = self.receipt_id(request, lease);
        let payload = match self.payload(request, lease) {
            Ok(payload) => payload,
            Err(receipt) => return Ok(*receipt),
        };

        if mode == ExecutionMode::DryRun {
            return Ok(ResponseReceipt {
                receipt_id,
                action: request.action.kind().to_string(),
                mode,
                status: ResponseStatus::Simulated,
                summary: format!("dry run http edr {}", request.action.kind()),
                details: json!({
                    "adapter": "http_edr",
                    "endpoint": self.config.endpoint,
                    "payload": payload,
                    "authorization_header": "Bearer <redacted>",
                }),
                audit: Default::default(),
            });
        }

        let started = Instant::now();
        let result = self
            .client
            .post(&self.config.endpoint)
            .bearer_auth(self.config.auth_token.expose_secret())
            .json(&payload)
            .send()
            .await;
        let elapsed_ms = started.elapsed().as_millis() as u64;

        match result {
            Ok(response) => {
                let status_code = response.status();
                let response_body = match response.text().await {
                    Ok(body) => body,
                    Err(error) => format!("<failed to read response body: {error}>"),
                };
                let success = status_code.is_success();
                Ok(ResponseReceipt {
                    receipt_id,
                    action: request.action.kind().to_string(),
                    mode,
                    status: if success {
                        ResponseStatus::Executed
                    } else {
                        ResponseStatus::Failed
                    },
                    summary: if success {
                        format!(
                            "http edr {} completed with status {}",
                            request.action.kind(),
                            status_code.as_u16()
                        )
                    } else {
                        format!(
                            "http edr {} failed with status {}",
                            request.action.kind(),
                            status_code.as_u16()
                        )
                    },
                    details: json!({
                        "adapter": "http_edr",
                        "endpoint": self.config.endpoint,
                        "payload": payload,
                        "status_code": status_code.as_u16(),
                        "response_body": response_body,
                        "elapsed_ms": elapsed_ms,
                    }),
                    audit: Default::default(),
                })
            }
            Err(error) if error.is_timeout() => Ok(ResponseReceipt {
                receipt_id,
                action: request.action.kind().to_string(),
                mode,
                status: ResponseStatus::Timeout,
                summary: format!("http edr {} timed out", request.action.kind()),
                details: json!({
                    "adapter": "http_edr",
                    "endpoint": self.config.endpoint,
                    "payload": payload,
                    "elapsed_ms": elapsed_ms,
                }),
                audit: Default::default(),
            }),
            Err(error) => Ok(ResponseReceipt {
                receipt_id,
                action: request.action.kind().to_string(),
                mode,
                status: ResponseStatus::Failed,
                summary: format!("http edr {} failed: {error}", request.action.kind()),
                details: json!({
                    "adapter": "http_edr",
                    "endpoint": self.config.endpoint,
                    "payload": payload,
                    "elapsed_ms": elapsed_ms,
                    "error": error.to_string(),
                }),
                audit: Default::default(),
            }),
        }
    }
}

/// Executes containment inverses against the same EDR endpoint
/// [`HttpEdrAdapter`] used to apply them.
///
/// This is the half of reversible containment that actually touches the world.
/// It refuses to invent a target: every request body is built from
/// [`resolve_inverse`], which reads the lease's typed `ResponseAction`, so a
/// step whose inverse is not defined produces no HTTP call at all and is
/// recorded as such.
#[derive(Clone)]
pub struct HttpEdrRollbackExecutor {
    config: HttpEdrConfig,
    client: Client,
}

impl HttpEdrRollbackExecutor {
    pub fn new(config: HttpEdrConfig) -> Result<Self, ResponseError> {
        if config.endpoint.trim().is_empty() {
            return Err(ResponseError::unavailable(
                "http_edr_rollback",
                ExecutionMode::Enforced,
                "http edr endpoint must not be empty",
            ));
        }
        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .redirect(Policy::none())
            .build()
            .map_err(|error| {
                ResponseError::unavailable(
                    "http_edr_rollback",
                    ExecutionMode::Enforced,
                    format!("failed to build reqwest client: {error}"),
                )
            })?;
        Ok(Self { config, client })
    }

    fn inverse_payload(
        lease: &ContainmentLease,
        inverse: &ContainmentInverse,
        trigger: RollbackTrigger,
    ) -> Value {
        // Serializing the inverse is what puts the target on the wire; the
        // `#[serde(tag = "action")]` on `ContainmentInverse` makes the operation
        // name and the fields it addresses one object that cannot disagree.
        let mut payload = serde_json::to_value(inverse).unwrap_or_else(|_| json!({}));
        if let Some(object) = payload.as_object_mut() {
            object.insert("lease_id".to_string(), json!(lease.lease_id()));
            object.insert(
                "origin_receipt_id".to_string(),
                json!(lease.origin_receipt_id()),
            );
            object.insert("contained_action".to_string(), json!(lease.action_kind()));
            object.insert("trigger".to_string(), json!(trigger.as_str()));
        }
        payload
    }

    async fn issue(
        &self,
        lease: &ContainmentLease,
        inverse: &ContainmentInverse,
        trigger: RollbackTrigger,
        kind: ResponseRollbackStepKind,
        mode: ExecutionMode,
    ) -> RollbackStepOutcome {
        let payload = Self::inverse_payload(lease, inverse, trigger);

        if mode == ExecutionMode::DryRun {
            return RollbackStepOutcome {
                kind,
                status: RollbackStepStatus::Simulated,
                detail: format!(
                    "dry run: would POST `{}` for `{}` to the configured edr endpoint",
                    inverse.kind(),
                    inverse.target()
                ),
            };
        }

        let result = self
            .client
            .post(&self.config.endpoint)
            .bearer_auth(self.config.auth_token.expose_secret())
            .json(&payload)
            .send()
            .await;

        match result {
            Ok(response) if response.status().is_success() => RollbackStepOutcome {
                kind,
                status: RollbackStepStatus::Reversed,
                detail: format!(
                    "`{}` accepted for `{}` with status {}",
                    inverse.kind(),
                    inverse.target(),
                    response.status().as_u16()
                ),
            },
            Ok(response) => RollbackStepOutcome {
                kind,
                status: RollbackStepStatus::Failed,
                detail: format!(
                    "`{}` for `{}` rejected with status {}; the containment stays in effect",
                    inverse.kind(),
                    inverse.target(),
                    response.status().as_u16()
                ),
            },
            Err(error) => RollbackStepOutcome {
                kind,
                status: RollbackStepStatus::Failed,
                detail: format!(
                    "`{}` for `{}` could not be issued: {error}; the containment stays in effect",
                    inverse.kind(),
                    inverse.target()
                ),
            },
        }
    }
}

impl std::fmt::Debug for HttpEdrRollbackExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpEdrRollbackExecutor")
            .field("endpoint", &self.config.endpoint)
            .field("timeout_ms", &self.config.timeout_ms)
            .finish()
    }
}

#[async_trait]
impl RollbackExecutor for HttpEdrRollbackExecutor {
    async fn rollback(
        &self,
        lease: &ContainmentLease,
        trigger: RollbackTrigger,
        mode: ExecutionMode,
        completed_at_ms: i64,
    ) -> Result<RollbackReceipt, ResponseError> {
        if lease.rollback().steps.is_empty() {
            return Err(ResponseError::unavailable(
                lease.action_kind(),
                mode,
                format!(
                    "containment lease `{}` carries no rollback steps; refusing to claim reversal",
                    lease.lease_id()
                ),
            ));
        }

        let mut steps = Vec::with_capacity(lease.rollback().steps.len());
        for step in &lease.rollback().steps {
            match resolve_inverse(lease.action(), step.kind) {
                Ok(inverse) => {
                    steps.push(self.issue(lease, &inverse, trigger, step.kind, mode).await);
                }
                Err(InverseGap::Irreversible { reason }) => steps.push(RollbackStepOutcome {
                    kind: step.kind,
                    status: RollbackStepStatus::Irreversible,
                    detail: format!("`{}` cannot be reversed: {reason}", lease.action_kind()),
                }),
                Err(InverseGap::Unmapped) => steps.push(RollbackStepOutcome {
                    kind: step.kind,
                    status: RollbackStepStatus::Unsupported,
                    detail: format!(
                        "no inverse operation is defined for step {:?} of `{}`; the containment \
                         stays in effect",
                        step.kind,
                        lease.action_kind()
                    ),
                }),
            }
        }

        Ok(RollbackReceipt::from_steps(
            lease,
            trigger,
            mode,
            completed_at_ms,
            steps,
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::HttpEdrAdapter;
    use crate::config::{CircuitBreakerConfig, HttpEdrConfig, RetryConfig};
    use crate::{ExecutionMode, ResponseExecutor, ResponseStatus};
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::{Value, json};
    use std::sync::Arc;
    use std::time::Duration;
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
    use swarm_policy::{ActionRequest, CapabilityLease};
    use tokio::sync::{Mutex, oneshot};

    #[derive(Clone, Default)]
    struct CaptureState {
        auth: Arc<Mutex<Option<String>>>,
        payload: Arc<Mutex<Option<Value>>>,
        delay: Duration,
        status: StatusCode,
    }

    async fn handler(
        State(state): State<CaptureState>,
        headers: HeaderMap,
        Json(payload): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        {
            let mut auth = state.auth.lock().await;
            *auth = headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string);
        }
        {
            let mut captured = state.payload.lock().await;
            *captured = Some(payload);
        }
        if !state.delay.is_zero() {
            tokio::time::sleep(state.delay).await;
        }
        (state.status, Json(json!({"ok": true})))
    }

    async fn spawn_server(
        delay: Duration,
        status: StatusCode,
    ) -> (
        String,
        CaptureState,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let state = CaptureState {
            auth: Arc::default(),
            payload: Arc::default(),
            delay,
            status,
        };
        let app = Router::new()
            .route("/", post(handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let server = axum::serve(listener, app).with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            });
            let _ = server.await;
        });
        (format!("http://{address}/"), state, shutdown_tx, handle)
    }

    fn sample_request() -> ActionRequest {
        ActionRequest {
            hunt_id: HuntId("hunt-edr".to_string()),
            requested_by: AgentId("agent-1".to_string()),
            action: ResponseAction::BlockEgress {
                target: "198.51.100.9".to_string(),
            },
            severity: Severity::High,
            evidence: json!({"signal": "egress"}),
        }
    }

    fn sample_lease() -> CapabilityLease {
        CapabilityLease {
            capability_id: "lease-edr".to_string(),
            expires_at_ms: 1_000,
            action: "block_egress".to_string(),
            scope: Some("198.51.100.9".to_string()),
        }
    }

    #[tokio::test]
    async fn dry_run_returns_simulated_receipt() {
        let adapter = HttpEdrAdapter::new(HttpEdrConfig {
            endpoint: "http://127.0.0.1:9/".to_string(),
            auth_token: "secret".to_string().into(),
            timeout_ms: 50,
            retry: RetryConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            dead_letter_path: "./dead-letter.jsonl".to_string(),
        })
        .unwrap();

        let receipt = adapter
            .execute(&sample_request(), &sample_lease(), ExecutionMode::DryRun)
            .await
            .unwrap();
        assert_eq!(receipt.status, ResponseStatus::Simulated);
    }

    #[tokio::test]
    async fn enforced_mode_posts_authorized_json_payload() {
        let (endpoint, state, shutdown_tx, handle) =
            spawn_server(Duration::from_millis(0), StatusCode::OK).await;
        let adapter = HttpEdrAdapter::new(HttpEdrConfig {
            endpoint,
            auth_token: "secret".to_string().into(),
            timeout_ms: 500,
            retry: RetryConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            dead_letter_path: "./dead-letter.jsonl".to_string(),
        })
        .unwrap();

        let receipt = adapter
            .execute(&sample_request(), &sample_lease(), ExecutionMode::Enforced)
            .await
            .unwrap();

        assert_eq!(receipt.status, ResponseStatus::Executed);
        assert_eq!(
            state.auth.lock().await.clone(),
            Some("Bearer secret".to_string())
        );
        let payload = state.payload.lock().await.clone().unwrap();
        assert_eq!(payload["action"], "block_egress");
        assert_eq!(payload["target"], "198.51.100.9");
        assert_eq!(payload["lease_id"], "lease-edr");

        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[tokio::test]
    async fn timeout_returns_timeout_status() {
        let (endpoint, _state, shutdown_tx, handle) =
            spawn_server(Duration::from_millis(50), StatusCode::OK).await;
        let adapter = HttpEdrAdapter::new(HttpEdrConfig {
            endpoint,
            auth_token: "secret".to_string().into(),
            timeout_ms: 10,
            retry: RetryConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            dead_letter_path: "./dead-letter.jsonl".to_string(),
        })
        .unwrap();

        let receipt = adapter
            .execute(&sample_request(), &sample_lease(), ExecutionMode::Enforced)
            .await
            .unwrap();
        assert_eq!(receipt.status, ResponseStatus::Timeout);

        let _ = shutdown_tx.send(());
        handle.abort();
    }
}

/// The forward containment and its inverse, against ONE stateful fake EDR.
///
/// The assertions here are about the fake's SET of contained targets, not about
/// the receipt. A rollback executor that returned a beautifully formed receipt
/// and issued no request passes every receipt-shaped assertion; it cannot pass
/// these. That gap is exactly what the shipped `SandboxRollbackExecutor` had.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod rollback_tests {
    use super::{HttpEdrAdapter, HttpEdrRollbackExecutor};
    use crate::config::{CircuitBreakerConfig, HttpEdrConfig, RetryConfig};
    use crate::containment::{ContainmentLease, ContainmentTtl};
    use crate::rollback::{RollbackExecutor, RollbackStepStatus, RollbackTrigger};
    use crate::{ExecutionMode, ResponseExecutor, ResponseStatus};
    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::{Value, json};
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};
    use swarm_core::types::{
        AgentId, HuntId, ResponseAction, ResponseBlastRadiusImpact, ResponseBlastRadiusPreview,
        ResponseRehearsalPreview, ResponseRehearsalScopeKind, ResponseRollbackPreview,
        ResponseRollbackStep, ResponseRollbackStepKind, Severity,
    };
    use swarm_policy::{ActionRequest, CapabilityLease};
    use tokio::sync::oneshot;

    /// A fake EDR that actually holds containment state.
    #[derive(Clone, Default)]
    struct FakeEdr {
        contained: Arc<Mutex<BTreeSet<String>>>,
    }

    impl FakeEdr {
        fn snapshot(&self) -> BTreeSet<String> {
            self.contained.lock().unwrap().clone()
        }
    }

    fn target_of(payload: &Value) -> Option<String> {
        let host = payload.get("host_id")?.as_str()?;
        Some(match payload.get("action")?.as_str()? {
            "quarantine_file" | "release_quarantined_file" => {
                format!("{host}:{}", payload.get("file_path")?.as_str()?)
            }
            "suspend_process" | "resume_process" => {
                format!("{host}:{}", payload.get("process_name")?.as_str()?)
            }
            "isolate_host" | "restore_host_connectivity" => host.to_string(),
            _ => return None,
        })
    }

    async fn handler(State(state): State<FakeEdr>, Json(payload): Json<Value>) -> StatusCode {
        let Some(action) = payload.get("action").and_then(Value::as_str) else {
            return StatusCode::BAD_REQUEST;
        };
        let Some(target) = target_of(&payload) else {
            return StatusCode::BAD_REQUEST;
        };
        let mut contained = state.contained.lock().unwrap();
        match action {
            "quarantine_file" | "suspend_process" | "isolate_host" => {
                contained.insert(target);
            }
            "release_quarantined_file" | "resume_process" | "restore_host_connectivity" => {
                // Releasing something never contained is refused, so a test
                // cannot pass by issuing a well-formed request at the wrong
                // target.
                if !contained.remove(&target) {
                    return StatusCode::CONFLICT;
                }
            }
            _ => return StatusCode::NOT_IMPLEMENTED,
        }
        StatusCode::OK
    }

    async fn spawn_fake_edr() -> (
        String,
        FakeEdr,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let state = FakeEdr::default();
        let app = Router::new()
            .route("/", post(handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let server = axum::serve(listener, app).with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            });
            let _ = server.await;
        });
        (format!("http://{address}/"), state, shutdown_tx, handle)
    }

    fn config_for(endpoint: &str) -> HttpEdrConfig {
        HttpEdrConfig {
            endpoint: endpoint.to_string(),
            auth_token: "secret".to_string().into(),
            timeout_ms: 2_000,
            retry: RetryConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            dead_letter_path: "./dead-letter.jsonl".to_string(),
        }
    }

    fn preview_for(
        scope_value: &str,
        required: bool,
        kind: ResponseRollbackStepKind,
    ) -> ResponseRehearsalPreview {
        ResponseRehearsalPreview {
            rehearsal_id: "rehearsal:test".to_string(),
            source_bundle_id: "bundle:test".to_string(),
            prepared_at_ms: 1_000,
            simulated_only: true,
            blast_radius: ResponseBlastRadiusPreview {
                scope_kind: ResponseRehearsalScopeKind::Host,
                scope_value: scope_value.to_string(),
                impact: ResponseBlastRadiusImpact::HostConnectivityIsolated,
                max_affected_scopes: 1,
                affected_capabilities: vec!["network_connectivity".to_string()],
                summary: "test blast radius".to_string(),
            },
            rollback: ResponseRollbackPreview {
                required,
                summary: "test rollback".to_string(),
                steps: vec![ResponseRollbackStep {
                    kind,
                    summary: format!("{kind:?}"),
                }],
            },
        }
    }

    fn lease_for(
        lease_id: &str,
        action: ResponseAction,
        scope_value: &str,
        required: bool,
        kind: ResponseRollbackStepKind,
    ) -> ContainmentLease {
        ContainmentLease::open(
            lease_id,
            action,
            format!("resp-edr:hunt-1:{lease_id}"),
            None,
            &preview_for(scope_value, required, kind),
            1_000,
            ContainmentTtl::from_config_ms(4_000).unwrap(),
        )
        .unwrap()
    }

    async fn contain(adapter: &HttpEdrAdapter, action: ResponseAction, scope: &str) {
        let request = ActionRequest {
            hunt_id: HuntId("hunt-1".to_string()),
            requested_by: AgentId("agent-1".to_string()),
            action,
            severity: Severity::High,
            evidence: json!({"signal": "test"}),
        };
        let lease = CapabilityLease {
            capability_id: format!("cap:{scope}"),
            expires_at_ms: 10_000,
            action: request.action.kind().to_string(),
            scope: Some(scope.to_string()),
        };
        let receipt = adapter
            .execute(&request, &lease, ExecutionMode::Enforced)
            .await
            .unwrap();
        assert_eq!(
            receipt.status,
            ResponseStatus::Executed,
            "forward containment did not execute: {}",
            receipt.summary
        );
    }

    #[tokio::test]
    async fn rollback_issues_the_concrete_inverse_and_the_target_is_no_longer_contained() {
        let (endpoint, edr, shutdown_tx, handle) = spawn_fake_edr().await;
        let adapter = HttpEdrAdapter::new(config_for(&endpoint)).unwrap();
        let executor = HttpEdrRollbackExecutor::new(config_for(&endpoint)).unwrap();

        contain(
            &adapter,
            ResponseAction::QuarantineFile {
                host_id: "host-1".to_string(),
                file_path: "/tmp/a".to_string(),
            },
            "host-1:/tmp/a",
        )
        .await;
        contain(
            &adapter,
            ResponseAction::SuspendProcess {
                host_id: "host-2".to_string(),
                process_name: "evil.exe".to_string(),
            },
            "host-2:evil.exe",
        )
        .await;
        contain(
            &adapter,
            ResponseAction::IsolateHost {
                host_id: "host-3".to_string(),
            },
            "host-3",
        )
        .await;

        assert_eq!(
            edr.snapshot(),
            BTreeSet::from([
                "host-1:/tmp/a".to_string(),
                "host-2:evil.exe".to_string(),
                "host-3".to_string(),
            ]),
            "the forward containments must have taken effect before anything is undone"
        );

        let leases = [
            lease_for(
                "lease-file",
                ResponseAction::QuarantineFile {
                    host_id: "host-1".to_string(),
                    file_path: "/tmp/a".to_string(),
                },
                "host-1:/tmp/a",
                true,
                ResponseRollbackStepKind::ReleaseQuarantinedFile,
            ),
            lease_for(
                "lease-proc",
                ResponseAction::SuspendProcess {
                    host_id: "host-2".to_string(),
                    process_name: "evil.exe".to_string(),
                },
                "host-2:evil.exe",
                true,
                ResponseRollbackStepKind::ResumeProcess,
            ),
            lease_for(
                "lease-host",
                ResponseAction::IsolateHost {
                    host_id: "host-3".to_string(),
                },
                "host-3",
                true,
                ResponseRollbackStepKind::RestoreHostConnectivity,
            ),
        ];

        for lease in &leases {
            let receipt = executor
                .rollback(
                    lease,
                    RollbackTrigger::Expiry,
                    ExecutionMode::Enforced,
                    5_000,
                )
                .await
                .unwrap();
            assert!(
                receipt.fully_reversed(),
                "rollback of `{}` did not reverse: {:?}",
                lease.lease_id(),
                receipt.steps
            );
            assert_eq!(receipt.steps[0].status, RollbackStepStatus::Reversed);
            assert_eq!(receipt.status, ResponseStatus::Executed);
            assert_eq!(receipt.origin_receipt_id, lease.origin_receipt_id());
            assert_eq!(receipt.completed_at_ms, 5_000);
        }

        assert!(
            edr.snapshot().is_empty(),
            "the inverse must have reached the fake edr; still contained: {:?}",
            edr.snapshot()
        );

        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[tokio::test]
    async fn an_irreversible_containment_issues_no_request_and_stays_contained() {
        let (endpoint, edr, shutdown_tx, handle) = spawn_fake_edr().await;
        let adapter = HttpEdrAdapter::new(config_for(&endpoint)).unwrap();
        let executor = HttpEdrRollbackExecutor::new(config_for(&endpoint)).unwrap();

        contain(
            &adapter,
            ResponseAction::IsolateHost {
                host_id: "host-9".to_string(),
            },
            "host-9",
        )
        .await;
        let before = edr.snapshot();

        let lease = lease_for(
            "lease-session",
            ResponseAction::TerminateUserSession {
                host_id: "host-9".to_string(),
                session_id: "sess-1".to_string(),
            },
            "host-9:sess-1",
            false,
            ResponseRollbackStepKind::ReauthenticateUserSession,
        );
        let receipt = executor
            .rollback(
                &lease,
                RollbackTrigger::Expiry,
                ExecutionMode::Enforced,
                5_000,
            )
            .await
            .unwrap();

        assert_eq!(receipt.steps[0].status, RollbackStepStatus::Irreversible);
        assert!(
            !receipt.fully_reversed(),
            "a terminated session was not restored; the receipt must not claim it was"
        );
        assert_eq!(receipt.status, ResponseStatus::Failed);
        assert_eq!(
            edr.snapshot(),
            before,
            "no request should have been issued for an action with no inverse"
        );

        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[tokio::test]
    async fn a_refused_inverse_is_recorded_as_failed_not_as_reversed() {
        let (endpoint, edr, shutdown_tx, handle) = spawn_fake_edr().await;
        let executor = HttpEdrRollbackExecutor::new(config_for(&endpoint)).unwrap();

        // Nothing was ever contained, so the fake answers 409 CONFLICT.
        let lease = lease_for(
            "lease-ghost",
            ResponseAction::IsolateHost {
                host_id: "host-absent".to_string(),
            },
            "host-absent",
            true,
            ResponseRollbackStepKind::RestoreHostConnectivity,
        );
        let receipt = executor
            .rollback(
                &lease,
                RollbackTrigger::Manual,
                ExecutionMode::Enforced,
                5_000,
            )
            .await
            .unwrap();

        assert_eq!(receipt.steps[0].status, RollbackStepStatus::Failed);
        assert!(!receipt.fully_reversed());
        assert_eq!(receipt.status, ResponseStatus::Failed);
        assert!(
            receipt.steps[0].detail.contains("409"),
            "unexpected detail: {}",
            receipt.steps[0].detail
        );
        assert!(edr.snapshot().is_empty());

        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[tokio::test]
    async fn dry_run_rollback_issues_no_request_and_claims_no_reversal() {
        let (endpoint, edr, shutdown_tx, handle) = spawn_fake_edr().await;
        let adapter = HttpEdrAdapter::new(config_for(&endpoint)).unwrap();
        let executor = HttpEdrRollbackExecutor::new(config_for(&endpoint)).unwrap();

        contain(
            &adapter,
            ResponseAction::IsolateHost {
                host_id: "host-4".to_string(),
            },
            "host-4",
        )
        .await;

        let lease = lease_for(
            "lease-dry",
            ResponseAction::IsolateHost {
                host_id: "host-4".to_string(),
            },
            "host-4",
            true,
            ResponseRollbackStepKind::RestoreHostConnectivity,
        );
        let receipt = executor
            .rollback(
                &lease,
                RollbackTrigger::Manual,
                ExecutionMode::DryRun,
                5_000,
            )
            .await
            .unwrap();

        assert_eq!(receipt.steps[0].status, RollbackStepStatus::Simulated);
        assert!(!receipt.fully_reversed());
        assert!(receipt.fully_rehearsed());
        assert_eq!(
            edr.snapshot(),
            BTreeSet::from(["host-4".to_string()]),
            "a dry-run rollback must not un-contain a real host"
        );

        let _ = shutdown_tx.send(());
        handle.abort();
    }
}
