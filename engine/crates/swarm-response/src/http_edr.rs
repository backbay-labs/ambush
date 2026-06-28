use crate::config::HttpEdrConfig;
use crate::{ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt, ResponseStatus};
use async_trait::async_trait;
use reqwest::Client;
use reqwest::redirect::Policy;
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use swarm_core::types::ResponseAction;
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
            .bearer_auth(&self.config.auth_token)
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
            auth_token: "secret".to_string(),
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
            auth_token: "secret".to_string(),
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
            auth_token: "secret".to_string(),
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
