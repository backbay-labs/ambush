use crate::adapters::SandboxExecutor;
use crate::config::ResponseAdapterConfig;
use crate::dead_letter::DeadLetterJournal;
use crate::http_edr::HttpEdrAdapter;
use crate::resilience::ResilientExecutor;
use crate::webhook::WebhookAdapter;
use crate::{ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt};
use async_trait::async_trait;
use std::sync::Arc;
use swarm_policy::{ActionRequest, CapabilityLease};

enum AdapterInner {
    Sandbox(SandboxExecutor),
    HttpEdr(ResilientExecutor<HttpEdrAdapter>),
    Webhook(ResilientExecutor<WebhookAdapter>),
}

pub struct DispatchingExecutor {
    inner: AdapterInner,
}

impl DispatchingExecutor {
    pub fn from_config(
        config: ResponseAdapterConfig,
        max_dead_letter_bytes: Option<u64>,
    ) -> Result<Self, ResponseError> {
        let inner = match config {
            ResponseAdapterConfig::Sandbox => AdapterInner::Sandbox(SandboxExecutor),
            ResponseAdapterConfig::HttpEdr { config } => {
                let journal = Arc::new(
                    DeadLetterJournal::new(&config.dead_letter_path, max_dead_letter_bytes)
                        .map_err(|error| {
                            ResponseError::unavailable(
                                "http_edr",
                                ExecutionMode::Enforced,
                                format!("failed to initialize dead-letter journal: {error}"),
                            )
                        })?,
                );
                let adapter = HttpEdrAdapter::new(config.clone())?;
                AdapterInner::HttpEdr(ResilientExecutor::new(
                    adapter,
                    "http_edr",
                    config.retry.clone(),
                    config.circuit_breaker.clone(),
                    Some(journal),
                ))
            }
            ResponseAdapterConfig::Webhook { config } => {
                let journal = Arc::new(
                    DeadLetterJournal::new(&config.dead_letter_path, max_dead_letter_bytes)
                        .map_err(|error| {
                            ResponseError::unavailable(
                                "webhook",
                                ExecutionMode::Enforced,
                                format!("failed to initialize dead-letter journal: {error}"),
                            )
                        })?,
                );
                let adapter = WebhookAdapter::new(config.clone())?;
                AdapterInner::Webhook(ResilientExecutor::new(
                    adapter,
                    "webhook",
                    config.retry.clone(),
                    config.circuit_breaker.clone(),
                    Some(journal),
                ))
            }
        };
        Ok(Self { inner })
    }

    pub fn kind(&self) -> &'static str {
        match &self.inner {
            AdapterInner::Sandbox(_) => "sandbox",
            AdapterInner::HttpEdr(_) => "http_edr",
            AdapterInner::Webhook(_) => "webhook",
        }
    }
}

impl std::fmt::Debug for DispatchingExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DispatchingExecutor")
            .field("kind", &self.kind())
            .finish()
    }
}

#[async_trait]
impl ResponseExecutor for DispatchingExecutor {
    async fn execute(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        mode: ExecutionMode,
    ) -> Result<ResponseReceipt, ResponseError> {
        let trace_id = request
            .evidence
            .get("trace_id")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string)
            .or_else(swarm_core::observability::current_trace_id)
            .unwrap_or_else(|| "unknown".to_string());
        let span = tracing::info_span!(
            "response.dispatch.execute",
            trace_id = %trace_id,
            hunt_id = %request.hunt_id.0,
            requested_by = %request.requested_by.0,
            action = %request.action.kind(),
            adapter = self.kind(),
            mode = ?mode,
            capability = %lease.capability_id
        );
        let _guard = span.enter();

        match &self.inner {
            AdapterInner::Sandbox(executor) => executor.execute(request, lease, mode).await,
            AdapterInner::HttpEdr(executor) => executor.execute(request, lease, mode).await,
            AdapterInner::Webhook(executor) => executor.execute(request, lease, mode).await,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::DispatchingExecutor;
    use crate::config::{
        CircuitBreakerConfig, HttpEdrConfig, ResponseAdapterConfig, RetryConfig, WebhookConfig,
    };
    use crate::{ExecutionMode, ResponseExecutor, ResponseStatus};
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::{Value, json};
    use std::sync::Arc;
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
    use swarm_policy::{ActionRequest, CapabilityLease};
    use tokio::sync::{Mutex, oneshot};

    #[derive(Clone, Default)]
    struct CaptureState {
        auth: Arc<Mutex<Option<String>>>,
        payload: Arc<Mutex<Option<Value>>>,
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
        (state.status, Json(json!({"ok": true})))
    }

    async fn spawn_server(
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

    #[tokio::test]
    async fn sandbox_config_dispatches_to_simulated_receipt() {
        let executor =
            DispatchingExecutor::from_config(ResponseAdapterConfig::Sandbox, None).unwrap();
        let request = ActionRequest {
            hunt_id: HuntId("hunt-1".to_string()),
            requested_by: AgentId("agent-1".to_string()),
            action: ResponseAction::BlockEgress {
                target: "198.51.100.7".to_string(),
            },
            severity: Severity::High,
            evidence: serde_json::json!({"signal": "test"}),
        };
        let lease = CapabilityLease {
            capability_id: "lease-1".to_string(),
            expires_at_ms: 1_000,
            action: request.action.kind().to_string(),
            scope: Some("198.51.100.7".to_string()),
        };

        let receipt = executor
            .execute(&request, &lease, ExecutionMode::DryRun)
            .await
            .unwrap();
        assert_eq!(receipt.status, ResponseStatus::Simulated);
    }

    #[tokio::test]
    async fn http_edr_config_dispatches_to_http_adapter() {
        let (endpoint, state, shutdown_tx, handle) = spawn_server(StatusCode::OK).await;
        let executor = DispatchingExecutor::from_config(
            ResponseAdapterConfig::HttpEdr {
                config: HttpEdrConfig {
                    endpoint,
                    auth_token: "secret".to_string(),
                    timeout_ms: 500,
                    retry: RetryConfig::default(),
                    circuit_breaker: CircuitBreakerConfig::default(),
                    dead_letter_path: "./dead-letter.jsonl".to_string(),
                },
            },
            None,
        )
        .unwrap();
        let request = ActionRequest {
            hunt_id: HuntId("hunt-edr".to_string()),
            requested_by: AgentId("agent-1".to_string()),
            action: ResponseAction::BlockEgress {
                target: "198.51.100.7".to_string(),
            },
            severity: Severity::High,
            evidence: serde_json::json!({"signal": "test"}),
        };
        let lease = CapabilityLease {
            capability_id: "lease-edr".to_string(),
            expires_at_ms: 1_000,
            action: request.action.kind().to_string(),
            scope: Some("198.51.100.7".to_string()),
        };

        let receipt = executor
            .execute(&request, &lease, ExecutionMode::Enforced)
            .await
            .unwrap();

        assert_eq!(receipt.status, ResponseStatus::Executed);
        assert_eq!(
            state.auth.lock().await.clone(),
            Some("Bearer secret".to_string())
        );
        assert_eq!(
            state.payload.lock().await.clone().unwrap()["action"],
            "block_egress"
        );

        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[tokio::test]
    async fn http_edr_config_dispatches_expanded_scan_action_payload() {
        let (endpoint, state, shutdown_tx, handle) = spawn_server(StatusCode::OK).await;
        let executor = DispatchingExecutor::from_config(
            ResponseAdapterConfig::HttpEdr {
                config: HttpEdrConfig {
                    endpoint,
                    auth_token: "secret".to_string(),
                    timeout_ms: 500,
                    retry: RetryConfig::default(),
                    circuit_breaker: CircuitBreakerConfig::default(),
                    dead_letter_path: "./dead-letter.jsonl".to_string(),
                },
            },
            None,
        )
        .unwrap();
        let request = ActionRequest {
            hunt_id: HuntId("hunt-edr-scan".to_string()),
            requested_by: AgentId("agent-1".to_string()),
            action: ResponseAction::TriggerEdrScan {
                host_id: "host-77".to_string(),
                scan_profile: "memory_quick".to_string(),
            },
            severity: Severity::Medium,
            evidence: serde_json::json!({"signal": "test"}),
        };
        let lease = CapabilityLease {
            capability_id: "lease-edr-scan".to_string(),
            expires_at_ms: 1_000,
            action: request.action.kind().to_string(),
            scope: Some("host-77".to_string()),
        };

        let receipt = executor
            .execute(&request, &lease, ExecutionMode::Enforced)
            .await
            .unwrap();

        assert_eq!(receipt.status, ResponseStatus::Executed);
        let payload = state.payload.lock().await.clone().unwrap();
        assert_eq!(payload["action"], "trigger_edr_scan");
        assert_eq!(payload["host_id"], "host-77");
        assert_eq!(payload["scan_profile"], "memory_quick");

        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[tokio::test]
    async fn webhook_config_dispatches_to_webhook_adapter() {
        let (url, state, shutdown_tx, handle) = spawn_server(StatusCode::OK).await;
        let executor = DispatchingExecutor::from_config(
            ResponseAdapterConfig::Webhook {
                config: WebhookConfig {
                    url,
                    timeout_ms: 500,
                    channel: Some("#soc".to_string()),
                    auth_token: Some("secret".to_string()),
                    retry: RetryConfig::default(),
                    circuit_breaker: CircuitBreakerConfig::default(),
                    dead_letter_path: "./dead-letter.jsonl".to_string(),
                },
            },
            None,
        )
        .unwrap();
        let request = ActionRequest {
            hunt_id: HuntId("hunt-webhook".to_string()),
            requested_by: AgentId("agent-1".to_string()),
            action: ResponseAction::Escalate {
                summary: "operator review required".to_string(),
                urgency: Severity::Critical,
            },
            severity: Severity::Critical,
            evidence: serde_json::json!({"signal": "test"}),
        };
        let lease = CapabilityLease {
            capability_id: "lease-webhook".to_string(),
            expires_at_ms: 1_000,
            action: request.action.kind().to_string(),
            scope: Some("global".to_string()),
        };

        let receipt = executor
            .execute(&request, &lease, ExecutionMode::Enforced)
            .await
            .unwrap();

        assert_eq!(receipt.status, ResponseStatus::Executed);
        assert_eq!(
            state.auth.lock().await.clone(),
            Some("Bearer secret".to_string())
        );
        let payload = state.payload.lock().await.clone().unwrap();
        assert_eq!(payload["channel"], "#soc");
        assert!(
            payload["text"]
                .as_str()
                .is_some_and(|text| text.contains("escalate"))
        );

        let _ = shutdown_tx.send(());
        handle.abort();
    }
}
