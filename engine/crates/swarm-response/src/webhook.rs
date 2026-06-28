use crate::config::WebhookConfig;
use crate::{ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt, ResponseStatus};
use async_trait::async_trait;
use reqwest::Client;
use reqwest::redirect::Policy;
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use swarm_core::types::{ResponseAction, Severity};
use swarm_policy::{ActionRequest, CapabilityLease};

#[derive(Clone)]
pub struct WebhookAdapter {
    config: WebhookConfig,
    client: Client,
}

impl WebhookAdapter {
    pub fn new(config: WebhookConfig) -> Result<Self, ResponseError> {
        if config.url.trim().is_empty() {
            return Err(ResponseError::unavailable(
                "webhook",
                ExecutionMode::Enforced,
                "webhook url must not be empty",
            ));
        }

        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .redirect(Policy::none())
            .build()
            .map_err(|error| {
                ResponseError::unavailable(
                    "webhook",
                    ExecutionMode::Enforced,
                    format!("failed to build reqwest client: {error}"),
                )
            })?;

        Ok(Self { config, client })
    }

    fn receipt_id(&self, request: &ActionRequest, lease: &CapabilityLease) -> String {
        format!("resp-webhook:{}:{}", request.hunt_id.0, lease.capability_id)
    }

    fn severity_label(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        }
    }

    fn severity_color(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "danger",
            Severity::High => "warning",
            Severity::Medium => "#D4AC0D",
            Severity::Low => "#439FE0",
        }
    }

    fn action_summary(action: &ResponseAction) -> String {
        match action {
            ResponseAction::DeployDecoy {
                decoy_type,
                target_zone,
            } => format!("deploy {decoy_type} decoy in {target_zone}"),
            ResponseAction::Escalate { summary, .. } => summary.clone(),
            ResponseAction::BlockEgress { target } => format!("block egress to {target}"),
            ResponseAction::IsolateHost { host_id } => format!("isolate host {host_id}"),
            ResponseAction::RevokeCredential { credential_id } => {
                format!("revoke credential {credential_id}")
            }
            ResponseAction::SinkholeDns { domain } => format!("sinkhole DNS for {domain}"),
            ResponseAction::TerminateUserSession {
                host_id,
                session_id,
            } => format!("terminate session {session_id} on {host_id}"),
            ResponseAction::TriggerEdrScan {
                host_id,
                scan_profile,
            } => format!("run {scan_profile} EDR scan on {host_id}"),
            ResponseAction::InjectFirewallRule {
                host_id, rule_name, ..
            } => format!("inject firewall rule {rule_name} on {host_id}"),
            ResponseAction::QuarantineFile { host_id, file_path } => {
                format!("quarantine file {file_path} on {host_id}")
            }
            ResponseAction::KillProcess {
                host_id,
                process_name,
            } => format!("kill process {process_name} on {host_id}"),
            ResponseAction::SuspendProcess {
                host_id,
                process_name,
            } => format!("suspend process {process_name} on {host_id}"),
            ResponseAction::DisableUserAccount { user_id } => {
                format!("disable user account {user_id}")
            }
            ResponseAction::ForcePasswordReset { user_id } => {
                format!("force password reset for {user_id}")
            }
            ResponseAction::RemoveScheduledTask { host_id, task_name } => {
                format!("remove scheduled task {task_name} on {host_id}")
            }
        }
    }

    fn payload(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
    ) -> Result<Value, Box<ResponseReceipt>> {
        if !matches!(
            request.action,
            ResponseAction::DeployDecoy { .. } | ResponseAction::Escalate { .. }
        ) {
            return Err(Box::new(ResponseReceipt {
                receipt_id: self.receipt_id(request, lease),
                action: request.action.kind().to_string(),
                mode: ExecutionMode::Enforced,
                status: ResponseStatus::Failed,
                summary: format!(
                    "webhook adapter does not support action `{}`",
                    request.action.kind()
                ),
                details: json!({
                    "adapter": "webhook",
                    "url": self.config.url,
                    "lease_id": lease.capability_id,
                }),
                audit: Default::default(),
            }));
        }

        let mut payload = json!({
            "text": format!(
                "[{}] {}: {}",
                Self::severity_label(request.severity),
                request.action.kind(),
                Self::action_summary(&request.action)
            ),
            "attachments": [{
                "color": Self::severity_color(request.severity),
                "fields": [
                    {"title": "Hunt ID", "value": request.hunt_id.0, "short": true},
                    {"title": "Action", "value": request.action.kind(), "short": true},
                    {"title": "Severity", "value": Self::severity_label(request.severity), "short": true},
                    {"title": "Scope", "value": lease.scope.clone().unwrap_or_else(|| "global".to_string()), "short": true}
                ]
            }]
        });

        if let Some(channel) = &self.config.channel
            && let Some(object) = payload.as_object_mut()
        {
            object.insert("channel".to_string(), json!(channel));
        }

        Ok(payload)
    }
}

impl std::fmt::Debug for WebhookAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookAdapter")
            .field("url", &self.config.url)
            .field("timeout_ms", &self.config.timeout_ms)
            .field("channel", &self.config.channel)
            .finish()
    }
}

#[async_trait]
impl ResponseExecutor for WebhookAdapter {
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
                summary: format!("dry run webhook {}", request.action.kind()),
                details: json!({
                    "adapter": "webhook",
                    "url": self.config.url,
                    "payload": payload,
                }),
                audit: Default::default(),
            });
        }

        let started = Instant::now();
        let mut outbound_request = self.client.post(&self.config.url).json(&payload);
        if let Some(auth_token) = &self.config.auth_token {
            outbound_request = outbound_request.bearer_auth(auth_token);
        }
        let result = outbound_request.send().await;
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
                            "webhook {} completed with status {}",
                            request.action.kind(),
                            status_code.as_u16()
                        )
                    } else {
                        format!(
                            "webhook {} failed with status {}",
                            request.action.kind(),
                            status_code.as_u16()
                        )
                    },
                    details: json!({
                        "adapter": "webhook",
                        "url": self.config.url,
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
                summary: format!("webhook {} timed out", request.action.kind()),
                details: json!({
                    "adapter": "webhook",
                    "url": self.config.url,
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
                summary: format!("webhook {} failed: {error}", request.action.kind()),
                details: json!({
                    "adapter": "webhook",
                    "url": self.config.url,
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
    use super::WebhookAdapter;
    use crate::config::{CircuitBreakerConfig, RetryConfig, WebhookConfig};
    use crate::{ExecutionMode, ResponseExecutor, ResponseStatus};
    use axum::extract::State;
    use axum::http::StatusCode;
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
        payload: Arc<Mutex<Option<Value>>>,
        delay: Duration,
        status: StatusCode,
    }

    async fn handler(
        State(state): State<CaptureState>,
        Json(payload): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
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
            hunt_id: HuntId("hunt-webhook".to_string()),
            requested_by: AgentId("agent-1".to_string()),
            action: ResponseAction::Escalate {
                summary: "operator review required".to_string(),
                urgency: Severity::Critical,
            },
            severity: Severity::Critical,
            evidence: json!({"signal": "pager"}),
        }
    }

    fn sample_lease() -> CapabilityLease {
        CapabilityLease {
            capability_id: "lease-webhook".to_string(),
            expires_at_ms: 1_000,
            action: "escalate".to_string(),
            scope: Some("global".to_string()),
        }
    }

    #[tokio::test]
    async fn webhook_posts_slack_compatible_payload() {
        let (url, state, shutdown_tx, handle) =
            spawn_server(Duration::from_millis(0), StatusCode::OK).await;
        let adapter = WebhookAdapter::new(WebhookConfig {
            url,
            timeout_ms: 500,
            channel: Some("#soc".to_string()),
            auth_token: None,
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

        let payload = state.payload.lock().await.clone().unwrap();
        assert_eq!(payload["channel"], "#soc");
        assert_eq!(payload["attachments"][0]["fields"][0]["title"], "Hunt ID");
        assert!(
            payload["text"]
                .as_str()
                .is_some_and(|text| text.contains("escalate"))
        );

        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[tokio::test]
    async fn webhook_non_success_status_returns_failed_receipt() {
        let (url, _state, shutdown_tx, handle) =
            spawn_server(Duration::from_millis(0), StatusCode::INTERNAL_SERVER_ERROR).await;
        let adapter = WebhookAdapter::new(WebhookConfig {
            url,
            timeout_ms: 500,
            channel: None,
            auth_token: None,
            retry: RetryConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            dead_letter_path: "./dead-letter.jsonl".to_string(),
        })
        .unwrap();

        let receipt = adapter
            .execute(&sample_request(), &sample_lease(), ExecutionMode::Enforced)
            .await
            .unwrap();
        assert_eq!(receipt.status, ResponseStatus::Failed);

        let _ = shutdown_tx.send(());
        handle.abort();
    }
}
