use crate::config::SiemForwardConfig;
use crate::dead_letter::DeadLetterJournal;
use crate::resilience::ResilientExecutor;
use crate::{ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt, ResponseStatus};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_policy::{ActionRequest, CapabilityLease};
use swarm_whisker::DetectionFinding;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmFindingEnvelope {
    pub schema: String,
    pub finding_id: String,
    pub event_id: String,
    pub strategy_id: String,
    pub threat_class: ThreatClass,
    pub severity: Severity,
    pub confidence: f64,
    pub evidence: Value,
}

impl From<&DetectionFinding> for SwarmFindingEnvelope {
    fn from(finding: &DetectionFinding) -> Self {
        Self {
            schema: "swarm_finding".to_string(),
            finding_id: finding.finding_id.clone(),
            event_id: finding.event_id.clone(),
            strategy_id: finding.strategy_id.clone(),
            threat_class: finding.threat_class.clone(),
            severity: finding.severity,
            confidence: finding.confidence,
            evidence: finding.evidence.clone(),
        }
    }
}

#[derive(Clone)]
pub struct SiemForwardAdapter {
    config: SiemForwardConfig,
    client: Client,
}

impl SiemForwardAdapter {
    pub fn new(config: SiemForwardConfig) -> Self {
        Self {
            config,
            client: Client::new(),
        }
    }

    fn receipt_id(&self, request: &ActionRequest, lease: &CapabilityLease) -> String {
        format!("resp-siem:{}:{}", request.hunt_id.0, lease.capability_id)
    }

    fn timeout_ms(&self) -> u64 {
        match &self.config {
            SiemForwardConfig::SplunkHec { timeout_ms, .. }
            | SiemForwardConfig::ElkBulk { timeout_ms, .. }
            | SiemForwardConfig::Chronicle { timeout_ms, .. } => *timeout_ms,
        }
    }

    fn endpoint(&self) -> &str {
        match &self.config {
            SiemForwardConfig::SplunkHec { endpoint, .. }
            | SiemForwardConfig::ElkBulk { endpoint, .. }
            | SiemForwardConfig::Chronicle { endpoint, .. } => endpoint,
        }
    }

    fn transport_kind(&self) -> &'static str {
        match &self.config {
            SiemForwardConfig::SplunkHec { .. } => "splunk_hec",
            SiemForwardConfig::ElkBulk { .. } => "elk_bulk",
            SiemForwardConfig::Chronicle { .. } => "chronicle",
        }
    }

    fn canonical_finding(&self, request: &ActionRequest) -> SwarmFindingEnvelope {
        serde_json::from_value(request.evidence.clone()).unwrap_or_else(|_| SwarmFindingEnvelope {
            schema: "swarm_finding".to_string(),
            finding_id: request.hunt_id.0.clone(),
            event_id: request.hunt_id.0.clone(),
            strategy_id: "unknown".to_string(),
            threat_class: ThreatClass::Custom("unknown".to_string()),
            severity: request.severity,
            confidence: 0.0,
            evidence: request.evidence.clone(),
        })
    }

    fn transport_payload(&self, finding: &SwarmFindingEnvelope) -> Value {
        match &self.config {
            SiemForwardConfig::SplunkHec { .. } => json!({
                "event": finding,
                "source": "swarm-team-six",
                "sourcetype": "swarm_finding",
            }),
            SiemForwardConfig::ElkBulk { index, .. } => json!({
                "index": index,
                "finding": finding,
            }),
            SiemForwardConfig::Chronicle { customer_id, .. } => json!({
                "customer_id": customer_id,
                "product_name": "swarm-team-six",
                "finding": finding,
            }),
        }
    }
}

impl std::fmt::Debug for SiemForwardAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SiemForwardAdapter")
            .field("transport", &self.transport_kind())
            .field("endpoint", &self.endpoint())
            .field("timeout_ms", &self.timeout_ms())
            .finish()
    }
}

#[async_trait]
impl ResponseExecutor for SiemForwardAdapter {
    async fn execute(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        mode: ExecutionMode,
    ) -> Result<ResponseReceipt, ResponseError> {
        let receipt_id = self.receipt_id(request, lease);
        let finding = self.canonical_finding(request);
        let payload = self.transport_payload(&finding);

        if mode == ExecutionMode::DryRun {
            return Ok(ResponseReceipt {
                receipt_id,
                action: "forward_finding".to_string(),
                mode,
                status: ResponseStatus::Simulated,
                summary: format!("dry run {} finding forward", self.transport_kind()),
                details: json!({
                    "adapter": "siem_forward",
                    "transport": self.transport_kind(),
                    "endpoint": self.endpoint(),
                    "payload": payload,
                }),
                audit: Default::default(),
            });
        }

        let elapsed_ms;
        let response = match &self.config {
            SiemForwardConfig::SplunkHec {
                endpoint,
                auth_token,
                ..
            } => {
                let started = std::time::Instant::now();
                let result = self
                    .client
                    .post(endpoint)
                    .header("Authorization", format!("Splunk {auth_token}"))
                    .timeout(Duration::from_millis(self.timeout_ms()))
                    .json(&payload)
                    .send()
                    .await;
                elapsed_ms = started.elapsed().as_millis() as u64;
                result
            }
            SiemForwardConfig::ElkBulk {
                endpoint,
                auth_token,
                index,
                ..
            } => {
                let ndjson = format!(
                    "{{\"index\":{{\"_index\":\"{index}\"}}}}\n{}\n",
                    serde_json::to_string(&finding).unwrap_or_else(|_| "{}".to_string())
                );
                let started = std::time::Instant::now();
                let mut request = self
                    .client
                    .post(endpoint)
                    .header("content-type", "application/x-ndjson")
                    .timeout(Duration::from_millis(self.timeout_ms()))
                    .body(ndjson);
                if let Some(auth_token) = auth_token {
                    request = request.bearer_auth(auth_token);
                }
                let result = request.send().await;
                elapsed_ms = started.elapsed().as_millis() as u64;
                result
            }
            SiemForwardConfig::Chronicle {
                endpoint,
                auth_token,
                ..
            } => {
                let started = std::time::Instant::now();
                let result = self
                    .client
                    .post(endpoint)
                    .bearer_auth(auth_token)
                    .timeout(Duration::from_millis(self.timeout_ms()))
                    .json(&payload)
                    .send()
                    .await;
                elapsed_ms = started.elapsed().as_millis() as u64;
                result
            }
        };

        match response {
            Ok(response) => {
                let status_code = response.status();
                let response_body = match response.text().await {
                    Ok(body) => body,
                    Err(error) => format!("<failed to read response body: {error}>"),
                };
                let success = status_code.is_success();
                Ok(ResponseReceipt {
                    receipt_id,
                    action: "forward_finding".to_string(),
                    mode,
                    status: if success {
                        ResponseStatus::Executed
                    } else {
                        ResponseStatus::Failed
                    },
                    summary: if success {
                        format!(
                            "{} finding forward completed with status {}",
                            self.transport_kind(),
                            status_code.as_u16()
                        )
                    } else {
                        format!(
                            "{} finding forward failed with status {}",
                            self.transport_kind(),
                            status_code.as_u16()
                        )
                    },
                    details: json!({
                        "adapter": "siem_forward",
                        "transport": self.transport_kind(),
                        "endpoint": self.endpoint(),
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
                action: "forward_finding".to_string(),
                mode,
                status: ResponseStatus::Timeout,
                summary: format!("{} finding forward timed out", self.transport_kind()),
                details: json!({
                    "adapter": "siem_forward",
                    "transport": self.transport_kind(),
                    "endpoint": self.endpoint(),
                    "payload": payload,
                    "elapsed_ms": elapsed_ms,
                }),
                audit: Default::default(),
            }),
            Err(error) => Ok(ResponseReceipt {
                receipt_id,
                action: "forward_finding".to_string(),
                mode,
                status: ResponseStatus::Failed,
                summary: format!("{} finding forward failed: {error}", self.transport_kind()),
                details: json!({
                    "adapter": "siem_forward",
                    "transport": self.transport_kind(),
                    "endpoint": self.endpoint(),
                    "payload": payload,
                    "elapsed_ms": elapsed_ms,
                    "error": error.to_string(),
                }),
                audit: Default::default(),
            }),
        }
    }
}

#[derive(Clone)]
pub struct SiemFindingForwarder {
    executor: Arc<ResilientExecutor<SiemForwardAdapter>>,
}

impl SiemFindingForwarder {
    pub fn new(config: SiemForwardConfig) -> Self {
        let (retry, circuit_breaker, dead_letter_path) = match &config {
            SiemForwardConfig::SplunkHec {
                retry,
                circuit_breaker,
                dead_letter_path,
                ..
            }
            | SiemForwardConfig::ElkBulk {
                retry,
                circuit_breaker,
                dead_letter_path,
                ..
            }
            | SiemForwardConfig::Chronicle {
                retry,
                circuit_breaker,
                dead_letter_path,
                ..
            } => (
                retry.clone(),
                circuit_breaker.clone(),
                dead_letter_path.clone(),
            ),
        };
        let adapter = SiemForwardAdapter::new(config);
        let journal = Arc::new(DeadLetterJournal::from_path(dead_letter_path, None));
        Self {
            executor: Arc::new(ResilientExecutor::new(
                adapter,
                "siem_forward",
                retry,
                circuit_breaker,
                Some(journal),
            )),
        }
    }

    pub async fn forward_finding(
        &self,
        finding: &DetectionFinding,
    ) -> Result<ResponseReceipt, ResponseError> {
        let request = ActionRequest {
            hunt_id: HuntId(finding.event_id.clone()),
            requested_by: AgentId("siem-forwarder".to_string()),
            action: ResponseAction::Escalate {
                summary: format!("forward {}", finding.finding_id),
                urgency: finding.severity,
            },
            severity: finding.severity,
            evidence: json!(SwarmFindingEnvelope::from(finding)),
        };
        let lease = CapabilityLease {
            capability_id: format!("siem-forward:{}", finding.finding_id),
            expires_at_ms: now_ms() + 60_000,
            action: request.action.kind().to_string(),
            scope: Some(finding.strategy_id.clone()),
        };
        self.executor
            .execute(&request, &lease, ExecutionMode::Enforced)
            .await
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{SiemFindingForwarder, SiemForwardAdapter, SwarmFindingEnvelope};
    use crate::config::{CircuitBreakerConfig, RetryConfig, SiemForwardConfig};
    use crate::{ExecutionMode, ResponseExecutor, ResponseStatus};
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::{Value, json};
    use std::sync::Arc;
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
    use swarm_policy::{ActionRequest, CapabilityLease};
    use swarm_whisker::DetectionFinding;
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

    fn sample_finding() -> DetectionFinding {
        DetectionFinding {
            finding_id: "finding-1".to_string(),
            event_id: "event-1".to_string(),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence: 0.91,
            evidence: json!({"host_id": "host-1", "command_line": "powershell.exe -enc AAA="}),
            strategy_id: "suspicious_process_tree".to_string(),
        }
    }

    #[tokio::test]
    async fn splunk_adapter_posts_canonical_payload() {
        let (endpoint, state, shutdown_tx, handle) = spawn_server(StatusCode::OK).await;
        let adapter = SiemForwardAdapter::new(SiemForwardConfig::SplunkHec {
            endpoint,
            auth_token: "splunk-secret".to_string(),
            timeout_ms: 500,
            retry: RetryConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            dead_letter_path: "./siem-dead-letter.jsonl".to_string(),
        });
        let finding = sample_finding();
        let request = ActionRequest {
            hunt_id: HuntId(finding.event_id.clone()),
            requested_by: AgentId("agent-1".to_string()),
            action: ResponseAction::Escalate {
                summary: "forward".to_string(),
                urgency: finding.severity,
            },
            severity: finding.severity,
            evidence: json!(SwarmFindingEnvelope::from(&finding)),
        };
        let lease = CapabilityLease {
            capability_id: "lease-1".to_string(),
            expires_at_ms: 1_000,
            action: request.action.kind().to_string(),
            scope: Some("soc".to_string()),
        };

        let receipt = adapter
            .execute(&request, &lease, ExecutionMode::Enforced)
            .await
            .unwrap();

        assert_eq!(receipt.status, ResponseStatus::Executed);
        assert_eq!(
            state.auth.lock().await.clone(),
            Some("Splunk splunk-secret".to_string())
        );
        let payload = state.payload.lock().await.clone().unwrap();
        assert_eq!(payload["event"]["schema"], "swarm_finding");
        assert_eq!(payload["event"]["strategy_id"], "suspicious_process_tree");

        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[tokio::test]
    async fn forwarder_wraps_finding_for_runtime_delivery() {
        let (endpoint, state, shutdown_tx, handle) = spawn_server(StatusCode::OK).await;
        let forwarder = SiemFindingForwarder::new(SiemForwardConfig::SplunkHec {
            endpoint,
            auth_token: "splunk-secret".to_string(),
            timeout_ms: 500,
            retry: RetryConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            dead_letter_path: "./siem-dead-letter.jsonl".to_string(),
        });

        let receipt = forwarder.forward_finding(&sample_finding()).await.unwrap();

        assert_eq!(receipt.status, ResponseStatus::Executed);
        let payload = state.payload.lock().await.clone().unwrap();
        assert_eq!(payload["event"]["finding_id"], "finding-1");

        let _ = shutdown_tx.send(());
        handle.abort();
    }
}
