use crate::siem::SwarmFindingEnvelope;
use crate::{ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt, ResponseStatus};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use swarm_core::config::{SecretString, SiemForwardConfig};
use swarm_core::types::Severity;
use swarm_policy::{ActionRequest, CapabilityLease};
use swarm_whisker::DetectionFinding;

const BATCH_SCHEMA: &str = "swarm_finding_batch";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmFindingBatchEnvelope {
    pub schema: String,
    pub transport: String,
    pub findings: Vec<SwarmFindingEnvelope>,
}

#[derive(Clone)]
pub struct SplunkHecAdapter {
    endpoint: String,
    auth_token: SecretString,
    timeout_ms: u64,
    batch_max_events: usize,
    batch_max_bytes: usize,
    client: Client,
}

impl SplunkHecAdapter {
    pub fn new(config: &SiemForwardConfig) -> Option<Self> {
        let SiemForwardConfig::SplunkHec {
            endpoint,
            auth_token,
            timeout_ms,
            batch_max_events,
            batch_max_bytes,
            ..
        } = config
        else {
            return None;
        };
        Some(Self {
            endpoint: endpoint.clone(),
            auth_token: auth_token.clone(),
            timeout_ms: *timeout_ms,
            batch_max_events: *batch_max_events,
            batch_max_bytes: *batch_max_bytes,
            client: Client::new(),
        })
    }

    pub fn batch_limits(&self) -> (usize, usize) {
        (self.batch_max_events, self.batch_max_bytes)
    }

    pub fn build_batches(&self, findings: &[DetectionFinding]) -> Vec<SwarmFindingBatchEnvelope> {
        if findings.is_empty() {
            return Vec::new();
        }

        let mut batches = Vec::new();
        let mut current = Vec::new();
        let mut current_bytes = 0usize;
        for finding in findings {
            let envelope = SwarmFindingEnvelope::from(finding);
            let event = self.hec_event(&envelope);
            let encoded_len = serde_json::to_vec(&event)
                .map(|encoded| encoded.len() + 1)
                .unwrap_or_default();
            let hits_event_limit = current.len() >= self.batch_max_events;
            let hits_byte_limit = !current.is_empty()
                && current_bytes.saturating_add(encoded_len) > self.batch_max_bytes;
            if hits_event_limit || hits_byte_limit {
                batches.push(SwarmFindingBatchEnvelope {
                    schema: BATCH_SCHEMA.to_string(),
                    transport: "splunk_hec".to_string(),
                    findings: std::mem::take(&mut current),
                });
                current_bytes = 0;
            }
            current.push(envelope);
            current_bytes = current_bytes.saturating_add(encoded_len);
        }
        if !current.is_empty() {
            batches.push(SwarmFindingBatchEnvelope {
                schema: BATCH_SCHEMA.to_string(),
                transport: "splunk_hec".to_string(),
                findings: current,
            });
        }
        batches
    }

    fn receipt_id(&self, request: &ActionRequest, lease: &CapabilityLease) -> String {
        format!(
            "resp-splunk-hec:{}:{}",
            request.hunt_id.0, lease.capability_id
        )
    }

    fn findings_from_request(&self, request: &ActionRequest) -> Vec<SwarmFindingEnvelope> {
        if let Ok(batch) =
            serde_json::from_value::<SwarmFindingBatchEnvelope>(request.evidence.clone())
        {
            return batch.findings;
        }
        if let Ok(finding) =
            serde_json::from_value::<SwarmFindingEnvelope>(request.evidence.clone())
        {
            return vec![finding];
        }
        vec![SwarmFindingEnvelope {
            schema: "swarm_finding".to_string(),
            finding_id: request.hunt_id.0.clone(),
            event_id: request.hunt_id.0.clone(),
            strategy_id: "unknown".to_string(),
            threat_class: swarm_core::pheromone::ThreatClass::Custom("unknown".to_string()),
            severity: request.severity,
            confidence: 0.0,
            evidence: request.evidence.clone(),
        }]
    }

    fn hec_event(&self, finding: &SwarmFindingEnvelope) -> Value {
        let host = finding
            .evidence
            .pointer("/host_metadata/host_id")
            .and_then(Value::as_str)
            .or_else(|| finding.evidence.get("host_id").and_then(Value::as_str))
            .unwrap_or("unknown");
        let command_line = finding
            .evidence
            .get("command_line")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let process_name = finding
            .evidence
            .get("process_name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let file_path = finding
            .evidence
            .get("file_path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let source_ip = finding
            .evidence
            .get("source_ip_address")
            .and_then(Value::as_str)
            .or_else(|| finding.evidence.get("source_ip").and_then(Value::as_str))
            .unwrap_or_default();
        let user = finding
            .evidence
            .get("user")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let event_time = finding
            .evidence
            .pointer("/host_metadata/event_timestamp")
            .and_then(Value::as_i64)
            .map(|value| value as f64);
        let technique_ids = technique_ids(&finding.evidence);

        json!({
            "time": event_time,
            "host": host,
            "source": "swarm-team-six",
            "sourcetype": "swarm:finding",
            "event": {
                "vendor_product": "Swarm Team Six",
                "signature": finding.strategy_id,
                "signature_id": finding.finding_id,
                "severity": severity_label(finding.severity),
                "threat_class": json_label(&finding.threat_class),
                "confidence": finding.confidence,
                "event_id": finding.event_id,
                "finding_id": finding.finding_id,
                "dest": host,
                "src": source_ip,
                "user": user,
                "process": process_name,
                "command": command_line,
                "file_path": file_path,
                "attack_technique_ids": technique_ids,
                "raw_evidence": finding.evidence,
            }
        })
    }

    #[allow(clippy::result_large_err)]
    fn render_body(
        &self,
        findings: &[SwarmFindingEnvelope],
    ) -> Result<(String, usize), ResponseReceipt> {
        let mut body = String::new();
        for finding in findings {
            let encoded = serde_json::to_string(&self.hec_event(finding)).map_err(|error| {
                ResponseReceipt {
                    receipt_id: "resp-splunk-hec:serialization".to_string(),
                    action: "forward_finding".to_string(),
                    mode: ExecutionMode::Enforced,
                    status: ResponseStatus::Failed,
                    summary: format!("splunk hec serialization failed: {error}"),
                    details: json!({
                        "adapter": "splunk_hec",
                        "endpoint": self.endpoint.clone(),
                    }),
                    audit: Default::default(),
                }
            })?;
            body.push_str(&encoded);
            body.push('\n');
        }
        let payload_bytes = body.len();
        Ok((body, payload_bytes))
    }
}

impl std::fmt::Debug for SplunkHecAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SplunkHecAdapter")
            .field("endpoint", &self.endpoint)
            .field("timeout_ms", &self.timeout_ms)
            .field("batch_max_events", &self.batch_max_events)
            .field("batch_max_bytes", &self.batch_max_bytes)
            .finish()
    }
}

#[async_trait]
impl ResponseExecutor for SplunkHecAdapter {
    async fn execute(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        mode: ExecutionMode,
    ) -> Result<ResponseReceipt, ResponseError> {
        let findings = self.findings_from_request(request);
        let (body, payload_bytes) = match self.render_body(&findings) {
            Ok(rendered) => rendered,
            Err(mut receipt) => {
                receipt.receipt_id = self.receipt_id(request, lease);
                receipt.mode = mode;
                return Ok(receipt);
            }
        };
        let event_count = findings.len() as u64;

        if mode == ExecutionMode::DryRun {
            return Ok(ResponseReceipt {
                receipt_id: self.receipt_id(request, lease),
                action: request.action.kind().to_string(),
                mode,
                status: ResponseStatus::Simulated,
                summary: format!("dry run splunk hec forward of {event_count} finding(s)"),
                details: json!({
                    "adapter": "splunk_hec",
                    "transport": "splunk_hec",
                    "endpoint": self.endpoint.clone(),
                    "event_count": event_count,
                    "payload_bytes": payload_bytes,
                }),
                audit: Default::default(),
            });
        }

        let started = Instant::now();
        let result = self
            .client
            .post(&self.endpoint)
            .header(
                "Authorization",
                format!("Splunk {}", self.auth_token.expose_secret()),
            )
            .header("Content-Type", "application/json")
            .timeout(Duration::from_millis(self.timeout_ms))
            .body(body)
            .send()
            .await;
        let elapsed_ms = started.elapsed().as_millis() as u64;

        match result {
            Ok(response) => {
                let status_code = response.status();
                let response_body = response.text().await.unwrap_or_default();
                let success = status_code.is_success();
                Ok(ResponseReceipt {
                    receipt_id: self.receipt_id(request, lease),
                    action: request.action.kind().to_string(),
                    mode,
                    status: if success {
                        ResponseStatus::Executed
                    } else {
                        ResponseStatus::Failed
                    },
                    summary: if success {
                        format!(
                            "splunk hec forward completed with status {}",
                            status_code.as_u16()
                        )
                    } else {
                        format!(
                            "splunk hec forward failed with status {}",
                            status_code.as_u16()
                        )
                    },
                    details: json!({
                        "adapter": "splunk_hec",
                        "transport": "splunk_hec",
                        "endpoint": self.endpoint.clone(),
                        "status_code": status_code.as_u16(),
                        "response_body": response_body,
                        "elapsed_ms": elapsed_ms,
                        "event_count": event_count,
                        "payload_bytes": payload_bytes,
                    }),
                    audit: Default::default(),
                })
            }
            Err(error) if error.is_timeout() => Ok(ResponseReceipt {
                receipt_id: self.receipt_id(request, lease),
                action: request.action.kind().to_string(),
                mode,
                status: ResponseStatus::Timeout,
                summary: "splunk hec forward timed out".to_string(),
                details: json!({
                    "adapter": "splunk_hec",
                    "transport": "splunk_hec",
                    "endpoint": self.endpoint.clone(),
                    "elapsed_ms": elapsed_ms,
                    "event_count": event_count,
                    "payload_bytes": payload_bytes,
                }),
                audit: Default::default(),
            }),
            Err(error) => Ok(ResponseReceipt {
                receipt_id: self.receipt_id(request, lease),
                action: request.action.kind().to_string(),
                mode,
                status: ResponseStatus::Failed,
                summary: format!("splunk hec forward failed: {error}"),
                details: json!({
                    "adapter": "splunk_hec",
                    "transport": "splunk_hec",
                    "endpoint": self.endpoint.clone(),
                    "elapsed_ms": elapsed_ms,
                    "event_count": event_count,
                    "payload_bytes": payload_bytes,
                    "error": error.to_string(),
                }),
                audit: Default::default(),
            }),
        }
    }
}

fn json_label<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToString::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn severity_label(severity: Severity) -> String {
    json_label(&severity)
}

fn technique_ids(evidence: &Value) -> Vec<String> {
    if let Some(entries) = evidence.get("attack_techniques").and_then(Value::as_array) {
        let ids: Vec<String> = entries
            .iter()
            .filter_map(|entry| entry.get("id").and_then(Value::as_str))
            .map(ToString::to_string)
            .collect();
        if !ids.is_empty() {
            return ids;
        }
    }
    evidence
        .get("mitre_technique_id")
        .and_then(Value::as_str)
        .map(|id| vec![id.to_string()])
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{BATCH_SCHEMA, SplunkHecAdapter, SwarmFindingBatchEnvelope};
    use crate::siem::SwarmFindingEnvelope;
    use crate::{ExecutionMode, ResponseExecutor, ResponseStatus};
    use axum::extract::{Request, State};
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::routing::post;
    use axum::{Json, Router, body::to_bytes};
    use serde_json::{Value, json};
    use std::sync::Arc;
    use swarm_core::config::{CircuitBreakerConfig, RetryConfig, SiemForwardConfig};
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
    use swarm_policy::{ActionRequest, CapabilityLease};
    use swarm_whisker::DetectionFinding;
    use tokio::sync::{Mutex, oneshot};

    #[derive(Clone)]
    struct CaptureState {
        auth: Arc<Mutex<Option<String>>>,
        payloads: Arc<Mutex<Vec<Value>>>,
        status: StatusCode,
    }

    impl Default for CaptureState {
        fn default() -> Self {
            Self {
                auth: Arc::default(),
                payloads: Arc::default(),
                status: StatusCode::OK,
            }
        }
    }

    async fn handler(
        State(state): State<CaptureState>,
        headers: HeaderMap,
        request: Request,
    ) -> (StatusCode, Json<Value>) {
        *state.auth.lock().await = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        let body = to_bytes(request.into_body(), usize::MAX).await.unwrap();
        let rendered = String::from_utf8(body.to_vec()).unwrap();
        let payloads = rendered
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        *state.payloads.lock().await = payloads;
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
            payloads: Arc::default(),
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

    fn config(
        endpoint: String,
        batch_max_events: usize,
        batch_max_bytes: usize,
    ) -> SiemForwardConfig {
        SiemForwardConfig::SplunkHec {
            endpoint,
            auth_token: "splunk-secret".to_string().into(),
            timeout_ms: 500,
            batch_max_events,
            batch_max_bytes,
            retry: RetryConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            dead_letter_path: "./siem-dead-letter.jsonl".to_string(),
        }
    }

    fn sample_finding(id: &str) -> DetectionFinding {
        DetectionFinding {
            finding_id: id.to_string(),
            event_id: format!("evt-{id}"),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence: 0.95,
            evidence: json!({
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -enc AAA=",
                "host_metadata": {
                    "host_id": "host-1",
                    "event_timestamp": 1_700_000_000
                },
                "mitre_technique_id": "T1059.001",
            }),
            strategy_id: "suspicious_process_tree".to_string(),
        }
    }

    fn request_for_evidence(evidence: Value) -> (ActionRequest, CapabilityLease) {
        let request = ActionRequest {
            hunt_id: HuntId("hunt-siem".to_string()),
            requested_by: AgentId("agent-1".to_string()),
            action: ResponseAction::Escalate {
                summary: "forward".to_string(),
                urgency: Severity::High,
            },
            severity: Severity::High,
            evidence,
        };
        let lease = CapabilityLease {
            capability_id: "lease-siem".to_string(),
            expires_at_ms: 1_000,
            action: request.action.kind().to_string(),
            scope: Some("soc".to_string()),
        };
        (request, lease)
    }

    #[tokio::test]
    async fn splunk_hec_posts_cim_aligned_payload() {
        let (endpoint, state, shutdown_tx, handle) = spawn_server(StatusCode::OK).await;
        let adapter = SplunkHecAdapter::new(&config(endpoint, 32, 131_072)).unwrap();
        let envelope = SwarmFindingEnvelope::from(&sample_finding("finding-1"));
        let (request, lease) = request_for_evidence(json!(envelope));

        let receipt = adapter
            .execute(&request, &lease, ExecutionMode::Enforced)
            .await
            .unwrap();

        assert_eq!(receipt.status, ResponseStatus::Executed);
        assert_eq!(
            state.auth.lock().await.clone(),
            Some("Splunk splunk-secret".to_string())
        );
        let payloads = state.payloads.lock().await.clone();
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0]["event"]["vendor_product"], "Swarm Team Six");
        assert_eq!(payloads[0]["event"]["signature"], "suspicious_process_tree");
        assert_eq!(payloads[0]["event"]["dest"], "host-1");
        assert_eq!(payloads[0]["event"]["attack_technique_ids"][0], "T1059.001");

        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[tokio::test]
    async fn splunk_hec_executes_batched_findings_in_one_request() {
        let (endpoint, state, shutdown_tx, handle) = spawn_server(StatusCode::OK).await;
        let adapter = SplunkHecAdapter::new(&config(endpoint, 32, 131_072)).unwrap();
        let batch = SwarmFindingBatchEnvelope {
            schema: BATCH_SCHEMA.to_string(),
            transport: "splunk_hec".to_string(),
            findings: vec![
                SwarmFindingEnvelope::from(&sample_finding("finding-1")),
                SwarmFindingEnvelope::from(&sample_finding("finding-2")),
            ],
        };
        let (request, lease) = request_for_evidence(json!(batch));

        let receipt = adapter
            .execute(&request, &lease, ExecutionMode::Enforced)
            .await
            .unwrap();

        assert_eq!(receipt.status, ResponseStatus::Executed);
        assert_eq!(receipt.details["event_count"], 2);
        assert!(receipt.details["payload_bytes"].as_u64().unwrap() > 0);
        assert_eq!(state.payloads.lock().await.len(), 2);

        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[test]
    fn build_batches_splits_on_event_limit() {
        let adapter = SplunkHecAdapter::new(&config(
            "http://127.0.0.1:8088/services/collector/event".to_string(),
            2,
            131_072,
        ))
        .unwrap();
        let findings = vec![
            sample_finding("finding-1"),
            sample_finding("finding-2"),
            sample_finding("finding-3"),
        ];

        let batches = adapter.build_batches(&findings);

        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].findings.len(), 2);
        assert_eq!(batches[1].findings.len(), 1);
    }
}
