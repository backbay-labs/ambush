use crate::config::CrowdStrikeRtrConfig;
use crate::{ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt, ResponseStatus};
use async_trait::async_trait;
use reqwest::Client;
use reqwest::redirect::Policy;
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use swarm_core::types::ResponseAction;
use swarm_policy::{ActionRequest, CapabilityLease};

#[derive(Clone)]
pub struct CrowdStrikeRtrAdapter {
    config: CrowdStrikeRtrConfig,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct SessionResponseEnvelope {
    #[serde(default)]
    resources: Vec<SessionResource>,
}

#[derive(Debug, Deserialize)]
struct SessionResource {
    session_id: String,
}

impl CrowdStrikeRtrAdapter {
    pub fn new(config: CrowdStrikeRtrConfig) -> Result<Self, ResponseError> {
        if config.base_url.trim().is_empty() {
            return Err(ResponseError::unavailable(
                "crowdstrike_rtr",
                ExecutionMode::Enforced,
                "crowdstrike rtr base_url must not be empty",
            ));
        }

        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .redirect(Policy::none())
            .build()
            .map_err(|error| {
                ResponseError::unavailable(
                    "crowdstrike_rtr",
                    ExecutionMode::Enforced,
                    format!("failed to build reqwest client: {error}"),
                )
            })?;

        Ok(Self { config, client })
    }

    fn receipt_id(&self, request: &ActionRequest, lease: &CapabilityLease) -> String {
        format!(
            "resp-crowdstrike-rtr:{}:{}",
            request.hunt_id.0, lease.capability_id
        )
    }

    fn endpoint(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.config.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    fn unsupported_receipt(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        mode: ExecutionMode,
    ) -> ResponseReceipt {
        ResponseReceipt {
            receipt_id: self.receipt_id(request, lease),
            action: request.action.kind().to_string(),
            mode,
            status: ResponseStatus::Failed,
            summary: format!(
                "crowdstrike rtr adapter does not support action `{}`",
                request.action.kind()
            ),
            details: json!({
                "adapter": "crowdstrike_rtr",
                "base_url": self.config.base_url.clone(),
                "lease_id": lease.capability_id.clone(),
            }),
            audit: Default::default(),
        }
    }

    fn dry_run_receipt(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        payload: Value,
        operation: &str,
    ) -> ResponseReceipt {
        ResponseReceipt {
            receipt_id: self.receipt_id(request, lease),
            action: request.action.kind().to_string(),
            mode: ExecutionMode::DryRun,
            status: ResponseStatus::Simulated,
            summary: format!("dry run crowdstrike rtr {}", request.action.kind()),
            details: json!({
                "adapter": "crowdstrike_rtr",
                "base_url": self.config.base_url.clone(),
                "operation": operation,
                "payload": payload,
                "authorization_header": "Bearer <redacted>",
            }),
            audit: Default::default(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn failed_receipt(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        mode: ExecutionMode,
        operation: &str,
        elapsed_ms: u64,
        status_code: Option<u16>,
        response_body: Option<String>,
        error: Option<String>,
        timeout: bool,
        payload: Value,
    ) -> ResponseReceipt {
        let status = if timeout {
            ResponseStatus::Timeout
        } else {
            ResponseStatus::Failed
        };
        let summary = if timeout {
            format!("crowdstrike rtr {} timed out", request.action.kind())
        } else if let Some(status_code) = status_code {
            format!(
                "crowdstrike rtr {} failed with status {}",
                request.action.kind(),
                status_code
            )
        } else if let Some(error) = &error {
            format!("crowdstrike rtr {} failed: {error}", request.action.kind())
        } else {
            format!("crowdstrike rtr {} failed", request.action.kind())
        };
        ResponseReceipt {
            receipt_id: self.receipt_id(request, lease),
            action: request.action.kind().to_string(),
            mode,
            status,
            summary,
            details: json!({
                "adapter": "crowdstrike_rtr",
                "base_url": self.config.base_url.clone(),
                "operation": operation,
                "payload": payload,
                "status_code": status_code,
                "response_body": response_body,
                "elapsed_ms": elapsed_ms,
                "error": error,
            }),
            audit: Default::default(),
        }
    }

    async fn fetch_access_token(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        payload: &Value,
        mode: ExecutionMode,
    ) -> Result<String, Box<ResponseReceipt>> {
        let started = Instant::now();
        let response = self
            .client
            .post(self.endpoint("/oauth2/token"))
            .form(&[
                ("client_id", self.config.client_id.expose_secret()),
                ("client_secret", self.config.client_secret.expose_secret()),
            ])
            .send()
            .await;
        let elapsed_ms = started.elapsed().as_millis() as u64;

        match response {
            Ok(response) => {
                let status_code = response.status();
                let body = response.text().await.unwrap_or_default();
                if !status_code.is_success() {
                    return Err(Box::new(self.failed_receipt(
                        request,
                        lease,
                        mode,
                        "oauth2_token",
                        elapsed_ms,
                        Some(status_code.as_u16()),
                        Some(body),
                        None,
                        false,
                        payload.clone(),
                    )));
                }
                let parsed: OAuthTokenResponse = serde_json::from_str(&body).map_err(|error| {
                    Box::new(self.failed_receipt(
                        request,
                        lease,
                        mode,
                        "oauth2_token",
                        elapsed_ms,
                        Some(status_code.as_u16()),
                        Some(body.clone()),
                        Some(format!("failed to parse oauth token response: {error}")),
                        false,
                        payload.clone(),
                    ))
                })?;
                Ok(parsed.access_token)
            }
            Err(error) if error.is_timeout() => Err(Box::new(self.failed_receipt(
                request,
                lease,
                mode,
                "oauth2_token",
                elapsed_ms,
                None,
                None,
                None,
                true,
                payload.clone(),
            ))),
            Err(error) => Err(Box::new(self.failed_receipt(
                request,
                lease,
                mode,
                "oauth2_token",
                elapsed_ms,
                None,
                None,
                Some(error.to_string()),
                false,
                payload.clone(),
            ))),
        }
    }

    async fn create_session(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        token: &str,
        host_id: &str,
        payload: &Value,
        mode: ExecutionMode,
    ) -> Result<String, Box<ResponseReceipt>> {
        let request_body = json!({
            "device_id": host_id,
            "queue_offline": false,
            "origin": "swarm-team-six",
        });
        let started = Instant::now();
        let response = self
            .client
            .post(self.endpoint("/real-time-response/entities/sessions/v1"))
            .bearer_auth(token)
            .json(&request_body)
            .send()
            .await;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        match response {
            Ok(response) => {
                let status_code = response.status();
                let body = response.text().await.unwrap_or_default();
                if !status_code.is_success() {
                    return Err(Box::new(self.failed_receipt(
                        request,
                        lease,
                        mode,
                        "create_session",
                        elapsed_ms,
                        Some(status_code.as_u16()),
                        Some(body),
                        None,
                        false,
                        payload.clone(),
                    )));
                }
                let parsed: SessionResponseEnvelope =
                    serde_json::from_str(&body).map_err(|error| {
                        Box::new(self.failed_receipt(
                            request,
                            lease,
                            mode,
                            "create_session",
                            elapsed_ms,
                            Some(status_code.as_u16()),
                            Some(body.clone()),
                            Some(format!("failed to parse session response: {error}")),
                            false,
                            payload.clone(),
                        ))
                    })?;
                parsed
                    .resources
                    .first()
                    .map(|resource| resource.session_id.clone())
                    .ok_or_else(|| {
                        Box::new(self.failed_receipt(
                            request,
                            lease,
                            mode,
                            "create_session",
                            elapsed_ms,
                            Some(status_code.as_u16()),
                            Some(body),
                            Some("session response did not include a session_id".to_string()),
                            false,
                            payload.clone(),
                        ))
                    })
            }
            Err(error) if error.is_timeout() => Err(Box::new(self.failed_receipt(
                request,
                lease,
                mode,
                "create_session",
                elapsed_ms,
                None,
                None,
                None,
                true,
                payload.clone(),
            ))),
            Err(error) => Err(Box::new(self.failed_receipt(
                request,
                lease,
                mode,
                "create_session",
                elapsed_ms,
                None,
                None,
                Some(error.to_string()),
                false,
                payload.clone(),
            ))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_json_call(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        token: &str,
        operation: &str,
        endpoint: String,
        payload: Value,
        mode: ExecutionMode,
    ) -> Result<ResponseReceipt, Box<ResponseReceipt>> {
        let started = Instant::now();
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(token)
            .json(&payload)
            .send()
            .await;
        let elapsed_ms = started.elapsed().as_millis() as u64;

        match response {
            Ok(response) => {
                let status_code = response.status();
                let body = response.text().await.unwrap_or_default();
                if !status_code.is_success() {
                    return Err(Box::new(self.failed_receipt(
                        request,
                        lease,
                        mode,
                        operation,
                        elapsed_ms,
                        Some(status_code.as_u16()),
                        Some(body),
                        None,
                        false,
                        payload,
                    )));
                }
                Ok(ResponseReceipt {
                    receipt_id: self.receipt_id(request, lease),
                    action: request.action.kind().to_string(),
                    mode,
                    status: ResponseStatus::Executed,
                    summary: format!(
                        "crowdstrike rtr {} completed with status {}",
                        request.action.kind(),
                        status_code.as_u16()
                    ),
                    details: json!({
                        "adapter": "crowdstrike_rtr",
                        "base_url": self.config.base_url.clone(),
                        "operation": operation,
                        "payload": payload,
                        "status_code": status_code.as_u16(),
                        "response_body": body,
                        "elapsed_ms": elapsed_ms,
                    }),
                    audit: Default::default(),
                })
            }
            Err(error) if error.is_timeout() => Err(Box::new(self.failed_receipt(
                request, lease, mode, operation, elapsed_ms, None, None, None, true, payload,
            ))),
            Err(error) => Err(Box::new(self.failed_receipt(
                request,
                lease,
                mode,
                operation,
                elapsed_ms,
                None,
                None,
                Some(error.to_string()),
                false,
                payload,
            ))),
        }
    }
}

impl std::fmt::Debug for CrowdStrikeRtrAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrowdStrikeRtrAdapter")
            .field("base_url", &self.config.base_url)
            .field("timeout_ms", &self.config.timeout_ms)
            .finish()
    }
}

#[async_trait]
impl ResponseExecutor for CrowdStrikeRtrAdapter {
    async fn execute(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        mode: ExecutionMode,
    ) -> Result<ResponseReceipt, ResponseError> {
        let (operation, payload, session_host, command) = match &request.action {
            ResponseAction::IsolateHost { host_id } => {
                ("host_isolation", json!({ "ids": [host_id] }), None, None)
            }
            ResponseAction::KillProcess {
                host_id,
                process_name,
            } => (
                "execute_admin_command",
                json!({
                    "host_id": host_id,
                    "arguments": {
                        "process_name": process_name,
                    }
                }),
                Some(host_id.as_str()),
                Some(("kill_process", process_name.as_str())),
            ),
            ResponseAction::QuarantineFile { host_id, file_path } => (
                "execute_admin_command",
                json!({
                    "host_id": host_id,
                    "arguments": {
                        "file_path": file_path,
                    }
                }),
                Some(host_id.as_str()),
                Some(("quarantine_file", file_path.as_str())),
            ),
            _ => return Ok(self.unsupported_receipt(request, lease, mode)),
        };

        if mode == ExecutionMode::DryRun {
            return Ok(self.dry_run_receipt(request, lease, payload.clone(), operation));
        }

        let token = match self
            .fetch_access_token(request, lease, &payload, mode)
            .await
        {
            Ok(token) => token,
            Err(receipt) => return Ok(*receipt),
        };

        if matches!(request.action, ResponseAction::IsolateHost { .. }) {
            return match self
                .execute_json_call(
                    request,
                    lease,
                    &token,
                    operation,
                    format!(
                        "{}?action_name=contain",
                        self.endpoint("/devices/entities/devices-actions/v2")
                    ),
                    payload,
                    mode,
                )
                .await
            {
                Ok(receipt) => Ok(receipt),
                Err(receipt) => Ok(*receipt),
            };
        }

        #[allow(clippy::expect_used)]
        let host_id = session_host.expect("session_host set for command-backed actions");
        let session_id = match self
            .create_session(request, lease, &token, host_id, &payload, mode)
            .await
        {
            Ok(session_id) => session_id,
            Err(receipt) => return Ok(*receipt),
        };
        #[allow(clippy::expect_used)]
        let (command_name, argument_value) =
            command.expect("command set for command-backed actions");
        let argument_key = if command_name == "kill_process" {
            "process_name"
        } else {
            "file_path"
        };
        let mut arguments = serde_json::Map::new();
        arguments.insert(argument_key.to_string(), json!(argument_value));
        let command_payload = json!({
            "session_id": session_id,
            "command": command_name,
            "arguments": Value::Object(arguments),
        });
        match self
            .execute_json_call(
                request,
                lease,
                &token,
                operation,
                self.endpoint("/real-time-response/entities/execute-admin-command/v1"),
                command_payload,
                mode,
            )
            .await
        {
            Ok(receipt) => Ok(receipt),
            Err(receipt) => Ok(*receipt),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::CrowdStrikeRtrAdapter;
    use crate::config::{CircuitBreakerConfig, CrowdStrikeRtrConfig, RetryConfig};
    use crate::dead_letter::DeadLetterJournal;
    use crate::dispatch::DispatchingExecutor;
    use crate::{ExecutionMode, ResponseExecutor, ResponseStatus};
    use axum::extract::{Form, Query, State};
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde::Deserialize;
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
    use swarm_policy::{ActionRequest, CapabilityLease};
    use tokio::sync::{Mutex, oneshot};

    #[derive(Clone)]
    struct CaptureState {
        token_requests: Arc<Mutex<Vec<HashMap<String, String>>>>,
        isolate_query: Arc<Mutex<Option<String>>>,
        isolate_payload: Arc<Mutex<Option<Value>>>,
        session_payload: Arc<Mutex<Option<Value>>>,
        command_payload: Arc<Mutex<Option<Value>>>,
        command_auth: Arc<Mutex<Option<String>>>,
        token_status: StatusCode,
        isolate_status: StatusCode,
        session_status: StatusCode,
        command_status: StatusCode,
        delay_ms: u64,
    }

    impl Default for CaptureState {
        fn default() -> Self {
            Self {
                token_requests: Arc::default(),
                isolate_query: Arc::default(),
                isolate_payload: Arc::default(),
                session_payload: Arc::default(),
                command_payload: Arc::default(),
                command_auth: Arc::default(),
                token_status: StatusCode::OK,
                isolate_status: StatusCode::OK,
                session_status: StatusCode::OK,
                command_status: StatusCode::OK,
                delay_ms: 0,
            }
        }
    }

    #[derive(Deserialize)]
    struct TokenForm {
        client_id: String,
        client_secret: String,
    }

    async fn token_handler(
        State(state): State<CaptureState>,
        Form(form): Form<TokenForm>,
    ) -> (StatusCode, Json<Value>) {
        state.token_requests.lock().await.push(HashMap::from([
            ("client_id".to_string(), form.client_id),
            ("client_secret".to_string(), form.client_secret),
        ]));
        if state.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(state.delay_ms)).await;
        }
        (
            state.token_status,
            Json(json!({ "access_token": "mock-access-token" })),
        )
    }

    async fn isolate_handler(
        State(state): State<CaptureState>,
        headers: HeaderMap,
        Query(query): Query<HashMap<String, String>>,
        Json(payload): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        *state.command_auth.lock().await = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        *state.isolate_query.lock().await = query.get("action_name").cloned();
        *state.isolate_payload.lock().await = Some(payload);
        if state.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(state.delay_ms)).await;
        }
        (state.isolate_status, Json(json!({ "ok": true })))
    }

    async fn session_handler(
        State(state): State<CaptureState>,
        Json(payload): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        *state.session_payload.lock().await = Some(payload);
        if state.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(state.delay_ms)).await;
        }
        (
            state.session_status,
            Json(json!({ "resources": [{ "session_id": "session-1" }] })),
        )
    }

    async fn command_handler(
        State(state): State<CaptureState>,
        Json(payload): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        *state.command_payload.lock().await = Some(payload);
        if state.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(state.delay_ms)).await;
        }
        (
            state.command_status,
            Json(json!({ "resources": [{ "ok": true }] })),
        )
    }

    async fn spawn_server(
        state: CaptureState,
    ) -> (
        String,
        CaptureState,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let app = Router::new()
            .route("/oauth2/token", post(token_handler))
            .route(
                "/devices/entities/devices-actions/v2",
                post(isolate_handler),
            )
            .route(
                "/real-time-response/entities/sessions/v1",
                post(session_handler),
            )
            .route(
                "/real-time-response/entities/execute-admin-command/v1",
                post(command_handler),
            )
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
        (format!("http://{address}"), state, shutdown_tx, handle)
    }

    fn adapter_config(base_url: String, timeout_ms: u64) -> CrowdStrikeRtrConfig {
        CrowdStrikeRtrConfig {
            base_url,
            client_id: "client-id".to_string().into(),
            client_secret: "client-secret".to_string().into(),
            timeout_ms,
            retry: RetryConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            dead_letter_path: temp_jsonl_path("crowdstrike-rtr"),
        }
    }

    fn sample_request(action: ResponseAction) -> (ActionRequest, CapabilityLease) {
        let request = ActionRequest {
            hunt_id: HuntId("hunt-rtr".to_string()),
            requested_by: AgentId("agent-1".to_string()),
            action,
            severity: Severity::High,
            evidence: json!({"trace_id": "trace-rtr"}),
        };
        let lease = CapabilityLease {
            capability_id: "lease-rtr".to_string(),
            expires_at_ms: 1_000,
            action: request.action.kind().to_string(),
            scope: Some("host-1".to_string()),
        };
        (request, lease)
    }

    fn temp_jsonl_path(label: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "swarm-response-{label}-{}-{nanos}.jsonl",
                std::process::id()
            ))
            .display()
            .to_string()
    }

    #[tokio::test]
    async fn isolate_host_fetches_token_and_calls_isolation_endpoint() {
        let state = CaptureState {
            token_status: StatusCode::OK,
            isolate_status: StatusCode::OK,
            session_status: StatusCode::OK,
            command_status: StatusCode::OK,
            delay_ms: 0,
            ..Default::default()
        };
        let (base_url, state, shutdown_tx, handle) = spawn_server(state).await;
        let adapter = CrowdStrikeRtrAdapter::new(adapter_config(base_url, 500)).unwrap();
        let (request, lease) = sample_request(ResponseAction::IsolateHost {
            host_id: "host-1".to_string(),
        });

        let receipt = adapter
            .execute(&request, &lease, ExecutionMode::Enforced)
            .await
            .unwrap();

        assert_eq!(receipt.status, ResponseStatus::Executed);
        assert_eq!(state.token_requests.lock().await.len(), 1);
        assert_eq!(
            state.isolate_query.lock().await.clone(),
            Some("contain".to_string())
        );
        assert_eq!(
            state.command_auth.lock().await.clone(),
            Some("Bearer mock-access-token".to_string())
        );
        assert_eq!(
            state.isolate_payload.lock().await.clone().unwrap()["ids"][0],
            "host-1"
        );

        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[tokio::test]
    async fn kill_process_creates_session_and_executes_command() {
        let state = CaptureState {
            token_status: StatusCode::OK,
            isolate_status: StatusCode::OK,
            session_status: StatusCode::OK,
            command_status: StatusCode::OK,
            delay_ms: 0,
            ..Default::default()
        };
        let (base_url, state, shutdown_tx, handle) = spawn_server(state).await;
        let adapter = CrowdStrikeRtrAdapter::new(adapter_config(base_url, 500)).unwrap();
        let (request, lease) = sample_request(ResponseAction::KillProcess {
            host_id: "host-1".to_string(),
            process_name: "powershell.exe".to_string(),
        });

        let receipt = adapter
            .execute(&request, &lease, ExecutionMode::Enforced)
            .await
            .unwrap();

        assert_eq!(receipt.status, ResponseStatus::Executed);
        assert_eq!(
            state.session_payload.lock().await.clone().unwrap()["device_id"],
            "host-1"
        );
        let command_payload = state.command_payload.lock().await.clone().unwrap();
        assert_eq!(command_payload["session_id"], "session-1");
        assert_eq!(command_payload["command"], "kill_process");
        assert_eq!(
            command_payload["arguments"]["process_name"],
            "powershell.exe"
        );

        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[tokio::test]
    async fn quarantine_file_creates_session_and_executes_command() {
        let state = CaptureState {
            token_status: StatusCode::OK,
            isolate_status: StatusCode::OK,
            session_status: StatusCode::OK,
            command_status: StatusCode::OK,
            delay_ms: 0,
            ..Default::default()
        };
        let (base_url, state, shutdown_tx, handle) = spawn_server(state).await;
        let adapter = CrowdStrikeRtrAdapter::new(adapter_config(base_url, 500)).unwrap();
        let (request, lease) = sample_request(ResponseAction::QuarantineFile {
            host_id: "host-1".to_string(),
            file_path: "C:\\malware.exe".to_string(),
        });

        let receipt = adapter
            .execute(&request, &lease, ExecutionMode::Enforced)
            .await
            .unwrap();

        assert_eq!(receipt.status, ResponseStatus::Executed);
        let command_payload = state.command_payload.lock().await.clone().unwrap();
        assert_eq!(command_payload["command"], "quarantine_file");
        assert_eq!(command_payload["arguments"]["file_path"], "C:\\malware.exe");

        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[tokio::test]
    async fn timeout_surfaces_timeout_receipt() {
        let state = CaptureState {
            token_status: StatusCode::OK,
            isolate_status: StatusCode::OK,
            session_status: StatusCode::OK,
            command_status: StatusCode::OK,
            delay_ms: 50,
            ..Default::default()
        };
        let (base_url, _state, shutdown_tx, handle) = spawn_server(state).await;
        let adapter = CrowdStrikeRtrAdapter::new(adapter_config(base_url, 10)).unwrap();
        let (request, lease) = sample_request(ResponseAction::IsolateHost {
            host_id: "host-1".to_string(),
        });

        let receipt = adapter
            .execute(&request, &lease, ExecutionMode::Enforced)
            .await
            .unwrap();

        assert_eq!(receipt.status, ResponseStatus::Timeout);

        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[tokio::test]
    async fn dispatching_executor_writes_dead_letter_on_final_rtr_failure() {
        let state = CaptureState {
            token_status: StatusCode::OK,
            isolate_status: StatusCode::BAD_GATEWAY,
            session_status: StatusCode::OK,
            command_status: StatusCode::OK,
            delay_ms: 0,
            ..Default::default()
        };
        let (base_url, _state, shutdown_tx, handle) = spawn_server(state).await;
        let dead_letter_path = temp_jsonl_path("crowdstrike-rtr-dead-letter");
        let executor = DispatchingExecutor::from_config(
            crate::config::ResponseAdapterConfig::CrowdStrikeRtr {
                config: CrowdStrikeRtrConfig {
                    base_url,
                    client_id: "client-id".to_string().into(),
                    client_secret: "client-secret".to_string().into(),
                    timeout_ms: 500,
                    retry: RetryConfig {
                        max_retries: 0,
                        ..RetryConfig::default()
                    },
                    circuit_breaker: CircuitBreakerConfig::default(),
                    dead_letter_path: dead_letter_path.clone(),
                },
            },
            None,
        )
        .unwrap();
        let (request, lease) = sample_request(ResponseAction::IsolateHost {
            host_id: "host-1".to_string(),
        });

        let receipt = executor
            .execute(&request, &lease, ExecutionMode::Enforced)
            .await
            .unwrap();

        assert_eq!(receipt.status, ResponseStatus::Failed);
        let journal = DeadLetterJournal::new(&dead_letter_path, None).unwrap();
        let entries = journal.read_entries(None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].adapter, "crowdstrike_rtr");

        let _ = std::fs::remove_file(dead_letter_path);
        let _ = shutdown_tx.send(());
        handle.abort();
    }
}
