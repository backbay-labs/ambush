use crate::{
    DeadLetterEntry, DeadLetterJournal, ExecutionMode, ResponseError, ResponseExecutor,
    ResponseReceipt, ResponseStatus,
};
use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use swarm_core::config::{CircuitBreakerConfig, RetryConfig};
use swarm_policy::{ActionRequest, CapabilityLease};

#[derive(Debug, Default)]
pub struct CircuitBreakerState {
    consecutive_failures: AtomicU32,
    last_failure_time: Mutex<Option<Instant>>,
}

/// Circuit breaking and failure accounting around a response adapter.
///
/// Whether an ambiguous outcome may be retried depends on the caller, not the
/// adapter, so it is chosen at construction and never inferred here.
///
/// [`ResilientExecutor::new`] disables retries: each call invokes the adapter at
/// most once. A timeout, transport error, 429, or 5xx response does not prove
/// that an enforced external effect did not happen, and retrying an effectful
/// response would require a verified adapter idempotency contract this trait
/// does not provide. The adapter's original outcome is returned unchanged,
/// including any uncertainty about the effect. Cross-call and crash-recovery
/// deduplication belongs to the durable dispatch journal.
///
/// [`ResilientExecutor::with_retries`] restores controlled, backed-off retries
/// of transient failures, and is only for duplicate-safe work such as SIEM
/// finding forwarding, where re-delivering a finding is harmless. It must never
/// wrap an effectful response dispatch adapter.
#[derive(Debug)]
pub struct ResilientExecutor<E> {
    inner: E,
    adapter: String,
    retry: RetryConfig,
    retries_enabled: bool,
    circuit_breaker: CircuitBreakerConfig,
    state: CircuitBreakerState,
    dead_letter: Option<Arc<DeadLetterJournal>>,
}

impl<E> ResilientExecutor<E> {
    /// Construct an executor that invokes its adapter at most once, never
    /// automatically repeating an invocation. Use this for every effectful
    /// response dispatch adapter: after an ambiguous outcome the external effect
    /// may already have happened, so the outcome cannot authorize retransmission.
    pub fn new(
        inner: E,
        adapter: impl Into<String>,
        retry: RetryConfig,
        circuit_breaker: CircuitBreakerConfig,
        dead_letter: Option<Arc<DeadLetterJournal>>,
    ) -> Self {
        Self::build(inner, adapter, retry, false, circuit_breaker, dead_letter)
    }

    /// Construct an executor that retries transient failures per `retry` with
    /// backoff before dead-lettering. Only safe for duplicate-tolerant work such
    /// as SIEM finding forwarding, never for an effectful response dispatch: a
    /// retry re-invokes the wrapped adapter.
    pub fn with_retries(
        inner: E,
        adapter: impl Into<String>,
        retry: RetryConfig,
        circuit_breaker: CircuitBreakerConfig,
        dead_letter: Option<Arc<DeadLetterJournal>>,
    ) -> Self {
        Self::build(inner, adapter, retry, true, circuit_breaker, dead_letter)
    }

    fn build(
        inner: E,
        adapter: impl Into<String>,
        retry: RetryConfig,
        retries_enabled: bool,
        circuit_breaker: CircuitBreakerConfig,
        dead_letter: Option<Arc<DeadLetterJournal>>,
    ) -> Self {
        Self {
            inner,
            adapter: adapter.into(),
            retry,
            retries_enabled,
            circuit_breaker,
            state: CircuitBreakerState::default(),
            dead_letter,
        }
    }

    fn last_failure_time(&self) -> MutexGuard<'_, Option<Instant>> {
        self.state
            .last_failure_time
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn circuit_is_open(&self) -> bool {
        let threshold = self.circuit_breaker.threshold;
        if self.state.consecutive_failures.load(Ordering::SeqCst) < threshold {
            return false;
        }
        self.last_failure_time()
            .as_ref()
            .is_some_and(|last_failure| {
                last_failure.elapsed() < Duration::from_millis(self.circuit_breaker.cooldown_ms)
            })
    }

    fn reset_after_success(&self) {
        self.state.consecutive_failures.store(0, Ordering::SeqCst);
        *self.last_failure_time() = None;
    }

    fn record_failure(&self) {
        self.state
            .consecutive_failures
            .fetch_add(1, Ordering::SeqCst);
        *self.last_failure_time() = Some(Instant::now());
    }

    fn circuit_open_receipt(
        &self,
        request: &ActionRequest,
        mode: ExecutionMode,
    ) -> ResponseReceipt {
        ResponseReceipt {
            receipt_id: format!(
                "resp-circuit-open:{}:{}",
                request.hunt_id.0,
                request.action.kind()
            ),
            action: request.action.kind().to_string(),
            mode,
            status: ResponseStatus::Failed,
            summary: format!("{} circuit breaker open", self.adapter),
            details: serde_json::json!({
                "adapter": self.adapter,
                "consecutive_failures": self.state.consecutive_failures.load(Ordering::SeqCst),
                "cooldown_ms": self.circuit_breaker.cooldown_ms,
            }),
            audit: Default::default(),
        }
    }

    fn backoff_for_retry(&self, retry_index: u32) -> Duration {
        let millis = (self.retry.initial_backoff_ms as f64)
            * self.retry.backoff_multiplier.powi(retry_index as i32);
        Duration::from_millis(millis.min(30_000.0).round() as u64)
    }

    fn receipt_is_retryable(receipt: &ResponseReceipt) -> bool {
        match receipt.status {
            ResponseStatus::Timeout => true,
            ResponseStatus::Failed => {
                if let Some(status_code) = receipt
                    .details
                    .get("status_code")
                    .and_then(serde_json::Value::as_u64)
                {
                    return status_code >= 500 || status_code == 429;
                }
                receipt
                    .details
                    .get("error")
                    .and_then(serde_json::Value::as_str)
                    .is_some()
            }
            ResponseStatus::Simulated | ResponseStatus::Executed => false,
        }
    }

    fn error_is_retryable(error: &ResponseError) -> bool {
        if error
            .failure
            .details
            .get("status")
            .and_then(serde_json::Value::as_str)
            == Some("timeout")
        {
            return true;
        }
        if let Some(status_code) = error
            .failure
            .details
            .get("status_code")
            .and_then(serde_json::Value::as_u64)
        {
            return status_code >= 500 || status_code == 429;
        }
        if error
            .failure
            .details
            .get("error")
            .and_then(serde_json::Value::as_str)
            .is_some()
        {
            return true;
        }
        let message = error.failure.message.to_ascii_lowercase();
        message.contains("timeout") || message.contains("connection")
    }

    fn dead_letter_entry_from_receipt(
        &self,
        receipt: &ResponseReceipt,
        attempts: u32,
    ) -> DeadLetterEntry {
        DeadLetterEntry {
            timestamp_ms: now_ms(),
            receipt_id: receipt.receipt_id.clone(),
            action: receipt.action.clone(),
            mode: receipt.mode,
            adapter: self.adapter.clone(),
            attempts,
            last_error: receipt.summary.clone(),
            details: receipt.details.clone(),
        }
    }

    fn dead_letter_entry_from_error(
        &self,
        error: &ResponseError,
        attempts: u32,
    ) -> DeadLetterEntry {
        DeadLetterEntry {
            timestamp_ms: now_ms(),
            receipt_id: error.failure.receipt_id.clone(),
            action: error.failure.action.clone(),
            mode: error.failure.mode,
            adapter: self.adapter.clone(),
            attempts,
            last_error: error.failure.message.clone(),
            details: error.failure.details.clone(),
        }
    }

    fn write_dead_letter(&self, entry: &DeadLetterEntry) {
        if let Some(journal) = &self.dead_letter
            && let Err(error) = journal.write(entry)
        {
            tracing::error!(
                adapter = %self.adapter,
                path = %journal.path().display(),
                reason = %error,
                "failed to write dead-letter entry"
            );
        }
    }
}

#[async_trait]
impl<E> ResponseExecutor for ResilientExecutor<E>
where
    E: ResponseExecutor,
{
    async fn execute(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        mode: ExecutionMode,
    ) -> Result<ResponseReceipt, ResponseError> {
        if mode == ExecutionMode::DryRun {
            return self.inner.execute(request, lease, mode).await;
        }

        if !self.retries_enabled {
            // Effectful dispatch: invoke the adapter exactly once. A timeout,
            // transport error, 429 or 5xx does not prove the external effect did
            // not happen, so the outcome is returned unchanged and never retried.
            if self.circuit_is_open() {
                return Ok(self.circuit_open_receipt(request, mode));
            }
            return match self.inner.execute(request, lease, mode).await {
                Ok(receipt) if receipt.status.indicates_success() => {
                    self.reset_after_success();
                    Ok(receipt)
                }
                Ok(receipt) => {
                    self.record_failure();
                    self.write_dead_letter(&self.dead_letter_entry_from_receipt(&receipt, 1));
                    Ok(receipt)
                }
                Err(error) => {
                    self.record_failure();
                    self.write_dead_letter(&self.dead_letter_entry_from_error(&error, 1));
                    Err(error)
                }
            };
        }

        // Retries enabled: duplicate-safe telemetry (SIEM finding forwarding).
        // Transient failures are retried with backoff, then dead-lettered.
        let total_attempts = self.retry.max_retries.saturating_add(1);
        for attempt in 0..total_attempts {
            if self.circuit_is_open() {
                return Ok(self.circuit_open_receipt(request, mode));
            }

            match self.inner.execute(request, lease, mode).await {
                Ok(receipt) if receipt.status.indicates_success() => {
                    self.reset_after_success();
                    return Ok(receipt);
                }
                Ok(receipt) => {
                    self.record_failure();
                    let attempts = attempt + 1;
                    if Self::receipt_is_retryable(&receipt) && attempts < total_attempts {
                        tokio::time::sleep(self.backoff_for_retry(attempt)).await;
                        continue;
                    }
                    self.write_dead_letter(
                        &self.dead_letter_entry_from_receipt(&receipt, attempts),
                    );
                    return Ok(receipt);
                }
                Err(error) => {
                    self.record_failure();
                    let attempts = attempt + 1;
                    if Self::error_is_retryable(&error) && attempts < total_attempts {
                        tokio::time::sleep(self.backoff_for_retry(attempt)).await;
                        continue;
                    }
                    self.write_dead_letter(&self.dead_letter_entry_from_error(&error, attempts));
                    return Err(error);
                }
            }
        }

        Ok(self.circuit_open_receipt(request, mode))
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::ResilientExecutor;
    use crate::test_paths::temp_jsonl_path as temp_path;
    use crate::{
        DeadLetterJournal, ExecutionMode, HttpEdrAdapter, HttpEdrConfig, ResponseError,
        ResponseExecutor, ResponseReceipt, ResponseStatus,
    };
    use async_trait::async_trait;
    use axum::{Router, http::StatusCode, routing::post};
    use serde_json::{Value, json};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};
    use swarm_core::config::{CircuitBreakerConfig, RetryConfig};
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
    use swarm_policy::{ActionRequest, CapabilityLease};

    #[derive(Clone)]
    struct StubExecutor {
        calls: Arc<AtomicUsize>,
        outcomes: Arc<Vec<Result<ResponseReceipt, ResponseError>>>,
    }

    #[async_trait]
    impl ResponseExecutor for StubExecutor {
        async fn execute(
            &self,
            _request: &ActionRequest,
            _lease: &CapabilityLease,
            _mode: ExecutionMode,
        ) -> Result<ResponseReceipt, ResponseError> {
            let index = self.calls.fetch_add(1, Ordering::SeqCst);
            self.outcomes
                .get(index)
                .cloned()
                .or_else(|| self.outcomes.last().cloned())
                .unwrap()
        }
    }

    fn request() -> ActionRequest {
        ActionRequest {
            hunt_id: HuntId("hunt-1".to_string()),
            requested_by: AgentId("agent-1".to_string()),
            action: ResponseAction::BlockEgress {
                target: "203.0.113.10".to_string(),
            },
            severity: Severity::High,
            evidence: serde_json::json!({"signal": "test"}),
        }
    }

    fn lease() -> CapabilityLease {
        CapabilityLease {
            capability_id: "lease-1".to_string(),
            expires_at_ms: 1_700_000_000_000,
            action: "block_egress".to_string(),
            scope: Some("203.0.113.10".to_string()),
        }
    }

    fn receipt(status: ResponseStatus, details: Value) -> ResponseReceipt {
        ResponseReceipt {
            receipt_id: "receipt-effect".to_string(),
            action: "block_egress".to_string(),
            mode: ExecutionMode::Enforced,
            status,
            summary: "adapter outcome after effect".to_string(),
            details,
            audit: Default::default(),
        }
    }

    fn retries_configured() -> RetryConfig {
        RetryConfig {
            max_retries: 3,
            initial_backoff_ms: 1,
            backoff_multiplier: 1.0,
        }
    }

    #[tokio::test]
    async fn enforced_ambiguous_outcomes_do_not_repeat_effects() {
        let outcomes = [
            Ok(receipt(
                ResponseStatus::Timeout,
                json!({"status": "timeout"}),
            )),
            Ok(receipt(
                ResponseStatus::Failed,
                json!({"error": "connection reset"}),
            )),
            Ok(receipt(ResponseStatus::Failed, json!({"status_code": 429}))),
            Ok(receipt(ResponseStatus::Failed, json!({"status_code": 500}))),
            Ok(receipt(ResponseStatus::Failed, json!({"status_code": 503}))),
            Err(ResponseError::execution_failed(
                "receipt-effect",
                "block_egress",
                ExecutionMode::Enforced,
                "timed out after dispatch",
                json!({"status": "timeout"}),
            )),
            Err(ResponseError::execution_failed(
                "receipt-effect",
                "block_egress",
                ExecutionMode::Enforced,
                "transport failed after dispatch",
                json!({"error": "connection reset"}),
            )),
            Err(ResponseError::execution_failed(
                "receipt-effect",
                "block_egress",
                ExecutionMode::Enforced,
                "rate limited after dispatch",
                json!({"status_code": 429}),
            )),
            Err(ResponseError::execution_failed(
                "receipt-effect",
                "block_egress",
                ExecutionMode::Enforced,
                "server failed after dispatch",
                json!({"status_code": 503}),
            )),
            Err(ResponseError::unavailable(
                "block_egress",
                ExecutionMode::Enforced,
                "connection timeout",
            )),
        ];

        for expected in outcomes {
            // The counter is written before returning the ambiguous outcome:
            // it models a committed external effect whose acknowledgment failed.
            let effects = Arc::new(AtomicUsize::new(0));
            let path = temp_path("dead-letter-single-effect");
            let journal = Arc::new(DeadLetterJournal::new(&path, None).unwrap());
            let executor = ResilientExecutor::new(
                StubExecutor {
                    calls: Arc::clone(&effects),
                    outcomes: Arc::new(vec![
                        expected.clone(),
                        Ok(receipt(ResponseStatus::Executed, json!({}))),
                    ]),
                },
                "http_edr",
                retries_configured(),
                CircuitBreakerConfig {
                    threshold: 5,
                    cooldown_ms: 1000,
                },
                Some(Arc::clone(&journal)),
            );

            let actual = executor
                .execute(&request(), &lease(), ExecutionMode::Enforced)
                .await;
            assert_eq!(effects.load(Ordering::SeqCst), 1, "outcome: {expected:?}");
            assert_eq!(
                serde_json::to_value(&actual).unwrap(),
                serde_json::to_value(&expected).unwrap()
            );
            assert_eq!(
                executor.state.consecutive_failures.load(Ordering::SeqCst),
                1
            );
            let entries = journal.read_entries(None).unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].attempts, 1);
            assert_eq!(entries[0].mode, ExecutionMode::Enforced);
            match expected {
                Ok(receipt) => {
                    assert_eq!(entries[0].receipt_id, receipt.receipt_id);
                    assert_eq!(entries[0].last_error, receipt.summary);
                    assert_eq!(entries[0].details, receipt.details);
                }
                Err(error) => {
                    assert_eq!(entries[0].receipt_id, error.failure.receipt_id);
                    assert_eq!(entries[0].last_error, error.failure.message);
                    assert_eq!(entries[0].details, error.failure.details);
                }
            }
            std::fs::remove_file(path).unwrap();
        }
    }

    async fn assert_http_effect_not_repeated(stall: bool, status: StatusCode) {
        let effects = Arc::new(AtomicUsize::new(0));
        let server_effects = Arc::clone(&effects);
        let router = Router::new().route(
            "/",
            post(move || {
                let effects = Arc::clone(&server_effects);
                async move {
                    // The remote effect has happened before the HTTP failure or
                    // missing acknowledgment. Count requests at the server boundary.
                    effects.fetch_add(1, Ordering::SeqCst);
                    if stall {
                        std::future::pending::<()>().await;
                    }
                    status
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let adapter = HttpEdrAdapter::new(HttpEdrConfig {
            endpoint,
            auth_token: "test-token".to_string().into(),
            timeout_ms: 200,
            retry: retries_configured(),
            circuit_breaker: CircuitBreakerConfig::default(),
            dead_letter_path: temp_path("unused-http-effect-journal")
                .display()
                .to_string(),
        })
        .unwrap();
        let executor = ResilientExecutor::new(
            adapter,
            "http_edr",
            retries_configured(),
            CircuitBreakerConfig {
                threshold: 5,
                cooldown_ms: 1000,
            },
            None,
        );
        let outcome = tokio::time::timeout(
            Duration::from_secs(10),
            executor.execute(&request(), &lease(), ExecutionMode::Enforced),
        )
        .await;
        server.abort();
        let receipt = outcome.unwrap().unwrap();
        assert_eq!(effects.load(Ordering::SeqCst), 1);
        if stall {
            assert_eq!(receipt.status, ResponseStatus::Timeout);
        } else {
            assert_eq!(receipt.status, ResponseStatus::Failed);
            assert_eq!(receipt.details["status_code"], status.as_u16());
        }
    }

    #[tokio::test]
    async fn http_effect_then_server_failure_is_not_retried() {
        assert_http_effect_not_repeated(false, StatusCode::SERVICE_UNAVAILABLE).await;
        assert_http_effect_not_repeated(false, StatusCode::TOO_MANY_REQUESTS).await;
    }

    #[tokio::test]
    async fn http_effect_then_timeout_is_not_retried() {
        assert_http_effect_not_repeated(true, StatusCode::OK).await;
    }

    #[tokio::test]
    async fn circuit_blocks_calls_until_cooldown_and_success_resets_failures() {
        let calls = Arc::new(AtomicUsize::new(0));
        let executor = ResilientExecutor::new(
            StubExecutor {
                calls: Arc::clone(&calls),
                outcomes: Arc::new(vec![
                    Ok(receipt(ResponseStatus::Failed, json!({"status_code": 503}))),
                    Ok(receipt(ResponseStatus::Executed, json!({}))),
                ]),
            },
            "http_edr",
            retries_configured(),
            CircuitBreakerConfig {
                threshold: 1,
                cooldown_ms: 1000,
            },
            None,
        );
        assert_eq!(
            executor
                .execute(&request(), &lease(), ExecutionMode::Enforced)
                .await
                .unwrap()
                .status,
            ResponseStatus::Failed
        );
        let blocked = executor
            .execute(&request(), &lease(), ExecutionMode::Enforced)
            .await
            .unwrap();
        assert!(blocked.summary.contains("circuit breaker open"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(blocked.details["consecutive_failures"], 1);

        *executor.last_failure_time() = Some(Instant::now() - Duration::from_secs(2));
        assert_eq!(
            executor
                .execute(&request(), &lease(), ExecutionMode::Enforced)
                .await
                .unwrap()
                .status,
            ResponseStatus::Executed
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            executor.state.consecutive_failures.load(Ordering::SeqCst),
            0
        );
        assert!(executor.last_failure_time().is_none());
    }

    #[tokio::test]
    async fn dry_run_still_bypasses_circuit_without_retries_or_failure_accounting() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut expected = receipt(ResponseStatus::Timeout, json!({"status": "timeout"}));
        expected.mode = ExecutionMode::DryRun;
        let path = temp_path("dry-run-no-dead-letter");
        let journal = Arc::new(DeadLetterJournal::new(&path, None).unwrap());
        let executor = ResilientExecutor::new(
            StubExecutor {
                calls: Arc::clone(&calls),
                outcomes: Arc::new(vec![Ok(expected.clone())]),
            },
            "http_edr",
            retries_configured(),
            CircuitBreakerConfig {
                threshold: 1,
                cooldown_ms: 1000,
            },
            Some(Arc::clone(&journal)),
        );
        executor.record_failure();
        let actual = executor
            .execute(&request(), &lease(), ExecutionMode::DryRun)
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            executor.state.consecutive_failures.load(Ordering::SeqCst),
            1
        );
        assert!(journal.read_entries(None).unwrap().is_empty());
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn with_retries_retries_transient_failure_then_succeeds() {
        // The duplicate-safe SIEM path: a transient timeout is retried and the
        // second invocation succeeds. The adapter is invoked more than once by
        // design, which is exactly why this constructor is forbidden for the
        // effectful dispatch adapters.
        let calls = Arc::new(AtomicUsize::new(0));
        let executor = ResilientExecutor::with_retries(
            StubExecutor {
                calls: Arc::clone(&calls),
                outcomes: Arc::new(vec![
                    Ok(receipt(
                        ResponseStatus::Timeout,
                        json!({"status": "timeout"}),
                    )),
                    Ok(receipt(ResponseStatus::Executed, json!({}))),
                ]),
            },
            "siem_forward",
            retries_configured(),
            CircuitBreakerConfig {
                threshold: 5,
                cooldown_ms: 1000,
            },
            None,
        );

        let receipt = executor
            .execute(&request(), &lease(), ExecutionMode::Enforced)
            .await
            .unwrap();
        assert_eq!(receipt.status, ResponseStatus::Executed);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            executor.state.consecutive_failures.load(Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn with_retries_exhausts_attempts_then_dead_letters() {
        let calls = Arc::new(AtomicUsize::new(0));
        let path = temp_path("with-retries-dead-letter");
        let journal = Arc::new(DeadLetterJournal::new(&path, None).unwrap());
        let executor = ResilientExecutor::with_retries(
            StubExecutor {
                calls: Arc::clone(&calls),
                outcomes: Arc::new(vec![Ok(receipt(
                    ResponseStatus::Failed,
                    json!({"status_code": 503}),
                ))]),
            },
            "siem_forward",
            retries_configured(),
            CircuitBreakerConfig {
                threshold: 100,
                cooldown_ms: 1000,
            },
            Some(Arc::clone(&journal)),
        );

        let receipt = executor
            .execute(&request(), &lease(), ExecutionMode::Enforced)
            .await
            .unwrap();
        assert_eq!(receipt.status, ResponseStatus::Failed);
        // max_retries = 3, so four total attempts before dead-lettering.
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        let entries = journal.read_entries(None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].attempts, 4);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn disabled_new_invokes_inner_exactly_once_on_transient_failure() {
        // The effectful dispatch guarantee at the executor level: a retryable
        // transient outcome under `new` still invokes the adapter exactly once.
        let calls = Arc::new(AtomicUsize::new(0));
        let executor = ResilientExecutor::new(
            StubExecutor {
                calls: Arc::clone(&calls),
                outcomes: Arc::new(vec![
                    Ok(receipt(
                        ResponseStatus::Timeout,
                        json!({"status": "timeout"}),
                    )),
                    Ok(receipt(ResponseStatus::Executed, json!({}))),
                ]),
            },
            "http_edr",
            retries_configured(),
            CircuitBreakerConfig {
                threshold: 5,
                cooldown_ms: 1000,
            },
            None,
        );

        let receipt = executor
            .execute(&request(), &lease(), ExecutionMode::Enforced)
            .await
            .unwrap();
        // The first, ambiguous outcome is returned unchanged; no second attempt.
        assert_eq!(receipt.status, ResponseStatus::Timeout);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
