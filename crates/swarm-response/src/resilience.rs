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
/// Each call invokes the adapter at most once. A timeout, transport error, 429,
/// or 5xx response does not prove that an enforced external effect did not
/// happen. Retrying requires a verified adapter idempotency contract, which
/// `ResponseExecutor` does not currently provide. The adapter's original
/// outcome is returned unchanged, including any uncertainty about the effect.
/// Cross-call and crash recovery deduplication belongs to the durable dispatch
/// journal; this wrapper only prevents retries within one invocation.
#[derive(Debug)]
pub struct ResilientExecutor<E> {
    inner: E,
    adapter: String,
    circuit_breaker: CircuitBreakerConfig,
    state: CircuitBreakerState,
    dead_letter: Option<Arc<DeadLetterJournal>>,
}

impl<E> ResilientExecutor<E> {
    /// Construct an executor that never automatically repeats an invocation.
    ///
    /// The retry configuration remains accepted for configuration/source
    /// compatibility, but cannot authorize retransmission of external effects.
    pub fn new(
        inner: E,
        adapter: impl Into<String>,
        _retry: RetryConfig,
        circuit_breaker: CircuitBreakerConfig,
        dead_letter: Option<Arc<DeadLetterJournal>>,
    ) -> Self {
        Self {
            inner,
            adapter: adapter.into(),
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

        if self.circuit_is_open() {
            return Ok(self.circuit_open_receipt(request, mode));
        }

        match self.inner.execute(request, lease, mode).await {
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
        }
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
}
