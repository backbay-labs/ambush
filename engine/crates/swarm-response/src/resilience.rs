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

#[derive(Debug)]
pub struct ResilientExecutor<E> {
    inner: E,
    adapter: String,
    retry: RetryConfig,
    circuit_breaker: CircuitBreakerConfig,
    state: CircuitBreakerState,
    dead_letter: Option<Arc<DeadLetterJournal>>,
}

impl<E> ResilientExecutor<E> {
    pub fn new(
        inner: E,
        adapter: impl Into<String>,
        retry: RetryConfig,
        circuit_breaker: CircuitBreakerConfig,
        dead_letter: Option<Arc<DeadLetterJournal>>,
    ) -> Self {
        Self {
            inner,
            adapter: adapter.into(),
            retry,
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
    use crate::{
        DeadLetterJournal, ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt,
        ResponseStatus,
    };
    use async_trait::async_trait;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
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

    fn temp_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "swarm-response-{label}-{}-{nanos}.jsonl",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn retries_transient_failures_then_succeeds() {
        let calls = Arc::new(AtomicUsize::new(0));
        let executor = ResilientExecutor::new(
            StubExecutor {
                calls: Arc::clone(&calls),
                outcomes: Arc::new(vec![
                    Ok(ResponseReceipt {
                        receipt_id: "receipt-1".to_string(),
                        action: "block_egress".to_string(),
                        mode: ExecutionMode::Enforced,
                        status: ResponseStatus::Timeout,
                        summary: "timed out".to_string(),
                        details: serde_json::json!({"status": "timeout"}),
                        audit: Default::default(),
                    }),
                    Ok(ResponseReceipt {
                        receipt_id: "receipt-2".to_string(),
                        action: "block_egress".to_string(),
                        mode: ExecutionMode::Enforced,
                        status: ResponseStatus::Executed,
                        summary: "ok".to_string(),
                        details: serde_json::json!({}),
                        audit: Default::default(),
                    }),
                ]),
            },
            "http_edr",
            RetryConfig {
                max_retries: 3,
                initial_backoff_ms: 1,
                backoff_multiplier: 1.0,
            },
            CircuitBreakerConfig {
                threshold: 5,
                cooldown_ms: 10,
            },
            None,
        );

        let receipt = executor
            .execute(&request(), &lease(), ExecutionMode::Enforced)
            .await
            .unwrap();
        assert_eq!(receipt.status, ResponseStatus::Executed);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn writes_dead_letter_after_final_failure() {
        let path = temp_path("dead-letter-final");
        let journal = Arc::new(DeadLetterJournal::new(&path, None).unwrap());
        let executor = ResilientExecutor::new(
            StubExecutor {
                calls: Arc::new(AtomicUsize::new(0)),
                outcomes: Arc::new(vec![Ok(ResponseReceipt {
                    receipt_id: "receipt-final".to_string(),
                    action: "block_egress".to_string(),
                    mode: ExecutionMode::Enforced,
                    status: ResponseStatus::Failed,
                    summary: "server error".to_string(),
                    details: serde_json::json!({"status_code": 503}),
                    audit: Default::default(),
                })]),
            },
            "http_edr",
            RetryConfig {
                max_retries: 0,
                initial_backoff_ms: 1,
                backoff_multiplier: 1.0,
            },
            CircuitBreakerConfig {
                threshold: 5,
                cooldown_ms: 10,
            },
            Some(Arc::clone(&journal)),
        );

        let receipt = executor
            .execute(&request(), &lease(), ExecutionMode::Enforced)
            .await
            .unwrap();
        assert_eq!(receipt.status, ResponseStatus::Failed);
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"receipt_id\":\"receipt-final\""));
        let _ = std::fs::remove_file(path);
    }
}
