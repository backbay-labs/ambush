use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::time::timeout;

use swarm_core::config::InvestigationConfig;
use swarm_spine::{
    InvestigationBundle, InvestigationBundleLookup, InvestigationBundleRecord,
    InvestigationBundleStore, InvestigationStatus, InvestigationStoreError,
};
use swarm_spine::{InvestigationStoreHealth, ReplayBundle};

/// Errors raised while submitting or processing investigation work.
#[derive(Debug, thiserror::Error)]
pub enum InvestigationError {
    #[error(transparent)]
    Store(#[from] InvestigationStoreError),
}

/// Durable summary produced by one investigation strategy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationOutcome {
    pub summary: String,
    pub evidence_points: Vec<String>,
    pub correlation_keys: Vec<String>,
}

/// Snapshot of async investigation queue state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationQueueSnapshot {
    pub enabled: bool,
    pub worker_count: usize,
    pub max_pending_jobs: usize,
    pub time_budget_ms: u64,
    pub queued_jobs: usize,
    pub running_jobs: usize,
    pub completed_jobs: u64,
    pub failed_jobs: u64,
    pub timed_out_jobs: u64,
    pub dropped_jobs: u64,
    pub last_failure_reason: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct InvestigationQueueState {
    queued_jobs: usize,
    running_jobs: usize,
    completed_jobs: u64,
    failed_jobs: u64,
    timed_out_jobs: u64,
    dropped_jobs: u64,
    last_failure_reason: Option<String>,
}

/// Deterministic investigation strategies that enrich replay bundles.
#[async_trait]
pub trait InvestigationStrategy: Send + Sync + Clone + 'static {
    fn id(&self) -> &str;

    async fn investigate(&self, replay: &ReplayBundle) -> Result<InvestigationOutcome, String>;
}

/// Minimal default investigator that summarizes the existing replay artifact.
#[derive(Debug, Clone, Default)]
pub struct SummaryInvestigator;

#[async_trait]
impl InvestigationStrategy for SummaryInvestigator {
    fn id(&self) -> &str {
        "summary_investigator"
    }

    async fn investigate(&self, replay: &ReplayBundle) -> Result<InvestigationOutcome, String> {
        let detection = &replay.audit.detection;
        let summary = format!(
            "finding {} via {} remained suspicious after replay review; response outcome was {}",
            detection.finding_id,
            detection.strategy_id,
            replay.audit.response_kind()
        );

        let mut evidence_points = Vec::new();
        if let Some(host_id) = &replay.event.host_id {
            evidence_points.push(format!("host_id={host_id}"));
        }
        if let Some(parent) = detection
            .evidence
            .get("parent_process")
            .and_then(|value| value.as_str())
        {
            evidence_points.push(format!("parent_process={parent}"));
        }
        if let Some(process_name) = detection
            .evidence
            .get("process_name")
            .and_then(|value| value.as_str())
        {
            evidence_points.push(format!("process_name={process_name}"));
        }
        if let Some(user) = detection
            .evidence
            .get("user")
            .and_then(|value| value.as_str())
        {
            evidence_points.push(format!("user={user}"));
        }
        if let Some(command_line) = detection
            .evidence
            .get("command_line")
            .and_then(|value| value.as_str())
        {
            evidence_points.push(format!("command_line={command_line}"));
        }
        evidence_points.push(format!("response_kind={}", replay.audit.response_kind()));
        evidence_points.push(format!(
            "action_kind={}",
            replay.action_request.action.kind()
        ));

        let mut correlation_keys = Vec::new();
        if let Some(host_id) = &replay.event.host_id {
            correlation_keys.push(format!("host:{host_id}"));
        }
        if let Some(user) = detection
            .evidence
            .get("user")
            .and_then(|value| value.as_str())
        {
            correlation_keys.push(format!("user:{user}"));
        }
        correlation_keys.push(format!("threat:{:?}", detection.threat_class).to_ascii_lowercase());
        correlation_keys.push(format!("strategy:{}", detection.strategy_id));

        Ok(InvestigationOutcome {
            summary,
            evidence_points,
            correlation_keys,
        })
    }
}

#[derive(Debug, Clone)]
struct InvestigationJob {
    replay: ReplayBundle,
    bundle: InvestigationBundle,
}

/// Async coordinator that queues replay bundles for background investigation.
#[derive(Debug, Clone)]
pub struct InvestigationCoordinator<S, Store> {
    config: InvestigationConfig,
    strategy: S,
    store: Store,
    sender: Option<mpsc::Sender<InvestigationJob>>,
    state: Arc<Mutex<InvestigationQueueState>>,
}

impl<S, Store> InvestigationCoordinator<S, Store>
where
    S: InvestigationStrategy,
    Store: InvestigationBundleStore + Clone + Send + Sync + 'static,
{
    pub fn new(config: InvestigationConfig, strategy: S, store: Store) -> Self {
        let state = Arc::new(Mutex::new(InvestigationQueueState::default()));

        if !config.enabled {
            return Self {
                config,
                strategy,
                store,
                sender: None,
                state,
            };
        }

        let (sender, receiver) = mpsc::channel::<InvestigationJob>(config.max_pending_jobs);
        let shared_receiver = Arc::new(AsyncMutex::new(receiver));

        for _worker_idx in 0..config.worker_count {
            let worker_state = Arc::clone(&state);
            let worker_receiver = Arc::clone(&shared_receiver);
            let worker_store = store.clone();
            let worker_strategy = strategy.clone();
            let worker_time_budget_ms = config.time_budget_ms;

            tokio::spawn(async move {
                loop {
                    let next_job = {
                        let mut guard = worker_receiver.lock().await;
                        guard.recv().await
                    };

                    let Some(job) = next_job else {
                        break;
                    };

                    {
                        let mut guard = worker_state.lock().expect("investigation queue state");
                        guard.queued_jobs = guard.queued_jobs.saturating_sub(1);
                        guard.running_jobs = guard.running_jobs.saturating_add(1);
                    }

                    let started_at_ms = now_ms();
                    let running_bundle = job.bundle.clone().with_status(
                        InvestigationStatus::Running,
                        Some(started_at_ms),
                        None,
                    );
                    if let Err(error) = worker_store.persist(&running_bundle) {
                        let mut guard = worker_state.lock().expect("investigation queue state");
                        guard.running_jobs = guard.running_jobs.saturating_sub(1);
                        guard.failed_jobs = guard.failed_jobs.saturating_add(1);
                        guard.last_failure_reason = Some(error.to_string());
                        continue;
                    }

                    let result = timeout(
                        Duration::from_millis(worker_time_budget_ms),
                        worker_strategy.investigate(&job.replay),
                    )
                    .await;
                    let completed_at_ms = now_ms();

                    let terminal_bundle = match result {
                        Ok(Ok(outcome)) => running_bundle.clone().with_summary(
                            outcome.summary,
                            outcome.evidence_points,
                            outcome.correlation_keys,
                            completed_at_ms,
                        ),
                        Ok(Err(reason)) => running_bundle.clone().with_failure(
                            InvestigationStatus::Failed,
                            reason,
                            completed_at_ms,
                        ),
                        Err(_) => running_bundle.clone().with_failure(
                            InvestigationStatus::TimedOut,
                            format!(
                                "investigation exceeded {} ms time budget",
                                worker_time_budget_ms
                            ),
                            completed_at_ms,
                        ),
                    };

                    let persist_result = worker_store.persist(&terminal_bundle);
                    let mut guard = worker_state.lock().expect("investigation queue state");
                    guard.running_jobs = guard.running_jobs.saturating_sub(1);
                    match terminal_bundle.status {
                        InvestigationStatus::Completed => {
                            guard.completed_jobs = guard.completed_jobs.saturating_add(1);
                        }
                        InvestigationStatus::Failed => {
                            guard.failed_jobs = guard.failed_jobs.saturating_add(1);
                            guard.last_failure_reason = terminal_bundle.failure_reason.clone();
                        }
                        InvestigationStatus::TimedOut => {
                            guard.timed_out_jobs = guard.timed_out_jobs.saturating_add(1);
                            guard.last_failure_reason = terminal_bundle.failure_reason.clone();
                        }
                        InvestigationStatus::Queued | InvestigationStatus::Running => {}
                    }
                    if let Err(error) = persist_result {
                        guard.failed_jobs = guard.failed_jobs.saturating_add(1);
                        guard.last_failure_reason = Some(error.to_string());
                    }
                }
            });
        }

        Self {
            config,
            strategy,
            store,
            sender: Some(sender),
            state,
        }
    }

    pub fn submit(
        &self,
        replay: &ReplayBundle,
    ) -> Result<Option<InvestigationBundleRecord>, InvestigationError> {
        if !self.config.enabled {
            return Ok(None);
        }

        let queued_at_ms = now_ms();
        let queued_bundle = InvestigationBundle::queued_from_bundle(
            replay,
            format!("investigation:{}:{queued_at_ms}", replay.audit.hunt_id),
            queued_at_ms,
        );
        let queued_record = self.store.persist(&queued_bundle)?;

        let Some(sender) = &self.sender else {
            return Ok(Some(queued_record));
        };

        match sender.try_send(InvestigationJob {
            replay: replay.clone(),
            bundle: queued_bundle.clone(),
        }) {
            Ok(()) => {
                let mut guard = self.state.lock().expect("investigation queue state");
                guard.queued_jobs = guard.queued_jobs.saturating_add(1);
                Ok(Some(queued_record))
            }
            Err(error) => {
                let failed_bundle = queued_bundle.with_failure(
                    InvestigationStatus::Failed,
                    format!("investigation queue rejected submission: {error}"),
                    now_ms(),
                );
                let failed_record = self.store.persist(&failed_bundle)?;
                let mut guard = self.state.lock().expect("investigation queue state");
                guard.dropped_jobs = guard.dropped_jobs.saturating_add(1);
                guard.failed_jobs = guard.failed_jobs.saturating_add(1);
                guard.last_failure_reason = failed_bundle.failure_reason.clone();
                Ok(Some(failed_record))
            }
        }
    }

    pub fn snapshot(&self) -> InvestigationQueueSnapshot {
        let guard = self.state.lock().expect("investigation queue state");
        InvestigationQueueSnapshot {
            enabled: self.config.enabled,
            worker_count: self.config.worker_count,
            max_pending_jobs: self.config.max_pending_jobs,
            time_budget_ms: self.config.time_budget_ms,
            queued_jobs: guard.queued_jobs,
            running_jobs: guard.running_jobs,
            completed_jobs: guard.completed_jobs,
            failed_jobs: guard.failed_jobs,
            timed_out_jobs: guard.timed_out_jobs,
            dropped_jobs: guard.dropped_jobs,
            last_failure_reason: guard.last_failure_reason.clone(),
        }
    }

    pub fn recent(
        &self,
        limit: usize,
    ) -> Result<Vec<InvestigationBundleRecord>, InvestigationError> {
        Ok(self.store.recent(limit)?)
    }

    pub fn load_by_hunt_id(
        &self,
        hunt_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, InvestigationError> {
        Ok(self.store.load_by_hunt_id(hunt_id)?)
    }

    pub fn load_by_receipt_id(
        &self,
        receipt_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, InvestigationError> {
        Ok(self.store.load_by_receipt_id(receipt_id)?)
    }

    pub fn health(&self) -> Result<InvestigationStoreHealth, InvestigationError> {
        Ok(self.store.health()?)
    }

    pub fn strategy_id(&self) -> &str {
        self.strategy.id()
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::{
        InvestigationCoordinator, InvestigationOutcome, InvestigationStatus, InvestigationStrategy,
    };
    use async_trait::async_trait;
    use std::time::{Duration, Instant};
    use swarm_core::config::{BundleStoreConfig, InvestigationConfig};
    use swarm_spine::{MemoryInvestigationBundleStore, ReplayBundle};

    fn config(enabled: bool, time_budget_ms: u64) -> InvestigationConfig {
        InvestigationConfig {
            enabled,
            worker_count: 1,
            max_pending_jobs: 1,
            time_budget_ms,
            bundle_store: BundleStoreConfig::Memory,
        }
    }

    fn sample_replay() -> ReplayBundle {
        use swarm_core::pheromone::ThreatClass;
        use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
        use swarm_policy::{ActionRequest, PolicyVerdict};
        use swarm_response::{ExecutionMode, ResponseReceipt, ResponseStatus};
        use swarm_spine::{AuditResponseRecord, AuditTrail, PolicyRecord};
        use swarm_whisker::{
            DetectionFinding, ProcessStartEvent, TelemetryEvent, TelemetryPayload,
        };

        ReplayBundle {
            bundle_id: "bundle:hunt-1:1".to_string(),
            event: TelemetryEvent {
                source: "synthetic".to_string(),
                event_id: "evt-1".to_string(),
                timestamp: 1_700_000_000,
                host_id: Some("host-1".to_string()),
                payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                    parent_process: "winword".to_string(),
                    process_name: "powershell".to_string(),
                    command_line: "powershell.exe -enc AAA=".to_string(),
                    user: Some("alice".to_string()),
                }),
            },
            findings: vec![DetectionFinding {
                finding_id: "finding-1".to_string(),
                event_id: "evt-1".to_string(),
                threat_class: ThreatClass::Execution,
                severity: Severity::Critical,
                confidence: 0.95,
                evidence: serde_json::json!({
                    "process_name": "powershell",
                    "user": "alice",
                    "command_line": "powershell.exe -enc AAA="
                }),
                strategy_id: "suspicious_process_tree".to_string(),
            }],
            deposits: Vec::new(),
            action_request: ActionRequest {
                hunt_id: HuntId("hunt-1".to_string()),
                requested_by: AgentId("whisker-a".to_string()),
                action: ResponseAction::BlockEgress {
                    target: "203.0.113.5".to_string(),
                },
                severity: Severity::Critical,
                evidence: serde_json::json!({"signal": "encoded-command"}),
            },
            audit: AuditTrail {
                trail_id: "trail:hunt-1:1".to_string(),
                hunt_id: "hunt-1".to_string(),
                related_receipt_ids: vec!["receipt-upstream-1".to_string()],
                detection: DetectionFinding {
                    finding_id: "finding-1".to_string(),
                    event_id: "evt-1".to_string(),
                    threat_class: ThreatClass::Execution,
                    severity: Severity::Critical,
                    confidence: 0.95,
                    evidence: serde_json::json!({
                        "process_name": "powershell",
                        "user": "alice",
                        "command_line": "powershell.exe -enc AAA="
                    }),
                    strategy_id: "suspicious_process_tree".to_string(),
                },
                policy: PolicyRecord {
                    verdict: PolicyVerdict::Allow,
                    reason: "allowed".to_string(),
                    lease: None,
                },
                response: AuditResponseRecord::Success(ResponseReceipt {
                    receipt_id: "receipt-response-1".to_string(),
                    action: "block_egress".to_string(),
                    mode: ExecutionMode::Enforced,
                    status: ResponseStatus::Executed,
                    summary: "egress blocked".to_string(),
                    details: serde_json::json!({}),
                }),
                created_at_ms: 1_700_000_000_123,
            },
        }
    }

    #[derive(Debug, Clone)]
    struct SlowInvestigator {
        delay_ms: u64,
        fail: bool,
    }

    #[async_trait]
    impl InvestigationStrategy for SlowInvestigator {
        fn id(&self) -> &str {
            "slow_test_investigator"
        }

        async fn investigate(&self, replay: &ReplayBundle) -> Result<InvestigationOutcome, String> {
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
            if self.fail {
                return Err("synthetic failure".to_string());
            }
            Ok(InvestigationOutcome {
                summary: format!("investigated {}", replay.audit.hunt_id),
                evidence_points: vec!["host_id=host-1".to_string()],
                correlation_keys: vec!["host:host-1".to_string()],
            })
        }
    }

    #[tokio::test]
    async fn submit_returns_before_slow_investigation_completes() {
        let coordinator = InvestigationCoordinator::new(
            config(true, 500),
            SlowInvestigator {
                delay_ms: 75,
                fail: false,
            },
            MemoryInvestigationBundleStore::default(),
        );

        let started = Instant::now();
        let record = coordinator.submit(&sample_replay()).unwrap().unwrap();
        let elapsed = started.elapsed();

        assert_eq!(record.status, InvestigationStatus::Queued);
        assert!(elapsed < Duration::from_millis(20));

        tokio::time::sleep(Duration::from_millis(125)).await;
        let persisted = coordinator.load_by_hunt_id("hunt-1").unwrap().unwrap();
        assert_eq!(persisted.bundle.status, InvestigationStatus::Completed);
        assert!(
            persisted
                .bundle
                .summary
                .as_deref()
                .unwrap()
                .contains("investigated")
        );
    }

    #[tokio::test]
    async fn timeout_degrades_without_failing_submission() {
        let coordinator = InvestigationCoordinator::new(
            config(true, 10),
            SlowInvestigator {
                delay_ms: 50,
                fail: false,
            },
            MemoryInvestigationBundleStore::default(),
        );

        let record = coordinator.submit(&sample_replay()).unwrap().unwrap();
        assert_eq!(record.status, InvestigationStatus::Queued);

        tokio::time::sleep(Duration::from_millis(60)).await;
        let persisted = coordinator
            .load_by_receipt_id("receipt-response-1")
            .unwrap()
            .unwrap();
        assert_eq!(persisted.bundle.status, InvestigationStatus::TimedOut);
        assert!(coordinator.snapshot().timed_out_jobs >= 1);
    }

    #[tokio::test]
    async fn queue_pressure_persists_visible_failure() {
        let coordinator = InvestigationCoordinator::new(
            config(true, 500),
            SlowInvestigator {
                delay_ms: 100,
                fail: false,
            },
            MemoryInvestigationBundleStore::default(),
        );

        let replay = sample_replay();
        let first = coordinator.submit(&replay).unwrap().unwrap();
        let second = coordinator.submit(&replay).unwrap().unwrap();

        assert_eq!(first.status, InvestigationStatus::Queued);
        assert_eq!(second.status, InvestigationStatus::Failed);
        assert!(
            second
                .failure_reason
                .as_deref()
                .unwrap()
                .contains("rejected")
        );
        assert!(coordinator.snapshot().dropped_jobs >= 1);
    }
}
