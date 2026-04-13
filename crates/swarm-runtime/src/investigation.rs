use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;
use tokio::time::timeout;

use swarm_core::config::InvestigationConfig;
use swarm_core::types::{ResponseAction, Severity};
use swarm_spine::{
    InvestigationBundle, InvestigationBundleLookup, InvestigationBundleRecord,
    InvestigationBundleStore, InvestigationDecision, InvestigationInterpretation,
    InvestigationPriority, InvestigationPriorityClass, InvestigationStatus,
    InvestigationStoreError, InvestigationVote,
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
    pub candidate_interpretations: Vec<InvestigationInterpretation>,
    pub vote_lineage: Vec<InvestigationVote>,
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
    pub budget_evictions: u64,
    pub starvation_preventions: u64,
    pub queue_budget_remaining: usize,
    pub highest_priority_score_basis_points: Option<u16>,
    pub oldest_job_age_ms: Option<u64>,
    pub last_completed_priority_score_basis_points: Option<u16>,
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
    budget_evictions: u64,
    starvation_preventions: u64,
    last_completed_priority_score_basis_points: Option<u16>,
    last_failure_reason: Option<String>,
}

#[derive(Debug, Clone)]
struct InvestigationJob {
    sequence: u64,
    replay: ReplayBundle,
    bundle: InvestigationBundle,
}

#[derive(Debug, Default)]
struct InvestigationScheduler {
    queue: Vec<InvestigationJob>,
    next_sequence: u64,
}

impl InvestigationScheduler {
    fn enqueue(&mut self, replay: ReplayBundle, bundle: InvestigationBundle) -> InvestigationJob {
        let job = InvestigationJob {
            sequence: self.next_sequence,
            replay,
            bundle,
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.queue.push(job.clone());
        job
    }

    fn remove_lowest_priority(
        &mut self,
        now_ms: i64,
        config: &InvestigationConfig,
    ) -> Option<InvestigationJob> {
        let index = self.lowest_priority_index(now_ms, config)?;
        Some(self.queue.remove(index))
    }

    fn pop_next(
        &mut self,
        now_ms: i64,
        config: &InvestigationConfig,
    ) -> Option<(InvestigationJob, bool)> {
        let index = self.highest_priority_index(now_ms, config)?;
        let job = self.queue.remove(index);
        let starvation_applied =
            starvation_boost_basis_points(job.bundle.queued_at_ms, now_ms, config) > 0;
        Some((job, starvation_applied))
    }

    fn lowest_effective_priority(&self, now_ms: i64, config: &InvestigationConfig) -> Option<u16> {
        self.lowest_priority_index(now_ms, config)
            .map(|index| effective_priority(&self.queue[index].bundle, now_ms, config))
    }

    fn highest_effective_priority(&self, now_ms: i64, config: &InvestigationConfig) -> Option<u16> {
        self.highest_priority_index(now_ms, config)
            .map(|index| effective_priority(&self.queue[index].bundle, now_ms, config))
    }

    fn oldest_job_age_ms(&self, now_ms: i64) -> Option<u64> {
        self.queue
            .iter()
            .map(|job| now_ms.saturating_sub(job.bundle.queued_at_ms).max(0) as u64)
            .max()
    }

    fn highest_priority_index(&self, now_ms: i64, config: &InvestigationConfig) -> Option<usize> {
        self.queue
            .iter()
            .enumerate()
            .max_by_key(|(_, job)| {
                (
                    effective_priority(&job.bundle, now_ms, config),
                    std::cmp::Reverse(job.bundle.queued_at_ms),
                    std::cmp::Reverse(job.sequence),
                )
            })
            .map(|(index, _)| index)
    }

    fn lowest_priority_index(&self, now_ms: i64, config: &InvestigationConfig) -> Option<usize> {
        self.queue
            .iter()
            .enumerate()
            .min_by_key(|(_, job)| {
                (
                    effective_priority(&job.bundle, now_ms, config),
                    job.bundle.queued_at_ms,
                    job.sequence,
                )
            })
            .map(|(index, _)| index)
    }
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

        let (candidate_interpretations, vote_lineage) =
            default_interpretations_and_votes(replay, &evidence_points);

        Ok(InvestigationOutcome {
            summary,
            evidence_points,
            correlation_keys,
            candidate_interpretations,
            vote_lineage,
        })
    }
}

/// Async coordinator that queues replay bundles for background investigation.
#[derive(Debug, Clone)]
pub struct InvestigationCoordinator<S, Store> {
    config: InvestigationConfig,
    strategy: S,
    store: Store,
    scheduler: Option<Arc<Mutex<InvestigationScheduler>>>,
    notify: Arc<Notify>,
    state: Arc<Mutex<InvestigationQueueState>>,
}

impl<S, Store> InvestigationCoordinator<S, Store>
where
    S: InvestigationStrategy,
    Store: InvestigationBundleStore + Clone + Send + Sync + 'static,
{
    pub fn new(config: InvestigationConfig, strategy: S, store: Store) -> Self {
        let state = Arc::new(Mutex::new(InvestigationQueueState::default()));
        let notify = Arc::new(Notify::new());

        if !config.enabled {
            return Self {
                config,
                strategy,
                store,
                scheduler: None,
                notify,
                state,
            };
        }

        let scheduler = Arc::new(Mutex::new(InvestigationScheduler::default()));

        for _worker_idx in 0..config.worker_count {
            let worker_state = Arc::clone(&state);
            let worker_scheduler = Arc::clone(&scheduler);
            let worker_notify = Arc::clone(&notify);
            let worker_store = store.clone();
            let worker_strategy = strategy.clone();
            let worker_config = config.clone();

            tokio::spawn(async move {
                loop {
                    let next_job = {
                        let mut guard = worker_scheduler
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner());
                        guard.pop_next(now_ms(), &worker_config)
                    };

                    let Some((job, starvation_applied)) = next_job else {
                        worker_notify.notified().await;
                        continue;
                    };

                    {
                        let mut guard = worker_state
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner());
                        guard.queued_jobs = guard.queued_jobs.saturating_sub(1);
                        guard.running_jobs = guard.running_jobs.saturating_add(1);
                        if starvation_applied {
                            guard.starvation_preventions =
                                guard.starvation_preventions.saturating_add(1);
                        }
                    }

                    let started_at_ms = now_ms();
                    let mut running_bundle = job.bundle.clone();
                    let starvation_boost = starvation_boost_basis_points(
                        running_bundle.queued_at_ms,
                        started_at_ms,
                        &worker_config,
                    );
                    running_bundle.priority.starvation_boost_basis_points = starvation_boost;
                    running_bundle.priority.total_basis_points =
                        base_priority(&running_bundle).saturating_add(starvation_boost);
                    running_bundle = running_bundle.with_status(
                        InvestigationStatus::Running,
                        Some(started_at_ms),
                        None,
                    );
                    if let Err(error) = worker_store.persist(&running_bundle) {
                        let mut guard = worker_state
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner());
                        guard.running_jobs = guard.running_jobs.saturating_sub(1);
                        guard.failed_jobs = guard.failed_jobs.saturating_add(1);
                        guard.last_failure_reason = Some(error.to_string());
                        continue;
                    }

                    let result = timeout(
                        Duration::from_millis(worker_config.time_budget_ms),
                        worker_strategy.investigate(&job.replay),
                    )
                    .await;
                    let completed_at_ms = now_ms();

                    let terminal_bundle = match result {
                        Ok(Ok(outcome)) => {
                            let decision = decide_outcome(
                                &outcome.candidate_interpretations,
                                &outcome.vote_lineage,
                                worker_config.ambiguity_margin_basis_points,
                            );
                            running_bundle.clone().with_summary(
                                outcome.summary,
                                outcome.evidence_points,
                                outcome.correlation_keys,
                                outcome.candidate_interpretations,
                                outcome.vote_lineage,
                                decision,
                                completed_at_ms,
                            )
                        }
                        Ok(Err(reason)) => running_bundle.clone().with_failure(
                            InvestigationStatus::Failed,
                            reason,
                            completed_at_ms,
                        ),
                        Err(_) => running_bundle.clone().with_failure(
                            InvestigationStatus::TimedOut,
                            format!(
                                "investigation exceeded {} ms time budget",
                                worker_config.time_budget_ms
                            ),
                            completed_at_ms,
                        ),
                    };

                    let persist_result = worker_store.persist(&terminal_bundle);
                    let mut guard = worker_state
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner());
                    guard.running_jobs = guard.running_jobs.saturating_sub(1);
                    match terminal_bundle.status {
                        InvestigationStatus::Completed => {
                            guard.completed_jobs = guard.completed_jobs.saturating_add(1);
                            guard.last_completed_priority_score_basis_points =
                                Some(terminal_bundle.priority.total_basis_points);
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
            scheduler: Some(scheduler),
            notify,
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
            compute_priority(replay, queued_at_ms),
        );
        let queued_record = self.store.persist(&queued_bundle)?;

        let Some(scheduler) = &self.scheduler else {
            return Ok(Some(queued_record));
        };

        let mut evicted_job = None;
        let mut rejected = false;
        {
            let mut guard = scheduler
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let now = now_ms();
            if guard.queue.len() >= self.config.max_pending_jobs {
                let lowest = guard
                    .lowest_effective_priority(now, &self.config)
                    .unwrap_or_default();
                let incoming = effective_priority(&queued_bundle, now, &self.config);
                if incoming > lowest {
                    evicted_job = guard.remove_lowest_priority(now, &self.config);
                } else {
                    rejected = true;
                }
            }
            if !rejected {
                guard.enqueue(replay.clone(), queued_bundle.clone());
            }
        }

        if let Some(evicted_job) = evicted_job {
            let failed_bundle = evicted_job.bundle.with_failure(
                InvestigationStatus::Failed,
                format!(
                    "investigation queue evicted lower-priority job under budget pressure for {}",
                    replay.audit.hunt_id
                ),
                now_ms(),
            );
            self.store.persist(&failed_bundle)?;
            let mut guard = self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            guard.dropped_jobs = guard.dropped_jobs.saturating_add(1);
            guard.failed_jobs = guard.failed_jobs.saturating_add(1);
            guard.budget_evictions = guard.budget_evictions.saturating_add(1);
            guard.last_failure_reason = failed_bundle.failure_reason.clone();
        }

        if rejected {
            let failed_bundle = queued_bundle.with_failure(
                InvestigationStatus::Failed,
                "investigation queue rejected submission because queue budget is reserved for higher-priority work"
                    .to_string(),
                now_ms(),
            );
            let failed_record = self.store.persist(&failed_bundle)?;
            let mut guard = self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            guard.dropped_jobs = guard.dropped_jobs.saturating_add(1);
            guard.failed_jobs = guard.failed_jobs.saturating_add(1);
            guard.last_failure_reason = failed_bundle.failure_reason.clone();
            return Ok(Some(failed_record));
        }

        {
            let mut guard = self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            guard.queued_jobs = guard.queued_jobs.saturating_add(1);
        }
        self.notify.notify_one();
        Ok(Some(queued_record))
    }

    pub fn snapshot(&self) -> InvestigationQueueSnapshot {
        let queue_observation = self.scheduler.as_ref().map(|scheduler| {
            let guard = scheduler
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let now = now_ms();
            (
                guard.queue.len(),
                self.config
                    .max_pending_jobs
                    .saturating_sub(guard.queue.len()),
                guard.highest_effective_priority(now, &self.config),
                guard.oldest_job_age_ms(now),
            )
        });
        let guard = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        InvestigationQueueSnapshot {
            enabled: self.config.enabled,
            worker_count: self.config.worker_count,
            max_pending_jobs: self.config.max_pending_jobs,
            time_budget_ms: self.config.time_budget_ms,
            queued_jobs: queue_observation
                .as_ref()
                .map(|(queued_jobs, _, _, _)| *queued_jobs)
                .unwrap_or(guard.queued_jobs),
            running_jobs: guard.running_jobs,
            completed_jobs: guard.completed_jobs,
            failed_jobs: guard.failed_jobs,
            timed_out_jobs: guard.timed_out_jobs,
            dropped_jobs: guard.dropped_jobs,
            budget_evictions: guard.budget_evictions,
            starvation_preventions: guard.starvation_preventions,
            queue_budget_remaining: queue_observation
                .as_ref()
                .map(|(_, remaining, _, _)| *remaining)
                .unwrap_or(self.config.max_pending_jobs),
            highest_priority_score_basis_points: queue_observation
                .as_ref()
                .and_then(|(_, _, highest, _)| *highest),
            oldest_job_age_ms: queue_observation
                .as_ref()
                .and_then(|(_, _, _, age_ms)| *age_ms),
            last_completed_priority_score_basis_points: guard
                .last_completed_priority_score_basis_points,
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

pub(crate) fn compute_priority(replay: &ReplayBundle, queued_at_ms: i64) -> InvestigationPriority {
    let severity_basis_points = severity_basis_points(replay.audit.detection.severity);
    let freshness_basis_points = freshness_basis_points(replay, queued_at_ms);
    let learned_value_basis_points = learned_value_basis_points(replay);
    let total_basis_points = severity_basis_points
        .saturating_add(freshness_basis_points)
        .saturating_add(learned_value_basis_points);
    InvestigationPriority {
        class: classify_priority(total_basis_points),
        severity_basis_points,
        freshness_basis_points,
        learned_value_basis_points,
        starvation_boost_basis_points: 0,
        total_basis_points,
    }
}

fn severity_basis_points(severity: Severity) -> u16 {
    match severity {
        Severity::Critical => 5_000,
        Severity::High => 3_800,
        Severity::Medium => 2_400,
        Severity::Low => 1_200,
    }
}

fn freshness_basis_points(replay: &ReplayBundle, queued_at_ms: i64) -> u16 {
    let event_timestamp_ms = replay.event.timestamp.saturating_mul(1_000);
    let age_ms = queued_at_ms.saturating_sub(event_timestamp_ms).max(0) as u64;
    if age_ms <= 60_000 {
        2_000
    } else if age_ms <= 300_000 {
        1_600
    } else if age_ms <= 900_000 {
        1_100
    } else {
        700
    }
}

fn learned_value_basis_points(replay: &ReplayBundle) -> u16 {
    let detection = &replay.audit.detection;
    let mut score = 0_u16;
    if detection.confidence >= 0.95 {
        score = score.saturating_add(1_200);
    } else if detection.confidence >= 0.8 {
        score = score.saturating_add(800);
    }
    if !replay.audit.all_receipt_ids().is_empty() {
        score = score.saturating_add(700);
    }
    if replay.event.host_id.is_some() {
        score = score.saturating_add(200);
    }
    if detection
        .evidence
        .get("user")
        .and_then(|value| value.as_str())
        .is_some()
    {
        score = score.saturating_add(200);
    }
    if detection
        .evidence
        .get("process_name")
        .and_then(|value| value.as_str())
        .is_some()
    {
        score = score.saturating_add(200);
    }
    score.saturating_add(response_action_value_basis_points(
        &replay.action_request.action,
    ))
}

fn response_action_value_basis_points(action: &ResponseAction) -> u16 {
    match action {
        ResponseAction::IsolateHost { .. } => 900,
        ResponseAction::RevokeCredential { .. } => 900,
        ResponseAction::KillProcess { .. } => 900,
        ResponseAction::DisableUserAccount { .. } => 900,
        ResponseAction::ForcePasswordReset { .. } => 850,
        ResponseAction::TerminateUserSession { .. } => 850,
        ResponseAction::QuarantineFile { .. } => 850,
        ResponseAction::BlockEgress { .. } => 750,
        ResponseAction::SinkholeDns { .. } => 750,
        ResponseAction::InjectFirewallRule { .. } => 800,
        ResponseAction::SuspendProcess { .. } => 700,
        ResponseAction::RemoveScheduledTask { .. } => 700,
        ResponseAction::TriggerEdrScan { .. } => 600,
        ResponseAction::Escalate { .. } => 650,
        ResponseAction::DeployDecoy { .. } => 500,
    }
}

fn classify_priority(total_basis_points: u16) -> InvestigationPriorityClass {
    match total_basis_points {
        8_000..=u16::MAX => InvestigationPriorityClass::Critical,
        5_500..=7_999 => InvestigationPriorityClass::High,
        3_000..=5_499 => InvestigationPriorityClass::Normal,
        _ => InvestigationPriorityClass::Deferred,
    }
}

fn base_priority(bundle: &InvestigationBundle) -> u16 {
    bundle
        .priority
        .severity_basis_points
        .saturating_add(bundle.priority.freshness_basis_points)
        .saturating_add(bundle.priority.learned_value_basis_points)
}

fn effective_priority(
    bundle: &InvestigationBundle,
    now_ms: i64,
    config: &InvestigationConfig,
) -> u16 {
    base_priority(bundle).saturating_add(starvation_boost_basis_points(
        bundle.queued_at_ms,
        now_ms,
        config,
    ))
}

fn starvation_boost_basis_points(
    queued_at_ms: i64,
    now_ms: i64,
    config: &InvestigationConfig,
) -> u16 {
    let age_ms = now_ms.saturating_sub(queued_at_ms).max(0) as u64;
    let accrued = ((age_ms * u64::from(config.starvation_boost_per_second_basis_points)) / 1_000)
        .min(u64::from(config.max_starvation_boost_basis_points));
    accrued as u16
}

fn default_interpretations_and_votes(
    replay: &ReplayBundle,
    evidence_points: &[String],
) -> (Vec<InvestigationInterpretation>, Vec<InvestigationVote>) {
    let detection = &replay.audit.detection;
    let primary_id = format!(
        "malicious_{}",
        format!("{:?}", detection.threat_class).to_ascii_lowercase()
    );
    let primary = InvestigationInterpretation {
        interpretation_id: primary_id.clone(),
        label: "Likely malicious activity".to_string(),
        rationale: format!(
            "Detection {} and response {} both support a malicious interpretation.",
            detection.strategy_id,
            replay.audit.response_kind()
        ),
        supporting_evidence: evidence_points.to_vec(),
    };

    let alternate_id = "benign_admin_tooling".to_string();
    let alternate = InvestigationInterpretation {
        interpretation_id: alternate_id.clone(),
        label: "Possible administrator or automation activity".to_string(),
        rationale: "Some suspicious command execution chains can still represent legitimate operator workflows.".to_string(),
        supporting_evidence: evidence_points
            .iter()
            .filter(|point| point.contains("user=") || point.contains("process_name="))
            .cloned()
            .collect(),
    };

    let mut interpretations = vec![primary, alternate];
    let mut votes = vec![InvestigationVote {
        voter: "threat_class".to_string(),
        interpretation_id: primary_id.clone(),
        confidence_basis_points: 5_800,
        rationale: format!(
            "Threat class {:?} materially raises malicious prior probability.",
            detection.threat_class
        ),
    }];

    if detection.strategy_id.contains("suspicious") {
        votes.push(InvestigationVote {
            voter: "strategy_signal".to_string(),
            interpretation_id: primary_id.clone(),
            confidence_basis_points: 2_200,
            rationale: format!(
                "Strategy {} already encodes suspicious behavior.",
                detection.strategy_id
            ),
        });
    }

    if evidence_points
        .iter()
        .any(|point| point.contains("parent_process=winword") || point.contains("command_line="))
    {
        let office_chain_id = "office_spawned_script_chain".to_string();
        interpretations.push(InvestigationInterpretation {
            interpretation_id: office_chain_id.clone(),
            label: "Office-spawned scripting chain".to_string(),
            rationale: "Office parent processes launching shells or scripting engines deserve separate review as a common intrusion shape.".to_string(),
            supporting_evidence: evidence_points
                .iter()
                .filter(|point| point.contains("parent_process=") || point.contains("command_line="))
                .cloned()
                .collect(),
        });
        votes.push(InvestigationVote {
            voter: "execution_chain".to_string(),
            interpretation_id: office_chain_id,
            confidence_basis_points: 3_200,
            rationale:
                "The parent/child process chain matches an office-to-script escalation pattern."
                    .to_string(),
        });
    }

    if detection
        .evidence
        .get("signature_valid")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        votes.push(InvestigationVote {
            voter: "signature_valid".to_string(),
            interpretation_id: alternate_id,
            confidence_basis_points: 2_400,
            rationale:
                "A valid signer meaningfully raises the chance of sanctioned operator tooling."
                    .to_string(),
        });
    } else {
        votes.push(InvestigationVote {
            voter: "unsigned_or_missing_signer".to_string(),
            interpretation_id: primary_id,
            confidence_basis_points: 1_600,
            rationale: "Missing or invalid signing context increases malicious likelihood."
                .to_string(),
        });
    }

    (interpretations, votes)
}

pub(crate) fn decide_outcome(
    interpretations: &[InvestigationInterpretation],
    votes: &[InvestigationVote],
    ambiguity_margin_basis_points: u16,
) -> InvestigationDecision {
    if interpretations.is_empty() {
        return InvestigationDecision::default();
    }

    let mut totals = BTreeMap::<String, u32>::new();
    for interpretation in interpretations {
        totals.insert(interpretation.interpretation_id.clone(), 0);
    }
    for vote in votes {
        let entry = totals.entry(vote.interpretation_id.clone()).or_default();
        *entry = entry.saturating_add(u32::from(vote.confidence_basis_points));
    }

    let mut ranked = totals.into_iter().collect::<Vec<_>>();
    ranked.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));

    let total_votes = ranked.iter().map(|(_, total)| *total).sum::<u32>();
    let top = ranked.first().cloned();
    let second = ranked.get(1).cloned();
    let selected_interpretation_id = top.as_ref().map(|(id, _)| id.clone());
    let top_votes = top.as_ref().map(|(_, total)| *total).unwrap_or_default();
    let second_votes = second.as_ref().map(|(_, total)| *total).unwrap_or_default();
    let final_confidence_basis_points = if total_votes == 0 {
        if interpretations.len() == 1 {
            10_000
        } else {
            5_000
        }
    } else {
        ((top_votes * 10_000) / total_votes).min(10_000) as u16
    };
    let ambiguous = interpretations.len() > 1
        && top_votes.saturating_sub(second_votes) <= u32::from(ambiguity_margin_basis_points);
    let rationale = selected_interpretation_id.as_ref().map(|selected| {
        format!(
            "selected {selected} with {top_votes} vote points over {second_votes}; ambiguous={ambiguous}"
        )
    });

    InvestigationDecision {
        selected_interpretation_id,
        final_confidence_basis_points,
        ambiguous,
        rationale,
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        InvestigationCoordinator, InvestigationOutcome, InvestigationStatus, InvestigationStrategy,
    };
    use async_trait::async_trait;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use swarm_core::config::{BundleStoreConfig, InvestigationConfig};
    use swarm_core::types::{ResponseAction, Severity};
    use swarm_spine::{
        InvestigationInterpretation, InvestigationVote, MemoryInvestigationBundleStore,
        ReplayBundle,
    };

    fn config(enabled: bool, time_budget_ms: u64) -> InvestigationConfig {
        InvestigationConfig {
            enabled,
            worker_count: 1,
            max_pending_jobs: 1,
            time_budget_ms,
            bundle_store: BundleStoreConfig::Memory,
            ..InvestigationConfig::default()
        }
    }

    fn sample_replay() -> ReplayBundle {
        sample_replay_with(
            "hunt-1",
            Severity::Critical,
            0.95,
            ResponseAction::BlockEgress {
                target: "203.0.113.5".to_string(),
            },
            5_000,
        )
    }

    fn sample_replay_with(
        hunt_id: &str,
        severity: Severity,
        confidence: f64,
        action: ResponseAction,
        recent_ms_ago: i64,
    ) -> ReplayBundle {
        use swarm_core::pheromone::ThreatClass;
        use swarm_core::types::{AgentId, HuntId};
        use swarm_policy::{ActionRequest, PolicyVerdict};
        use swarm_response::{ExecutionMode, ResponseReceipt, ResponseStatus};
        use swarm_spine::{AuditResponseRecord, AuditTrail, PolicyRecord};
        use swarm_whisker::{
            DetectionFinding, ProcessStartEvent, TelemetryEvent, TelemetryPayload,
        };

        let now_ms = super::now_ms();
        let event_timestamp_ms = now_ms.saturating_sub(recent_ms_ago);
        let event_id = format!("evt-{hunt_id}");
        let finding_id = format!("finding-{hunt_id}");
        let receipt_id = format!("receipt-response-{hunt_id}");
        let trail_id = format!("trail:{hunt_id}:1");

        ReplayBundle {
            bundle_id: format!("bundle:{hunt_id}:1"),
            event: TelemetryEvent {
                source: "synthetic".to_string(),
                event_id: event_id.clone(),
                timestamp: event_timestamp_ms / 1_000,
                host_id: Some("host-1".to_string()),
                payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                    parent_process: "winword".to_string(),
                    process_name: "powershell".to_string(),
                    command_line: "powershell.exe -enc AAA=".to_string(),
                    user: Some("alice".to_string()),
                    executable_path: None,
                    signer: None,
                    signature_valid: None,
                }),
            },
            findings: vec![DetectionFinding {
                finding_id: finding_id.clone(),
                event_id: event_id.clone(),
                threat_class: ThreatClass::Execution,
                severity,
                confidence,
                evidence: serde_json::json!({
                    "process_name": "powershell",
                    "user": "alice",
                    "command_line": "powershell.exe -enc AAA="
                }),
                strategy_id: "suspicious_process_tree".to_string(),
            }],
            deposits: Vec::new(),
            action_request: ActionRequest {
                hunt_id: HuntId(hunt_id.to_string()),
                requested_by: AgentId("whisker-a".to_string()),
                action,
                severity,
                evidence: serde_json::json!({"signal": "encoded-command"}),
            },
            rehearsal: None,
            audit: AuditTrail {
                trail_id,
                hunt_id: hunt_id.to_string(),
                related_receipt_ids: vec!["receipt-upstream-1".to_string()],
                detection: DetectionFinding {
                    finding_id,
                    event_id,
                    threat_class: ThreatClass::Execution,
                    severity,
                    confidence,
                    evidence: serde_json::json!({
                        "process_name": "powershell",
                        "user": "alice",
                        "command_line": "powershell.exe -enc AAA="
                    }),
                    strategy_id: "suspicious_process_tree".to_string(),
                },
                policy: PolicyRecord {
                    verdict: PolicyVerdict::Allow,
                    rule_name: "test.allow".to_string(),
                    reason: "allowed".to_string(),
                    lease: None,
                },
                response: AuditResponseRecord::Success(ResponseReceipt {
                    receipt_id,
                    action: "block_egress".to_string(),
                    mode: ExecutionMode::Enforced,
                    status: ResponseStatus::Executed,
                    summary: "egress blocked".to_string(),
                    details: serde_json::json!({}),
                    audit: Default::default(),
                }),
                created_at_ms: event_timestamp_ms.saturating_add(123),
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
                candidate_interpretations: Vec::new(),
                vote_lineage: Vec::new(),
            })
        }
    }

    #[derive(Debug, Clone)]
    struct OrderedInvestigator {
        delays_ms: BTreeMap<String, u64>,
        started_hunts: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl InvestigationStrategy for OrderedInvestigator {
        fn id(&self) -> &str {
            "ordered_test_investigator"
        }

        async fn investigate(&self, replay: &ReplayBundle) -> Result<InvestigationOutcome, String> {
            self.started_hunts
                .lock()
                .unwrap()
                .push(replay.audit.hunt_id.clone());
            let delay_ms = self
                .delays_ms
                .get(&replay.audit.hunt_id)
                .copied()
                .unwrap_or(0);
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            Ok(InvestigationOutcome {
                summary: format!("ordered {}", replay.audit.hunt_id),
                evidence_points: vec![format!("hunt_id={}", replay.audit.hunt_id)],
                correlation_keys: vec![format!("hunt:{}", replay.audit.hunt_id)],
                candidate_interpretations: Vec::new(),
                vote_lineage: Vec::new(),
            })
        }
    }

    #[derive(Debug, Clone)]
    struct AmbiguousInvestigator;

    #[async_trait]
    impl InvestigationStrategy for AmbiguousInvestigator {
        fn id(&self) -> &str {
            "ambiguous_test_investigator"
        }

        async fn investigate(&self, replay: &ReplayBundle) -> Result<InvestigationOutcome, String> {
            Ok(InvestigationOutcome {
                summary: format!("ambiguous {}", replay.audit.hunt_id),
                evidence_points: vec!["host_id=host-1".to_string()],
                correlation_keys: vec!["host:host-1".to_string()],
                candidate_interpretations: vec![
                    InvestigationInterpretation {
                        interpretation_id: "malicious_execution".to_string(),
                        label: "Malicious execution".to_string(),
                        rationale: "The encoded PowerShell chain is suspicious.".to_string(),
                        supporting_evidence: vec![
                            "command_line=powershell.exe -enc AAA=".to_string(),
                        ],
                    },
                    InvestigationInterpretation {
                        interpretation_id: "benign_admin_tooling".to_string(),
                        label: "Benign admin tooling".to_string(),
                        rationale: "Administrator or automation tooling can look similar."
                            .to_string(),
                        supporting_evidence: vec!["user=alice".to_string()],
                    },
                ],
                vote_lineage: vec![
                    InvestigationVote {
                        voter: "threat_class".to_string(),
                        interpretation_id: "malicious_execution".to_string(),
                        confidence_basis_points: 5_500,
                        rationale: "Execution-class detections bias toward malicious activity."
                            .to_string(),
                    },
                    InvestigationVote {
                        voter: "operator_context".to_string(),
                        interpretation_id: "benign_admin_tooling".to_string(),
                        confidence_basis_points: 5_000,
                        rationale: "The same pattern can represent sanctioned operator work."
                            .to_string(),
                    },
                ],
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
            .load_by_receipt_id("receipt-response-hunt-1")
            .unwrap()
            .unwrap();
        assert_eq!(persisted.bundle.status, InvestigationStatus::TimedOut);
        assert!(coordinator.snapshot().timed_out_jobs >= 1);
    }

    #[tokio::test]
    async fn queue_pressure_persists_visible_failure() {
        let mut queue_config = config(true, 500);
        queue_config.max_pending_jobs = 1;
        let coordinator = InvestigationCoordinator::new(
            queue_config,
            SlowInvestigator {
                delay_ms: 100,
                fail: false,
            },
            MemoryInvestigationBundleStore::default(),
        );

        let first = coordinator.submit(&sample_replay()).unwrap().unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let second = coordinator
            .submit(&sample_replay_with(
                "hunt-queued",
                Severity::High,
                0.9,
                ResponseAction::DeployDecoy {
                    decoy_type: "honeypot".to_string(),
                    target_zone: "dmz".to_string(),
                },
                5_000,
            ))
            .unwrap()
            .unwrap();
        let third = coordinator
            .submit(&sample_replay_with(
                "hunt-rejected",
                Severity::Low,
                0.8,
                ResponseAction::DeployDecoy {
                    decoy_type: "canary".to_string(),
                    target_zone: "dmz".to_string(),
                },
                5_000,
            ))
            .unwrap()
            .unwrap();

        assert_eq!(first.status, InvestigationStatus::Queued);
        assert_eq!(second.status, InvestigationStatus::Queued);
        assert_eq!(third.status, InvestigationStatus::Failed);
        assert!(
            third
                .failure_reason
                .as_deref()
                .unwrap()
                .contains("rejected")
        );
        assert!(coordinator.snapshot().dropped_jobs >= 1);
    }

    #[tokio::test]
    async fn higher_priority_submission_evicts_lower_priority_job_under_budget_pressure() {
        let mut queue_config = config(true, 500);
        queue_config.max_pending_jobs = 1;
        let coordinator = InvestigationCoordinator::new(
            queue_config,
            OrderedInvestigator {
                delays_ms: BTreeMap::from([("hunt-first".to_string(), 150)]),
                started_hunts: Arc::new(Mutex::new(Vec::new())),
            },
            MemoryInvestigationBundleStore::default(),
        );

        coordinator
            .submit(&sample_replay_with(
                "hunt-first",
                Severity::Critical,
                0.98,
                ResponseAction::BlockEgress {
                    target: "203.0.113.10".to_string(),
                },
                1_000,
            ))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        coordinator
            .submit(&sample_replay_with(
                "hunt-low",
                Severity::Low,
                0.6,
                ResponseAction::DeployDecoy {
                    decoy_type: "honeypot".to_string(),
                    target_zone: "dmz".to_string(),
                },
                1_000,
            ))
            .unwrap();
        coordinator
            .submit(&sample_replay_with(
                "hunt-high",
                Severity::Critical,
                0.99,
                ResponseAction::IsolateHost {
                    host_id: "host-1".to_string(),
                },
                1_000,
            ))
            .unwrap();

        tokio::time::sleep(Duration::from_millis(250)).await;

        let evicted = coordinator.load_by_hunt_id("hunt-low").unwrap().unwrap();
        let retained = coordinator.load_by_hunt_id("hunt-high").unwrap().unwrap();
        assert_eq!(evicted.bundle.status, InvestigationStatus::Failed);
        assert!(
            evicted
                .bundle
                .failure_reason
                .as_deref()
                .unwrap()
                .contains("evicted lower-priority")
        );
        assert_eq!(retained.bundle.status, InvestigationStatus::Completed);
        assert!(coordinator.snapshot().budget_evictions >= 1);
    }

    #[tokio::test]
    async fn older_job_gains_starvation_boost_and_runs_before_newer_job() {
        let mut queue_config = config(true, 500);
        queue_config.max_pending_jobs = 2;
        queue_config.starvation_boost_per_second_basis_points = 5_000;
        queue_config.max_starvation_boost_basis_points = 5_000;
        let started_hunts = Arc::new(Mutex::new(Vec::new()));
        let coordinator = InvestigationCoordinator::new(
            queue_config,
            OrderedInvestigator {
                delays_ms: BTreeMap::from([("hunt-first".to_string(), 150)]),
                started_hunts: Arc::clone(&started_hunts),
            },
            MemoryInvestigationBundleStore::default(),
        );

        coordinator
            .submit(&sample_replay_with(
                "hunt-first",
                Severity::Critical,
                0.99,
                ResponseAction::BlockEgress {
                    target: "203.0.113.10".to_string(),
                },
                1_000,
            ))
            .unwrap();
        coordinator
            .submit(&sample_replay_with(
                "hunt-old",
                Severity::High,
                0.8,
                ResponseAction::DeployDecoy {
                    decoy_type: "honeypot".to_string(),
                    target_zone: "dmz".to_string(),
                },
                1_000,
            ))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        coordinator
            .submit(&sample_replay_with(
                "hunt-new",
                Severity::High,
                0.8,
                ResponseAction::BlockEgress {
                    target: "203.0.113.20".to_string(),
                },
                1_000,
            ))
            .unwrap();

        tokio::time::sleep(Duration::from_millis(250)).await;

        let started = started_hunts.lock().unwrap().clone();
        assert_eq!(started[0], "hunt-first");
        assert_eq!(started[1], "hunt-old");
        assert_eq!(started[2], "hunt-new");
        assert!(coordinator.snapshot().starvation_preventions >= 1);
    }

    #[tokio::test]
    async fn ambiguous_investigation_persists_vote_lineage_and_final_decision() {
        let coordinator = InvestigationCoordinator::new(
            config(true, 250),
            AmbiguousInvestigator,
            MemoryInvestigationBundleStore::default(),
        );

        let record = coordinator
            .submit(&sample_replay_with(
                "hunt-ambiguous",
                Severity::High,
                0.92,
                ResponseAction::BlockEgress {
                    target: "203.0.113.25".to_string(),
                },
                1_000,
            ))
            .unwrap()
            .unwrap();
        assert_eq!(record.status, InvestigationStatus::Queued);

        tokio::time::sleep(Duration::from_millis(50)).await;
        let persisted = coordinator
            .load_by_hunt_id("hunt-ambiguous")
            .unwrap()
            .unwrap();
        assert_eq!(persisted.bundle.status, InvestigationStatus::Completed);
        assert_eq!(persisted.bundle.candidate_interpretations.len(), 2);
        assert_eq!(persisted.bundle.vote_lineage.len(), 2);
        assert!(persisted.bundle.decision.ambiguous);
        assert_eq!(
            persisted
                .bundle
                .decision
                .selected_interpretation_id
                .as_deref(),
            Some("malicious_execution")
        );
        assert!(persisted.bundle.decision.final_confidence_basis_points >= 5_000);
    }
}
