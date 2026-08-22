//! Deterministic clock and scheduling seams for the collective hypothesis graph.
//!
//! `GraphLogicalTime` is owned by `swarm-core`.  This module deliberately does
//! not introduce another time representation: runtime decisions accept the
//! core value and the injected clock exposes only the millisecond observation
//! needed to construct one.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use swarm_core::hypothesis_graph::{
    CONFIDENCE_BASIS_POINTS, GraphAdmissionError, GraphLogicalTime, GraphResourceLimits,
    GraphSchedulerKey, TaskId, TaskKind,
};

/// Clock seam used by graph orchestration.
///
/// Implementations may observe a host clock, but callers must convert that
/// observation into an explicit [`GraphLogicalTime`] before putting it into
/// deterministic state.  The scheduler in this module never reads a clock.
pub trait GraphClock: Send + Sync {
    /// Return the current observation in Unix milliseconds.
    fn now_ms(&self) -> i64;
}

/// A clock fixed to one logical graph instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedGraphClock {
    start: GraphLogicalTime,
}

impl FixedGraphClock {
    /// Construct a fixed clock.  Validation is performed when the value is
    /// admitted into a graph decision, matching the core contract.
    pub const fn new(start: GraphLogicalTime) -> Self {
        Self { start }
    }

    /// Return the fixed logical instant.
    pub const fn start(&self) -> GraphLogicalTime {
        self.start
    }
}

impl GraphClock for FixedGraphClock {
    fn now_ms(&self) -> i64 {
        self.start.as_millis()
    }
}

/// Blue/runtime-only host-clock observation.
///
/// This type is intentionally not used by [`DeterministicScheduler`].  A
/// production adapter may record its value as an operational observation and
/// then explicitly choose a logical time for graph state.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemObservationClock;

impl GraphClock for SystemObservationClock {
    fn now_ms(&self) -> i64 {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or(0);
        i64::try_from(millis).unwrap_or(i64::MAX)
    }
}

/// A task admitted to the deterministic scheduler.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScheduledGraphTask {
    pub key: GraphSchedulerKey,
}

impl ScheduledGraphTask {
    pub fn new(
        ready_at: GraphLogicalTime,
        task_kind: TaskKind,
        priority_basis_points: u16,
        task_id: TaskId,
    ) -> Result<Self, GraphAdmissionError> {
        if priority_basis_points > CONFIDENCE_BASIS_POINTS {
            return Err(GraphAdmissionError::InvalidConfidence {
                value: priority_basis_points,
            });
        }
        Ok(Self {
            key: GraphSchedulerKey::new(ready_at, task_kind, priority_basis_points, task_id)?,
        })
    }

    pub fn ready_at(&self) -> GraphLogicalTime {
        self.key.ready_at
    }

    pub fn task_kind(&self) -> TaskKind {
        self.key.task_kind
    }

    pub fn priority_basis_points(&self) -> u16 {
        self.key.priority_basis_points
    }

    pub fn task_id(&self) -> &TaskId {
        &self.key.task_id
    }
}

/// Deterministic ready queue.
///
/// Ordering is exactly the core key ordering: logical ready time, task kind,
/// stable priority, then task ID.  A task ID can be scheduled only once; an
/// exact retry is idempotent, while a retry with a different key fails closed.
#[derive(Debug, Clone)]
pub struct DeterministicScheduler {
    ready: BTreeSet<GraphSchedulerKey>,
    by_task_id: BTreeMap<TaskId, GraphSchedulerKey>,
    tombstones: BTreeMap<TaskId, GraphSchedulerKey>,
    limits: GraphResourceLimits,
}

impl Default for DeterministicScheduler {
    fn default() -> Self {
        Self::from_validated_limits(GraphResourceLimits::default())
    }
}

impl DeterministicScheduler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a scheduler with explicit graph resource ceilings.
    ///
    /// `max_tasks` covers all retained task IDs, including consumed-task
    /// tombstones. This prevents a long-lived runtime from growing its
    /// idempotency history without bound while preserving exact retries.
    pub fn with_limits(limits: GraphResourceLimits) -> Result<Self, GraphAdmissionError> {
        limits.validate()?;
        Ok(Self::from_validated_limits(limits))
    }

    pub(crate) fn from_validated_limits(limits: GraphResourceLimits) -> Self {
        debug_assert!(limits.validate().is_ok());
        Self {
            ready: BTreeSet::new(),
            by_task_id: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            limits,
        }
    }

    pub fn new_with_limits(limits: GraphResourceLimits) -> Result<Self, GraphAdmissionError> {
        Self::with_limits(limits)
    }

    pub fn limits(&self) -> &GraphResourceLimits {
        &self.limits
    }

    /// Admit a complete scheduler key.
    ///
    /// Returns `true` when a new key was inserted and `false` for an exact
    /// idempotent retry.
    pub fn schedule(&mut self, key: GraphSchedulerKey) -> Result<bool, GraphAdmissionError> {
        key.validate()?;
        if let Some(existing) = self.by_task_id.get(&key.task_id) {
            if existing == &key {
                return Ok(false);
            }
            return Err(GraphAdmissionError::InvalidTransition {
                reason: format!(
                    "task `{}` was already scheduled with a different deterministic key",
                    key.task_id
                ),
            });
        }
        if let Some(existing) = self.tombstones.get(&key.task_id) {
            if existing == &key {
                return Ok(false);
            }
            return Err(GraphAdmissionError::InvalidTransition {
                reason: format!(
                    "task `{}` was already consumed with a different deterministic key",
                    key.task_id
                ),
            });
        }
        if self.retained_len() >= self.limits.max_tasks {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "scheduler.tasks".to_string(),
                limit: self.limits.max_tasks,
            });
        }
        self.by_task_id.insert(key.task_id.clone(), key.clone());
        self.ready.insert(key);
        Ok(true)
    }

    /// Construct and admit one scheduler key.
    pub fn schedule_task(
        &mut self,
        ready_at: GraphLogicalTime,
        task_kind: TaskKind,
        priority_basis_points: u16,
        task_id: TaskId,
    ) -> Result<bool, GraphAdmissionError> {
        let task = ScheduledGraphTask::new(ready_at, task_kind, priority_basis_points, task_id)?;
        self.schedule(task.key)
    }

    /// Remove and return the next task in deterministic order.  This
    /// crate-private primitive assumes the caller already checked readiness;
    /// external callers must use [`Self::pop_ready`].
    pub(crate) fn pop_next(&mut self) -> Option<GraphSchedulerKey> {
        let key = self.ready.pop_first()?;
        self.by_task_id.remove(&key.task_id);
        self.tombstones.insert(key.task_id.clone(), key.clone());
        Some(key)
    }

    /// Pop work only when its declared logical ready time has arrived.
    pub fn pop_ready(
        &mut self,
        now: GraphLogicalTime,
    ) -> Result<Option<GraphSchedulerKey>, GraphAdmissionError> {
        now.validate()?;
        if self.ready.first().is_some_and(|key| key.ready_at <= now) {
            Ok(self.pop_next())
        } else {
            Ok(None)
        }
    }

    /// Borrow the next task without changing scheduler state.
    pub fn peek(&self) -> Option<&GraphSchedulerKey> {
        self.ready.first()
    }

    /// Return a deterministic snapshot of all pending tasks.
    pub fn ordered(&self) -> Vec<GraphSchedulerKey> {
        self.ready.iter().cloned().collect()
    }

    pub fn contains(&self, task_id: &TaskId) -> bool {
        self.by_task_id.contains_key(task_id)
    }

    pub fn len(&self) -> usize {
        self.ready.len()
    }

    /// Number of task IDs retained by the scheduler, including tombstones.
    pub fn retained_len(&self) -> usize {
        self.by_task_id.len().saturating_add(self.tombstones.len())
    }

    pub fn tombstone_len(&self) -> usize {
        self.tombstones.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ready.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{DeterministicScheduler, FixedGraphClock, GraphClock};
    use swarm_core::hypothesis_graph::{
        GraphAdmissionError, GraphLogicalTime, GraphResourceLimits, TaskId, TaskKind,
    };

    #[test]
    fn fixed_clock_returns_the_single_core_logical_time() {
        let clock = FixedGraphClock::new(GraphLogicalTime::new(42));
        assert_eq!(clock.now_ms(), 42);
        assert_eq!(clock.start(), GraphLogicalTime::new(42));
    }

    #[test]
    fn scheduler_uses_only_the_declared_key_fields() {
        let mut scheduler = DeterministicScheduler::new();
        scheduler
            .schedule_task(
                GraphLogicalTime::new(20),
                TaskKind::FalsifyHypothesis,
                10,
                TaskId::new("task:z"),
            )
            .unwrap();
        scheduler
            .schedule_task(
                GraphLogicalTime::new(10),
                TaskKind::AcquireEvidence,
                500,
                TaskId::new("task:b"),
            )
            .unwrap();
        scheduler
            .schedule_task(
                GraphLogicalTime::new(10),
                TaskKind::AcquireEvidence,
                500,
                TaskId::new("task:a"),
            )
            .unwrap();

        let ids = scheduler
            .ordered()
            .into_iter()
            .map(|key| key.task_id)
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            [
                TaskId::new("task:a"),
                TaskId::new("task:b"),
                TaskId::new("task:z")
            ]
        );
    }

    #[test]
    fn insertion_perturbation_is_idempotent_and_order_invariant() {
        let tasks = [
            (20, TaskKind::ChallengeEdge, 20, "task:c"),
            (10, TaskKind::AcquireEvidence, 40, "task:b"),
            (10, TaskKind::AcquireEvidence, 40, "task:a"),
            (10, TaskKind::FalsifyHypothesis, 1, "task:d"),
        ];
        let mut first = DeterministicScheduler::new();
        for (ready_at, kind, priority, task_id) in tasks {
            first
                .schedule_task(
                    GraphLogicalTime::new(ready_at),
                    kind,
                    priority,
                    TaskId::new(task_id),
                )
                .unwrap();
        }

        let mut second = DeterministicScheduler::new();
        for (ready_at, kind, priority, task_id) in tasks.into_iter().rev() {
            second
                .schedule_task(
                    GraphLogicalTime::new(ready_at),
                    kind,
                    priority,
                    TaskId::new(task_id),
                )
                .unwrap();
        }
        assert_eq!(first.ordered(), second.ordered());
        assert!(
            !first
                .schedule_task(
                    GraphLogicalTime::new(20),
                    TaskKind::ChallengeEdge,
                    20,
                    TaskId::new("task:c"),
                )
                .unwrap()
        );
        assert!(
            first
                .schedule_task(
                    GraphLogicalTime::new(21),
                    TaskKind::ChallengeEdge,
                    20,
                    TaskId::new("task:c"),
                )
                .is_err()
        );
    }

    #[test]
    fn popped_task_tombstone_rejects_changed_key_and_accepts_exact_retry() {
        let mut scheduler = DeterministicScheduler::new();
        let task_id = TaskId::new("task:tombstone");
        scheduler
            .schedule_task(
                GraphLogicalTime::new(10),
                TaskKind::AcquireEvidence,
                10,
                task_id.clone(),
            )
            .unwrap();
        let popped = scheduler
            .pop_ready(GraphLogicalTime::new(10))
            .unwrap()
            .expect("task should be ready");
        assert_eq!(popped.task_id, task_id);
        assert!(!scheduler.contains(&task_id));
        assert!(
            !scheduler
                .schedule_task(
                    GraphLogicalTime::new(10),
                    TaskKind::AcquireEvidence,
                    10,
                    task_id.clone(),
                )
                .unwrap()
        );
        assert!(
            scheduler
                .schedule_task(
                    GraphLogicalTime::new(11),
                    TaskKind::AcquireEvidence,
                    10,
                    task_id,
                )
                .is_err()
        );
    }

    #[test]
    fn scheduler_does_not_consume_future_work_before_ready_time() {
        let mut scheduler = DeterministicScheduler::new();
        scheduler
            .schedule_task(
                GraphLogicalTime::new(20),
                TaskKind::AcquireEvidence,
                1,
                TaskId::new("task:future"),
            )
            .unwrap();
        assert!(
            scheduler
                .pop_ready(GraphLogicalTime::new(19))
                .unwrap()
                .is_none()
        );
        assert_eq!(scheduler.retained_len(), 1);
        assert!(
            scheduler
                .pop_ready(GraphLogicalTime::new(20))
                .unwrap()
                .is_some()
        );
        assert_eq!(scheduler.tombstone_len(), 1);
    }

    #[test]
    fn custom_task_limit_bounds_ready_and_lifetime_tombstones() {
        let limits = GraphResourceLimits {
            max_tasks: 2,
            ..GraphResourceLimits::default()
        };
        let mut scheduler = DeterministicScheduler::with_limits(limits).unwrap();
        assert_eq!(scheduler.limits().max_tasks, 2);

        let first = TaskId::new("task:bounded:first");
        let second = TaskId::new("task:bounded:second");
        let third = TaskId::new("task:bounded:third");
        scheduler
            .schedule_task(
                GraphLogicalTime::new(1),
                TaskKind::AcquireEvidence,
                1,
                first.clone(),
            )
            .unwrap();
        scheduler
            .schedule_task(
                GraphLogicalTime::new(2),
                TaskKind::AcquireEvidence,
                1,
                second,
            )
            .unwrap();
        assert_eq!(scheduler.len(), 2);
        assert_eq!(scheduler.retained_len(), 2);

        scheduler
            .pop_ready(GraphLogicalTime::new(1))
            .unwrap()
            .expect("first task should be popped");
        assert_eq!(scheduler.len(), 1);
        assert_eq!(scheduler.tombstone_len(), 1);
        assert_eq!(scheduler.retained_len(), 2);

        let error = scheduler
            .schedule_task(
                GraphLogicalTime::new(3),
                TaskKind::AcquireEvidence,
                1,
                third,
            )
            .expect_err("ready plus tombstone must consume the whole task budget");
        assert!(matches!(
            error,
            GraphAdmissionError::ResourceLimitExceeded { resource, limit }
                if resource == "scheduler.tasks" && limit == 2
        ));
        assert!(
            !scheduler
                .schedule_task(
                    GraphLogicalTime::new(1),
                    TaskKind::AcquireEvidence,
                    1,
                    first,
                )
                .unwrap()
        );
        assert_eq!(scheduler.retained_len(), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn host_clock_and_async_yield_perturbations_do_not_change_queue() {
        async fn run(delays: Vec<(usize, i64, TaskKind, u16, &'static str)>) -> Vec<TaskId> {
            let scheduler = Arc::new(Mutex::new(DeterministicScheduler::new()));
            let mut handles = Vec::new();
            for (delay, ready_at, task_kind, priority, task_id) in delays {
                let scheduler = Arc::clone(&scheduler);
                handles.push(tokio::spawn(async move {
                    for _ in 0..delay {
                        tokio::task::yield_now().await;
                    }
                    scheduler
                        .lock()
                        .expect("scheduler lock")
                        .schedule_task(
                            GraphLogicalTime::new(ready_at),
                            task_kind,
                            priority,
                            TaskId::new(task_id),
                        )
                        .expect("schedule");
                }));
            }
            for handle in handles {
                handle.await.expect("scheduler task");
            }
            scheduler
                .lock()
                .expect("scheduler lock")
                .ordered()
                .into_iter()
                .map(|key| key.task_id)
                .collect()
        }

        let first_clock = FixedGraphClock::new(GraphLogicalTime::new(1));
        let second_clock = FixedGraphClock::new(GraphLogicalTime::new(9_999_999));
        assert_ne!(first_clock.now_ms(), second_clock.now_ms());
        let first = run(vec![
            (3, 10, TaskKind::AcquireEvidence, 5, "task:b"),
            (0, 10, TaskKind::AcquireEvidence, 5, "task:a"),
            (2, 20, TaskKind::FalsifyHypothesis, 1, "task:c"),
        ])
        .await;
        let second = run(vec![
            (0, 20, TaskKind::FalsifyHypothesis, 1, "task:c"),
            (2, 10, TaskKind::AcquireEvidence, 5, "task:a"),
            (1, 10, TaskKind::AcquireEvidence, 5, "task:b"),
        ])
        .await;
        assert_eq!(first, second);
    }
}
