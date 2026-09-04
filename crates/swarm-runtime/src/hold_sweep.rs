//! Expire holds past their TTL and resolve stalled decisions, on a running
//! daemon — not only after a restart. Same loop shape as `ContainmentSweep`.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

use crate::held_action::{HeldAction, HeldActionStore, HoldState};
use crate::runtime_events::{RuntimeEvent, RuntimeEventBroadcaster, now_ms};

/// One tick's outcome.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HoldSweepReport {
    /// Holds moved `created|notified|armed -> expired`. No action was taken.
    pub expired: Vec<String>,
    /// Holds moved `deciding -> failed` with the unknown-outcome refusal.
    pub stalled: Vec<String>,
    /// Store errors, one string each. The sweep never panics.
    pub failures: Vec<String>,
}

/// The sweep. Reads the clock once per tick.
pub struct HoldSweep {
    store: Arc<dyn HeldActionStore>,
    events: Option<RuntimeEventBroadcaster>,
    decide_stall_ms: u64,
}

impl HoldSweep {
    /// Bundle the daemon's one store and broadcaster with
    /// `runtime.response.decide_stall_ms`.
    pub fn new(
        store: Arc<dyn HeldActionStore>,
        events: Option<RuntimeEventBroadcaster>,
        decide_stall_ms: u64,
    ) -> Self {
        Self {
            store,
            events,
            decide_stall_ms,
        }
    }

    fn publish(&self, hold: &HeldAction, state: HoldState, at_ms: i64) {
        if let Some(events) = &self.events {
            events.publish(RuntimeEvent::ResponseHeld {
                emitted_at_ms: at_ms,
                hold_id: hold.hold_id.clone(),
                hunt_id: hold.action_request.hunt_id.0.clone(),
                action_kind: hold.action_request.action.kind().to_string(),
                severity: hold.action_request.severity,
                expires_at_ms: hold.expires_at_ms,
                state,
            });
        }
    }

    /// Expiry first, then stall resolution. Every row either method returns
    /// is published as its own `ResponseHeld`, so the bridge can publish the
    /// terminal card without polling.
    pub fn tick(&self, now_ms: i64) -> HoldSweepReport {
        let mut report = HoldSweepReport::default();
        match self.store.expire_due(now_ms) {
            Ok(expired) => {
                for hold in expired {
                    self.publish(&hold, HoldState::Expired, now_ms);
                    report.expired.push(hold.hold_id);
                }
            }
            Err(error) => report.failures.push(format!("expire_due: {error}")),
        }
        match self
            .store
            .fail_stalled_decisions(now_ms, self.decide_stall_ms)
        {
            Ok(stalled) => {
                for hold in stalled {
                    tracing::error!(
                        module = module_path!(),
                        hold_id = %hold.hold_id,
                        "decision stalled past decide_stall_ms; resolved to failed with an unknown outcome"
                    );
                    self.publish(&hold, HoldState::Failed, now_ms);
                    report.stalled.push(hold.hold_id);
                }
            }
            Err(error) => report
                .failures
                .push(format!("fail_stalled_decisions: {error}")),
        }
        report
    }

    /// Tick every `interval_ms` until the shutdown flag flips. Missed ticks
    /// are skipped, never bursted.
    pub async fn run_until_shutdown(&self, interval_ms: u64, mut shutdown: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms.max(1)));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    if *shutdown.borrow() {
                        break;
                    }
                    let report = self.tick(now_ms());
                    if !report.expired.is_empty()
                        || !report.stalled.is_empty()
                        || !report.failures.is_empty()
                    {
                        tracing::info!(
                            module = module_path!(),
                            expired = report.expired.len(),
                            stalled = report.stalled.len(),
                            failures = report.failures.len(),
                            "hold sweep tick"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::held_action::{HoldDecision, HoldState, MemoryHeldActionStore};
    use crate::held_action_fixtures::{T0, fixture_hold};
    use crate::runtime_events::{RuntimeEvent, RuntimeEventBroadcaster};
    use swarm_core::types::ResponseAction;

    fn store_with(state: HoldState) -> (Arc<MemoryHeldActionStore>, String) {
        let store = Arc::new(MemoryHeldActionStore::default());
        let mut hold = fixture_hold(
            ResponseAction::IsolateHost {
                host_id: "h".into(),
            },
            T0,
        );
        hold.state = state;
        let id = hold.hold_id.clone();
        store.create(hold).unwrap();
        (store, id)
    }

    fn sweep_with(
        state: HoldState,
    ) -> (
        HoldSweep,
        Arc<MemoryHeldActionStore>,
        tokio::sync::broadcast::Receiver<RuntimeEvent>,
        String,
    ) {
        let (store, id) = store_with(state);
        let events = RuntimeEventBroadcaster::new(16);
        let rx = events.subscribe();
        (
            HoldSweep::new(store.clone(), Some(events), 60_000),
            store,
            rx,
            id,
        )
    }

    #[test]
    fn a_hold_is_expired_at_its_ttl_not_before_and_the_record_is_published() {
        let (sweep, store, mut rx, id) = sweep_with(HoldState::Notified);
        assert!(sweep.tick(T0 + 3_600_000 - 1).expired.is_empty());
        assert_eq!(store.get(&id).unwrap().unwrap().state, HoldState::Notified);
        let report = sweep.tick(T0 + 3_600_000);
        assert_eq!(report.expired, vec![id.clone()]);
        let hold = store.get(&id).unwrap().unwrap();
        assert_eq!(hold.state, HoldState::Expired);
        assert!(
            hold.decision.is_none(),
            "expiry takes no action and writes no decision"
        );
        match rx.try_recv().unwrap() {
            RuntimeEvent::ResponseHeld { state, hold_id, .. } => {
                assert_eq!(state, HoldState::Expired);
                assert_eq!(hold_id, id);
            }
            other => panic!("{other:?}"),
        }
        // Still listed, so /handoff can count it (INV-19).
        assert_eq!(store.list(true, 10).unwrap().len(), 1);
        assert!(store.list(false, 10).unwrap().is_empty());
        // And a second tick neither re-expires nor re-publishes it.
        assert!(sweep.tick(T0 + 3_600_001).expired.is_empty());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn the_sweep_resolves_a_stalled_decision_without_a_restart() {
        let (store, id) = store_with(HoldState::Notified);
        store
            .begin_decision(&id, &"aa".repeat(32), T0 + 100)
            .unwrap();
        let events = RuntimeEventBroadcaster::new(16);
        let mut rx = events.subscribe();
        let sweep = HoldSweep::new(store.clone(), Some(events), 60_000);

        assert!(sweep.tick(T0 + 100 + 59_999).stalled.is_empty());
        let report = sweep.tick(T0 + 100 + 60_000);
        assert_eq!(report.stalled, vec![id.clone()]);
        let hold = store.get(&id).unwrap().unwrap();
        assert_eq!(hold.state, HoldState::Failed);
        let decision = hold.decision.unwrap();
        assert!(!decision.dispatched);
        assert!(
            decision
                .refusal
                .unwrap()
                .reason
                .contains("whether the action ran is unknown")
        );
        match rx.try_recv().unwrap() {
            RuntimeEvent::ResponseHeld { state, .. } => assert_eq!(state, HoldState::Failed),
            other => panic!("{other:?}"),
        }
    }

    /// A refused hold is terminal. The sweep must not touch it, must not
    /// publish about it, and must not turn it into an expiry or a failure.
    #[test]
    fn the_sweep_never_reopens_or_republishes_a_refused_hold() {
        let (store, id) = store_with(HoldState::Notified);
        let claimed = store
            .begin_decision(&id, &"aa".repeat(32), T0 + 100)
            .unwrap();
        let mut record = crate::held_action::HoldDecisionRecord {
            decision: HoldDecision::Refuse,
            operator_id: "perch-dev-operator".into(),
            voter_id: format!("swarm:ed25519:{}", "ab".repeat(32)),
            rationale_sha256: None,
            hold_notice_published: false,
            governance_clearance: crate::held_action::GovernanceClearance::NotRequired,
            decided_at_ms: T0 + 100,
            nostr_intent_event_id: "aa".repeat(32),
            signature: None,
            rationale: None,
            outcome: crate::held_action::HoldOutcome::RefusedByOperator,
            dispatched: false,
            receipt_id: None,
            audit_trail_id: None,
            refusal: None,
        };
        record.hold_notice_published = claimed.notified_at_ms.is_some();
        store
            .complete_decision(&id, record, HoldState::Refused)
            .unwrap();

        let events = RuntimeEventBroadcaster::new(16);
        let mut rx = events.subscribe();
        let sweep = HoldSweep::new(store.clone(), Some(events), 60_000);
        let report = sweep.tick(T0 + 3_600_000 + 60_000);
        assert!(report.expired.is_empty());
        assert!(report.stalled.is_empty());
        assert!(report.failures.is_empty());
        assert!(rx.try_recv().is_err());
        let hold = store.get(&id).unwrap().unwrap();
        assert_eq!(hold.state, HoldState::Refused);
        assert_eq!(
            hold.decision.as_ref().unwrap().decision,
            HoldDecision::Refuse
        );
        assert!(!hold.decision.as_ref().unwrap().dispatched);
    }

    /// A store fault is reported, not swallowed and not fatal: the loop keeps
    /// running and the failure is on the report.
    #[test]
    fn a_store_fault_is_reported_on_the_tick_and_does_not_panic() {
        struct BrokenStore;
        impl HeldActionStore for BrokenStore {
            fn create(
                &self,
                _hold: HeldAction,
            ) -> Result<(), crate::held_action::HeldActionStoreError> {
                Err(crate::held_action::HeldActionStoreError::Poisoned)
            }
            fn get(
                &self,
                _hold_id: &str,
            ) -> Result<Option<HeldAction>, crate::held_action::HeldActionStoreError> {
                Err(crate::held_action::HeldActionStoreError::Poisoned)
            }
            fn list(
                &self,
                _include_terminal: bool,
                _limit: usize,
            ) -> Result<Vec<HeldAction>, crate::held_action::HeldActionStoreError> {
                Err(crate::held_action::HeldActionStoreError::Poisoned)
            }
            fn mark_case_channel(
                &self,
                _hold_id: &str,
                _case_channel: &str,
            ) -> Result<(), crate::held_action::HeldActionStoreError> {
                Err(crate::held_action::HeldActionStoreError::Poisoned)
            }
            fn mark_notified(
                &self,
                _hold_id: &str,
                _at_ms: i64,
                _notice_event_id: &str,
                _card_event_id: Option<&str>,
            ) -> Result<(), crate::held_action::HeldActionStoreError> {
                Err(crate::held_action::HeldActionStoreError::Poisoned)
            }
            fn mark_armed(
                &self,
                _hold_id: &str,
                _at_ms: i64,
            ) -> Result<(), crate::held_action::HeldActionStoreError> {
                Err(crate::held_action::HeldActionStoreError::Poisoned)
            }
            fn begin_decision(
                &self,
                _hold_id: &str,
                _intent_event_id: &str,
                _cas_instant_ms: i64,
            ) -> Result<HeldAction, crate::held_action::HeldActionStoreError> {
                Err(crate::held_action::HeldActionStoreError::Poisoned)
            }
            fn abandon_decision(
                &self,
                _hold_id: &str,
                _intent_event_id: &str,
            ) -> Result<(), crate::held_action::HeldActionStoreError> {
                Err(crate::held_action::HeldActionStoreError::Poisoned)
            }
            fn complete_decision(
                &self,
                _hold_id: &str,
                _decision: crate::held_action::HoldDecisionRecord,
                _state: HoldState,
            ) -> Result<(), crate::held_action::HeldActionStoreError> {
                Err(crate::held_action::HeldActionStoreError::Poisoned)
            }
            fn expire_due(
                &self,
                _now_ms: i64,
            ) -> Result<Vec<HeldAction>, crate::held_action::HeldActionStoreError> {
                Err(crate::held_action::HeldActionStoreError::Poisoned)
            }
            fn fail_stalled_decisions(
                &self,
                _now_ms: i64,
                _stall_ms: u64,
            ) -> Result<Vec<HeldAction>, crate::held_action::HeldActionStoreError> {
                Err(crate::held_action::HeldActionStoreError::Poisoned)
            }
            fn health(
                &self,
                _now_ms: i64,
                _stall_ms: u64,
            ) -> Result<
                crate::held_action::HeldActionStoreHealth,
                crate::held_action::HeldActionStoreError,
            > {
                Err(crate::held_action::HeldActionStoreError::Poisoned)
            }
        }

        let sweep = HoldSweep::new(Arc::new(BrokenStore), None, 60_000);
        let report = sweep.tick(T0);
        assert_eq!(report.failures.len(), 2);
        assert!(report.failures[0].starts_with("expire_due:"));
        assert!(report.failures[1].starts_with("fail_stalled_decisions:"));
        assert!(report.expired.is_empty());
        assert!(report.stalled.is_empty());
    }

    /// The SPAWNED loop sweeps: no test calls `tick`. The hold is already past
    /// its TTL against the wall clock the loop reads, so a loop that never ran
    /// leaves it open and this times out.
    #[tokio::test]
    async fn the_spawned_loop_expires_a_due_hold_with_no_manual_tick() {
        let store = Arc::new(MemoryHeldActionStore::default());
        let started_at = now_ms();
        let mut hold = fixture_hold(
            ResponseAction::IsolateHost {
                host_id: "h".into(),
            },
            started_at - 10_000,
        );
        hold.state = HoldState::Notified;
        hold.expires_at_ms = started_at - 1;
        let id = hold.hold_id.clone();
        store.create(hold).unwrap();

        let events = RuntimeEventBroadcaster::new(16);
        let mut rx = events.subscribe();
        let sweep = HoldSweep::new(store.clone(), Some(events), 60_000);
        let (tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(async move { sweep.run_until_shutdown(5, shutdown_rx).await });

        let expired = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(hold) = store.get(&id).unwrap()
                    && hold.state == HoldState::Expired
                {
                    return hold;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the spawned sweep never expired a due hold");

        assert!(expired.decision.is_none());
        match rx.try_recv().unwrap() {
            RuntimeEvent::ResponseHeld { state, hold_id, .. } => {
                assert_eq!(state, HoldState::Expired);
                assert_eq!(hold_id, id);
            }
            other => panic!("{other:?}"),
        }
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap();
    }

    /// The same, for a stalled decision: the spawned loop resolves a claim
    /// nobody completed, with no restart and no manual tick.
    #[tokio::test]
    async fn the_spawned_loop_resolves_a_stalled_decision_with_no_manual_tick() {
        let store = Arc::new(MemoryHeldActionStore::default());
        let started_at = now_ms();
        let mut hold = fixture_hold(
            ResponseAction::IsolateHost {
                host_id: "h".into(),
            },
            started_at,
        );
        hold.state = HoldState::Notified;
        hold.expires_at_ms = started_at + 3_600_000;
        let id = hold.hold_id.clone();
        store.create(hold).unwrap();
        // A claim taken far enough in the past to be stalled at a 1 ms bound.
        store
            .begin_decision(&id, &"aa".repeat(32), started_at - 1_000)
            .unwrap();

        let events = RuntimeEventBroadcaster::new(16);
        let mut rx = events.subscribe();
        let sweep = HoldSweep::new(store.clone(), Some(events), 1);
        let (tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(async move { sweep.run_until_shutdown(5, shutdown_rx).await });

        let failed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(hold) = store.get(&id).unwrap()
                    && hold.state == HoldState::Failed
                {
                    return hold;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the spawned sweep never resolved a stalled decision");

        let decision = failed.decision.unwrap();
        assert!(!decision.dispatched);
        assert!(
            decision
                .refusal
                .unwrap()
                .reason
                .contains("whether the action ran is unknown")
        );
        match rx.try_recv().unwrap() {
            RuntimeEvent::ResponseHeld { state, .. } => assert_eq!(state, HoldState::Failed),
            other => panic!("{other:?}"),
        }
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn run_until_shutdown_stops_on_the_watch_flag() {
        let store = Arc::new(MemoryHeldActionStore::default());
        let sweep = HoldSweep::new(store, None, 60_000);
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(async move { sweep.run_until_shutdown(1, rx).await });
        tokio::time::sleep(Duration::from_millis(5)).await;
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap();
    }
}
