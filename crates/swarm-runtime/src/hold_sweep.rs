//! Expire holds past their TTL, resolve stalled decisions, and re-file holds
//! the relay never learned of, on a running daemon — not only after a restart.
//! Same loop shape as `ContainmentSweep`.
//!
//! W3-39. A hold whose filing steps were lost — the bridge died between the
//! store write and the notice, or the relay refused them past the bridge's
//! budget — sits in `created` with no `notice_event_id` until its TTL: durable
//! on the daemon, invisible to every console, and reported as held. The third
//! pass re-publishes its `ResponseHeld { Created }` once per
//! `refile_after_ms`, and the bridge re-plans the filing from durable state.
//!
//! That is one of the two promises the hold path keeps, and the daemon owns
//! only this one: a hold the relay never learned of is re-filed until it is.
//! The other is the bridge's — a refused relay step for one case never delays
//! another case's hold — and neither is enough alone, because re-filing into a
//! blocked drainer only queues behind the same refusal.
//!
//! The per-hold throttle is in-memory on purpose. After a restart the first
//! tick re-files every stale unfiled hold at once, which is the promise; ADR
//! 0012 keeps the daemon the sole writer of hold state, so the sweep publishes
//! and never writes to record that it did.

use std::collections::{BTreeMap, BTreeSet};
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
    /// Holds still `created` with no notice past `refile_after_ms`, whose
    /// `ResponseHeld { Created }` was published again.
    pub refiled: Vec<String>,
    /// Store errors, one string each. The sweep never panics.
    pub failures: Vec<String>,
}

/// The sweep. Reads the clock once per tick.
pub struct HoldSweep {
    store: Arc<dyn HeldActionStore>,
    events: Option<RuntimeEventBroadcaster>,
    decide_stall_ms: u64,
    refile_after_ms: u64,
    /// Hold id -> the instant it was last re-filed. In-memory on purpose: see
    /// the module header.
    refiled_at: BTreeMap<String, i64>,
}

impl HoldSweep {
    /// Bundle the daemon's one store and broadcaster with
    /// `runtime.response.decide_stall_ms` and
    /// `runtime.response.refile_after_ms`.
    pub fn new(
        store: Arc<dyn HeldActionStore>,
        events: Option<RuntimeEventBroadcaster>,
        decide_stall_ms: u64,
        refile_after_ms: u64,
    ) -> Self {
        Self {
            store,
            events,
            decide_stall_ms,
            refile_after_ms,
            refiled_at: BTreeMap::new(),
        }
    }

    /// How many holds the re-file throttle remembers. Nothing in the daemon
    /// reads it; the tests assert the map stays bounded by the open holds.
    #[cfg(test)]
    fn throttled_hold_count(&self) -> usize {
        self.refiled_at.len()
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

    /// Re-publish `ResponseHeld { Created }` for every hold the relay never
    /// learned of, once per `refile_after_ms`. The bridge plans a re-filed
    /// record from durable state, so every step the relay already accepted is
    /// skipped and no card is duplicated.
    ///
    /// A hold is unfiled when it is still `created` AND carries no
    /// `notice_event_id`. `notified` is the bridge's own `mark_notified`
    /// callback and `armed` is client-reported, so either one proves a console
    /// has the row; `deciding` is a console acting on it. Terminal holds are
    /// not listed at all.
    fn refile_unfiled(&mut self, now_ms: i64, report: &mut HoldSweepReport) {
        let open = match self.store.list(false, usize::MAX) {
            Ok(open) => open,
            Err(error) => {
                report.failures.push(format!("refile_unfiled: {error}"));
                return;
            }
        };
        let interval_ms = i64::try_from(self.refile_after_ms).unwrap_or(i64::MAX);
        for hold in &open {
            if hold.state != HoldState::Created || hold.notice_event_id.is_some() {
                continue;
            }
            if hold.held_at_ms.saturating_add(interval_ms) > now_ms {
                continue;
            }
            let due = self
                .refiled_at
                .get(&hold.hold_id)
                .is_none_or(|last| last.saturating_add(interval_ms) <= now_ms);
            if !due {
                continue;
            }
            tracing::warn!(
                module = module_path!(),
                hold_id = %hold.hold_id,
                age_ms = now_ms - hold.held_at_ms,
                "hold is not filed on the relay; re-publishing its created event so the bridge re-plans it"
            );
            self.publish(hold, HoldState::Created, now_ms);
            self.refiled_at.insert(hold.hold_id.clone(), now_ms);
            report.refiled.push(hold.hold_id.clone());
        }
        // A hold the store no longer lists is decided, expired or gone, and
        // will never be re-filed again: forgetting it bounds the map by the
        // open holds rather than by the process's lifetime.
        let open_ids: BTreeSet<&str> = open.iter().map(|hold| hold.hold_id.as_str()).collect();
        self.refiled_at
            .retain(|hold_id, _| open_ids.contains(hold_id.as_str()));
    }

    /// Expiry first, then stall resolution, then the re-file pass. Every row
    /// the first two methods return is published as its own `ResponseHeld`, so
    /// the bridge can publish the terminal card without polling; the third
    /// publishes nothing new, it repeats an announcement that was lost.
    ///
    /// The order matters: a hold this tick expires leaves the open list before
    /// the re-file pass reads it, so it is never both retired and re-filed.
    pub fn tick(&mut self, now_ms: i64) -> HoldSweepReport {
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
        self.refile_unfiled(now_ms, &mut report);
        report
    }

    /// Tick every `interval_ms` until the shutdown flag flips. Missed ticks
    /// are skipped, never bursted.
    pub async fn run_until_shutdown(
        mut self,
        interval_ms: u64,
        mut shutdown: watch::Receiver<bool>,
    ) {
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
                        || !report.refiled.is_empty()
                        || !report.failures.is_empty()
                    {
                        tracing::info!(
                            module = module_path!(),
                            expired = report.expired.len(),
                            stalled = report.stalled.len(),
                            refiled = report.refiled.len(),
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
            HoldSweep::new(store.clone(), Some(events), 60_000, 30_000),
            store,
            rx,
            id,
        )
    }

    /// The shape W3-39 concerns: a `created` hold with no `notice_event_id`,
    /// held at `held_at_ms`, under a sweep with the given re-file interval.
    fn unfiled_sweep(
        held_at_ms: i64,
        refile_after_ms: u64,
    ) -> (
        HoldSweep,
        Arc<MemoryHeldActionStore>,
        tokio::sync::broadcast::Receiver<RuntimeEvent>,
        String,
    ) {
        let store = Arc::new(MemoryHeldActionStore::default());
        let hold = fixture_hold(
            ResponseAction::IsolateHost {
                host_id: "h".into(),
            },
            held_at_ms,
        );
        let id = hold.hold_id.clone();
        store.create(hold).unwrap();
        let events = RuntimeEventBroadcaster::new(16);
        let rx = events.subscribe();
        (
            HoldSweep::new(store.clone(), Some(events), 60_000, refile_after_ms),
            store,
            rx,
            id,
        )
    }

    /// The one `ResponseHeld` a receiver is holding, or a panic naming what
    /// else arrived. Every re-file test asserts on the events that left.
    fn next_held(
        rx: &mut tokio::sync::broadcast::Receiver<RuntimeEvent>,
    ) -> (HoldState, String, i64) {
        match rx.try_recv().unwrap() {
            RuntimeEvent::ResponseHeld {
                state,
                hold_id,
                emitted_at_ms,
                ..
            } => (state, hold_id, emitted_at_ms),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_hold_is_expired_at_its_ttl_not_before_and_the_record_is_published() {
        let (mut sweep, store, mut rx, id) = sweep_with(HoldState::Notified);
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
        let mut sweep = HoldSweep::new(store.clone(), Some(events), 60_000, 30_000);

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
            partition_state_at_execution: None,
        };
        record.hold_notice_published = claimed.notified_at_ms.is_some();
        store
            .complete_decision(&id, record, HoldState::Refused)
            .unwrap();

        let events = RuntimeEventBroadcaster::new(16);
        let mut rx = events.subscribe();
        let mut sweep = HoldSweep::new(store.clone(), Some(events), 60_000, 30_000);
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

        let mut sweep = HoldSweep::new(Arc::new(BrokenStore), None, 60_000, 30_000);
        let report = sweep.tick(T0);
        assert_eq!(report.failures.len(), 3);
        assert!(report.failures[0].starts_with("expire_due:"));
        assert!(report.failures[1].starts_with("fail_stalled_decisions:"));
        assert!(report.failures[2].starts_with("refile_unfiled:"));
        assert!(report.expired.is_empty());
        assert!(report.stalled.is_empty());
        assert!(report.refiled.is_empty());
    }

    /// W3-39. Re-filing is a repair, not a routine: a hold the bridge is still
    /// working through is younger than the interval and must be left to it.
    #[test]
    fn an_unfiled_hold_younger_than_refile_after_ms_is_left_alone() {
        let (mut sweep, _store, mut rx, _id) = unfiled_sweep(T0 - 10_000, 30_000);
        let report = sweep.tick(T0);
        assert!(report.refiled.is_empty());
        assert!(
            rx.try_recv().is_err(),
            "a hold younger than refile_after_ms is the bridge's to file"
        );
    }

    /// The throttle is the whole point: an unfiled hold is re-published once
    /// per interval, not once per tick, or the alarm spool floods.
    #[test]
    fn an_unfiled_hold_older_than_refile_after_ms_is_re_filed_exactly_once_per_interval() {
        let (mut sweep, _store, mut rx, id) = unfiled_sweep(T0 - 31_000, 30_000);

        assert_eq!(sweep.tick(T0).refiled, vec![id.clone()]);
        let (state, hold_id, emitted_at_ms) = next_held(&mut rx);
        assert_eq!(state, HoldState::Created);
        assert_eq!(hold_id, id);
        assert_eq!(emitted_at_ms, T0);
        assert!(
            rx.try_recv().is_err(),
            "one event, not one per open hold pass"
        );

        assert!(sweep.tick(T0 + 1_000).refiled.is_empty());
        assert!(
            rx.try_recv().is_err(),
            "a second tick inside the interval publishes nothing"
        );

        assert_eq!(sweep.tick(T0 + 30_000).refiled, vec![id.clone()]);
        let (state, hold_id, emitted_at_ms) = next_held(&mut rx);
        assert_eq!(state, HoldState::Created);
        assert_eq!(hold_id, id);
        assert_eq!(emitted_at_ms, T0 + 30_000);
    }

    /// `notified` is the bridge's own `mark_notified` callback: the relay
    /// accepted the notice, so the console has the row and re-filing it would
    /// be a duplicate.
    #[test]
    fn a_notified_hold_is_never_re_filed() {
        let (mut sweep, store, mut rx, id) = unfiled_sweep(T0 - 31_000, 30_000);
        store
            .mark_notified(&id, T0 - 30_000, &"aa".repeat(32), None)
            .unwrap();

        for at_ms in [T0, T0 + 30_000, T0 + 3_000_000] {
            assert!(sweep.tick(at_ms).refiled.is_empty());
        }
        assert!(rx.try_recv().is_err(), "a filed hold is never re-filed");
    }

    /// The repair stops the moment it worked: the notice that lands between two
    /// ticks ends the re-filing, with no store write from the sweep.
    #[test]
    fn a_hold_that_becomes_notified_stops_being_re_filed() {
        let (mut sweep, store, mut rx, id) = unfiled_sweep(T0 - 31_000, 30_000);
        assert_eq!(sweep.tick(T0).refiled, vec![id.clone()]);
        assert_eq!(next_held(&mut rx).0, HoldState::Created);

        store
            .mark_notified(&id, T0 + 1_000, &"aa".repeat(32), None)
            .unwrap();
        assert!(sweep.tick(T0 + 30_000).refiled.is_empty());
        assert!(rx.try_recv().is_err());
    }

    /// Restart semantics, and the reason the throttle is in-memory on purpose:
    /// a daemon that just came up knows nothing about earlier re-files, so its
    /// first tick re-files every stale unfiled hold at once.
    #[test]
    fn a_fresh_sweep_re_files_a_stale_hold_on_its_first_tick() {
        let (mut sweep, store, mut rx, id) = unfiled_sweep(T0 - 31_000, 30_000);
        assert_eq!(sweep.tick(T0).refiled, vec![id.clone()]);
        assert_eq!(next_held(&mut rx).0, HoldState::Created);

        let events = RuntimeEventBroadcaster::new(16);
        let mut restarted_rx = events.subscribe();
        let mut restarted = HoldSweep::new(store.clone(), Some(events), 60_000, 30_000);
        assert_eq!(restarted.tick(T0 + 1).refiled, vec![id.clone()]);
        let (state, hold_id, _) = next_held(&mut restarted_rx);
        assert_eq!(state, HoldState::Created);
        assert_eq!(hold_id, id);
    }

    /// ADR 0012: the sweep publishes, it does not write. A re-file that moved
    /// the record would fork the one writer of hold state.
    #[test]
    fn re_filing_does_not_touch_the_store() {
        let (mut sweep, store, mut rx, id) = unfiled_sweep(T0 - 31_000, 30_000);
        let before = serde_json::to_string(&store.get(&id).unwrap().unwrap()).unwrap();

        assert_eq!(sweep.tick(T0).refiled, vec![id.clone()]);
        assert_eq!(next_held(&mut rx).0, HoldState::Created);

        let after = serde_json::to_string(&store.get(&id).unwrap().unwrap()).unwrap();
        assert_eq!(before, after, "re-filing publishes; it never writes");
    }

    /// The map is bounded by the open holds: an id the store stopped listing is
    /// decided or expired and will never be re-filed again, so remembering it
    /// would grow the daemon's memory for the life of the process.
    #[test]
    fn the_throttle_map_forgets_holds_that_are_no_longer_open() {
        let (mut sweep, store, mut rx, id) = unfiled_sweep(T0 - 31_000, 30_000);
        assert_eq!(sweep.tick(T0).refiled, vec![id.clone()]);
        assert_eq!(next_held(&mut rx).0, HoldState::Created);
        assert_eq!(sweep.throttled_hold_count(), 1);

        let expires_at_ms = store.get(&id).unwrap().unwrap().expires_at_ms;
        assert_eq!(sweep.tick(expires_at_ms).expired, vec![id.clone()]);
        assert_eq!(next_held(&mut rx).0, HoldState::Expired);
        assert_eq!(
            sweep.throttled_hold_count(),
            0,
            "an expired hold leaves the throttle map with it"
        );
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
        let sweep = HoldSweep::new(store.clone(), Some(events), 60_000, 30_000);
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
        let sweep = HoldSweep::new(store.clone(), Some(events), 1, 30_000);
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

    /// And the same for the third pass: the SPAWNED loop re-files. The hold is
    /// already older than a 1 ms interval against the wall clock the loop
    /// reads, so a loop that never ran publishes nothing and this times out.
    #[tokio::test]
    async fn the_spawned_loop_re_files_with_no_manual_tick() {
        let store = Arc::new(MemoryHeldActionStore::default());
        let hold = fixture_hold(
            ResponseAction::IsolateHost {
                host_id: "h".into(),
            },
            now_ms() - 10_000,
        );
        let id = hold.hold_id.clone();
        store.create(hold).unwrap();

        let events = RuntimeEventBroadcaster::new(16);
        let mut rx = events.subscribe();
        let sweep = HoldSweep::new(store.clone(), Some(events), 60_000, 1);
        let (tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(async move { sweep.run_until_shutdown(5, shutdown_rx).await });

        let state = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match rx.recv().await {
                    Ok(RuntimeEvent::ResponseHeld { state, hold_id, .. }) if hold_id == id => {
                        return state;
                    }
                    Ok(_) => continue,
                    Err(error) => panic!("{error:?}"),
                }
            }
        })
        .await
        .expect("the spawned sweep never re-filed an unfiled hold");

        assert_eq!(state, HoldState::Created);
        assert_eq!(
            store.get(&id).unwrap().unwrap().state,
            HoldState::Created,
            "the re-file republishes the created event and leaves the record alone"
        );
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn run_until_shutdown_stops_on_the_watch_flag() {
        let store = Arc::new(MemoryHeldActionStore::default());
        let sweep = HoldSweep::new(store, None, 60_000, 30_000);
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
