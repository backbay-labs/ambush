//! The daemon's 1 Hz governance heartbeat.
//!
//! 16-PLAN-WINDOW-WALK Task 3 (found-3). The console's governance strip keys on
//! the `26004` governance-status frame, and nothing produced it: the bridge
//! turns runtime events into frames but no runtime event carried a governance
//! reading, so the strip could never read healthy. This is the missing source.
//!
//! Governance health is EVALUATED event-driven inside the authority (a health
//! observation moves the partition state, a decision opens a lease), not on a
//! clock. The readyz `governance` component reads a snapshot of it on demand.
//! So the reading a live console needs is not published by anything on its own —
//! it has to be sampled. This heartbeat samples [`GovernanceAuthority::status_report`]
//! once per second and publishes one [`RuntimeEvent::GovernanceStatus`], the
//! same shape and cadence as the telemetry the bridge already coalesces at 1 Hz.
//!
//! Modelled on [`crate::hold_sweep::HoldSweep`]: a struct that reads the clock
//! once per tick, a pure [`GovernanceHeartbeat::tick`] the unit tests drive, and
//! a [`GovernanceHeartbeat::run_until_shutdown`] loop the daemon spawns beside
//! the sweeps. It writes to nothing and authorizes nothing — it only reads what
//! the authority already decided and puts it on the runtime-event bus.

use std::sync::Arc;
use std::time::Duration;

use swarm_policy::governance::GovernanceAuthority;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

use crate::runtime_events::{RuntimeEvent, RuntimeEventBroadcaster, now_ms};

/// The heartbeat's cadence.
///
/// 1 Hz, on purpose and by name: the bridge's telemetry publisher drains its
/// spool once per second and keeps the last reading per frame kind, so a
/// heartbeat at this cadence lands at least one fresh `26004` in every publish
/// window. The strip's contract is "at least once per second"; publishing
/// faster only spends runtime-event capacity a coalescing bridge would collapse
/// anyway.
pub const GOVERNANCE_HEARTBEAT_INTERVAL_MS: u64 = 1_000;

/// Samples the governance authority and publishes one reading per tick.
pub struct GovernanceHeartbeat {
    /// The authority whose `status_report` is sampled. `None` is a real,
    /// testable state: a daemon wired with no governance authority publishes
    /// nothing, and the console's strip stays bridge-down — which is the truth,
    /// not a fabricated healthy.
    authority: Option<Arc<dyn GovernanceAuthority>>,
    /// Where the reading goes. The bridge subscribes; so may `/v1/events/stream`.
    events: RuntimeEventBroadcaster,
    /// `runtime.partition_contingency_lease_ttl_ms`. The `26004` frame carries
    /// it so no surface has to guess the TTL, and the authority's report does
    /// not include it, so the heartbeat threads it through from config.
    contingency_lease_ttl_ms: i64,
}

impl GovernanceHeartbeat {
    /// Bundle the daemon's governance authority and broadcaster with the
    /// configured contingency-lease TTL.
    pub fn new(
        authority: Option<Arc<dyn GovernanceAuthority>>,
        events: RuntimeEventBroadcaster,
        contingency_lease_ttl_ms: i64,
    ) -> Self {
        Self {
            authority,
            events,
            contingency_lease_ttl_ms,
        }
    }

    /// Publish one reading. Returns whether it published.
    ///
    /// `false` is the honest answer for a daemon with no authority: publishing a
    /// synthetic reading would paint the strip healthy on a daemon that cannot
    /// vouch for its own governance, and the strip staying bridge-down is the
    /// true state. Every number is copied straight off the authority's own
    /// report, so the heartbeat asserts nothing the authority did not.
    pub fn tick(&self, now_ms: i64) -> bool {
        let Some(authority) = &self.authority else {
            return false;
        };
        let report = authority.status_report();
        self.events.publish(RuntimeEvent::GovernanceStatus {
            emitted_at_ms: now_ms,
            partition_state: report.partition_state,
            total_governors: report.total_governors,
            healthy_governors: report.healthy_governors,
            quorum_threshold: report.quorum_threshold,
            unauthorized_partition_actions: report.unauthorized_partition_actions,
            active_contingency_leases: report.active_contingency_leases,
            last_transition_at_ms: report.last_transition_at_ms,
            last_reconciliation_report_id: report.last_reconciliation_report_id,
            contingency_lease_ttl_ms: self.contingency_lease_ttl_ms,
        });
        true
    }

    /// Sample every `interval_ms` until the shutdown flag flips. Missed ticks
    /// are skipped, never bursted: a reading is a statement about now, so a
    /// stale one the loop fell behind on is worth nothing and the next one
    /// supersedes it — the same reason the telemetry publisher never retries a
    /// frame.
    pub async fn run_until_shutdown(self, interval_ms: u64, mut shutdown: watch::Receiver<bool>) {
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
                    self.tick(now_ms());
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::runtime_events::RuntimeEventKind;
    use ed25519_dalek::SigningKey;
    use swarm_agents::tom_agent::{GovernancePolicy, GovernancePolicyConfig};
    use swarm_core::types::AgentId;

    /// One governor, observed healthy: the "committee of 1 (solo transport)"
    /// reading the dev profile runs on. Built from the REAL `GovernancePolicy`,
    /// because `GovernanceAuthority` is a sealed trait — a test double would
    /// have to break the seal, exactly as `governance_gate`'s tests found.
    fn solo_healthy_authority() -> Arc<GovernancePolicy> {
        let policy = Arc::new(GovernancePolicy::new(GovernancePolicyConfig {
            contingency_lease_ttl_ms: 300_000,
            contingency_blast_radius_cap: 1,
        }));
        let governor = AgentId::new("tom", "primary");
        policy
            .register_governor(governor.clone(), SigningKey::from_bytes(&[23; 32]))
            .expect("the policy holds no other governor key");
        policy.observe_health(&governor, &[], now_ms());
        policy
    }

    #[test]
    fn the_heartbeat_publishes_the_authoritys_current_reading() {
        let policy = solo_healthy_authority();
        let expected = policy.status_report();
        let events = RuntimeEventBroadcaster::new(16);
        let mut rx = events.subscribe();
        let heartbeat = GovernanceHeartbeat::new(
            Some(Arc::clone(&policy) as Arc<dyn GovernanceAuthority>),
            events,
            300_000,
        );

        assert!(heartbeat.tick(7), "a wired authority publishes a reading");

        match rx.try_recv().unwrap() {
            RuntimeEvent::GovernanceStatus {
                emitted_at_ms,
                partition_state,
                total_governors,
                healthy_governors,
                quorum_threshold,
                unauthorized_partition_actions,
                active_contingency_leases,
                last_transition_at_ms,
                last_reconciliation_report_id,
                contingency_lease_ttl_ms,
            } => {
                // Every field is the authority's own report, unaltered.
                assert_eq!(emitted_at_ms, 7);
                assert_eq!(partition_state, expected.partition_state);
                assert_eq!(total_governors, expected.total_governors);
                assert_eq!(healthy_governors, expected.healthy_governors);
                assert_eq!(quorum_threshold, expected.quorum_threshold);
                assert_eq!(
                    unauthorized_partition_actions,
                    expected.unauthorized_partition_actions
                );
                assert_eq!(
                    active_contingency_leases,
                    expected.active_contingency_leases
                );
                assert_eq!(last_transition_at_ms, expected.last_transition_at_ms);
                assert_eq!(
                    last_reconciliation_report_id,
                    expected.last_reconciliation_report_id
                );
                // The TTL is threaded from config, not the report.
                assert_eq!(contingency_lease_ttl_ms, 300_000);
                // The dev profile's honest reading: a committee of one, healthy.
                assert_eq!(total_governors, 1);
                assert_eq!(healthy_governors, 1);
                assert_eq!(
                    partition_state,
                    swarm_policy::governance::PartitionState::Healthy
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_daemon_with_no_authority_publishes_nothing() {
        let events = RuntimeEventBroadcaster::new(16);
        let mut rx = events.subscribe();
        let heartbeat = GovernanceHeartbeat::new(None, events, 300_000);
        assert!(!heartbeat.tick(7), "no authority, no reading");
        assert!(
            rx.try_recv().is_err(),
            "the strip stays bridge-down, which is the truth"
        );
    }

    /// The SPAWNED loop samples: no test calls `tick`. A loop that never ran
    /// publishes nothing and this times out.
    #[tokio::test]
    async fn the_spawned_loop_publishes_a_reading_with_no_manual_tick() {
        let policy = solo_healthy_authority();
        let events = RuntimeEventBroadcaster::new(16);
        let mut rx = events.subscribe();
        let heartbeat = GovernanceHeartbeat::new(
            Some(Arc::clone(&policy) as Arc<dyn GovernanceAuthority>),
            events,
            300_000,
        );
        let (tx, shutdown_rx) = watch::channel(false);
        // A fast interval so the test does not wait a real second.
        let handle =
            tokio::spawn(async move { heartbeat.run_until_shutdown(5, shutdown_rx).await });

        let kind = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match rx.recv().await {
                    Ok(event) => return event.kind(),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(error) => panic!("{error:?}"),
                }
            }
        })
        .await
        .expect("the spawned heartbeat never published a reading");

        assert_eq!(kind, RuntimeEventKind::GovernanceStatus);
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn run_until_shutdown_stops_on_the_watch_flag() {
        let events = RuntimeEventBroadcaster::new(16);
        let heartbeat = GovernanceHeartbeat::new(None, events, 300_000);
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(async move { heartbeat.run_until_shutdown(1, rx).await });
        tokio::time::sleep(Duration::from_millis(5)).await;
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap();
    }
}
