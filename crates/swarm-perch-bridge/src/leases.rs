//! B7: the containment-lease watcher and the `swarm:lease:v1` card body.
//!
//! The daemon's lease store is the authority; this module only notices what
//! changed in it. A lease that appeared becomes a card, a lease that left
//! becomes the rollback card's subject, and a poll that sees no change emits
//! nothing.
//!
//! Nothing here reads a clock. Every instant on the card comes from the lease
//! itself, so a card cannot claim a lifetime the store never granted.

use std::collections::BTreeSet;
use std::sync::Arc;

use swarm_perch_wire::FactIssuer;
use swarm_response::containment::ContainmentLease;
use swarm_runtime::containment::ContainmentSweep;

use crate::error::BridgeError;

/// What one poll saw change.
#[derive(Debug, Default)]
pub struct LeaseDiff {
    /// Leases in the store that were not there at the previous poll.
    pub appeared: Vec<ContainmentLease>,
    /// Lease ids that were there and are not now.
    pub disappeared: Vec<String>,
}

impl LeaseDiff {
    /// True when nothing changed, so the caller publishes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.appeared.is_empty() && self.disappeared.is_empty()
    }
}

/// Watches the containment lease store for openings and closures.
#[derive(Debug)]
pub struct LeaseWatcher {
    sweep: Option<Arc<ContainmentSweep>>,
    open: BTreeSet<String>,
}

impl LeaseWatcher {
    /// A watcher over `sweep`, or over nothing when no store is configured.
    #[must_use]
    pub fn new(sweep: Option<Arc<ContainmentSweep>>) -> Self {
        Self {
            sweep,
            open: BTreeSet::new(),
        }
    }

    /// True on the shipped default: no `runtime.containment.lease_store_path`.
    ///
    /// Reported rather than inferred from an empty diff, because "no store" and
    /// "a store with no leases" are different facts and only one of them means
    /// the console should say containment is unconfigured.
    #[must_use]
    pub fn store_absent(&self) -> bool {
        self.sweep.is_none()
    }

    /// One poll.
    ///
    /// # Errors
    ///
    /// [`BridgeError::LeaseStore`] when the store cannot be read. The previous
    /// view is left untouched, so a transient read failure does not report every
    /// open lease as disappeared on the next successful poll.
    pub fn poll(&mut self) -> Result<LeaseDiff, BridgeError> {
        let Some(sweep) = self.sweep.as_ref() else {
            return Ok(LeaseDiff::default());
        };
        let current = sweep
            .open_leases()
            .map_err(|error| BridgeError::LeaseStore {
                reason: error.to_string(),
            })?;
        let now: BTreeSet<String> = current
            .iter()
            .map(|lease| lease.lease_id().to_string())
            .collect();
        let appeared = current
            .into_iter()
            .filter(|lease| !self.open.contains(lease.lease_id()))
            .collect();
        let disappeared = self.open.difference(&now).cloned().collect();
        self.open = now;
        Ok(LeaseDiff {
            appeared,
            disappeared,
        })
    }
}

/// The `swarm:lease:v1` fact for one open containment lease.
///
/// The lease is embedded VERBATIM through its own serialization, which is the
/// shape the schema pins. Nothing here derives a field from a clock: every
/// instant is the store's, so a card cannot claim a lifetime that was never
/// granted.
///
/// `receipt_card_id` is left null; the caller fills it when the routing map
/// knows the `swarm:receipt:v1` card for this lease's `origin_receipt_id`, and
/// a guess would be a join an operator could not check.
#[must_use]
pub fn lease_card_body(
    lease: &ContainmentLease,
    case_channel: uuid::Uuid,
    issuer: FactIssuer,
) -> serde_json::Value {
    serde_json::json!({
        "schema": "swarm.perch.lease.v1",
        "issuer": issuer,
        "emitted_at_ms": lease.issued_at_ms(),
        "locator": {
            "lease_id": lease.lease_id(),
            "case_channel": case_channel.to_string(),
            "origin_receipt_id": lease.origin_receipt_id(),
            "receipt_card_id": serde_json::Value::Null,
        },
        "lease": lease,
        "ttl_source": "runtime.containment.lease_ttl_ms",
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use swarm_core::types::ResponseAction;
    use swarm_core::types::ResponseRehearsalPreview;
    use swarm_response::containment::{
        ContainmentLeaseStore, ContainmentTtl, MemoryContainmentLeaseStore,
    };
    use swarm_response::rollback::{RollbackReceipt, RollbackTrigger};
    use swarm_response::{
        ExecutionMode, ResponseError, ResponseStatus, rollback::RollbackExecutor,
    };

    /// A rollback executor that is never called: these tests are about the
    /// WATCHER, and an executor with behaviour would only add a second reason
    /// for them to fail.
    #[derive(Debug, Default)]
    struct InertExecutor;

    #[async_trait::async_trait]
    impl RollbackExecutor for InertExecutor {
        async fn rollback(
            &self,
            lease: &swarm_response::containment::ContainmentLease,
            trigger: RollbackTrigger,
            mode: ExecutionMode,
            completed_at_ms: i64,
        ) -> Result<RollbackReceipt, ResponseError> {
            Ok(RollbackReceipt {
                rollback_id: format!("rb:{}", lease.lease_id()),
                lease_id: lease.lease_id().to_string(),
                origin_receipt_id: lease.origin_receipt_id().to_string(),
                governance_receipt_id: None,
                trigger,
                mode,
                status: ResponseStatus::Executed,
                steps: Vec::new(),
                completed_at_ms,
                summary: "0 of 0 steps reversed".to_string(),
                governance_attestation: None,
            })
        }
    }

    fn preview() -> ResponseRehearsalPreview {
        use swarm_core::types::{
            ResponseBlastRadiusImpact, ResponseBlastRadiusPreview, ResponseRehearsalScopeKind,
            ResponseRollbackPreview, ResponseRollbackStep, ResponseRollbackStepKind,
        };
        ResponseRehearsalPreview {
            rehearsal_id: "rehearsal:test".to_string(),
            source_bundle_id: "bundle:test".to_string(),
            prepared_at_ms: 1_000,
            simulated_only: true,
            blast_radius: ResponseBlastRadiusPreview {
                scope_kind: ResponseRehearsalScopeKind::Host,
                scope_value: "host-1".to_string(),
                impact: ResponseBlastRadiusImpact::HostConnectivityIsolated,
                max_affected_scopes: 1,
                affected_capabilities: vec!["network_connectivity".to_string()],
                summary: "isolates one host".to_string(),
            },
            rollback: ResponseRollbackPreview {
                required: true,
                summary: "restore connectivity".to_string(),
                steps: vec![ResponseRollbackStep {
                    kind: ResponseRollbackStepKind::RestoreHostConnectivity,
                    summary: "restore host-1".to_string(),
                }],
            },
        }
    }

    fn lease(id: &str, issued_at_ms: i64, ttl_ms: i64) -> ContainmentLease {
        ContainmentLease::open(
            id,
            ResponseAction::IsolateHost {
                host_id: "host-1".to_string(),
            },
            format!("resp:{id}"),
            None,
            &preview(),
            issued_at_ms,
            ContainmentTtl::from_config_ms(ttl_ms).expect("a positive ttl"),
        )
        .expect("the lease opens")
    }

    fn sweep_with(
        leases: &[(&str, i64, i64)],
    ) -> (Arc<ContainmentSweep>, Arc<MemoryContainmentLeaseStore>) {
        let store = Arc::new(MemoryContainmentLeaseStore::new());
        for (id, issued, ttl) in leases {
            store.open_lease(&lease(id, *issued, *ttl)).expect("open");
        }
        let sweep = Arc::new(ContainmentSweep::new(
            store.clone(),
            Arc::new(InertExecutor),
            ExecutionMode::Enforced,
        ));
        (sweep, store)
    }

    /// The watcher reports transitions, not state. A steady store emits nothing,
    /// because a card per poll would be a stream of claims that nothing changed.
    #[test]
    fn poll_reports_appeared_and_disappeared_by_lease_id() {
        let (sweep, store) = sweep_with(&[("cl_a", 1_000, 900_000)]);
        let mut watcher = LeaseWatcher::new(Some(sweep));

        let first = watcher.poll().expect("the store reads");
        assert_eq!(
            first
                .appeared
                .iter()
                .map(|lease| lease.lease_id().to_string())
                .collect::<Vec<_>>(),
            vec!["cl_a"]
        );
        assert!(first.disappeared.is_empty());

        store
            .open_lease(&lease("cl_b", 2_000, 900_000))
            .expect("open");
        let second = watcher.poll().expect("the store reads");
        assert_eq!(
            second
                .appeared
                .iter()
                .map(|lease| lease.lease_id().to_string())
                .collect::<Vec<_>>(),
            vec!["cl_b"]
        );
        assert!(second.disappeared.is_empty());

        let third = watcher.poll().expect("the store reads");
        assert!(third.is_empty(), "a steady state emits nothing");
    }

    /// "No store" and "a store with no leases" are different facts, and only one
    /// of them means the console should say containment is unconfigured.
    #[test]
    fn no_store_publishes_nothing_and_reports_absent() {
        let mut watcher = LeaseWatcher::new(None);
        let diff = watcher.poll().expect("no store is not an error");
        assert!(diff.is_empty());
        assert!(watcher.store_absent());

        let (sweep, _store) = sweep_with(&[]);
        let mut configured = LeaseWatcher::new(Some(sweep));
        assert!(configured.poll().expect("reads").is_empty());
        assert!(
            !configured.store_absent(),
            "an empty store is configured, and says so"
        );
    }

    /// Every instant on the card is the store's. Nothing here reads a clock, so
    /// a card cannot claim a lifetime that was never granted.
    #[test]
    fn lease_card_body_carries_the_lease_verbatim_and_nothing_clock_derived() {
        let (sweep, _store) = sweep_with(&[("cl_a", 1_000, 900_000)]);
        let lease = sweep.open_leases().expect("reads").remove(0);
        let case = uuid::Uuid::parse_str("27799e23-ab25-4659-b381-3de47ea7ca4d").expect("a uuid");
        let body = lease_card_body(
            &lease,
            case,
            FactIssuer {
                swarm_agent_id: "containment-sweep".to_string(),
                role: None,
                nostr_pubkey: None,
            },
        );

        assert_eq!(body["schema"], "swarm.perch.lease.v1");
        assert_eq!(body["emitted_at_ms"], lease.issued_at_ms());
        assert_eq!(body["locator"]["lease_id"], "cl_a");
        assert_eq!(body["locator"]["case_channel"], case.to_string());
        assert_eq!(body["locator"]["origin_receipt_id"], "resp:cl_a");
        assert!(
            body["locator"]["receipt_card_id"].is_null(),
            "a guessed join is one an operator could not check"
        );
        assert_eq!(body["ttl_source"], "runtime.containment.lease_ttl_ms");
        // The lease rides verbatim through its own serialization.
        assert_eq!(
            body["lease"],
            serde_json::to_value(&lease).expect("the lease serializes")
        );
    }
}
