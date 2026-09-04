//! The 1 Hz open-lease diff. There is no `RuntimeEvent` for a containment lease opening, so the
//! bridge polls.

use std::collections::BTreeSet;
use std::sync::Arc;

use swarm_response::containment::ContainmentLease;
use swarm_runtime::containment::ContainmentSweep;

use crate::error::BridgeError;

/// Poll cadence. Matches the console's own containment poll so the two never disagree by more
/// than one tick. PROPOSED.
pub const LEASE_POLL_MS: u64 = 1_000;

/// Diffs `open_leases()` by `lease_id` and emits `swarm:lease:v1` on appearance.
///
/// `ContainmentSweep::open_leases()` (`swarm-runtime/src/containment.rs:537-539`) is `pub` and
/// reads the process's ONE `Arc<ContainmentSweep>` -- the same `Arc` that `swarm_detect.rs:1022-1075`
/// builds and hands to both the TTL task and the operator release route, for the reason the
/// comment there states at length: two sweeps over a `MemoryContainmentLeaseStore` are two
/// different maps and one of them would report clean passes over nothing.
pub struct LeaseWatcher {
    sweep: Option<Arc<ContainmentSweep>>,
    open: BTreeSet<String>,
}

impl LeaseWatcher {
    /// `None` is the SHIPPED DEFAULT, not an error: `ContainmentSettings.lease_store_path`
    /// defaults to `None` (`swarm-core/src/config/runtime.rs:93-95`), whose own doc says a
    /// restart "FORGETS every open containment and no sweep will ever release it -- the host stays
    /// contained until an operator intervenes". With no store, `prepare_containment` returns
    /// `RuntimeError::ContainmentRefused` (`swarm-runtime/src/lib.rs:836-844`) for all four
    /// containment actions, so nothing new is ever leased either.
    ///
    /// The watcher publishes nothing and exports `perch_bridge_lease_store_absent = 1`, so
    /// `/leases` can render `no-lease-store-configured` -- naming the `lease_store_path` key --
    /// as a first-class state rather than as an empty list that looks like calm.
    pub fn new(sweep: Option<Arc<ContainmentSweep>>) -> Self {
        Self {
            sweep,
            open: BTreeSet::new(),
        }
    }

    /// One poll. Returns the containment leases that newly appeared.
    pub fn poll(&mut self) -> Result<LeaseDiff, BridgeError> {
        let _ = &self.sweep;
        todo!("open_leases()?; diff against self.open by lease_id; update self.open")
    }
}

#[derive(Debug, Default)]
pub struct LeaseDiff {
    pub appeared: Vec<ContainmentLease>,
    /// A containment lease that left `open_leases()`. The bridge does **not** invent a rollback
    /// card for it:
    /// the `RollbackReceipt` is produced inside `ContainmentSweep::sweep`
    /// (`swarm-runtime/src/containment.rs:568+`) as part of a `ContainmentSweepReport` that
    /// `run_until_shutdown` consumes internally, so the bridge never sees it. Inventing a receipt
    /// it never saw is exactly the class of claim render law 3 forbids.
    ///
    /// See `11-BRIDGE-CRATE.md` section 9.4: an operator release is the console's leg-1 publish;
    /// a TTL expiry needs the proposed **B1c** thirteenth `RuntimeEvent` variant. Until then the
    /// console renders `containment lease no longer open -- release receipt not available`, which
    /// is true.
    pub disappeared: Vec<String>,
}

/// Builds the `swarm:lease:v1` body from a `ContainmentLease`.
///
/// **`remaining_ms` and `expired` are never baked in.** `ContainmentLeaseView`'s own doc comment
/// (`swarm-runtime-http/src/http/containment.rs:75-86`) says `remaining_ms` "SATURATES AT ZERO"
/// and therefore cannot distinguish "expires in an instant" from "expired an hour ago and the
/// sweep has not managed to release it", which is why `expired` is a separate field. Both are
/// clock-derived; a card is immutable; freezing either would freeze a lie.
///
/// This is also why the crate depends on `swarm-response` for `ContainmentLease` and NOT on
/// `swarm-runtime-http` for `ContainmentLeaseView` -- which would be a dependency cycle anyway,
/// since `swarm-runtime-http` mounts this crate.
pub fn lease_card_body(lease: &ContainmentLease, case_channel: uuid::Uuid) -> serde_json::Value {
    let _ = (lease, case_channel);
    todo!("13-WIRE-SCHEMAS.md owns this shape; assemble lease_id, action.kind(), \
           origin_receipt_id, governance_receipt_id, blast_radius, rollback, issued_at_ms, \
           expires_at_ms -- and nothing clock-derived")
}
