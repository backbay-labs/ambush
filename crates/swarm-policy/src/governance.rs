//! The governance authority the dispatcher authorizes partition-time actions through.
//!
//! # Why this exists (SPLIT-03, phase 282)
//!
//! `dispatcher.rs` -- the composition root's agent loop -- used to hold an
//! `Arc<crate::tom_agent::GovernancePolicy>` and match on
//! `crate::tom_agent::GovernanceRuntimeEvent`, while `tom_agent` imports back into
//! the runtime. That coupling is bidirectional, so no extraction order resolves it;
//! the root has to stop naming the concrete governance agent.
//!
//! # Why this trait lives in `swarm-policy` and not `swarm_core::agent`
//!
//! [`GovernanceAuthority::authorize_partition_request`] must be handed the whole
//! [`ActionRequest`] -- the Tom implementation records the rejected request in its
//! partition activity log, not just the action kind -- and `ActionRequest` is defined
//! here, in a crate that already depends on `swarm-core` rather than the other way
//! round. Putting the trait in `swarm-core` would mean moving `ActionRequest` down
//! with it, which is a far larger change than breaking one cycle. `swarm-policy` is
//! the lowest crate that can name both `ActionRequest` and `AgentRole`, both the
//! dispatcher and the governance agent already depend on it, and authorizing a
//! destructive action during a partition is a policy decision by any reading.

use serde::{Deserialize, Serialize};
use swarm_core::agent::AgentRole;

use crate::ActionRequest;

/// One governance-originated runtime event, flattened to what the dispatcher publishes.
///
/// The concrete event enum stays private to the governance agent. Everything the
/// dispatcher ever read out of it -- the governing agent, the action-kind label, and
/// the serialized body -- is carried here, so the agent owns the mapping and the
/// dispatcher owns only the publishing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernanceRuntimeEventRecord {
    /// Identifier of the governor that emitted the event.
    pub governing_agent_id: String,
    /// Role to attribute the event to on the runtime event bus.
    pub role: AgentRole,
    /// Stable action-kind label for the emitted runtime event.
    pub action_kind: String,
    /// Serialized event body.
    pub details: serde_json::Value,
}

/// Where the governance quorum currently sits on the partition/heal path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionState {
    Healthy,
    Degraded,
    Partitioned,
    Healing,
}

/// The governance authority's own account of itself, as operators read it.
///
/// Moved down here from the concrete governance agent in SPLIT-05, so
/// [`GovernanceAuthority::status_report`] can name its own return type. The ingest
/// health surface renders these eight fields into `/healthz` and reads nothing else
/// off the authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceStatusReport {
    pub partition_state: PartitionState,
    pub total_governors: usize,
    pub healthy_governors: usize,
    pub quorum_threshold: usize,
    pub active_contingency_leases: usize,
    pub unauthorized_partition_actions: usize,
    pub last_transition_at_ms: Option<i64>,
    pub last_reconciliation_report_id: Option<String>,
}

/// Not public API. Seals [`GovernanceAuthority`]; see the note on that trait.
#[doc(hidden)]
pub mod sealed {
    /// Supertrait of [`super::GovernanceAuthority`], carrying no contract of its own.
    ///
    /// Its only job is to make implementing `GovernanceAuthority` require naming a
    /// `#[doc(hidden)]` item, so the set of types that can authorize a destructive
    /// action during a governance partition stays enumerable and every addition is
    /// explicit.
    pub trait SealedGovernanceAuthority {}
}

/// Partition-time authorization and event drain, as the dispatcher needs them.
///
/// Deliberately narrow. The first four methods are the entire surface the dispatcher
/// used of the concrete governance policy; [`GovernanceAuthority::status_report`] is
/// the entire surface the ingest health endpoint used of it (SPLIT-05). Widening it
/// beyond what a named consumer already called would re-import the coupling this
/// trait exists to remove.
///
/// # What the trait widened, and why it is sealed
///
/// This is a security-relevant extension point, and it did not exist before SPLIT-03.
/// The dispatcher used to install one concrete type,
/// `swarm_runtime::tom_agent::GovernancePolicy`, whose enforcement logic is the only
/// thing that could answer [`GovernanceAuthority::authorize_partition_request`]. That
/// method returning `Ok(true)` is what lets a destructive action proceed while the
/// governance quorum is partitioned, so an arbitrary implementation installed through
/// `AgentDispatcher::with_governance_policy` could approve every partition-time
/// request without minting a contingency lease.
///
/// The trait is therefore sealed: it requires
/// [`sealed::SealedGovernanceAuthority`], which lives in a `#[doc(hidden)]` module and
/// is not part of the documented API. An implementer must write that impl too, so
/// every type that can render this verdict stays enumerable with
/// `grep -rn SealedGovernanceAuthority`, and adding one is a deliberate, reviewable
/// act rather than a side effect of depending on this crate.
///
/// The seal is a deliberate-act barrier, not a capability boundary. Rust cannot
/// restrict an impl to a named set of crates, and this trait must stay implementable
/// from whichever crate the governance agent is extracted into (that is the entire
/// point of SPLIT-03), so a determined downstream crate can still name the hidden
/// module. What the seal buys is that it cannot happen by accident or unnoticed.
pub trait GovernanceAuthority: sealed::SealedGovernanceAuthority + Send + Sync {
    /// Whether `request` may proceed while the governance quorum is partitioned.
    ///
    /// `Ok(true)` means a contingency lease covers the request, `Ok(false)` that no
    /// partition-time authorization was required or issued, and `Err` that the
    /// request was rejected outright.
    fn authorize_partition_request(
        &self,
        request: &ActionRequest,
        now_ms: i64,
    ) -> Result<bool, String>;

    /// Whether the governance quorum is currently partitioned.
    fn is_partitioned(&self) -> bool;

    /// Record that `request` was vetoed while the quorum was partitioned.
    ///
    /// A no-op unless the quorum is actually partitioned.
    fn note_partition_veto(&self, request: &ActionRequest, reason: &str, now_ms: i64);

    /// Take the governance events queued since the last drain.
    fn drain_runtime_events(&self) -> Vec<GovernanceRuntimeEventRecord>;

    /// Snapshot of quorum health, for the operator-facing health surface.
    ///
    /// Read-only and verdict-free: it reports what the authority already decided and
    /// authorizes nothing. It is on this trait rather than a second one because the
    /// ingest surface holds the same authority object the dispatcher does, and one
    /// sealed governance trait keeps the enumerable-implementers property in one place.
    fn status_report(&self) -> GovernanceStatusReport;
}
