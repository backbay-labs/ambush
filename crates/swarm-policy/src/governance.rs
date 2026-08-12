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

/// Partition-time authorization and event drain, as the dispatcher needs them.
///
/// Deliberately narrow: these two methods are the entire surface the dispatcher used
/// of the concrete governance policy, and widening it would re-import the coupling
/// this trait exists to remove.
pub trait GovernanceAuthority: Send + Sync {
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
}
