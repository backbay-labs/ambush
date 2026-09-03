//! Coalescing. Runs in the pacer's task, once per tick, **never in the receive loop**.
//!
//! # The distinction this module exists to protect
//!
//! A **coalesce** is meaning-preserving: the information survives, compressed. A **gap** is loss.
//! They render differently, the operator's correct reaction to each is different, and the
//! accounting invariant counts them on opposite sides:
//!
//! ```text
//! ingested == dropped + Sum(source_events over published)
//! ```
//!
//! (stated verbatim at `BUZZ crates/buzz-acp/src/lib.rs:453`). A coalesced input is counted in
//! `published`, because its meaning was published. It never appears in `dropped`.

use std::collections::BTreeMap;

use swarm_core::pheromone::ThreatClass;
use swarm_core::types::AgentId;
use swarm_runtime::runtime_events::{EscalationLevel, RuntimeEvent};

/// Bounded republish for a class that has been at one level for a long time, so a console that
/// connected ten minutes ago is not missing it. PROPOSED; no measurement behind it.
pub const PERCH_ESCALATION_HEARTBEAT_MS: i64 = 60_000;

/// State-change detection for `TamperAlert`. Not coalescing -- no alarm is ever discarded because
/// a budget was tight, only because it said the same thing as the one before it. PROPOSED.
pub const PERCH_ALARM_HEARTBEAT_MS: i64 = 60_000;

/// Telemetry is depth 1 per key. The key set is 1 concentration slot + one per live agent.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TelemetryKey {
    /// A single key: the snapshot carries all twelve classes
    /// (`swarm-runtime/src/escalation.rs:267-281` loops `standard_threat_classes()`), so
    /// last-wins over the whole snapshot is lossless in meaning.
    Concentration,
    AgentHealth(AgentId),
    IngestGauge,
}

/// `26001`, the 10 Hz firehose.
///
/// `ConcentrationMonitor::run_until_shutdown` ticks every
/// `CONCENTRATION_MONITOR_INTERVAL_MS = 100` (`swarm_detect.rs:40`, spawned `:1002-1006`) and
/// `evaluate_all` calls `publish_concentration_snapshot` **unconditionally on every tick**
/// (`escalation.rs:198-199` -> `:282-292`). At rest, with zero telemetry, that is 864,000
/// snapshots per day.
///
/// Against `agent_standard_messages_per_min = 120` (`buzz-auth/src/rate_limit.rs:105`, default fn
/// `:129-131`, selected at `buzz-relay/src/connection.rs:689-692`), a pre-coalescing 10 Hz stream
/// is 600/min -- 5x over on the telemetry identity alone -- and it also consumes the entire
/// 50-frames-per-5-second `WsEvents` budget (`connection.rs:671-681` x `admission.rs:9,40-45`).
///
/// So the appendix's "coalesced 10 Hz -> 1 Hz in the bridge, before IPC" is a hard requirement.
/// Nine of ten snapshots per second are overwritten in memory and never reach the relay, disk, or
/// `serde_json`.
pub struct TelemetryCoalescer {
    slots: BTreeMap<TelemetryKey, RuntimeEvent>,
    /// Counts overwrites. Reported as `perch_bridge_coalesced_total{stream="telemetry"}`, never
    /// as a drop.
    coalesced: u64,
}

impl TelemetryCoalescer {
    pub fn offer(&mut self, key: TelemetryKey, event: RuntimeEvent) {
        let _ = (key, event);
        todo!("if the slot was occupied, self.coalesced += 1; then overwrite")
    }

    /// Takes everything for this tick and clears.
    pub fn drain(&mut self) -> Vec<(TelemetryKey, RuntimeEvent)> {
        todo!("std::mem::take(&mut self.slots).into_iter().collect()")
    }
}

/// `Escalation` -- edge-triggered, with a bounded heartbeat.
///
/// # CORRECTION to the ground survey, and it is load-bearing
///
/// `ambush-touchpoints.md` blocker B-3 offers a free mitigation: *"`now` is
/// `unix_timestamp_secs()` (`escalation.rs:228`), so all ten ticks in a second emit
/// byte-identical events -- the bridge can dedupe on `(threat_class, level, timestamp)`."*
/// **That is wrong and the dedupe would never fire.** Read from source:
///
/// ```text
/// // swarm-runtime/src/escalation.rs:247-264 -- publish_escalation
/// runtime_events.publish(RuntimeEvent::Escalation {
///     emitted_at_ms: now_ms(),          // FRESH MILLISECOND CLOCK, EVERY TICK
///     ...
/// });
/// ```
///
/// `RuntimeEvent::Escalation` (`runtime_events.rs:288-297`) has **no `timestamp` field at all**;
/// the seconds-resolution `now` reaches the substrate's `EscalationRecord` and the concentration
/// query, never the broadcast event. `publish_concentration_snapshot` (`escalation.rs:282-292`)
/// and `publish_mode_transition` do the same, at `escalation.rs:288` and `:306`.
///
/// The useful half survives and is stronger: because `query_concentration(threat_class, now)`
/// receives seconds, `total_strength`, `distinct_sources` and `peak_confidence` are identical
/// across all ten ticks within a second unless a deposit lands mid-second. So the ten events
/// differ in exactly one field. The rule is therefore edge-triggering, not deduplication.
pub struct EscalationCoalescer {
    last_level: BTreeMap<ThreatClass, EscalationLevel>,
    last_published_ms: BTreeMap<(ThreatClass, EscalationLevel), i64>,
    coalesced: u64,
}

impl EscalationCoalescer {
    /// Returns `true` when this escalation should be published.
    ///
    /// Publishes on: a level change for a class (`evaluate_threat_class` is a pure level
    /// comparison with no memory of prior state -- `escalation.rs:78-101` runs two
    /// `exceeds_threshold` tests, each returning `Some(EscalationEvent)` on EVERY evaluation
    /// while over threshold, so a level-triggered producer needs an edge-triggered consumer);
    /// or a heartbeat older than [`PERCH_ESCALATION_HEARTBEAT_MS`].
    ///
    /// Worst case with all twelve classes at Incident: 12 frames/min against 8 x 120/min.
    /// Uncoalesced: up to **120 events/second**.
    pub fn should_publish(
        &mut self,
        threat_class: &ThreatClass,
        level: EscalationLevel,
        now_ms: i64,
    ) -> bool {
        let _ = (threat_class, level, now_ms);
        todo!("is_edge || is_heartbeat; else self.coalesced += 1 and return false")
    }

    /// `evaluate_all` drops a class out of `events` entirely once it falls below threshold
    /// (`escalation.rs:153-195`), so the de-escalation edge has to be observed by absence.
    /// Called once per tick with the classes seen this tick.
    pub fn observe_absent(&mut self, seen: &[ThreatClass]) -> Vec<ThreatClass> {
        let _ = seen;
        todo!("classes in last_level and not in `seen` -> remove and return as de-escalation edges")
    }
}

/// `Finding` -- batched, never last-wins. Two findings are two facts.
///
/// One `kind:9` card per `(threat_class, host_id)` per tick, carrying an array, until the frame
/// reaches `PERCH_FRAME_MAX_BYTES`. Overflow spills to the next tick from the spool; overflow past
/// `PERCH_SPOOL_MAX_BYTES` is an eviction, which is a **gap**, not a coalesce.
///
/// `host_id` comes off the `RuntimeEvent::Finding` **wrapper** (`runtime_events.rs:224-228`), not
/// out of `SwarmFindingEnvelope` -- which is exactly what `GET /v2/api/stream/findings` throws
/// away (`platform_api.rs:1391-1414`), and one of the reasons that transport is rejected.
pub struct FindingBatcher {
    _private: (),
}

/// The `coalesced` block a card carries when this module compressed its inputs.
///
/// Populates `07-REALTIME-AND-DATA.md` section 5.5's row:
/// `-- 340 finding cards coalesced into 12 (bridge over budget 14:22:01-14:22:09) --`
/// with a disclosure listing the suppressed triples.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CoalescedBlock {
    pub from_ms: i64,
    pub to_ms: i64,
    pub input_count: u64,
    pub output_count: u64,
    pub suppressed: Vec<SuppressedTriple>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SuppressedTriple {
    pub threat_class: String,
    pub host_id: Option<String>,
    pub count: u64,
}

/// `AgentHealth` + `AgentAction` -> one `26002` frame.
///
/// Last-wins per `agent_id` for health; a tally for actions.
///
/// **The tally key vocabulary is not closed.** `action_kind` takes nine `&'static str` values from
/// `swarm_action_kind` (`swarm-runtime/src/dispatcher.rs:1251-1263`), plus the literal
/// `"agent_restart"` (`:1142`), plus whatever `governance_policy.drain_runtime_events()` supplies
/// (`:1034`). Everything outside the allowlist is bucketed as `other` and counted separately: a
/// nonzero `perch_bridge_unknown_action_kind_total` means the daemon grew a kind and the allowlist
/// is stale, not that the bridge is broken.
pub struct AgentTally {
    health: BTreeMap<AgentId, RuntimeEvent>,
    actions: BTreeMap<(AgentId, String), u64>,
}

impl AgentTally {
    pub const KNOWN_ACTION_KINDS: [&'static str; 10] = [
        // The nine from swarm_action_kind (dispatcher.rs:1251-1263) plus agent_restart (:1142).
        // Fill from source at implementation time; a wrong literal here silently buckets a real
        // action as `other`.
        "", "", "", "", "", "", "", "", "", "agent_restart",
    ];

    pub fn record_action(&mut self, agent: AgentId, action_kind: &str) {
        let _ = (agent, action_kind);
        todo!("bucket to `other` when not in KNOWN_ACTION_KINDS, and count it")
    }
}
