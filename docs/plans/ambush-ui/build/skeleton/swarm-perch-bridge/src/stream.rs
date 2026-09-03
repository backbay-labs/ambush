//! Stream classification.
//!
//! "Stream" is `APPENDIX-NORMATIVE.md` section 7's ruled word: one of the bridge's four transport
//! classes. It never means a threat-class channel (that is a *lane*) and never means one of The
//! Watch's inbox categories (that is a *queue*).

use swarm_runtime::runtime_events::RuntimeEvent;

/// The four transport classes. Each `RuntimeEvent` variant maps to exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Stream {
    /// Durable `kind:9` marker cards into a lane or case channel. Disk-spooled, coalesced,
    /// shed oldest-first with accounting.
    Evidence,
    /// Ephemeral `26000`-`26005` frames, global, no `h` -- deliberately, because none of the six
    /// carries a `p` tag and p-gating them would make them undeliverable (ADR 0017). Memory-spooled
    /// at depth 1 per key; last-wins is lossless in meaning so dropping an older frame is not loss.
    Telemetry,
    /// `kind:46010` plus the ephemeral `26006`/`26003`/`26005` nudges, and (with the proposed
    /// B1d) case-channel provisioning. Disk-spooled, **never coalesced, never shed**, bypasses
    /// the pacer to meet the <= 400 ms budget on the `26006` frame
    /// (`APPENDIX-NORMATIVE.md` section 4).
    ///
    /// Unlike `Telemetry`, the `26006` frame in this stream is **channel-scoped**: it carries an
    /// `h` tag naming the standing `#watch` ops channel as well as its `p` tags. That is what
    /// closes the disclosure hole, and it makes membership of `#watch` a publish precondition.
    /// See [`crate::channels::PublishStep::PublishAlarm`] for the mechanism, measured.
    Alarm,
    /// Carries no domain fact. Counts, ranges, and the `26000` ingest-rate gauge. Not spooled;
    /// its `GapSlot` is persisted inside the sibling streams' cursors so a crash between a loss
    /// and the next card does not lose the knowledge that the loss happened.
    DroppedAtSource,
}

impl Stream {
    /// Whether this stream keeps a segmented on-disk log.
    ///
    /// `Telemetry` is deliberately false — a replayed ephemeral is a lie about "now", the relay
    /// never stores ephemerals anyway (`buzz-relay/src/handlers/event.rs:794-906` writes nothing
    /// to Postgres in either branch), and last-wins at depth 1 is already lossless in meaning.
    /// This is the proposed amendment in `11-BRIDGE-CRATE.md` section 5.1.
    pub const fn is_disk_spooled(self) -> bool {
        matches!(self, Self::Evidence | Self::Alarm)
    }

    /// Metric label value. Stable; dashboards key on it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Evidence => "evidence",
            Self::Telemetry => "telemetry",
            Self::Alarm => "alarm",
            Self::DroppedAtSource => "dropped_at_source",
        }
    }
}

/// Maps a `RuntimeEvent` to its **scheduling** stream.
///
/// EXHAUSTIVE, WITH NO `_` ARM, ON PURPOSE. `RuntimeEvent` has 11 variants today
/// (`AMBUSH crates/swarm-runtime/src/runtime_events.rs:214-305`, counted; the parallel
/// `RuntimeEventKind` at `:127-139` has the same 11). B1 adds a twelfth (`ResponseHeld`), the
/// proposed B1c adds a thirteenth (`ContainmentReleased`), and the proposed B1d adds a fourteenth
/// (`CasePromoted`). Each time, this function fails to compile and somebody must decide which
/// stream the new fact belongs to. That is the point.
///
/// A new variant is never a one-line change upstream either: `runtime_events.rs` needs the
/// `RuntimeEventKind` member (`:127-139`), its `as_str` (`:143-155`) and `parse` (`:158-173`)
/// arms, the `RuntimeEvent` variant itself (`:214-305`), `emitted_at_ms` (`:309-322`) and `kind`
/// (`:325-338`); and `runtime_event_matches_scope`
/// (`AMBUSH crates/swarm-ingest-runtime/src/ingest/mod.rs:698-770`) is likewise exhaustive with
/// no `_` arm, so its arm is the one that decides whether the new fact reaches the unauthenticated
/// Providence context stream. Seven edits plus this one.
///
/// `ModeTransition` and `TamperAlert` are dual-routed on the wire: they are `Alarm` for
/// scheduling — never coalesced, never shed, pacer-bypassing — and the alarm publisher
/// *additionally* emits their `26003` / `26005` telemetry ephemeral so the Watchfloor sees them
/// without a second subscription. This function returns the scheduling class, which is the one
/// that governs backpressure.
pub fn classify(event: &RuntimeEvent) -> Stream {
    match event {
        // --- Alarm -------------------------------------------------------------------------
        // RuntimeEvent::ResponseHeld { .. } => Stream::Alarm,   // uncomment with B1
        // RuntimeEvent::CasePromoted { .. } => Stream::Alarm,   // uncomment with B1d.
        //
        // B1d is Alarm, not Evidence, for one reason: it is the only trigger that creates a case
        // channel on the manual-promotion clause, which ADR 0018 C4 enables FIRST. Coalescing or
        // shedding it would leave a daemon incident record whose `case_id` names a channel that
        // does not exist. It carries no `26006` frame -- a promotion is not a held action and must
        // not alarm the shift -- so it costs one `kind:9007` and one `kind:9000` per operator, and
        // nothing on the alarm identity's per-minute burst budget.
        RuntimeEvent::ModeTransition { .. } => Stream::Alarm,
        RuntimeEvent::TamperAlert { .. } => Stream::Alarm,

        // --- Evidence ----------------------------------------------------------------------
        RuntimeEvent::Escalation { .. } => Stream::Evidence,
        RuntimeEvent::Finding { .. } => Stream::Evidence,
        RuntimeEvent::ResponseExecution { .. } => Stream::Evidence,

        // --- Telemetry ---------------------------------------------------------------------
        RuntimeEvent::ConcentrationSnapshot { .. } => Stream::Telemetry,
        RuntimeEvent::AgentHealth { .. } => Stream::Telemetry,
        RuntimeEvent::AgentAction { .. } => Stream::Telemetry,

        // --- Dropped at source -------------------------------------------------------------
        // `Ingest` is published once per accepted telemetry event
        // (`swarm-ingest-runtime/src/ingest/mod.rs:1122,1135,1200`) and is reduced, deliberately,
        // to the 1 Hz `26000` gauge. One relay event per ingested event exceeds the relay quota
        // by ~1,800x, and the record already exists in the `ReplayBundle`.
        RuntimeEvent::Ingest { .. } => Stream::DroppedAtSource,
        // `Replay` and `EvolutionStatus` are not published at all. The Watchfloor and `/tuning`
        // read the daemon.
        RuntimeEvent::Replay { .. } => Stream::DroppedAtSource,
        RuntimeEvent::EvolutionStatus { .. } => Stream::DroppedAtSource,
    }
}

/// Fields stripped at classification time, before the record ever reaches the spool.
///
/// Two of these are security obligations rather than size optimizations:
///
/// - `AgentAction.details` is `serde_json::to_value(action)` over the entire `SwarmAction`
///   (`swarm-runtime/src/dispatcher.rs:951`), i.e. adversary-influenced content, and there is no
///   route that serves it — the operator router registers 49 routes
///   (`swarm-runtime-http/src/http/state.rs:292-488`) and none serves agent actions, so
///   "fetch the details on demand" would be fiction. Dropped; a tally is published instead.
/// - `TamperAlert.unexpected_library_loads` is reduced to its `.len()`. The `26000` block's
///   payload rule is counts, not paths.
pub fn redact_in_place(event: &mut RuntimeEvent) {
    let _ = event;
    todo!("clear AgentAction.details; replace TamperAlert.unexpected_library_loads with its len")
}
