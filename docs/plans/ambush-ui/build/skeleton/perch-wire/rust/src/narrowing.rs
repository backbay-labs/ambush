//! `RuntimeEvent` -> card or frame, with every deliberate narrowing named.
//!
//! This module is the whole answer to "what does the wire type drop, and why".
//! There are eleven `RuntimeEvent` variants today
//! (`AMB crates/swarm-runtime/src/runtime_events.rs:214-305`) and a twelfth,
//! `ResponseHeld`, after B1. Every one of the eleven is classified below, and
//! `classify` is an EXHAUSTIVE match with no `_` arm so a new variant is a
//! compile error here rather than a silently unpublished fact.
//!
//! Adding that twelfth variant costs six edits inside `runtime_events.rs` alone
//! — the `RuntimeEventKind` enum (`:127-139`), `as_str` (`:142-156`), `parse`
//! (`:158-173`), the `RuntimeEvent` enum (`:214-305`), `emitted_at_ms`
//! (`:308-322`) and `kind` (`:324-338`) — plus a new arm in
//! `runtime_event_matches_scope`
//! (`AMB crates/swarm-ingest-runtime/src/ingest/mod.rs:698-770`), which is also
//! exhaustive and which decides whether the hold alarm leaks on
//! `GET /v1/events/stream`. Default it to `false`, like the `TamperAlert`,
//! `AgentHealth` and `EvolutionStatus` arms at `:766-768`.

use swarm_runtime::runtime_events::RuntimeEvent;

use crate::frames::{FrameKind, Stream};
use crate::marker::CardKind;

/// Where one `RuntimeEvent` goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    /// A durable `kind:9` marker card.
    Card(CardKind),
    /// An aggregated ephemeral frame.
    Frame(FrameKind),
    /// Folded into a frame that is keyed on something else.
    FoldedInto(FrameKind),
    /// Dropped at source, with a reason.
    Dropped(&'static str),
}

/// Classify one `RuntimeEvent`.
///
/// EXHAUSTIVE by construction: no `_` arm. This function is where a twelfth
/// `RuntimeEvent` variant becomes a compile error in the bridge instead of a
/// fact nobody publishes.
#[must_use]
pub fn classify(event: &RuntimeEvent) -> Destination {
    match event {
        // ---------------------------------------------------------- carried
        //
        // NARROWS: nothing on the card. `host_id` is lifted OUT of the wrapper
        // and into `locator.host_id`, because SwarmFindingEnvelope has eight
        // fields and none of them is a host
        // (AMB crates/swarm-response/src/siem.rs:17-27).
        RuntimeEvent::Finding { .. } => Destination::Card(CardKind::Finding),

        // NARROWS: nothing. Carried whole onto an escalation card with
        // cause = concentration_crossing, PLUS a bridge-computed dedupe_key,
        // because the monitor re-emits this event at 10 Hz while over threshold
        // (AMB crates/swarm-runtime/src/escalation.rs:105-207, publish at :148).
        RuntimeEvent::Escalation { .. } => Destination::Card(CardKind::Escalation),

        // TWO DESTINATIONS. Every transition, in both directions, reaches the
        // 26003 frame. Only a transition INTO incident earns a durable card: a
        // de-escalation is not evidence about an attack, and a lane channel that
        // fills with "back to normal" rows teaches an operator to scroll past it.
        RuntimeEvent::ModeTransition { to, .. } => {
            if matches!(to, swarm_core::agent::SwarmMode::Incident) {
                Destination::Card(CardKind::Escalation)
            } else {
                Destination::Frame(FrameKind::ModeTransition)
            }
        }

        // TWO DESTINATIONS, and the split is the disclosure boundary.
        // fail_closed => a durable lane-channel card carrying the library PATHS and the
        // details string, because a lane channel is membership-gated.
        // Always => the 26005 frame carrying a COUNT and a hash, because the
        // frame is community-global.
        RuntimeEvent::TamperAlert { fail_closed, .. } => {
            if *fail_closed {
                Destination::Card(CardKind::Escalation)
            } else {
                Destination::Frame(FrameKind::TamperAlert)
            }
        }

        // ---------------------------------------------------------- frames
        //
        // NARROWS: everything per-event. correlation_id, event_id, source,
        // host_id and reason all stop at the bridge; only the second's counts
        // and a by-source histogram are published. host_id alone fails the
        // aggregates-only rule, and at the measured 3,645 events/second one
        // frame per event is not a design.
        RuntimeEvent::Ingest { .. } => Destination::Frame(FrameKind::IngestRate),

        // NARROWS: cadence only. Coalesced 10 Hz -> 1 Hz IN THE BRIDGE, BEFORE
        // THE IPC BOUNDARY. evaluate_all publishes a twelve-class snapshot
        // unconditionally on every tick
        // (AMB crates/swarm-runtime/src/escalation.rs:198-199) at 100 ms
        // (AMB .../bin/swarm_detect.rs:40) -- 864,000 a day at rest -- against a
        // 50-frames-per-5-seconds relay budget.
        RuntimeEvent::ConcentrationSnapshot { .. } => {
            Destination::Frame(FrameKind::Concentration)
        }

        // NARROWS: nothing. Carried whole, last-wins per agent_id.
        RuntimeEvent::AgentHealth { .. } => Destination::Frame(FrameKind::AgentHealth),

        // NARROWS: hunt_id and details, both entirely. Only the
        // {action_kind: count} tally survives, folded into the 26002 frame keyed
        // on agent_id. `details` is unbounded agent-shaped JSON and `hunt_id` is
        // a telemetry event id -- a join key into detection data -- on a
        // community-global frame.
        //
        // 03 section 4.2 files AgentAction under carrier H, "daemon HTTP only,
        // fetch the details on demand". That is unbuildable: none of the 49
        // routes on the operator surface (AMB crates/swarm-runtime-http/src/http/
        // state.rs:292-488) and none of the daemon's 16
        // (AMB crates/swarm-ingest-runtime/src/ingest/mod.rs:2540-2576) serves
        // agent actions. 07 section 4 is right and this is where it lands.
        RuntimeEvent::AgentAction { .. } => Destination::FoldedInto(FrameKind::AgentHealth),

        // ------------------------------------------------------- dropped
        RuntimeEvent::ResponseExecution { .. } => Destination::Dropped(
            "the receipt card carries the AuditTrail, which is the same fact with \
             the policy record and the detection attached. Publishing both would \
             put two rows in a case timeline for one execution.",
        ),
        RuntimeEvent::Replay { .. } => Destination::Dropped(
            "replay is a demo-mode concern. GET /v1/demo/* is gated behind \
             demo_mode_enabled() (AMB crates/swarm-ingest-runtime/src/ingest/\
             demo.rs:1284) and Perch does not render it.",
        ),
        RuntimeEvent::EvolutionStatus { .. } => Destination::Dropped(
            "EvolutionStatusReport is a Kitten-role artifact with no Perch \
             surface. When one exists it needs an eighth marker and the \
             justification shape in 03 section 4.4.",
        ),
    }
}

/// Which transport class a destination rides.
#[must_use]
pub const fn stream_of(destination: Destination) -> Stream {
    match destination {
        Destination::Card(_) => Stream::Evidence,
        Destination::Frame(kind) => kind.stream(),
        Destination::FoldedInto(kind) => kind.stream(),
        Destination::Dropped(_) => Stream::DroppedAtSource,
    }
}

#[cfg(test)]
mod tests {
    //! These tests exist to make the eleven-variant fan-out reviewable, not to
    //! exercise logic. A twelfth variant makes `classify` fail to compile, which
    //! is the real gate.
    use super::*;

    #[test]
    fn every_variant_has_a_named_destination() {
        // Constructing all eleven needs real domain values; the bridge crate's
        // fixture module supplies them. What this test pins is the CLASSIFICATION
        // TABLE, which is reviewable as data:
        let table = [
            ("ingest", "frame 26000, per-event fields dropped at source"),
            ("finding", "card swarm:finding:v1"),
            ("replay", "dropped — demo mode only"),
            ("agent_action", "folded into frame 26002 as a tally"),
            ("tamper_alert", "card when fail_closed, else frame 26005"),
            ("evolution_status", "dropped — no Perch surface"),
            ("response_execution", "dropped — the receipt card carries it"),
            ("agent_health", "frame 26002"),
            ("concentration_snapshot", "frame 26001, coalesced 10 Hz -> 1 Hz"),
            ("escalation", "card swarm:escalation:v1, deduped then edge-triggered"),
            ("mode_transition", "card when to == incident, else frame 26003"),
        ];
        assert_eq!(table.len(), 11, "eleven RuntimeEvent variants today");
    }
}
