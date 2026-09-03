//! The `26000`-`26006` ephemeral frame bodies.
//!
//! # Two rules govern this whole block
//!
//! **Aggregates only.** Every frame in the block is community-global — none
//! carries an `h` tag — and
//! reaches every member of the colony's Buzz community, including members on no
//! case. `handle_ephemeral_event`'s channel-less branch publishes to Redis
//! `EventTopic::Global` under a `Uuid::nil()` routing sentinel and fans out with
//! `channel_id = None`
//! (`BUZZ crates/buzz-relay/src/handlers/event.rs:875-903`), and
//! `filter_fanout_by_access` returns EVERY match at `:177-179` for a
//! channel-less event after applying only the receiver tenant label,
//! `AUTHOR_ONLY_KINDS` and `SHARED_GATED_KINDS`. So no host id, no indicator, no
//! finding id, no library path and no non-opaque join key may appear on a global
//! frame. Every narrowing in this module exists for that rule.
//!
//! **Admitted issuer.** A frame renders only if the NOSTR EVENT's `pubkey`
//! resolves to an admitted bridge identity; others are counted and dropped and
//! the count is visible. The ephemeral ingest gate is a single scope test with no
//! per-kind allowlist — `if !scopes.is_empty() &&
//! !scopes.contains(&Scope::MessagesWrite)`,
//! `BUZZ crates/buzz-relay/src/handlers/event.rs:699-707` — so every
//! chat-capable member of the community can publish one, and an empty scope set
//! passes outright. Without the rule, a member can page the rotation with a
//! fabricated `26003`, paint the Watchfloor with a fabricated `26001`/`26002`,
//! or put a phantom row in every queue with a fabricated `26006`.
//!
//! The predicate matches the EVENT's signer, not `Frame::issuer`, which is
//! inside content an adversary controls. The shipped precedent is
//! `getConfigNudgeAuthorPubkey`
//! (`BUZZ desktop/src/features/messages/ui/configNudgeAuthPubkey.ts:22-34`),
//! whose own doc comment states the rule: authenticate against
//! `message.signerPubkey`, the raw event signer, NOT `message.pubkey`, which may
//! be a relay-delegated display author.
//!
//! # Why the block needs zero relay change
//!
//! `handle_event` short-circuits every 20000-29999 kind into
//! `handle_ephemeral_event` and RETURNS at
//! `BUZZ crates/buzz-relay/src/handlers/event.rs:751`, before `ingest_event` is
//! reached at `:761`, so `required_scope_for_kind` never sees a `26xxx`. Proved
//! in-tree by `ephemeral_kinds_not_in_scope_allowlist`
//! (`BUZZ crates/buzz-relay/src/handlers/ingest.rs:3851-3854`).
//!
//! # WebSocket only
//!
//! `POST /events` goes straight into `ingest_event`
//! (`BUZZ crates/buzz-relay/src/api/bridge.rs:925`) with no ephemeral branch, so
//! an HTTP-posted `26xxx` is rejected `"restricted: unknown event kind"`. The
//! bridge must hold a live WebSocket.
//!
//! # The frame budget is the binding constraint, not the message quota
//!
//! `enforce_ws_admission` charges EVERY inbound `EVENT`, `REQ` and `COUNT` frame
//! against a 50-frames-per-rolling-5-second budget per pubkey, with NO agent
//! exemption (`BUZZ crates/buzz-relay/src/connection.rs:671-681` ->
//! `ws_admission_budget` at `BUZZ crates/buzz-relay/src/admission.rs:40-45`,
//! `WS_BURST_WINDOW_SECS = 5` at `:9`, `human_ws_events_per_sec = 10`). Seven
//! 1 Hz streams are 35 of 50. A pre-coalescing 10 Hz concentration stream
//! consumes the whole budget by itself, which is why `26001`'s coalescing is a
//! requirement and not an optimisation. REQ frames are charged too, and no plan
//! document budgets them: a reconnect storm that opens one REQ per case channel
//! can exhaust the window before a single frame is sent.

use serde::{Deserialize, Serialize};

use swarm_core::agent::{AgentHealth, AgentRole, SwarmMode};
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;
use swarm_policy::governance::PartitionState;

/// Which frame this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameKind {
    /// `26000`
    IngestRate,
    /// `26001`
    Concentration,
    /// `26002`
    AgentHealth,
    /// `26003`
    ModeTransition,
    /// `26004`
    GovernanceStatus,
    /// `26005`
    TamperAlert,
    /// `26006`
    HoldAlarm,
}

impl FrameKind {
    /// The Nostr kind.
    #[must_use]
    pub const fn kind(self) -> u16 {
        match self {
            Self::IngestRate => 26000,
            Self::Concentration => 26001,
            Self::AgentHealth => 26002,
            Self::ModeTransition => 26003,
            Self::GovernanceStatus => 26004,
            Self::TamperAlert => 26005,
            Self::HoldAlarm => 26006,
        }
    }

    /// Which of the bridge's four transport streams this frame rides.
    ///
    /// "stream" is a ruled word (appendix §7): one of the bridge's four transport
    /// classes, never a lane channel and never a queue.
    #[must_use]
    pub const fn stream(self) -> Stream {
        match self {
            Self::HoldAlarm => Stream::Alarm,
            // ModeTransition and TamperAlert ride BOTH: the alarm copy is what
            // fires a wake class, the telemetry copy is what paints the strip.
            Self::ModeTransition | Self::TamperAlert => Stream::AlarmAndTelemetry,
            _ => Stream::Telemetry,
        }
    }

    /// Whether the bridge may coalesce or shed this frame under back-pressure.
    ///
    /// `26006` is never coalesced and never shed: the <=400 ms end-to-end budget
    /// is on that frame, and shedding it means a destructive action waits for a
    /// human nobody told.
    #[must_use]
    pub const fn sheddable(self) -> bool {
        !matches!(self, Self::HoldAlarm)
    }
}

/// The bridge's transport classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Stream {
    Evidence,
    Telemetry,
    Alarm,
    AlarmAndTelemetry,
    DroppedAtSource,
}

/// One ephemeral frame.
///
/// Frames carry NO spine envelope: they are aggregates, not records, nothing
/// stores them, and a hash chain over a lossy stream would claim a property it
/// cannot have. `seq` alone is here, because a gap between two frames the console
/// actually received is a real, renderable fact.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "schema")]
pub enum Frame {
    /// `26000`
    #[serde(rename = "ambush.perch.frame.ingest_rate.v1")]
    IngestRate(FrameHeader, IngestRate),
    /// `26001`
    #[serde(rename = "ambush.perch.frame.concentration.v1")]
    Concentration(FrameHeader, ConcentrationFrame),
    /// `26002`
    #[serde(rename = "ambush.perch.frame.agent_health.v1")]
    AgentHealth(FrameHeader, AgentHealthFrame),
    /// `26003`
    #[serde(rename = "ambush.perch.frame.mode_transition.v1")]
    ModeTransition(FrameHeader, ModeTransitionFrame),
    /// `26004`
    #[serde(rename = "ambush.perch.frame.governance_status.v1")]
    GovernanceStatus(FrameHeader, GovernanceStatusFrame),
    /// `26005`
    #[serde(rename = "ambush.perch.frame.tamper_alert.v1")]
    TamperAlert(FrameHeader, TamperAlertFrame),
    /// `26006`
    #[serde(rename = "ambush.perch.frame.hold_alarm.v1")]
    HoldAlarm(FrameHeader, HoldAlarm),
}

/// Fields every frame carries.
///
/// `#[serde(flatten)]` at the use site keeps the wire form flat, matching the
/// JSON Schemas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameHeader {
    /// The Nostr kind, repeated in the body so a copied frame is
    /// self-describing.
    pub kind: u16,
    /// The bridge's spine identity, FOR DISPLAY ONLY. The admission check reads
    /// the event's `pubkey`.
    pub issuer: String,
    /// The source `RuntimeEvent`'s `emitted_at_ms`, or the aggregation window's
    /// close for `26000`/`26001`.
    pub emitted_at_ms: i64,
    /// Per-kind monotonic counter.
    pub seq: u64,
}

/// `26000` — ingest counts.
///
/// NARROWING, total. `RuntimeEvent::Ingest`
/// (`AMB crates/swarm-runtime/src/runtime_events.rs:216-223`) carries
/// `correlation_id`, `event_id`, `source`, `Option<String> host_id`, `accepted`
/// and `Option<String> reason` PER EVENT. None of it crosses the wire: `host_id`
/// alone fails the aggregates-only rule, and at the measured 3,645 events/second
/// one frame per event is not a design. The bridge classifies these as
/// dropped-at-source and publishes only the second's counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestRate {
    /// Always 1000.
    pub window_ms: u32,
    /// Count of `accepted == true` in the window.
    pub accepted: u64,
    /// Count of `accepted == false`.
    pub rejected: u64,
    /// Counts keyed by `RuntimeEvent::Ingest.source`, a COLLECTOR name. A source
    /// name that looks like a host is a bridge configuration error and the bridge
    /// refuses to publish it rather than leaking one.
    pub by_source: std::collections::BTreeMap<String, u64>,
}

/// `26001` — a coalesced concentration snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcentrationFrame {
    /// Mode at the last coalesced tick.
    pub current_mode: SwarmMode,
    /// Twelve entries minimum — `standard_threat_classes()` returns exactly
    /// twelve (`AMB crates/swarm-runtime/src/escalation.rs:315-330`) and
    /// `snapshot_concentrations` loops it. A `ThreatClass::Custom` class may
    /// appear as a thirteenth; it has no lane channel and the console renders it in an
    /// explicit overflow row rather than folding it into the nearest standard
    /// class.
    pub concentrations: Vec<ThreatConcentration>,
    /// How many daemon ticks this frame collapsed. Rendered as the derived
    /// marker render law 4 requires: the console is showing 1 of N and says so.
    pub coalesced_from: u32,
    /// The substrate's own `now`, in SECONDS, in its native unit and with the
    /// unit in the name. A shared millisecond helper here produces a 1000x wrong
    /// decay curve silently, in the direction of "everything looks evaporated".
    pub observed_at_seconds: i64,
}

/// `RuntimeThreatConcentration`
/// (`AMB crates/swarm-runtime/src/runtime_events.rs:191-196`), carried whole.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatConcentration {
    /// The class.
    pub threat_class: ThreatClass,
    /// Post-evaporation, post-suppression sum at `observed_at_seconds`.
    pub total_strength: f64,
    /// **Never render bare.** Counts agent instance ids, not detectors.
    pub distinct_sources: usize,
    /// Highest deposit confidence in the sum.
    pub peak_confidence: f64,
}

/// `26002` — agent liveness and action tallies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHealthFrame {
    /// One entry per agent whose state changed, or whose tally is non-empty.
    pub agents: Vec<AgentHealthEntry>,
}

/// One agent's liveness plus its action tally.
///
/// NARROWING. `RuntimeEvent::AgentAction`
/// (`AMB crates/swarm-runtime/src/runtime_events.rs:241-248`) carries
/// `hunt_id: Option<String>` and `details: serde_json::Value`. NEITHER crosses
/// the wire: `hunt_id` is a telemetry event id and a join key into detection
/// data, and `details` is unbounded agent-shaped JSON. Only the
/// `{action_kind: count}` tally survives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHealthEntry {
    /// `RuntimeEvent::AgentHealth.agent_id`.
    pub agent_id: String,
    /// One of eight.
    pub role: AgentRole,
    /// `None` on the first observation of an agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<AgentHealth>,
    /// Current health.
    pub to: AgentHealth,
    /// When it changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_at_ms: Option<i64>,
    /// `action_kind` -> count since the previous `26002` for this agent.
    pub actions: std::collections::BTreeMap<String, u64>,
}

/// `26003` — a swarm mode transition, in EITHER direction.
///
/// `SwarmModeState::transition_to` refuses a non-upward move
/// (`AMB crates/swarm-core/src/agent.rs:137-146`) but `transition_down` exists on
/// the same type with the mirror guard and mutates `current` (`:148-155`), so the
/// mode is not monotonic. A header band that can only ever appear is one an
/// operator learns to ignore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeTransitionFrame {
    /// Mode before.
    pub from: SwarmMode,
    /// Mode after.
    pub to: SwarmMode,
    /// Always `None` on a de-escalation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triggering_threat_class: Option<ThreatClass>,
    /// The runtime's own reason string.
    pub reason: String,
}

/// `26004` — the governance authority's account of itself.
///
/// All EIGHT fields of `GovernanceStatusReport`
/// (`AMB crates/swarm-policy/src/governance.rs:55-71`). APPENDIX-NORMATIVE §3
/// lists six; `last_transition_at_ms` and `last_reconciliation_report_id` are
/// also on the type, and the first is the natural source for the governance
/// strip's staleness clock.
///
/// `INV-09`: no surface may render a quorum fraction from these numbers. The
/// honest string is `committee of 1 (solo transport)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceStatusFrame {
    /// One of four.
    pub partition_state: PartitionState,
    /// Configured governors.
    pub total_governors: usize,
    /// Governors currently healthy.
    pub healthy_governors: usize,
    /// Threshold for a quorum.
    pub quorum_threshold: usize,
    /// Contingency leases open right now.
    pub active_contingency_leases: usize,
    /// Actions taken during a partition without authorization.
    pub unauthorized_partition_actions: usize,
    /// The strip's `recv Nm ago` clock reads this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition_at_ms: Option<i64>,
    /// Last reconciliation report, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reconciliation_report_id: Option<String>,
    /// `runtime.partition_contingency_lease_ttl_ms`, so no surface has to guess.
    /// The production default is 300_000 ms
    /// (`AMB crates/swarm-core/src/config/defaults.rs:15`, set explicitly at
    /// `AMB rulesets/default.yaml:20` and threaded into
    /// `GovernancePolicyConfig.contingency_lease_ttl_ms` at
    /// `AMB crates/swarm-runtime-http/src/bin/swarm_detect.rs:721`). `06` §2.2's
    /// "60-second TTL, dispatcher.rs:1592" cites a `#[tokio::test]` fixture and
    /// is wrong by 5x.
    pub contingency_lease_ttl_ms: i64,
}

/// `26005` — a tamper alert, counts only.
///
/// NARROWING. `RuntimeEvent::TamperAlert`
/// (`AMB crates/swarm-runtime/src/runtime_events.rs:249-256`) carries
/// `unexpected_library_loads: Vec<String>` — host filesystem paths — and a
/// free-form `details: String`. Neither crosses a community-global frame. Both
/// are carried on the durable `ambush:escalation:v1` lane card with
/// `cause = tamper_fail_closed`, which is channel-scoped and membership-gated.
/// The sha256 is on BOTH so the two can be joined without the frame disclosing
/// anything.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperAlertFrame {
    /// Whether a debugger was attached.
    pub debugger_attached: bool,
    /// The tracer pid, when one was found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracer_pid: Option<u32>,
    /// `unexpected_library_loads.len()`.
    pub unexpected_library_count: usize,
    /// `0x`-prefixed sha256 over the newline-joined, sorted path list.
    pub unexpected_library_sha256: String,
    /// Whether the runtime failed closed.
    pub fail_closed: bool,
}

/// `26006` — the hold alarm. The ONLY live path to a hold.
///
/// GLOBAL, NO `h` TAG, AND `26006` IS ADDED TO `P_GATED_KINDS`.
///
/// This is the ratified answer to the alarm-disclosure hole. It is `adr/0017`
/// clause C3, and `APPENDIX-NORMATIVE.md` §3's "global (no `h`)" survives
/// unchanged. `13-WIRE-SCHEMAS.md` amendment `W-1` previously specified an `h`
/// tag naming a standing `#watch` channel; **W-1 is WITHDRAWN** and `W-9`
/// records why.
///
/// THE HOLE IS REAL. `filter_fanout_by_access` applies only the receiver tenant
/// label, `AUTHOR_ONLY_KINDS` and `SHARED_GATED_KINDS` to a channel-less event
/// and then returns every match
/// (`BUZZ crates/buzz-relay/src/handlers/event.rs:115-222`, early return at
/// `:177-179`). Without a further gate, any authenticated community member
/// opening `REQ {kinds:[26006]}` receives every hold alarm — `hold_id`,
/// `action_kind`, `severity`, `case_channel`, `expires_at_ms` — including alarms
/// `p`-tagged to other operators.
///
/// WHY THE `h` TAG DOES NOT FIX IT, WHICH IS THE PART W-1 GOT WRONG. The p-gate
/// is scoped to global subscriptions ONLY:
/// `crates/buzz-relay/src/handlers/req.rs:218` wraps `p_gated_filters_authorized`
/// in `if channel_id.is_none()`, and the comment at `:215-217` says so outright —
/// *"Only applies to GLOBAL subscriptions (channel_id = None): channel-scoped
/// subs can never receive globally-stored events because of the fan_out()
/// invariant in subscription.rs."* An `h`-tagged `26006` is delivered through the
/// channel index, where the gate is never consulted, so any member of the
/// `#watch` channel could open `{kinds:[26006],"#h":[watch]}` and read every
/// operator's alarms. The `h` tag narrows the disclosure ring from the community
/// to the ops channel; it does not close it. It would also silently break the
/// only shipped client filter — `perchSubscriptions.ts` writes a global
/// `{kinds:[26006],"#p":[me],limit:0}`, which under W-1 delivers zero frames with
/// nothing failing loudly.
///
/// WHAT C3 BUYS. With `26006` in `P_GATED_KINDS`
/// (`BUZZ crates/buzz-core/src/kind.rs:159-169`, which already carries
/// `KIND_AGENT_OBSERVER_FRAME` — an ephemeral, included for exactly this
/// filter-layer enforcement per the doc comment at `:156-158`),
/// `p_gated_filters_authorized` (`req.rs:1182-1215`) requires every global filter
/// naming `26006` to carry a `#p` whose values are ALL the authed pubkey
/// (`:1211-1213`), and CLOSEs the subscription otherwise with
/// `"restricted: p-gated events require #p matching your pubkey"`. A member
/// cannot subscribe to another operator's alarms at all, and the `p` tags stop
/// being a client-side paging hint and become the relay's own authorization test.
///
/// COST: one line in `buzz-core` — a THIRD fork site beyond the two `ingest.rs`
/// arms. That is brief amendment `AD-A7`'s framing: "three hunks in
/// `buzz-relay/src/handlers/ingest.rs` and one line in `buzz-core/src/kind.rs`;
/// zero client registration points."
///
/// NEVER COALESCED, NEVER SHED. The <=400 ms end-to-end budget rides this frame,
/// not the durable row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoldAlarm {
    /// Opaque random token, shape pinned by
    /// `schemas/common.schema.json#/$defs/HoldId`. NEVER derived from `hunt_id`:
    /// this frame is the widest-audience object in the registry and `hunt_id` is
    /// a join key into detection data
    /// (`AMB crates/swarm-runtime/src/service/runtime_service.rs:391`).
    pub hold_id: String,
    /// `ResponseAction::kind()`.
    pub action_kind: String,
    /// `ActionRequest.severity`.
    pub severity: Severity,
    /// Where the durable record is.
    pub case_channel: String,
    /// When the hold lapses.
    pub expires_at_ms: i64,
}

/// The escalation level. Mirrors `AMB crates/swarm-runtime/src/runtime_events.rs:184-189`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum EscalationLevel {
    Alert,
    Incident,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_block_is_exactly_seven_contiguous_kinds() {
        let kinds: Vec<u16> = [
            FrameKind::IngestRate,
            FrameKind::Concentration,
            FrameKind::AgentHealth,
            FrameKind::ModeTransition,
            FrameKind::GovernanceStatus,
            FrameKind::TamperAlert,
            FrameKind::HoldAlarm,
        ]
        .iter()
        .map(|k| k.kind())
        .collect();
        assert_eq!(kinds, vec![26000, 26001, 26002, 26003, 26004, 26005, 26006]);
        assert!(kinds.iter().all(|k| crate::is_perch_frame_kind(*k)));
    }

    #[test]
    fn only_the_hold_alarm_is_unsheddable() {
        assert!(!FrameKind::HoldAlarm.sheddable());
        assert!(FrameKind::Concentration.sheddable());
    }

    #[test]
    fn seven_one_hz_streams_fit_the_ws_frame_budget() {
        // 50 frames per rolling 5 s, per pubkey, EVENT + REQ + COUNT alike
        // (BUZZ crates/buzz-relay/src/admission.rs:9,40-45). Seven 1 Hz streams
        // are 35, leaving 15 for un-shed 26006 alarms and REQ frames. A 10 Hz
        // 26001 alone would be 50.
        const BUDGET_PER_WINDOW: u32 = 50;
        const WINDOW_SECS: u32 = 5;
        let coalesced = 7 * WINDOW_SECS;
        let uncoalesced = (6 * WINDOW_SECS) + (10 * WINDOW_SECS);
        assert!(coalesced < BUDGET_PER_WINDOW);
        assert!(uncoalesced > BUDGET_PER_WINDOW);
    }
}
