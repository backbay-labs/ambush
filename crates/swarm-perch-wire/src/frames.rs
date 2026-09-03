//! The `26000`-`26006` ephemeral frame bodies.
//!
//! # Two rules govern this whole block
//!
//! **Aggregates only.** Every frame in the block is community-global — none
//! carries an `h` tag — and reaches every member of the colony's community,
//! including members on no case. The relay's channel-less ephemeral branch fans
//! out with `channel_id = None` and returns EVERY match after applying only the
//! receiver tenant label and the author-only / shared-gated kind lists. So no
//! host id, no indicator, no finding id, no library path and no non-opaque join
//! key may appear on a global frame. Every narrowing in this module exists for
//! that rule.
//!
//! **Admitted issuer.** A frame renders only if the NOSTR EVENT's `pubkey`
//! resolves to an admitted bridge identity; others are counted and dropped and
//! the count is visible. The relay's ephemeral ingest gate is a single scope
//! test with no per-kind allowlist, so every chat-capable member of the
//! community can publish one, and an empty scope set passes outright. Without
//! the rule, a member can page the rotation with a fabricated `26003`, paint the
//! Watchfloor with a fabricated `26001`/`26002`, or put a phantom row in every
//! queue with a fabricated `26006`.
//!
//! The predicate matches the EVENT's signer, not [`FrameHeader::issuer`], which
//! is inside content an adversary controls.
//!
//! # Why the block needs zero relay change
//!
//! The relay short-circuits every 20000-29999 kind into its ephemeral handler
//! before `ingest_event` is reached, so `required_scope_for_kind` never sees a
//! `26xxx`. Proved in-tree by `ephemeral_kinds_not_in_scope_allowlist`.
//!
//! # WebSocket only
//!
//! `POST /events` goes straight into `ingest_event` with no ephemeral branch, so
//! an HTTP-posted `26xxx` is rejected `"restricted: unknown event kind"`. The
//! bridge must hold a live WebSocket.
//!
//! # The frame budget is the binding constraint, not the message quota
//!
//! The relay charges EVERY inbound `EVENT`, `REQ` and `COUNT` frame against a
//! 50-frames-per-rolling-5-second budget per pubkey, with NO agent exemption.
//! Seven 1 Hz streams are 35 of 50. A pre-coalescing 10 Hz concentration stream
//! consumes the whole budget by itself, which is why `26001`'s coalescing is a
//! requirement and not an optimisation. REQ frames are charged too: a reconnect
//! storm that opens one REQ per case channel can exhaust the window before a
//! single frame is sent.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::cards::{
    WireAgentHealth, WireAgentRole, WirePartitionState, WireResponseActionKind, WireSeverity,
    WireSwarmMode, WireThreatClass,
};

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
    /// Every frame kind, in kind order.
    pub const ALL: [Self; 7] = [
        Self::IngestRate,
        Self::Concentration,
        Self::AgentHealth,
        Self::ModeTransition,
        Self::GovernanceStatus,
        Self::TamperAlert,
        Self::HoldAlarm,
    ];

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

    /// The `schema` constant the frame body carries.
    #[must_use]
    pub const fn schema(self) -> &'static str {
        match self {
            Self::IngestRate => "swarm.perch.frame.ingest_rate.v1",
            Self::Concentration => "swarm.perch.frame.concentration.v1",
            Self::AgentHealth => "swarm.perch.frame.agent_health.v1",
            Self::ModeTransition => "swarm.perch.frame.mode_transition.v1",
            Self::GovernanceStatus => "swarm.perch.frame.governance_status.v1",
            Self::TamperAlert => "swarm.perch.frame.tamper_alert.v1",
            Self::HoldAlarm => "swarm.perch.frame.hold_alarm.v1",
        }
    }

    /// The frame kind for a Nostr kind, when it is one of the seven.
    #[must_use]
    pub fn from_kind(kind: u16) -> Option<Self> {
        Self::ALL.iter().copied().find(|k| k.kind() == kind)
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

/// One ephemeral frame, tagged by its `schema` field.
///
/// Frames carry NO spine envelope: they are aggregates, not records, nothing
/// stores them, and a hash chain over a lossy stream would claim a property it
/// cannot have. `seq` alone is here, because a gap between two frames the console
/// actually received is a real, renderable fact.
///
/// Each variant is a [`FrameBody`] — the four header fields flattened beside
/// the kind-specific body — so the wire form is exactly the flat object the
/// JSON Schemas describe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "schema")]
pub enum Frame {
    /// `26000`
    #[serde(rename = "swarm.perch.frame.ingest_rate.v1")]
    IngestRate(FrameBody<IngestRate>),
    /// `26001`
    #[serde(rename = "swarm.perch.frame.concentration.v1")]
    Concentration(FrameBody<ConcentrationFrame>),
    /// `26002`
    #[serde(rename = "swarm.perch.frame.agent_health.v1")]
    AgentHealth(FrameBody<AgentHealthFrame>),
    /// `26003`
    #[serde(rename = "swarm.perch.frame.mode_transition.v1")]
    ModeTransition(FrameBody<ModeTransitionFrame>),
    /// `26004`
    #[serde(rename = "swarm.perch.frame.governance_status.v1")]
    GovernanceStatus(FrameBody<GovernanceStatusFrame>),
    /// `26005`
    #[serde(rename = "swarm.perch.frame.tamper_alert.v1")]
    TamperAlert(FrameBody<TamperAlertFrame>),
    /// `26006`
    #[serde(rename = "swarm.perch.frame.hold_alarm.v1")]
    HoldAlarm(FrameBody<HoldAlarm>),
}

impl Frame {
    /// Which frame this is.
    #[must_use]
    pub const fn frame_kind(&self) -> FrameKind {
        match self {
            Self::IngestRate(_) => FrameKind::IngestRate,
            Self::Concentration(_) => FrameKind::Concentration,
            Self::AgentHealth(_) => FrameKind::AgentHealth,
            Self::ModeTransition(_) => FrameKind::ModeTransition,
            Self::GovernanceStatus(_) => FrameKind::GovernanceStatus,
            Self::TamperAlert(_) => FrameKind::TamperAlert,
            Self::HoldAlarm(_) => FrameKind::HoldAlarm,
        }
    }

    /// The four fields every frame carries.
    #[must_use]
    pub const fn header(&self) -> &FrameHeader {
        match self {
            Self::IngestRate(f) => &f.header,
            Self::Concentration(f) => &f.header,
            Self::AgentHealth(f) => &f.header,
            Self::ModeTransition(f) => &f.header,
            Self::GovernanceStatus(f) => &f.header,
            Self::TamperAlert(f) => &f.header,
            Self::HoldAlarm(f) => &f.header,
        }
    }
}

/// A frame header flattened beside its kind-specific body.
///
/// `#[serde(flatten)]` on both halves keeps the wire form flat, matching the
/// JSON Schemas, while the bridge still builds the body as its own type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrameBody<B> {
    /// The four fields every frame carries.
    #[serde(flatten)]
    pub header: FrameHeader,
    /// The kind-specific body.
    #[serde(flatten)]
    pub body: B,
}

/// Fields every frame carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
/// NARROWING, total. `RuntimeEvent::Ingest` carries `correlation_id`,
/// `event_id`, `source`, `host_id`, `accepted` and `reason` PER EVENT. None of
/// it crosses the wire: `host_id` alone fails the aggregates-only rule, and at
/// the measured 3,645 events/second one frame per event is not a design. The
/// bridge classifies these as dropped-at-source and publishes only the second's
/// counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub by_source: BTreeMap<String, u64>,
}

/// `26001` — a coalesced concentration snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConcentrationFrame {
    /// Mode at the last coalesced tick.
    pub current_mode: WireSwarmMode,
    /// Twelve entries minimum — the engine's `standard_threat_classes()`
    /// returns exactly twelve and its snapshot loops it. A custom class may
    /// appear as a thirteenth; it has no lane channel and the console renders
    /// it in an explicit overflow row rather than folding it into the nearest
    /// standard class.
    pub concentrations: Vec<ThreatConcentration>,
    /// How many daemon ticks this frame collapsed. Rendered as the derived
    /// marker render law 4 requires: the console is showing 1 of N and says so.
    pub coalesced_from: u32,
    /// The substrate's own `now`, in SECONDS, in its native unit and with the
    /// unit in the name. A shared millisecond helper here produces a 1000x wrong
    /// decay curve silently, in the direction of "everything looks evaporated".
    pub observed_at_seconds: i64,
}

/// The engine's `RuntimeThreatConcentration`, carried whole
/// (`common.schema.json#/$defs/PheromoneConcentration`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatConcentration {
    /// The class.
    pub threat_class: WireThreatClass,
    /// Post-evaporation, post-suppression sum at `observed_at_seconds`.
    pub total_strength: f64,
    /// **Never render bare.** Counts STRATEGY-SCOPED agent ids, not agent
    /// instances and not detectors alone — see
    /// [`crate::cards::SourceCountMechanism`].
    pub distinct_sources: usize,
    /// Highest deposit confidence in the sum.
    pub peak_confidence: f64,
}

/// `26002` — agent liveness and action tallies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentHealthFrame {
    /// One entry per agent whose state changed, or whose tally is non-empty.
    pub agents: Vec<AgentHealthEntry>,
}

/// One agent's liveness plus its action tally.
///
/// NARROWING. `RuntimeEvent::AgentAction` carries `hunt_id: Option<String>`
/// and `details: serde_json::Value`. NEITHER crosses the wire: `hunt_id` is a
/// telemetry event id and a join key into detection data, and `details` is
/// unbounded agent-shaped JSON. Only the `{action_kind: count}` tally survives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentHealthEntry {
    /// `RuntimeEvent::AgentHealth.agent_id`.
    pub agent_id: String,
    /// One of eight.
    pub role: WireAgentRole,
    /// `None` on the first observation of an agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<WireAgentHealth>,
    /// Current health.
    pub to: WireAgentHealth,
    /// When it changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_at_ms: Option<i64>,
    /// `action_kind` -> count since the previous `26002` for this agent.
    pub actions: BTreeMap<String, u64>,
}

/// `26003` — a swarm mode transition, in EITHER direction.
///
/// The engine's mode state refuses a non-upward `transition_to` but has a
/// `transition_down` with the mirror guard on the same type, so the mode is not
/// monotonic. A header band that can only ever appear is one an operator learns
/// to ignore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeTransitionFrame {
    /// Mode before.
    pub from: WireSwarmMode,
    /// Mode after.
    pub to: WireSwarmMode,
    /// Always `None` on a de-escalation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triggering_threat_class: Option<WireThreatClass>,
    /// The runtime's own reason string.
    pub reason: String,
}

/// `26004` — the governance authority's account of itself.
///
/// All EIGHT fields of the engine's `GovernanceStatusReport`, plus the TTL the
/// contingency lease runs on. `INV-09`: no surface may render a quorum fraction
/// from these numbers. The honest string is `committee of 1 (solo transport)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceStatusFrame {
    /// One of four.
    pub partition_state: WirePartitionState,
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
    /// `runtime.partition_contingency_lease_ttl_ms`, so no surface has to
    /// guess. The production default is 300_000 ms; the 60-second figure some
    /// earlier documents quote is a test fixture and is wrong by 5x.
    pub contingency_lease_ttl_ms: i64,
}

/// `26005` — a tamper alert, counts only.
///
/// NARROWING. `RuntimeEvent::TamperAlert` carries `unexpected_library_loads` —
/// host filesystem paths — and a free-form `details` string. Neither crosses a
/// community-global frame. Both are carried on the durable `swarm:escalation:v1`
/// lane card with `cause = tamper_fail_closed`, which is channel-scoped and
/// membership-gated. The sha256 is on BOTH so the two can be joined without the
/// frame disclosing anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
/// GLOBAL, NO `h` TAG, AND `26006` IS IN THE RELAY'S `P_GATED_KINDS`.
///
/// This is the ratified answer to the alarm-disclosure hole: `adr/0017` clause
/// C3. Without a further gate, any authenticated community member opening
/// `REQ {kinds:[26006]}` would receive every hold alarm — `hold_id`,
/// `action_kind`, `severity`, `case_channel`, `expires_at_ms` — including alarms
/// `p`-tagged to other operators. An `h` tag does NOT fix it: the relay's
/// p-gate runs only for global subscriptions, so an `h`-tagged `26006` is
/// delivered through the channel index where the gate is never consulted,
/// narrowing the disclosure ring to the ops channel's membership rather than
/// closing it. With `26006` in `P_GATED_KINDS` the relay requires every global
/// filter naming it to carry a `#p` whose values are ALL the authed pubkey,
/// and the `p` tags stop being a client-side paging hint and become the relay's
/// own authorization test. See [`crate::tags::TagError::ScopedHoldAlarm`].
///
/// NEVER COALESCED, NEVER SHED. The <=400 ms end-to-end budget rides this frame,
/// not the durable row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldAlarm {
    /// Opaque random token, shape pinned by [`crate::tags::HoldId`]. NEVER
    /// derived from `hunt_id`: this frame is the widest-audience object in the
    /// registry and `hunt_id` is a join key into detection data.
    pub hold_id: String,
    /// `ResponseAction::kind()`.
    pub action_kind: WireResponseActionKind,
    /// `ActionRequest.severity`.
    pub severity: WireSeverity,
    /// Where the durable record is.
    pub case_channel: String,
    /// When the hold lapses.
    pub expires_at_ms: i64,
}

/// The escalation level (`common.schema.json#/$defs/EscalationLevel`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum EscalationLevel {
    Alert,
    Incident,
}

impl EscalationLevel {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::Incident => "incident",
        }
    }

    /// The SCREAMING_SNAKE spelling a human line uses for `{LEVEL}`.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Alert => "ALERT",
            Self::Incident => "INCIDENT",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_block_is_exactly_seven_contiguous_kinds() {
        let kinds: Vec<u16> = FrameKind::ALL.iter().map(|k| k.kind()).collect();
        assert_eq!(kinds, vec![26000, 26001, 26002, 26003, 26004, 26005, 26006]);
        assert!(kinds.iter().all(|k| crate::is_perch_frame_kind(*k)));
        for kind in FrameKind::ALL {
            assert_eq!(FrameKind::from_kind(kind.kind()), Some(kind));
        }
        assert_eq!(FrameKind::from_kind(26007), None);
    }

    #[test]
    fn only_the_hold_alarm_is_unsheddable() {
        assert!(!FrameKind::HoldAlarm.sheddable());
        assert!(FrameKind::Concentration.sheddable());
    }

    #[test]
    fn seven_one_hz_streams_fit_the_ws_frame_budget() {
        // 50 frames per rolling 5 s, per pubkey, EVENT + REQ + COUNT alike.
        // Seven 1 Hz streams are 35, leaving 15 for un-shed 26006 alarms and
        // REQ frames. A 10 Hz 26001 alone would be 50.
        const BUDGET_PER_WINDOW: u32 = 50;
        const WINDOW_SECS: u32 = 5;
        let coalesced = 7 * WINDOW_SECS;
        let uncoalesced = (6 * WINDOW_SECS) + (10 * WINDOW_SECS);
        assert!(coalesced < BUDGET_PER_WINDOW);
        assert!(uncoalesced > BUDGET_PER_WINDOW);
    }

    #[test]
    fn a_frame_is_flat_on_the_wire_and_tagged_by_schema() {
        let frame = Frame::HoldAlarm(FrameBody {
            header: FrameHeader {
                kind: 26006,
                issuer: "swarm:ed25519:00".into(),
                emitted_at_ms: 1,
                seq: 8,
            },
            body: HoldAlarm {
                hold_id: "h_a07aeacf".into(),
                action_kind: WireResponseActionKind::IsolateHost,
                severity: WireSeverity::Critical,
                case_channel: "27799e23-ab25-4659-b381-3de47ea7ca4d".into(),
                expires_at_ms: 2,
            },
        });
        let wire = serde_json::to_value(&frame).unwrap();
        assert_eq!(
            wire,
            json!({
                "schema": "swarm.perch.frame.hold_alarm.v1",
                "kind": 26006,
                "issuer": "swarm:ed25519:00",
                "emitted_at_ms": 1,
                "seq": 8,
                "hold_id": "h_a07aeacf",
                "action_kind": "isolate_host",
                "severity": "CRITICAL",
                "case_channel": "27799e23-ab25-4659-b381-3de47ea7ca4d",
                "expires_at_ms": 2
            })
        );
        let back: Frame = serde_json::from_value(wire).unwrap();
        assert_eq!(back, frame);
        assert_eq!(back.frame_kind(), FrameKind::HoldAlarm);
        assert_eq!(back.header().kind, FrameKind::HoldAlarm.kind());
        assert_eq!(
            back.frame_kind().schema(),
            "swarm.perch.frame.hold_alarm.v1"
        );
    }

    #[test]
    fn the_level_label_is_screaming_snake_and_the_wire_form_is_not() {
        assert_eq!(EscalationLevel::Alert.label(), "ALERT");
        assert_eq!(EscalationLevel::Incident.as_str(), "incident");
        assert_eq!(
            serde_json::to_value(EscalationLevel::Incident).unwrap(),
            json!("incident")
        );
    }
}
