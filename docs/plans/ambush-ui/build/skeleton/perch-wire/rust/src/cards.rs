//! The seven card bodies.
//!
//! Every field here is either a domain type re-exported from the crate that owns
//! it, or a field this crate adds for a stated reason. Where a wire type NARROWS
//! a domain type, the narrowing is named at the field with the reason and the
//! source line of the thing being narrowed. Where a domain type is carried
//! whole, it is carried by TYPE, never re-declared, so a field added upstream
//! reaches the wire without an edit here and a field removed upstream is a
//! compile error rather than a silently absent key.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// Module paths verified against the crates' own `pub mod` / `pub use` blocks:
// swarm-response/src/lib.rs:41-86, swarm-spine/src/lib.rs:46-87,
// swarm-policy/src/lib.rs:38-40, swarm-core/src/lib.rs:10-55.
use swarm_core::agent::SwarmMode;
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;
use swarm_policy::{ActionRequest, PolicyDecision};
use swarm_response::rollback::{RollbackReceipt, RollbackTrigger};
use swarm_response::SwarmFindingEnvelope;
use swarm_spine::AuditTrail;

use crate::envelope::{FactIssuer, OperatorFactIssuer};
use crate::marker::CardKind;

/// One of the seven card bodies, tagged by its own `schema` field.
///
/// `#[serde(tag = "schema")]` is internal tagging on a field every variant
/// already carries, so the wire form is exactly what the JSON Schemas describe
/// and there is no extra nesting level.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "schema")]
pub enum Card {
    /// `ambush:finding:v1`
    #[serde(rename = "ambush.perch.finding.v1")]
    Finding(FindingCard),
    /// `ambush:escalation:v1`
    #[serde(rename = "ambush.perch.escalation.v1")]
    Escalation(EscalationCard),
    /// `ambush:hold:v1`
    #[serde(rename = "ambush.perch.hold.v1")]
    Hold(HoldCard),
    /// `ambush:verdict:v1`
    #[serde(rename = "ambush.perch.verdict.v1")]
    Verdict(VerdictCard),
    /// `ambush:receipt:v1`
    #[serde(rename = "ambush.perch.receipt.v1")]
    Receipt(ReceiptCard),
    /// `ambush:lease:v1`
    #[serde(rename = "ambush.perch.lease.v1")]
    Lease(LeaseCard),
    /// `ambush:rollback:v1`
    #[serde(rename = "ambush.perch.rollback.v1")]
    Rollback(RollbackCard),
}

impl Card {
    /// Which marker this card must ship under.
    #[must_use]
    pub const fn kind(&self) -> CardKind {
        match self {
            Self::Finding(_) => CardKind::Finding,
            Self::Escalation(_) => CardKind::Escalation,
            Self::Hold(_) => CardKind::Hold,
            Self::Verdict(_) => CardKind::Verdict,
            Self::Receipt(_) => CardKind::Receipt,
            Self::Lease(_) => CardKind::Lease,
            Self::Rollback(_) => CardKind::Rollback,
        }
    }

    /// The one-line human fallback. THE DEGRADATION CONTRACT.
    ///
    /// This string is what the Flutter app renders, what an FTS snippet shows,
    /// and what `buzz --format compact messages thread` returns — that command
    /// projects an event to exactly `{id, content, created_at}` and drops `kind`,
    /// `pubkey` and `tags`
    /// (`BUZZ crates/buzz-cli/src/commands/messages.rs:335-354`, pinned by the
    /// test `compact_event_format_remains_the_three_key_contract` at `:1082-1106`).
    /// So it must name the identifiers a human needs to go find the real thing,
    /// on its own, with no tags and no kind.
    ///
    /// Voice law L5: every number carries its denominator and its unit. Appendix
    /// §7: `SCREAMING_SNAKE` only for `Severity`, `lower_snake_case` for anything
    /// that is a literal action kind or wire field.
    #[must_use]
    pub fn human_line(&self) -> String {
        match self {
            Self::Finding(c) => c.human_line(),
            Self::Escalation(c) => c.human_line(),
            Self::Hold(c) => c.human_line(),
            Self::Verdict(c) => c.human_line(),
            Self::Receipt(c) => c.human_line(),
            Self::Lease(c) => c.human_line(),
            Self::Rollback(c) => c.human_line(),
        }
    }
}

/// Separator between fields of a human fallback line: U+00B7 with a space either
/// side. Not a hyphen — a hyphen is a lexeme boundary in Postgres's `simple`
/// text-search configuration, so `web-04` would already contribute `web` and
/// `04` and a hyphen separator makes an FTS query for a field value ambiguous.
pub const HUMAN_SEP: &str = " · ";

// ───────────────────────────────────────────────────────────── finding

/// `ambush:finding:v1` — one `DetectionFinding`, in a lane channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingCard {
    /// Who produced it.
    pub issuer: FactIssuer,
    /// `RuntimeEvent::Finding.emitted_at_ms` unchanged.
    pub emitted_at_ms: i64,
    /// Join keys.
    pub locator: FindingLocator,
    /// `SwarmFindingEnvelope` VERBATIM
    /// (`AMB crates/swarm-response/src/siem.rs:17-27`, eight fields, unsigned,
    /// built `From<&DetectionFinding>` at `:29-41` where `schema` is hardcoded
    /// to `"swarm_finding"`).
    pub finding: SwarmFindingEnvelope,
    /// Present only when the bridge replaced `finding.evidence`.
    ///
    /// NARROWING, conditional. `DetectionFinding.evidence` is a
    /// `serde_json::Value` (`AMB crates/swarm-whisker/src/detector.rs:56`) built
    /// from telemetry an adversary can shape, and it is the only unbounded field
    /// in the whole registry. When the serialized card would exceed
    /// `CARD_CONTENT_MAX_BYTES` the bridge replaces it with a byte count and a
    /// hash, so the card renders an explicit absence rather than a silently
    /// smaller evidence blob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_truncated: Option<EvidenceTruncated>,
}

/// Join keys for a finding card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingLocator {
    /// `DetectionFinding.finding_id`.
    pub finding_id: String,
    /// The TELEMETRY event id. Half of the feedback-suppression key:
    /// `FeedbackSuppressionKey{threat_class, event_id}`
    /// (`AMB crates/swarm-pheromone/src/substrate.rs:345-348`), which
    /// `concentration_for` applies at `:1286` to drop every matching deposit at
    /// or before a Dismiss marker — reaching detectors the operator never
    /// reviewed. Carried in the locator, not only in `finding`, because the
    /// Dismiss preview arithmetic needs it without parsing the envelope.
    pub event_id: String,
    /// `DetectionFinding.strategy_id`.
    pub strategy_id: String,
    /// From the `RuntimeEvent::Finding` WRAPPER
    /// (`AMB crates/swarm-runtime/src/runtime_events.rs:224-228`), not from the
    /// envelope: `SwarmFindingEnvelope` has eight fields and none of them is a
    /// host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    /// The lane channel this was published into.
    pub lane_channel: String,
}

/// Replacement for an oversized evidence blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceTruncated {
    /// Serialized size of the omitted value.
    pub bytes: usize,
    /// `0x`-prefixed sha256 of its canonical form.
    pub sha256: String,
}

impl FindingCard {
    fn human_line(&self) -> String {
        // `Whisker-7a3f · data_exfiltration · HIGH · confidence 0.82 · host web-04 · finding f2c9a1b4`
        //
        // 06 §3: agent identities render `Name · role word` on first appearance.
        // The confidence carries two decimals AND the word, because a bare 0.82
        // beside a bare 2.41 is two different quantities that read the same.
        todo!("compose from issuer, finding and locator; see 13-WIRE-SCHEMAS.md §7.1")
    }
}

// ────────────────────────────────────────────────────────── escalation

/// `ambush:escalation:v1` — one of three daemon events, in a lane channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationCard {
    /// Who produced it.
    pub issuer: FactIssuer,
    /// The source event's `emitted_at_ms`.
    pub emitted_at_ms: i64,
    /// Join keys.
    pub locator: EscalationLocator,
    /// Which of the three, and its payload.
    pub escalation: EscalationBody,
}

/// Join keys for an escalation card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationLocator {
    /// The lane channel.
    pub lane_channel: String,
    /// Set when this escalation promoted a case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_channel: Option<String>,
}

/// Which daemon event this escalation card carries.
///
/// APPENDIX-NORMATIVE §3 collapses three `RuntimeEvent` variants onto one
/// marker. They are kept separable here so a renderer never guesses which shape
/// it holds, and so an exhaustive `match` fails to compile if a fourth is added.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cause", rename_all = "snake_case")]
pub enum EscalationBody {
    /// `RuntimeEvent::Escalation`
    /// (`AMB crates/swarm-runtime/src/runtime_events.rs:290-299`).
    ConcentrationCrossing(ConcentrationCrossing),
    /// `RuntimeEvent::ModeTransition` (`:300-306`), published only for a
    /// transition INTO `incident`. Every direction reaches the ephemeral `26003`;
    /// only this one earns a durable card, because a de-escalation is not
    /// evidence about an attack.
    ModeTransition(ModeTransitionBody),
    /// `RuntimeEvent::TamperAlert` (`:249-256`), published only when
    /// `fail_closed` is true.
    TamperFailClosed(TamperFailClosed),
}

/// A concentration crossing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcentrationCrossing {
    /// The class that crossed.
    pub threat_class: ThreatClass,
    /// `alert` or `incident`.
    pub level: crate::frames::EscalationLevel,
    /// Post-evaporation, post-suppression sum at the crossing instant.
    pub total_strength: f64,
    /// **Never render this bare.** See `distinct_sources_counts` for the unit
    /// and `source_ids_absent_reason` for why the other half of render law 2 is
    /// not derivable in Phase 1.
    pub distinct_sources: usize,
    /// The counting unit, carried so no surface has to assume it.
    pub distinct_sources_counts: SourceCountMechanism,
    /// The strategy-scoped ids themselves, or `None` with a NAMED reason.
    ///
    /// `None` on every Phase-1 card. The absence is carried as a named state in
    /// `source_ids_absent_reason` rather than left as a bare `None`, because
    /// render law 2's `M agents` half has no other source: `RuntimeEvent::Escalation`
    /// carries `distinct_sources: usize` and nothing else
    /// (`AMB crates/swarm-runtime/src/runtime_events.rs:288-296`), its input
    /// `RuntimeThreatConcentration` is four scalars (`:193-197`), and the bridge
    /// takes a `broadcast::Receiver` with no substrate handle. Only **B4** can
    /// serve them, and B4 is Phase 2.
    ///
    /// When B4 lands, a consumer derives the agent half by dropping the last
    /// colon-separated segment of each id and counting the distinct remainder —
    /// a derivation that is correct ONLY under the strategy-scoped mechanism,
    /// which is why the mechanism travels beside the ids.
    #[serde(default)]
    pub source_ids: Option<Vec<String>>,
    /// Why `source_ids` is `None`. Exactly one of this and `source_ids` is
    /// `Some`; `both_or_neither_is_a_decode_error` asserts it.
    pub source_ids_absent_reason: Option<SourceIdsAbsentReason>,
    /// Highest deposit confidence in the sum.
    pub peak_confidence: f64,
    /// Whether this crossing moved the swarm mode.
    pub mode_changed: bool,
    /// Mode after the crossing.
    pub current_mode: SwarmMode,
    /// `{threat_class_slug}:{level}:{unix_seconds}`.
    ///
    /// The monitor is LEVEL-triggered at 10 Hz
    /// (`CONCENTRATION_MONITOR_INTERVAL_MS = 100`,
    /// `AMB crates/swarm-runtime-http/src/bin/swarm_detect.rs:40`, driven at
    /// `:1002-1006`) and `evaluate_threat_class`
    /// (`AMB crates/swarm-runtime/src/escalation.rs:61-103`) is a pure level
    /// comparison with no memory, so it re-emits on every tick while over
    /// threshold — up to 120 events/second for twelve classes, against a 120/min
    /// per-pubkey relay quota. Its `now` is `unix_timestamp_secs`
    /// (`escalation.rs:407-410`), so all ten ticks in a second are byte-identical
    /// and this key dedupes them for free. The bridge then EDGE-TRIGGERS on a
    /// level change. Both steps are mandatory.
    pub dedupe_key: String,
}

/// What `distinct_sources` counts: the STRATEGY-SCOPED agent id.
///
/// Deliberately ONE variant. A closed single-variant enum makes the wrong
/// mechanism unrepresentable rather than merely undocumented, and a second
/// counting unit would be a wire change with its own argument, not a value a
/// producer picks. The earlier `AgentInstanceId` variant was factually wrong and
/// is removed; `13-WIRE-SCHEMAS.md` §9 amendment W-10 records the withdrawal.
///
/// THE PRODUCTION PATH, hop by hop, all inside `swarm_detect --serve`:
///
/// 1. `WhiskerAgent::tick` builds a base id
///    `AgentId(format!("{}:{}", derived_identity.0, self.id.0))`
///    (`AMB crates/swarm-agents/src/whisker_agent.rs:148-149`) — already
///    instance-scoped, two segments — and calls `detect_and_deposit_with_role`
///    with it at `:150-156`.
/// 2. `detect_and_deposit_with_role`
///    (`AMB crates/swarm-runtime/src/detection/pipeline.rs:60-91`) calls
///    `resolve_deposits` at `:80`.
/// 3. `resolve_deposits` sets EVERY deposit's
///    `agent_id: strategy_scoped_agent_id(agent_id, &finding.strategy_id)`
///    (`pipeline.rs:573`) — a THIRD segment, per detector.
/// 4. `strategy_scoped_agent_id` is `format!("{}:{strategy_id}", base.0)`
///    (`AMB crates/swarm-whisker/src/stream.rs:20-22`).
/// 5. `concentration_for`, run on each monitor tick, does
///    `sources.insert(deposit.agent_id.0.clone())`
///    (`AMB crates/swarm-pheromone/src/substrate.rs:1295`) and reports
///    `sources.len()` at `:1301`.
///
/// So one Whisker running two detectors is TWO sources / ONE agent, and clears
/// `min_sources_for_escalation: 2` on its own. The workspace asserts this itself:
/// `query_counts_strategy_scoped_agent_ids_as_distinct_sources`
/// (`AMB crates/swarm-pheromone/src/substrate.rs:2105`).
///
/// WARNING TO ANYONE RE-DERIVING THIS. `PheromoneConcentration`'s own doc
/// comments say "Sum of effective strengths from distinct agents" and "Number of
/// distinct agents contributing" (`AMB crates/swarm-core/src/pheromone.rs:323`,
/// `:325`). Those comments are wrong about the unit and are exactly how this was
/// misread twice. Read `pipeline.rs:573`, not the doc comment.
///
/// CONSEQUENCE FOR COPY: `APPENDIX-NORMATIVE.md` §8 render law 2 stands exactly
/// as written. `N sources / M agents` is two genuinely different numbers and the
/// expansion does not collapse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceCountMechanism {
    /// `{derived_identity}:{agent_id}:{strategy_id}` — one id per (agent
    /// instance, detector) pair.
    StrategyScopedAgentId,
}

/// Why `source_ids` is absent, as a value rather than an implication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceIdsAbsentReason {
    /// `RuntimeEvent::Escalation` carries a count and no ids
    /// (`AMB crates/swarm-runtime/src/runtime_events.rs:288-296`), and the
    /// bridge holds no substrate handle with which to resolve them. Only B4
    /// (`GET /v1/operator/pheromone/deposits`, Phase 2) can serve them.
    ///
    /// A component renders THIS REASON. It never renders a fabricated agent
    /// count and it never renders a spinner: nothing is loading.
    NotCarriedByRuntimeEvent,
}

/// A transition into `incident`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeTransitionBody {
    /// Mode before.
    pub from: SwarmMode,
    /// Always `incident` on a durable card.
    pub to: SwarmMode,
    /// `None` on a de-escalation, because `transition_down` clears it
    /// (`AMB crates/swarm-core/src/agent.rs:148-155`); always `Some` here,
    /// because `transition_to` requires it (`:137-146`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triggering_threat_class: Option<ThreatClass>,
    /// The runtime's own reason string.
    pub reason: String,
}

/// A fail-closed tamper alert.
///
/// UNLIKE the `26005` frame, this DURABLE card carries the paths and the detail
/// string. The aggregates-only rule is scoped to the community-global ephemeral
/// block; a lane channel is membership-gated, and an operator investigating a
/// tamper alert needs the library paths. The frame carries only a count and a
/// hash so two alarms can be compared for identity without disclosure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperFailClosed {
    /// `RuntimeEvent::TamperAlert.debugger_attached`.
    pub debugger_attached: bool,
    /// `RuntimeEvent::TamperAlert.tracer_pid`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracer_pid: Option<u32>,
    /// `unexpected_library_loads.len()`.
    pub unexpected_library_count: usize,
    /// `0x`-prefixed sha256 over the newline-joined, lexicographically sorted
    /// path list. Present on BOTH the card and the frame, so the two can be
    /// joined without the frame carrying paths.
    pub unexpected_library_sha256: String,
    /// The paths themselves. Card only, never on `26005`.
    pub unexpected_library_loads: Vec<String>,
    /// Always `true` on a durable card.
    pub fail_closed: bool,
    /// `RuntimeEvent::TamperAlert.details`
    /// (`AMB crates/swarm-runtime/src/runtime_events.rs:255`). Card only.
    pub details: String,
}

impl EscalationCard {
    fn human_line(&self) -> String {
        todo!("see 13-WIRE-SCHEMAS.md §7.1 for the three grammars")
    }
}

// ──────────────────────────────────────────────────────────────── hold

/// `ambush:hold:v1` — one held destructive action, in a case channel.
///
/// One hold produces two or more cards: an OPEN card (`state` in
/// `created|notified|armed|deciding`) and exactly one TERMINAL card (`state` in
/// `granted|refused|expired|executed|failed`) published as a NIP-10 reply to it.
/// The terminal card is the appendix's "also the expiry record". Both carry the
/// whole hold, because a card is immutable and a timeline must read top to
/// bottom without a join.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoldCard {
    /// Who produced it — the requesting agent.
    pub issuer: FactIssuer,
    /// When the hold was created, or when it reached its terminal state.
    pub emitted_at_ms: i64,
    /// Join keys.
    pub locator: HoldLocator,
    /// The hold.
    pub hold: HeldAction,
}

/// Join keys for a hold card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoldLocator {
    /// An OPAQUE RANDOM TOKEN, never `hold:{hunt_id}:{held_at_ms}`: `hunt_id` is
    /// the telemetry event id
    /// (`AMB crates/swarm-runtime/src/service/runtime_service.rs:391`), a join key
    /// into detection data, and `hold_id` travels in a `26006` frame — the
    /// widest-audience object in the registry. The shape is pinned by
    /// `schemas/common.schema.json#/$defs/HoldId`
    /// (`^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$`): URL-safe because it is a path
    /// parameter on `POST /v1/response/holds/{hold_id}/decide`, and
    /// COLON-FREE so the forbidden `hold:{hunt_id}:{held_at_ms}` derived form
    /// is unrepresentable rather than merely warned about.
    pub hold_id: String,
    /// The case channel UUID. In Perch's vocabulary the case id IS the channel
    /// UUID; a `CorrelatedIncident` is a different, recomputed object.
    pub case_channel: String,
    /// `ActionRequest.hunt_id`.
    pub hunt_id: String,
    /// Nostr event id of the `ambush:finding:v1` card this answers, when one
    /// exists. Also the `e` tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_card_id: Option<String>,
}

/// `HeldActionView` minus its two clock-derived fields.
///
/// Field-for-field the same object as
/// `build/openapi/perch-operator-v1.yaml#/components/schemas/HeldActionView`,
/// which is normative for the HTTP shape while this is normative for the wire
/// shape; `tools/check-perch-wire-parity.sh` (PROPOSED) holds them together.
///
/// NARROWING: `remaining_ms` and `expired` are NOT here. They are computed
/// against an observation instant and this card is immutable, so baking them in
/// would freeze a countdown at its publish value forever. The console recomputes
/// both from `expires_at_ms` and renders them as two separate elements —
/// `INV-06`, and the same rule `ContainmentLeaseView`'s own doc comment states
/// (`AMB crates/swarm-runtime-http/src/http/containment.rs:72-88`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeldAction {
    /// The opaque id, repeated inside the body so a copied JSON blob is
    /// self-describing.
    pub hold_id: String,
    /// The state machine. `12-BACKEND-BILL-API.md` §3.3 owns the transitions.
    pub state: HoldState,
    /// `ResponseAction::kind()`
    /// (`AMB crates/swarm-core/src/types.rs:558-576`).
    pub action_kind: String,
    /// `ActionRequest.severity`. REQUEST-CARRIED — see `rationale`.
    pub severity: Severity,
    /// When the daemon created the hold.
    pub held_at_ms: i64,
    /// `held_at_ms + PERCH_HOLD_TTL_MS` by default.
    pub expires_at_ms: i64,
    /// The request VERBATIM
    /// (`AMB crates/swarm-policy/src/lib.rs:45-58`). `severity` and the threat
    /// class inside `evidence` are set by the REQUESTING AGENT and read back by
    /// `ConfigurableApprovalGate::selector_matches`
    /// (`AMB crates/swarm-policy/src/configurable_gate.rs:44-56`), so an agent
    /// influences which rule judges its own destructive action.
    pub action_request: ActionRequest,
    /// The gate's verdict VERBATIM (`AMB crates/swarm-policy/src/lib.rs:73-83`).
    /// Today this is one constant pair for all twelve action kinds, which is why
    /// `rationale` exists.
    pub policy_decision: PolicyDecision,
    /// NEW IN B1. The differentiating context, captured at hold time.
    pub rationale: HoldRationale,
    /// `is_containment_action(action)`
    /// (`AMB crates/swarm-runtime/src/containment.rs:54-63`). FALSE for eight of
    /// the twelve destructive kinds, and a false means the card renders NO
    /// pending containment-lease slot rather than an empty one.
    pub leases_a_containment: bool,
    /// `SwarmService::rehearsal_preview`
    /// (`AMB crates/swarm-runtime/src/service/runtime_service.rs:861-868`, the
    /// public wrapper over the `pub(crate)` `build_rehearsal_preview`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rehearsal: Option<swarm_core::types::ResponseRehearsalPreview>,
    /// DERIVED, NOT SERVED. One entry per rollback step, from `resolve_inverse`
    /// (`AMB crates/swarm-response/src/rollback.rs:151-192`). Render law 4
    /// requires the console to name that function beside the row.
    #[serde(default)]
    pub inverse_resolution: Vec<InverseResolution>,
    /// `None` on the open card, `Some` on the terminal card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<HoldDecisionRecord>,
}

/// The hold state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum HoldState {
    Created,
    Notified,
    Armed,
    Deciding,
    Granted,
    Refused,
    Expired,
    Executed,
    Failed,
}

/// Why THIS action was held, as distinct from why holds exist.
///
/// Every hold today carries `rule_name = "static.human_gate"` and
/// `reason = "authorized but held for human approval"`, because
/// `StaticApprovalGate::evaluate`
/// (`AMB crates/swarm-policy/src/static_gate.rs:294-299`) is the only production
/// `RequireHuman` producer and `ConfigurableApprovalGate` can only emit
/// allow/deny before delegating (`configurable_gate.rs:172-183`). Render law 1's
/// WHY WE ARE ASKING slot would otherwise print the same 42 characters on all
/// twelve action kinds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoldRationale {
    /// Copied from `policy_decision`.
    pub rule_name: String,
    /// Copied from `policy_decision`.
    pub reason: String,
    /// From `request.evidence["escalation"]["threat_class"]`, falling back to
    /// `request.evidence["threat_class"]` — the same two keys
    /// `threat_class_from_request` reads
    /// (`AMB crates/swarm-policy/src/configurable_gate.rs:34-41`).
    pub threat_class: ThreatClass,
    /// `ActionRequest.severity`.
    pub severity: Severity,
    /// Which fields on this rationale came from the requesting agent rather than
    /// the runtime. Always contains at least `severity` and `threat_class`.
    pub request_carried_fields: Vec<String>,
    /// The class concentration when the hold was created, or `None` when no
    /// escalation context rode in the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concentration_at_hold: Option<crate::frames::ThreatConcentration>,
    /// `alert` or `incident`, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalation_level: Option<crate::frames::EscalationLevel>,
    /// Whether `evidence["governance_receipt"]` was present at HOLD time. NOT a
    /// verification result: B2g verifies at DECISION time and the answer can
    /// differ.
    pub governance_receipt_present: bool,
}

/// Per-step inverse resolution. DERIVED.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InverseResolution {
    /// The step this answers.
    pub step_kind: swarm_core::types::ResponseRollbackStepKind,
    /// `executable` | `irreversible` | `unmapped`.
    pub verdict: InverseVerdict,
    /// Quotable for `irreversible`; the shipped one reads "a terminated session
    /// cannot be resumed; the principal can only establish a fresh session"
    /// (`AMB crates/swarm-response/src/rollback.rs:183-189`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Outcome of `resolve_inverse` for one step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum InverseVerdict {
    Executable,
    Irreversible,
    Unmapped,
}

/// The stored outcome of a decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoldDecisionRecord {
    /// `grant` or `refuse`. NEVER `deny`: appendix §7 rules `refuse` to the
    /// operator, `deny` to the policy and `veto` to governance, and a body that
    /// says `deny` puts the policy's word in a human's mouth in the one record
    /// meant to keep them apart.
    pub decision: Decision,
    /// From `AuthenticatedOperatorPrincipal.operator_id`, never from a body.
    pub operator_id: String,
    /// The instant the hold store's compare-and-set succeeded, not the instant
    /// the operator's client claimed. Both the capability lease and the
    /// containment lease are minted from this.
    pub decided_at_ms: i64,
    /// 64-hex Nostr event id of the leg-1 card. The idempotency key.
    pub nostr_intent_event_id: String,
    /// The operator's Ed25519 signature, when the decide route recorded one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<swarm_crypto::DetachedSignature>,
    /// Free text the operator typed. Never parsed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    /// The daemon's outcome label.
    pub outcome: String,
    /// Whether the runtime attempted the response at all. False for every
    /// refusal and for a late refusal.
    pub dispatched: bool,
    /// Set only when the runtime produced one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    /// The named check that refused late, when one did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<Value>,
}

/// The operator's two verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Record my decision and send it to the daemon.
    Grant,
    /// Refuse. One keypress, no dialog, no undo.
    Refuse,
}

impl HoldCard {
    fn human_line(&self) -> String {
        todo!("see 13-WIRE-SCHEMAS.md §7.1")
    }
}

// ───────────────────────────────────────────────────────────── verdict

/// `ambush:verdict:v1` — LEG 1 OF THE TWO-LEGGED WRITE.
///
/// A signed human intent record, published by the OPERATOR'S OWN Nostr key. It
/// is not an authorization and no daemon reads it as one: leg 2 is a separate
/// POST across a process boundary and the daemon re-derives authority from
/// scratch. This is the only card the operator publishes and the only one whose
/// envelope `issuer` is not the bridge's.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictCard {
    /// The operator, as an `OperatorFactIssuer` — a SEPARATE type from
    /// `FactIssuer` whose `role` is structurally `()`, i.e. always serialized
    /// `null`.
    ///
    /// This is not a style choice. `AgentRole` is a closed eight-variant enum of
    /// SWARM agents (`AMB crates/swarm-core/src/agent.rs:14-34`) with no human
    /// member, and `AgentRole::Tom` is "Governance — enforces policy, manages
    /// lifecycle" (`agent.rs:26-27`): the veto actor. Stamping `tom` on an
    /// operator's own decision conflates the human's *refuse* with governance's
    /// *veto*, which `APPENDIX-NORMATIVE.md` §7 forbids and `adr/0016` spends a
    /// document keeping apart. The daemon could not produce it either —
    /// `infer_agent_role` (`AMB crates/swarm-runtime/src/detection/pipeline.rs:583-604`)
    /// prefix-matches and returns `None` for any operator id.
    ///
    /// A separate type makes the conflation a compile error. `W-8` previously
    /// filed this as a request for an `AgentRole`-free issuer; `W-11` records
    /// that it is now implemented rather than requested.
    pub issuer: OperatorFactIssuer,
    /// `decided_at_ms`.
    pub emitted_at_ms: i64,
    /// Join keys.
    pub locator: VerdictLocator,
    /// What was decided.
    pub decision: VerdictBody,
    /// Ed25519 over the RFC 8785 canonical form of
    /// `{decided_at_ms, decision, hold_id}` — EXACTLY the preimage the decide
    /// route requires, so ONE signature serves both legs and a reviewer diffing
    /// them checks one thing. `rationale` and `operator_id` are deliberately
    /// outside the preimage: rationale is free text the operator may reword, and
    /// `operator_id` is re-derived from `public_key_hex` by
    /// `voter_id_from_public_key`
    /// (`AMB crates/swarm-runtime/src/approval.rs:1783-1785`).
    pub signature: swarm_crypto::DetachedSignature,
    /// The console's own record of what leg 2 did, published as an UPDATE card
    /// replying to the first. `INV-33` forbids optimistic UI: three distinct
    /// states, none of them offering an undo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leg2: Option<Leg2State>,
}

/// Join keys for a verdict card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictLocator {
    /// The hold.
    pub hold_id: String,
    /// The case channel. `INV-12` asserts it equals the `h` tag; `INV-13`
    /// asserts a mismatch refuses to render.
    pub case_channel: String,
    /// Nostr event id of the open `ambush:hold:v1` card. Also the `e` tag.
    pub hold_card_id: String,
}

/// The decision itself. The signing preimage is a subset of this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictBody {
    /// `grant` | `refuse`.
    pub decision: Decision,
    /// The hold.
    pub hold_id: String,
    /// When the operator signed.
    pub decided_at_ms: i64,
    /// The configured Ambush operator principal id
    /// (`AMB crates/swarm-core/src/config/operator.rs:118-129`). The console
    /// asserts it equals `voter_id_from_public_key(signature.public_key_hex)`
    /// before publishing, because the decide route will.
    pub operator_id: String,
    /// Free text. Never parsed by anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

/// What leg 2 did.
///
/// TWO OPERATORS, ONE HOLD. `APPENDIX-NORMATIVE.md` §4 layer 1 `p`-tags EVERY
/// `OperatorScope::Approve` principal and §13's declined-amendment note confirms
/// the watch claim does not narrow that, so two consoles can legitimately hold
/// the same open hold. Leg 1 is published to the relay BEFORE leg 2 is POSTed
/// (§3.2's publish order), the relay has no compare-and-set, and a `kind:9` event
/// is immutable — so both signed verdict cards land in the case channel and stay
/// there forever. `12-BACKEND-BILL-API.md` §4.4 resolves the DAEMON side
/// (`409 hold_already_deciding` / `409 hold_already_decided`); `Superseded` is
/// the relay side of the same event.
///
/// It has to be the losing CONSOLE that publishes it: the daemon never saw the
/// losing leg-1 card, and the console is the only party holding both its own
/// card's event id and the 409 body naming the winner's. An operator who closes
/// the window before the 409 arrives therefore leaves an unqualified
/// human-decision record — which is why the reconciliation rule in
/// `13-WIRE-SCHEMAS.md` §3.5 is stated as a RENDER rule too, not only a publish
/// rule: a verdict card with no matching daemon decision record renders as
/// not-the-decision, whatever its `leg2` says.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Leg2State {
    /// The outcome.
    pub state: Leg2Outcome,
    /// Set once the daemon returns one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    /// The named check that refused, verbatim from the daemon. A late refusal is
    /// a NORMAL OUTCOME naming a rule, never a client error (`INV-28`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_check: Option<String>,
    /// The WINNING leg-1 card's Nostr event id — the `nostr_intent_event_id` the
    /// daemon recorded as the decision, read out of the 409 body.
    /// `Some` iff `state == Superseded`, asserted by
    /// `superseded_carries_its_winner`. `12-BACKEND-BILL-API.md` commits
    /// `nostr_intent_event_id` as `POST /decide`'s idempotency key, which is what
    /// makes this id available to the losing console at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
    /// When THIS console learned it had lost — its own clock at the 409, not the
    /// winner's `decided_at_ms`, which it never observes. `Some` iff
    /// `state == Superseded`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_at_ms: Option<i64>,
}

/// The five leg-2 outcomes. Closed; a sixth is a wire change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Leg2Outcome {
    /// Leg 1 is published; leg 2 has not answered.
    Sending,
    /// The daemon recorded the decision.
    Recorded,
    /// A receipt id came back.
    Acknowledged,
    /// The daemon refused AFTER leg 1 was signed and published. The intent
    /// record stands; the action did not run.
    RefusedLate,
    /// ANOTHER operator's decision was the one the daemon executed. This card is
    /// a human intent record that did not become the decision, and no surface
    /// may render it as one.
    Superseded,
}

impl Leg2State {
    /// `Ok(())` iff exactly the `Superseded` state carries a winner.
    ///
    /// Not a `Result` for ceremony: without it a `superseded` card with no
    /// `superseded_by` is a dead end for the reconciler, and a `recorded` card
    /// carrying one is a claim the console cannot have observed.
    pub fn assert_superseded_shape(&self) -> Result<(), &'static str> {
        let s = matches!(self.state, Leg2Outcome::Superseded);
        match (s, self.superseded_by.is_some(), self.superseded_at_ms.is_some()) {
            (true, true, true) | (false, false, false) => Ok(()),
            (true, _, _) => Err("leg2.superseded requires superseded_by and superseded_at_ms"),
            (false, _, _) => Err("only leg2.superseded may carry superseded_by/superseded_at_ms"),
        }
    }
}

impl VerdictCard {
    fn human_line(&self) -> String {
        todo!("see 13-WIRE-SCHEMAS.md §7.1")
    }
}

// ───────────────────────────────────────────────────────────── receipt

/// `ambush:receipt:v1` — one `AuditTrail`, in a case channel.
///
/// NARROWING: carries `AuditTrail` ONLY, not `AuditTrail` + `ResponseReceipt`.
/// APPENDIX-NORMATIVE §3 says both; `AuditResponseRecord::Success(ResponseReceipt)`
/// (`AMB crates/swarm-spine/src/lib.rs:103-110`) already embeds the whole receipt,
/// so carrying both puts a byte-for-byte duplicate in a card that `INV-26` then
/// has to reconcile against the daemon's stored body. See `13-WIRE-SCHEMAS.md`
/// §9 amendment W-5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptCard {
    /// Who executed.
    pub issuer: FactIssuer,
    /// `AuditTrail.created_at_ms`.
    pub emitted_at_ms: i64,
    /// Join keys.
    pub locator: ReceiptLocator,
    /// The trail VERBATIM (`AMB crates/swarm-spine/src/lib.rs:112-122`, seven
    /// fields, unsigned).
    pub audit_trail: AuditTrail,
}

/// Join keys for a receipt card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptLocator {
    /// `AuditTrail.trail_id`.
    pub trail_id: String,
    /// `AuditTrail.hunt_id`.
    pub hunt_id: String,
    /// The case channel.
    pub case_channel: String,
    /// `AuditTrail::response_receipt_id()`
    /// (`AMB crates/swarm-spine/src/lib.rs:136-145`): `Some` for the `Success`
    /// and `Failure` arms, `None` for `Skipped` and `GuardRejected`. Lifted into
    /// the locator so a search finds a receipt without parsing the trail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    /// Set when this receipt followed a human grant. Also the `e` tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict_card_id: Option<String>,
}

impl ReceiptCard {
    fn human_line(&self) -> String {
        todo!("see 13-WIRE-SCHEMAS.md §7.1")
    }
}

// ─────────────────────────────────────────────────────────────── lease

/// `ambush:lease:v1` — one containment lease on open, in a case channel.
///
/// NARROWING: carries `ContainmentLease` (which serializes as the private
/// `ContainmentLeaseRecord`, `AMB crates/swarm-response/src/containment.rs:101-118`
/// via `#[serde(into = ..., try_from = ...)]` at `:129-130`), NOT
/// `ContainmentLeaseView`. The View's `remaining_ms` and `expired` are computed
/// against an observation instant
/// (`AMB crates/swarm-runtime-http/src/http/containment.rs:72-88`) and this card
/// is immutable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseCard {
    /// Who opened it.
    pub issuer: FactIssuer,
    /// `lease.issued_at_ms`.
    pub emitted_at_ms: i64,
    /// Join keys.
    pub locator: LeaseLocator,
    /// The containment lease VERBATIM.
    pub lease: swarm_response::containment::ContainmentLease,
    /// Which config key the TTL came from, carried so no surface renders the
    /// wrong one. A containment lease's default TTL is 900_000 ms
    /// (`AMB crates/swarm-core/src/config/defaults.rs:23-27`); the 60_000 at
    /// `rulesets/default.yaml:94` is `policy.lease_ttl_ms`, the CAPABILITY
    /// lease's authorization window, and rendering it beside a containment lease
    /// is wrong by 15x.
    pub ttl_source: TtlSource,
}

/// Where a rendered TTL came from.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TtlSource {
    /// `runtime.containment.lease_ttl_ms`, default 900_000.
    #[serde(rename = "runtime.containment.lease_ttl_ms")]
    ContainmentLeaseTtlMs,
}

/// Join keys for a lease card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseLocator {
    /// `ContainmentLease::lease_id`.
    pub lease_id: String,
    /// The case channel.
    pub case_channel: String,
    /// The response receipt that made the containment.
    pub origin_receipt_id: String,
    /// Nostr event id of the `ambush:receipt:v1` card. Also the `e` tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_card_id: Option<String>,
}

impl LeaseCard {
    fn human_line(&self) -> String {
        todo!("see 13-WIRE-SCHEMAS.md §7.1")
    }
}

// ──────────────────────────────────────────────────────────── rollback

/// `ambush:rollback:v1` — one `RollbackReceipt`, replying to its lease card.
///
/// THE ONLY CARD THAT CAN REACH TIER 1 TODAY.
/// `RollbackReceipt.governance_attestation`
/// (`AMB crates/swarm-response/src/rollback.rs:263-285`) holds a serialized
/// `ConsensusGovernanceReceipt` over this receipt's canonical form with THAT
/// FIELD CLEARED, and `verify_release_attestation`
/// (`AMB crates/swarm-runtime/src/containment.rs:235-269`) checks the signature
/// AND the subject binding. It is actually called, at
/// `AMB crates/swarm-runtime-http/src/http/containment.rs:219-222`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackCard {
    /// Who ran it — the sweep, or the operator's release.
    pub issuer: FactIssuer,
    /// `rollback_receipt.completed_at_ms`.
    pub emitted_at_ms: i64,
    /// Join keys.
    pub locator: RollbackLocator,
    /// The receipt VERBATIM.
    pub rollback_receipt: RollbackReceipt,
    /// `ContainmentReleaseResponse` minus its receipt and schema_version
    /// (`AMB crates/swarm-runtime-http/src/http/containment.rs:126-145`).
    ///
    /// PRESENT ONLY for `RollbackTrigger::Manual`. An expiry-triggered rollback
    /// comes from the TTL sweep with no HTTP request and therefore no such body.
    /// `lease_closed: false` on an HTTP 200 means `release_lease` attempted the
    /// inverse, it failed, and the containment lease was deliberately kept open for the next
    /// sweep — a host is STILL contained. `INV-05` forbids reading the status
    /// code instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_response: Option<ReleaseOutcome>,
    /// Which of the two UNATTESTED renderings applies (`INV-08`).
    /// `Partitioned` or `Healing` means `UNATTESTED — BY DESIGN`. `None` means
    /// the console could not establish it and must say so rather than assume
    /// healthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition_state_at_execution: Option<swarm_policy::governance::PartitionState>,
}

/// The four booleans a release returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseOutcome {
    /// Read this, never the HTTP status.
    pub lease_closed: bool,
    /// Deliberately stricter than "nothing errored": a simulated step did not
    /// restore anything and an irreversible step never will
    /// (`AMB crates/swarm-response/src/rollback.rs:288-298`).
    pub fully_reversed: bool,
    /// From `verify_release_attestation`.
    pub attestation_verified: bool,
    /// Why it did not, when it did not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_error: Option<String>,
}

/// Join keys for a rollback card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackLocator {
    /// `RollbackReceipt.rollback_id`.
    pub rollback_id: String,
    /// The containment lease this closed.
    pub lease_id: String,
    /// The case channel.
    pub case_channel: String,
    /// Nostr event id of the `ambush:lease:v1` card. Also the `e` tag.
    pub lease_card_id: String,
}

impl RollbackCard {
    fn human_line(&self) -> String {
        let _ = RollbackTrigger::Manual;
        todo!("see 13-WIRE-SCHEMAS.md §7.1")
    }
}
