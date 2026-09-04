//! One `PolicyVerdict::RequireHuman` made durable (bill item B1).
//!
//! The record lives in `swarm-runtime` rather than `swarm-ingest-runtime`
//! because two consumers need the trait and neither may link the ingest crate:
//! the perch bridge (W3-13: it takes a bare receiver and holds a store handle
//! for the in-process `mark_*` callbacks `12-BACKEND-BILL-API.md` §3.2 names),
//! and `swarm_detect`, which builds the store from config beside the
//! containment store. The interception point stays in the ingest crate
//! (`perch_ops::holds::HoldCapture`).
//!
//! # State machine
//!
//! `created -> notified -> armed -> deciding -> {granted, refused}`,
//! `granted -> {executed, failed, refused}`, and `{created, notified, armed}
//! -> expired` on the sweep. `deciding` is never absorbing: `abandon_decision`
//! returns it to `prior_state`, and `fail_stalled_decisions` moves it to
//! `failed` after `decide_stall_ms`. `created` IS decidable — `notified` is a
//! fact about the queue card, not about the hold.

use serde::{Deserialize, Serialize};
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::{ResponseRehearsalPreview, Severity};
use swarm_crypto::DetachedSignature;
use swarm_policy::{ActionRequest, PolicyDecision};
use swarm_whisker::DetectionFinding;

use crate::runtime_events::{EscalationLevel, RuntimeThreatConcentration};

/// The nine hold states. Transitions are in the module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldState {
    /// Stored, not yet announced to anyone.
    Created,
    /// The relay accepted the `46010` notice.
    Notified,
    /// A console reported the row armed for a decision.
    Armed,
    /// One decision holds the compare-and-set claim.
    Deciding,
    /// Granted; dispatch has not reported back yet.
    Granted,
    /// Refused by the operator, or refused late.
    Refused,
    /// The TTL passed with no decision. No action was taken.
    Expired,
    /// Granted and the response executed.
    Executed,
    /// Granted and the response failed, or the decision stalled.
    Failed,
}

impl HoldState {
    /// `created`, `notified` or `armed`.
    pub fn is_open(self) -> bool {
        matches!(self, Self::Created | Self::Notified | Self::Armed)
    }

    /// `granted`, `refused`, `expired`, `executed` or `failed`.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Granted | Self::Refused | Self::Expired | Self::Executed | Self::Failed
        )
    }

    /// The wire string, matching `#[serde(rename_all = "snake_case")]`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Notified => "notified",
            Self::Armed => "armed",
            Self::Deciding => "deciding",
            Self::Granted => "granted",
            Self::Refused => "refused",
            Self::Expired => "expired",
            Self::Executed => "executed",
            Self::Failed => "failed",
        }
    }
}

/// `grant` / `refuse`. Never `deny`: `refuse` is the operator's word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldDecision {
    /// The operator allowed the held action to run.
    Grant,
    /// The operator refused it. Nothing is dispatched, ever.
    Refuse,
}

impl HoldDecision {
    /// The wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Refuse => "refuse",
        }
    }
}

/// What actually happened after a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldOutcome {
    /// Granted and the response executed for real.
    GrantedExecuted,
    /// Granted in a dry-run execution mode; nothing left the process.
    GrantedSimulated,
    /// Granted, dispatched, and the response failed.
    GrantedFailed,
    /// The operator refused while the hold was still decidable.
    RefusedByOperator,
    /// The decision arrived after the hold stopped being decidable.
    RefusedLate,
    /// A guard between the grant and the dispatch rejected the action.
    GuardRejected,
}

/// Which governance checks ran at decision time. No variant is named
/// `Verified`, because nothing this bill can build establishes that a
/// receipt's signer is a governor (`12-BACKEND-BILL-API.md` §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceClearance {
    /// The action carried no governance receipt and needed none.
    NotRequired,
    /// The partition authority admitted the act.
    PartitionAuthorized,
    /// The receipt's signature verified against its own stated key.
    ReceiptSignatureOk,
    /// The receipt's subject matched this hold's action.
    ReceiptSubjectBound,
}

/// Why a grant did not become an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldRefusal {
    /// One of the fifteen rules `12-BACKEND-BILL-API.md` §4.6 enumerates.
    pub rule: String,
    /// The verbatim reason from the refusing layer.
    pub reason: String,
}

/// The differentiating context render law 1 needs and `PolicyDecision`
/// cannot give: every hold today carries `static.human_gate` and the same
/// reason string.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HoldRationale {
    /// The policy rule that produced the `RequireHuman` verdict.
    pub rule_name: String,
    /// That rule's reason string, verbatim.
    pub reason: String,
    /// The threat class the requesting agent claimed.
    pub threat_class: ThreatClass,
    /// The severity the requesting agent claimed.
    pub severity: Severity,
    /// Always contains at least `severity` and `threat_class`: both are set by
    /// the requesting agent and read back by `ConfigurableApprovalGate`.
    pub request_carried_fields: Vec<String>,
    /// The pheromone concentration recorded in the request's evidence at hold
    /// time, if it carried one.
    ///
    /// Typed as [`RuntimeThreatConcentration`] and not
    /// `swarm_core::pheromone::PheromoneConcentration`: the record has to
    /// survive a round trip through a JSON document on disk (`FileHeldActionStore`)
    /// and `PheromoneConcentration` derives neither `Serialize` nor
    /// `Deserialize`. `RuntimeThreatConcentration` is this crate's existing
    /// serializable mirror of it, field for field, with a `From` impl.
    pub concentration_at_hold: Option<RuntimeThreatConcentration>,
    /// The escalation level in the request's evidence, if it carried one.
    pub escalation_level: Option<EscalationLevel>,
    /// Whether `evidence["governance_receipt"]` was present at hold time. Not
    /// a verification result.
    pub governance_receipt_present: bool,
}

/// The stored outcome of a decision. Written once, replayed byte-identically
/// to any retry carrying the same `nostr_intent_event_id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HoldDecisionRecord {
    /// Grant or refuse.
    pub decision: HoldDecision,
    /// From `AuthenticatedOperatorPrincipal.operator_id`, never from the body.
    pub operator_id: String,
    /// `swarm:ed25519:{public_key_hex}`, derived from the signature's own key.
    pub voter_id: String,
    /// The digest inside the signature preimage, or `None` when there was none.
    pub rationale_sha256: Option<String>,
    /// Whether the hold had reached `notified` at the compare-and-set.
    pub hold_notice_published: bool,
    /// Which governance checks ran.
    pub governance_clearance: GovernanceClearance,
    /// The compare-and-set instant. Both leases are minted from it.
    pub decided_at_ms: i64,
    /// The leg-1 card id. The idempotency key and an UNSIGNED pointer.
    pub nostr_intent_event_id: String,
    /// The operator's detached Ed25519 signature over the decision preimage.
    pub signature: Option<DetachedSignature>,
    /// The operator's free-text rationale, if any.
    pub rationale: Option<String>,
    /// What actually happened.
    pub outcome: HoldOutcome,
    /// Whether the runtime attempted the response at all.
    pub dispatched: bool,
    /// The response receipt id, when one was minted.
    pub receipt_id: Option<String>,
    /// The audit trail this decision produced.
    pub audit_trail_id: Option<String>,
    /// Why a grant did not become an action, when it did not.
    pub refusal: Option<HoldRefusal>,
}

/// One held destructive action. Field order IS the verdict pane's render
/// order and a test asserts it.
///
/// Not `PartialEq`: three of its members — `ActionRequest`, `DetectionFinding`
/// and `PolicyDecision` — derive only `Debug + Clone + Serialize + Deserialize`
/// in their own crates, so an equality bound here would be a widening of three
/// trusted-computing-base types for one convenience. Tests compare the fields
/// they care about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeldAction {
    /// `hold_` + lowercase v4 UUID; see [`mint_hold_id`].
    pub hold_id: String,
    /// Where this hold sits in the state machine.
    pub state: HoldState,
    /// ACTION. Persisted verbatim: `AuditTrail` does not carry it.
    pub action_request: ActionRequest,
    /// BLAST RADIUS. `None` when no preview could be built; the card renders
    /// an explicit absence.
    pub rehearsal: Option<ResponseRehearsalPreview>,
    /// The routed detection the request was authorized against.
    pub detection: DetectionFinding,
    /// The verdict that held it.
    pub policy_decision: PolicyDecision,
    /// WHY WE ARE ASKING.
    pub rationale: HoldRationale,
    /// When the hold was captured (unix ms).
    pub held_at_ms: i64,
    /// WHAT GRANTING OPENS is computed from this and the configured TTLs.
    pub expires_at_ms: i64,
    /// The runtime's own `AuditTrail.trail_id` for the `Skipped` trail.
    pub audit_trail_id: Option<String>,
    /// The case channel the bridge created (or reused) for this hold's hunt.
    /// `None` until the bridge reports it; a hold is decidable without one,
    /// but leg 1 has nowhere to be published until it exists.
    pub case_channel: Option<String>,
    /// When the relay accepted the `kind:46010` notice. Informational.
    pub notified_at_ms: Option<i64>,
    /// The `46010` event id, once accepted.
    pub notice_event_id: Option<String>,
    /// The `swarm:hold:v1` card's event id, once accepted.
    pub card_event_id: Option<String>,
    /// Set exactly once, by `complete_decision`.
    pub decision: Option<HoldDecisionRecord>,
    /// The `nostr_intent_event_id` that won the compare-and-set.
    pub deciding_intent_event_id: Option<String>,
    /// The instant the compare-and-set succeeded.
    pub cas_instant_ms: Option<i64>,
    /// The state the compare-and-set moved out of.
    pub prior_state: Option<HoldState>,
}

/// Why a hold cannot be decided right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotDecidable {
    /// `now_ms >= expires_at_ms`, or the state is already `expired`.
    Expired,
    /// Another decision holds the claim.
    Deciding,
    /// The hold is in a terminal state.
    Terminal,
}

/// `hold_` plus a lowercase RFC 4122 v4 UUID: 41 characters, purely random,
/// no timestamp, no `hunt_id`. Satisfies the R-3 pattern.
pub fn mint_hold_id() -> String {
    format!("hold_{}", uuid::Uuid::new_v4().hyphenated())
}

/// The R-3 wire pattern `^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$`, hand-written so
/// no regex engine sits under a safety assert.
pub fn is_opaque_hold_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (8..=64).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'-')
}

impl HeldAction {
    /// A fresh `created` hold.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hold_id: String,
        action_request: ActionRequest,
        detection: DetectionFinding,
        policy_decision: PolicyDecision,
        rehearsal: Option<ResponseRehearsalPreview>,
        held_at_ms: i64,
        expires_at_ms: i64,
        audit_trail_id: Option<String>,
    ) -> Self {
        let rationale = HoldRationale::derive(&action_request, &policy_decision);
        Self {
            hold_id,
            state: HoldState::Created,
            action_request,
            rehearsal,
            detection,
            policy_decision,
            rationale,
            held_at_ms,
            expires_at_ms,
            audit_trail_id,
            case_channel: None,
            notified_at_ms: None,
            notice_event_id: None,
            card_event_id: None,
            decision: None,
            deciding_intent_event_id: None,
            cas_instant_ms: None,
            prior_state: None,
        }
    }

    /// `created`, `notified` or `armed`.
    pub fn is_open(&self) -> bool {
        self.state.is_open()
    }

    /// Any of the five terminal states.
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Whether `is_containment_action` matches: true for exactly four of the
    /// twelve destructive kinds, so the card knows whether to render a
    /// pending containment-lease slot at all.
    pub fn leases_a_containment(&self) -> bool {
        crate::containment::is_containment_action(&self.action_request.action)
    }

    /// Read-only decidability check. Mutates nothing.
    pub fn assert_decidable(&self, now_ms: i64) -> Result<(), NotDecidable> {
        match self.state {
            HoldState::Deciding => Err(NotDecidable::Deciding),
            HoldState::Expired => Err(NotDecidable::Expired),
            state if state.is_terminal() => Err(NotDecidable::Terminal),
            _ if now_ms >= self.expires_at_ms => Err(NotDecidable::Expired),
            _ => Ok(()),
        }
    }
}

impl HoldRationale {
    /// Built at hold time from the request's own evidence. `severity` and
    /// `threat_class` are always request-carried.
    pub fn derive(request: &ActionRequest, decision: &PolicyDecision) -> Self {
        let escalation = request.evidence.get("escalation");
        let threat_class = escalation
            .and_then(|value| value.get("threat_class"))
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or(ThreatClass::Execution);
        let escalation_level = escalation
            .and_then(|value| value.get("level"))
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok());
        let concentration_at_hold = escalation
            .and_then(|value| value.get("concentration"))
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok());
        Self {
            rule_name: decision.rule_name.clone(),
            reason: decision.reason.clone(),
            threat_class,
            severity: request.severity,
            request_carried_fields: vec!["severity".to_string(), "threat_class".to_string()],
            concentration_at_hold,
            escalation_level,
            governance_receipt_present: request.evidence.get("governance_receipt").is_some(),
        }
    }
}

#[cfg(test)]
#[path = "held_action_tests.rs"]
pub(crate) mod tests;
