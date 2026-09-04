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

use std::collections::BTreeMap;
use std::sync::RwLock;

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

/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
pub enum HeldActionStoreError {
    /// No hold with that id.
    #[error("no hold `{hold_id}`")]
    NotFound {
        /// The id that was looked up.
        hold_id: String,
    },
    /// Carries the CURRENT record so the route can tell a replay from a
    /// conflict without a second read.
    #[error("hold `{hold_id}` is not decidable in state {}", current.state.as_str())]
    NotDecidable {
        /// The id that was claimed.
        hold_id: String,
        /// The record as it stands, boxed because `HeldAction` is large.
        current: Box<HeldAction>,
    },
    /// A hold with that id already exists.
    #[error("hold `{hold_id}` already exists")]
    Duplicate {
        /// The id that collided.
        hold_id: String,
    },
    /// The backing directory or document could not be read or written.
    #[error("hold store io error at {path}: {source}")]
    Io {
        /// The path that failed.
        path: String,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
    /// A stored document did not parse. Never skipped: a skipped hold is a
    /// destructive action nobody is shown.
    #[error("hold store document {path} is corrupt: {reason}")]
    Corrupt {
        /// The document that failed to parse.
        path: String,
        /// What the parser said.
        reason: String,
    },
    /// The store's lock was poisoned by a panic in another holder.
    #[error("hold store lock poisoned")]
    Poisoned,
}

/// What a list response says about the backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldActionStoreHealth {
    /// FALSE for the in-memory backend: a restart forgets every open hold.
    pub durable: bool,
    /// `memory` or `local_files`.
    pub backend: String,
    /// Holds in `created`, `notified` or `armed`.
    pub open_holds: usize,
    /// Holds in `deciding` older than `stall_ms`.
    pub deciding_stalled: usize,
}

/// Durable home for holds. `begin_decision` is a compare-and-set, not a write.
pub trait HeldActionStore: Send + Sync {
    /// Insert a `created` hold. `Duplicate` on an existing id.
    fn create(&self, hold: HeldAction) -> Result<(), HeldActionStoreError>;
    /// One hold, any state.
    fn get(&self, hold_id: &str) -> Result<Option<HeldAction>, HeldActionStoreError>;
    /// Sorted `(expires_at_ms, hold_id)`. `include_terminal` adds decided and
    /// expired holds.
    fn list(
        &self,
        include_terminal: bool,
        limit: usize,
    ) -> Result<Vec<HeldAction>, HeldActionStoreError>;
    /// The bridge reports the case channel it created or reused. Any open
    /// state; informational.
    fn mark_case_channel(
        &self,
        hold_id: &str,
        case_channel: &str,
    ) -> Result<(), HeldActionStoreError>;
    /// The bridge reports that the relay accepted the `46010` notice.
    /// `created -> notified`; a no-op on any other state. Gates nothing.
    fn mark_notified(
        &self,
        hold_id: &str,
        at_ms: i64,
        notice_event_id: &str,
        card_event_id: Option<&str>,
    ) -> Result<(), HeldActionStoreError>;
    /// Client-reported arming. `notified -> armed`; a no-op otherwise.
    fn mark_armed(&self, hold_id: &str, at_ms: i64) -> Result<(), HeldActionStoreError>;
    /// `created|notified|armed -> deciding`, atomically, re-checking expiry
    /// inside the lock. Returns the claimed record; `NotDecidable` carries the
    /// current record for every other state.
    fn begin_decision(
        &self,
        hold_id: &str,
        intent_event_id: &str,
        cas_instant_ms: i64,
    ) -> Result<HeldAction, HeldActionStoreError>;
    /// `deciding -> prior_state`. The only non-terminal exit. Idempotent: a
    /// hold that is not `deciding`, or that is deciding under another id, is
    /// left alone and this is NOT an error.
    fn abandon_decision(
        &self,
        hold_id: &str,
        intent_event_id: &str,
    ) -> Result<(), HeldActionStoreError>;
    /// `deciding -> terminal`, with the outcome. Keeps `deciding_intent_event_id`
    /// so a 409'd console can learn the winner; clears `prior_state`.
    fn complete_decision(
        &self,
        hold_id: &str,
        decision: HoldDecisionRecord,
        state: HoldState,
    ) -> Result<(), HeldActionStoreError>;
    /// `created|notified|armed -> expired` for everything past `now_ms`.
    fn expire_due(&self, now_ms: i64) -> Result<Vec<HeldAction>, HeldActionStoreError>;
    /// `deciding -> failed` for every claim older than `stall_ms`, with the
    /// honest unknown-outcome refusal.
    fn fail_stalled_decisions(
        &self,
        now_ms: i64,
        stall_ms: u64,
    ) -> Result<Vec<HeldAction>, HeldActionStoreError>;
    /// Backend facts for the list response.
    fn health(
        &self,
        now_ms: i64,
        stall_ms: u64,
    ) -> Result<HeldActionStoreHealth, HeldActionStoreError>;
}

/// The refusal a stalled decision is resolved with. One string, rendered
/// verbatim, because neither the daemon nor the operator can know more.
pub const STALLED_DECISION_REASON: &str = "the decision stalled; whether the action ran is unknown";

fn stalled_refusal() -> HoldRefusal {
    HoldRefusal {
        rule: "runtime.capability_lease_expired".to_string(),
        reason: STALLED_DECISION_REASON.to_string(),
    }
}

/// Pure transition logic shared by both backends, applied under the backend's
/// own lock. Every method mutates in place and reports what it did.
mod transitions {
    use super::{
        GovernanceClearance, HeldAction, HoldDecision, HoldDecisionRecord, HoldOutcome, HoldState,
        stalled_refusal,
    };

    /// `created|notified|armed -> deciding`, or `Err(())` when the hold is not
    /// decidable at `cas_instant_ms`.
    pub fn begin(
        hold: &mut HeldAction,
        intent_event_id: &str,
        cas_instant_ms: i64,
    ) -> Result<(), ()> {
        if hold.assert_decidable(cas_instant_ms).is_err() {
            return Err(());
        }
        hold.prior_state = Some(hold.state);
        hold.state = HoldState::Deciding;
        hold.deciding_intent_event_id = Some(intent_event_id.to_string());
        hold.cas_instant_ms = Some(cas_instant_ms);
        Ok(())
    }

    /// `deciding -> prior_state` for the claim holder only. Reports whether it
    /// changed anything, so the file backend knows whether to persist.
    pub fn abandon(hold: &mut HeldAction, intent_event_id: &str) -> bool {
        if hold.state != HoldState::Deciding
            || hold.deciding_intent_event_id.as_deref() != Some(intent_event_id)
        {
            return false;
        }
        hold.state = hold.prior_state.take().unwrap_or(HoldState::Created);
        hold.deciding_intent_event_id = None;
        hold.cas_instant_ms = None;
        true
    }

    /// Write the terminal record.
    pub fn complete(hold: &mut HeldAction, decision: HoldDecisionRecord, state: HoldState) {
        hold.state = state;
        hold.decision = Some(decision);
        hold.prior_state = None;
    }

    /// `created|notified|armed -> expired` past the TTL. No action, no decision.
    pub fn expire(hold: &mut HeldAction, now_ms: i64) -> bool {
        if hold.state.is_open() && now_ms >= hold.expires_at_ms {
            hold.state = HoldState::Expired;
            return true;
        }
        false
    }

    /// `deciding -> failed` past the stall bound, with the honest
    /// unknown-outcome refusal and `dispatched: false`.
    pub fn fail_stalled(hold: &mut HeldAction, now_ms: i64, stall_ms: u64) -> bool {
        if !is_stalled(hold, now_ms, stall_ms) {
            return false;
        }
        let intent = hold.deciding_intent_event_id.clone().unwrap_or_default();
        hold.decision = Some(HoldDecisionRecord {
            decision: HoldDecision::Grant,
            operator_id: String::new(),
            voter_id: String::new(),
            rationale_sha256: None,
            hold_notice_published: hold.notified_at_ms.is_some(),
            governance_clearance: GovernanceClearance::NotRequired,
            decided_at_ms: hold.cas_instant_ms.unwrap_or(now_ms),
            nostr_intent_event_id: intent,
            signature: None,
            rationale: None,
            outcome: HoldOutcome::GrantedFailed,
            dispatched: false,
            receipt_id: None,
            audit_trail_id: None,
            refusal: Some(stalled_refusal()),
        });
        hold.state = HoldState::Failed;
        hold.prior_state = None;
        true
    }

    /// Whether a `deciding` claim is older than `stall_ms`.
    pub fn is_stalled(hold: &HeldAction, now_ms: i64, stall_ms: u64) -> bool {
        hold.state == HoldState::Deciding
            && hold
                .cas_instant_ms
                .is_some_and(|cas| now_ms.saturating_sub(cas) >= stall_ms as i64)
    }

    /// `(expires_at_ms, hold_id)` — the list order.
    pub fn sort_key(hold: &HeldAction) -> (i64, String) {
        (hold.expires_at_ms, hold.hold_id.clone())
    }
}

/// In-memory backend. `durable: false`.
#[derive(Debug, Default)]
pub struct MemoryHeldActionStore {
    holds: RwLock<BTreeMap<String, HeldAction>>,
}

impl MemoryHeldActionStore {
    fn read(
        &self,
    ) -> Result<std::sync::RwLockReadGuard<'_, BTreeMap<String, HeldAction>>, HeldActionStoreError>
    {
        self.holds
            .read()
            .map_err(|_| HeldActionStoreError::Poisoned)
    }

    fn write(
        &self,
    ) -> Result<std::sync::RwLockWriteGuard<'_, BTreeMap<String, HeldAction>>, HeldActionStoreError>
    {
        self.holds
            .write()
            .map_err(|_| HeldActionStoreError::Poisoned)
    }

    fn with_hold<T>(
        &self,
        hold_id: &str,
        apply: impl FnOnce(&mut HeldAction) -> T,
    ) -> Result<T, HeldActionStoreError> {
        let mut holds = self.write()?;
        let hold = holds
            .get_mut(hold_id)
            .ok_or_else(|| HeldActionStoreError::NotFound {
                hold_id: hold_id.to_string(),
            })?;
        Ok(apply(hold))
    }
}

impl HeldActionStore for MemoryHeldActionStore {
    fn create(&self, hold: HeldAction) -> Result<(), HeldActionStoreError> {
        let mut holds = self.write()?;
        if holds.contains_key(&hold.hold_id) {
            return Err(HeldActionStoreError::Duplicate {
                hold_id: hold.hold_id,
            });
        }
        holds.insert(hold.hold_id.clone(), hold);
        Ok(())
    }

    fn get(&self, hold_id: &str) -> Result<Option<HeldAction>, HeldActionStoreError> {
        Ok(self.read()?.get(hold_id).cloned())
    }

    fn list(
        &self,
        include_terminal: bool,
        limit: usize,
    ) -> Result<Vec<HeldAction>, HeldActionStoreError> {
        let mut holds: Vec<HeldAction> = self
            .read()?
            .values()
            .filter(|hold| include_terminal || !hold.is_terminal())
            .cloned()
            .collect();
        holds.sort_by_key(transitions::sort_key);
        holds.truncate(limit);
        Ok(holds)
    }

    fn mark_case_channel(
        &self,
        hold_id: &str,
        case_channel: &str,
    ) -> Result<(), HeldActionStoreError> {
        self.with_hold(hold_id, |hold| {
            hold.case_channel = Some(case_channel.to_string());
        })
    }

    fn mark_notified(
        &self,
        hold_id: &str,
        at_ms: i64,
        notice_event_id: &str,
        card_event_id: Option<&str>,
    ) -> Result<(), HeldActionStoreError> {
        self.with_hold(hold_id, |hold| {
            hold.notified_at_ms = Some(at_ms);
            hold.notice_event_id = Some(notice_event_id.to_string());
            hold.card_event_id = card_event_id.map(str::to_string);
            if hold.state == HoldState::Created {
                hold.state = HoldState::Notified;
            }
        })
    }

    fn mark_armed(&self, hold_id: &str, _at_ms: i64) -> Result<(), HeldActionStoreError> {
        self.with_hold(hold_id, |hold| {
            if hold.state == HoldState::Notified {
                hold.state = HoldState::Armed;
            }
        })
    }

    fn begin_decision(
        &self,
        hold_id: &str,
        intent_event_id: &str,
        cas_instant_ms: i64,
    ) -> Result<HeldAction, HeldActionStoreError> {
        let mut holds = self.write()?;
        let hold = holds
            .get_mut(hold_id)
            .ok_or_else(|| HeldActionStoreError::NotFound {
                hold_id: hold_id.to_string(),
            })?;
        match transitions::begin(hold, intent_event_id, cas_instant_ms) {
            Ok(()) => Ok(hold.clone()),
            Err(()) => Err(HeldActionStoreError::NotDecidable {
                hold_id: hold_id.to_string(),
                current: Box::new(hold.clone()),
            }),
        }
    }

    fn abandon_decision(
        &self,
        hold_id: &str,
        intent_event_id: &str,
    ) -> Result<(), HeldActionStoreError> {
        let mut holds = self.write()?;
        let Some(hold) = holds.get_mut(hold_id) else {
            return Ok(());
        };
        transitions::abandon(hold, intent_event_id);
        Ok(())
    }

    fn complete_decision(
        &self,
        hold_id: &str,
        decision: HoldDecisionRecord,
        state: HoldState,
    ) -> Result<(), HeldActionStoreError> {
        self.with_hold(hold_id, |hold| {
            transitions::complete(hold, decision, state);
        })
    }

    fn expire_due(&self, now_ms: i64) -> Result<Vec<HeldAction>, HeldActionStoreError> {
        let mut holds = self.write()?;
        let mut expired = Vec::new();
        for hold in holds.values_mut() {
            if transitions::expire(hold, now_ms) {
                expired.push(hold.clone());
            }
        }
        Ok(expired)
    }

    fn fail_stalled_decisions(
        &self,
        now_ms: i64,
        stall_ms: u64,
    ) -> Result<Vec<HeldAction>, HeldActionStoreError> {
        let mut holds = self.write()?;
        let mut failed = Vec::new();
        for hold in holds.values_mut() {
            if transitions::fail_stalled(hold, now_ms, stall_ms) {
                failed.push(hold.clone());
            }
        }
        Ok(failed)
    }

    fn health(
        &self,
        now_ms: i64,
        stall_ms: u64,
    ) -> Result<HeldActionStoreHealth, HeldActionStoreError> {
        let holds = self.read()?;
        Ok(HeldActionStoreHealth {
            durable: false,
            backend: "memory".to_string(),
            open_holds: holds.values().filter(|hold| hold.is_open()).count(),
            deciding_stalled: holds
                .values()
                .filter(|hold| transitions::is_stalled(hold, now_ms, stall_ms))
                .count(),
        })
    }
}

/// The claim a decide call holds between the compare-and-set and the outcome
/// write. `Drop` abandons unless `complete` disarmed it, so every early return
/// — including ones nobody has written yet, and a panic — leaves the hold
/// decidable.
pub struct DecisionClaim<'a> {
    store: &'a dyn HeldActionStore,
    hold_id: String,
    intent_event_id: String,
    claimed: HeldAction,
    armed: bool,
}

impl<'a> DecisionClaim<'a> {
    /// The compare-and-set. `Err(NotDecidable)` carries the current record.
    pub fn begin(
        store: &'a dyn HeldActionStore,
        hold_id: &str,
        intent_event_id: &str,
        cas_instant_ms: i64,
    ) -> Result<Self, HeldActionStoreError> {
        let claimed = store.begin_decision(hold_id, intent_event_id, cas_instant_ms)?;
        Ok(Self {
            store,
            hold_id: hold_id.to_string(),
            intent_event_id: intent_event_id.to_string(),
            claimed,
            armed: true,
        })
    }

    /// The record as it was at the compare-and-set.
    pub fn claimed(&self) -> &HeldAction {
        &self.claimed
    }

    /// The ONLY terminal exit from `deciding`. Disarms the guard first, so a
    /// store fault on the terminal write is reported and not followed by an
    /// abandon that would erase the fault.
    pub fn complete(
        mut self,
        decision: HoldDecisionRecord,
        state: HoldState,
    ) -> Result<(), HeldActionStoreError> {
        self.armed = false;
        self.store.complete_decision(&self.hold_id, decision, state)
    }
}

impl Drop for DecisionClaim<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Err(error) = self
            .store
            .abandon_decision(&self.hold_id, &self.intent_event_id)
        {
            tracing::error!(
                module = module_path!(),
                hold_id = %self.hold_id,
                reason = %error,
                "abandon_decision failed; the hold may be parked in deciding until the sweep resolves it"
            );
        }
    }
}

#[cfg(test)]
#[path = "held_action_tests.rs"]
pub(crate) mod tests;
