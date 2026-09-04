//! B1's interception point, and (Tasks 10 and 13) the hold reads and the decide engine.
//!
//! Owns: turning a `RequireHuman` audit trail into a durable `HeldAction`, and
//! publishing `RuntimeEvent::ResponseHeld`.
//!
//! Does not own: the store (`swarm_runtime::held_action`), the routes
//! (`swarm_runtime_http::http::perch::holds`), or any authorization decision.

use std::sync::Arc;

use swarm_core::config::{ResponseHoldSettings, RuntimeMode};
use swarm_core::types::{OperatorApproval, ResponseRehearsalPreview};
use swarm_crypto::{DetachedSignature, canonical_json_bytes, verify_detached_signature};
use swarm_perch_wire::verdict::rationale_sha256_hex;
use swarm_policy::{
    ActionRequest, ApprovalContext, ApprovalGate, CapabilityLease, PolicyDecision, PolicyVerdict,
};
use swarm_response::ResponseReceipt;
use swarm_runtime::governance_gate::{GovernanceReceiptBounds, reauthorize};
use swarm_runtime::held_action::{
    DecisionClaim, GovernanceClearance, HeldAction, HeldActionStore, HeldActionStoreError,
    HeldActionStoreHealth, HoldDecision, HoldDecisionRecord, HoldOutcome, HoldRefusal, HoldState,
    NotDecidable, mint_hold_id,
};
use swarm_runtime::runtime_events::{RuntimeEvent, RuntimeEventBroadcaster};
use swarm_spine::{AuditResponseRecord, AuditTrail};
use swarm_whisker::DetectionFinding;

use crate::ingest::threat_class_slug;

/// Everything `route_request` needs to make a hold durable after the runtime
/// has returned its `Skipped` trail.
#[derive(Clone)]
pub struct HoldCapture {
    store: Arc<dyn HeldActionStore>,
    events: Option<RuntimeEventBroadcaster>,
    settings: ResponseHoldSettings,
}

impl HoldCapture {
    /// Bundle the daemon's one store, its broadcaster and the hold settings.
    pub fn new(
        store: Arc<dyn HeldActionStore>,
        events: Option<RuntimeEventBroadcaster>,
        settings: ResponseHoldSettings,
    ) -> Self {
        Self {
            store,
            events,
            settings,
        }
    }

    /// The store handle, for the reads and the decide engine.
    pub fn store(&self) -> &Arc<dyn HeldActionStore> {
        &self.store
    }

    /// The configured settings.
    pub fn settings(&self) -> &ResponseHoldSettings {
        &self.settings
    }

    /// Capture iff BOTH clauses hold: `verdict == RequireHuman` AND
    /// `response == Skipped`. `Skipped` alone has four producers (Deny,
    /// RequireHuman-in-live, containment-refused, the guard path) and matching
    /// it alone would turn denied actions into holds an operator could grant.
    pub fn capture_hold(
        &self,
        request: &ActionRequest,
        detection: &DetectionFinding,
        audit: &AuditTrail,
        rehearsal: Option<ResponseRehearsalPreview>,
        now_ms: i64,
    ) -> Option<HeldAction> {
        if !matches!(audit.policy.verdict, PolicyVerdict::RequireHuman)
            || !matches!(audit.response, AuditResponseRecord::Skipped { .. })
        {
            return None;
        }
        let decision = PolicyDecision {
            verdict: audit.policy.verdict,
            rule_name: audit.policy.rule_name.clone(),
            reason: audit.policy.reason.clone(),
        };
        let slug = request
            .evidence
            .get("escalation")
            .and_then(|value| value.get("threat_class"))
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
            .map(|class| threat_class_slug(&class))
            .unwrap_or_else(|| "execution".to_string());
        let ttl_ms = i64::try_from(self.settings.hold_ttl_ms_for(&slug)).unwrap_or(i64::MAX);
        let hold = HeldAction::new(
            mint_hold_id(),
            request.clone(),
            detection.clone(),
            decision,
            rehearsal,
            now_ms,
            now_ms.saturating_add(ttl_ms),
            Some(audit.trail_id.clone()),
        );
        if let Err(error) = self.store.create(hold.clone()) {
            tracing::error!(
                module = module_path!(),
                hold_id = %hold.hold_id,
                reason = %error,
                "hold could not be stored; the action was NOT taken and is NOT queued"
            );
            return None;
        }
        self.publish_state(&hold, HoldState::Created, now_ms);
        Some(hold)
    }

    /// One `ResponseHeld` per state change. Called by capture and by the sweep.
    pub fn publish_state(&self, hold: &HeldAction, state: HoldState, now_ms: i64) {
        if let Some(events) = &self.events {
            events.publish(RuntimeEvent::ResponseHeld {
                emitted_at_ms: now_ms,
                hold_id: hold.hold_id.clone(),
                hunt_id: hold.action_request.hunt_id.0.clone(),
                action_kind: hold.action_request.action.kind().to_string(),
                severity: hold.action_request.severity,
                expires_at_ms: hold.expires_at_ms,
                state,
            });
        }
    }
}

/// Why a hold read failed.
#[derive(Debug, thiserror::Error)]
pub enum HoldReadError {
    /// The daemon has no hold store: the feature is not configured. NEVER an
    /// empty list — a console that read "no holds" would silently drop every
    /// queued destructive action.
    #[error("no hold store is attached to this daemon")]
    NoHoldStore,
    /// The store itself failed.
    #[error(transparent)]
    Store(#[from] HeldActionStoreError),
}

/// A page of holds plus the facts the list response must carry.
pub struct HoldListing {
    /// The page, sorted `(expires_at_ms, hold_id)` ascending.
    pub holds: Vec<HeldAction>,
    /// Open holds across the WHOLE store, not just this page.
    pub open_count: usize,
    /// Whether `limit` cut the page short.
    pub truncated: bool,
    /// What the backend says about itself.
    pub health: HeldActionStoreHealth,
}

/// `GET /v1/response/holds`'s engine half. Sorted `(expires_at_ms, hold_id)`.
pub fn list_holds(
    state: &crate::ingest::IngestState,
    include_terminal: bool,
    limit: usize,
    now_ms: i64,
) -> Result<HoldListing, HoldReadError> {
    let capture = state
        .current_hold_capture()
        .ok_or(HoldReadError::NoHoldStore)?;
    let store = capture.store();
    // Read the whole set first: `open_count` and `truncated` are facts about
    // the store, not about the page, and a store-side limit would make both
    // of them lies whenever the page was short.
    let all = store.list(include_terminal, usize::MAX)?;
    let open_count = all.iter().filter(|hold| hold.is_open()).count();
    let truncated = all.len() > limit;
    let mut holds = all;
    holds.truncate(limit);
    let health = store.health(now_ms, capture.settings().decide_stall_ms)?;
    Ok(HoldListing {
        holds,
        open_count,
        truncated,
        health,
    })
}

/// `GET /v1/response/holds/{hold_id}`'s engine half.
pub fn get_hold(
    state: &crate::ingest::IngestState,
    hold_id: &str,
) -> Result<Option<HeldAction>, HoldReadError> {
    let capture = state
        .current_hold_capture()
        .ok_or(HoldReadError::NoHoldStore)?;
    Ok(capture.store().get(hold_id)?)
}

// ── B2: the decide engine ──────────────────────────────────────────────────

/// The decide body after the route's own validation.
#[derive(Debug, Clone)]
pub struct HoldDecisionInput {
    /// Grant or refuse.
    pub decision: HoldDecision,
    /// The instant the console claims it decided. A SIGNED INPUT, never the
    /// authority: the record's `decided_at_ms` is the daemon's own
    /// compare-and-set instant.
    pub decided_at_ms: i64,
    /// The leg-1 card id. The idempotency key and an unsigned pointer.
    pub nostr_intent_event_id: String,
    /// The operator's detached signature over the four-member preimage.
    pub signature: DetachedSignature,
    /// The operator's free-text rationale, if any.
    pub rationale: Option<String>,
    /// When the console reported the row armed. Informational.
    pub armed_at_ms: Option<i64>,
}

/// Every way a decision can be refused before it becomes a record.
#[derive(Debug, thiserror::Error)]
pub enum HoldDecisionError {
    /// 503. The feature is not configured.
    #[error("no hold store is attached to this daemon")]
    NoHoldStore,
    /// 404.
    #[error("no such hold")]
    NotFound,
    /// 422. Nothing was written.
    #[error("signature did not verify: {0}")]
    InvalidSignature(String),
    /// 403. Nothing was written.
    #[error("voter `{voter_id}` does not bind to operator `{operator_id}`")]
    VoterMismatch {
        /// The authenticated principal.
        operator_id: String,
        /// The voter the signature's own key derives.
        voter_id: String,
    },
    /// 409. The hold stopped being decidable; the action was never taken.
    #[error("hold expired")]
    Expired,
    /// 409, same intent id, still deciding.
    #[error("this decision is still in flight")]
    DecisionInFlight,
    /// 409, another intent id holds the claim.
    #[error("another decision holds the claim")]
    AlreadyDeciding,
    /// 409, terminal under another intent id.
    #[error("the hold was already decided by another intent")]
    AlreadyDecided,
    /// 500.
    #[error(transparent)]
    Store(#[from] HeldActionStoreError),
    /// A transport or store fault after the compare-and-set. The guard
    /// abandoned the claim, so the hold is decidable again.
    #[error("runtime error: {0}")]
    Runtime(String),
}

/// What the route returns on 200.
#[derive(Debug)]
pub struct HoldDecisionOutcome {
    /// The hold as stored after the decision.
    pub hold: HeldAction,
    /// True when this call replayed an existing record rather than deciding.
    pub replayed: bool,
    /// The response receipt, when the action executed.
    pub receipt: Option<ResponseReceipt>,
    /// The capability lease, minted from the compare-and-set instant.
    pub capability_lease: Option<CapabilityLease>,
    /// The containment lease the receipt reported, when there was one.
    pub containment_lease_id: Option<String>,
}

/// Signature payload, serialized through `canonical_json_bytes` so key order is
/// the canonical one. `swarm_perch_wire::verdict::decision_preimage_bytes`
/// produces identical bytes, and a test in this module asserts it: the console
/// signs with one implementation and the daemon verifies with the other, so a
/// divergence would refuse every honest decision.
#[derive(serde::Serialize)]
struct DecisionSignaturePayload<'a> {
    decided_at_ms: i64,
    decision: &'a str,
    hold_id: &'a str,
    rationale_sha256: Option<&'a str>,
}

fn voter_id_from_public_key(public_key_hex: &str) -> String {
    format!("swarm:ed25519:{public_key_hex}")
}

/// The daemon re-derives authority from scratch (ADR 0014). Nothing the console
/// sent is trusted as a decision: the body carries a claim and a signature, and
/// every fact that authorizes the action is re-read here.
///
/// Order, and why it is this order:
///
/// 1. READ, and replay an identical intent. No write.
/// 2. SIGNATURE, then voter binding. Still no write, so a forged or
///    misattributed decision leaves the hold exactly as it was.
/// 3. COMPARE-AND-SET, held by a `Drop` guard. This is the point of no return
///    and the only place a second decision can be excluded.
/// 4. REFUSE short-circuits. Nothing about governance, policy or telemetry is
///    consulted: refusal is the exit that must survive every degraded state.
/// 5. GOVERNANCE, re-evaluated at the DECISION instant, not at hold time.
/// 6. POLICY + EXECUTION, with the capability lease minted from the
///    compare-and-set instant.
/// 7. COMMIT the outcome to the store, THEN publish. A record nobody stored is
///    a record nobody can reconcile.
pub async fn decide_hold(
    state: &crate::ingest::IngestState,
    hold_id: &str,
    operator_id: &str,
    input: HoldDecisionInput,
    now_ms: i64,
) -> Result<HoldDecisionOutcome, HoldDecisionError> {
    let capture = state
        .current_hold_capture()
        .ok_or(HoldDecisionError::NoHoldStore)?;
    let store = capture.store();

    // 1. READ. Nothing is mutated in steps 1-2.
    let hold = store.get(hold_id)?.ok_or(HoldDecisionError::NotFound)?;
    if let Some(record) = &hold.decision
        && record.nostr_intent_event_id == input.nostr_intent_event_id
    {
        return Ok(HoldDecisionOutcome {
            hold,
            replayed: true,
            receipt: None,
            capability_lease: None,
            containment_lease_id: None,
        });
    }
    match hold.assert_decidable(now_ms) {
        Ok(()) => {}
        Err(NotDecidable::Expired) => return Err(HoldDecisionError::Expired),
        Err(NotDecidable::Deciding) => {
            return Err(
                if hold.deciding_intent_event_id.as_deref()
                    == Some(input.nostr_intent_event_id.as_str())
                {
                    HoldDecisionError::DecisionInFlight
                } else {
                    HoldDecisionError::AlreadyDeciding
                },
            );
        }
        Err(NotDecidable::Terminal) => return Err(HoldDecisionError::AlreadyDecided),
    }

    // 2. SIGNATURE, BEFORE ANY WRITE. The preimage is rebuilt from the
    //    daemon's OWN `hold_id`, so a signature over a different hold cannot be
    //    replayed onto this one.
    let rationale_sha256 = rationale_sha256_hex(input.rationale.as_deref());
    let payload = canonical_json_bytes(&DecisionSignaturePayload {
        decided_at_ms: input.decided_at_ms,
        decision: input.decision.as_str(),
        hold_id,
        rationale_sha256: rationale_sha256.as_deref(),
    })
    .map_err(|error| HoldDecisionError::Runtime(error.to_string()))?;
    verify_detached_signature(&payload, &input.signature)
        .map_err(|error| HoldDecisionError::InvalidSignature(error.to_string()))?;
    let voter_id = voter_id_from_public_key(&input.signature.public_key_hex);
    if !state.operator_binds_voter_id(operator_id, &voter_id) {
        return Err(HoldDecisionError::VoterMismatch {
            operator_id: operator_id.to_string(),
            voter_id,
        });
    }

    // 3. COMPARE-AND-SET, by a guard. Expiry and state are re-checked inside
    //    the lock, so the decidability read in step 1 is a courtesy and this is
    //    the check that counts.
    let claim = match DecisionClaim::begin(
        store.as_ref(),
        hold_id,
        &input.nostr_intent_event_id,
        now_ms,
    ) {
        Ok(claim) => claim,
        Err(HeldActionStoreError::NotDecidable { current, .. }) => {
            return Err(classify_conflict(&current, &input.nostr_intent_event_id));
        }
        Err(error) => return Err(error.into()),
    };
    let claimed = claim.claimed().clone();
    let hold_notice_published = claimed.prior_state != Some(HoldState::Created);
    let base_record = |outcome: HoldOutcome, clearance: GovernanceClearance| HoldDecisionRecord {
        decision: input.decision,
        operator_id: operator_id.to_string(),
        voter_id: voter_id.clone(),
        rationale_sha256: rationale_sha256.clone(),
        hold_notice_published,
        governance_clearance: clearance,
        // The daemon's instant, not the body's. The body's `decided_at_ms` is
        // signed input; this is when authority was actually taken.
        decided_at_ms: now_ms,
        nostr_intent_event_id: input.nostr_intent_event_id.clone(),
        signature: Some(input.signature.clone()),
        rationale: input.rationale.clone(),
        outcome,
        dispatched: false,
        receipt_id: None,
        audit_trail_id: None,
        refusal: None,
    };

    // 4. REFUSE short-circuits.
    if input.decision == HoldDecision::Refuse {
        let record = base_record(
            HoldOutcome::RefusedByOperator,
            GovernanceClearance::NotRequired,
        );
        claim.complete(record, HoldState::Refused)?;
        capture.publish_state(&claimed, HoldState::Refused, now_ms);
        let hold = store.get(hold_id)?.ok_or(HoldDecisionError::NotFound)?;
        return Ok(HoldDecisionOutcome {
            hold,
            replayed: false,
            receipt: None,
            capability_lease: None,
            containment_lease_id: None,
        });
    }

    // 5. GOVERNANCE (B2g), at the decision instant. A typed refusal is
    //    terminal; a store fault is not (the guard abandons on `?`).
    let bounds = GovernanceReceiptBounds {
        subject_captured_at_ms: claimed.held_at_ms,
        max_age_ms: capture.settings().governance_receipt_max_age_ms,
    };
    let authority = state.current_governance_authority();
    let clearance = match reauthorize(authority.as_ref(), &claimed.action_request, now_ms, bounds) {
        Ok(clearance) => clearance,
        Err(refusal) => {
            let mut record =
                base_record(HoldOutcome::RefusedLate, GovernanceClearance::NotRequired);
            record.refusal = Some(HoldRefusal {
                rule: refusal.rule.to_string(),
                reason: refusal.reason,
            });
            claim.complete(record, HoldState::Refused)?;
            capture.publish_state(&claimed, HoldState::Refused, now_ms);
            let hold = store.get(hold_id)?.ok_or(HoldDecisionError::NotFound)?;
            return Ok(HoldDecisionOutcome {
                hold,
                replayed: false,
                receipt: None,
                capability_lease: None,
                containment_lease_id: None,
            });
        }
    };

    // 6. POLICY + EXECUTION. `now_ms` here is the compare-and-set instant, so
    //    the capability lease is minted from the decision and never from hold
    //    time -- a lease dated an hour ago would already be dead.
    let context = ApprovalContext {
        live_mode: state.current_runtime_mode() == RuntimeMode::LiveResponse,
        receipt_chain: vec![claimed.hold_id.clone()],
        correlation_id: Some(claimed.hold_id.clone()),
        now_ms,
    };
    let approval = OperatorApproval {
        operator_id: operator_id.to_string(),
        voter_id: voter_id.clone(),
        hold_id: claimed.hold_id.clone(),
        decided_at_ms: now_ms,
        signature: input.signature.clone(),
        rationale: input.rationale.clone(),
        rationale_sha256: rationale_sha256.clone(),
        nostr_intent_event_id: Some(input.nostr_intent_event_id.clone()),
    };
    let runtime = state.request_runtime.load_full();
    let execution = runtime
        .audit_authorize_and_execute_human_approved_instrumented(
            &claimed.detection,
            &claimed.action_request,
            &context,
            Some(approval),
        )
        .await
        .map_err(|error| HoldDecisionError::Runtime(error.to_string()))?;

    // 7. COMMIT, then publish. Store first: a record nobody stored is a record
    //    nobody can reconcile, and the console reconciles against the store.
    let audit = execution.audit.clone();
    let (receipt_id, response_error) = crate::ingest::response_receipt_details(&audit);
    let (outcome, state_after, refusal, receipt) = classify_execution(&audit);
    let mut record = base_record(outcome, clearance);
    record.dispatched = execution.response_attempted;
    record.receipt_id = receipt_id.clone();
    record.audit_trail_id = Some(audit.trail_id.clone());
    record.refusal = refusal;
    claim.complete(record, state_after)?;
    capture.publish_state(&claimed, state_after, now_ms);
    state.publish_runtime_event(RuntimeEvent::ResponseExecution {
        emitted_at_ms: now_ms,
        agent_id: claimed.action_request.requested_by.to_string(),
        hunt_id: audit.hunt_id.clone(),
        action_kind: claimed.action_request.action.kind().to_string(),
        response_kind: audit.response_kind().to_string(),
        policy_verdict: audit.policy.verdict,
        rule_name: audit.policy.rule_name.clone(),
        reason: audit.policy.reason.clone(),
        receipt_id,
        governing_agent_id: None,
        error: response_error,
    });
    let capability_lease = runtime
        .policy()
        .issue_lease(&claimed.action_request, &context)
        .ok();
    let containment_lease_id = receipt.as_ref().and_then(|receipt| {
        receipt
            .details
            .get("containment_lease_id")
            .and_then(|value| value.as_str())
            .map(str::to_string)
    });
    let hold = store.get(hold_id)?.ok_or(HoldDecisionError::NotFound)?;
    Ok(HoldDecisionOutcome {
        hold,
        replayed: false,
        receipt,
        capability_lease,
        containment_lease_id,
    })
}

/// Which 409 a lost compare-and-set is.
fn classify_conflict(current: &HeldAction, intent: &str) -> HoldDecisionError {
    match current.state {
        HoldState::Deciding if current.deciding_intent_event_id.as_deref() == Some(intent) => {
            HoldDecisionError::DecisionInFlight
        }
        HoldState::Deciding => HoldDecisionError::AlreadyDeciding,
        HoldState::Expired => HoldDecisionError::Expired,
        _ => HoldDecisionError::AlreadyDecided,
    }
}

/// Map the runtime's trail onto a hold outcome. Every late refusal is a typed
/// rule, never an error: the operator granted in good faith and is owed the
/// reason the grant did not become an action.
fn classify_execution(
    audit: &AuditTrail,
) -> (
    HoldOutcome,
    HoldState,
    Option<HoldRefusal>,
    Option<ResponseReceipt>,
) {
    match &audit.response {
        AuditResponseRecord::Success(receipt) => {
            let outcome = if receipt.mode == swarm_response::ExecutionMode::DryRun {
                HoldOutcome::GrantedSimulated
            } else {
                HoldOutcome::GrantedExecuted
            };
            (outcome, HoldState::Executed, None, Some(receipt.clone()))
        }
        AuditResponseRecord::Failure(failure) => {
            let lease_expired = failure
                .details
                .get("status")
                .and_then(|value| value.as_str())
                == Some("lease_expired");
            if lease_expired {
                (
                    HoldOutcome::RefusedLate,
                    HoldState::Refused,
                    Some(HoldRefusal {
                        rule: "runtime.capability_lease_expired".into(),
                        reason: failure.message.clone(),
                    }),
                    None,
                )
            } else {
                (HoldOutcome::GrantedFailed, HoldState::Failed, None, None)
            }
        }
        AuditResponseRecord::Skipped { reason } => {
            // The rule strings are the ones `swarm-policy` actually emits;
            // anything else is `policy.denied` rather than a guess.
            let rule = if reason.contains("containment") {
                "runtime.containment_refused"
            } else {
                match audit.policy.rule_name.as_str() {
                    "static.minimum_severity" => "policy.minimum_severity",
                    "static.deploy_decoy_min_severity" => "policy.minimum_severity",
                    "static.scope_rate_limit" => "policy.scope_rate_limit",
                    "configurable.fail_closed.empty_ruleset" => "policy.empty_ruleset",
                    "static.human_gate" => "policy.human_gate",
                    _ => "policy.denied",
                }
            };
            (
                HoldOutcome::RefusedLate,
                HoldState::Refused,
                Some(HoldRefusal {
                    rule: rule.into(),
                    reason: reason.clone(),
                }),
                None,
            )
        }
        AuditResponseRecord::GuardRejected { guard_name, reason } => (
            HoldOutcome::GuardRejected,
            HoldState::Refused,
            Some(HoldRefusal {
                rule: "runtime.guard_rejected".into(),
                reason: format!("{guard_name}: {reason}"),
            }),
            None,
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
    use swarm_policy::{ActionRequest, PolicyVerdict};
    use swarm_runtime::held_action::{HoldState, MemoryHeldActionStore};
    use swarm_runtime::runtime_events::RuntimeEventBroadcaster;
    use swarm_spine::{AuditResponseRecord, AuditTrail, PolicyRecord};

    const T0: i64 = 1_773_739_200_000;

    fn request() -> ActionRequest {
        ActionRequest {
            hunt_id: HuntId("hunt-evt-1".into()),
            requested_by: AgentId::from_public_key_hex(&"18".repeat(32)),
            action: ResponseAction::IsolateHost {
                host_id: "host-ops-1".into(),
            },
            severity: Severity::Critical,
            evidence: serde_json::json!({ "escalation": { "threat_class": "execution" } }),
        }
    }

    fn trail(verdict: PolicyVerdict, response: AuditResponseRecord) -> AuditTrail {
        let request = request();
        AuditTrail {
            trail_id: "trail-1".into(),
            hunt_id: request.hunt_id.0.clone(),
            related_receipt_ids: vec![],
            detection: crate::ingest::routed_detection_from_request(&request),
            policy: PolicyRecord {
                verdict,
                rule_name: "static.human_gate".into(),
                reason: "authorized but held for human approval".into(),
                lease: None,
            },
            response,
            created_at_ms: T0,
        }
    }

    fn capture() -> (
        HoldCapture,
        Arc<MemoryHeldActionStore>,
        tokio::sync::broadcast::Receiver<RuntimeEvent>,
    ) {
        let store = Arc::new(MemoryHeldActionStore::default());
        let events = RuntimeEventBroadcaster::new(16);
        let rx = events.subscribe();
        let capture = HoldCapture::new(
            store.clone(),
            Some(events),
            swarm_core::config::ResponseHoldSettings::default(),
        );
        (capture, store, rx)
    }

    #[test]
    fn exactly_one_of_the_four_skipped_producers_becomes_a_hold() {
        let skipped = || AuditResponseRecord::Skipped { reason: "r".into() };
        let cases = [
            ("deny", trail(PolicyVerdict::Deny, skipped()), false),
            (
                "require_human",
                trail(PolicyVerdict::RequireHuman, skipped()),
                true,
            ),
            (
                "containment_refused",
                trail(
                    PolicyVerdict::Allow,
                    AuditResponseRecord::Skipped {
                        reason: "no containment lease store is configured".into(),
                    },
                ),
                false,
            ),
            (
                "guard",
                trail(
                    PolicyVerdict::Allow,
                    AuditResponseRecord::GuardRejected {
                        guard_name: "g".into(),
                        reason: "r".into(),
                    },
                ),
                false,
            ),
        ];
        for (label, audit, expect_hold) in cases {
            let (capture, store, mut rx) = capture();
            let request = request();
            let detection = crate::ingest::routed_detection_from_request(&request);
            let captured = capture.capture_hold(&request, &detection, &audit, None, T0);
            assert_eq!(captured.is_some(), expect_hold, "{label}");
            assert_eq!(
                store.list(true, 10).unwrap().len(),
                usize::from(expect_hold),
                "{label}"
            );
            if expect_hold {
                let hold = captured.unwrap();
                assert_eq!(hold.state, HoldState::Created);
                assert_eq!(hold.expires_at_ms, T0 + 3_600_000);
                assert_eq!(hold.audit_trail_id.as_deref(), Some("trail-1"));
                assert_eq!(
                    hold.rationale.threat_class,
                    swarm_core::pheromone::ThreatClass::Execution
                );
                match rx.try_recv().unwrap() {
                    RuntimeEvent::ResponseHeld {
                        hold_id,
                        state,
                        action_kind,
                        ..
                    } => {
                        assert_eq!(hold_id, hold.hold_id);
                        assert_eq!(state, HoldState::Created);
                        assert_eq!(action_kind, "isolate_host");
                    }
                    other => panic!("expected ResponseHeld, got {other:?}"),
                }
            } else {
                assert!(rx.try_recv().is_err(), "{label} published an event");
            }
        }
    }

    /// A `Deny` verdict that also reports `Skipped` is the shape a
    /// single-clause match would have turned into a grantable hold. Asserted
    /// separately from the table because it is the whole reason both clauses
    /// are checked.
    #[test]
    fn a_denied_action_is_never_stored_as_a_holdable_row() {
        let (capture, store, mut rx) = capture();
        let request = request();
        let detection = crate::ingest::routed_detection_from_request(&request);
        let audit = trail(
            PolicyVerdict::Deny,
            AuditResponseRecord::Skipped {
                reason: "policy denied".into(),
            },
        );
        assert!(
            capture
                .capture_hold(&request, &detection, &audit, None, T0)
                .is_none()
        );
        assert!(store.list(true, 10).unwrap().is_empty());
        assert!(store.get("hold_anything").unwrap().is_none());
        assert!(rx.try_recv().is_err());
    }

    /// A store that refuses the write produces no hold, no event and no
    /// queue row: nothing downstream can act on an action that was not
    /// recorded. This is the "durable store before any queue" property.
    #[test]
    fn a_hold_the_store_refuses_is_not_published() {
        let dir = std::env::temp_dir().join(format!(
            "hold-capture-persist-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // A file where the store wants its directory: every write fails.
        let store_path = dir.join("holds");
        std::fs::write(&store_path, b"not a directory").unwrap();

        let settings = swarm_core::config::ResponseHoldSettings {
            hold_store_path: Some(store_path.display().to_string()),
            ..Default::default()
        };
        let store = swarm_runtime::held_action::ConfiguredHeldActionStore::from_settings(
            &settings,
            std::path::Path::new("."),
        );
        assert!(store.is_err(), "opening a store over a file should fail");

        // And with a store that opens but cannot persist, capture returns None
        // and publishes nothing.
        let good_dir = dir.join("real-holds");
        let store =
            Arc::new(swarm_runtime::held_action::FileHeldActionStore::open(&good_dir).unwrap());
        let events = RuntimeEventBroadcaster::new(16);
        let mut rx = events.subscribe();
        let capture = HoldCapture::new(
            store.clone(),
            Some(events),
            swarm_core::config::ResponseHoldSettings::default(),
        );
        // Block every temp write by making the directory unusable for new
        // files: replace it with a read-only one is uid-dependent, so instead
        // pre-create a directory at the exact temp path the next mint would
        // use. That is not knowable in advance, so drive the failure through a
        // store whose directory was deleted out from under it.
        std::fs::remove_dir_all(&good_dir).unwrap();
        std::fs::write(&good_dir, b"now a file").unwrap();

        let request = request();
        let detection = crate::ingest::routed_detection_from_request(&request);
        let audit = trail(
            PolicyVerdict::RequireHuman,
            AuditResponseRecord::Skipped {
                reason: "held".into(),
            },
        );
        assert!(
            capture
                .capture_hold(&request, &detection, &audit, None, T0)
                .is_none(),
            "a hold that could not be persisted was returned as captured"
        );
        assert!(
            rx.try_recv().is_err(),
            "a hold that could not be persisted was announced"
        );
        assert!(store.list(true, 10).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── B2: the decide engine ──────────────────────────────────────────────

    use swarm_crypto::{Ed25519Signer, canonical_json_bytes};
    use swarm_perch_wire::verdict::{decision_preimage_bytes, rationale_sha256_hex};
    use swarm_runtime::held_action::{
        GovernanceClearance, HeldActionStore, HoldDecision, HoldOutcome,
    };

    fn signer() -> Ed25519Signer {
        Ed25519Signer::from_secret_material("perch-dev-operator-verdict-seed")
    }

    fn other_signer() -> Ed25519Signer {
        Ed25519Signer::from_secret_material("someone-elses-key")
    }

    fn signed_input(
        signer: &Ed25519Signer,
        decision: HoldDecision,
        hold_id: &str,
        rationale: Option<&str>,
        intent: &str,
    ) -> HoldDecisionInput {
        let digest = rationale_sha256_hex(rationale);
        let bytes =
            decision_preimage_bytes(T0 + 100, decision.as_str(), hold_id, digest.as_deref());
        HoldDecisionInput {
            decision,
            decided_at_ms: T0 + 100,
            nostr_intent_event_id: intent.to_string(),
            signature: signer.sign(&bytes),
            rationale: rationale.map(str::to_string),
            armed_at_ms: Some(T0 + 90),
        }
    }

    fn input(
        decision: HoldDecision,
        hold_id: &str,
        rationale: Option<&str>,
        intent: &str,
    ) -> HoldDecisionInput {
        signed_input(&signer(), decision, hold_id, rationale, intent)
    }

    fn state_with_hold_action(
        hold_state: HoldState,
        action: ResponseAction,
    ) -> (crate::ingest::IngestState, String) {
        let store = Arc::new(MemoryHeldActionStore::default());
        let mut hold = swarm_runtime::held_action_fixtures::fixture_hold(action, T0);
        hold.state = hold_state;
        let id = hold.hold_id.clone();
        store.create(hold).unwrap();
        let state = crate::ingest::tests::test_ingest_state_live_response()
            .with_hold_store(store)
            .with_verdict_key_for_test("perch-dev-operator", signer().public_key_hex());
        (state, id)
    }

    fn state_with_hold(hold_state: HoldState) -> (crate::ingest::IngestState, String) {
        state_with_hold_action(
            hold_state,
            ResponseAction::IsolateHost {
                host_id: "host-ops-1".into(),
            },
        )
    }

    fn stored(state: &crate::ingest::IngestState, id: &str) -> HeldAction {
        state
            .current_hold_store()
            .unwrap()
            .get(id)
            .unwrap()
            .unwrap()
    }

    /// The console signs with `swarm-perch-wire` and the daemon verifies with
    /// `swarm-crypto`. Two implementations, one contract: if they diverge every
    /// honest decision is refused.
    #[test]
    fn the_engine_preimage_equals_the_wire_preimage_byte_for_byte() {
        let engine = canonical_json_bytes(&serde_json::json!({
            "hold_id": "h_a07aeacf",
            "decision": "grant",
            "decided_at_ms": 5,
            "rationale_sha256": null
        }))
        .unwrap();
        let wire = decision_preimage_bytes(5, "grant", "h_a07aeacf", None);
        assert_eq!(engine, wire);

        let engine = canonical_json_bytes(&serde_json::json!({
            "hold_id": "h_a07aeacf",
            "decision": "refuse",
            "decided_at_ms": 1_773_738_979_000_i64,
            "rationale_sha256": "ab"
        }))
        .unwrap();
        let wire = decision_preimage_bytes(1_773_738_979_000, "refuse", "h_a07aeacf", Some("ab"));
        assert_eq!(engine, wire);
    }

    #[tokio::test]
    async fn a_bad_signature_is_refused_and_writes_nothing() {
        let (state, id) = state_with_hold(HoldState::Notified);
        let mut bad = input(HoldDecision::Refuse, &id, None, &"aa".repeat(32));
        bad.signature.signature_hex = "00".repeat(64);
        let error = decide_hold(&state, &id, "perch-dev-operator", bad, T0 + 100)
            .await
            .unwrap_err();
        assert!(matches!(error, HoldDecisionError::InvalidSignature(_)));
        let after = stored(&state, &id);
        assert_eq!(after.state, HoldState::Notified);
        assert!(after.decision.is_none());
        assert!(after.deciding_intent_event_id.is_none());
    }

    /// A signature over ANOTHER hold cannot be replayed onto this one: the
    /// daemon rebuilds the preimage from its own stored `hold_id`.
    #[tokio::test]
    async fn a_signature_over_a_different_hold_is_refused() {
        let (state, id) = state_with_hold(HoldState::Notified);
        let forged = input(
            HoldDecision::Grant,
            "hold_ffffffff-0000-4000-8000-000000000000",
            None,
            &"aa".repeat(32),
        );
        let error = decide_hold(&state, &id, "perch-dev-operator", forged, T0 + 100)
            .await
            .unwrap_err();
        assert!(matches!(error, HoldDecisionError::InvalidSignature(_)));
        assert_eq!(stored(&state, &id).state, HoldState::Notified);
    }

    /// The decided_at_ms in the body is signed, so changing it after signing
    /// breaks the signature rather than moving the recorded instant.
    #[tokio::test]
    async fn a_restated_decision_instant_is_refused() {
        let (state, id) = state_with_hold(HoldState::Notified);
        let mut tampered = input(HoldDecision::Grant, &id, None, &"aa".repeat(32));
        tampered.decided_at_ms = T0 + 999;
        let error = decide_hold(&state, &id, "perch-dev-operator", tampered, T0 + 100)
            .await
            .unwrap_err();
        assert!(matches!(error, HoldDecisionError::InvalidSignature(_)));
    }

    #[tokio::test]
    async fn a_substituted_rationale_is_refused() {
        let (state, id) = state_with_hold(HoldState::Notified);
        let mut swapped = input(
            HoldDecision::Refuse,
            &id,
            Some("original"),
            &"aa".repeat(32),
        );
        swapped.rationale = Some("substituted".into());
        let error = decide_hold(&state, &id, "perch-dev-operator", swapped, T0 + 100)
            .await
            .unwrap_err();
        assert!(matches!(error, HoldDecisionError::InvalidSignature(_)));
        assert_eq!(stored(&state, &id).state, HoldState::Notified);
    }

    /// A real signature by the WRONG key is refused at the binding step, not
    /// at the signature step: the signature verifies, the voter does not bind.
    #[tokio::test]
    async fn a_voter_that_does_not_bind_to_the_principal_is_refused() {
        let (state, id) = state_with_hold(HoldState::Notified);
        // Right operator, wrong key.
        let wrong_key = signed_input(
            &other_signer(),
            HoldDecision::Refuse,
            &id,
            None,
            &"aa".repeat(32),
        );
        let error = decide_hold(&state, &id, "perch-dev-operator", wrong_key, T0 + 100)
            .await
            .unwrap_err();
        assert!(matches!(error, HoldDecisionError::VoterMismatch { .. }));

        // Right key, operator the config does not bind it to.
        let error = decide_hold(
            &state,
            &id,
            "someone-else",
            input(HoldDecision::Refuse, &id, None, &"bb".repeat(32)),
            T0 + 100,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, HoldDecisionError::VoterMismatch { .. }));
        let after = stored(&state, &id);
        assert_eq!(after.state, HoldState::Notified);
        assert!(after.decision.is_none());
    }

    /// A principal with NO verdict key binds to nothing. "No key configured"
    /// must never read as "any key accepted".
    #[tokio::test]
    async fn a_principal_with_no_verdict_key_cannot_decide() {
        let store = Arc::new(MemoryHeldActionStore::default());
        let mut hold = swarm_runtime::held_action_fixtures::fixture_hold(
            ResponseAction::IsolateHost {
                host_id: "host-ops-1".into(),
            },
            T0,
        );
        hold.state = HoldState::Notified;
        let id = hold.hold_id.clone();
        store.create(hold).unwrap();
        // No `with_verdict_key_for_test`.
        let state = crate::ingest::tests::test_ingest_state_live_response().with_hold_store(store);
        let error = decide_hold(
            &state,
            &id,
            "perch-dev-operator",
            input(HoldDecision::Refuse, &id, None, &"aa".repeat(32)),
            T0 + 100,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, HoldDecisionError::VoterMismatch { .. }));
        assert_eq!(stored(&state, &id).state, HoldState::Notified);
    }

    #[tokio::test]
    async fn refuse_short_circuits_on_a_created_hold_and_records_the_notice_state() {
        let (state, id) = state_with_hold(HoldState::Created);
        let outcome = decide_hold(
            &state,
            &id,
            "perch-dev-operator",
            input(HoldDecision::Refuse, &id, Some("not now"), &"aa".repeat(32)),
            T0 + 100,
        )
        .await
        .unwrap();
        assert!(!outcome.replayed);
        assert_eq!(outcome.hold.state, HoldState::Refused);
        let record = outcome.hold.decision.unwrap();
        assert_eq!(record.outcome, HoldOutcome::RefusedByOperator);
        assert!(!record.dispatched);
        assert!(!record.hold_notice_published);
        assert_eq!(
            record.decided_at_ms,
            T0 + 100,
            "the CAS instant, not the body's clock"
        );
        assert_eq!(
            record.rationale_sha256,
            rationale_sha256_hex(Some("not now"))
        );
        assert!(
            record.audit_trail_id.is_none(),
            "the runtime is never entered on refuse"
        );
        assert!(outcome.receipt.is_none());
        assert!(outcome.capability_lease.is_none());
    }

    #[tokio::test]
    async fn a_replay_returns_the_stored_record_and_a_different_id_conflicts() {
        let (state, id) = state_with_hold(HoldState::Notified);
        let first = input(HoldDecision::Refuse, &id, None, &"aa".repeat(32));
        decide_hold(&state, &id, "perch-dev-operator", first.clone(), T0 + 100)
            .await
            .unwrap();
        let replay = decide_hold(&state, &id, "perch-dev-operator", first, T0 + 200)
            .await
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(
            replay.hold.decision.unwrap().decided_at_ms,
            T0 + 100,
            "a replay returns the ORIGINAL record, not a re-decision"
        );
        let other = decide_hold(
            &state,
            &id,
            "perch-dev-operator",
            input(HoldDecision::Grant, &id, None, &"bb".repeat(32)),
            T0 + 300,
        )
        .await
        .unwrap_err();
        assert!(matches!(other, HoldDecisionError::AlreadyDecided));
        // And the stored record is untouched by the losing attempt.
        let after = stored(&state, &id);
        assert_eq!(after.state, HoldState::Refused);
        assert_eq!(after.decision.unwrap().decision, HoldDecision::Refuse);
    }

    #[tokio::test]
    async fn an_expired_hold_is_a_typed_hold_expired() {
        let (state, id) = state_with_hold(HoldState::Notified);
        let error = decide_hold(
            &state,
            &id,
            "perch-dev-operator",
            input(HoldDecision::Grant, &id, None, &"aa".repeat(32)),
            T0 + 3_600_000,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, HoldDecisionError::Expired));
        assert_eq!(stored(&state, &id).state, HoldState::Notified);
    }

    /// A claim already held by another intent conflicts rather than
    /// double-granting, and the same intent reports itself in flight.
    #[tokio::test]
    async fn a_claimed_hold_reports_which_conflict_it_is() {
        let (state, id) = state_with_hold(HoldState::Notified);
        state
            .current_hold_store()
            .unwrap()
            .begin_decision(&id, &"cc".repeat(32), T0 + 50)
            .unwrap();

        let other = decide_hold(
            &state,
            &id,
            "perch-dev-operator",
            input(HoldDecision::Grant, &id, None, &"aa".repeat(32)),
            T0 + 100,
        )
        .await
        .unwrap_err();
        assert!(matches!(other, HoldDecisionError::AlreadyDeciding));

        let same = decide_hold(
            &state,
            &id,
            "perch-dev-operator",
            input(HoldDecision::Grant, &id, None, &"cc".repeat(32)),
            T0 + 100,
        )
        .await
        .unwrap_err();
        assert!(matches!(same, HoldDecisionError::DecisionInFlight));
    }

    /// A grant whose governance receipt is stale is refused LATE, with the
    /// typed rule, and dispatches nothing. This is B2g re-evaluated at the
    /// decision instant: the hold was captured with no receipt at all.
    #[tokio::test]
    async fn a_grant_with_no_governance_receipt_is_refused_late_with_a_typed_rule() {
        let (state, id) = state_with_hold(HoldState::Notified);
        let outcome = decide_hold(
            &state,
            &id,
            "perch-dev-operator",
            input(HoldDecision::Grant, &id, Some("isolate"), &"aa".repeat(32)),
            T0 + 100,
        )
        .await
        .unwrap();
        let record = outcome.hold.decision.unwrap();
        assert_eq!(record.outcome, HoldOutcome::RefusedLate);
        assert!(!record.dispatched, "a governance refusal never dispatches");
        assert_eq!(
            record.refusal.unwrap().rule,
            "governance.missing_receipt",
            "the operator is owed the reason their grant did not act"
        );
        assert!(
            record.audit_trail_id.is_none(),
            "the runtime is never entered when governance refuses"
        );
        assert_eq!(outcome.hold.state, HoldState::Refused);
    }

    /// The whole grant path, on an action that clears governance: the runtime
    /// runs, the receipt names the operator, and the capability lease is minted
    /// from the compare-and-set instant rather than from hold time.
    #[tokio::test]
    async fn a_granted_action_executes_and_names_the_operator_on_the_receipt() {
        let store = Arc::new(MemoryHeldActionStore::default());
        let mut hold = swarm_runtime::held_action_fixtures::fixture_hold(
            ResponseAction::TriggerEdrScan {
                host_id: "host-ops-1".into(),
                scan_profile: "quick".into(),
            },
            T0,
        );
        hold.state = HoldState::Notified;
        let id = hold.hold_id.clone();
        store.create(hold).unwrap();
        let state = crate::ingest::tests::test_ingest_state_live_response()
            .with_hold_store(store)
            .with_verdict_key_for_test("perch-dev-operator", signer().public_key_hex());

        let outcome = decide_hold(
            &state,
            &id,
            "perch-dev-operator",
            input(HoldDecision::Grant, &id, Some("scan it"), &"aa".repeat(32)),
            T0 + 100,
        )
        .await
        .unwrap();
        let record = outcome.hold.decision.clone().unwrap();
        assert!(
            matches!(
                record.outcome,
                HoldOutcome::GrantedExecuted | HoldOutcome::GrantedSimulated
            ),
            "{record:?}"
        );
        assert!(record.dispatched);
        assert_eq!(
            record.governance_clearance,
            GovernanceClearance::NotRequired,
            "trigger_edr_scan is not a receipt-gated action"
        );
        assert!(record.audit_trail_id.is_some());
        let receipt = outcome.receipt.expect("an executed grant has a receipt");
        let approved = receipt
            .audit
            .approved_by
            .expect("a granted action names its operator");
        assert_eq!(approved.hold_id, id);
        assert_eq!(approved.operator_id, "perch-dev-operator");
        assert_eq!(approved.decided_at_ms, T0 + 100);
        let lease = outcome
            .capability_lease
            .expect("a grant mints a capability lease");
        assert_eq!(
            lease.expires_at_ms,
            T0 + 100 + 60_000,
            "the lease is minted from the decision instant, not from hold time"
        );
    }

    /// Concurrency at the route level: many decisions on one hold, exactly one
    /// wins, and every loser is a typed conflict rather than a second dispatch.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_decisions_on_one_hold_produce_exactly_one_record() {
        let (state, id) = state_with_hold(HoldState::Notified);
        let mut handles = Vec::new();
        for slot in 0..8u8 {
            let state = state.clone();
            let id = id.clone();
            handles.push(tokio::spawn(async move {
                let intent = format!("{slot:02x}").repeat(32);
                decide_hold(
                    &state,
                    &id,
                    "perch-dev-operator",
                    input(HoldDecision::Refuse, &id, None, &intent),
                    T0 + 100,
                )
                .await
                .map(|outcome| outcome.replayed)
            }));
        }
        let mut decided = 0;
        let mut conflicts = 0;
        for handle in handles {
            match handle.await.unwrap() {
                Ok(replayed) => {
                    assert!(!replayed);
                    decided += 1;
                }
                Err(HoldDecisionError::AlreadyDeciding | HoldDecisionError::AlreadyDecided) => {
                    conflicts += 1;
                }
                Err(other) => panic!("unexpected error {other:?}"),
            }
        }
        assert_eq!(decided, 1, "more than one decision was recorded");
        assert_eq!(conflicts, 7);
        let after = stored(&state, &id);
        assert_eq!(after.state, HoldState::Refused);
        assert!(!after.decision.unwrap().dispatched);
    }

    #[test]
    fn the_ttl_honours_the_threat_class_override() {
        let store = Arc::new(MemoryHeldActionStore::default());
        let mut settings = swarm_core::config::ResponseHoldSettings::default();
        settings
            .hold_ttl_ms_by_threat_class
            .insert("execution".into(), 900_000);
        let capture = HoldCapture::new(store, None, settings);
        let request = request();
        let detection = crate::ingest::routed_detection_from_request(&request);
        let audit = trail(
            PolicyVerdict::RequireHuman,
            AuditResponseRecord::Skipped { reason: "r".into() },
        );
        let hold = capture
            .capture_hold(&request, &detection, &audit, None, T0)
            .unwrap();
        assert_eq!(hold.expires_at_ms, T0 + 900_000);
    }
}
