//! The hold routes (B2r now, B2's decide in Task 13). Owns the DTOs, the scope
//! checks and the status codes; does not own holding, deciding or reading
//! (those are `perch_ops::holds`).
//!
//! These two reads are the RECONCILIATION AUTHORITY: the console's queue is
//! whatever this says it is, and the relay's `46010` notices are a hint that
//! something changed, never the record. That is why a daemon with no hold store
//! answers 503 rather than an empty list — an empty list is a claim about the
//! world, and this daemon is not in a position to make it.

use axum::Json;
use axum::extract::{Extension, Path as RoutePath, Query, State};
use serde::{Deserialize, Serialize};
use swarm_core::config::OperatorScope;
use swarm_core::types::{ResponseRehearsalPreview, Severity};
use swarm_ingest_runtime::control::CURRENT_OPERATOR_API_SCHEMA_VERSION;
use swarm_ingest_runtime::perch_ops::holds::{
    HoldDecisionError, HoldDecisionInput, HoldReadError, decide_hold, get_hold, list_holds,
};
use swarm_policy::{ActionRequest, PolicyDecision};
use swarm_response::rollback::{InverseGap, resolve_inverse};
use swarm_runtime::held_action::{
    HeldAction, HoldDecision, HoldDecisionRecord, HoldRationale, HoldState,
};

use super::PerchHttpState;
use crate::http::auth::{AuthenticatedOperatorPrincipal, require_operator_api_scope};
use crate::http::error::OperatorApiError;
use crate::http::helpers::now_ms;

/// The function every `inverse_resolution` entry names, so a console can say
/// where the verdict came from instead of presenting it as its own judgement.
const INVERSE_DERIVED_BY: &str = "swarm_response::rollback::resolve_inverse";

/// Default page size for the list route.
const DEFAULT_HOLD_LIMIT: usize = 200;
/// Upper bound on the page size a caller may ask for.
const MAX_HOLD_LIMIT: usize = 1_000;

/// Per rollback step, what `resolve_inverse` said. DERIVED, not served.
#[derive(Debug, Clone, Serialize)]
pub struct InverseResolution {
    /// The planned rollback step, by its `ResponseRollbackStepKind` name.
    pub step_kind: String,
    /// Executable, irreversible, or an unmapped pair.
    pub verdict: InverseVerdict,
    /// The refusing layer's own words, when it had any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Render law 4: the console names the producing function.
    pub derived_by: &'static str,
}

/// `executable | irreversible | unmapped`.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InverseVerdict {
    /// An inverse operation exists for this (action, step) pair.
    Executable,
    /// The forward action states the effect cannot be undone.
    Irreversible,
    /// No inverse is defined. A mapping gap, not a statement about the world.
    Unmapped,
}

/// One hold as an operator reads it. `remaining_ms` and `expired` are TWO
/// facts, for the reason `ContainmentLeaseView` carries both: a clock reading
/// and a decision about that reading are different claims, and collapsing them
/// hides which one the daemon is actually making.
#[derive(Debug, Clone, Serialize)]
pub struct HeldActionView {
    /// The opaque hold id.
    pub hold_id: String,
    /// The stored state. NOT the same question as `expired`.
    pub state: HoldState,
    /// When the relay accepted the `46010` notice, if it has.
    pub notified_at_ms: Option<i64>,
    /// The intent id that won the compare-and-set, when one has.
    pub deciding_intent_event_id: Option<String>,
    /// The case channel the bridge created, when it has.
    pub case_channel: Option<String>,
    /// The `46010` event id, when accepted.
    pub notice_event_id: Option<String>,
    /// The `swarm:hold:v1` card's event id, when accepted.
    pub card_event_id: Option<String>,
    /// `ResponseAction::kind()`.
    pub action_kind: String,
    /// The severity the requesting agent claimed.
    pub severity: Severity,
    /// When the hold was captured (unix ms).
    pub held_at_ms: i64,
    /// When it stops being decidable (unix ms).
    pub expires_at_ms: i64,
    /// Saturates at zero.
    pub remaining_ms: i64,
    /// True past `expires_at_ms`, or once the sweep has recorded the expiry.
    pub expired: bool,
    /// ACTION, verbatim.
    pub action_request: ActionRequest,
    /// The verdict that held it.
    pub policy_decision: PolicyDecision,
    /// WHY WE ARE ASKING.
    pub rationale: HoldRationale,
    /// Whether granting would mint a containment lease.
    pub leases_a_containment: bool,
    /// BLAST RADIUS, when a preview could be built.
    pub rehearsal: Option<ResponseRehearsalPreview>,
    /// IF YOU UNDO, derived per planned rollback step.
    pub inverse_resolution: Vec<InverseResolution>,
    /// The decision record, once one exists.
    pub decision: Option<HoldDecisionRecord>,
}

impl HeldActionView {
    /// Build the view against a stated instant.
    pub fn from_hold(hold: HeldAction, observed_at_ms: i64) -> Self {
        let remaining_ms = hold.expires_at_ms.saturating_sub(observed_at_ms).max(0);
        let expired = hold.state == HoldState::Expired || observed_at_ms >= hold.expires_at_ms;
        let inverse_resolution = hold
            .rehearsal
            .as_ref()
            .map(|preview| {
                preview
                    .rollback
                    .steps
                    .iter()
                    .map(|step| {
                        let (verdict, reason) =
                            match resolve_inverse(&hold.action_request.action, step.kind) {
                                Ok(_) => (InverseVerdict::Executable, None),
                                Err(InverseGap::Irreversible { reason }) => {
                                    (InverseVerdict::Irreversible, Some(reason.to_string()))
                                }
                                Err(InverseGap::Unmapped) => (InverseVerdict::Unmapped, None),
                            };
                        InverseResolution {
                            step_kind: format!("{:?}", step.kind),
                            verdict,
                            reason,
                            derived_by: INVERSE_DERIVED_BY,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            hold_id: hold.hold_id,
            state: hold.state,
            notified_at_ms: hold.notified_at_ms,
            deciding_intent_event_id: hold.deciding_intent_event_id,
            case_channel: hold.case_channel,
            notice_event_id: hold.notice_event_id,
            card_event_id: hold.card_event_id,
            action_kind: hold.action_request.action.kind().to_string(),
            severity: hold.action_request.severity,
            held_at_ms: hold.held_at_ms,
            expires_at_ms: hold.expires_at_ms,
            remaining_ms,
            expired,
            leases_a_containment: swarm_runtime::containment::is_containment_action(
                &hold.action_request.action,
            ),
            action_request: hold.action_request,
            policy_decision: hold.policy_decision,
            rationale: hold.rationale,
            rehearsal: hold.rehearsal,
            inverse_resolution,
            decision: hold.decision,
        }
    }
}

/// `GET /v1/response/holds`.
#[derive(Debug, Clone, Serialize)]
pub struct HoldListResponse {
    /// The operator API schema version this body follows.
    pub schema_version: u32,
    /// The instant every derived field was computed against.
    pub observed_at_ms: i64,
    /// The page, sorted `(expires_at_ms, hold_id)` ascending.
    pub holds: Vec<HeldActionView>,
    /// Open holds across the whole store, not just this page.
    pub open_count: usize,
    /// Whether `limit` cut the page short.
    pub truncated: bool,
    /// Claims older than `decide_stall_ms` the sweep has not resolved yet.
    pub deciding_stalled_count: usize,
    /// FALSE means a restart forgets every open hold. The console renders it.
    pub store_durable: bool,
}

/// `GET /v1/response/holds/{hold_id}`.
#[derive(Debug, Clone, Serialize)]
pub struct HoldDetailResponse {
    /// The operator API schema version this body follows.
    pub schema_version: u32,
    /// The instant every derived field was computed against.
    pub observed_at_ms: i64,
    /// The hold.
    pub hold: HeldActionView,
}

/// Query of the list route. `now_ms` absent means now.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoldListQuery {
    /// Evaluate the clock-derived fields against this instant.
    pub now_ms: Option<i64>,
    /// Include decided and expired holds. Default false.
    pub include_terminal: Option<bool>,
    /// Page size, clamped to `1..=1000`. Default 200.
    pub limit: Option<usize>,
}

/// Query of the detail route.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoldDetailQuery {
    /// Evaluate the clock-derived fields against this instant.
    pub now_ms: Option<i64>,
}

fn map_read_error(error: HoldReadError) -> OperatorApiError {
    match error {
        HoldReadError::NoHoldStore => OperatorApiError::service_unavailable(
            "no hold store is attached to this daemon; set runtime.response.hold_store_path or \
             start with the hold-capable profile",
        ),
        HoldReadError::Store(error) => OperatorApiError::internal(error.to_string()),
    }
}

/// `GET /v1/response/holds` — the queue the console reconciles against.
pub(super) async fn hold_list_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<PerchHttpState>,
    Query(query): Query<HoldListQuery>,
) -> Result<Json<HoldListResponse>, OperatorApiError> {
    require_operator_api_scope(&principal, OperatorScope::Read, "read")?;
    let observed_at_ms = query.now_ms.unwrap_or_else(now_ms);
    let listing = list_holds(
        &state.ingest,
        query.include_terminal.unwrap_or(false),
        query
            .limit
            .unwrap_or(DEFAULT_HOLD_LIMIT)
            .clamp(1, MAX_HOLD_LIMIT),
        observed_at_ms,
    )
    .map_err(map_read_error)?;
    Ok(Json(HoldListResponse {
        schema_version: CURRENT_OPERATOR_API_SCHEMA_VERSION,
        observed_at_ms,
        holds: listing
            .holds
            .into_iter()
            .map(|hold| HeldActionView::from_hold(hold, observed_at_ms))
            .collect(),
        open_count: listing.open_count,
        truncated: listing.truncated,
        deciding_stalled_count: listing.health.deciding_stalled,
        store_durable: listing.health.durable,
    }))
}

/// `GET /v1/response/holds/{hold_id}` — one hold, and after a 409 the way the
/// console learns which decision won (00-DECISIONS W3-17: re-read, never from
/// the error body).
pub(super) async fn hold_detail_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<PerchHttpState>,
    RoutePath(hold_id): RoutePath<String>,
    Query(query): Query<HoldDetailQuery>,
) -> Result<Json<HoldDetailResponse>, OperatorApiError> {
    require_operator_api_scope(&principal, OperatorScope::Read, "read")?;
    let observed_at_ms = query.now_ms.unwrap_or_else(now_ms);
    let hold = get_hold(&state.ingest, &hold_id)
        .map_err(map_read_error)?
        .ok_or_else(|| OperatorApiError::not_found(format!("no hold `{hold_id}`")))?;
    Ok(Json(HoldDetailResponse {
        schema_version: CURRENT_OPERATOR_API_SCHEMA_VERSION,
        observed_at_ms,
        hold: HeldActionView::from_hold(hold, observed_at_ms),
    }))
}

/// Body of `POST /v1/response/holds/{hold_id}/decide`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoldDecisionRequest {
    /// Grant or refuse.
    pub decision: HoldDecision,
    /// The instant the console claims it decided. Signed input, not authority.
    pub decided_at_ms: i64,
    /// 64 lowercase hex. The idempotency key and an unsigned pointer.
    pub nostr_intent_event_id: String,
    /// The operator's detached signature over the four-member preimage.
    pub signature: swarm_crypto::DetachedSignature,
    /// The operator's free-text rationale, if any.
    #[serde(default)]
    pub rationale: Option<String>,
    /// When the console reported the row armed. Informational.
    #[serde(default)]
    pub armed_at_ms: Option<i64>,
}

/// Response. The caller reads `decision.outcome` and `decision.dispatched`,
/// never the status code, to learn what happened to the world: a 200 means the
/// daemon recorded a decision, not that the action ran.
#[derive(Debug, Clone, Serialize)]
pub struct HoldDecisionResponse {
    /// The operator API schema version this body follows.
    pub schema_version: u32,
    /// The hold that was decided.
    pub hold_id: String,
    /// The hold's state after the decision.
    pub state: HoldState,
    /// The authoritative decision record.
    pub decision: HoldDecisionRecord,
    /// True when this call replayed an existing record rather than deciding.
    pub replayed: bool,
    /// The response receipt, when the action executed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<swarm_response::ResponseReceipt>,
    /// The audit trail the runtime wrote, when it was entered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_trail_id: Option<String>,
    /// The containment lease the receipt reported, when there was one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containment_lease_id: Option<String>,
    /// The capability lease, minted from the compare-and-set instant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_lease: Option<swarm_policy::CapabilityLease>,
}

/// Longest rationale the route accepts, in bytes.
const MAX_RATIONALE_BYTES: usize = 4096;

fn is_hex64_lower(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase() && byte <= b'f')
}

/// `POST /v1/response/holds/{hold_id}/decide` — the one route that can turn a
/// held destructive action into a real one.
///
/// The console never authorizes. Everything below the scope check is
/// re-derived by the daemon from its own stored record (ADR 0014): the
/// signature is verified against a preimage rebuilt from the daemon's
/// `hold_id`, the voter is bound to the authenticated principal by config, and
/// governance is re-evaluated at the decision instant.
pub(super) async fn hold_decide_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<PerchHttpState>,
    RoutePath(hold_id): RoutePath<String>,
    Json(request): Json<HoldDecisionRequest>,
) -> Result<Json<HoldDecisionResponse>, OperatorApiError> {
    require_operator_api_scope(&principal, OperatorScope::Approve, "approve")?;
    if !swarm_runtime::held_action::is_opaque_hold_id(&hold_id) {
        return Err(OperatorApiError::bad_request(
            "hold_id must match ^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$",
        ));
    }
    if !is_hex64_lower(&request.nostr_intent_event_id) {
        return Err(OperatorApiError::bad_request(
            "nostr_intent_event_id must be 64 lowercase hex characters",
        ));
    }
    if request
        .rationale
        .as_ref()
        .is_some_and(|text| text.len() > MAX_RATIONALE_BYTES)
    {
        return Err(OperatorApiError::bad_request(
            "rationale exceeds 4096 bytes",
        ));
    }
    let input = HoldDecisionInput {
        decision: request.decision,
        decided_at_ms: request.decided_at_ms,
        nostr_intent_event_id: request.nostr_intent_event_id,
        signature: request.signature,
        rationale: request.rationale,
        armed_at_ms: request.armed_at_ms,
    };
    let outcome = decide_hold(
        &state.ingest,
        &hold_id,
        principal.operator_id.as_ref(),
        input,
        now_ms(),
    )
    .await
    .map_err(|error| match error {
        HoldDecisionError::NoHoldStore => {
            OperatorApiError::service_unavailable("no hold store is attached to this daemon")
        }
        HoldDecisionError::NotFound => OperatorApiError::not_found(format!("no hold `{hold_id}`")),
        HoldDecisionError::InvalidSignature(reason) => OperatorApiError::unprocessable(reason),
        HoldDecisionError::VoterMismatch {
            operator_id,
            voter_id,
        } => OperatorApiError::forbidden(format!(
            "signature key `{voter_id}` does not bind to operator `{operator_id}`"
        )),
        HoldDecisionError::Expired => OperatorApiError::conflict(
            "hold_expired",
            "the hold expired; the action was never taken",
            None,
        ),
        HoldDecisionError::DecisionInFlight => OperatorApiError::conflict(
            "decision_in_flight",
            "this decision is still being applied",
            Some(1),
        ),
        HoldDecisionError::AlreadyDeciding => OperatorApiError::conflict(
            "hold_already_deciding",
            "another decision holds the claim; re-read the hold",
            Some(1),
        ),
        HoldDecisionError::AlreadyDecided => OperatorApiError::conflict(
            "hold_already_decided",
            "the hold was decided under another intent; re-read the hold",
            None,
        ),
        HoldDecisionError::Store(error) => OperatorApiError::internal(error.to_string()),
        HoldDecisionError::Runtime(reason) => OperatorApiError::internal(reason),
    })?;
    let decision = outcome
        .hold
        .decision
        .clone()
        .ok_or_else(|| OperatorApiError::internal("decided hold carries no decision record"))?;
    Ok(Json(HoldDecisionResponse {
        schema_version: CURRENT_OPERATOR_API_SCHEMA_VERSION,
        hold_id: outcome.hold.hold_id.clone(),
        state: outcome.hold.state,
        audit_trail_id: decision.audit_trail_id.clone(),
        decision,
        replayed: outcome.replayed,
        receipt: outcome.receipt,
        containment_lease_id: outcome.containment_lease_id,
        capability_lease: outcome.capability_lease,
    }))
}
