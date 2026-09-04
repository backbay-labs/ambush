//! The console's daemon-bound writes.
//!
//! INV-01: the whole non-GET surface is the five `(method, template)` tuples in
//! `PERCH_DAEMON_WRITES` (`crate::perch::daemon_client`). This milestone
//! implements two of them. There is no generic passthrough command and no
//! command that accepts a path: each one names a `&'static str` route constant
//! declared here, and `crate::perch::daemon_client::perch_daemon_post` refuses
//! any pair the table does not carry, before the keyring is read and before a
//! socket is opened.
//!
//! Neither command signs anything, so neither reaches `perch_sign_gate`: leg 1
//! of a verdict is a relay-published card produced only by
//! `perch_record_verdict`, and these are leg 2.

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::app_state::AppState;
use crate::commands::perch_verdict::DetachedSignature;
use crate::perch::daemon_client::{
    daemon_response_error, perch_daemon_get, perch_daemon_post, route, DaemonResponse,
};

const ROUTE_FINDING_FEEDBACK: &str = "/v1/operator/findings/{finding_id}/feedback";
const ROUTE_MINT_INCIDENT: &str = "/v1/operator/incidents";
/// The one route in this console that can cause a destructive action to run.
const ROUTE_DECIDE_HOLD: &str = "/v1/response/holds/{hold_id}/decide";
/// The re-read a 409 resolves through. A GET, deliberately not on the write
/// table (00-DECISIONS W3-17).
const ROUTE_GET_HOLD: &str = "/v1/response/holds/{hold_id}";
const ROUTE_RELEASE_CONTAINMENT: &str = "/v1/operator/containment/leases/{lease_id}/release";

/// Leg 2 of a finding verdict (B3): tell the daemon what the operator decided,
/// naming the leg-1 card that carries the signed intent.
///
/// A 404 is the honest not-yet-correlated answer — the daemon has not yet
/// joined this finding to an incident — and is surfaced as such rather than as
/// a generic failure, because the console retries that case and not the others.
#[tauri::command]
pub async fn perch_finding_feedback(
    finding_id: String,
    incident_id: String,
    action: String,
    verdict_event_id: String,
    reason: Option<String>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    if !matches!(action.as_str(), "confirm" | "dismiss" | "investigate") {
        return Err(format!("unknown finding action `{action}`"));
    }
    let r = perch_daemon_post(
        &state,
        &route(ROUTE_FINDING_FEEDBACK, &[("finding_id", &finding_id)])?,
        serde_json::json!({
            "action": action,
            "incident_id": incident_id,
            "verdict_event_id": verdict_event_id,
            "reason": reason,
        }),
    )
    .await?;
    match r.status {
        200 => Ok(r.body),
        404 => Err(format!(
            "not-yet-correlated: {}",
            r.body["message"].as_str().unwrap_or("")
        )),
        s => Err(format!(
            "daemon answered {s}: {}",
            r.body["message"].as_str().unwrap_or("")
        )),
    }
}

/// Everything B3i needs to mint an incident and its `case_id` from a finding.
///
/// Mirrors the daemon's request body one field for one field; the renderer
/// supplies it in camelCase.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintIncidentInput {
    /// The finding this incident is promoted from.
    pub finding_id: String,
    /// The hunt that produced the finding.
    pub hunt_id: String,
    /// The runtime event the finding was raised on.
    pub event_id: String,
    /// The detection strategy that fired.
    pub strategy_id: String,
    /// The threat class, standard slug or `{"custom": "…"}`.
    pub threat_class: serde_json::Value,
    /// `LOW | MEDIUM | HIGH | CRITICAL`.
    pub severity: String,
    /// When the finding was raised, in milliseconds.
    pub created_at_ms: i64,
    /// The finding's human sentence, carried onto the incident.
    pub summary: String,
    /// The host the finding is about, when it names one.
    pub host_id: Option<String>,
    /// Correlation keys the daemon joins later findings on.
    pub correlation_keys: Vec<String>,
}

/// Promote a finding to an incident (B3i). The daemon mints both the incident
/// and its `case_id`, and publishes `RuntimeEvent::CasePromoted` so the bridge
/// creates the case channel.
#[tauri::command]
pub async fn perch_mint_incident(
    input: MintIncidentInput,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({
        "finding_id": input.finding_id,
        "hunt_id": input.hunt_id,
        "event_id": input.event_id,
        "strategy_id": input.strategy_id,
        "threat_class": input.threat_class,
        "severity": input.severity,
        "created_at_ms": input.created_at_ms,
        "summary": input.summary,
        "host_id": input.host_id,
        "correlation_keys": input.correlation_keys,
    });
    let r = perch_daemon_post(&state, &route(ROUTE_MINT_INCIDENT, &[])?, body).await?;
    if r.status != 200 {
        return Err(format!(
            "daemon answered {}: {}",
            r.status,
            r.body["message"].as_str().unwrap_or("")
        ));
    }
    Ok(r.body)
}

// ── B2 leg 2: the decide route ─────────────────────────────────────────────

/// The operator's two words on a hold. Never `deny`: `refuse` is the
/// operator's word, `deny` is the policy's.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PerchDecision {
    /// Let the held action run.
    Grant,
    /// Refuse it. Nothing is dispatched, ever.
    Refuse,
}

impl PerchDecision {
    /// The wire word, which is also the one inside the signature preimage.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Refuse => "refuse",
        }
    }
}

/// Leg 1's output, forwarded verbatim.
///
/// Every field here was produced and signed by `perch_record_verdict`. Leg 2
/// carries them; it does not mint, re-stamp or re-sign any of them, which is
/// why a retry can re-send the same bytes and why the daemon can treat the
/// intent id as an idempotency key.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecideHoldInput {
    /// `hold_` + lowercase UUIDv4. Validated here, before a socket opens: a
    /// malformed id is a local refusal, not a 404 round trip.
    pub hold_id: String,
    /// Grant or refuse. INSIDE the signature preimage.
    pub decision: PerchDecision,
    /// The operator's own words. Covered by the signature as its SHA-256, so
    /// nothing holding the bearer can replay a valid signature with
    /// substituted text.
    pub rationale: Option<String>,
    /// Leg 1's clock. INSIDE the preimage, so leg 2 must not restate it.
    pub decided_at_ms: i64,
    /// The leg-1 card's event id, 64 lowercase hex. The idempotency key, and
    /// an UNSIGNED pointer: it names the object carrying this very signature,
    /// so it cannot be inside the preimage. The checkable join between the two
    /// legs is `signature.signature_hex`, byte-identical on both.
    pub nostr_intent_event_id: String,
    /// Leg 1's detached Ed25519 signature.
    pub signature: DetachedSignature,
    /// When the row was armed. Advisory, outside the preimage: the 1500 ms
    /// dwell is a client-side control, and a daemon enforcing it would be
    /// gating a destructive action on a client clock.
    pub armed_at_ms: Option<i64>,
}

/// Typed daemon outcome.
///
/// `RefusedLate` and `RefusedLateGovernance` are NORMAL outcomes carried in
/// `Ok`, never `Err`: a late refusal is the system working, and rendering it
/// as a client error teaches operators that refusals are bugs. `Superseded` is
/// the same shape of fact for a different cause.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecideOutcomeKind {
    /// The daemon recorded the decision and acted on it as asked.
    Dispatched,
    /// The daemon recorded the decision and refused to act, naming a rule.
    RefusedLate,
    /// The same, where the refusing rule was a governance one.
    RefusedLateGovernance,
    /// The hold stopped being decidable before the decision arrived.
    Expired,
    /// The daemon has no such hold.
    UnknownHold,
    /// Another decision won the store's compare-and-set.
    Superseded,
}

/// What leg 2 tells the renderer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecideOutcome {
    /// Which of the six outcomes this was.
    pub outcome: DecideOutcomeKind,
    /// The refusing rule's name, quoted separately from its reason so the pane
    /// can render the rule without paraphrasing it.
    pub rule: Option<String>,
    /// The refusing layer's own words. Rendered verbatim, never summarised.
    pub reason: Option<String>,
    /// The response receipt, when one was minted.
    pub receipt_id: Option<String>,
    /// The daemon's own compare-and-set instant, not the one leg 1 signed.
    pub decided_at_ms: i64,
    /// Populated ONLY on `Superseded`, and only from a RE-READ of the hold
    /// (W3-17). Never synthesised from the 409 body, which carries no winner.
    pub superseded_by: Option<String>,
    /// Whether the daemon replayed a decision it already held.
    pub replayed: bool,
    /// Whether the runtime attempted the response at all. Carried from the
    /// daemon's record rather than inferred from the outcome.
    pub dispatched: bool,
}

/// Which request an attempt was. The re-read is a different request from the
/// decide, and the retry test asserts the sequence, so the kind is explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecideAttemptKind {
    /// `POST /v1/response/holds/{hold_id}/decide`.
    Decide,
    /// `GET /v1/response/holds/{hold_id}`.
    ReadHold,
}

/// One request leg 2 made, as the tests observe it.
#[derive(Debug, Clone)]
pub struct DecideAttempt {
    /// Decide or re-read.
    pub kind: DecideAttemptKind,
    /// The hold id the route was built from.
    pub hold_id: String,
    /// The JSON body, or `Null` for the re-read.
    pub body: serde_json::Value,
}

/// Map a 200 onto a typed outcome.
///
/// `dispatched` is carried from the record, never inferred: "the daemon acted"
/// and "the daemon said yes" are different facts, and a refusal the operator
/// MADE is a different row from a refusal the daemon imposed.
fn map_success(body: &serde_json::Value) -> DecideOutcome {
    let decision = &body["decision"];
    let rule = decision["refusal"]["rule"].as_str().map(str::to_string);
    let reason = decision["refusal"]["reason"].as_str().map(str::to_string);
    let governance = rule
        .as_deref()
        .is_some_and(|rule| rule.starts_with("governance."));
    let outcome = match decision["outcome"].as_str().unwrap_or_default() {
        "granted_executed" | "granted_simulated" | "refused_by_operator" => {
            DecideOutcomeKind::Dispatched
        }
        _ if governance => DecideOutcomeKind::RefusedLateGovernance,
        _ => DecideOutcomeKind::RefusedLate,
    };
    DecideOutcome {
        outcome,
        rule,
        reason,
        receipt_id: decision["receipt_id"].as_str().map(str::to_string),
        decided_at_ms: decision["decided_at_ms"].as_i64().unwrap_or_default(),
        superseded_by: None,
        replayed: body["replayed"].as_bool().unwrap_or(false),
        dispatched: decision["dispatched"].as_bool().unwrap_or(false),
    }
}

/// Map a 409 onto a typed outcome, given the hold as the daemon reports it NOW.
///
/// W3-17: the winner is learned by re-reading, not from the error body, so
/// there is one authority for "who decided this" rather than two that can
/// disagree. A re-read naming our OWN intent is not a supersession — the
/// decision that won was this console's, and telling the operator they were
/// overridden when they were not is worse than saying nothing.
fn map_conflict(error: &str, own_intent: &str, re_read: &serde_json::Value) -> DecideOutcome {
    let hold = &re_read["hold"];
    let winner = hold["deciding_intent_event_id"]
        .as_str()
        .unwrap_or_default();
    let superseded = matches!(error, "hold_already_deciding" | "hold_already_decided")
        && !winner.is_empty()
        && winner != own_intent;
    let outcome = if superseded {
        DecideOutcomeKind::Superseded
    } else if error == "hold_expired" {
        DecideOutcomeKind::Expired
    } else {
        DecideOutcomeKind::RefusedLate
    };
    DecideOutcome {
        outcome,
        rule: Some(error.to_string()),
        reason: hold["decision"]["decision"]
            .as_str()
            .map(|decision| format!("another operator's {decision} was recorded first")),
        receipt_id: None,
        decided_at_ms: hold["decision"]["decided_at_ms"]
            .as_i64()
            .unwrap_or_default(),
        superseded_by: superseded.then(|| winner.to_string()),
        replayed: false,
        dispatched: false,
    }
}

/// The decide sequence, over an injected sender.
///
/// The request body is built ONCE, before the loop, and every attempt re-sends
/// that same value. That is the whole of the retry contract: leg 2 forwards
/// bytes leg 1 signed, so rebuilding them per attempt would invalidate the
/// signature and hand the daemon a second intent id for one human decision.
/// The sender is a parameter so a test can watch the sequence; the property is
/// about which bytes go out, and no return value shows that.
pub(crate) async fn decide_with<S, F>(
    input: &DecideHoldInput,
    send: S,
) -> Result<DecideOutcome, String>
where
    S: Fn(DecideAttempt) -> F,
    F: std::future::Future<Output = Result<DaemonResponse, String>>,
{
    if !swarm_perch_wire::tags::is_opaque_hold_id(&input.hold_id) {
        return Err("holdId must match ^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$".to_string());
    }
    let body = serde_json::json!({
        "decision": input.decision.as_str(),
        "decided_at_ms": input.decided_at_ms,
        "nostr_intent_event_id": input.nostr_intent_event_id,
        "signature": input.signature,
        "rationale": input.rationale,
        "armed_at_ms": input.armed_at_ms,
    });

    let mut attempts = 0_u32;
    loop {
        attempts += 1;
        let response = send(DecideAttempt {
            kind: DecideAttemptKind::Decide,
            hold_id: input.hold_id.clone(),
            body: body.clone(),
        })
        .await?;
        match response.status {
            200 => return Ok(map_success(&response.body)),
            404 => {
                return Ok(DecideOutcome {
                    outcome: DecideOutcomeKind::UnknownHold,
                    rule: Some("not_found".to_string()),
                    reason: response.body["message"].as_str().map(str::to_string),
                    receipt_id: None,
                    decided_at_ms: input.decided_at_ms,
                    superseded_by: None,
                    replayed: false,
                    dispatched: false,
                });
            }
            409 => {
                let error = response.body["error"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                // The daemon is still applying a decision under THIS intent id.
                // One retry, at the interval the daemon asked for; a second
                // conflict is surfaced rather than spun on.
                if error == "decision_in_flight" {
                    if attempts >= 2 {
                        return Err("decision_in_flight".to_string());
                    }
                    let wait = response.retry_after_seconds.unwrap_or(1);
                    if wait > 0 {
                        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                    }
                    continue;
                }
                // `hold_expired` needs no re-read: the daemon already said the
                // hold stopped being decidable and nothing was taken.
                if error == "hold_expired" {
                    return Ok(map_conflict(
                        &error,
                        &input.nostr_intent_event_id,
                        &serde_json::Value::Null,
                    ));
                }
                let re_read = send(DecideAttempt {
                    kind: DecideAttemptKind::ReadHold,
                    hold_id: input.hold_id.clone(),
                    body: serde_json::Value::Null,
                })
                .await?;
                return Ok(map_conflict(
                    &error,
                    &input.nostr_intent_event_id,
                    &re_read.body,
                ));
            }
            status => {
                // 401, 403 and 422 are client bugs, not outcomes: a rejected
                // signature or an unbound voter means this console built
                // something wrong, and rendering it as a refusal would teach
                // the operator that the daemon refused their decision.
                return Err(format!(
                    "daemon answered {status}: {}",
                    response.body["message"].as_str().unwrap_or_default()
                ));
            }
        }
    }
}

/// LEG 2 of the two-legged write, and the only call in this console that can
/// cause a destructive action to run.
///
/// It carries leg 1's signed bytes to the daemon and reports what the daemon
/// decided. It signs nothing, stamps no clock and mints no id: the daemon
/// re-derives every authority question from its own stored record (ADR 0014),
/// and this command's whole job is transport plus an honest mapping of the
/// answer.
///
/// # Errors
///
/// When the hold id is malformed, when the daemon is unreachable, or when the
/// daemon rejects the request as malformed — a 401, 403 or 422 is a bug in
/// this console, not an outcome for the operator to read.
#[tauri::command]
pub async fn perch_decide_hold(
    input: DecideHoldInput,
    state: State<'_, AppState>,
) -> Result<DecideOutcome, String> {
    decide_with(&input, |attempt| {
        let state = &state;
        async move {
            match attempt.kind {
                DecideAttemptKind::Decide => {
                    perch_daemon_post(
                        state,
                        &route(ROUTE_DECIDE_HOLD, &[("hold_id", &attempt.hold_id)])?,
                        attempt.body,
                    )
                    .await
                }
                DecideAttemptKind::ReadHold => {
                    perch_daemon_get(
                        state,
                        &route(ROUTE_GET_HOLD, &[("hold_id", &attempt.hold_id)])?,
                    )
                    .await
                }
            }
        }
    })
    .await
}

#[cfg(test)]
#[path = "perch_writes_tests.rs"]
mod tests;

/// `POST /v1/operator/containment/leases/{lease_id}/release` — ask the daemon
/// to run a containment's inverse now rather than at its TTL.
///
/// The body is returned whole. The caller reads `lease_closed` from it and
/// never the HTTP status: the daemon answers 200 for a release whose inverse
/// FAILED, because the request was understood and carried out — the world
/// simply did not change. A console that read the status would report a host
/// as freed while it is still contained.
///
/// # Errors
///
/// When the lease id is malformed, when the daemon is unreachable, or when the
/// daemon refuses the request itself.
#[tauri::command]
pub async fn perch_release_containment(
    lease_id: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let r = perch_daemon_post(
        &state,
        &route(ROUTE_RELEASE_CONTAINMENT, &[("lease_id", &lease_id)])?,
        serde_json::json!({}),
    )
    .await?;
    if r.status != 200 {
        return Err(daemon_response_error(&r));
    }
    Ok(r.body)
}
