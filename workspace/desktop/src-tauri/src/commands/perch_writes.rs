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

use serde::Deserialize;
use tauri::State;

use crate::app_state::AppState;
use crate::perch::daemon_client::{perch_daemon_post, route};

const ROUTE_FINDING_FEEDBACK: &str = "/v1/operator/findings/{finding_id}/feedback";
const ROUTE_MINT_INCIDENT: &str = "/v1/operator/incidents";

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
