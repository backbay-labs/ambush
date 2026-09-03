//! B3 — the engine half of `POST /v1/operator/findings/{finding_id}/feedback`.
//!
//! The seven steps of `providence_feedback_handler`, with the three changes
//! 12-BACKEND-BILL-API.md §8 names: the HMAC step is replaced by the bearer +
//! `Approve` scope the handler enforces; `analyst_id` comes from the
//! authenticated principal and never from the body (C6 — the body type cannot
//! carry one); and `feedback_id` is derived from the leg-1 verdict card id, so
//! a retry finds its own audit entry and replays instead of appending (§8.5).
//!
//! `request_signature` is `operator-bearer:{operator_id}` (C7): self-describing,
//! so nothing downstream mistakes a shared-token bearer for a signature.

use super::super::providence_handlers::{
    apply_providence_feedback, enrich_feedback_target, false_positive_measurement,
};
use super::super::{IngestState, sanitize_id};
use super::PerchOpsError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use swarm_core::types::{ProvidenceFeedbackAction, SwarmProvidenceFeedbackRequest};
use swarm_runtime::providence::{ProvidenceFeedbackTarget, resolve_feedback_target};
use swarm_spine::{AnalystFeedbackAuditEntry, IncidentStore};

/// Body of `POST /v1/operator/findings/{finding_id}/feedback`.
///
/// Deliberately has no `analyst_id`; sending one is a 400.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingFeedbackRequest {
    /// The verdict. Only `dismiss` sets `false_positive`.
    pub action: ProvidenceFeedbackAction,
    /// The incident carrying the finding; mint one with B3i when absent.
    pub incident_id: String,
    /// 32-byte lowercase hex id of the leg-1 `swarm:verdict:v1` card; derives
    /// the deterministic `feedback_id`.
    pub verdict_event_id: String,
    /// The operator's free-text reason, if any.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Response of `POST /v1/operator/findings/{finding_id}/feedback`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingFeedbackResponse {
    /// Response schema version; `1`.
    pub schema_version: u32,
    /// `perch-feedback:{finding_id}:{verdict_event_id}` — deterministic.
    pub feedback_id: String,
    /// The recorded action.
    pub action: ProvidenceFeedbackAction,
    /// The incident the measurement was written onto.
    pub incident_id: String,
    /// The finding the verdict was recorded on.
    pub finding_id: String,
    /// The authenticated `operator_id`, echoed so the client can show what was recorded.
    pub analyst_id: String,
    /// True only for `dismiss`.
    pub false_positive: bool,
    /// True when an audit entry with the derived `feedback_id` already existed.
    pub replayed: bool,
    /// The suppression outcome from `apply_providence_feedback`, verbatim.
    pub outcome: Value,
}

/// Record an operator's verdict on a finding, attributing it to `operator_id`.
///
/// Idempotent on `verdict_event_id`: an audit entry with the derived
/// `feedback_id` already present short-circuits with `replayed: true` and the
/// recorded outcome, writing nothing.
pub async fn record_finding_feedback(
    state: &IngestState,
    operator_id: &str,
    finding_id: &str,
    request: FindingFeedbackRequest,
    now_ms: i64,
) -> Result<FindingFeedbackResponse, PerchOpsError> {
    if request.verdict_event_id.len() != 64
        || !request
            .verdict_event_id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(PerchOpsError::BadRequest(
            "verdict_event_id must be 64 lowercase hex".into(),
        ));
    }
    let store = state.current_incident_store();
    let lookup = store
        .load_by_incident_id(&request.incident_id)?
        .ok_or_else(|| {
            PerchOpsError::NotFound(format!("incident `{}` was not found", request.incident_id))
        })?;
    let target =
        resolve_feedback_target(&lookup, Some(finding_id)).map_err(PerchOpsError::NotFound)?;
    // `select_feedback_member` falls back to the FIRST member when the named
    // finding is not one (providence.rs `select_feedback_member`), which the
    // webhook tolerates because Providence may omit `finding_id`. B3 names the
    // finding in its path, so a fallback here would record the operator's
    // verdict on a finding they never looked at: refuse it as the same
    // not-yet-correlated wall an absent incident is.
    if target.finding_id != finding_id {
        return Err(PerchOpsError::NotFound(format!(
            "incident `{}` does not contain finding `{finding_id}`",
            request.incident_id
        )));
    }
    let target = enrich_feedback_target(state, &lookup, &target)?;
    let feedback_id = format!(
        "perch-feedback:{}:{}",
        sanitize_id(finding_id),
        request.verdict_event_id
    );
    let mut incident = lookup.incident.clone();
    if let Some(existing) = incident
        .feedback_audit_entries
        .iter()
        .find(|entry| entry.feedback_id == feedback_id)
    {
        return Ok(response(
            &feedback_id,
            &request,
            &target,
            operator_id,
            true,
            existing.outcome.clone(),
        ));
    }
    // The webhook's request type, with analyst_id set from the PRINCIPAL (C5/C6).
    let providence_request = SwarmProvidenceFeedbackRequest {
        action: request.action,
        incident_id: request.incident_id.clone(),
        finding_id: Some(target.finding_id.clone()),
        analyst_id: operator_id.to_string(),
        reason: request.reason.clone(),
    };
    let applied =
        apply_providence_feedback(state, &providence_request, &target, &feedback_id, now_ms)
            .await?;
    incident
        .feedback_audit_entries
        .push(AnalystFeedbackAuditEntry {
            feedback_id: feedback_id.clone(),
            received_at_ms: now_ms,
            action: request.action,
            analyst_id: operator_id.to_string(),
            incident_id: request.incident_id.clone(),
            finding_id: Some(target.finding_id.clone()),
            reason: request.reason.clone(),
            request_signature: format!("operator-bearer:{operator_id}"),
            evidence: Some(applied.evidence),
            soar_lineage: None,
            payload: serde_json::to_value(&request)?,
            outcome: applied.outcome.clone(),
        });
    incident.upsert_false_positive_measurement(false_positive_measurement(
        &providence_request,
        &target,
        &feedback_id,
        now_ms,
    ));
    store.persist(&incident)?;
    Ok(response(
        &feedback_id,
        &request,
        &target,
        operator_id,
        false,
        applied.outcome,
    ))
}

fn response(
    feedback_id: &str,
    request: &FindingFeedbackRequest,
    target: &ProvidenceFeedbackTarget,
    operator_id: &str,
    replayed: bool,
    outcome: Value,
) -> FindingFeedbackResponse {
    FindingFeedbackResponse {
        schema_version: 1,
        feedback_id: feedback_id.to_string(),
        action: request.action,
        incident_id: request.incident_id.clone(),
        finding_id: target.finding_id.clone(),
        analyst_id: operator_id.to_string(),
        false_positive: matches!(request.action, ProvidenceFeedbackAction::Dismiss),
        replayed,
        outcome,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::super::PerchOpsError;
    use super::super::mint::mint_incident;
    use super::super::test_support::{mint_request, seed_replay_bundle, test_state};
    use super::{FindingFeedbackRequest, record_finding_feedback};
    use swarm_core::types::ProvidenceFeedbackAction;
    use swarm_spine::IncidentStore;

    #[tokio::test]
    async fn feedback_takes_analyst_id_from_the_caller_and_is_idempotent_on_the_verdict_event() {
        let state = test_state();
        let minted = mint_incident(&state, mint_request("f-1", Some("host-ops-1")), 1).unwrap();
        let req = FindingFeedbackRequest {
            action: ProvidenceFeedbackAction::Dismiss,
            incident_id: minted.incident_id.clone(),
            verdict_event_id: "cd".repeat(32),
            reason: None,
        };
        let first = record_finding_feedback(&state, "ops-alice", "f-1", req.clone(), 10)
            .await
            .unwrap();
        assert_eq!(first.schema_version, 1);
        assert_eq!(first.analyst_id, "ops-alice");
        assert_eq!(
            first.feedback_id,
            format!("perch-feedback:f-1:{}", "cd".repeat(32))
        );
        assert_eq!(first.action, ProvidenceFeedbackAction::Dismiss);
        assert_eq!(first.incident_id, minted.incident_id);
        assert_eq!(first.finding_id, "f-1");
        assert!(first.false_positive && !first.replayed);
        assert_eq!(first.outcome["substrate"]["status"], "suppressed");
        assert_eq!(first.outcome["substrate"]["false_positive"], true);

        let second = record_finding_feedback(&state, "ops-alice", "f-1", req, 11)
            .await
            .unwrap();
        assert!(second.replayed);
        assert_eq!(second.feedback_id, first.feedback_id);
        assert_eq!(
            second.outcome, first.outcome,
            "a replay returns the recorded outcome"
        );

        let record = state
            .current_incident_store()
            .load_by_incident_id(&minted.incident_id)
            .unwrap()
            .unwrap()
            .record;
        assert_eq!(
            record.feedback_audit_entries.len(),
            1,
            "an append guarded by the deterministic id"
        );
        let entry = &record.feedback_audit_entries[0];
        assert_eq!(entry.request_signature, "operator-bearer:ops-alice");
        assert_eq!(entry.analyst_id, "ops-alice");
        assert_eq!(entry.received_at_ms, 10);
        assert_eq!(entry.finding_id.as_deref(), Some("f-1"));
        assert!(entry.evidence.is_some());
        assert!(entry.payload.get("analyst_id").is_none());
        assert_eq!(record.false_positive_measurements.len(), 1);
        let measurement = &record.false_positive_measurements[0];
        assert_eq!(measurement.analyst_id, "ops-alice");
        assert_eq!(measurement.strategy_id, "suspicious_process_tree");
        assert_eq!(measurement.host_id.as_deref(), Some("host-ops-1"));
        assert_eq!(measurement.reviewed_at_ms, 10);
        assert!(measurement.false_positive);
    }

    #[tokio::test]
    async fn confirm_and_investigate_move_the_denominator_without_a_false_positive() {
        let state = test_state();
        let minted = mint_incident(&state, mint_request("f-2", Some("h")), 1).unwrap();
        // `investigate` re-queues the hunt's replay bundle, so one must exist.
        seed_replay_bundle(&state, "hunt-evt-1", "f-2", "h");
        for (action, verdict) in [
            (ProvidenceFeedbackAction::Confirm, "01"),
            (ProvidenceFeedbackAction::Investigate, "02"),
        ] {
            let out = record_finding_feedback(
                &state,
                "ops",
                "f-2",
                FindingFeedbackRequest {
                    action,
                    incident_id: minted.incident_id.clone(),
                    verdict_event_id: verdict.repeat(32),
                    reason: None,
                },
                5,
            )
            .await
            .unwrap();
            assert!(!out.false_positive);
            assert!(!out.replayed);
            assert_eq!(out.action, action);
        }
        let record = state
            .current_incident_store()
            .load_by_incident_id(&minted.incident_id)
            .unwrap()
            .unwrap()
            .record;
        assert_eq!(
            record.false_positive_measurements.len(),
            1,
            "upsert replaces by finding_id"
        );
        assert_eq!(
            record.false_positive_measurements[0].action,
            ProvidenceFeedbackAction::Investigate
        );
        assert!(!record.false_positive_measurements[0].false_positive);
        assert_eq!(record.feedback_audit_entries.len(), 2);
    }

    #[tokio::test]
    async fn feedback_on_an_unknown_incident_or_finding_is_the_not_yet_correlated_wall() {
        let state = test_state();
        let missing = record_finding_feedback(
            &state,
            "ops",
            "f-9",
            FindingFeedbackRequest {
                action: ProvidenceFeedbackAction::Dismiss,
                incident_id: "incident:perch-case:nope".into(),
                verdict_event_id: "ee".repeat(32),
                reason: None,
            },
            1,
        )
        .await;
        assert!(
            matches!(&missing, Err(PerchOpsError::NotFound(message)) if message.contains("incident:perch-case:nope")),
            "{missing:?}"
        );
        let minted = mint_incident(&state, mint_request("f-3", Some("h")), 1).unwrap();
        let wrong_member = record_finding_feedback(
            &state,
            "ops",
            "f-not-a-member",
            FindingFeedbackRequest {
                action: ProvidenceFeedbackAction::Dismiss,
                incident_id: minted.incident_id.clone(),
                verdict_event_id: "ff".repeat(32),
                reason: None,
            },
            1,
        )
        .await;
        assert!(
            matches!(&wrong_member, Err(PerchOpsError::NotFound(message)) if message.contains("f-not-a-member")),
            "{wrong_member:?}"
        );
        let record = state
            .current_incident_store()
            .load_by_incident_id(&minted.incident_id)
            .unwrap()
            .unwrap()
            .record;
        assert!(record.feedback_audit_entries.is_empty());
        assert!(record.false_positive_measurements.is_empty());
    }

    #[tokio::test]
    async fn a_malformed_verdict_event_id_is_refused_before_any_lookup() {
        let state = test_state();
        for bad in [
            "",
            "ab",
            &"AB".repeat(32),
            &"zz".repeat(32),
            &"ab".repeat(33),
        ] {
            let out = record_finding_feedback(
                &state,
                "ops",
                "f-1",
                FindingFeedbackRequest {
                    action: ProvidenceFeedbackAction::Dismiss,
                    incident_id: "incident:perch-case:nope".into(),
                    verdict_event_id: bad.to_string(),
                    reason: None,
                },
                1,
            )
            .await;
            assert!(
                matches!(out, Err(PerchOpsError::BadRequest(_))),
                "{bad:?} must be a bad request, not a lookup"
            );
        }
    }

    #[test]
    fn the_request_body_carries_no_analyst_id() {
        // C6: the body type cannot carry one; the principal is the analyst.
        let mut value = serde_json::json!({
            "action": "dismiss",
            "incident_id": "incident:perch-case:x",
            "verdict_event_id": "ab".repeat(32),
            "reason": null
        });
        assert!(serde_json::from_value::<FindingFeedbackRequest>(value.clone()).is_ok());
        value["analyst_id"] = serde_json::json!("mallory");
        assert!(serde_json::from_value::<FindingFeedbackRequest>(value).is_err());
    }
}
