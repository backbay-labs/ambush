use super::IngestState;
use crate::ingest::providence_handlers::{
    ProvidenceFeedbackError, apply_providence_feedback, enrich_feedback_target,
    false_positive_measurement, verify_providence_feedback_signature,
};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json as ResponseJson;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::{Value, json};
use swarm_core::types::{
    SoarSourceSystem, SoarVerdictLineage, SwarmProvidenceFeedbackRequest, SwarmSoarVerdictRequest,
};
use swarm_runtime::providence::resolve_feedback_target;
use swarm_runtime::runtime_events::now_ms;
use swarm_spine::{AnalystFeedbackAuditEntry, IncidentStore};

pub(crate) const SOAR_VERDICT_CHANNEL: &str = "soar_verdict_webhook";

#[derive(Debug, Serialize)]
pub(super) struct SoarVerdictResponse {
    pub(super) feedback_id: String,
    pub(super) incident_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) finding_id: Option<String>,
    pub(super) source_system: SoarSourceSystem,
    pub(super) source_verdict_id: String,
    pub(super) outcome: Value,
}

pub(crate) async fn soar_verdict_handler(
    State(state): State<IngestState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<Response, ProvidenceFeedbackError> {
    let channel = soar_verdict_channel(&state)?;
    let signature = verify_providence_feedback_signature(&channel, &headers, &body)?;
    let payload_value = serde_json::from_slice::<Value>(&body)
        .map_err(|error| ProvidenceFeedbackError::bad_request(error.to_string()))?;
    let request = serde_json::from_value::<SwarmSoarVerdictRequest>(payload_value.clone())
        .map_err(|error| ProvidenceFeedbackError::bad_request(error.to_string()))?;

    if request.incident_id.trim().is_empty() {
        return Err(ProvidenceFeedbackError::bad_request(
            "incident_id must not be empty",
        ));
    }

    let lookup = state
        .current_incident_store()
        .load_by_incident_id(&request.incident_id)
        .map_err(|error| ProvidenceFeedbackError::internal(error.to_string()))?
        .ok_or_else(|| {
            ProvidenceFeedbackError::not_found(format!(
                "incident `{}` was not found",
                request.incident_id
            ))
        })?;

    let verdict_lineage = SoarVerdictLineage {
        source_system: request.source_system,
        source_verdict_id: request.source_verdict_id.clone(),
        verdict_at_ms: request.verdict_at_ms,
        source_case_id: request.source_case_id.clone(),
        source_case_url: request.source_case_url.clone(),
    };
    validate_soar_verdict_request(&request).or_else(|error| {
        persist_rejected_soar_verdict(
            &state,
            &lookup.incident,
            &request,
            signature.clone(),
            payload_value.clone(),
            Some(verdict_lineage.clone()),
            &error.error,
        )?;
        Err(error)
    })?;

    if lookup.incident.feedback_audit_entries.iter().any(|entry| {
        entry.soar_lineage.as_ref().is_some_and(|lineage| {
            lineage.source_system == request.source_system
                && lineage.source_verdict_id == request.source_verdict_id
        })
    }) {
        persist_rejected_soar_verdict(
            &state,
            &lookup.incident,
            &request,
            signature,
            payload_value,
            Some(verdict_lineage),
            "duplicate source verdict",
        )?;
        return Err(ProvidenceFeedbackError {
            status: StatusCode::CONFLICT,
            error: format!(
                "source verdict `{}` from `{}` was already applied",
                request.source_verdict_id,
                soar_source_slug(request.source_system)
            ),
        });
    }

    let target = resolve_feedback_target(&lookup, request.finding_id.as_deref())
        .map_err(ProvidenceFeedbackError::not_found)?;
    let target = enrich_feedback_target(&state, &lookup, &target)?;
    let received_at_ms = now_ms();
    let feedback_id = format!(
        "soar-verdict:{}:{}:{}",
        soar_source_slug(request.source_system),
        super::sanitize_id(&request.source_verdict_id),
        received_at_ms
    );
    let normalized = SwarmProvidenceFeedbackRequest {
        action: request.action,
        incident_id: request.incident_id.clone(),
        finding_id: request.finding_id.clone(),
        analyst_id: request.analyst_id.clone(),
        reason: request.reason.clone(),
    };
    let applied =
        apply_providence_feedback(&state, &normalized, &target, &feedback_id, received_at_ms)
            .await?;

    let mut incident = lookup.incident.clone();
    incident
        .feedback_audit_entries
        .push(AnalystFeedbackAuditEntry {
            feedback_id: feedback_id.clone(),
            received_at_ms,
            action: request.action,
            analyst_id: request.analyst_id.clone(),
            incident_id: request.incident_id.clone(),
            finding_id: request
                .finding_id
                .clone()
                .or(Some(target.finding_id.clone())),
            reason: request.reason.clone(),
            request_signature: signature,
            evidence: Some(applied.evidence),
            soar_lineage: Some(verdict_lineage.clone()),
            payload: payload_value,
            outcome: applied.outcome.clone(),
        });
    let mut measurement =
        false_positive_measurement(&normalized, &target, &feedback_id, received_at_ms);
    measurement.soar_lineage = Some(verdict_lineage.clone());
    incident.upsert_false_positive_measurement(measurement);
    state
        .current_incident_store()
        .persist(&incident)
        .map_err(|error| ProvidenceFeedbackError::internal(error.to_string()))?;

    Ok((
        StatusCode::OK,
        ResponseJson(SoarVerdictResponse {
            feedback_id,
            incident_id: request.incident_id,
            finding_id: request.finding_id.or(Some(target.finding_id)),
            source_system: verdict_lineage.source_system,
            source_verdict_id: verdict_lineage.source_verdict_id,
            outcome: applied.outcome,
        }),
    )
        .into_response())
}

fn soar_verdict_channel(
    state: &IngestState,
) -> Result<swarm_core::config::NotificationChannelConfig, ProvidenceFeedbackError> {
    let stack = state.stack.load_full();
    stack
        .service
        .config
        .notification_channels
        .get(SOAR_VERDICT_CHANNEL)
        .cloned()
        .ok_or_else(|| {
            ProvidenceFeedbackError::service_unavailable(
                "SOAR signed ingress is unavailable because soar_verdict_webhook is not configured",
            )
        })
}

fn validate_soar_verdict_request(
    request: &SwarmSoarVerdictRequest,
) -> Result<(), ProvidenceFeedbackError> {
    if request.source_verdict_id.trim().is_empty() {
        return Err(ProvidenceFeedbackError::bad_request(
            "source_verdict_id must not be empty",
        ));
    }
    if request.analyst_id.trim().is_empty() {
        return Err(ProvidenceFeedbackError::bad_request(
            "analyst_id must not be empty",
        ));
    }
    if request.verdict_at_ms <= 0 {
        return Err(ProvidenceFeedbackError::bad_request(
            "verdict_at_ms must be a positive Unix timestamp in milliseconds",
        ));
    }
    Ok(())
}

fn persist_rejected_soar_verdict(
    state: &IngestState,
    incident: &swarm_spine::CorrelatedIncident,
    request: &SwarmSoarVerdictRequest,
    signature: String,
    payload: Value,
    verdict_lineage: Option<SoarVerdictLineage>,
    reason: &str,
) -> Result<(), ProvidenceFeedbackError> {
    let received_at_ms = now_ms();
    let feedback_id = format!(
        "soar-verdict-rejected:{}:{}:{}",
        soar_source_slug(request.source_system),
        super::sanitize_id(&request.source_verdict_id),
        received_at_ms
    );
    let mut rejected = incident.clone();
    rejected
        .feedback_audit_entries
        .push(AnalystFeedbackAuditEntry {
            feedback_id,
            received_at_ms,
            action: request.action,
            analyst_id: request.analyst_id.clone(),
            incident_id: request.incident_id.clone(),
            finding_id: request.finding_id.clone(),
            reason: request.reason.clone(),
            request_signature: signature,
            evidence: None,
            soar_lineage: verdict_lineage,
            payload,
            outcome: json!({
                "status": "rejected",
                "reason": reason,
            }),
        });
    state
        .current_incident_store()
        .persist(&rejected)
        .map_err(|error| ProvidenceFeedbackError::internal(error.to_string()))?;
    Ok(())
}

fn soar_source_slug(source_system: SoarSourceSystem) -> &'static str {
    match source_system {
        SoarSourceSystem::SplunkSoar => "splunk_soar",
        SoarSourceSystem::SentinelSoar => "sentinel_soar",
        SoarSourceSystem::ChronicleSoar => "chronicle_soar",
    }
}
