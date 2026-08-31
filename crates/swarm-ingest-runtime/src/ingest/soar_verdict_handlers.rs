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
use swarm_spine::{
    AnalystFeedbackAuditEntry, IncidentStore, SoarVerdictClaimLease, SoarVerdictClaimResult,
};
use uuid::Uuid;

pub(crate) const SOAR_VERDICT_CHANNEL: &str = "soar_verdict_webhook";
const SOAR_VERDICT_CLAIM_LEASE_MS: i64 = 30_000;

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
    if let Err(error) = validate_soar_verdict_request(&request) {
        persist_rejected_soar_verdict(
            &state,
            &lookup.incident,
            &request,
            signature.clone(),
            payload_value.clone(),
            Some(verdict_lineage.clone()),
            &error.error,
        )
        .await?;
        return Err(error);
    }

    let feedback_id = soar_feedback_id(request.source_system, &request.source_verdict_id)?;
    let normalized = SwarmProvidenceFeedbackRequest {
        action: request.action,
        incident_id: request.incident_id.clone(),
        finding_id: request.finding_id.clone(),
        analyst_id: request.analyst_id.clone(),
        reason: request.reason.clone(),
    };
    let prior_claim = state
        .current_incident_store()
        .load_soar_verdict_claim(request.source_system, &request.source_verdict_id)
        .map_err(|error| ProvidenceFeedbackError::internal(error.to_string()))?;
    let prior_target = prior_claim
        .as_ref()
        .and_then(|entry| claimed_feedback_target(entry).ok());
    let current_target = || {
        let target = resolve_feedback_target(&lookup, request.finding_id.as_deref())
            .map_err(ProvidenceFeedbackError::not_found)?;
        enrich_feedback_target(&state, &lookup, &target)
    };
    let claim_target = match prior_target {
        Some(target) => Some(target),
        None => match current_target() {
            Ok(target) => Some(target),
            Err(_) if prior_claim.is_some() => None,
            Err(error) => return Err(error),
        },
    };
    let claim_outcome = claim_target.as_ref().map_or_else(
        || json!({"status": "applying"}),
        |target| json!({"status": "applying", "target": target}),
    );
    let claim_observed_at_ms = now_ms();
    let claimed = AnalystFeedbackAuditEntry {
        feedback_id: feedback_id.clone(),
        received_at_ms: claim_observed_at_ms,
        action: request.action,
        analyst_id: request.analyst_id.clone(),
        incident_id: request.incident_id.clone(),
        // Request identity retains the caller's exact optional field. The
        // resolved finding is frozen separately in the target snapshot below.
        finding_id: request.finding_id.clone(),
        reason: request.reason.clone(),
        request_signature: signature.clone(),
        evidence: None,
        soar_lineage: Some(verdict_lineage.clone()),
        payload: payload_value.clone(),
        outcome: claim_outcome,
        soar_claim_lease: Some(SoarVerdictClaimLease {
            token: Uuid::new_v4().to_string(),
            expires_at_ms: claim_observed_at_ms
                .checked_add(SOAR_VERDICT_CLAIM_LEASE_MS)
                .ok_or_else(|| {
                    ProvidenceFeedbackError::internal("SOAR claim lease timestamp overflow")
                })?,
        }),
    };
    let claim = state
        .current_incident_store()
        .claim_soar_verdict(&request.incident_id, claimed)
        .map_err(|error| ProvidenceFeedbackError::internal(error.to_string()))?
        .ok_or_else(|| {
            ProvidenceFeedbackError::not_found(format!(
                "incident `{}` disappeared before the SOAR verdict was claimed",
                request.incident_id
            ))
        })?;
    let claimed_entry = match claim {
        SoarVerdictClaimResult::Claimed(entry) => entry,
        SoarVerdictClaimResult::CompletedExact(entry) => {
            return completed_soar_verdict_response(entry);
        }
        SoarVerdictClaimResult::PendingExact(entry) => {
            return wait_for_soar_verdict_completion(
                &state,
                &request.incident_id,
                &entry.feedback_id,
            )
            .await;
        }
        SoarVerdictClaimResult::Conflict => {
            return Err(ProvidenceFeedbackError {
                status: StatusCode::CONFLICT,
                error: format!(
                    "source verdict `{}` from `{}` conflicts with its durable claim",
                    request.source_verdict_id,
                    soar_source_slug(request.source_system)
                ),
            });
        }
    };
    let received_at_ms = claimed_entry.received_at_ms;
    let target = claimed_feedback_target(&claimed_entry)?;
    let claim_lease = claimed_entry.soar_claim_lease.clone();
    let applied =
        apply_providence_feedback(&state, &normalized, &target, &feedback_id, received_at_ms)
            .await?;

    let audit_entry = AnalystFeedbackAuditEntry {
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
        soar_claim_lease: claim_lease,
    };
    let mut measurement =
        false_positive_measurement(&normalized, &target, &feedback_id, received_at_ms);
    measurement.soar_lineage = Some(verdict_lineage.clone());
    state
        .current_incident_store()
        .record_feedback_outcome(&request.incident_id, audit_entry, measurement)
        .map_err(|error| ProvidenceFeedbackError::internal(error.to_string()))?
        .ok_or_else(|| {
            ProvidenceFeedbackError::not_found(format!(
                "incident `{}` disappeared before the SOAR verdict was recorded",
                request.incident_id
            ))
        })?;

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

fn soar_feedback_id(
    source_system: SoarSourceSystem,
    source_verdict_id: &str,
) -> Result<String, ProvidenceFeedbackError> {
    let identity = serde_json::to_vec(&(
        "swarm-soar-feedback-id-v1",
        source_system,
        source_verdict_id,
    ))
    .map_err(|error| ProvidenceFeedbackError::internal(error.to_string()))?;
    Ok(format!(
        "soar-verdict:{}:{}",
        soar_source_slug(source_system),
        swarm_crypto::sha256_hex(&identity)
    ))
}

fn claimed_feedback_target(
    entry: &AnalystFeedbackAuditEntry,
) -> Result<swarm_runtime::providence::ProvidenceFeedbackTarget, ProvidenceFeedbackError> {
    let target = entry.outcome.get("target").cloned().ok_or_else(|| {
        ProvidenceFeedbackError::internal(
            "claimed SOAR verdict is missing its immutable feedback target",
        )
    })?;
    serde_json::from_value(target)
        .map_err(|error| ProvidenceFeedbackError::internal(error.to_string()))
}

fn completed_soar_verdict_response(
    entry: AnalystFeedbackAuditEntry,
) -> Result<Response, ProvidenceFeedbackError> {
    let lineage = entry.soar_lineage.ok_or_else(|| {
        ProvidenceFeedbackError::internal("completed SOAR verdict is missing source lineage")
    })?;
    if entry.evidence.is_none() {
        return Err(ProvidenceFeedbackError::internal(
            "completed SOAR verdict is missing signed evidence",
        ));
    }
    Ok((
        StatusCode::OK,
        ResponseJson(SoarVerdictResponse {
            feedback_id: entry.feedback_id,
            incident_id: entry.incident_id,
            finding_id: entry.finding_id,
            source_system: lineage.source_system,
            source_verdict_id: lineage.source_verdict_id,
            outcome: entry.outcome,
        }),
    )
        .into_response())
}

async fn wait_for_soar_verdict_completion(
    state: &IngestState,
    incident_id: &str,
    feedback_id: &str,
) -> Result<Response, ProvidenceFeedbackError> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let lookup = state
            .current_incident_store()
            .load_by_incident_id(incident_id)
            .map_err(|error| ProvidenceFeedbackError::internal(error.to_string()))?
            .ok_or_else(|| {
                ProvidenceFeedbackError::not_found(format!(
                    "incident `{incident_id}` disappeared while its SOAR verdict was in progress"
                ))
            })?;
        if let Some(entry) = lookup
            .incident
            .feedback_audit_entries
            .into_iter()
            .find(|entry| entry.feedback_id == feedback_id)
            && entry.evidence.is_some()
        {
            return completed_soar_verdict_response(entry);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(ProvidenceFeedbackError::service_unavailable(format!(
                "source verdict claim `{feedback_id}` remains in progress"
            )));
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
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

async fn persist_rejected_soar_verdict(
    state: &IngestState,
    incident: &swarm_spine::CorrelatedIncident,
    request: &SwarmSoarVerdictRequest,
    signature: String,
    payload: Value,
    verdict_lineage: Option<SoarVerdictLineage>,
    reason: &str,
) -> Result<(), ProvidenceFeedbackError> {
    let received_at_ms = state
        .next_providence_feedback_timestamp_ms()
        .await
        .map_err(ProvidenceFeedbackError::internal)?;
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
            soar_claim_lease: None,
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

#[cfg(test)]
mod tests {
    use super::soar_feedback_id;
    use swarm_core::types::SoarSourceSystem;

    #[test]
    fn feedback_ids_do_not_collide_when_sanitized_source_ids_would()
    -> Result<(), super::ProvidenceFeedbackError> {
        let slash = soar_feedback_id(SoarSourceSystem::SplunkSoar, "case/a")?;
        let question = soar_feedback_id(SoarSourceSystem::SplunkSoar, "case?a")?;
        assert_ne!(slash, question);
        assert_eq!(slash.len(), question.len());
        Ok(())
    }
}
