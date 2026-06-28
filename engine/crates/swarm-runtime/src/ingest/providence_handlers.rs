use crate::bridge_runtime::bridge_health_report;
use crate::kitten_agent::route_feedback_signal;
use crate::providence::{
    PROVIDENCE_CHANNEL, ProvidenceContextScope, ProvidenceFeedbackTarget,
    apply_providence_callback_reconciliation, build_providence_reconciliation,
    build_scoped_providence_links, resolve_callback_incident, resolve_feedback_target,
};
use crate::runtime_events::now_ms;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json as ResponseJson;
use axum::response::{IntoResponse, Response};
use ed25519_dalek::Signer;
use serde::Serialize;
use serde_json::{Value, json};
use swarm_core::agent::{AgentRole, SwarmMode, SwarmModeState};
use swarm_core::config::OperatorSurfaceConfig;
use swarm_core::pheromone::PheromoneDeposit;
use swarm_core::types::{
    AgentId, ProvidenceCreateIncidentBody, ProvidenceFeedbackAction, ProvidenceFeedbackEvidence,
    ProvidenceIncidentReconciliation, ProvidenceIncidentStatus, SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
    SWARM_PROVIDENCE_FEEDBACK_SCHEMA_VERSION, SWARM_PROVIDENCE_WEBHOOK_SCHEMA,
    SWARM_PROVIDENCE_WEBHOOK_SCHEMA_VERSION, Severity, SwarmAction, SwarmFeedbackSignal,
    SwarmProvidenceAggregateContext, SwarmProvidenceCallbackRequest,
    SwarmProvidenceFeedbackRequest, SwarmProvidenceFindingContext, SwarmProvidenceLinks,
    SwarmProvidenceRuntimeBridgeHealth, SwarmProvidenceRuntimeContext,
    SwarmProvidenceWebhookContract,
};
use swarm_crypto::{canonical_json_bytes, hmac_sha256_hex};
use swarm_pheromone::{DepositSigningPayload, PheromoneSubstrate};
use swarm_response::notification::AggregatedNotification;
use swarm_spine::{
    AnalystFeedbackAuditEntry, FalsePositiveMeasurement, IncidentLookup, IncidentStore,
    ReplayBundleStore,
};

use super::IngestState;
use super::health::active_agent_counts;

#[derive(Debug)]
pub(super) struct ProvidenceFeedbackError {
    pub(super) status: StatusCode,
    pub(super) error: String,
}

impl ProvidenceFeedbackError {
    pub(super) fn bad_request(error: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: error.into(),
        }
    }

    pub(super) fn unauthorized(error: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error: error.into(),
        }
    }

    pub(super) fn not_found(error: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            error: error.into(),
        }
    }

    pub(super) fn internal(error: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: error.into(),
        }
    }

    pub(super) fn service_unavailable(error: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            error: error.into(),
        }
    }
}

impl IntoResponse for ProvidenceFeedbackError {
    fn into_response(self) -> Response {
        (
            self.status,
            ResponseJson(json!({
                "error": self.error,
            })),
        )
            .into_response()
    }
}

#[derive(Debug, Serialize)]
pub(super) struct ProvidenceFeedbackResponse {
    pub(super) feedback_id: String,
    pub(super) action: ProvidenceFeedbackAction,
    pub(super) incident_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) finding_id: Option<String>,
    pub(super) outcome: Value,
}

#[derive(Debug, Serialize)]
pub(super) struct ProvidenceCallbackResponse {
    pub(super) callback_id: String,
    pub(super) incident_id: String,
    pub(super) reconciliation: ProvidenceIncidentReconciliation,
}

#[derive(Debug)]
struct ProvidenceFeedbackApplicationResult {
    outcome: Value,
    evidence: ProvidenceFeedbackEvidence,
}

pub(crate) async fn providence_feedback_handler(
    State(state): State<IngestState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<Response, ProvidenceFeedbackError> {
    let channel = providence_feedback_channel(&state)?;
    let signature = verify_providence_feedback_signature(&channel, &headers, &body)?;
    let payload_value = serde_json::from_slice::<Value>(&body)
        .map_err(|error| ProvidenceFeedbackError::bad_request(error.to_string()))?;
    let request = serde_json::from_value::<SwarmProvidenceFeedbackRequest>(payload_value.clone())
        .map_err(|error| ProvidenceFeedbackError::bad_request(error.to_string()))?;
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
    let target = resolve_feedback_target(&lookup, request.finding_id.as_deref())
        .map_err(ProvidenceFeedbackError::not_found)?;
    let target = enrich_feedback_target(&state, &lookup, &target)?;
    let received_at_ms = now_ms();
    let feedback_id = format!(
        "providence-feedback:{}:{}",
        super::sanitize_id(&request.incident_id),
        received_at_ms
    );
    let applied =
        apply_providence_feedback(&state, &request, &target, &feedback_id, received_at_ms).await?;
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
        payload: payload_value,
        outcome: applied.outcome.clone(),
    };
    let mut incident = lookup.incident.clone();
    incident.feedback_audit_entries.push(audit_entry);
    incident.upsert_false_positive_measurement(false_positive_measurement(
        &request,
        &target,
        &feedback_id,
        received_at_ms,
    ));
    state
        .current_incident_store()
        .persist(&incident)
        .map_err(|error| ProvidenceFeedbackError::internal(error.to_string()))?;

    Ok((
        StatusCode::OK,
        ResponseJson(ProvidenceFeedbackResponse {
            feedback_id,
            action: request.action,
            incident_id: request.incident_id.clone(),
            finding_id: request.finding_id.clone().or(Some(target.finding_id)),
            outcome: applied.outcome,
        }),
    )
        .into_response())
}

pub(crate) async fn providence_callback_handler(
    State(state): State<IngestState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<Response, ProvidenceFeedbackError> {
    let channel = providence_feedback_channel(&state)?;
    let signature = verify_providence_feedback_signature(&channel, &headers, &body)?;
    let payload_value = serde_json::from_slice::<Value>(&body)
        .map_err(|error| ProvidenceFeedbackError::bad_request(error.to_string()))?;
    let request = serde_json::from_value::<SwarmProvidenceCallbackRequest>(payload_value.clone())
        .map_err(|error| ProvidenceFeedbackError::bad_request(error.to_string()))?;
    let lookup = resolve_callback_incident(&state.current_incident_store(), &request)
        .map_err(ProvidenceFeedbackError::not_found)?;
    let received_at_ms = now_ms();
    let reconciliation = build_providence_reconciliation(
        &lookup.record,
        &state.current_mode_state(),
        &request,
        received_at_ms,
    );
    let mut incident = lookup.incident.clone();
    apply_providence_callback_reconciliation(
        &mut incident,
        &request,
        signature,
        payload_value,
        reconciliation.clone(),
        received_at_ms,
    );
    state
        .current_incident_store()
        .persist(&incident)
        .map_err(|error| ProvidenceFeedbackError::internal(error.to_string()))?;

    Ok((
        StatusCode::OK,
        ResponseJson(ProvidenceCallbackResponse {
            callback_id: format!(
                "providence-callback:{}:{received_at_ms}",
                super::sanitize_id(&incident.incident_id)
            ),
            incident_id: incident.incident_id,
            reconciliation,
        }),
    )
        .into_response())
}

pub(super) fn providence_feedback_channel(
    state: &IngestState,
) -> Result<swarm_core::config::NotificationChannelConfig, ProvidenceFeedbackError> {
    let stack = state.stack.load_full();
    stack
        .service
        .config
        .notification_channels
        .get(PROVIDENCE_CHANNEL)
        .cloned()
        .ok_or_else(|| {
            ProvidenceFeedbackError::service_unavailable(
                "Providence signed ingress is unavailable because providence_webhook is not configured",
            )
        })
}

pub(super) fn verify_providence_feedback_signature(
    channel: &swarm_core::config::NotificationChannelConfig,
    headers: &axum::http::HeaderMap,
    body: &[u8],
) -> Result<String, ProvidenceFeedbackError> {
    let signature = channel.request_signature.as_ref().ok_or_else(|| {
        ProvidenceFeedbackError::service_unavailable(
            "Providence feedback requires notification_channels.providence_webhook.request_signature",
        )
    })?;
    let provided = headers
        .get(signature.header.as_str())
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ProvidenceFeedbackError::unauthorized(format!("missing {} header", signature.header))
        })?
        .to_string();
    let payload = serde_json::from_slice::<Value>(body)
        .map_err(|error| ProvidenceFeedbackError::bad_request(error.to_string()))?;
    let canonical = canonical_json_bytes(&payload)
        .map_err(|error| ProvidenceFeedbackError::bad_request(error.to_string()))?;
    let expected = format!(
        "sha256={}",
        hmac_sha256_hex(signature.secret.as_bytes(), &canonical)
    );
    if provided != expected {
        return Err(ProvidenceFeedbackError::unauthorized(
            "invalid Providence signature",
        ));
    }
    Ok(provided)
}

async fn apply_providence_feedback(
    state: &IngestState,
    request: &SwarmProvidenceFeedbackRequest,
    target: &ProvidenceFeedbackTarget,
    feedback_id: &str,
    recorded_at_ms: i64,
) -> Result<ProvidenceFeedbackApplicationResult, ProvidenceFeedbackError> {
    let memory_disposition = feedback_memory_disposition(state);
    match request.action {
        ProvidenceFeedbackAction::Confirm => {
            let deposit = signed_providence_feedback_deposit(
                state,
                request,
                target,
                feedback_id,
                recorded_at_ms,
                1.0,
                Some("confirm"),
            )
            .await?;
            let evidence = providence_feedback_evidence(&deposit);
            state
                .current_substrate()
                .deposit(deposit)
                .await
                .map_err(|error| ProvidenceFeedbackError::internal(error.to_string()))?;
            Ok(ProvidenceFeedbackApplicationResult {
                outcome: json!({
                    "substrate": {
                        "status": "boosted",
                        "event_id": target.event_id,
                        "threat_class": target.threat_class,
                    },
                    "memory": {
                        "disposition": memory_disposition,
                        "feedback_id": feedback_id,
                    }
                }),
                evidence,
            })
        }
        ProvidenceFeedbackAction::Dismiss => {
            let deposit = signed_providence_feedback_deposit(
                state,
                request,
                target,
                feedback_id,
                recorded_at_ms,
                0.0,
                Some("dismiss"),
            )
            .await?;
            let evidence = providence_feedback_evidence(&deposit);
            state
                .current_substrate()
                .deposit(deposit)
                .await
                .map_err(|error| ProvidenceFeedbackError::internal(error.to_string()))?;
            let signal = SwarmFeedbackSignal {
                action: request.action,
                incident_id: request.incident_id.clone(),
                finding_id: request
                    .finding_id
                    .clone()
                    .or(Some(target.finding_id.clone())),
                strategy_id: target.strategy_id.clone(),
                threat_class: Some(target.threat_class.clone()),
                analyst_id: request.analyst_id.clone(),
                reason: request.reason.clone(),
                recorded_at_ms,
            };
            let _feedback_action = SwarmAction::FeedbackSignal {
                signal: signal.clone(),
            };
            let kitten = route_feedback_signal(
                state.config_path(),
                &state.stack.load_full().service.config,
                state
                    .current_agent_health()
                    .iter()
                    .any(|entry| entry.role == AgentRole::Kitten),
                &signal,
            )
            .map_err(ProvidenceFeedbackError::internal)?;
            Ok(ProvidenceFeedbackApplicationResult {
                outcome: json!({
                    "substrate": {
                        "status": "suppressed",
                        "event_id": target.event_id,
                        "finding_id": target.finding_id,
                        "schema": SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
                        "schema_version": SWARM_PROVIDENCE_FEEDBACK_SCHEMA_VERSION,
                        "false_positive": true,
                    },
                    "memory": {
                        "disposition": memory_disposition,
                        "feedback_id": feedback_id,
                    },
                    "kitten": {
                        "disposition": kitten.disposition,
                        "penalty_applied": kitten.penalty_applied,
                        "details": kitten.details,
                    },
                    "swarm_action_kind": "feedback_signal",
                }),
                evidence,
            })
        }
        ProvidenceFeedbackAction::Investigate => {
            let deposit = signed_providence_feedback_deposit(
                state,
                request,
                target,
                feedback_id,
                recorded_at_ms,
                0.0,
                Some("investigate"),
            )
            .await?;
            let evidence = providence_feedback_evidence(&deposit);
            state
                .current_substrate()
                .deposit(deposit)
                .await
                .map_err(|error| ProvidenceFeedbackError::internal(error.to_string()))?;
            let replay = state
                .current_replay_store()
                .load_by_hunt_id(&target.hunt_id)
                .map_err(|error| ProvidenceFeedbackError::internal(error.to_string()))?
                .ok_or_else(|| {
                    ProvidenceFeedbackError::not_found(format!(
                        "replay bundle for hunt `{}` was not found",
                        target.hunt_id
                    ))
                })?;
            let submitted = state
                .current_investigation()
                .submit(&replay.bundle)
                .map_err(|error| ProvidenceFeedbackError::internal(error.to_string()))?;
            Ok(ProvidenceFeedbackApplicationResult {
                outcome: json!({
                    "substrate": {
                        "status": "investigate_requested",
                        "event_id": target.event_id,
                    },
                    "memory": {
                        "disposition": memory_disposition,
                        "feedback_id": feedback_id,
                    },
                    "investigation": {
                        "queued": submitted.is_some(),
                        "investigation_id": submitted.as_ref().map(|record| record.investigation_id.clone()),
                        "status": submitted.as_ref().map(|record| record.status),
                        "hunt_id": target.hunt_id,
                    }
                }),
                evidence,
            })
        }
    }
}

fn enrich_feedback_target(
    state: &IngestState,
    _lookup: &IncidentLookup,
    target: &ProvidenceFeedbackTarget,
) -> Result<ProvidenceFeedbackTarget, ProvidenceFeedbackError> {
    let mut enriched = target.clone();
    if let Some(replay) = state
        .current_replay_store()
        .load_by_hunt_id(&target.hunt_id)
        .map_err(|error| ProvidenceFeedbackError::internal(error.to_string()))?
    {
        enriched.host_id = replay.bundle.event.host_id.clone().or(enriched.host_id);
        enriched.strategy_id = Some(replay.bundle.audit.detection.strategy_id.clone());
    }
    Ok(enriched)
}

fn false_positive_measurement(
    request: &SwarmProvidenceFeedbackRequest,
    target: &ProvidenceFeedbackTarget,
    feedback_id: &str,
    reviewed_at_ms: i64,
) -> FalsePositiveMeasurement {
    FalsePositiveMeasurement {
        finding_id: target.finding_id.clone(),
        hunt_id: target.hunt_id.clone(),
        strategy_id: target
            .strategy_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        host_id: target.host_id.clone(),
        feedback_id: feedback_id.to_string(),
        reviewed_at_ms,
        analyst_id: request.analyst_id.clone(),
        action: request.action,
        reason: request.reason.clone(),
        false_positive: matches!(request.action, ProvidenceFeedbackAction::Dismiss),
    }
}

async fn signed_providence_feedback_deposit(
    state: &IngestState,
    request: &SwarmProvidenceFeedbackRequest,
    target: &ProvidenceFeedbackTarget,
    feedback_id: &str,
    recorded_at_ms: i64,
    confidence: f64,
    status: Option<&str>,
) -> Result<PheromoneDeposit, ProvidenceFeedbackError> {
    let substrate = state.current_substrate();
    let pheromone_config = state.current_pheromone_config();
    let threat_class_config = substrate
        .query_threat_class_config(&target.threat_class)
        .await
        .map_err(|error| ProvidenceFeedbackError::internal(error.to_string()))?;
    let policy = pheromone_config.resolve_threat_class_policy(threat_class_config.as_ref());
    let mut deposit = PheromoneDeposit {
        schema_version: PheromoneDeposit::current_schema_version(),
        indicator: json!({
            "schema": SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
            "schema_version": SWARM_PROVIDENCE_FEEDBACK_SCHEMA_VERSION,
            "feedback_id": feedback_id,
            "action": request.action,
            "status": status,
            "incident_id": request.incident_id,
            "finding_id": target.finding_id,
            "event_id": target.event_id,
            "hunt_id": target.hunt_id,
            "host_id": target.host_id,
            "strategy_id": target.strategy_id,
            "analyst_id": request.analyst_id,
            "reason": request.reason,
            "observed_at_ms": recorded_at_ms,
        }),
        threat_class: target.threat_class.clone(),
        severity: target.severity,
        confidence,
        timestamp: recorded_at_ms,
        decay_half_life: policy.half_life_secs,
        agent_id: AgentId::from_verifying_key(&state.signing_key.verifying_key()),
        agent_identity: AgentId::from_verifying_key(&state.signing_key.verifying_key()).0,
        agent_role: None,
        signature: Vec::new(),
        agent_key: Vec::new(),
    };
    let payload = DepositSigningPayload {
        schema_version: deposit.schema_version,
        indicator: &deposit.indicator,
        threat_class: &deposit.threat_class,
        severity: &deposit.severity,
        confidence: deposit.confidence,
        timestamp: deposit.timestamp,
        decay_half_life: deposit.decay_half_life,
        agent_id: &deposit.agent_id,
        agent_identity: &deposit.agent_identity,
        agent_role: deposit.agent_role,
    };
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|error| ProvidenceFeedbackError::internal(error.to_string()))?;
    let signature = state.signing_key.sign(&payload_bytes);
    deposit.signature = signature.to_bytes().to_vec();
    deposit.agent_key = state.signing_key.verifying_key().to_bytes().to_vec();
    Ok(deposit)
}

fn providence_feedback_evidence(deposit: &PheromoneDeposit) -> ProvidenceFeedbackEvidence {
    ProvidenceFeedbackEvidence {
        schema: SWARM_PROVIDENCE_FEEDBACK_SCHEMA.to_string(),
        schema_version: SWARM_PROVIDENCE_FEEDBACK_SCHEMA_VERSION,
        threat_class: deposit.threat_class.clone(),
        agent_id: deposit.agent_id.to_string(),
        signed_at_ms: deposit
            .indicator
            .get("observed_at_ms")
            .and_then(Value::as_i64)
            .unwrap_or(deposit.timestamp),
        signature_hex: hex::encode(&deposit.signature),
    }
}

fn feedback_memory_disposition(state: &IngestState) -> &'static str {
    if state
        .current_agent_health()
        .iter()
        .any(|entry| entry.role == AgentRole::Sphinx)
    {
        "queued"
    } else {
        "audit_only"
    }
}

pub(super) fn build_providence_notification_payload(
    aggregate: &AggregatedNotification,
    operator: &OperatorSurfaceConfig,
    agent_health: Option<
        &std::sync::Arc<arc_swap::ArcSwap<Vec<swarm_core::agent::AgentHealthEntry>>>,
    >,
    mode_state: Option<&std::sync::Arc<arc_swap::ArcSwap<SwarmModeState>>>,
    bridge_health: Option<&crate::bridge_runtime::SharedBridgeHealth>,
) -> Value {
    let threat_class = super::threat_class_slug(&aggregate.threat_class);
    let mode_state = mode_state
        .map(|state| state.load_full().as_ref().clone())
        .unwrap_or_default();
    let agent_health = agent_health
        .map(|health| health.load_full().as_ref().clone())
        .unwrap_or_default();
    let bridge_health = bridge_health.map(bridge_health_report).unwrap_or_default();
    let (active_agent_count, degraded_agent_count, failed_agent_count) =
        active_agent_counts(&agent_health);
    let hunt_id = aggregate.sample_finding.event_id.clone();
    let incident_key = format!(
        "{}:{}:{}",
        &aggregate.strategy_id, threat_class, &aggregate.sample_finding.finding_id,
    );
    let links = build_scoped_providence_links(
        operator,
        ProvidenceContextScope {
            incident_id: None,
            hunt_id: Some(hunt_id.clone()),
            finding_id: Some(aggregate.sample_finding.finding_id.clone()),
            strategy_id: Some(aggregate.strategy_id.clone()),
            threat_class: Some(aggregate.threat_class.clone()),
        },
    );
    let contract = SwarmProvidenceWebhookContract {
        schema: SWARM_PROVIDENCE_WEBHOOK_SCHEMA.to_string(),
        schema_version: SWARM_PROVIDENCE_WEBHOOK_SCHEMA_VERSION,
        channel: aggregate.channel.clone(),
        incident_key: incident_key.clone(),
        create_incident: ProvidenceCreateIncidentBody {
            title: format!("{threat_class} detection from {}", &aggregate.strategy_id),
            severity: aggregate.highest_severity,
            status: ProvidenceIncidentStatus::Open,
            source: "swarm-team-six".to_string(),
            description: build_providence_incident_description(
                aggregate,
                &incident_key,
                &links,
                mode_state.current,
                agent_health.len(),
                active_agent_count,
                degraded_agent_count,
                failed_agent_count,
                bridge_health.status(),
            ),
        },
        finding: SwarmProvidenceFindingContext {
            schema: aggregate.sample_finding.schema.clone(),
            finding_id: aggregate.sample_finding.finding_id.clone(),
            event_id: aggregate.sample_finding.event_id.clone(),
            strategy_id: aggregate.sample_finding.strategy_id.clone(),
            threat_class: aggregate.sample_finding.threat_class.clone(),
            severity: aggregate.sample_finding.severity,
            confidence: aggregate.sample_finding.confidence,
            evidence: aggregate.sample_finding.evidence.clone(),
        },
        aggregate: SwarmProvidenceAggregateContext {
            first_seen_ms: aggregate.first_seen_ms,
            last_seen_ms: aggregate.last_seen_ms,
            count: aggregate.count,
        },
        runtime: SwarmProvidenceRuntimeContext {
            mode: mode_state.current,
            registered_agent_count: agent_health.len(),
            active_agent_count,
            degraded_agent_count,
            failed_agent_count,
            bridge_health: SwarmProvidenceRuntimeBridgeHealth {
                status: bridge_health.status().to_string(),
                configured: bridge_health.configured,
                ok: bridge_health.ok,
                degraded: bridge_health.degraded,
                idle: bridge_health.idle,
                entries: bridge_health
                    .entries
                    .iter()
                    .map(|entry| {
                        json!({
                            "name": &entry.name,
                            "source_id": &entry.source_id,
                            "ready": entry.ready,
                            "status": entry.status(),
                            "events_processed": entry.events_processed,
                            "error_count": entry.error_count,
                            "lag_seconds": entry.lag_seconds,
                            "last_error": &entry.last_error,
                        })
                    })
                    .collect(),
            },
        },
        links,
    };

    serde_json::to_value(contract).unwrap_or_else(|error| {
        tracing::error!(reason = %error, "failed to serialize Providence webhook contract");
        json!({
            "schema": SWARM_PROVIDENCE_WEBHOOK_SCHEMA,
            "schema_version": SWARM_PROVIDENCE_WEBHOOK_SCHEMA_VERSION,
            "channel": &aggregate.channel,
            "serialization_error": error.to_string(),
        })
    })
}

#[allow(clippy::too_many_arguments)]
fn build_providence_incident_description(
    aggregate: &AggregatedNotification,
    incident_key: &str,
    links: &SwarmProvidenceLinks,
    mode: SwarmMode,
    registered_agent_count: usize,
    active_agent_count: usize,
    degraded_agent_count: usize,
    failed_agent_count: usize,
    bridge_health_status: &str,
) -> String {
    format!(
        "Swarm Team Six detected {threat_class} activity from strategy {strategy_id}.\n\
Incident Key: {incident_key}\n\
Severity: {severity}\n\
Confidence: {confidence:.2}\n\
Finding Count: {count}\n\
First Seen (ms): {first_seen_ms}\n\
Last Seen (ms): {last_seen_ms}\n\
Runtime Mode: {mode}\n\
Agents: active {active_agent_count}/{registered_agent_count}, degraded {degraded_agent_count}, failed {failed_agent_count}\n\
Bridge Health: {bridge_health_status}\n\
Dashboard: {dashboard}\n\
Finding Drilldown: {finding_drilldown}\n\
Replay Bundle: {replay_bundle}\n\
Audit Trail: {audit_trail}\n\
Incident View: {incident}\n\
Review Home: {review_home}",
        threat_class = super::threat_class_slug(&aggregate.threat_class),
        strategy_id = &aggregate.strategy_id,
        incident_key = incident_key,
        severity = severity_label(aggregate.highest_severity),
        confidence = aggregate.sample_finding.confidence,
        count = aggregate.count,
        first_seen_ms = aggregate.first_seen_ms,
        last_seen_ms = aggregate.last_seen_ms,
        mode = swarm_mode_label(mode),
        active_agent_count = active_agent_count,
        registered_agent_count = registered_agent_count,
        degraded_agent_count = degraded_agent_count,
        failed_agent_count = failed_agent_count,
        bridge_health_status = bridge_health_status,
        dashboard = links.dashboard,
        finding_drilldown = links.finding_drilldown,
        replay_bundle = links.replay_bundle,
        audit_trail = links.audit_trail,
        incident = links.incident,
        review_home = links.review_home,
    )
}

pub(super) fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    }
}

pub(super) fn swarm_mode_label(mode: SwarmMode) -> &'static str {
    match mode {
        SwarmMode::Normal => "normal",
        SwarmMode::Alert => "alert",
        SwarmMode::Incident => "incident",
    }
}

pub(super) fn publish_runtime_findings(
    state: &IngestState,
    event: &swarm_whisker::TelemetryEvent,
    findings: &[swarm_whisker::DetectionFinding],
) {
    for finding in findings {
        state.publish_runtime_event(crate::runtime_events::RuntimeEvent::Finding {
            emitted_at_ms: now_ms(),
            host_id: event.host_id.clone(),
            finding: swarm_response::SwarmFindingEnvelope::from(finding),
        });
    }
}
