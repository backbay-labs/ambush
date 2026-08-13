use super::auth::{AuthenticatedOperatorPrincipal, require_operator_api_scope};
use super::error::{OperatorApiError, map_control_error};
use super::helpers::{
    effective_limit, now_ms, parse_incident_selector, parse_investigation_selector,
    parse_replay_selector,
};
use super::state::OperatorHttpState;
use axum::Json;
use axum::extract::{Extension, Path as RoutePath, Query, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use serde::Deserialize;
use swarm_core::config::OperatorScope;
use swarm_core::pheromone::{ThreatClassConfig, ThreatIntelEntry, ThreatIntelIndicatorType};
use swarm_ingest_runtime::control::{
    ControlEnvelope, IncidentArtifactView, InvestigationArtifactView, ReplayArtifactView,
};
use swarm_runtime::detection::metrics::encode_metrics;
use swarm_runtime::service::OperatorStatusReport;

#[derive(Debug, Deserialize)]
pub(super) struct ReplayLookupQuery {
    pub(super) bundle_id: Option<String>,
    pub(super) hunt_id: Option<String>,
    pub(super) receipt_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct InvestigationLookupQuery {
    pub(super) investigation_id: Option<String>,
    pub(super) hunt_id: Option<String>,
    pub(super) receipt_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct IncidentLookupQuery {
    pub(super) incident_id: Option<String>,
    pub(super) hunt_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ThreatIntelLookupQuery {
    indicator_type: ThreatIntelIndicatorType,
    value: String,
    now: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub(super) struct NotificationDeadLetterListQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(super) struct NotificationDeadLetterReplayRequest {
    receipt_ids: Option<Vec<String>>,
}

pub(super) async fn status_handler(
    State(state): State<OperatorHttpState>,
) -> Result<Json<ControlEnvelope<OperatorStatusReport>>, OperatorApiError> {
    let mut status = state.control.status().await.map_err(map_control_error)?;
    status.data.rate_limit = state.rate_limiter.status();
    Ok(Json(status))
}

pub(super) async fn threat_class_config_list_handler(
    State(state): State<OperatorHttpState>,
) -> Result<Json<ControlEnvelope<Vec<ThreatClassConfig>>>, OperatorApiError> {
    let configs = state
        .control
        .threat_class_configs()
        .await
        .map_err(map_control_error)?;
    Ok(Json(configs))
}

pub(super) async fn threat_class_config_upsert_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<OperatorHttpState>,
    Json(config): Json<ThreatClassConfig>,
) -> Result<Json<ControlEnvelope<ThreatClassConfig>>, OperatorApiError> {
    require_operator_api_scope(&principal, OperatorScope::Maintenance, "maintenance")?;
    let stored = state
        .control
        .store_threat_class_config(config)
        .await
        .map_err(map_control_error)?;
    Ok(Json(stored))
}

pub(super) async fn threat_intel_entry_lookup_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<ThreatIntelLookupQuery>,
) -> Result<Json<ControlEnvelope<Option<ThreatIntelEntry>>>, OperatorApiError> {
    if query.value.trim().is_empty() {
        return Err(OperatorApiError::bad_request(
            "threat-intel lookup requires a non-empty `value` query parameter",
        ));
    }
    let entry = state
        .control
        .query_threat_intel_entry(
            query.indicator_type,
            query.value,
            query.now.unwrap_or_else(now_ms),
        )
        .await
        .map_err(map_control_error)?;
    Ok(Json(entry))
}

pub(super) async fn threat_intel_entry_upsert_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<OperatorHttpState>,
    Json(entry): Json<ThreatIntelEntry>,
) -> Result<Json<ControlEnvelope<ThreatIntelEntry>>, OperatorApiError> {
    require_operator_api_scope(&principal, OperatorScope::Maintenance, "maintenance")?;
    if entry.value.trim().is_empty() {
        return Err(OperatorApiError::bad_request(
            "threat-intel entry requires a non-empty `value` field",
        ));
    }
    let stored = state
        .control
        .store_threat_intel_entry(entry)
        .await
        .map_err(map_control_error)?;
    Ok(Json(stored))
}

pub(super) async fn notification_dead_letter_list_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(channel): RoutePath<String>,
    Query(query): Query<NotificationDeadLetterListQuery>,
) -> Result<Json<ControlEnvelope<Vec<swarm_response::DeadLetterEntry>>>, OperatorApiError> {
    let entries = state
        .control
        .notification_dead_letters(
            &channel,
            Some(effective_limit(query.limit, state.max_list_results)),
        )
        .await
        .map_err(map_control_error)?;
    Ok(Json(entries))
}

pub(super) async fn notification_dead_letter_replay_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<OperatorHttpState>,
    RoutePath(channel): RoutePath<String>,
    Json(request): Json<NotificationDeadLetterReplayRequest>,
) -> Result<Json<ControlEnvelope<Vec<swarm_response::NotificationReplayResult>>>, OperatorApiError>
{
    require_operator_api_scope(&principal, OperatorScope::Maintenance, "maintenance")?;
    let result = state
        .control
        .replay_notification_dead_letters(&channel, request.receipt_ids)
        .await
        .map_err(map_control_error)?;
    Ok(Json(result))
}

pub(super) async fn metrics_handler(State(state): State<OperatorHttpState>) -> impl IntoResponse {
    match &state.prometheus {
        Some(metrics) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
            )],
            encode_metrics(metrics),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "metrics not enabled").into_response(),
    }
}

pub(super) async fn replay_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<ReplayLookupQuery>,
) -> Result<Json<ControlEnvelope<ReplayArtifactView>>, OperatorApiError> {
    let selector = parse_replay_selector(&query)?;
    let replay = state
        .control
        .replay_lookup(selector)
        .map_err(map_control_error)?;
    Ok(Json(replay))
}

pub(super) async fn investigation_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<InvestigationLookupQuery>,
) -> Result<Json<ControlEnvelope<InvestigationArtifactView>>, OperatorApiError> {
    let selector = parse_investigation_selector(&query)?;
    let lookup = state
        .control
        .investigation_lookup(selector)
        .map_err(map_control_error)?;
    Ok(Json(lookup))
}

pub(super) async fn incident_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<IncidentLookupQuery>,
) -> Result<Json<ControlEnvelope<IncidentArtifactView>>, OperatorApiError> {
    let selector = parse_incident_selector(&query)?;
    let incident = state
        .control
        .incident_lookup(selector)
        .map_err(map_control_error)?;
    Ok(Json(incident))
}
