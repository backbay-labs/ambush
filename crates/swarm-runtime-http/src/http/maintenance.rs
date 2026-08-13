use super::auth::{AuthenticatedOperatorPrincipal, require_operator_api_scope};
use super::error::{OperatorApiError, map_maintenance_error};
use super::helpers::{limit_maintenance_list, maintenance_service, parse_maintenance_status};
use super::state::OperatorHttpState;
use axum::Json;
use axum::extract::{Extension, Path as RoutePath, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use swarm_core::config::OperatorScope;
use swarm_evolution::operator_maintenance::{
    OperatorMaintenanceExecution, OperatorMaintenanceList, OperatorMaintenanceRecord,
    OperatorMaintenanceRequest,
};

#[derive(Debug, Deserialize)]
pub(super) struct MaintenanceActionListQuery {
    status: Option<String>,
    limit: Option<usize>,
}

pub(super) async fn maintenance_action_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<OperatorHttpState>,
    Json(request): Json<OperatorMaintenanceRequest>,
) -> Response {
    if let Err(error) =
        require_operator_api_scope(&principal, OperatorScope::Maintenance, "maintenance")
    {
        return error.into_response();
    }
    let service = match maintenance_service(&state) {
        Ok(service) => service,
        Err(error) => return error.into_response(),
    };
    match service.execute(principal.operator_id.as_ref(), request) {
        Ok(execution) => {
            let (status, record) = match execution {
                OperatorMaintenanceExecution::Applied(lookup) => (StatusCode::OK, lookup.record),
                OperatorMaintenanceExecution::Blocked(lookup) => {
                    (StatusCode::CONFLICT, lookup.record)
                }
                OperatorMaintenanceExecution::Failed(lookup) => {
                    (StatusCode::INTERNAL_SERVER_ERROR, lookup.record)
                }
            };
            (status, Json(record)).into_response()
        }
        Err(error) => map_maintenance_error(error).into_response(),
    }
}

pub(super) async fn maintenance_action_lookup_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(action_id): RoutePath<String>,
) -> Result<Json<OperatorMaintenanceRecord>, OperatorApiError> {
    let service = maintenance_service(&state)?;
    let lookup = service
        .load(&action_id)
        .map_err(map_maintenance_error)?
        .ok_or_else(|| {
            OperatorApiError::not_found(format!("maintenance action `{action_id}` was not found"))
        })?;
    Ok(Json(lookup.record))
}

pub(super) async fn maintenance_action_list_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<MaintenanceActionListQuery>,
) -> Result<Json<OperatorMaintenanceList>, OperatorApiError> {
    let service = maintenance_service(&state)?;
    let status = query
        .status
        .as_deref()
        .map(parse_maintenance_status)
        .transpose()?;
    let list = service.list(status).map_err(map_maintenance_error)?;
    Ok(Json(limit_maintenance_list(
        list,
        query.limit,
        state.max_list_results,
    )))
}
