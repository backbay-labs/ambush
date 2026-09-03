//! B3i — `POST /v1/operator/incidents`. `OperatorScope::Approve`.

use super::super::auth::{AuthenticatedOperatorPrincipal, require_operator_api_scope};
use super::super::error::OperatorApiError;
use super::super::helpers::now_ms;
use super::{PerchHttpState, map_perch_error};
use axum::Json;
use axum::extract::{Extension, State, rejection::JsonRejection};
use swarm_core::config::OperatorScope;
use swarm_ingest_runtime::perch_ops::mint::{
    IncidentMintRequest, IncidentMintResponse, mint_incident,
};

pub(super) async fn mint_incident_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<PerchHttpState>,
    body: Result<Json<IncidentMintRequest>, JsonRejection>,
) -> Result<Json<IncidentMintResponse>, OperatorApiError> {
    require_operator_api_scope(&principal, OperatorScope::Approve, "approve")?;
    let Json(request) = body.map_err(|error| OperatorApiError::bad_request(error.body_text()))?;
    mint_incident(&state.ingest, request, now_ms())
        .map(Json)
        .map_err(map_perch_error)
}
