//! B3 — `POST /v1/operator/findings/{finding_id}/feedback`. `OperatorScope::Approve`.
//!
//! The analyst is the authenticated principal's `operator_id`, never a body
//! value: this is the one place a human's identity reaches Ambush's own record.

use super::super::auth::{AuthenticatedOperatorPrincipal, require_operator_api_scope};
use super::super::error::OperatorApiError;
use super::super::helpers::now_ms;
use super::{PerchHttpState, map_perch_error};
use axum::Json;
use axum::extract::{Extension, Path as RoutePath, State, rejection::JsonRejection};
use swarm_core::config::OperatorScope;
use swarm_ingest_runtime::perch_ops::feedback::{
    FindingFeedbackRequest, FindingFeedbackResponse, record_finding_feedback,
};

pub(super) async fn finding_feedback_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<PerchHttpState>,
    RoutePath(finding_id): RoutePath<String>,
    body: Result<Json<FindingFeedbackRequest>, JsonRejection>,
) -> Result<Json<FindingFeedbackResponse>, OperatorApiError> {
    require_operator_api_scope(&principal, OperatorScope::Approve, "approve")?;
    let Json(request) = body.map_err(|error| OperatorApiError::bad_request(error.body_text()))?;
    record_finding_feedback(
        &state.ingest,
        principal.operator_id.as_ref(),
        &finding_id,
        request,
        now_ms(),
    )
    .await
    .map(Json)
    .map_err(map_perch_error)
}
