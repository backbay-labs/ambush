use super::platform_api::{
    PlatformApiBearerPrincipal, PlatformApiError, require_governed_resume_bearer_auth,
    require_supported_platform_api_schema_version,
};
use super::{IngestState, response_receipt_details};
use axum::Router;
use axum::extract::{Extension, Json, Path, State};
use axum::middleware;
use axum::routing::post;
use serde::{Deserialize, Serialize};
use swarm_policy::governance::GOVERNED_HUMAN_APPROVAL_EVIDENCE_PREFIX;
use swarm_runtime::approval::ApprovalError;
use swarm_runtime::dispatcher::HumanApprovalResumeDispatcher;
use swarm_runtime::runtime_events::{RuntimeEvent, now_ms};
use swarm_spine::AuditTrail;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GovernedApprovalResumeRequest {
    receipt_pack_id: String,
}

#[derive(Debug, Serialize)]
pub(super) struct GovernedApprovalResumeResponse {
    approval_set_id: String,
    receipt_pack_id: String,
    response_kind: String,
    response_receipt_id: Option<String>,
    audit: AuditTrail,
}

pub(super) fn governed_resume_router(state: &IngestState) -> Router<IngestState> {
    Router::new()
        .route(
            "/v1/governance/approvals/{approval_set_id}/resume",
            post(governed_approval_resume_handler),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_governed_resume_bearer_auth,
        ))
        .layer(middleware::from_fn(
            require_supported_platform_api_schema_version,
        ))
}

async fn governed_approval_resume_handler(
    Extension(principal): Extension<PlatformApiBearerPrincipal>,
    State(state): State<IngestState>,
    Path(approval_set_id): Path<String>,
    Json(request): Json<GovernedApprovalResumeRequest>,
) -> Result<Json<GovernedApprovalResumeResponse>, PlatformApiError> {
    if request.receipt_pack_id.trim().is_empty() {
        return Err(PlatformApiError::bad_request(
            "receipt_pack_id must not be empty",
        ));
    }
    let harness = state.approval_harness.as_ref().ok_or_else(|| {
        PlatformApiError::service_unavailable("approval artifact stores are not configured")
    })?;
    let receipt_pack = harness
        .load_receipt_pack(&request.receipt_pack_id)
        .map_err(|error| match error {
            ApprovalError::ReceiptPackStoreNotConfigured => PlatformApiError::service_unavailable(
                "approval receipt-pack store is not configured",
            ),
            other => PlatformApiError::service_unavailable(format!(
                "approval receipt pack could not be loaded: {other}"
            )),
        })?
        .ok_or_else(|| {
            PlatformApiError::not_found(format!(
                "approval receipt pack `{}` was not found",
                request.receipt_pack_id
            ))
        })?;
    if receipt_pack.report.approval_set.set_id != approval_set_id {
        return Err(PlatformApiError::bad_request(
            "approval set id does not match the persisted receipt pack",
        ));
    }
    if !receipt_pack
        .report
        .approval_set
        .promotion_evidence_ref
        .starts_with(GOVERNED_HUMAN_APPROVAL_EVIDENCE_PREFIX)
    {
        return Err(PlatformApiError::bad_request(
            "approval set is not a governed human authorization",
        ));
    }
    let governance = state.governance_policy.clone().ok_or_else(|| {
        PlatformApiError::service_unavailable("governance authority is not configured")
    })?;
    let action_kind = governance
        .pending_human_authorization(&approval_set_id)
        .map_err(PlatformApiError::conflict)?
        .request
        .action
        .kind()
        .to_string();
    let audit =
        HumanApprovalResumeDispatcher::new(governance, state.current_request_response_router())
            .resume(receipt_pack.report.clone())
            .await
            .map_err(|error| PlatformApiError::conflict(error.to_string()))?;
    let (response_receipt_id, response_error) = response_receipt_details(&audit);
    state.publish_runtime_event(RuntimeEvent::ResponseExecution {
        emitted_at_ms: now_ms(),
        agent_id: principal.operator_id.to_string(),
        hunt_id: audit.hunt_id.clone(),
        action_kind,
        response_kind: audit.response_kind().to_string(),
        policy_verdict: audit.policy.verdict,
        rule_name: audit.policy.rule_name.clone(),
        reason: audit.policy.reason.clone(),
        receipt_id: response_receipt_id.clone(),
        governing_agent_id: None,
        error: response_error,
    });
    Ok(Json(GovernedApprovalResumeResponse {
        approval_set_id,
        receipt_pack_id: receipt_pack.report.pack_id,
        response_kind: audit.response_kind().to_string(),
        response_receipt_id,
        audit,
    }))
}
