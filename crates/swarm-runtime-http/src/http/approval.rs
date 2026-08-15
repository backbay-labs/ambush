use super::auth::{AuthenticatedOperatorPrincipal, require_operator_api_scope};
use super::error::{OperatorApiError, map_approval_error};
use super::helpers::{approval_harness, limit_approval_ledger_list, limit_approval_set_list};
use super::state::OperatorHttpState;
use axum::Json;
use axum::extract::{Extension, Path as RoutePath, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use serde::Deserialize;
use serde_json::json;
use swarm_core::config::OperatorScope;
use swarm_crypto::DetachedSignature;
use swarm_policy::governance::GOVERNED_HUMAN_APPROVAL_EVIDENCE_PREFIX;
use swarm_runtime::approval::{
    ApprovalLedgerList, ApprovalLedgerLookup, ApprovalSetList, ApprovalSetReport,
    ApprovalVerdictStatus, ThresholdRule,
};

#[derive(Debug, Deserialize)]
pub(super) struct ApprovalSetListQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ApprovalLedgerListQuery {
    approval_set_id: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ApprovalSetCreateRequest {
    eligible_voters: Vec<String>,
    threshold_required: usize,
    promotion_evidence_ref: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct ApprovalVoteAppendRequest {
    voter_id: String,
    signature: DetachedSignature,
}

pub(super) async fn approval_set_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(set_id): RoutePath<String>,
) -> Result<Json<ApprovalSetReport>, OperatorApiError> {
    let harness = approval_harness(&state)?;
    let lookup = harness
        .load_approval_set(&set_id)
        .map_err(map_approval_error)?
        .ok_or_else(|| {
            OperatorApiError::not_found(format!("approval set `{set_id}` was not found"))
        })?;
    Ok(Json(lookup.report))
}

pub(super) async fn approval_set_list_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<ApprovalSetListQuery>,
) -> Result<Json<ApprovalSetList>, OperatorApiError> {
    let harness = approval_harness(&state)?;
    let list = harness.list_approval_sets().map_err(map_approval_error)?;
    Ok(Json(limit_approval_set_list(
        list,
        query.limit,
        state.max_list_results,
    )))
}

pub(super) async fn approval_set_create_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<OperatorHttpState>,
    Json(request): Json<ApprovalSetCreateRequest>,
) -> Result<(StatusCode, Json<ApprovalSetReport>), OperatorApiError> {
    require_operator_api_scope(&principal, OperatorScope::Approve, "approval")?;
    if let Some(ineligible_voter) = request.eligible_voters.iter().find(|voter_id| {
        !state
            .auth
            .operator_has_scope(voter_id, OperatorScope::Approve)
    }) {
        return Err(OperatorApiError::bad_request(format!(
            "eligible voter `{ineligible_voter}` is not configured with `approve` scope"
        )));
    }
    let harness = approval_harness(&state)?;
    let record = harness
        .create_approval_set(
            request.eligible_voters,
            ThresholdRule::AtLeast {
                required: request.threshold_required,
            },
            &request.promotion_evidence_ref,
        )
        .map_err(map_approval_error)?;
    let lookup = harness
        .load_approval_set(&record.set_id)
        .map_err(map_approval_error)?
        .ok_or_else(|| {
            OperatorApiError::internal("approval set was created but could not be reloaded")
        })?;
    Ok((StatusCode::CREATED, Json(lookup.report)))
}

pub(super) async fn approval_ledger_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(ledger_id): RoutePath<String>,
) -> Result<Json<ApprovalLedgerLookup>, OperatorApiError> {
    let harness = approval_harness(&state)?;
    let lookup = harness
        .load_ledger(&ledger_id)
        .map_err(map_approval_error)?
        .ok_or_else(|| {
            OperatorApiError::not_found(format!("approval ledger `{ledger_id}` was not found"))
        })?;
    Ok(Json(lookup))
}

pub(super) async fn approval_ledger_list_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<ApprovalLedgerListQuery>,
) -> Result<Json<ApprovalLedgerList>, OperatorApiError> {
    let harness = approval_harness(&state)?;
    let list = harness
        .list_ledgers(query.approval_set_id.as_deref())
        .map_err(map_approval_error)?;
    Ok(Json(limit_approval_ledger_list(
        list,
        query.limit,
        state.max_list_results,
    )))
}

pub(super) async fn approval_vote_append_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<OperatorHttpState>,
    RoutePath(ledger_id): RoutePath<String>,
    headers: HeaderMap,
    Json(request): Json<ApprovalVoteAppendRequest>,
) -> Result<Json<ApprovalLedgerLookup>, OperatorApiError> {
    require_operator_api_scope(&principal, OperatorScope::Approve, "approval")?;
    if request.voter_id != principal.operator_id.as_ref() {
        return Err(OperatorApiError::forbidden(format!(
            "authenticated operator `{}` cannot submit votes for `{}`",
            principal.operator_id, request.voter_id
        )));
    }
    let harness = approval_harness(&state)?;
    harness
        .load_ledger(&ledger_id)
        .map_err(map_approval_error)?
        .ok_or_else(|| {
            OperatorApiError::not_found(format!("approval ledger `{ledger_id}` was not found"))
        })?;
    harness
        .append_signed_vote(&ledger_id, &request.voter_id, &request.signature)
        .map_err(map_approval_error)?;
    let updated = harness
        .load_ledger(&ledger_id)
        .map_err(map_approval_error)?
        .ok_or_else(|| {
            OperatorApiError::internal("approval ledger was updated but could not be reloaded")
        })?;
    if updated.quorum_state.quorum_met {
        let verdict = harness
            .create_verdict(&updated.report.approval_set_id, &updated.report.ledger_id)
            .map_err(map_approval_error)?;
        if matches!(verdict.report.status, ApprovalVerdictStatus::Approved) {
            let receipt_pack = harness
                .export_receipt_pack(
                    &verdict.report.verdict_id,
                    &state.approval_receipt_signer_id,
                    &state.approval_receipt_signing_key_env,
                )
                .map_err(map_approval_error)?;
            let approval_set = harness
                .load_approval_set(&updated.report.approval_set_id)
                .map_err(map_approval_error)?
                .ok_or_else(|| {
                    OperatorApiError::internal(
                        "approval set disappeared before its approved verdict was routed",
                    )
                })?;
            if approval_set
                .report
                .promotion_evidence_ref
                .starts_with(GOVERNED_HUMAN_APPROVAL_EVIDENCE_PREFIX)
            {
                let authorization = headers
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| {
                        OperatorApiError::unauthorized(
                            "authenticated vote request lost its Authorization header",
                        )
                    })?;
                resume_governed_approval(
                    &state.callback_client,
                    &state.runtime_base_url,
                    &updated.report.approval_set_id,
                    &receipt_pack.report.pack_id,
                    authorization,
                )
                .await?;
            } else {
                resume_demo_approval(
                    &state.callback_client,
                    &state.runtime_base_url,
                    &updated.report.approval_set_id,
                    &receipt_pack.report,
                )
                .await?;
            }
        }
    }
    Ok(Json(updated))
}

pub(super) async fn resume_governed_approval(
    client: &reqwest::Client,
    runtime_base_url: &str,
    approval_set_id: &str,
    receipt_pack_id: &str,
    authorization: &str,
) -> Result<(), OperatorApiError> {
    let url = format!(
        "{}/v1/governance/approvals/{}/resume",
        runtime_base_url.trim_end_matches('/'),
        approval_set_id
    );
    let response = client
        .post(url)
        .header(header::AUTHORIZATION.as_str(), authorization)
        .json(&json!({ "receipt_pack_id": receipt_pack_id }))
        .send()
        .await
        .map_err(|error| {
            OperatorApiError::bad_gateway(format!(
                "failed to resume governed approval `{approval_set_id}`: {error}"
            ))
        })?;
    if response.status().is_success() {
        return Ok(());
    }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Err(OperatorApiError::bad_gateway(format!(
        "runtime governed-resume endpoint returned {} for approval `{approval_set_id}`: {}",
        status.as_u16(),
        body
    )))
}

async fn resume_demo_approval(
    client: &reqwest::Client,
    runtime_base_url: &str,
    approval_set_id: &str,
    receipt_pack: &swarm_runtime::approval::ApprovalReceiptPackReport,
) -> Result<(), OperatorApiError> {
    let url = format!(
        "{}/v1/demo/approvals/{}/resume",
        runtime_base_url.trim_end_matches('/'),
        approval_set_id
    );
    let response = client
        .post(url)
        .json(&json!({ "receipt_pack": receipt_pack }))
        .send()
        .await
        .map_err(|error| {
            OperatorApiError::bad_gateway(format!(
                "failed to resume demo approval `{approval_set_id}`: {error}"
            ))
        })?;
    if response.status().is_success() {
        return Ok(());
    }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Err(OperatorApiError::bad_gateway(format!(
        "runtime resume endpoint returned {} for approval `{approval_set_id}`: {}",
        status.as_u16(),
        body
    )))
}
