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
    ApprovalError, ApprovalLedgerList, ApprovalLedgerLookup, ApprovalReceiptPackLookup,
    ApprovalSetList, ApprovalSetReport, ApprovalVerdictStatus, ThresholdRule,
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
    let _store_guard = state.approval_store_lock.lock().await;
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
    let _store_guard = state.approval_store_lock.lock().await;
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
    let _store_guard = state.approval_store_lock.lock().await;
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
    let _store_guard = state.approval_store_lock.lock().await;
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
    let _store_guard = state.approval_store_lock.lock().await;
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
    // The ledger, its global index, the quorum-derived verdict, and the
    // receipt-pack index are separate files. Keep their read/modify/write
    // transition atomic with respect to every other surface operation. The
    // callback is intentionally performed after releasing the lock.
    let store_guard = state.approval_store_lock.lock().await;
    let harness = approval_harness(&state)?;
    let existing = harness
        .load_ledger(&ledger_id)
        .map_err(map_approval_error)?
        .ok_or_else(|| {
            OperatorApiError::not_found(format!("approval ledger `{ledger_id}` was not found"))
        })?;
    let approval_set = harness
        .load_approval_set(&existing.report.approval_set_id)
        .map_err(map_approval_error)?
        .ok_or_else(|| {
            OperatorApiError::internal("approval set disappeared before its vote was appended")
        })?;
    let governed = approval_set
        .report
        .promotion_evidence_ref
        .starts_with(GOVERNED_HUMAN_APPROVAL_EVIDENCE_PREFIX);
    match harness.append_signed_vote(&ledger_id, &request.voter_id, &request.signature) {
        Ok(_) => {}
        Err(ApprovalError::DuplicateVoter { .. })
            if governed
                && existing.report.entries.iter().any(|entry| {
                    entry.voter_id == request.voter_id && entry.signature == request.signature
                }) => {}
        Err(error) => return Err(map_approval_error(error)),
    }
    let updated = harness
        .load_ledger(&ledger_id)
        .map_err(map_approval_error)?
        .ok_or_else(|| {
            OperatorApiError::internal("approval ledger was updated but could not be reloaded")
        })?;
    let receipt_pack = if updated.quorum_state.quorum_met {
        Some(load_or_create_single_receipt_pack(
            harness,
            &updated.report.approval_set_id,
            &updated.report.ledger_id,
            &state.approval_receipt_signer_id,
            &state.approval_receipt_signing_key_env,
        )?)
    } else {
        None
    };
    drop(store_guard);
    if let Some(receipt_pack) = receipt_pack {
        if governed {
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
    Ok(Json(updated))
}

fn load_or_create_single_receipt_pack(
    harness: &swarm_runtime::approval::DefaultApprovalHarness,
    approval_set_id: &str,
    ledger_id: &str,
    signer_id: &str,
    signing_key_env: &str,
) -> Result<ApprovalReceiptPackLookup, OperatorApiError> {
    let matching = harness
        .list_receipt_packs()
        .map_err(map_approval_error)?
        .packs
        .into_iter()
        .filter(|record| record.ledger_id == ledger_id)
        .collect::<Vec<_>>();
    if let [record] = matching.as_slice() {
        return harness
            .load_receipt_pack(&record.pack_id)
            .map_err(map_approval_error)?
            .ok_or_else(|| {
                OperatorApiError::internal(format!(
                    "persisted receipt pack `{}` disappeared before quorum resume",
                    record.pack_id
                ))
            });
    }
    if !matching.is_empty() {
        return Err(OperatorApiError::internal(format!(
            "quorum resume found multiple persisted receipt packs for ledger `{ledger_id}`: {}",
            matching.len()
        )));
    }

    // A process can stop after the quorum vote is durable but before the
    // verdict or receipt pack is written. Recover that exact persisted quorum
    // instead of leaving the one-voter workflow permanently wedged.
    let verdicts = harness
        .list_verdicts()
        .map_err(map_approval_error)?
        .verdicts
        .into_iter()
        .filter(|record| record.approval_set_id == approval_set_id && record.ledger_id == ledger_id)
        .collect::<Vec<_>>();
    let verdict = match verdicts.as_slice() {
        [] => harness
            .create_verdict(approval_set_id, ledger_id)
            .map_err(map_approval_error)?,
        [record] => harness
            .load_verdict(&record.verdict_id)
            .map_err(map_approval_error)?
            .ok_or_else(|| {
                OperatorApiError::internal(format!(
                    "persisted verdict `{}` disappeared before quorum resume",
                    record.verdict_id
                ))
            })?,
        records => {
            return Err(OperatorApiError::internal(format!(
                "quorum resume found multiple persisted verdicts for ledger `{ledger_id}`: {}",
                records.len()
            )));
        }
    };
    if !matches!(verdict.report.status, ApprovalVerdictStatus::Approved) {
        return Err(OperatorApiError::internal(format!(
            "persisted quorum for ledger `{ledger_id}` produced a non-approved verdict"
        )));
    }
    harness
        .export_receipt_pack(&verdict.report.verdict_id, signer_id, signing_key_env)
        .map_err(map_approval_error)
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
    require_callback_success(response, "governed-resume")
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
    require_callback_success(response, "demo-resume")
}

fn require_callback_success(
    response: reqwest::Response,
    endpoint: &'static str,
) -> Result<(), OperatorApiError> {
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    Err(OperatorApiError::bad_gateway(format!(
        "runtime {endpoint} endpoint returned HTTP {}",
        status.as_u16()
    )))
}
