use super::auth::{AuthenticatedOperatorPrincipal, require_operator_review_scope};
use super::error::{
    OperatorReviewError, map_control_review_error, map_review_evidence_error,
    map_review_workbench_error,
};
use super::helpers::{
    filter_review_evidence_list, filter_review_promotion_packet_list, limit_evidence_bundle_list,
    limit_promotion_packet_list, limit_review_capsule_import_list, limit_review_capsule_list,
    limit_review_delegation_list, limit_review_session_export_list,
    limit_review_session_handoff_list, limit_review_session_list,
    limit_review_session_promotion_readiness_list, normalize_form_optional_text,
    parse_review_artifact_refs_text, parse_review_evidence_subject_kind,
    parse_review_evidence_verification_status, parse_review_promotion_recommendation,
    review_evidence_harness, review_evidence_secret_material, review_evidence_service,
    review_workbench_service,
};
use super::pages::{
    render_review_capsule_import_page, render_review_capsule_page, render_review_delegation_page,
    render_review_evidence_bundle_page, render_review_evidence_list_page,
    render_review_evidence_verification_page, render_review_home_page,
    render_review_promotion_packet_list_page, render_review_promotion_packet_page,
    render_review_session_export_page, render_review_session_handoff_page,
    render_review_session_list_page, render_review_session_page,
    render_review_session_promotion_readiness_page,
};
use super::state::OperatorHttpState;
use axum::extract::{Extension, Form, Path as RoutePath, Query, State};
use axum::response::{Html, Redirect};
use serde::Deserialize;
use swarm_core::config::OperatorScope;
use swarm_runtime::control::{
    ControlError, IncidentArtifactView, IncidentLookupSelector, ReplayArtifactView,
    ReplayLookupSelector,
};
use swarm_runtime::evidence::{EvidenceExportRequest, EvidenceSubjectKind};
use swarm_runtime::review_workbench::{
    ReviewCapsuleImportRequest, ReviewDelegationCreateRequest, ReviewSessionCreateRequest,
    ReviewSessionReverifyRequest,
};

#[derive(Debug, Deserialize)]
pub(super) struct ReviewEvidenceListQuery {
    subject_kind: Option<String>,
    verification_status: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ReviewHomeQuery {
    hunt_id: Option<String>,
    incident_id: Option<String>,
    bundle_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ReviewPromotionPacketListQuery {
    recommendation: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ReviewSessionListQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ReviewSessionCreateForm {
    title: Option<String>,
    notes: Option<String>,
    artifact_refs: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct ReviewSessionHandoffForm {
    selected_artifact_refs: Option<String>,
    expected_key_id: Option<String>,
    reason: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct ReviewCapsuleImportForm {
    source_path: String,
    expected_key_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ReviewDelegationForm {
    reason: String,
    delegate_label: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct ReviewHomeContext {
    pub(super) selected_bundle: Option<ReplayArtifactView>,
    pub(super) latest_rehearsal_bundle: Option<ReplayArtifactView>,
    pub(super) incident: Option<IncidentArtifactView>,
    pub(super) signed_rehearsal_bundle_id: Option<String>,
}

pub(super) async fn review_home_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<ReviewHomeQuery>,
) -> Result<Html<String>, OperatorReviewError> {
    let service = review_evidence_service(&state)?;
    let workbench = review_workbench_service(&state)?;
    let context = resolve_review_home_context(&state, &query)?;
    let bundles = limit_evidence_bundle_list(
        service
            .list_bundles(None)
            .map_err(map_review_evidence_error)?,
        Some(state.max_list_results),
        state.max_list_results,
    );
    let packets = limit_promotion_packet_list(
        service
            .list_promotion_evidence_packets()
            .map_err(map_review_evidence_error)?,
        Some(state.max_list_results),
        state.max_list_results,
    );
    let sessions = limit_review_session_list(
        workbench
            .list_sessions()
            .map_err(map_review_workbench_error)?,
        Some(state.max_list_results),
        state.max_list_results,
    );
    let capsules = limit_review_capsule_list(
        workbench
            .list_capsules(None)
            .map_err(map_review_workbench_error)?,
        Some(state.max_list_results),
        state.max_list_results,
    );
    let imports = limit_review_capsule_import_list(
        workbench
            .list_capsule_imports()
            .map_err(map_review_workbench_error)?,
        Some(state.max_list_results),
        state.max_list_results,
    );
    let delegations = limit_review_delegation_list(
        workbench
            .list_delegations(None)
            .map_err(map_review_workbench_error)?,
        Some(state.max_list_results),
        state.max_list_results,
    );
    Ok(Html(render_review_home_page(
        &state.runtime_base_url,
        context.as_ref(),
        &bundles,
        &packets,
        &sessions,
        &capsules,
        &imports,
        &delegations,
    )))
}

pub(super) async fn review_rehearsal_export_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<OperatorHttpState>,
    RoutePath(bundle_id): RoutePath<String>,
) -> Result<Redirect, OperatorReviewError> {
    require_operator_review_scope(&principal, OperatorScope::Rehearse, "rehearsal")?;
    let replay = state
        .control
        .replay_lookup(ReplayLookupSelector::BundleId(&bundle_id))
        .map_err(map_control_review_error)?;
    if replay.data.bundle.rehearsal.is_none() {
        return Err(OperatorReviewError::bad_request(format!(
            "replay bundle `{bundle_id}` does not contain rehearsal proof"
        )));
    }
    let harness = review_evidence_harness(&state)?;
    let secret_material = review_evidence_secret_material(&state)?;
    let lookup = harness
        .export_bundle(EvidenceExportRequest {
            subject_kind: EvidenceSubjectKind::ReplayBundle,
            stable_id: bundle_id,
            signer_id: state.approval_receipt_signer_id.clone(),
            secret_material,
        })
        .map_err(map_review_evidence_error)?;
    Ok(Redirect::to(&format!(
        "/v1/operator/review/evidence/{}",
        lookup.record.bundle_id
    )))
}

pub(super) async fn review_session_list_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<ReviewSessionListQuery>,
) -> Result<Html<String>, OperatorReviewError> {
    let service = review_workbench_service(&state)?;
    let list = service
        .list_sessions()
        .map_err(map_review_workbench_error)?;
    let list = limit_review_session_list(list, query.limit, state.max_list_results);
    Ok(Html(render_review_session_list_page(&list)))
}

pub(super) async fn review_session_create_handler(
    State(state): State<OperatorHttpState>,
    Form(form): Form<ReviewSessionCreateForm>,
) -> Result<Redirect, OperatorReviewError> {
    let service = review_workbench_service(&state)?;
    let artifact_refs = parse_review_artifact_refs_text(&form.artifact_refs)?;
    let lookup = service
        .create_session(ReviewSessionCreateRequest {
            title: form.title,
            notes: form.notes,
            artifact_refs,
        })
        .map_err(map_review_workbench_error)?;
    Ok(Redirect::to(&format!(
        "/v1/operator/review/sessions/{}",
        lookup.report.session_id
    )))
}

pub(super) async fn review_session_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(session_id): RoutePath<String>,
) -> Result<Html<String>, OperatorReviewError> {
    let service = review_workbench_service(&state)?;
    let resolved = service
        .resolve_session(&session_id)
        .map_err(map_review_workbench_error)?;
    let exports = limit_review_session_export_list(
        service
            .list_exports(Some(&session_id))
            .map_err(map_review_workbench_error)?,
        Some(state.max_list_results),
        state.max_list_results,
    );
    let handoffs = limit_review_session_handoff_list(
        service
            .list_handoffs(Some(&session_id))
            .map_err(map_review_workbench_error)?,
        Some(state.max_list_results),
        state.max_list_results,
    );
    let readiness_reports = limit_review_session_promotion_readiness_list(
        service
            .list_promotion_readiness(Some(&session_id))
            .map_err(map_review_workbench_error)?,
        Some(state.max_list_results),
        state.max_list_results,
    );
    let capsules = limit_review_capsule_list(
        service
            .list_capsules(Some(&session_id))
            .map_err(map_review_workbench_error)?,
        Some(state.max_list_results),
        state.max_list_results,
    );
    let delegations = limit_review_delegation_list(
        service
            .list_delegations(Some(&session_id))
            .map_err(map_review_workbench_error)?,
        Some(state.max_list_results),
        state.max_list_results,
    );
    Ok(Html(render_review_session_page(
        &resolved,
        &exports.exports,
        &readiness_reports.readiness_reports,
        &handoffs.handoffs,
        &capsules.capsules,
        &delegations.delegations,
    )))
}

pub(super) async fn review_session_export_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(session_id): RoutePath<String>,
) -> Result<Redirect, OperatorReviewError> {
    let service = review_workbench_service(&state)?;
    let lookup = service
        .export_session(&session_id)
        .map_err(map_review_workbench_error)?;
    Ok(Redirect::to(&format!(
        "/v1/operator/review/exports/{}",
        lookup.export.export_id
    )))
}

pub(super) async fn review_session_capsule_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(session_id): RoutePath<String>,
) -> Result<Redirect, OperatorReviewError> {
    let service = review_workbench_service(&state)?;
    let lookup = service
        .create_capsule_from_session(&session_id)
        .map_err(map_review_workbench_error)?;
    Ok(Redirect::to(&format!(
        "/v1/operator/review/capsules/{}",
        lookup.capsule.capsule_id
    )))
}

pub(super) async fn review_session_export_page_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(export_id): RoutePath<String>,
) -> Result<Html<String>, OperatorReviewError> {
    let service = review_workbench_service(&state)?;
    let lookup = service
        .load_export(&export_id)
        .map_err(map_review_workbench_error)?
        .ok_or_else(|| {
            OperatorReviewError::not_found(format!(
                "review session export `{export_id}` was not found"
            ))
        })?;
    Ok(Html(render_review_session_export_page(&lookup.export)))
}

pub(super) async fn review_capsule_page_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(capsule_id): RoutePath<String>,
) -> Result<Html<String>, OperatorReviewError> {
    let service = review_workbench_service(&state)?;
    let lookup = service
        .load_capsule(&capsule_id)
        .map_err(map_review_workbench_error)?
        .ok_or_else(|| {
            OperatorReviewError::not_found(format!("review capsule `{capsule_id}` was not found"))
        })?;
    Ok(Html(render_review_capsule_page(&lookup.capsule)))
}

pub(super) async fn review_capsule_import_handler(
    State(state): State<OperatorHttpState>,
    Form(form): Form<ReviewCapsuleImportForm>,
) -> Result<Redirect, OperatorReviewError> {
    let service = review_workbench_service(&state)?;
    let lookup = service
        .import_capsule(ReviewCapsuleImportRequest {
            source_path: form.source_path,
            expected_key_id: normalize_form_optional_text(form.expected_key_id),
        })
        .map_err(map_review_workbench_error)?;
    Ok(Redirect::to(&format!(
        "/v1/operator/review/capsule-imports/{}",
        lookup.import.import_id
    )))
}

pub(super) async fn review_capsule_import_page_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(import_id): RoutePath<String>,
) -> Result<Html<String>, OperatorReviewError> {
    let service = review_workbench_service(&state)?;
    let lookup = service
        .load_capsule_import(&import_id)
        .map_err(map_review_workbench_error)?
        .ok_or_else(|| {
            OperatorReviewError::not_found(format!(
                "review capsule import `{import_id}` was not found"
            ))
        })?;
    Ok(Html(render_review_capsule_import_page(&lookup.import)))
}

pub(super) async fn review_session_promotion_readiness_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(session_id): RoutePath<String>,
) -> Result<Redirect, OperatorReviewError> {
    let service = review_workbench_service(&state)?;
    let lookup = service
        .create_promotion_readiness_review(&session_id)
        .map_err(map_review_workbench_error)?;
    Ok(Redirect::to(&format!(
        "/v1/operator/review/promotion-readiness/{}",
        lookup.report.readiness_id
    )))
}

pub(super) async fn review_session_promotion_readiness_page_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(readiness_id): RoutePath<String>,
) -> Result<Html<String>, OperatorReviewError> {
    let service = review_workbench_service(&state)?;
    let lookup = service
        .load_promotion_readiness(&readiness_id)
        .map_err(map_review_workbench_error)?
        .ok_or_else(|| {
            OperatorReviewError::not_found(format!(
                "review session readiness `{readiness_id}` was not found"
            ))
        })?;
    Ok(Html(render_review_session_promotion_readiness_page(
        &lookup.report,
    )))
}

pub(super) async fn review_session_readiness_capsule_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(readiness_id): RoutePath<String>,
) -> Result<Redirect, OperatorReviewError> {
    let service = review_workbench_service(&state)?;
    let lookup = service
        .create_capsule_from_readiness(&readiness_id)
        .map_err(map_review_workbench_error)?;
    Ok(Redirect::to(&format!(
        "/v1/operator/review/capsules/{}",
        lookup.capsule.capsule_id
    )))
}

pub(super) async fn review_session_handoff_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<OperatorHttpState>,
    RoutePath(session_id): RoutePath<String>,
    Form(form): Form<ReviewSessionHandoffForm>,
) -> Result<Redirect, OperatorReviewError> {
    require_operator_review_scope(&principal, OperatorScope::Maintenance, "maintenance")?;
    let service = review_workbench_service(&state)?;
    let selected_artifact_refs = form
        .selected_artifact_refs
        .as_deref()
        .map(parse_review_artifact_refs_text)
        .transpose()?
        .unwrap_or_default();
    let lookup = service
        .create_reverify_handoff(
            principal.operator_id.as_ref(),
            ReviewSessionReverifyRequest {
                session_id,
                selected_artifact_refs,
                expected_key_id: normalize_form_optional_text(form.expected_key_id),
                reason: form.reason,
            },
        )
        .map_err(map_review_workbench_error)?;
    Ok(Redirect::to(&format!(
        "/v1/operator/review/handoffs/{}",
        lookup.handoff.handoff_id
    )))
}

pub(super) async fn review_capsule_delegation_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(capsule_id): RoutePath<String>,
    Form(form): Form<ReviewDelegationForm>,
) -> Result<Redirect, OperatorReviewError> {
    let service = review_workbench_service(&state)?;
    let lookup = service
        .create_delegation_packet(ReviewDelegationCreateRequest {
            capsule_id: Some(capsule_id),
            import_id: None,
            reason: form.reason,
            delegate_label: normalize_form_optional_text(form.delegate_label),
        })
        .map_err(map_review_workbench_error)?;
    Ok(Redirect::to(&format!(
        "/v1/operator/review/delegations/{}",
        lookup.packet.delegation_id
    )))
}

pub(super) async fn review_capsule_import_delegation_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(import_id): RoutePath<String>,
    Form(form): Form<ReviewDelegationForm>,
) -> Result<Redirect, OperatorReviewError> {
    let service = review_workbench_service(&state)?;
    let lookup = service
        .create_delegation_packet(ReviewDelegationCreateRequest {
            capsule_id: None,
            import_id: Some(import_id),
            reason: form.reason,
            delegate_label: normalize_form_optional_text(form.delegate_label),
        })
        .map_err(map_review_workbench_error)?;
    Ok(Redirect::to(&format!(
        "/v1/operator/review/delegations/{}",
        lookup.packet.delegation_id
    )))
}

pub(super) async fn review_session_handoff_page_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(handoff_id): RoutePath<String>,
) -> Result<Html<String>, OperatorReviewError> {
    let service = review_workbench_service(&state)?;
    let lookup = service
        .load_handoff(&handoff_id)
        .map_err(map_review_workbench_error)?
        .ok_or_else(|| {
            OperatorReviewError::not_found(format!(
                "review session handoff `{handoff_id}` was not found"
            ))
        })?;
    Ok(Html(render_review_session_handoff_page(&lookup.handoff)))
}

pub(super) async fn review_delegation_page_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(delegation_id): RoutePath<String>,
) -> Result<Html<String>, OperatorReviewError> {
    let service = review_workbench_service(&state)?;
    let lookup = service
        .load_delegation(&delegation_id)
        .map_err(map_review_workbench_error)?
        .ok_or_else(|| {
            OperatorReviewError::not_found(format!(
                "review delegation `{delegation_id}` was not found"
            ))
        })?;
    Ok(Html(render_review_delegation_page(&lookup.packet)))
}

pub(super) async fn review_evidence_list_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<ReviewEvidenceListQuery>,
) -> Result<Html<String>, OperatorReviewError> {
    let service = review_evidence_service(&state)?;
    let subject_kind = query
        .subject_kind
        .as_deref()
        .map(parse_review_evidence_subject_kind)
        .transpose()?;
    let verification_status = query
        .verification_status
        .as_deref()
        .map(parse_review_evidence_verification_status)
        .transpose()?;
    let list = service
        .list_bundles(subject_kind)
        .map_err(map_review_evidence_error)?;
    let list = filter_review_evidence_list(list, verification_status);
    let list = limit_evidence_bundle_list(list, query.limit, state.max_list_results);
    Ok(Html(render_review_evidence_list_page(
        &list,
        verification_status,
    )))
}

pub(super) async fn review_evidence_bundle_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(bundle_id): RoutePath<String>,
) -> Result<Html<String>, OperatorReviewError> {
    let service = review_evidence_service(&state)?;
    let lookup = service
        .load_bundle(&bundle_id)
        .map_err(map_review_evidence_error)?
        .ok_or_else(|| {
            OperatorReviewError::not_found(format!("evidence bundle `{bundle_id}` was not found"))
        })?;
    let latest_verification =
        if let Some(verification_id) = lookup.record.latest_verification_id.as_deref() {
            service
                .load_verification(verification_id)
                .map_err(map_review_evidence_error)?
        } else {
            None
        };
    Ok(Html(render_review_evidence_bundle_page(
        &lookup.bundle,
        lookup.record.latest_verification_status,
        latest_verification.as_ref().map(|lookup| &lookup.report),
    )))
}

pub(super) async fn review_evidence_verification_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(verification_id): RoutePath<String>,
) -> Result<Html<String>, OperatorReviewError> {
    let service = review_evidence_service(&state)?;
    let lookup = service
        .load_verification(&verification_id)
        .map_err(map_review_evidence_error)?
        .ok_or_else(|| {
            OperatorReviewError::not_found(format!(
                "evidence verification `{verification_id}` was not found"
            ))
        })?;
    Ok(Html(render_review_evidence_verification_page(
        &lookup.report,
    )))
}

pub(super) async fn review_promotion_packet_list_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<ReviewPromotionPacketListQuery>,
) -> Result<Html<String>, OperatorReviewError> {
    let service = review_evidence_service(&state)?;
    let recommendation = query
        .recommendation
        .as_deref()
        .map(parse_review_promotion_recommendation)
        .transpose()?;
    let list = service
        .list_promotion_evidence_packets()
        .map_err(map_review_evidence_error)?;
    let list = filter_review_promotion_packet_list(list, recommendation);
    let list = limit_promotion_packet_list(list, query.limit, state.max_list_results);
    Ok(Html(render_review_promotion_packet_list_page(
        &list,
        recommendation,
    )))
}

pub(super) async fn review_promotion_packet_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(packet_id): RoutePath<String>,
) -> Result<Html<String>, OperatorReviewError> {
    let service = review_evidence_service(&state)?;
    let lookup = service
        .load_promotion_evidence_packet(&packet_id)
        .map_err(map_review_evidence_error)?
        .ok_or_else(|| {
            OperatorReviewError::not_found(format!(
                "promotion evidence packet `{packet_id}` was not found"
            ))
        })?;
    Ok(Html(render_review_promotion_packet_page(&lookup.packet)))
}

fn resolve_review_home_context(
    state: &OperatorHttpState,
    query: &ReviewHomeQuery,
) -> Result<Option<ReviewHomeContext>, OperatorReviewError> {
    if query.hunt_id.is_none() && query.incident_id.is_none() && query.bundle_id.is_none() {
        return Ok(None);
    }

    let selected_bundle = match query.bundle_id.as_deref() {
        Some(bundle_id) => Some(
            state
                .control
                .replay_lookup(ReplayLookupSelector::BundleId(bundle_id))
                .map_err(map_control_review_error)?
                .data,
        ),
        None => query
            .hunt_id
            .as_deref()
            .map(|hunt_id| {
                match state
                    .control
                    .replay_lookup(ReplayLookupSelector::HuntId(hunt_id))
                {
                    Ok(lookup) => Ok(Some(lookup.data)),
                    Err(ControlError::NotFound { .. }) => Ok(None),
                    Err(other) => Err(map_control_review_error(other)),
                }
            })
            .transpose()?
            .flatten(),
    };

    let incident = match query.incident_id.as_deref() {
        Some(incident_id) => Some(
            state
                .control
                .incident_lookup(IncidentLookupSelector::IncidentId(incident_id))
                .map_err(map_control_review_error)?
                .data,
        ),
        None => query
            .hunt_id
            .as_deref()
            .map(|hunt_id| {
                match state
                    .control
                    .incident_lookup(IncidentLookupSelector::HuntId(hunt_id))
                {
                    Ok(lookup) => Ok(Some(lookup.data)),
                    Err(ControlError::NotFound { .. }) => Ok(None),
                    Err(other) => Err(map_control_review_error(other)),
                }
            })
            .transpose()?
            .flatten(),
    };

    let rehearsal_hunt_id = query
        .hunt_id
        .as_deref()
        .map(ToString::to_string)
        .or_else(|| {
            selected_bundle
                .as_ref()
                .map(|bundle| bundle.record.hunt_id.clone())
        })
        .or_else(|| {
            incident
                .as_ref()
                .and_then(|incident| incident.record.included_hunt_ids.first().cloned())
        });
    let latest_rehearsal_bundle = rehearsal_hunt_id
        .as_deref()
        .map(|hunt_id| {
            match state
                .control
                .replay_lookup(ReplayLookupSelector::HuntId(hunt_id))
            {
                Ok(lookup) => Ok(Some(lookup.data)),
                Err(ControlError::NotFound { .. }) => Ok(None),
                Err(other) => Err(map_control_review_error(other)),
            }
        })
        .transpose()?
        .flatten()
        .filter(|lookup| lookup.bundle.rehearsal.is_some());
    let signed_rehearsal_bundle_id = latest_rehearsal_bundle
        .as_ref()
        .map(|lookup| {
            review_evidence_service(state)?
                .find_bundle_by_subject(EvidenceSubjectKind::ReplayBundle, &lookup.bundle.bundle_id)
                .map_err(map_review_evidence_error)
                .map(|lookup| lookup.map(|bundle| bundle.record.bundle_id))
        })
        .transpose()?
        .flatten();

    Ok(Some(ReviewHomeContext {
        selected_bundle,
        latest_rehearsal_bundle,
        incident,
        signed_rehearsal_bundle_id,
    }))
}
