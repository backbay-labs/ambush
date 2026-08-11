use super::error::{OperatorApiError, map_evidence_api_error};
use super::helpers::{evidence_service, limit_evidence_bundle_list, parse_evidence_subject_kind};
use super::state::OperatorHttpState;
use crate::evidence::{
    EvidenceBundle, EvidenceBundleList, EvidenceVerificationReport, PromotionEvidencePacket,
};
use axum::Json;
use axum::extract::{Path as RoutePath, Query, State};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct EvidenceListQuery {
    subject_kind: Option<String>,
    limit: Option<usize>,
}

pub(super) async fn evidence_bundle_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(bundle_id): RoutePath<String>,
) -> Result<Json<EvidenceBundle>, OperatorApiError> {
    let service = evidence_service(&state)?;
    let lookup = service
        .load_bundle(&bundle_id)
        .map_err(map_evidence_api_error)?
        .ok_or_else(|| {
            OperatorApiError::not_found(format!("evidence bundle `{bundle_id}` was not found"))
        })?;
    Ok(Json(lookup.bundle))
}

pub(super) async fn evidence_bundle_list_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<EvidenceListQuery>,
) -> Result<Json<EvidenceBundleList>, OperatorApiError> {
    let service = evidence_service(&state)?;
    let subject_kind = query
        .subject_kind
        .as_deref()
        .map(parse_evidence_subject_kind)
        .transpose()?;
    let list = service
        .list_bundles(subject_kind)
        .map_err(map_evidence_api_error)?;
    Ok(Json(limit_evidence_bundle_list(
        list,
        query.limit,
        state.max_list_results,
    )))
}

pub(super) async fn evidence_verification_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(verification_id): RoutePath<String>,
) -> Result<Json<EvidenceVerificationReport>, OperatorApiError> {
    let service = evidence_service(&state)?;
    let lookup = service
        .load_verification(&verification_id)
        .map_err(map_evidence_api_error)?
        .ok_or_else(|| {
            OperatorApiError::not_found(format!(
                "evidence verification `{verification_id}` was not found"
            ))
        })?;
    Ok(Json(lookup.report))
}

pub(super) async fn promotion_evidence_packet_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(packet_id): RoutePath<String>,
) -> Result<Json<PromotionEvidencePacket>, OperatorApiError> {
    let service = evidence_service(&state)?;
    let lookup = service
        .load_promotion_evidence_packet(&packet_id)
        .map_err(map_evidence_api_error)?
        .ok_or_else(|| {
            OperatorApiError::not_found(format!(
                "promotion evidence packet `{packet_id}` was not found"
            ))
        })?;
    Ok(Json(lookup.packet))
}
