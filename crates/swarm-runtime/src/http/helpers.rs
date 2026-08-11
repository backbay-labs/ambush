use super::control::{IncidentLookupQuery, InvestigationLookupQuery, ReplayLookupQuery};
use super::error::{OperatorApiError, OperatorReviewError};
use super::state::{OperatorHttpState, OperatorSurfacePaths};
use crate::approval::{ApprovalLedgerList, ApprovalSetList, DefaultApprovalHarness};
use crate::control::{IncidentLookupSelector, InvestigationLookupSelector, ReplayLookupSelector};
use crate::evidence::{
    DefaultEvidenceHarness, EvidenceBundleList, EvidenceHarnessPaths, EvidenceSubjectKind,
    EvidenceVerificationStatus, OperatorEvidenceReadService, PromotionEvidencePacketList,
    PromotionEvidenceRecommendation,
};
use crate::governance_prep::{
    DefaultEvolutionGovernancePrepHarness, EvolutionGovernancePacketSetList,
    EvolutionPortfolioHistoryList,
};
use crate::operator_maintenance::{
    OperatorMaintenanceList, OperatorMaintenanceService, OperatorMaintenanceStatus,
};
use crate::portfolio::{
    DefaultEvolutionPortfolioHarness, EvolutionPortfolioEntryReviewState, EvolutionPortfolioList,
};
use crate::review_workbench::{
    DefaultReviewWorkbenchHarness, ReviewArtifactRef, ReviewArtifactRefKind,
    ReviewCapsuleImportList, ReviewCapsuleList, ReviewDelegationPacketList, ReviewSessionList,
    ReviewSessionMaintenanceHandoffList, ReviewSessionPromotionReadinessList,
};

pub(super) fn evidence_harness_paths(paths: &OperatorSurfacePaths) -> EvidenceHarnessPaths {
    EvidenceHarnessPaths {
        verification_results_dir: paths.verification_results_dir.clone(),
        shadow_results_dir: paths.shadow_results_dir.clone(),
        promotion_review_results_dir: paths.promotion_review_results_dir.clone(),
        canary_results_dir: paths.canary_results_dir.clone(),
        promotion_results_dir: paths.promotion_results_dir.clone(),
        operator_maintenance_results_dir: paths.operator_maintenance_results_dir.clone(),
        evidence_results_dir: paths.evidence_results_dir.clone(),
        evidence_verification_results_dir: paths.evidence_verification_results_dir.clone(),
        promotion_evidence_results_dir: paths.promotion_evidence_results_dir.clone(),
    }
}

pub(super) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub(super) fn parse_replay_selector(
    query: &ReplayLookupQuery,
) -> Result<ReplayLookupSelector<'_>, OperatorApiError> {
    let set = count_set(&[
        query.bundle_id.as_deref(),
        query.hunt_id.as_deref(),
        query.receipt_id.as_deref(),
    ]);
    if set != 1 {
        return Err(OperatorApiError::bad_request(
            "exactly one replay selector must be supplied",
        ));
    }
    if let Some(bundle_id) = query.bundle_id.as_deref() {
        Ok(ReplayLookupSelector::BundleId(bundle_id))
    } else if let Some(hunt_id) = query.hunt_id.as_deref() {
        Ok(ReplayLookupSelector::HuntId(hunt_id))
    } else if let Some(receipt_id) = query.receipt_id.as_deref() {
        Ok(ReplayLookupSelector::ReceiptId(receipt_id))
    } else {
        Err(OperatorApiError::bad_request(
            "exactly one replay selector must be supplied",
        ))
    }
}

pub(super) fn parse_investigation_selector(
    query: &InvestigationLookupQuery,
) -> Result<InvestigationLookupSelector<'_>, OperatorApiError> {
    let set = count_set(&[
        query.investigation_id.as_deref(),
        query.hunt_id.as_deref(),
        query.receipt_id.as_deref(),
    ]);
    if set != 1 {
        return Err(OperatorApiError::bad_request(
            "exactly one investigation selector must be supplied",
        ));
    }
    if let Some(investigation_id) = query.investigation_id.as_deref() {
        Ok(InvestigationLookupSelector::InvestigationId(
            investigation_id,
        ))
    } else if let Some(hunt_id) = query.hunt_id.as_deref() {
        Ok(InvestigationLookupSelector::HuntId(hunt_id))
    } else if let Some(receipt_id) = query.receipt_id.as_deref() {
        Ok(InvestigationLookupSelector::ReceiptId(receipt_id))
    } else {
        Err(OperatorApiError::bad_request(
            "exactly one investigation selector must be supplied",
        ))
    }
}

pub(super) fn parse_incident_selector(
    query: &IncidentLookupQuery,
) -> Result<IncidentLookupSelector<'_>, OperatorApiError> {
    let set = count_set(&[query.incident_id.as_deref(), query.hunt_id.as_deref()]);
    if set != 1 {
        return Err(OperatorApiError::bad_request(
            "exactly one incident selector must be supplied",
        ));
    }
    if let Some(incident_id) = query.incident_id.as_deref() {
        Ok(IncidentLookupSelector::IncidentId(incident_id))
    } else if let Some(hunt_id) = query.hunt_id.as_deref() {
        Ok(IncidentLookupSelector::HuntId(hunt_id))
    } else {
        Err(OperatorApiError::bad_request(
            "exactly one incident selector must be supplied",
        ))
    }
}

pub(super) fn parse_portfolio_review_state(
    value: &str,
) -> Result<EvolutionPortfolioEntryReviewState, OperatorApiError> {
    match value {
        "pending_review" => Ok(EvolutionPortfolioEntryReviewState::PendingReview),
        "included" => Ok(EvolutionPortfolioEntryReviewState::Included),
        "deferred" => Ok(EvolutionPortfolioEntryReviewState::Deferred),
        "dropped" => Ok(EvolutionPortfolioEntryReviewState::Dropped),
        "blocked" => Ok(EvolutionPortfolioEntryReviewState::Blocked),
        other => Err(OperatorApiError::bad_request(format!(
            "unsupported portfolio review_state `{other}`"
        ))),
    }
}

pub(super) fn parse_maintenance_status(
    value: &str,
) -> Result<OperatorMaintenanceStatus, OperatorApiError> {
    match value {
        "applied" => Ok(OperatorMaintenanceStatus::Applied),
        "blocked" => Ok(OperatorMaintenanceStatus::Blocked),
        "failed" => Ok(OperatorMaintenanceStatus::Failed),
        other => Err(OperatorApiError::bad_request(format!(
            "unsupported maintenance status `{other}`"
        ))),
    }
}

pub(super) fn parse_evidence_subject_kind(
    value: &str,
) -> Result<EvidenceSubjectKind, OperatorApiError> {
    value.parse::<EvidenceSubjectKind>().map_err(|_| {
        OperatorApiError::bad_request(format!("unsupported evidence subject_kind `{value}`"))
    })
}

pub(super) fn portfolio_harness(
    state: &OperatorHttpState,
) -> Result<&DefaultEvolutionPortfolioHarness, OperatorApiError> {
    state
        .portfolio
        .as_deref()
        .ok_or_else(|| OperatorApiError::internal("portfolio stores are not configured"))
}

pub(super) fn governance_harness(
    state: &OperatorHttpState,
) -> Result<&DefaultEvolutionGovernancePrepHarness, OperatorApiError> {
    state
        .governance_prep
        .as_deref()
        .ok_or_else(|| OperatorApiError::internal("governance-prep stores are not configured"))
}

pub(super) fn approval_harness(
    state: &OperatorHttpState,
) -> Result<&DefaultApprovalHarness, OperatorApiError> {
    state
        .approval
        .as_deref()
        .ok_or_else(|| OperatorApiError::internal("approval stores are not configured"))
}

pub(super) fn maintenance_service(
    state: &OperatorHttpState,
) -> Result<&OperatorMaintenanceService, OperatorApiError> {
    state
        .maintenance
        .as_deref()
        .ok_or_else(|| OperatorApiError::internal("maintenance stores are not configured"))
}

pub(super) fn evidence_service(
    state: &OperatorHttpState,
) -> Result<&OperatorEvidenceReadService, OperatorApiError> {
    state
        .evidence
        .as_deref()
        .ok_or_else(|| OperatorApiError::internal("evidence stores are not configured"))
}

pub(super) fn review_evidence_harness(
    state: &OperatorHttpState,
) -> Result<&DefaultEvidenceHarness, OperatorReviewError> {
    state
        .evidence_harness
        .as_deref()
        .ok_or_else(|| OperatorReviewError::internal("evidence export stores are not configured"))
}

pub(super) fn review_workbench_service(
    state: &OperatorHttpState,
) -> Result<&DefaultReviewWorkbenchHarness, OperatorReviewError> {
    state
        .workbench
        .as_deref()
        .ok_or_else(|| OperatorReviewError::internal("review workbench stores are not configured"))
}

pub(super) fn review_evidence_secret_material(
    state: &OperatorHttpState,
) -> Result<String, OperatorReviewError> {
    std::env::var(&state.approval_receipt_signing_key_env)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            OperatorReviewError::internal(format!(
                "evidence signing key env `{}` is missing or empty",
                state.approval_receipt_signing_key_env
            ))
        })
}

fn count_set(values: &[Option<&str>]) -> usize {
    values.iter().filter(|value| value.is_some()).count()
}

pub(super) fn effective_limit(requested_limit: Option<usize>, max_limit: usize) -> usize {
    requested_limit.unwrap_or(max_limit).min(max_limit)
}

pub(super) fn limit_portfolio_list(
    mut list: EvolutionPortfolioList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> EvolutionPortfolioList {
    let limit = effective_limit(requested_limit, max_limit);
    list.portfolios = list.portfolios.into_iter().take(limit).collect();
    list.total_count = list.portfolios.len();
    list
}

pub(super) fn limit_packet_set_list(
    mut list: EvolutionGovernancePacketSetList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> EvolutionGovernancePacketSetList {
    let limit = effective_limit(requested_limit, max_limit);
    list.packet_sets = list.packet_sets.into_iter().take(limit).collect();
    list.total_count = list.packet_sets.len();
    list
}

pub(super) fn limit_portfolio_history_list(
    mut list: EvolutionPortfolioHistoryList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> EvolutionPortfolioHistoryList {
    let limit = effective_limit(requested_limit, max_limit);
    list.histories = list.histories.into_iter().take(limit).collect();
    list.total_count = list.histories.len();
    list
}

pub(super) fn limit_evidence_bundle_list(
    mut list: EvidenceBundleList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> EvidenceBundleList {
    let limit = effective_limit(requested_limit, max_limit);
    list.bundles = list.bundles.into_iter().take(limit).collect();
    list.total_count = list.bundles.len();
    list
}

pub(super) fn limit_maintenance_list(
    mut list: OperatorMaintenanceList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> OperatorMaintenanceList {
    let limit = effective_limit(requested_limit, max_limit);
    list.actions = list.actions.into_iter().take(limit).collect();
    list.total_count = list.actions.len();
    list
}

pub(super) fn limit_approval_set_list(
    mut list: ApprovalSetList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> ApprovalSetList {
    let limit = effective_limit(requested_limit, max_limit);
    list.sets = list.sets.into_iter().take(limit).collect();
    list.total_count = list.sets.len();
    list
}

pub(super) fn limit_approval_ledger_list(
    mut list: ApprovalLedgerList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> ApprovalLedgerList {
    let limit = effective_limit(requested_limit, max_limit);
    list.ledgers = list.ledgers.into_iter().take(limit).collect();
    list.total_count = list.ledgers.len();
    list
}

pub(super) fn limit_review_session_list(
    mut list: ReviewSessionList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> ReviewSessionList {
    let limit = effective_limit(requested_limit, max_limit);
    list.sessions = list.sessions.into_iter().take(limit).collect();
    list.total_count = list.sessions.len();
    list
}

pub(super) fn limit_review_session_export_list(
    mut list: crate::review_workbench::ReviewSessionExportList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> crate::review_workbench::ReviewSessionExportList {
    let limit = effective_limit(requested_limit, max_limit);
    list.exports = list.exports.into_iter().take(limit).collect();
    list.total_count = list.exports.len();
    list
}

pub(super) fn limit_review_capsule_list(
    mut list: ReviewCapsuleList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> ReviewCapsuleList {
    let limit = effective_limit(requested_limit, max_limit);
    list.capsules = list.capsules.into_iter().take(limit).collect();
    list.total_count = list.capsules.len();
    list
}

pub(super) fn limit_review_capsule_import_list(
    mut list: ReviewCapsuleImportList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> ReviewCapsuleImportList {
    let limit = effective_limit(requested_limit, max_limit);
    list.imports = list.imports.into_iter().take(limit).collect();
    list.total_count = list.imports.len();
    list
}

pub(super) fn limit_review_session_handoff_list(
    mut list: ReviewSessionMaintenanceHandoffList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> ReviewSessionMaintenanceHandoffList {
    let limit = effective_limit(requested_limit, max_limit);
    list.handoffs = list.handoffs.into_iter().take(limit).collect();
    list.total_count = list.handoffs.len();
    list
}

pub(super) fn limit_review_delegation_list(
    mut list: ReviewDelegationPacketList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> ReviewDelegationPacketList {
    let limit = effective_limit(requested_limit, max_limit);
    list.delegations = list.delegations.into_iter().take(limit).collect();
    list.total_count = list.delegations.len();
    list
}

pub(super) fn limit_review_session_promotion_readiness_list(
    mut list: ReviewSessionPromotionReadinessList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> ReviewSessionPromotionReadinessList {
    let limit = effective_limit(requested_limit, max_limit);
    list.readiness_reports = list.readiness_reports.into_iter().take(limit).collect();
    list.total_count = list.readiness_reports.len();
    list
}

pub(super) fn parse_review_artifact_refs_text(
    raw: &str,
) -> Result<Vec<ReviewArtifactRef>, OperatorReviewError> {
    let mut refs = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (kind, id) = trimmed.split_once(':').ok_or_else(|| {
            OperatorReviewError::bad_request(format!(
                "invalid artifact ref `{trimmed}`; expected kind:id"
            ))
        })?;
        let kind = kind.parse::<ReviewArtifactRefKind>().map_err(|_| {
            OperatorReviewError::bad_request(format!("unsupported review artifact kind `{kind}`"))
        })?;
        let id = id.trim();
        if id.is_empty() {
            return Err(OperatorReviewError::bad_request(format!(
                "invalid artifact ref `{trimmed}`; missing id"
            )));
        }
        refs.push(ReviewArtifactRef {
            kind,
            id: id.to_string(),
        });
    }
    Ok(refs)
}

pub(super) fn normalize_form_optional_text(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReviewEvidenceVerificationFilter {
    Passed,
    Failed,
    Unverified,
}

impl ReviewEvidenceVerificationFilter {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Unverified => "unverified",
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Passed => "Passed",
            Self::Failed => "Failed",
            Self::Unverified => "Unverified",
        }
    }
}

pub(super) fn parse_review_evidence_subject_kind(
    value: &str,
) -> Result<EvidenceSubjectKind, OperatorReviewError> {
    value.parse::<EvidenceSubjectKind>().map_err(|_| {
        OperatorReviewError::bad_request(format!("unsupported review subject_kind `{value}`"))
    })
}

pub(super) fn parse_review_evidence_verification_status(
    value: &str,
) -> Result<ReviewEvidenceVerificationFilter, OperatorReviewError> {
    match value {
        "passed" => Ok(ReviewEvidenceVerificationFilter::Passed),
        "failed" => Ok(ReviewEvidenceVerificationFilter::Failed),
        "unverified" => Ok(ReviewEvidenceVerificationFilter::Unverified),
        other => Err(OperatorReviewError::bad_request(format!(
            "unsupported review verification_status `{other}`"
        ))),
    }
}

pub(super) fn parse_review_promotion_recommendation(
    value: &str,
) -> Result<PromotionEvidenceRecommendation, OperatorReviewError> {
    match value {
        "ready_for_external_review" | "ready" => {
            Ok(PromotionEvidenceRecommendation::ReadyForExternalReview)
        }
        "blocked" => Ok(PromotionEvidenceRecommendation::Blocked),
        other => Err(OperatorReviewError::bad_request(format!(
            "unsupported promotion recommendation `{other}`"
        ))),
    }
}

pub(super) fn review_evidence_service(
    state: &OperatorHttpState,
) -> Result<&OperatorEvidenceReadService, OperatorReviewError> {
    state
        .evidence
        .as_deref()
        .ok_or_else(|| OperatorReviewError::internal("evidence stores are not configured"))
}

pub(super) fn filter_review_evidence_list(
    mut list: EvidenceBundleList,
    verification_status: Option<ReviewEvidenceVerificationFilter>,
) -> EvidenceBundleList {
    if let Some(filter) = verification_status {
        list.bundles.retain(|entry| match filter {
            ReviewEvidenceVerificationFilter::Passed => {
                entry.latest_verification_status == Some(EvidenceVerificationStatus::Passed)
            }
            ReviewEvidenceVerificationFilter::Failed => {
                entry.latest_verification_status == Some(EvidenceVerificationStatus::Failed)
            }
            ReviewEvidenceVerificationFilter::Unverified => {
                entry.latest_verification_status.is_none()
            }
        });
        list.total_count = list.bundles.len();
    }
    list
}

pub(super) fn filter_review_promotion_packet_list(
    mut list: PromotionEvidencePacketList,
    recommendation: Option<PromotionEvidenceRecommendation>,
) -> PromotionEvidencePacketList {
    if let Some(recommendation) = recommendation {
        let ready = recommendation == PromotionEvidenceRecommendation::ReadyForExternalReview;
        list.packets
            .retain(|entry| entry.ready_for_external_review == ready);
        list.total_count = list.packets.len();
    }
    list
}

pub(super) fn limit_promotion_packet_list(
    mut list: PromotionEvidencePacketList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> PromotionEvidencePacketList {
    let limit = effective_limit(requested_limit, max_limit);
    list.packets = list.packets.into_iter().take(limit).collect();
    list.total_count = list.packets.len();
    list
}
