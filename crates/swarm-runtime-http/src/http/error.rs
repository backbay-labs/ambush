use super::render::{escape_html, render_review_layout};
use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use serde::Serialize;
use swarm_evolution::evidence::EvidenceError;
use swarm_evolution::governance_prep::EvolutionGovernancePrepError;
use swarm_evolution::operator_maintenance::OperatorMaintenanceError;
use swarm_runtime::approval::ApprovalError;
use swarm_runtime::control::ControlError;
use swarm_runtime::http::rate_limit::HttpRateLimitRejection;
use swarm_runtime::portfolio::EvolutionPortfolioError;
use swarm_runtime::service::{ReadinessError, ServiceError};
use swarm_runtime_workbench::review_workbench::ReviewWorkbenchError;

#[derive(Debug, Clone, Serialize)]
struct OperatorApiErrorBody {
    error: &'static str,
    message: String,
}

pub(super) struct OperatorApiError {
    status: StatusCode,
    error: &'static str,
    message: String,
    retry_after_seconds: Option<u64>,
}

pub(super) struct OperatorReviewError {
    status: StatusCode,
    title: &'static str,
    message: String,
}

impl OperatorApiError {
    pub(super) fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error: "unauthorized",
            message: message.into(),
            retry_after_seconds: None,
        }
    }

    pub(super) fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "bad_request",
            message: message.into(),
            retry_after_seconds: None,
        }
    }

    pub(super) fn bad_gateway(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            error: "bad_gateway",
            message: message.into(),
            retry_after_seconds: None,
        }
    }

    pub(super) fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            error: "forbidden",
            message: message.into(),
            retry_after_seconds: None,
        }
    }

    pub(super) fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            error: "not_found",
            message: message.into(),
            retry_after_seconds: None,
        }
    }

    pub(super) fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: "internal_error",
            message: message.into(),
            retry_after_seconds: None,
        }
    }

    fn too_many_requests(message: impl Into<String>, retry_after_seconds: u64) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            error: "too_many_requests",
            message: message.into(),
            retry_after_seconds: Some(retry_after_seconds),
        }
    }
}

impl IntoResponse for OperatorApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(OperatorApiErrorBody {
                error: self.error,
                message: self.message,
            }),
        )
            .into_response();
        if let Some(retry_after_seconds) = self.retry_after_seconds
            && let Ok(value) = retry_after_seconds.to_string().parse()
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
}

impl OperatorReviewError {
    pub(super) fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            title: "Bad Request",
            message: message.into(),
        }
    }

    pub(super) fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            title: "Not Found",
            message: message.into(),
        }
    }

    pub(super) fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            title: "Forbidden",
            message: message.into(),
        }
    }

    pub(super) fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            title: "Review Surface Error",
            message: message.into(),
        }
    }
}

impl IntoResponse for OperatorReviewError {
    fn into_response(self) -> Response {
        (
            self.status,
            Html(render_review_layout(
                self.title,
                "",
                &format!(
                    "<section class=\"card\"><p>{}</p></section>",
                    escape_html(&self.message)
                ),
            )),
        )
            .into_response()
    }
}

pub(super) fn map_operator_rate_limit_rejection(
    rejection: HttpRateLimitRejection,
) -> OperatorApiError {
    OperatorApiError::too_many_requests(
        format!(
            "{} rate limit exceeded for source `{}` on `{}`; retry after {}ms",
            rate_limit_threshold_label(rejection.threshold),
            rejection.source,
            rejection.path,
            rejection.retry_after_ms
        ),
        retry_after_seconds(rejection.retry_after_ms),
    )
}

fn rate_limit_threshold_label(
    threshold: swarm_runtime::service::HttpRateLimitThreshold,
) -> &'static str {
    match threshold {
        swarm_runtime::service::HttpRateLimitThreshold::Burst => "burst",
        swarm_runtime::service::HttpRateLimitThreshold::Sustained => "sustained",
    }
}

fn retry_after_seconds(retry_after_ms: u64) -> u64 {
    retry_after_ms.max(1).div_ceil(1_000)
}

fn map_service_api_error(error: ServiceError) -> OperatorApiError {
    match error {
        ServiceError::Readiness {
            component,
            source: ReadinessError::SubstrateNotReady { backend },
        } => OperatorApiError::internal(format!(
            "runtime readiness check failed for {component}: backend `{backend}` is not ready"
        )),
        ServiceError::Readiness {
            component,
            source: ReadinessError::SubstrateNotDurable { backend },
        } => OperatorApiError::internal(format!(
            "runtime readiness check failed for {component}: backend `{backend}` is not durable but live response requires durability"
        )),
        other => OperatorApiError::internal(other.to_string()),
    }
}

fn map_service_review_error(error: ServiceError) -> OperatorReviewError {
    match error {
        ServiceError::Readiness {
            component,
            source: ReadinessError::SubstrateNotReady { backend },
        } => OperatorReviewError::internal(format!(
            "runtime readiness check failed for {component}: backend `{backend}` is not ready"
        )),
        ServiceError::Readiness {
            component,
            source: ReadinessError::SubstrateNotDurable { backend },
        } => OperatorReviewError::internal(format!(
            "runtime readiness check failed for {component}: backend `{backend}` is not durable but live response requires durability"
        )),
        other => OperatorReviewError::internal(other.to_string()),
    }
}

pub(super) fn map_control_error(error: ControlError) -> OperatorApiError {
    match error {
        ControlError::NotFound { entity, lookup } => {
            OperatorApiError::not_found(format!("{entity} `{lookup}` was not found"))
        }
        ControlError::Service(error) => map_service_api_error(error),
        other => OperatorApiError::internal(other.to_string()),
    }
}

pub(super) fn map_evidence_api_error(error: EvidenceError) -> OperatorApiError {
    match error {
        EvidenceError::ArtifactNotFound { kind, id } => {
            OperatorApiError::not_found(format!("artifact `{kind}` with id `{id}` was not found"))
        }
        EvidenceError::Control(error) => map_control_error(error),
        other => OperatorApiError::internal(other.to_string()),
    }
}

pub(super) fn map_portfolio_error(error: EvolutionPortfolioError) -> OperatorApiError {
    match error {
        EvolutionPortfolioError::SelectionNotFound { selection_id } => OperatorApiError::not_found(
            format!("ranked-candidate selection `{selection_id}` was not found"),
        ),
        EvolutionPortfolioError::RankingNotFound { ranking_id } => {
            OperatorApiError::not_found(format!("candidate ranking `{ranking_id}` was not found"))
        }
        EvolutionPortfolioError::PortfolioNotFound { portfolio_id } => {
            OperatorApiError::not_found(format!("portfolio `{portfolio_id}` was not found"))
        }
        EvolutionPortfolioError::PortfolioEntryNotFound {
            portfolio_id,
            entry_id,
        } => OperatorApiError::not_found(format!(
            "portfolio entry `{entry_id}` was not found in portfolio `{portfolio_id}`"
        )),
        EvolutionPortfolioError::GovernancePacketNotFound { packet_id } => {
            OperatorApiError::not_found(format!(
                "governance review packet `{packet_id}` was not found"
            ))
        }
        EvolutionPortfolioError::InvalidPortfolioRequest { .. }
        | EvolutionPortfolioError::InvalidDecision { .. } => {
            OperatorApiError::bad_request(error.to_string())
        }
        other => OperatorApiError::internal(other.to_string()),
    }
}

pub(super) fn map_governance_prep_error(error: EvolutionGovernancePrepError) -> OperatorApiError {
    match error {
        EvolutionGovernancePrepError::GovernancePacketNotFound { packet_id } => {
            OperatorApiError::not_found(format!(
                "governance review packet `{packet_id}` was not found"
            ))
        }
        EvolutionGovernancePrepError::PacketSetNotFound { packet_set_id } => {
            OperatorApiError::not_found(format!(
                "governance packet set `{packet_set_id}` was not found"
            ))
        }
        EvolutionGovernancePrepError::PortfolioHistoryNotFound { history_id } => {
            OperatorApiError::not_found(format!("portfolio history `{history_id}` was not found"))
        }
        EvolutionGovernancePrepError::InvalidPacketSetRequest { .. }
        | EvolutionGovernancePrepError::PacketNotInSet { .. }
        | EvolutionGovernancePrepError::InconsistentPacketEvidence { .. } => {
            OperatorApiError::bad_request(error.to_string())
        }
        other => OperatorApiError::internal(other.to_string()),
    }
}

pub(super) fn map_review_workbench_error(error: ReviewWorkbenchError) -> OperatorReviewError {
    match error {
        ReviewWorkbenchError::InvalidRequest(message) => OperatorReviewError::bad_request(message),
        ReviewWorkbenchError::SessionNotFound { session_id } => {
            OperatorReviewError::not_found(format!("review session `{session_id}` was not found"))
        }
        ReviewWorkbenchError::ExportNotFound { export_id } => OperatorReviewError::not_found(
            format!("review session export `{export_id}` was not found"),
        ),
        ReviewWorkbenchError::CapsuleNotFound { capsule_id } => {
            OperatorReviewError::not_found(format!("review capsule `{capsule_id}` was not found"))
        }
        ReviewWorkbenchError::CapsuleImportNotFound { import_id } => {
            OperatorReviewError::not_found(format!(
                "review capsule import `{import_id}` was not found"
            ))
        }
        ReviewWorkbenchError::DelegationNotFound { delegation_id } => {
            OperatorReviewError::not_found(format!(
                "review delegation `{delegation_id}` was not found"
            ))
        }
        ReviewWorkbenchError::HandoffNotFound { handoff_id } => OperatorReviewError::not_found(
            format!("review session handoff `{handoff_id}` was not found"),
        ),
        ReviewWorkbenchError::ReadinessNotFound { readiness_id } => OperatorReviewError::not_found(
            format!("review session readiness `{readiness_id}` was not found"),
        ),
        other => OperatorReviewError::internal(other.to_string()),
    }
}

pub(super) fn map_control_review_error(error: ControlError) -> OperatorReviewError {
    match error {
        ControlError::NotFound { entity, lookup } => {
            OperatorReviewError::not_found(format!("{entity} `{lookup}` was not found"))
        }
        ControlError::Service(error) => map_service_review_error(error),
        other => OperatorReviewError::internal(other.to_string()),
    }
}

pub(super) fn map_review_evidence_error(error: EvidenceError) -> OperatorReviewError {
    match error {
        EvidenceError::ArtifactNotFound { kind, id } => OperatorReviewError::not_found(format!(
            "artifact `{kind}` with id `{id}` was not found"
        )),
        EvidenceError::Control(error) => map_control_review_error(error),
        other => OperatorReviewError::internal(other.to_string()),
    }
}

pub(super) fn map_approval_error(error: ApprovalError) -> OperatorApiError {
    match error {
        ApprovalError::ApprovalSetNotFound { set_id } => {
            OperatorApiError::not_found(format!("approval set `{set_id}` was not found"))
        }
        ApprovalError::ApprovalLedgerNotFound { ledger_id } => {
            OperatorApiError::not_found(format!("approval ledger `{ledger_id}` was not found"))
        }
        ApprovalError::ApprovalVerdictNotFound { verdict_id } => {
            OperatorApiError::not_found(format!("approval verdict `{verdict_id}` was not found"))
        }
        ApprovalError::ApprovalReceiptPackNotFound { pack_id } => {
            OperatorApiError::not_found(format!("approval receipt pack `{pack_id}` was not found"))
        }
        ApprovalError::MissingLedgerForSet { set_id } => {
            OperatorApiError::not_found(format!("approval set `{set_id}` does not have a ledger"))
        }
        ApprovalError::AmbiguousLedgerForSet { .. }
        | ApprovalError::InvalidApprovalSetRequest { .. }
        | ApprovalError::InvalidVerdictRequest { .. }
        | ApprovalError::InvalidReceiptPack { .. }
        | ApprovalError::DuplicateVoter { .. }
        | ApprovalError::IneligibleVoter { .. }
        | ApprovalError::InvalidSignature { .. } => {
            OperatorApiError::bad_request(error.to_string())
        }
        ApprovalError::VerdictStoreNotConfigured | ApprovalError::ReceiptPackStoreNotConfigured => {
            OperatorApiError::internal(error.to_string())
        }
        ApprovalError::MissingSigningKey { .. } => OperatorApiError::bad_request(error.to_string()),
        ApprovalError::SetStore(_)
        | ApprovalError::LedgerStore(_)
        | ApprovalError::VerdictStore(_)
        | ApprovalError::ReceiptPackStore(_)
        | ApprovalError::Crypto(_)
        | ApprovalError::Spine(_) => OperatorApiError::internal(error.to_string()),
    }
}

pub(super) fn map_maintenance_error(error: OperatorMaintenanceError) -> OperatorApiError {
    match error {
        OperatorMaintenanceError::Store(_) => OperatorApiError::internal(error.to_string()),
        OperatorMaintenanceError::Portfolio(error) => map_portfolio_error(error),
        OperatorMaintenanceError::GovernancePrep(error) => map_governance_prep_error(error),
        OperatorMaintenanceError::Evidence(error) => map_evidence_api_error(error),
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    #[test]
    fn control_service_readiness_error_maps_to_internal_api_error() {
        let error = super::map_control_error(swarm_runtime::control::ControlError::Service(
            swarm_runtime::service::ServiceError::Readiness {
                component: "substrate",
                source: swarm_runtime::service::ReadinessError::SubstrateNotDurable {
                    backend: "in_memory".to_string(),
                },
            },
        ));

        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.error, "internal_error");
        assert!(error.message.contains("substrate"));
        assert!(error.message.contains("not durable"));
    }

    #[test]
    fn portfolio_invalid_request_maps_to_bad_request() {
        let error = super::map_portfolio_error(
            swarm_runtime::portfolio::EvolutionPortfolioError::InvalidPortfolioRequest {
                reason: "missing cohort".to_string(),
            },
        );

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.error, "bad_request");
        assert!(error.message.contains("missing cohort"));
    }

    #[test]
    fn review_evidence_artifact_not_found_maps_to_not_found() {
        let error = super::map_review_evidence_error(
            swarm_evolution::evidence::EvidenceError::ArtifactNotFound {
                kind: "replay_bundle",
                id: "bundle:missing".to_string(),
            },
        );

        assert_eq!(error.status, StatusCode::NOT_FOUND);
        assert_eq!(error.title, "Not Found");
        assert!(error.message.contains("bundle:missing"));
    }
}
