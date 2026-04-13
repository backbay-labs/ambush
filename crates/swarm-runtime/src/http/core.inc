use crate::approval::{
    ApprovalError, ApprovalLedgerList, ApprovalLedgerLookup, ApprovalSetList, ApprovalSetReport,
    ApprovalVerdictStatus, DefaultApprovalHarness, ThresholdRule,
};
use crate::config::{RuntimeConfigError, load_config};
use crate::control::{
    ControlEnvelope, ControlError, DefaultControlPlane, IncidentArtifactView,
    IncidentLookupSelector, InvestigationArtifactView, InvestigationLookupSelector,
    OPERATOR_API_SCHEMA_VERSION_HEADER, ReplayArtifactView, ReplayLookupSelector,
    resolve_operator_api_schema_version,
};
use crate::detection::metrics::{CriticalPathMetrics, encode_metrics};
use crate::evidence::{
    DefaultEvidenceHarness, EvidenceBundle, EvidenceBundleList, EvidenceError,
    EvidenceExportRequest, EvidenceHarnessPaths, EvidenceSubjectKind, EvidenceVerificationReport,
    EvidenceVerificationStatus, OperatorEvidenceReadService, PromotionEvidencePacket,
    PromotionEvidencePacketList, PromotionEvidenceRecommendation,
};
use crate::governance_prep::{
    DefaultEvolutionGovernancePrepHarness, EvolutionGovernancePacketSetList,
    EvolutionGovernancePrepError, EvolutionPortfolioHistoryList,
};
use crate::operator_maintenance::{
    OperatorMaintenanceError, OperatorMaintenanceExecution, OperatorMaintenanceList,
    OperatorMaintenanceRecord, OperatorMaintenanceRequest, OperatorMaintenanceService,
    OperatorMaintenanceStatus,
};
use crate::portfolio::{
    DefaultEvolutionPortfolioHarness, EvolutionPortfolioEntryReviewState, EvolutionPortfolioError,
    EvolutionPortfolioList,
};
use crate::review_workbench::{
    DefaultReviewWorkbenchHarness, ReviewArtifactRef, ReviewArtifactRefKind, ReviewCapsule,
    ReviewCapsuleImport, ReviewCapsuleImportList, ReviewCapsuleImportRequest, ReviewCapsuleList,
    ReviewDelegationCreateRequest, ReviewDelegationPacket, ReviewDelegationPacketList,
    ReviewSessionCreateRequest, ReviewSessionExport, ReviewSessionList,
    ReviewSessionMaintenanceHandoff, ReviewSessionMaintenanceHandoffList,
    ReviewSessionPromotionReadiness, ReviewSessionPromotionReadinessList, ReviewSessionResolved,
    ReviewSessionReverifyRequest, ReviewWorkbenchError,
};
use crate::serve::{ServeError, serve_with_listener};
use crate::service::{OperatorStatusReport, ReadinessError, ServiceError};
use axum::extract::{Extension, Form, Path as RoutePath, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use swarm_core::config::{OperatorScope, SwarmConfig};
use swarm_core::pheromone::{ThreatClassConfig, ThreatIntelEntry, ThreatIntelIndicatorType};
use swarm_core::types::{
    ProvidenceIncidentStatus, ProvidenceReconciliationOutcome, ResponseRehearsalPreview,
};
use swarm_crypto::DetachedSignature;

/// Result directories required to expose authenticated operator artifacts through HTTP.
#[derive(Debug, Clone)]
pub struct OperatorSurfacePaths {
    pub evidence_signer_id: String,
    pub evidence_signing_key_env: String,
    pub verification_results_dir: PathBuf,
    pub shadow_results_dir: PathBuf,
    pub promotion_review_results_dir: PathBuf,
    pub canary_results_dir: PathBuf,
    pub promotion_results_dir: PathBuf,
    pub evolution_ranking_results_dir: PathBuf,
    pub evolution_selection_results_dir: PathBuf,
    pub evolution_portfolio_results_dir: PathBuf,
    pub evolution_governance_review_packet_results_dir: PathBuf,
    pub evolution_packet_set_results_dir: PathBuf,
    pub strategy_memory_results_dir: PathBuf,
    pub evolution_portfolio_history_results_dir: PathBuf,
    pub operator_maintenance_results_dir: PathBuf,
    pub evidence_results_dir: PathBuf,
    pub evidence_verification_results_dir: PathBuf,
    pub promotion_evidence_results_dir: PathBuf,
    pub review_session_results_dir: PathBuf,
    pub review_session_export_results_dir: PathBuf,
    pub review_session_readiness_results_dir: PathBuf,
    pub review_session_handoff_results_dir: PathBuf,
    pub review_capsule_results_dir: PathBuf,
    pub review_capsule_import_results_dir: PathBuf,
    pub review_delegation_results_dir: PathBuf,
    pub approval_set_results_dir: PathBuf,
    pub approval_ledger_results_dir: PathBuf,
    pub approval_verdict_results_dir: PathBuf,
    pub approval_receipt_pack_results_dir: PathBuf,
}

/// Errors raised while building or serving the authenticated operator surface.
#[derive(Debug, thiserror::Error)]
pub enum OperatorHttpError {
    #[error(transparent)]
    Config(#[from] RuntimeConfigError),

    #[error(transparent)]
    Control(#[from] ControlError),

    #[error(transparent)]
    Evidence(#[from] crate::evidence::EvidenceError),

    #[error(transparent)]
    Portfolio(#[from] crate::portfolio::EvolutionPortfolioError),

    #[error(transparent)]
    GovernancePrep(#[from] crate::governance_prep::EvolutionGovernancePrepError),

    #[error(transparent)]
    Maintenance(#[from] OperatorMaintenanceError),

    #[error(transparent)]
    ReviewWorkbench(#[from] ReviewWorkbenchError),

    #[error(transparent)]
    Approval(#[from] ApprovalError),

    #[error("operator surface is disabled in repo config")]
    Disabled,

    #[error(
        "operator surface token env `{env_name}` is missing or empty; set it before starting the server"
    )]
    MissingTokenEnv { env_name: String },

    #[error("failed to bind operator surface at `{bind_addr}`: {source}")]
    Bind {
        bind_addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("operator surface server exited: {0}")]
    Serve(#[from] ServeError),
}

#[derive(Clone)]
pub struct LocalOperatorSurface {
    bind_addr: SocketAddr,
    state: OperatorHttpState,
}

#[derive(Clone)]
struct OperatorHttpState {
    auth: OperatorAuthState,
    control: Arc<DefaultControlPlane>,
    portfolio: Option<Arc<DefaultEvolutionPortfolioHarness>>,
    governance_prep: Option<Arc<DefaultEvolutionGovernancePrepHarness>>,
    maintenance: Option<Arc<OperatorMaintenanceService>>,
    evidence: Option<Arc<OperatorEvidenceReadService>>,
    evidence_harness: Option<Arc<DefaultEvidenceHarness>>,
    workbench: Option<Arc<DefaultReviewWorkbenchHarness>>,
    approval: Option<Arc<DefaultApprovalHarness>>,
    prometheus: Option<CriticalPathMetrics>,
    runtime_base_url: String,
    max_list_results: usize,
    approval_receipt_signer_id: String,
    approval_receipt_signing_key_env: String,
}

#[derive(Debug, Clone)]
struct AuthenticatedOperatorPrincipal {
    operator_id: Arc<str>,
    scopes: Vec<OperatorScope>,
}

impl AuthenticatedOperatorPrincipal {
    fn has_scope(&self, scope: OperatorScope) -> bool {
        self.scopes.contains(&scope)
    }
}

#[derive(Debug, Clone)]
struct ResolvedOperatorPrincipal {
    principal: AuthenticatedOperatorPrincipal,
    expected_token: Arc<str>,
}

#[derive(Debug, Clone)]
struct OperatorAuthState {
    principals: Arc<Vec<ResolvedOperatorPrincipal>>,
}

impl OperatorAuthState {
    fn from_config(config: &SwarmConfig) -> Result<Self, OperatorHttpError> {
        let principals = config
            .operator
            .auth
            .effective_principals()
            .into_iter()
            .map(|principal| {
                let expected_token = std::env::var(&principal.token_env)
                    .ok()
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| OperatorHttpError::MissingTokenEnv {
                        env_name: principal.token_env.clone(),
                    })?;
                Ok(ResolvedOperatorPrincipal {
                    principal: AuthenticatedOperatorPrincipal {
                        operator_id: Arc::from(principal.operator_id),
                        scopes: principal.scopes,
                    },
                    expected_token: Arc::from(expected_token),
                })
            })
            .collect::<Result<Vec<_>, OperatorHttpError>>()?;
        Ok(Self {
            principals: Arc::new(principals),
        })
    }

    fn authenticate(&self, token: &str) -> Option<AuthenticatedOperatorPrincipal> {
        self.principals.iter().find_map(|principal| {
            (principal.expected_token.as_ref() == token).then(|| principal.principal.clone())
        })
    }

    fn operator_has_scope(&self, operator_id: &str, scope: OperatorScope) -> bool {
        self.principals.iter().any(|principal| {
            principal.principal.operator_id.as_ref() == operator_id
                && principal.principal.has_scope(scope)
        })
    }
}

#[derive(Debug, Clone, Serialize)]
struct OperatorApiErrorBody {
    error: &'static str,
    message: String,
}

#[derive(Debug, Deserialize)]
struct ReplayLookupQuery {
    bundle_id: Option<String>,
    hunt_id: Option<String>,
    receipt_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InvestigationLookupQuery {
    investigation_id: Option<String>,
    hunt_id: Option<String>,
    receipt_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IncidentLookupQuery {
    incident_id: Option<String>,
    hunt_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ThreatIntelLookupQuery {
    indicator_type: ThreatIntelIndicatorType,
    value: String,
    now: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct NotificationDeadLetterListQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct NotificationDeadLetterReplayRequest {
    receipt_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct PortfolioListQuery {
    cohort: Option<String>,
    review_state: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct CohortListQuery {
    cohort: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct MaintenanceActionListQuery {
    status: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct ApprovalSetListQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct ApprovalLedgerListQuery {
    approval_set_id: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct EvidenceListQuery {
    subject_kind: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct ReviewEvidenceListQuery {
    subject_kind: Option<String>,
    verification_status: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct ReviewHomeQuery {
    hunt_id: Option<String>,
    incident_id: Option<String>,
    bundle_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReviewPromotionPacketListQuery {
    recommendation: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct ReviewSessionListQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct ReviewSessionCreateForm {
    title: Option<String>,
    notes: Option<String>,
    artifact_refs: String,
}

#[derive(Debug, Deserialize)]
struct ReviewSessionHandoffForm {
    selected_artifact_refs: Option<String>,
    expected_key_id: Option<String>,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct ReviewCapsuleImportForm {
    source_path: String,
    expected_key_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReviewDelegationForm {
    reason: String,
    delegate_label: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApprovalSetCreateRequest {
    eligible_voters: Vec<String>,
    threshold_required: usize,
    promotion_evidence_ref: String,
}

#[derive(Debug, Deserialize)]
struct ApprovalVoteAppendRequest {
    voter_id: String,
    signature: DetachedSignature,
}

struct OperatorApiError {
    status: StatusCode,
    error: &'static str,
    message: String,
}

struct OperatorReviewError {
    status: StatusCode,
    title: &'static str,
    message: String,
}

#[derive(Debug, Clone)]
struct ReviewHomeContext {
    selected_bundle: Option<ReplayArtifactView>,
    latest_rehearsal_bundle: Option<ReplayArtifactView>,
    incident: Option<IncidentArtifactView>,
    signed_rehearsal_bundle_id: Option<String>,
}

impl OperatorApiError {
    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error: "unauthorized",
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "bad_request",
            message: message.into(),
        }
    }

    fn bad_gateway(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            error: "bad_gateway",
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            error: "forbidden",
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            error: "not_found",
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: "internal_error",
            message: message.into(),
        }
    }
}

impl IntoResponse for OperatorApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(OperatorApiErrorBody {
                error: self.error,
                message: self.message,
            }),
        )
            .into_response()
    }
}

impl OperatorReviewError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            title: "Bad Request",
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            title: "Not Found",
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            title: "Forbidden",
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
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

fn evidence_harness_paths(paths: &OperatorSurfacePaths) -> EvidenceHarnessPaths {
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

impl LocalOperatorSurface {
    /// Build the local operator surface from repo-owned config and process env.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, OperatorHttpError> {
        let path = path.as_ref();
        let config = load_config(path)?;
        Self::from_config(path, config)
    }

    /// Build the local operator surface from an already validated config.
    pub fn from_config(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
    ) -> Result<Self, OperatorHttpError> {
        Self::from_config_with_paths(config_path, config, None)
    }

    /// Build the local operator surface with additional evolution artifact stores.
    pub fn from_config_and_paths(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
        paths: OperatorSurfacePaths,
    ) -> Result<Self, OperatorHttpError> {
        Self::from_config_with_paths(config_path, config, Some(paths))
    }

    fn from_config_with_paths(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
        paths: Option<OperatorSurfacePaths>,
    ) -> Result<Self, OperatorHttpError> {
        if !config.operator.enabled {
            return Err(OperatorHttpError::Disabled);
        }

        let bind_addr =
            config
                .operator
                .bind_addr
                .parse()
                .map_err(|_| RuntimeConfigError::Validation {
                    source_name: format!(
                        "operator_surface.bind_addr:{}",
                        config.operator.bind_addr
                    ),
                    source: swarm_core::config::ConfigValidationError::InvalidField {
                        field: "operator_surface.bind_addr",
                        reason: "must be a valid socket address".to_string(),
                    },
                })?;
        let auth = OperatorAuthState::from_config(&config)?;

        let config_path = config_path.into();
        let control = Arc::new(DefaultControlPlane::from_config(
            config_path.clone(),
            config.clone(),
        )?);
        let prometheus = control.stack.service.prometheus_metrics().cloned();
        let approval_receipt_signer_id = paths
            .as_ref()
            .map(|value| value.evidence_signer_id.clone())
            .unwrap_or_else(|| "local-approval-signer".to_string());
        let approval_receipt_signing_key_env = paths
            .as_ref()
            .map(|value| value.evidence_signing_key_env.clone())
            .unwrap_or_else(|| "SWARM_EVIDENCE_SIGNING_KEY".to_string());
        let (
            portfolio,
            governance_prep,
            maintenance,
            evidence,
            evidence_harness,
            workbench,
            approval,
        ) = if let Some(paths) = paths {
            let portfolio = DefaultEvolutionPortfolioHarness::from_path(
                &paths.evolution_ranking_results_dir,
                &paths.evolution_selection_results_dir,
                &paths.evolution_portfolio_results_dir,
                &paths.evolution_governance_review_packet_results_dir,
            )?;
            let governance_prep = DefaultEvolutionGovernancePrepHarness::from_path(
                &paths.evolution_governance_review_packet_results_dir,
                &paths.evolution_packet_set_results_dir,
                &paths.strategy_memory_results_dir,
                &paths.evolution_portfolio_history_results_dir,
            )?;
            let maintenance = OperatorMaintenanceService::from_paths(&paths)?;
            let evidence = OperatorEvidenceReadService::from_store_paths(
                &paths.evidence_results_dir,
                &paths.evidence_verification_results_dir,
                &paths.promotion_evidence_results_dir,
            )?;
            let evidence_harness = DefaultEvidenceHarness::from_control(
                control.clone(),
                evidence_harness_paths(&paths),
            )?;
            let workbench = DefaultReviewWorkbenchHarness::from_paths(&paths)?;
            let approval = DefaultApprovalHarness::from_path(
                &config_path,
                &paths.approval_verdict_results_dir,
                &paths.approval_receipt_pack_results_dir,
                &paths.approval_set_results_dir,
                &paths.approval_ledger_results_dir,
            )?;
            (
                Some(Arc::new(portfolio)),
                Some(Arc::new(governance_prep)),
                Some(Arc::new(maintenance)),
                Some(Arc::new(evidence)),
                Some(Arc::new(evidence_harness)),
                Some(Arc::new(workbench)),
                Some(Arc::new(approval)),
            )
        } else {
            (None, None, None, None, None, None, None)
        };

        Ok(Self {
            bind_addr,
            state: OperatorHttpState {
                auth,
                control,
                portfolio,
                governance_prep,
                maintenance,
                evidence,
                evidence_harness,
                workbench,
                approval,
                prometheus,
                runtime_base_url: config.operator.runtime_base_url.clone(),
                max_list_results: config.operator.max_list_results,
                approval_receipt_signer_id,
                approval_receipt_signing_key_env,
            },
        })
    }

    /// Build the local operator surface from config on disk plus evolution artifact stores.
    pub fn from_paths(
        config_path: impl AsRef<Path>,
        paths: OperatorSurfacePaths,
    ) -> Result<Self, OperatorHttpError> {
        let config_path = config_path.as_ref();
        let config = load_config(config_path)?;
        Self::from_config_and_paths(config_path, config, paths)
    }

    /// Bound socket address for the local surface.
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Build the authenticated router.
    pub fn router(&self) -> Router {
        let protected = Router::new()
            .route("/v1/operator/status", get(status_handler))
            .route(
                "/v1/operator/pheromone/threat-class-configs",
                get(threat_class_config_list_handler).post(threat_class_config_upsert_handler),
            )
            .route(
                "/v1/operator/threat-intel/entries",
                get(threat_intel_entry_lookup_handler).post(threat_intel_entry_upsert_handler),
            )
            .route(
                "/v1/notifications/dead-letter/{channel}",
                get(notification_dead_letter_list_handler)
                    .post(notification_dead_letter_replay_handler),
            )
            .route("/v1/operator/replay", get(replay_handler))
            .route("/v1/operator/investigation", get(investigation_handler))
            .route("/v1/operator/incident", get(incident_handler))
            .route("/v1/operator/review", get(review_home_handler))
            .route(
                "/v1/operator/review/rehearsals/{bundle_id}/export",
                post(review_rehearsal_export_handler),
            )
            .route(
                "/v1/operator/review/sessions",
                get(review_session_list_handler).post(review_session_create_handler),
            )
            .route(
                "/v1/operator/review/sessions/{session_id}",
                get(review_session_handler),
            )
            .route(
                "/v1/operator/review/sessions/{session_id}/export",
                post(review_session_export_handler),
            )
            .route(
                "/v1/operator/review/sessions/{session_id}/capsules",
                post(review_session_capsule_handler),
            )
            .route(
                "/v1/operator/review/sessions/{session_id}/promotion-readiness",
                post(review_session_promotion_readiness_handler),
            )
            .route(
                "/v1/operator/review/sessions/{session_id}/handoffs/reverify",
                post(review_session_handoff_handler),
            )
            .route(
                "/v1/operator/review/exports/{export_id}",
                get(review_session_export_page_handler),
            )
            .route(
                "/v1/operator/review/capsules/{capsule_id}",
                get(review_capsule_page_handler),
            )
            .route(
                "/v1/operator/review/capsules/{capsule_id}/delegations",
                post(review_capsule_delegation_handler),
            )
            .route(
                "/v1/operator/review/capsule-imports",
                post(review_capsule_import_handler),
            )
            .route(
                "/v1/operator/review/capsule-imports/{import_id}",
                get(review_capsule_import_page_handler),
            )
            .route(
                "/v1/operator/review/capsule-imports/{import_id}/delegations",
                post(review_capsule_import_delegation_handler),
            )
            .route(
                "/v1/operator/review/delegations/{delegation_id}",
                get(review_delegation_page_handler),
            )
            .route(
                "/v1/operator/review/promotion-readiness/{readiness_id}",
                get(review_session_promotion_readiness_page_handler),
            )
            .route(
                "/v1/operator/review/promotion-readiness/{readiness_id}/capsules",
                post(review_session_readiness_capsule_handler),
            )
            .route(
                "/v1/operator/review/handoffs/{handoff_id}",
                get(review_session_handoff_page_handler),
            )
            .route(
                "/v1/operator/review/evidence",
                get(review_evidence_list_handler),
            )
            .route(
                "/v1/operator/review/evidence/{bundle_id}",
                get(review_evidence_bundle_handler),
            )
            .route(
                "/v1/operator/review/verifications/{verification_id}",
                get(review_evidence_verification_handler),
            )
            .route(
                "/v1/operator/review/promotion-packets",
                get(review_promotion_packet_list_handler),
            )
            .route(
                "/v1/operator/review/promotion-packets/{packet_id}",
                get(review_promotion_packet_handler),
            )
            .route(
                "/v1/operator/evidence/bundles",
                get(evidence_bundle_list_handler),
            )
            .route(
                "/v1/operator/evidence/bundles/{bundle_id}",
                get(evidence_bundle_handler),
            )
            .route(
                "/v1/operator/evidence/verifications/{verification_id}",
                get(evidence_verification_handler),
            )
            .route(
                "/v1/operator/evidence/promotion-packets/{packet_id}",
                get(promotion_evidence_packet_handler),
            )
            .route(
                "/v1/operator/approval-sets",
                get(approval_set_list_handler).post(approval_set_create_handler),
            )
            .route(
                "/v1/operator/approval-sets/{set_id}",
                get(approval_set_handler),
            )
            .route(
                "/v1/operator/approval-ledgers",
                get(approval_ledger_list_handler),
            )
            .route(
                "/v1/operator/approval-ledgers/{ledger_id}",
                get(approval_ledger_handler),
            )
            .route(
                "/v1/operator/approval-ledgers/{ledger_id}/vote",
                post(approval_vote_append_handler),
            )
            .route(
                "/v1/operator/evolution/portfolios",
                get(portfolio_list_handler),
            )
            .route(
                "/v1/operator/evolution/portfolios/{portfolio_id}",
                get(portfolio_handler),
            )
            .route(
                "/v1/operator/evolution/governance-packets/{packet_id}",
                get(governance_packet_handler),
            )
            .route(
                "/v1/operator/evolution/packet-sets",
                get(packet_set_list_handler),
            )
            .route(
                "/v1/operator/evolution/packet-sets/{packet_set_id}",
                get(packet_set_handler),
            )
            .route(
                "/v1/operator/evolution/portfolio-histories",
                get(portfolio_history_list_handler),
            )
            .route(
                "/v1/operator/evolution/portfolio-histories/{history_id}",
                get(portfolio_history_handler),
            )
            .route(
                "/v1/operator/maintenance/actions",
                get(maintenance_action_list_handler).post(maintenance_action_handler),
            )
            .route(
                "/v1/operator/maintenance/actions/{action_id}",
                get(maintenance_action_lookup_handler),
            )
            .with_state(self.state.clone())
            .layer(middleware::from_fn_with_state(
                self.state.auth.clone(),
                require_bearer_auth,
            ))
            .layer(middleware::from_fn(
                require_supported_operator_api_schema_version,
            ));

        Router::new()
            .route("/metrics", get(metrics_handler))
            .with_state(self.state.clone())
            .merge(protected)
    }

    /// Serve the authenticated operator surface until the process exits.
    pub async fn serve(self) -> Result<(), OperatorHttpError> {
        let listener = tokio::net::TcpListener::bind(self.bind_addr)
            .await
            .map_err(|source| OperatorHttpError::Bind {
                bind_addr: self.bind_addr,
                source,
            })?;
        serve_with_listener(
            listener,
            self.router(),
            self.state.control.stack.service.config.tls.clone(),
            std::future::pending(),
        )
        .await
        .map_err(OperatorHttpError::Serve)
    }
}

async fn status_handler(
    State(state): State<OperatorHttpState>,
) -> Result<Json<ControlEnvelope<OperatorStatusReport>>, OperatorApiError> {
    let status = state.control.status().await.map_err(map_control_error)?;
    Ok(Json(status))
}

async fn threat_class_config_list_handler(
    State(state): State<OperatorHttpState>,
) -> Result<Json<ControlEnvelope<Vec<ThreatClassConfig>>>, OperatorApiError> {
    let configs = state
        .control
        .threat_class_configs()
        .await
        .map_err(map_control_error)?;
    Ok(Json(configs))
}

async fn threat_class_config_upsert_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<OperatorHttpState>,
    Json(config): Json<ThreatClassConfig>,
) -> Result<Json<ControlEnvelope<ThreatClassConfig>>, OperatorApiError> {
    require_operator_api_scope(&principal, OperatorScope::Maintenance, "maintenance")?;
    let stored = state
        .control
        .store_threat_class_config(config)
        .await
        .map_err(map_control_error)?;
    Ok(Json(stored))
}

async fn threat_intel_entry_lookup_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<ThreatIntelLookupQuery>,
) -> Result<Json<ControlEnvelope<Option<ThreatIntelEntry>>>, OperatorApiError> {
    if query.value.trim().is_empty() {
        return Err(OperatorApiError::bad_request(
            "threat-intel lookup requires a non-empty `value` query parameter",
        ));
    }
    let entry = state
        .control
        .query_threat_intel_entry(
            query.indicator_type,
            query.value,
            query.now.unwrap_or_else(now_ms),
        )
        .await
        .map_err(map_control_error)?;
    Ok(Json(entry))
}

async fn threat_intel_entry_upsert_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<OperatorHttpState>,
    Json(entry): Json<ThreatIntelEntry>,
) -> Result<Json<ControlEnvelope<ThreatIntelEntry>>, OperatorApiError> {
    require_operator_api_scope(&principal, OperatorScope::Maintenance, "maintenance")?;
    if entry.value.trim().is_empty() {
        return Err(OperatorApiError::bad_request(
            "threat-intel entry requires a non-empty `value` field",
        ));
    }
    let stored = state
        .control
        .store_threat_intel_entry(entry)
        .await
        .map_err(map_control_error)?;
    Ok(Json(stored))
}

async fn notification_dead_letter_list_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(channel): RoutePath<String>,
    Query(query): Query<NotificationDeadLetterListQuery>,
) -> Result<Json<ControlEnvelope<Vec<swarm_response::DeadLetterEntry>>>, OperatorApiError> {
    let entries = state
        .control
        .notification_dead_letters(
            &channel,
            Some(effective_limit(query.limit, state.max_list_results)),
        )
        .await
        .map_err(map_control_error)?;
    Ok(Json(entries))
}

async fn notification_dead_letter_replay_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<OperatorHttpState>,
    RoutePath(channel): RoutePath<String>,
    Json(request): Json<NotificationDeadLetterReplayRequest>,
) -> Result<Json<ControlEnvelope<Vec<swarm_response::NotificationReplayResult>>>, OperatorApiError>
{
    require_operator_api_scope(&principal, OperatorScope::Maintenance, "maintenance")?;
    let result = state
        .control
        .replay_notification_dead_letters(&channel, request.receipt_ids)
        .await
        .map_err(map_control_error)?;
    Ok(Json(result))
}

async fn metrics_handler(State(state): State<OperatorHttpState>) -> impl IntoResponse {
    match &state.prometheus {
        Some(metrics) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
            )],
            encode_metrics(metrics),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "metrics not enabled").into_response(),
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn parse_requested_operator_api_schema_version(
    headers: &HeaderMap,
) -> Result<Option<u32>, OperatorApiError> {
    headers
        .get(OPERATOR_API_SCHEMA_VERSION_HEADER)
        .map(|value| {
            value
                .to_str()
                .map_err(|_| {
                    OperatorApiError::bad_request(format!(
                        "{OPERATOR_API_SCHEMA_VERSION_HEADER} header must be valid UTF-8"
                    ))
                })?
                .trim()
                .parse::<u32>()
                .map_err(|_| {
                    OperatorApiError::bad_request(format!(
                        "{OPERATOR_API_SCHEMA_VERSION_HEADER} header must be an unsigned integer"
                    ))
                })
        })
        .transpose()
}

async fn require_supported_operator_api_schema_version(
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, OperatorApiError> {
    let requested = parse_requested_operator_api_schema_version(&headers)?;
    resolve_operator_api_schema_version(requested).map_err(OperatorApiError::bad_request)?;
    Ok(next.run(request).await)
}

fn require_operator_api_scope(
    principal: &AuthenticatedOperatorPrincipal,
    scope: OperatorScope,
    action: &str,
) -> Result<(), OperatorApiError> {
    if principal.has_scope(scope) {
        return Ok(());
    }
    Err(OperatorApiError::forbidden(format!(
        "operator `{}` does not grant `{}` access",
        principal.operator_id, action
    )))
}

fn require_operator_review_scope(
    principal: &AuthenticatedOperatorPrincipal,
    scope: OperatorScope,
    action: &str,
) -> Result<(), OperatorReviewError> {
    if principal.has_scope(scope) {
        return Ok(());
    }
    Err(OperatorReviewError::forbidden(format!(
        "operator `{}` does not grant `{}` access",
        principal.operator_id, action
    )))
}

async fn replay_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<ReplayLookupQuery>,
) -> Result<Json<ControlEnvelope<ReplayArtifactView>>, OperatorApiError> {
    let selector = parse_replay_selector(&query)?;
    let replay = state
        .control
        .replay_lookup(selector)
        .map_err(map_control_error)?;
    Ok(Json(replay))
}

async fn investigation_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<InvestigationLookupQuery>,
) -> Result<Json<ControlEnvelope<InvestigationArtifactView>>, OperatorApiError> {
    let selector = parse_investigation_selector(&query)?;
    let lookup = state
        .control
        .investigation_lookup(selector)
        .map_err(map_control_error)?;
    Ok(Json(lookup))
}

async fn incident_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<IncidentLookupQuery>,
) -> Result<Json<ControlEnvelope<IncidentArtifactView>>, OperatorApiError> {
    let selector = parse_incident_selector(&query)?;
    let incident = state
        .control
        .incident_lookup(selector)
        .map_err(map_control_error)?;
    Ok(Json(incident))
}

async fn review_home_handler(
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

async fn review_rehearsal_export_handler(
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

async fn review_session_list_handler(
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

async fn review_session_create_handler(
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

async fn review_session_handler(
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

async fn review_session_export_handler(
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

async fn review_session_capsule_handler(
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

async fn review_session_export_page_handler(
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

async fn review_capsule_page_handler(
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

async fn review_capsule_import_handler(
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

async fn review_capsule_import_page_handler(
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

async fn review_session_promotion_readiness_handler(
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

async fn review_session_promotion_readiness_page_handler(
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

async fn review_session_readiness_capsule_handler(
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

async fn review_session_handoff_handler(
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

async fn review_capsule_delegation_handler(
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

async fn review_capsule_import_delegation_handler(
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

async fn review_session_handoff_page_handler(
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

async fn review_delegation_page_handler(
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

async fn review_evidence_list_handler(
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

async fn review_evidence_bundle_handler(
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

async fn review_evidence_verification_handler(
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

async fn review_promotion_packet_list_handler(
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

async fn review_promotion_packet_handler(
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

async fn evidence_bundle_handler(
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

async fn evidence_bundle_list_handler(
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

async fn evidence_verification_handler(
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

async fn promotion_evidence_packet_handler(
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

async fn approval_set_handler(
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

async fn approval_set_list_handler(
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

async fn approval_set_create_handler(
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

async fn approval_ledger_handler(
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

async fn approval_ledger_list_handler(
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

async fn approval_vote_append_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<OperatorHttpState>,
    RoutePath(ledger_id): RoutePath<String>,
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
            resume_demo_approval(
                &state.runtime_base_url,
                &updated.report.approval_set_id,
                &receipt_pack.report,
            )
            .await?;
        }
    }
    Ok(Json(updated))
}

async fn resume_demo_approval(
    runtime_base_url: &str,
    approval_set_id: &str,
    receipt_pack: &crate::approval::ApprovalReceiptPackReport,
) -> Result<(), OperatorApiError> {
    let url = format!(
        "{}/v1/demo/approvals/{}/resume",
        runtime_base_url.trim_end_matches('/'),
        approval_set_id
    );
    let response = reqwest::Client::new()
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

async fn portfolio_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(portfolio_id): RoutePath<String>,
) -> Result<Json<crate::portfolio::EvolutionPortfolioReport>, OperatorApiError> {
    let harness = portfolio_harness(&state)?;
    let lookup = harness
        .load_portfolio(&portfolio_id)
        .map_err(map_portfolio_error)?
        .ok_or_else(|| {
            OperatorApiError::not_found(format!("portfolio `{portfolio_id}` was not found"))
        })?;
    Ok(Json(lookup.report))
}

async fn portfolio_list_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<PortfolioListQuery>,
) -> Result<Json<EvolutionPortfolioList>, OperatorApiError> {
    let harness = portfolio_harness(&state)?;
    let review_state = query
        .review_state
        .as_deref()
        .map(parse_portfolio_review_state)
        .transpose()?;
    let list = harness
        .list_portfolios(query.cohort.as_deref(), review_state)
        .map_err(map_portfolio_error)?;
    Ok(Json(limit_portfolio_list(
        list,
        query.limit,
        state.max_list_results,
    )))
}

async fn governance_packet_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(packet_id): RoutePath<String>,
) -> Result<Json<crate::portfolio::EvolutionGovernanceReviewPacketReport>, OperatorApiError> {
    let harness = portfolio_harness(&state)?;
    let lookup = harness
        .load_governance_review_packet(&packet_id)
        .map_err(map_portfolio_error)?
        .ok_or_else(|| {
            OperatorApiError::not_found(format!("governance packet `{packet_id}` was not found"))
        })?;
    Ok(Json(lookup.report))
}

async fn packet_set_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(packet_set_id): RoutePath<String>,
) -> Result<Json<crate::governance_prep::EvolutionGovernancePacketSetReport>, OperatorApiError> {
    let harness = governance_harness(&state)?;
    let lookup = harness
        .load_packet_set(&packet_set_id)
        .map_err(map_governance_prep_error)?
        .ok_or_else(|| {
            OperatorApiError::not_found(format!("packet set `{packet_set_id}` was not found"))
        })?;
    Ok(Json(lookup.report))
}

async fn packet_set_list_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<CohortListQuery>,
) -> Result<Json<EvolutionGovernancePacketSetList>, OperatorApiError> {
    let harness = governance_harness(&state)?;
    let list = harness
        .list_packet_sets(query.cohort.as_deref())
        .map_err(map_governance_prep_error)?;
    Ok(Json(limit_packet_set_list(
        list,
        query.limit,
        state.max_list_results,
    )))
}

async fn portfolio_history_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(history_id): RoutePath<String>,
) -> Result<Json<crate::governance_prep::EvolutionPortfolioHistoryReport>, OperatorApiError> {
    let harness = governance_harness(&state)?;
    let lookup = harness
        .load_portfolio_history(&history_id)
        .map_err(map_governance_prep_error)?
        .ok_or_else(|| {
            OperatorApiError::not_found(format!("portfolio history `{history_id}` was not found"))
        })?;
    Ok(Json(lookup.report))
}

async fn portfolio_history_list_handler(
    State(state): State<OperatorHttpState>,
    Query(query): Query<CohortListQuery>,
) -> Result<Json<EvolutionPortfolioHistoryList>, OperatorApiError> {
    let harness = governance_harness(&state)?;
    let list = harness
        .list_portfolio_history(query.cohort.as_deref())
        .map_err(map_governance_prep_error)?;
    Ok(Json(limit_portfolio_history_list(
        list,
        query.limit,
        state.max_list_results,
    )))
}

async fn maintenance_action_handler(
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

async fn maintenance_action_lookup_handler(
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

async fn maintenance_action_list_handler(
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

async fn require_bearer_auth(
    State(auth): State<OperatorAuthState>,
    headers: HeaderMap,
    mut request: axum::extract::Request,
    next: Next,
) -> Result<Response, OperatorApiError> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| OperatorApiError::unauthorized("missing Authorization header"))?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or_else(|| OperatorApiError::unauthorized("expected Authorization: Bearer <token>"))?;
    let principal = auth
        .authenticate(token)
        .ok_or_else(|| OperatorApiError::unauthorized("invalid bearer token"))?;
    request.extensions_mut().insert(principal);

    Ok(next.run(request).await)
}

fn parse_replay_selector(
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

fn parse_investigation_selector(
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

fn parse_incident_selector(
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

fn parse_portfolio_review_state(
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

fn parse_maintenance_status(value: &str) -> Result<OperatorMaintenanceStatus, OperatorApiError> {
    match value {
        "applied" => Ok(OperatorMaintenanceStatus::Applied),
        "blocked" => Ok(OperatorMaintenanceStatus::Blocked),
        "failed" => Ok(OperatorMaintenanceStatus::Failed),
        other => Err(OperatorApiError::bad_request(format!(
            "unsupported maintenance status `{other}`"
        ))),
    }
}

fn parse_evidence_subject_kind(value: &str) -> Result<EvidenceSubjectKind, OperatorApiError> {
    value.parse::<EvidenceSubjectKind>().map_err(|_| {
        OperatorApiError::bad_request(format!("unsupported evidence subject_kind `{value}`"))
    })
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

fn map_control_error(error: ControlError) -> OperatorApiError {
    match error {
        ControlError::NotFound { entity, lookup } => {
            OperatorApiError::not_found(format!("{entity} `{lookup}` was not found"))
        }
        ControlError::Service(error) => map_service_api_error(error),
        other => OperatorApiError::internal(other.to_string()),
    }
}

fn map_evidence_api_error(error: EvidenceError) -> OperatorApiError {
    match error {
        EvidenceError::ArtifactNotFound { kind, id } => {
            OperatorApiError::not_found(format!("artifact `{kind}` with id `{id}` was not found"))
        }
        EvidenceError::Control(error) => map_control_error(error),
        other => OperatorApiError::internal(other.to_string()),
    }
}

fn map_portfolio_error(error: EvolutionPortfolioError) -> OperatorApiError {
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

fn map_governance_prep_error(error: EvolutionGovernancePrepError) -> OperatorApiError {
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

fn portfolio_harness(
    state: &OperatorHttpState,
) -> Result<&DefaultEvolutionPortfolioHarness, OperatorApiError> {
    state
        .portfolio
        .as_deref()
        .ok_or_else(|| OperatorApiError::internal("portfolio stores are not configured"))
}

fn governance_harness(
    state: &OperatorHttpState,
) -> Result<&DefaultEvolutionGovernancePrepHarness, OperatorApiError> {
    state
        .governance_prep
        .as_deref()
        .ok_or_else(|| OperatorApiError::internal("governance-prep stores are not configured"))
}

fn approval_harness(
    state: &OperatorHttpState,
) -> Result<&DefaultApprovalHarness, OperatorApiError> {
    state
        .approval
        .as_deref()
        .ok_or_else(|| OperatorApiError::internal("approval stores are not configured"))
}

fn maintenance_service(
    state: &OperatorHttpState,
) -> Result<&OperatorMaintenanceService, OperatorApiError> {
    state
        .maintenance
        .as_deref()
        .ok_or_else(|| OperatorApiError::internal("maintenance stores are not configured"))
}

fn evidence_service(
    state: &OperatorHttpState,
) -> Result<&OperatorEvidenceReadService, OperatorApiError> {
    state
        .evidence
        .as_deref()
        .ok_or_else(|| OperatorApiError::internal("evidence stores are not configured"))
}

fn review_evidence_harness(
    state: &OperatorHttpState,
) -> Result<&DefaultEvidenceHarness, OperatorReviewError> {
    state
        .evidence_harness
        .as_deref()
        .ok_or_else(|| OperatorReviewError::internal("evidence export stores are not configured"))
}

fn review_workbench_service(
    state: &OperatorHttpState,
) -> Result<&DefaultReviewWorkbenchHarness, OperatorReviewError> {
    state
        .workbench
        .as_deref()
        .ok_or_else(|| OperatorReviewError::internal("review workbench stores are not configured"))
}

fn review_evidence_secret_material(
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

fn map_review_workbench_error(error: ReviewWorkbenchError) -> OperatorReviewError {
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

fn map_control_review_error(error: ControlError) -> OperatorReviewError {
    match error {
        ControlError::NotFound { entity, lookup } => {
            OperatorReviewError::not_found(format!("{entity} `{lookup}` was not found"))
        }
        ControlError::Service(error) => map_service_review_error(error),
        other => OperatorReviewError::internal(other.to_string()),
    }
}

fn map_review_evidence_error(error: EvidenceError) -> OperatorReviewError {
    match error {
        EvidenceError::ArtifactNotFound { kind, id } => OperatorReviewError::not_found(format!(
            "artifact `{kind}` with id `{id}` was not found"
        )),
        EvidenceError::Control(error) => map_control_review_error(error),
        other => OperatorReviewError::internal(other.to_string()),
    }
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

fn map_approval_error(error: ApprovalError) -> OperatorApiError {
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

fn map_maintenance_error(error: OperatorMaintenanceError) -> OperatorApiError {
    match error {
        OperatorMaintenanceError::Store(_) => OperatorApiError::internal(error.to_string()),
        OperatorMaintenanceError::Portfolio(error) => map_portfolio_error(error),
        OperatorMaintenanceError::GovernancePrep(error) => map_governance_prep_error(error),
        OperatorMaintenanceError::Evidence(error) => map_evidence_api_error(error),
    }
}

fn count_set(values: &[Option<&str>]) -> usize {
    values.iter().filter(|value| value.is_some()).count()
}

fn effective_limit(requested_limit: Option<usize>, max_limit: usize) -> usize {
    requested_limit.unwrap_or(max_limit).min(max_limit)
}

fn limit_portfolio_list(
    mut list: EvolutionPortfolioList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> EvolutionPortfolioList {
    let limit = effective_limit(requested_limit, max_limit);
    list.portfolios = list.portfolios.into_iter().take(limit).collect();
    list.total_count = list.portfolios.len();
    list
}

fn limit_packet_set_list(
    mut list: EvolutionGovernancePacketSetList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> EvolutionGovernancePacketSetList {
    let limit = effective_limit(requested_limit, max_limit);
    list.packet_sets = list.packet_sets.into_iter().take(limit).collect();
    list.total_count = list.packet_sets.len();
    list
}

fn limit_portfolio_history_list(
    mut list: EvolutionPortfolioHistoryList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> EvolutionPortfolioHistoryList {
    let limit = effective_limit(requested_limit, max_limit);
    list.histories = list.histories.into_iter().take(limit).collect();
    list.total_count = list.histories.len();
    list
}

fn limit_evidence_bundle_list(
    mut list: EvidenceBundleList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> EvidenceBundleList {
    let limit = effective_limit(requested_limit, max_limit);
    list.bundles = list.bundles.into_iter().take(limit).collect();
    list.total_count = list.bundles.len();
    list
}

fn limit_maintenance_list(
    mut list: OperatorMaintenanceList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> OperatorMaintenanceList {
    let limit = effective_limit(requested_limit, max_limit);
    list.actions = list.actions.into_iter().take(limit).collect();
    list.total_count = list.actions.len();
    list
}

fn limit_approval_set_list(
    mut list: ApprovalSetList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> ApprovalSetList {
    let limit = effective_limit(requested_limit, max_limit);
    list.sets = list.sets.into_iter().take(limit).collect();
    list.total_count = list.sets.len();
    list
}

fn limit_approval_ledger_list(
    mut list: ApprovalLedgerList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> ApprovalLedgerList {
    let limit = effective_limit(requested_limit, max_limit);
    list.ledgers = list.ledgers.into_iter().take(limit).collect();
    list.total_count = list.ledgers.len();
    list
}

fn limit_review_session_list(
    mut list: ReviewSessionList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> ReviewSessionList {
    let limit = effective_limit(requested_limit, max_limit);
    list.sessions = list.sessions.into_iter().take(limit).collect();
    list.total_count = list.sessions.len();
    list
}

fn limit_review_session_export_list(
    mut list: crate::review_workbench::ReviewSessionExportList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> crate::review_workbench::ReviewSessionExportList {
    let limit = effective_limit(requested_limit, max_limit);
    list.exports = list.exports.into_iter().take(limit).collect();
    list.total_count = list.exports.len();
    list
}

fn limit_review_capsule_list(
    mut list: ReviewCapsuleList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> ReviewCapsuleList {
    let limit = effective_limit(requested_limit, max_limit);
    list.capsules = list.capsules.into_iter().take(limit).collect();
    list.total_count = list.capsules.len();
    list
}

fn limit_review_capsule_import_list(
    mut list: ReviewCapsuleImportList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> ReviewCapsuleImportList {
    let limit = effective_limit(requested_limit, max_limit);
    list.imports = list.imports.into_iter().take(limit).collect();
    list.total_count = list.imports.len();
    list
}

fn limit_review_session_handoff_list(
    mut list: ReviewSessionMaintenanceHandoffList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> ReviewSessionMaintenanceHandoffList {
    let limit = effective_limit(requested_limit, max_limit);
    list.handoffs = list.handoffs.into_iter().take(limit).collect();
    list.total_count = list.handoffs.len();
    list
}

fn limit_review_delegation_list(
    mut list: ReviewDelegationPacketList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> ReviewDelegationPacketList {
    let limit = effective_limit(requested_limit, max_limit);
    list.delegations = list.delegations.into_iter().take(limit).collect();
    list.total_count = list.delegations.len();
    list
}

fn limit_review_session_promotion_readiness_list(
    mut list: ReviewSessionPromotionReadinessList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> ReviewSessionPromotionReadinessList {
    let limit = effective_limit(requested_limit, max_limit);
    list.readiness_reports = list.readiness_reports.into_iter().take(limit).collect();
    list.total_count = list.readiness_reports.len();
    list
}

fn parse_review_artifact_refs_text(
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

fn normalize_form_optional_text(value: Option<String>) -> Option<String> {
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
enum ReviewEvidenceVerificationFilter {
    Passed,
    Failed,
    Unverified,
}

impl ReviewEvidenceVerificationFilter {
    fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Unverified => "unverified",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Passed => "Passed",
            Self::Failed => "Failed",
            Self::Unverified => "Unverified",
        }
    }
}

fn parse_review_evidence_subject_kind(
    value: &str,
) -> Result<EvidenceSubjectKind, OperatorReviewError> {
    value.parse::<EvidenceSubjectKind>().map_err(|_| {
        OperatorReviewError::bad_request(format!("unsupported review subject_kind `{value}`"))
    })
}

fn parse_review_evidence_verification_status(
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

fn parse_review_promotion_recommendation(
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

fn review_evidence_service(
    state: &OperatorHttpState,
) -> Result<&OperatorEvidenceReadService, OperatorReviewError> {
    state
        .evidence
        .as_deref()
        .ok_or_else(|| OperatorReviewError::internal("evidence stores are not configured"))
}

fn filter_review_evidence_list(
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

fn filter_review_promotion_packet_list(
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

fn limit_promotion_packet_list(
    mut list: PromotionEvidencePacketList,
    requested_limit: Option<usize>,
    max_limit: usize,
) -> PromotionEvidencePacketList {
    let limit = effective_limit(requested_limit, max_limit);
    list.packets = list.packets.into_iter().take(limit).collect();
    list.total_count = list.packets.len();
    list
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn review_link(path: &str, label: &str) -> String {
    format!(
        "<a class=\"review-link\" href=\"{}\">{}</a>",
        escape_html(path),
        escape_html(label)
    )
}

fn render_review_layout(title: &str, subtitle: &str, body: &str) -> String {
    let subtitle_html = if subtitle.is_empty() {
        String::new()
    } else {
        format!("<p class=\"subtitle\">{}</p>", escape_html(subtitle))
    };
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{title}</title><style>{style}</style></head><body><main class=\"page\"><header class=\"hero\"><div><p class=\"eyebrow\">Swarm Team Six</p><h1>{heading}</h1>{subtitle}</div><nav class=\"nav\"><a href=\"/v1/operator/review\">Home</a><a href=\"/v1/operator/review/sessions\">Sessions</a><a href=\"/v1/operator/review/evidence\">Evidence</a><a href=\"/v1/operator/review/promotion-packets\">Promotion Packets</a></nav></header>{body}</main></body></html>",
        title = escape_html(title),
        heading = escape_html(title),
        subtitle = subtitle_html,
        body = body,
        style = concat!(
            ":root{color-scheme:light;font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;}",
            "body{margin:0;background:#f4efe5;color:#1d2433;}",
            ".page{max-width:1120px;margin:0 auto;padding:24px 20px 56px;}",
            ".hero{display:flex;justify-content:space-between;gap:24px;align-items:flex-start;margin-bottom:24px;padding:20px 24px;border-radius:20px;background:linear-gradient(135deg,#fef7e5,#e7f1ff);border:1px solid #d7deeb;}",
            ".eyebrow{margin:0 0 6px;font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#805b10;}",
            "h1{margin:0;font-size:32px;line-height:1.1;}",
            ".subtitle{margin:10px 0 0;max-width:70ch;color:#465066;}",
            ".nav{display:flex;gap:10px;flex-wrap:wrap;justify-content:flex-end;}",
            ".nav a,.review-link{color:#0f4f8a;text-decoration:none;font-weight:600;}",
            ".nav a{padding:10px 12px;border-radius:999px;background:#ffffffbf;border:1px solid #d3dceb;}",
            ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:18px;}",
            ".card{background:#fff;border:1px solid #d7deeb;border-radius:18px;padding:18px;box-shadow:0 10px 25px rgba(29,36,51,.06);}",
            ".card h2,.card h3{margin-top:0;}",
            ".dashboard-shell{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(320px,.85fr);gap:18px;margin-bottom:18px;}",
            ".dashboard-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-top:16px;}",
            ".metric-card{padding:16px;border-radius:16px;background:linear-gradient(160deg,#fff9ef,#eef5ff);border:1px solid #d7deeb;}",
            ".metric-card h3{margin:0 0 8px;font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:#6a7282;}",
            ".kpi{font-size:28px;line-height:1.05;font-weight:800;letter-spacing:-.02em;}",
            ".status-row{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap;}",
            ".status-banner{display:inline-flex;align-items:center;gap:8px;padding:8px 12px;border-radius:999px;font-weight:700;font-size:12px;letter-spacing:.04em;text-transform:uppercase;}",
            ".status-banner.ok{background:#ddf8e8;color:#15643a;}",
            ".status-banner.warn{background:#fff1dc;color:#9a580a;}",
            ".status-banner.err{background:#fde1e1;color:#9c2331;}",
            ".status-dot{width:10px;height:10px;border-radius:999px;background:currentColor;}",
            ".health-list,.timeline-list{list-style:none;padding:0;margin:0;}",
            ".health-list{display:flex;flex-direction:column;gap:10px;}",
            ".health-item{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:12px 14px;border-radius:14px;border:1px solid #e0e6f0;background:#f8fafc;}",
            ".timeline-list{display:flex;flex-direction:column;gap:10px;max-height:420px;overflow:auto;padding-right:4px;}",
            ".timeline-item{padding:12px 14px;border-radius:14px;border:1px solid #dfe7f2;background:#f8fafc;border-left:4px solid #9fb2c8;}",
            ".timeline-item.escalation{background:#fff1ea;border-left-color:#c2410c;}",
            ".timeline-item.mode_transition{background:#edf4ff;border-left-color:#0f4f8a;}",
            ".timeline-item.agent_health{background:#eef4ff;border-left-color:#2563eb;}",
            ".timeline-item.response_execution{background:#f4f0ff;border-left-color:#7c3aed;}",
            ".timeline-item.ingest{background:#eefbf5;border-left-color:#15803d;}",
            ".timeline-title{display:flex;justify-content:space-between;gap:10px;align-items:baseline;margin-bottom:6px;}",
            ".timeline-title strong{font-size:14px;}",
            ".timeline-time{font-size:12px;color:#667085;white-space:nowrap;}",
            ".dashboard-empty{padding:14px;border:1px dashed #cbd5e1;border-radius:14px;background:#fbfdff;color:#667085;}",
            ".compact-table td,.compact-table th{padding:8px 6px;}",
            ".meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;margin:16px 0;}",
            ".meta div{padding:12px 14px;border-radius:14px;background:#f7f9fc;border:1px solid #e0e6f0;}",
            ".meta dt{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#6a7282;font-weight:700;}",
            ".meta dd{margin:6px 0 0;font-weight:600;word-break:break-word;}",
            ".pill{display:inline-block;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;}",
            ".pill.passed,.pill.ready{background:#ddf8e8;color:#15643a;}",
            ".pill.failed,.pill.blocked{background:#fde1e1;color:#9c2331;}",
            ".pill.unverified{background:#eceff5;color:#495164;}",
            "table{width:100%;border-collapse:collapse;margin-top:10px;}",
            "th,td{text-align:left;padding:10px 8px;border-bottom:1px solid #e7ebf3;vertical-align:top;}",
            "th{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#6a7282;}",
            ".toolbar{display:flex;flex-wrap:wrap;gap:12px;align-items:end;margin:18px 0;}",
            ".toolbar label{display:flex;flex-direction:column;gap:6px;font-size:14px;font-weight:600;color:#344054;}",
            ".toolbar input,.toolbar select,.toolbar textarea{min-width:180px;padding:10px 12px;border-radius:12px;border:1px solid #ccd5e3;background:#fff;}",
            ".toolbar button{padding:10px 16px;border-radius:12px;border:0;background:#0f4f8a;color:#fff;font-weight:700;cursor:pointer;}",
            "code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;}",
            "pre{margin:0;white-space:pre-wrap;word-break:break-word;background:#141923;color:#eef3ff;padding:14px;border-radius:14px;}",
            "details{margin-top:14px;}",
            "ul{padding-left:20px;}",
            ".muted{color:#667085;}",
            "@media (max-width:980px){.dashboard-shell{grid-template-columns:1fr;}}",
            "@media (max-width:760px){.hero{flex-direction:column;}.nav{justify-content:flex-start;}}"
        )
    )
}

fn render_demo_dashboard_panel(runtime_base_url: &str) -> String {
    let runtime_base_url_json =
        serde_json::to_string(runtime_base_url).unwrap_or_else(|_| "\"\"".to_string());
    let script = r#"<script>
(function () {
  const runtimeBaseUrl = __RUNTIME_BASE_URL__;
  const snapshotUrl = runtimeBaseUrl.replace(/\/$/, "") + "/v1/demo/dashboard";
  const streamUrl = runtimeBaseUrl.replace(/\/$/, "") + "/v1/events/stream?types=" + encodeURIComponent([
    "agent_health",
    "concentration_snapshot",
    "escalation",
    "mode_transition",
    "agent_action",
    "response_execution",
    "replay",
    "ingest"
  ].join(","));

  const connection = document.getElementById("dashboard-connection");
  const modeValue = document.getElementById("dashboard-mode");
  const modeDetail = document.getElementById("dashboard-mode-detail");
  const runtimeSource = document.getElementById("dashboard-runtime-source");
  const escalationsValue = document.getElementById("dashboard-escalation-count");
  const healthValue = document.getElementById("dashboard-health-count");
  const healthList = document.getElementById("dashboard-agent-health");
  const concentrationBody = document.getElementById("dashboard-concentrations");
  const timeline = document.getElementById("dashboard-timeline");

  let eventSource = null;
  let latestHealth = new Map();

  function setConnection(kind, label) {
    connection.className = "status-banner " + kind;
    connection.innerHTML = '<span class="status-dot"></span>' + label;
  }

  function titleCase(value) {
    return String(value || "")
      .split("_")
      .filter(Boolean)
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(" ");
  }

  function formatTime(epochMs) {
    if (!epochMs) {
      return "pending";
    }
    return new Date(epochMs).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    });
  }

  function renderMode(modeState) {
    const mode = modeState && modeState.current ? modeState.current : "normal";
    modeValue.textContent = titleCase(mode);
    if (modeState && modeState.last_transition_at) {
      const transitionMs = modeState.last_transition_at * 1000;
      const threatClass = modeState.triggering_threat_class
        ? titleCase(modeState.triggering_threat_class)
        : "cooldown reset";
      modeDetail.textContent = "Last transition " + formatTime(transitionMs) + " via " + threatClass;
    } else {
      modeDetail.textContent = "No escalation recorded in this runtime session.";
    }
  }

  function renderHealth(entries) {
    latestHealth = new Map((entries || []).map((entry) => [entry.id, entry]));
    healthValue.textContent = String(entries.length);
    if (!entries.length) {
      healthList.innerHTML = '<li class="dashboard-empty">No registered agent health has been published yet.</li>';
      return;
    }
    healthList.innerHTML = entries.map((entry) => {
      const pillClass = entry.health === "healthy" ? "ready" : entry.health;
      return '<li class="health-item"><div><strong>' + entry.id + '</strong><div class="muted">' +
        titleCase(entry.role) + '</div></div><span class="pill ' + pillClass + '">' +
        titleCase(entry.health) + '</span></li>';
    }).join("");
  }

  function renderConcentrations(entries) {
    const rows = (entries || []).map((entry) => {
      return '<tr><td><strong>' + titleCase(entry.threat_class) + '</strong></td><td>' +
        Number(entry.total_strength || 0).toFixed(2) + '</td><td>' +
        String(entry.distinct_sources || 0) + '</td><td>' +
        Number(entry.peak_confidence || 0).toFixed(2) + '</td></tr>';
    }).join("");
    concentrationBody.innerHTML = rows || '<tr><td colspan="4" class="dashboard-empty">No concentration data available yet.</td></tr>';
  }

  function timelineItem(kind, title, detail, epochMs) {
    return '<li class="timeline-item ' + kind + '"><div class="timeline-title"><strong>' +
      title + '</strong><span class="timeline-time">' + formatTime(epochMs) +
      '</span></div><div class="muted">' + detail + '</div></li>';
  }

  function pushTimeline(kind, title, detail, epochMs) {
    const markup = timelineItem(kind, title, detail, epochMs);
    if (timeline.querySelector(".dashboard-empty")) {
      timeline.innerHTML = markup;
    } else {
      timeline.insertAdjacentHTML("afterbegin", markup);
    }
    while (timeline.children.length > 30) {
      timeline.removeChild(timeline.lastElementChild);
    }
  }

  function renderEscalationSeed(records) {
    if (!(records || []).length) {
      timeline.innerHTML = '<li class="dashboard-empty">Waiting for live runtime events.</li>';
      escalationsValue.textContent = "0";
      return;
    }
    escalationsValue.textContent = String(records.length);
    timeline.innerHTML = records.map((record) => {
      const detail = titleCase(record.threat_class) + " strength " +
        Number(record.total_strength || 0).toFixed(2) + " from " +
        String(record.distinct_sources || 0) + " sources";
      return timelineItem(
        "escalation",
        titleCase(record.mode) + " escalation",
        detail,
        (record.timestamp || 0) * 1000
      );
    }).join("");
  }

  function handleRuntimeEvent(event) {
    switch (event.event_type) {
      case "concentration_snapshot":
        renderConcentrations(event.concentrations || []);
        renderMode({ current: event.current_mode });
        break;
      case "agent_health": {
        const next = Array.from(latestHealth.values());
        const index = next.findIndex((entry) => entry.id === event.agent_id);
        const entry = { id: event.agent_id, role: event.role, health: event.to };
        if (index >= 0) {
          next[index] = entry;
        } else {
          next.push(entry);
        }
        renderHealth(next.sort((left, right) => left.id.localeCompare(right.id)));
        pushTimeline(
          "agent_health",
          event.agent_id + " health changed",
          titleCase(event.role) + " is now " + titleCase(event.to),
          event.emitted_at_ms
        );
        break;
      }
      case "escalation":
        pushTimeline(
          "escalation",
          titleCase(event.level) + " escalation",
          titleCase(event.threat_class) + " strength " + Number(event.total_strength || 0).toFixed(2) +
            " from " + String(event.distinct_sources || 0) + " sources",
          event.emitted_at_ms
        );
        break;
      case "mode_transition":
        renderMode({
          current: event.to
        });
        pushTimeline(
          "mode_transition",
          titleCase(event.from) + " → " + titleCase(event.to),
          event.reason || "mode transition",
          event.emitted_at_ms
        );
        break;
      case "response_execution":
        pushTimeline(
          "response_execution",
          titleCase(event.response_kind) + " response",
          event.agent_id + " · " + event.action_kind + " · " + titleCase(event.policy_verdict),
          event.emitted_at_ms
        );
        break;
      case "agent_action":
        pushTimeline(
          "agent_action",
          event.agent_id + " action",
          titleCase(event.action_kind),
          event.emitted_at_ms
        );
        break;
      case "ingest":
        pushTimeline(
          "ingest",
          event.accepted ? "Telemetry accepted" : "Telemetry rejected",
          event.event_id + " · " + event.source,
          event.emitted_at_ms
        );
        break;
      case "replay":
        if (event.phase === "step") {
          return;
        }
        pushTimeline(
          "replay",
          "Replay " + titleCase(event.phase),
          event.scenario_name + " · " + String(event.total_steps || 0) + " steps",
          event.emitted_at_ms
        );
        break;
      default:
        break;
    }
  }

  async function bootstrap() {
    runtimeSource.textContent = runtimeBaseUrl;
    setConnection("warn", "Connecting");
    try {
      const response = await fetch(snapshotUrl, { credentials: "omit" });
      if (!response.ok) {
        throw new Error("snapshot returned " + response.status);
      }
      const snapshot = await response.json();
      renderMode(snapshot.mode_state || { current: "normal" });
      renderHealth(snapshot.agent_health || []);
      renderConcentrations(snapshot.concentrations || []);
      renderEscalationSeed(snapshot.recent_escalations || []);
      setConnection("ok", "Live");
    } catch (error) {
      setConnection("err", "Snapshot Error");
      timeline.innerHTML = '<li class="dashboard-empty">Unable to load runtime snapshot: ' +
        String(error.message || error) + '</li>';
    }

    eventSource = new EventSource(streamUrl, { withCredentials: false });
    eventSource.onopen = function () {
      setConnection("ok", "Streaming");
    };
    eventSource.onerror = function () {
      setConnection("warn", "Reconnecting");
    };
    [
      "agent_health",
      "concentration_snapshot",
      "escalation",
      "mode_transition",
      "agent_action",
      "response_execution",
      "replay",
      "ingest"
    ].forEach((type) => {
      eventSource.addEventListener(type, function (message) {
        try {
          handleRuntimeEvent(JSON.parse(message.data));
        } catch (error) {
          setConnection("warn", "Stream Decode Error");
        }
      });
    });
  }

  bootstrap();
})();
</script>"#
        .replace("__RUNTIME_BASE_URL__", &runtime_base_url_json);

    format!(
        "<section class=\"dashboard-shell\">\
            <article class=\"card\">\
                <div class=\"status-row\">\
                    <div><h2>Live Demo Dashboard</h2><p class=\"muted\">Bootstrapped from the runtime snapshot endpoint and kept live from the typed runtime event stream.</p></div>\
                    <div id=\"dashboard-connection\" class=\"status-banner warn\"><span class=\"status-dot\"></span>Connecting</div>\
                </div>\
                <div class=\"dashboard-grid\">\
                    <div class=\"metric-card\"><h3>Swarm Mode</h3><div id=\"dashboard-mode\" class=\"kpi\">Loading</div><div id=\"dashboard-mode-detail\" class=\"muted\">Waiting for runtime snapshot.</div></div>\
                    <div class=\"metric-card\"><h3>Agents Visible</h3><div id=\"dashboard-health-count\" class=\"kpi\">0</div><div class=\"muted\">Per-agent health over the live runtime stream.</div></div>\
                    <div class=\"metric-card\"><h3>Escalations Seeded</h3><div id=\"dashboard-escalation-count\" class=\"kpi\">0</div><div class=\"muted\">Recent escalation records used to seed the timeline.</div></div>\
                    <div class=\"metric-card\"><h3>Runtime Source</h3><div id=\"dashboard-runtime-source\" class=\"kpi\" style=\"font-size:18px;word-break:break-word;\">{runtime_base_url}</div><div class=\"muted\">Repo-owned base URL for snapshot and SSE reads.</div></div>\
                </div>\
            </article>\
            <article class=\"card\">\
                <h2>Runtime Timeline</h2>\
                <p class=\"muted\">Escalations, mode shifts, and agent actions arrive here from the shared event backbone.</p>\
                <ol id=\"dashboard-timeline\" class=\"timeline-list\"><li class=\"dashboard-empty\">Waiting for live runtime events.</li></ol>\
            </article>\
        </section>\
        <section class=\"grid\" style=\"margin-bottom:18px;\">\
            <article class=\"card\"><h2>Agent Health</h2><ul id=\"dashboard-agent-health\" class=\"health-list\"><li class=\"dashboard-empty\">Waiting for agent health.</li></ul></article>\
            <article class=\"card\"><h2>Threat Concentrations</h2><table class=\"compact-table\"><thead><tr><th>Threat Class</th><th>Strength</th><th>Sources</th><th>Peak Confidence</th></tr></thead><tbody id=\"dashboard-concentrations\"><tr><td colspan=\"4\" class=\"dashboard-empty\">Waiting for concentration snapshots.</td></tr></tbody></table></article>\
        </section>{script}",
        runtime_base_url = escape_html(runtime_base_url),
        script = script
    )
}

fn render_status_pill(label: &str, class_name: &str) -> String {
    format!(
        "<span class=\"pill {class_name}\">{label}</span>",
        class_name = escape_html(class_name),
        label = escape_html(label)
    )
}

fn render_subject_kind_options(selected: Option<EvidenceSubjectKind>) -> String {
    let mut options = vec!["<option value=\"\">All subject kinds</option>".to_string()];
    for kind in [
        EvidenceSubjectKind::ReplayBundle,
        EvidenceSubjectKind::InvestigationBundle,
        EvidenceSubjectKind::CorrelatedIncident,
        EvidenceSubjectKind::CanaryRun,
        EvidenceSubjectKind::ProductionPromotion,
        EvidenceSubjectKind::OperatorMaintenanceAction,
        EvidenceSubjectKind::DetectorVerification,
        EvidenceSubjectKind::StrategyShadow,
        EvidenceSubjectKind::PromotionReview,
    ] {
        let selected_attr = if selected == Some(kind) {
            " selected"
        } else {
            ""
        };
        options.push(format!(
            "<option value=\"{value}\"{selected}>{value}</option>",
            value = kind.as_str(),
            selected = selected_attr
        ));
    }
    options.join("")
}

fn render_verification_filter_options(
    selected: Option<ReviewEvidenceVerificationFilter>,
) -> String {
    let mut options = vec!["<option value=\"\">Any verification state</option>".to_string()];
    for filter in [
        ReviewEvidenceVerificationFilter::Passed,
        ReviewEvidenceVerificationFilter::Failed,
        ReviewEvidenceVerificationFilter::Unverified,
    ] {
        let selected_attr = if selected == Some(filter) {
            " selected"
        } else {
            ""
        };
        options.push(format!(
            "<option value=\"{value}\"{selected}>{label}</option>",
            value = filter.as_str(),
            selected = selected_attr,
            label = filter.label()
        ));
    }
    options.join("")
}

fn render_promotion_recommendation_options(
    selected: Option<PromotionEvidenceRecommendation>,
) -> String {
    let mut options = vec!["<option value=\"\">Any recommendation</option>".to_string()];
    for recommendation in [
        PromotionEvidenceRecommendation::ReadyForExternalReview,
        PromotionEvidenceRecommendation::Blocked,
    ] {
        let selected_attr = if selected == Some(recommendation) {
            " selected"
        } else {
            ""
        };
        options.push(format!(
            "<option value=\"{value}\"{selected}>{value}</option>",
            value = recommendation.as_str(),
            selected = selected_attr
        ));
    }
    options.join("")
}

fn render_review_session_list_page(list: &ReviewSessionList) -> String {
    let mut rows = String::new();
    for session in &list.sessions {
        rows.push_str(&format!(
            "<tr><td>{session_link}</td><td>{title}</td><td>{artifacts}</td><td>{bundles}</td><td>{verifications}</td><td>{packets}</td></tr>",
            session_link = review_link(
                &format!("/v1/operator/review/sessions/{}", session.session_id),
                &session.session_id
            ),
            title = escape_html(session.title.as_deref().unwrap_or("untitled")),
            artifacts = session.artifact_count,
            bundles = session.evidence_bundle_count,
            verifications = session.verification_count,
            packets = session.promotion_packet_count
        ));
    }
    if rows.is_empty() {
        rows.push_str(
            "<tr><td colspan=\"6\" class=\"muted\">No review sessions created yet.</td></tr>",
        );
    }

    render_review_layout(
        "Review Sessions",
        "Assemble durable multi-artifact evidence sessions from existing stable IDs, then export or hand them into bounded maintenance actions.",
        &format!(
            "<section class=\"grid\">\
                <article class=\"card\">\
                    <h2>Create Session</h2>\
                    <form class=\"toolbar\" method=\"post\" action=\"/v1/operator/review/sessions\">\
                        <label>Title<input type=\"text\" name=\"title\" placeholder=\"red evidence workbench\"></label>\
                        <label>Notes<input type=\"text\" name=\"notes\" placeholder=\"optional operator context\"></label>\
                        <label style=\"min-width:100%;\">Artifact refs<textarea name=\"artifact_refs\" rows=\"6\" placeholder=\"promotion_review:review:red&#10;canary_run:canary:red&#10;production_promotion:promotion:red\"></textarea></label>\
                        <button type=\"submit\">Create Review Session</button>\
                    </form>\
                    <p class=\"muted\">One artifact ref per line. Supported kinds: <code>evidence_bundle</code>, <code>evidence_verification</code>, <code>promotion_evidence_packet</code>, <code>promotion_review</code>, <code>canary_run</code>, <code>production_promotion</code>.</p>\
                </article>\
                <article class=\"card\">\
                    <h2>Recent Sessions</h2>\
                    <table><thead><tr><th>Session</th><th>Title</th><th>Artifacts</th><th>Bundles</th><th>Verifications</th><th>Packets</th></tr></thead><tbody>{rows}</tbody></table>\
                </article>\
            </section>",
            rows = rows
        ),
    )
}

fn render_review_session_page(
    resolved: &ReviewSessionResolved,
    exports: &[crate::review_workbench::ReviewSessionExportRecord],
    readiness_reports: &[crate::review_workbench::ReviewSessionPromotionReadinessRecord],
    handoffs: &[crate::review_workbench::ReviewSessionMaintenanceHandoffRecord],
    capsules: &[crate::review_workbench::ReviewCapsuleRecord],
    delegations: &[crate::review_workbench::ReviewDelegationPacketRecord],
) -> String {
    let mut lane_rows = String::new();
    for summary in &resolved.lane_summaries {
        lane_rows.push_str(&format!(
            "<tr><td>{lane}</td><td>{artifacts}</td><td>{bundles}</td><td>{verifications}</td><td>{packets}</td><td>{refs}</td></tr>",
            lane = escape_html(summary.lane.title()),
            artifacts = summary.artifact_count,
            bundles = summary.evidence_bundle_count,
            verifications = summary.verification_count,
            packets = summary.promotion_packet_count,
            refs = summary.subject_refs.len()
        ));
    }
    if lane_rows.is_empty() {
        lane_rows.push_str(
            "<tr><td colspan=\"6\" class=\"muted\">No cross-lane summary available.</td></tr>",
        );
    }

    let mut gap_rows = String::new();
    for gap in &resolved.unresolved_gaps {
        gap_rows.push_str(&format!(
            "<tr><td>{lane}</td><td><code>{code}</code></td><td>{details}</td></tr>",
            lane = escape_html(
                gap.lane
                    .map(|lane| lane.title().to_string())
                    .unwrap_or_else(|| "Cross-Lane".to_string())
                    .as_str()
            ),
            code = escape_html(&gap.code),
            details = escape_html(&gap.details)
        ));
    }
    if gap_rows.is_empty() {
        gap_rows.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No unresolved evidence gaps.</td></tr>",
        );
    }

    let mut bundle_rows = String::new();
    for bundle in &resolved.evidence_bundles {
        let verification = bundle
            .record
            .latest_verification_status
            .map(|status| render_status_pill(status.as_str(), status.as_str()))
            .unwrap_or_else(|| render_status_pill("unverified", "unverified"));
        bundle_rows.push_str(&format!(
            "<tr><td>{bundle_link}</td><td>{subject_kind}</td><td><code>{subject_id}</code></td><td>{verification}</td></tr>",
            bundle_link = review_link(
                &format!("/v1/operator/review/evidence/{}", bundle.record.bundle_id),
                &bundle.record.bundle_id
            ),
            subject_kind = escape_html(bundle.record.subject_kind.as_str()),
            subject_id = escape_html(&bundle.record.subject_id),
            verification = verification
        ));
    }
    if bundle_rows.is_empty() {
        bundle_rows.push_str(
            "<tr><td colspan=\"4\" class=\"muted\">No evidence bundles in this session.</td></tr>",
        );
    }

    let mut verification_rows = String::new();
    for verification in &resolved.evidence_verifications {
        verification_rows.push_str(&format!(
            "<tr><td>{verification_link}</td><td>{bundle_link}</td><td>{status}</td><td><code>{key_id}</code></td></tr>",
            verification_link = review_link(
                &format!(
                    "/v1/operator/review/verifications/{}",
                    verification.report.verification_id
                ),
                &verification.report.verification_id
            ),
            bundle_link = review_link(
                &format!("/v1/operator/review/evidence/{}", verification.report.bundle_id),
                &verification.report.bundle_id
            ),
            status = render_status_pill(
                verification.report.status.as_str(),
                verification.report.status.as_str()
            ),
            key_id = escape_html(&verification.report.signer_key_id)
        ));
    }
    if verification_rows.is_empty() {
        verification_rows.push_str(
            "<tr><td colspan=\"4\" class=\"muted\">No evidence verifications in this session.</td></tr>",
        );
    }

    let mut packet_rows = String::new();
    for packet in &resolved.promotion_packets {
        let recommendation = match packet.packet.recommendation {
            PromotionEvidenceRecommendation::ReadyForExternalReview => {
                render_status_pill("ready_for_external_review", "ready")
            }
            PromotionEvidenceRecommendation::Blocked => render_status_pill("blocked", "blocked"),
        };
        packet_rows.push_str(&format!(
            "<tr><td>{packet_link}</td><td><code>{promotion_id}</code></td><td>{recommendation}</td><td>{attachments}</td></tr>",
            packet_link = review_link(
                &format!("/v1/operator/review/promotion-packets/{}", packet.packet.packet_id),
                &packet.packet.packet_id
            ),
            promotion_id = escape_html(&packet.packet.promotion_id),
            recommendation = recommendation,
            attachments = packet.packet.supporting_evidence.len()
        ));
    }
    if packet_rows.is_empty() {
        packet_rows.push_str(
            "<tr><td colspan=\"4\" class=\"muted\">No promotion evidence packets in this session.</td></tr>",
        );
    }

    let mut export_rows = String::new();
    for export in exports {
        export_rows.push_str(&format!(
            "<tr><td>{export_link}</td><td>{artifacts}</td></tr>",
            export_link = review_link(
                &format!("/v1/operator/review/exports/{}", export.export_id),
                &export.export_id
            ),
            artifacts = export.artifact_count
        ));
    }
    if export_rows.is_empty() {
        export_rows
            .push_str("<tr><td colspan=\"2\" class=\"muted\">No exports created yet.</td></tr>");
    }

    let mut readiness_rows = String::new();
    for readiness in readiness_reports {
        readiness_rows.push_str(&format!(
            "<tr><td>{readiness_link}</td><td>{recommendation}</td><td>{gaps}</td></tr>",
            readiness_link = review_link(
                &format!(
                    "/v1/operator/review/promotion-readiness/{}",
                    readiness.readiness_id
                ),
                &readiness.readiness_id
            ),
            recommendation = render_status_pill(
                readiness.recommendation.as_str(),
                readiness.recommendation.as_str()
            ),
            gaps = readiness.gap_count
        ));
    }
    if readiness_rows.is_empty() {
        readiness_rows.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No promotion readiness reviews created yet.</td></tr>",
        );
    }

    let mut handoff_rows = String::new();
    for handoff in handoffs {
        handoff_rows.push_str(&format!(
            "<tr><td>{handoff_link}</td><td>{status}</td><td>{actions}</td></tr>",
            handoff_link = review_link(
                &format!("/v1/operator/review/handoffs/{}", handoff.handoff_id),
                &handoff.handoff_id
            ),
            status = render_maintenance_status_pill(handoff.status),
            actions = handoff.action_count
        ));
    }
    if handoff_rows.is_empty() {
        handoff_rows.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No maintenance handoffs created yet.</td></tr>",
        );
    }

    let mut capsule_rows = String::new();
    for capsule in capsules {
        capsule_rows.push_str(&format!(
            "<tr><td>{capsule_link}</td><td><code>{source_kind}</code></td><td><code>{key_id}</code></td><td>{gaps}</td></tr>",
            capsule_link = review_link(
                &format!("/v1/operator/review/capsules/{}", capsule.capsule_id),
                &capsule.capsule_id
            ),
            source_kind = escape_html(capsule.source_kind.as_str()),
            key_id = escape_html(&capsule.signer_key_id),
            gaps = capsule.gap_count
        ));
    }
    if capsule_rows.is_empty() {
        capsule_rows.push_str(
            "<tr><td colspan=\"4\" class=\"muted\">No portable review capsules created yet.</td></tr>",
        );
    }

    let mut delegation_rows = String::new();
    for delegation in delegations {
        delegation_rows.push_str(&format!(
            "<tr><td>{delegation_link}</td><td><code>{source_kind}</code></td><td><code>{capsule_id}</code></td><td>{gaps}</td></tr>",
            delegation_link = review_link(
                &format!("/v1/operator/review/delegations/{}", delegation.delegation_id),
                &delegation.delegation_id
            ),
            source_kind = escape_html(delegation.source_kind.as_str()),
            capsule_id = escape_html(&delegation.source_capsule_id),
            gaps = delegation.gap_count
        ));
    }
    if delegation_rows.is_empty() {
        delegation_rows.push_str(
            "<tr><td colspan=\"4\" class=\"muted\">No delegation packets created yet.</td></tr>",
        );
    }

    render_review_layout(
        "Review Session Detail",
        "Compare the reviewed evidence set across governance-prep, canary, and production lanes, export a stable snapshot, sign a portable capsule, or launch one bounded evidence re-verification handoff.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Session ID</dt><dd><code>{session_id}</code></dd></div>\
                    <div><dt>Title</dt><dd>{title}</dd></div>\
                    <div><dt>Artifacts</dt><dd>{artifact_count}</dd></div>\
                    <div><dt>Cross-Lane Gaps</dt><dd>{gap_count}</dd></div>\
                    <div><dt>Notes</dt><dd>{notes}</dd></div>\
                </div>\
                <div class=\"grid\">\
                    <article class=\"card\">\
                        <h3>Export Snapshot</h3>\
                        <form method=\"post\" action=\"/v1/operator/review/sessions/{session_id}/export\">\
                            <button type=\"submit\">Create Export</button>\
                        </form>\
                        <p class=\"muted\">Exports preserve digests, signer metadata, verification state, and related stable references for this session.</p>\
                    </article>\
                    <article class=\"card\">\
                        <h3>Portable Review Capsule</h3>\
                        <form method=\"post\" action=\"/v1/operator/review/sessions/{session_id}/capsules\">\
                            <button type=\"submit\">Create Signed Capsule</button>\
                        </form>\
                        <p class=\"muted\">Portable capsules package the cross-lane session into one signed review artifact for external verification without direct store access.</p>\
                    </article>\
                    <article class=\"card\">\
                        <h3>Promotion Readiness Review</h3>\
                        <form method=\"post\" action=\"/v1/operator/review/sessions/{session_id}/promotion-readiness\">\
                            <button type=\"submit\">Create Promotion Readiness Review</button>\
                        </form>\
                        <p class=\"muted\">This remains advisory-only. It summarizes whether governance-prep, canary, and production evidence are all present and free of unresolved gaps.</p>\
                    </article>\
                    <article class=\"card\">\
                        <h3>Re-Verification Handoff</h3>\
                        <form class=\"toolbar\" method=\"post\" action=\"/v1/operator/review/sessions/{session_id}/handoffs/reverify\">\
                            <label>Reason<input type=\"text\" name=\"reason\" placeholder=\"recheck signer integrity before maintenance review\"></label>\
                            <label>Expected key ID<input type=\"text\" name=\"expected_key_id\" placeholder=\"optional signer fingerprint\"></label>\
                            <label style=\"min-width:100%;\">Selected refs<textarea name=\"selected_artifact_refs\" rows=\"4\" placeholder=\"optional; leave empty to use all session refs\"></textarea></label>\
                            <button type=\"submit\">Launch Bounded Handoff</button>\
                        </form>\
                    </article>\
                </div>\
            </section>\
            <section class=\"grid\" style=\"margin-top:18px;\">\
                <article class=\"card\"><h2>Cross-Lane Summary</h2><table><thead><tr><th>Lane</th><th>Artifacts</th><th>Bundles</th><th>Verifications</th><th>Packets</th><th>Refs</th></tr></thead><tbody>{lane_rows}</tbody></table></article>\
                <article class=\"card\"><h2>Evidence Gaps</h2><table><thead><tr><th>Lane</th><th>Code</th><th>Details</th></tr></thead><tbody>{gap_rows}</tbody></table></article>\
            </section>\
            <section class=\"grid\" style=\"margin-top:18px;\">\
                <article class=\"card\"><h2>Evidence Bundles</h2><table><thead><tr><th>Bundle</th><th>Kind</th><th>Subject</th><th>Verification</th></tr></thead><tbody>{bundle_rows}</tbody></table></article>\
                <article class=\"card\"><h2>Verification Reports</h2><table><thead><tr><th>Verification</th><th>Bundle</th><th>Status</th><th>Signer Key</th></tr></thead><tbody>{verification_rows}</tbody></table></article>\
            </section>\
            <section class=\"grid\" style=\"margin-top:18px;\">\
                <article class=\"card\"><h2>Promotion Evidence Packets</h2><table><thead><tr><th>Packet</th><th>Promotion</th><th>Recommendation</th><th>Attachments</th></tr></thead><tbody>{packet_rows}</tbody></table></article>\
                <article class=\"card\"><h2>Recent Exports</h2><table><thead><tr><th>Export</th><th>Artifacts</th></tr></thead><tbody>{export_rows}</tbody></table>\
                <h2 style=\"margin-top:20px;\">Portable Capsules</h2><table><thead><tr><th>Capsule</th><th>Source</th><th>Signer Key</th><th>Gaps</th></tr></thead><tbody>{capsule_rows}</tbody></table>\
                <h2 style=\"margin-top:20px;\">Promotion Readiness Reviews</h2><table><thead><tr><th>Review</th><th>Recommendation</th><th>Gaps</th></tr></thead><tbody>{readiness_rows}</tbody></table>\
                <h2 style=\"margin-top:20px;\">Delegation Packets</h2><table><thead><tr><th>Delegation</th><th>Source</th><th>Capsule</th><th>Gaps</th></tr></thead><tbody>{delegation_rows}</tbody></table>\
                <h2 style=\"margin-top:20px;\">Recent Handoffs</h2><table><thead><tr><th>Handoff</th><th>Status</th><th>Actions</th></tr></thead><tbody>{handoff_rows}</tbody></table></article>\
            </section>",
            session_id = escape_html(&resolved.session.report.session_id),
            title = escape_html(
                resolved
                    .session
                    .report
                    .title
                    .as_deref()
                    .unwrap_or("untitled")
            ),
            artifact_count = resolved.session.report.artifact_refs.len(),
            gap_count = resolved.unresolved_gaps.len(),
            notes = escape_html(resolved.session.report.notes.as_deref().unwrap_or("none")),
            lane_rows = lane_rows,
            gap_rows = gap_rows,
            bundle_rows = bundle_rows,
            verification_rows = verification_rows,
            packet_rows = packet_rows,
            export_rows = export_rows,
            capsule_rows = capsule_rows,
            readiness_rows = readiness_rows,
            delegation_rows = delegation_rows,
            handoff_rows = handoff_rows
        ),
    )
}

fn render_review_session_export_page(export: &ReviewSessionExport) -> String {
    let mut lane_rows = String::new();
    for summary in &export.lane_summaries {
        lane_rows.push_str(&format!(
            "<tr><td>{lane}</td><td>{artifacts}</td><td>{bundles}</td><td>{verifications}</td><td>{packets}</td></tr>",
            lane = escape_html(summary.lane.title()),
            artifacts = summary.artifact_count,
            bundles = summary.evidence_bundle_count,
            verifications = summary.verification_count,
            packets = summary.promotion_packet_count
        ));
    }
    if lane_rows.is_empty() {
        lane_rows.push_str(
            "<tr><td colspan=\"5\" class=\"muted\">No lane summaries exported.</td></tr>",
        );
    }

    let mut gap_rows = String::new();
    for gap in &export.unresolved_gaps {
        gap_rows.push_str(&format!(
            "<tr><td>{lane}</td><td><code>{code}</code></td><td>{details}</td></tr>",
            lane = escape_html(
                gap.lane
                    .map(|lane| lane.title().to_string())
                    .unwrap_or_else(|| "Cross-Lane".to_string())
                    .as_str()
            ),
            code = escape_html(&gap.code),
            details = escape_html(&gap.details)
        ));
    }
    if gap_rows.is_empty() {
        gap_rows.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No unresolved gaps exported.</td></tr>",
        );
    }

    let mut bundle_rows = String::new();
    for bundle in &export.evidence_bundles {
        let verification = bundle
            .latest_verification_status
            .map(|status| render_status_pill(status.as_str(), status.as_str()))
            .unwrap_or_else(|| render_status_pill("unverified", "unverified"));
        bundle_rows.push_str(&format!(
            "<tr><td><code>{bundle_id}</code></td><td>{subject_kind}</td><td><code>{subject_id}</code></td><td><code>{digest}</code></td><td>{verification}</td></tr>",
            bundle_id = escape_html(&bundle.bundle_id),
            subject_kind = escape_html(bundle.subject_kind.as_str()),
            subject_id = escape_html(&bundle.subject_id),
            digest = escape_html(&bundle.payload_sha256),
            verification = verification
        ));
    }
    if bundle_rows.is_empty() {
        bundle_rows
            .push_str("<tr><td colspan=\"5\" class=\"muted\">No bundles exported.</td></tr>");
    }

    let mut verification_rows = String::new();
    for verification in &export.evidence_verifications {
        verification_rows.push_str(&format!(
            "<tr><td><code>{verification_id}</code></td><td><code>{bundle_id}</code></td><td>{status}</td><td><code>{key_id}</code></td></tr>",
            verification_id = escape_html(&verification.verification_id),
            bundle_id = escape_html(&verification.bundle_id),
            status = render_status_pill(verification.status.as_str(), verification.status.as_str()),
            key_id = escape_html(&verification.signer_key_id)
        ));
    }
    if verification_rows.is_empty() {
        verification_rows.push_str(
            "<tr><td colspan=\"4\" class=\"muted\">No verification reports exported.</td></tr>",
        );
    }

    let mut packet_rows = String::new();
    for packet in &export.promotion_packets {
        packet_rows.push_str(&format!(
            "<tr><td><code>{packet_id}</code></td><td><code>{promotion_id}</code></td><td>{recommendation}</td><td>{attachments}</td></tr>",
            packet_id = escape_html(&packet.packet_id),
            promotion_id = escape_html(&packet.promotion_id),
            recommendation = match packet.recommendation {
                PromotionEvidenceRecommendation::ReadyForExternalReview => render_status_pill("ready_for_external_review", "ready"),
                PromotionEvidenceRecommendation::Blocked => render_status_pill("blocked", "blocked"),
            },
            attachments = packet.supporting_evidence.len()
        ));
    }
    if packet_rows.is_empty() {
        packet_rows.push_str(
            "<tr><td colspan=\"4\" class=\"muted\">No promotion packets exported.</td></tr>",
        );
    }

    render_review_layout(
        "Review Session Export",
        "Stable export snapshot preserving the current review set and its trust metadata.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Export ID</dt><dd><code>{export_id}</code></dd></div>\
                    <div><dt>Session ID</dt><dd>{session_link}</dd></div>\
                    <div><dt>Artifacts</dt><dd>{artifacts}</dd></div>\
                    <div><dt>Lane Summaries</dt><dd>{lane_count}</dd></div>\
                    <div><dt>Gaps</dt><dd>{gap_count}</dd></div>\
                    <div><dt>Title</dt><dd>{title}</dd></div>\
                </div>\
                <p class=\"muted\">This export preserves digests, signer metadata, verification state, and related stable references without rereading raw store files.</p>\
                <h2>Cross-Lane Summary</h2><table><thead><tr><th>Lane</th><th>Artifacts</th><th>Bundles</th><th>Verifications</th><th>Packets</th></tr></thead><tbody>{lane_rows}</tbody></table>\
                <h2 style=\"margin-top:20px;\">Unresolved Gaps</h2><table><thead><tr><th>Lane</th><th>Code</th><th>Details</th></tr></thead><tbody>{gap_rows}</tbody></table>\
                <h2>Bundles</h2><table><thead><tr><th>Bundle</th><th>Kind</th><th>Subject</th><th>Payload SHA-256</th><th>Verification</th></tr></thead><tbody>{bundle_rows}</tbody></table>\
                <h2 style=\"margin-top:20px;\">Verification Reports</h2><table><thead><tr><th>Verification</th><th>Bundle</th><th>Status</th><th>Signer Key</th></tr></thead><tbody>{verification_rows}</tbody></table>\
                <h2 style=\"margin-top:20px;\">Promotion Packets</h2><table><thead><tr><th>Packet</th><th>Promotion</th><th>Recommendation</th><th>Attachments</th></tr></thead><tbody>{packet_rows}</tbody></table>\
            </section>",
            export_id = escape_html(&export.export_id),
            session_link = review_link(
                &format!("/v1/operator/review/sessions/{}", export.session_id),
                &export.session_id
            ),
            artifacts = export.artifact_refs.len(),
            lane_count = export.lane_summaries.len(),
            gap_count = export.unresolved_gaps.len(),
            title = escape_html(export.title.as_deref().unwrap_or("untitled")),
            lane_rows = lane_rows,
            gap_rows = gap_rows,
            bundle_rows = bundle_rows,
            verification_rows = verification_rows,
            packet_rows = packet_rows
        ),
    )
}

fn render_review_capsule_page(capsule: &ReviewCapsule) -> String {
    let mut lane_rows = String::new();
    for summary in &capsule.lane_summaries {
        lane_rows.push_str(&format!(
            "<tr><td>{lane}</td><td>{artifacts}</td><td>{bundles}</td><td>{verifications}</td><td>{packets}</td></tr>",
            lane = escape_html(summary.lane.title()),
            artifacts = summary.artifact_count,
            bundles = summary.evidence_bundle_count,
            verifications = summary.verification_count,
            packets = summary.promotion_packet_count
        ));
    }
    if lane_rows.is_empty() {
        lane_rows.push_str(
            "<tr><td colspan=\"5\" class=\"muted\">No lane summaries captured.</td></tr>",
        );
    }

    let mut gap_rows = String::new();
    for gap in &capsule.unresolved_gaps {
        gap_rows.push_str(&format!(
            "<tr><td>{lane}</td><td><code>{code}</code></td><td>{details}</td></tr>",
            lane = escape_html(
                gap.lane
                    .map(|lane| lane.title().to_string())
                    .unwrap_or_else(|| "Cross-Lane".to_string())
                    .as_str()
            ),
            code = escape_html(&gap.code),
            details = escape_html(&gap.details)
        ));
    }
    if gap_rows.is_empty() {
        gap_rows.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No unresolved gaps captured.</td></tr>",
        );
    }

    let mut related_ref_rows = String::new();
    for related in &capsule.related_refs {
        related_ref_rows.push_str(&format!(
            "<tr><td><code>{kind}</code></td><td><code>{id}</code></td></tr>",
            kind = escape_html(&related.kind),
            id = escape_html(&related.id)
        ));
    }
    if related_ref_rows.is_empty() {
        related_ref_rows.push_str(
            "<tr><td colspan=\"2\" class=\"muted\">No related stable refs preserved.</td></tr>",
        );
    }

    render_review_layout(
        "Portable Review Capsule",
        "Signed cross-lane review capsule suitable for external verification without direct store access.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Capsule ID</dt><dd><code>{capsule_id}</code></dd></div>\
                    <div><dt>Session ID</dt><dd>{session_link}</dd></div>\
                    <div><dt>Source</dt><dd><code>{source_kind}</code> / <code>{source_id}</code></dd></div>\
                    <div><dt>Signer</dt><dd><code>{signer_id}</code></dd></div>\
                    <div><dt>Signer Key</dt><dd><code>{signer_key_id}</code></dd></div>\
                    <div><dt>Advisory Only</dt><dd>{advisory_only}</dd></div>\
                </div>\
                <p class=\"muted\">This capsule is signed and portable. It preserves lane summaries, unresolved gaps, and stable evidence references without exposing the local store.</p>\
                <form class=\"toolbar\" method=\"post\" action=\"/v1/operator/review/capsules/{capsule_id}/delegations\">\
                    <label>Reason<input type=\"text\" name=\"reason\" placeholder=\"handoff this signed review to a separate trust boundary\"></label>\
                    <label>Delegate label<input type=\"text\" name=\"delegate_label\" placeholder=\"optional external review group\"></label>\
                    <button type=\"submit\">Create Delegation Packet</button>\
                </form>\
                <h2>Lane Summary</h2><table><thead><tr><th>Lane</th><th>Artifacts</th><th>Bundles</th><th>Verifications</th><th>Packets</th></tr></thead><tbody>{lane_rows}</tbody></table>\
                <h2 style=\"margin-top:20px;\">Unresolved Gaps</h2><table><thead><tr><th>Lane</th><th>Code</th><th>Details</th></tr></thead><tbody>{gap_rows}</tbody></table>\
                <h2 style=\"margin-top:20px;\">Related Stable Refs</h2><table><thead><tr><th>Kind</th><th>ID</th></tr></thead><tbody>{related_ref_rows}</tbody></table>\
            </section>",
            capsule_id = escape_html(&capsule.capsule_id),
            session_link = review_link(
                &format!("/v1/operator/review/sessions/{}", capsule.session_id),
                &capsule.session_id
            ),
            source_kind = escape_html(capsule.source_kind.as_str()),
            source_id = escape_html(&capsule.source_id),
            signer_id = escape_html(&capsule.signature.signer_id),
            signer_key_id = escape_html(&capsule.signature.key_id),
            advisory_only = capsule.advisory_only,
            lane_rows = lane_rows,
            gap_rows = gap_rows,
            related_ref_rows = related_ref_rows
        ),
    )
}

fn render_review_capsule_import_page(import: &ReviewCapsuleImport) -> String {
    let mut check_rows = String::new();
    for check in &import.checks {
        check_rows.push_str(&format!(
            "<tr><td><code>{name}</code></td><td>{status}</td><td>{details}</td></tr>",
            name = escape_html(&check.name),
            status = if check.passed {
                render_status_pill("passed", "passed")
            } else {
                render_status_pill("failed", "failed")
            },
            details = escape_html(&check.details)
        ));
    }
    if check_rows.is_empty() {
        check_rows.push_str("<tr><td colspan=\"3\" class=\"muted\">No checks recorded.</td></tr>");
    }

    let continuation_form = if import.capsule.is_some() {
        format!(
            "<form class=\"toolbar\" method=\"post\" action=\"/v1/operator/review/capsule-imports/{import_id}/delegations\">\
                <label>Reason<input type=\"text\" name=\"reason\" placeholder=\"preserve signed review continuity after import\"></label>\
                <label>Delegate label<input type=\"text\" name=\"delegate_label\" placeholder=\"optional receiving trust boundary\"></label>\
                <button type=\"submit\">Create Delegation Packet</button>\
            </form>",
            import_id = escape_html(&import.import_id)
        )
    } else {
        "<p class=\"muted\">This import did not decode into a valid review capsule, so delegation is unavailable.</p>".to_string()
    };

    render_review_layout(
        "Imported Review Capsule",
        "Local inspection result for one foreign signed review capsule with explicit local trust status.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Import ID</dt><dd><code>{import_id}</code></dd></div>\
                    <div><dt>Source Path</dt><dd><code>{source_path}</code></dd></div>\
                    <div><dt>Trust Status</dt><dd>{trust_status}</dd></div>\
                    <div><dt>Capsule ID</dt><dd><code>{capsule_id}</code></dd></div>\
                    <div><dt>Remote Signer</dt><dd><code>{remote_signer}</code></dd></div>\
                    <div><dt>Remote Key</dt><dd><code>{remote_key}</code></dd></div>\
                    <div><dt>Trusted Key</dt><dd><code>{trusted_key}</code></dd></div>\
                </div>\
                {continuation_form}\
                <h2>Verification Checks</h2><table><thead><tr><th>Check</th><th>Status</th><th>Details</th></tr></thead><tbody>{check_rows}</tbody></table>\
            </section>",
            import_id = escape_html(&import.import_id),
            source_path = escape_html(&import.source_path),
            trust_status =
                render_status_pill(import.trust_status.as_str(), import.trust_status.as_str()),
            capsule_id = escape_html(import.source_capsule_id.as_deref().unwrap_or("unavailable")),
            remote_signer =
                escape_html(import.remote_signer_id.as_deref().unwrap_or("unavailable")),
            remote_key = escape_html(
                import
                    .remote_signer_key_id
                    .as_deref()
                    .unwrap_or("unavailable")
            ),
            trusted_key = escape_html(import.trusted_key_id.as_deref().unwrap_or("none")),
            continuation_form = continuation_form,
            check_rows = check_rows
        ),
    )
}

fn render_review_session_promotion_readiness_page(
    readiness: &ReviewSessionPromotionReadiness,
) -> String {
    let mut lane_rows = String::new();
    for summary in &readiness.lane_summaries {
        lane_rows.push_str(&format!(
            "<tr><td>{lane}</td><td>{artifacts}</td><td>{bundles}</td><td>{verifications}</td><td>{packets}</td></tr>",
            lane = escape_html(summary.lane.title()),
            artifacts = summary.artifact_count,
            bundles = summary.evidence_bundle_count,
            verifications = summary.verification_count,
            packets = summary.promotion_packet_count
        ));
    }
    if lane_rows.is_empty() {
        lane_rows.push_str(
            "<tr><td colspan=\"5\" class=\"muted\">No lane summaries recorded.</td></tr>",
        );
    }

    let mut gap_rows = String::new();
    for gap in &readiness.unresolved_gaps {
        gap_rows.push_str(&format!(
            "<tr><td>{lane}</td><td><code>{code}</code></td><td>{details}</td></tr>",
            lane = escape_html(
                gap.lane
                    .map(|lane| lane.title().to_string())
                    .unwrap_or_else(|| "Cross-Lane".to_string())
                    .as_str()
            ),
            code = escape_html(&gap.code),
            details = escape_html(&gap.details)
        ));
    }
    if gap_rows.is_empty() {
        gap_rows
            .push_str("<tr><td colspan=\"3\" class=\"muted\">No blocking gaps recorded.</td></tr>");
    }

    render_review_layout(
        "Promotion Readiness Review",
        "Advisory-only cross-lane review summarizing whether governance-prep, canary, and production evidence are all present and free of unresolved gaps.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Readiness ID</dt><dd><code>{readiness_id}</code></dd></div>\
                    <div><dt>Session ID</dt><dd>{session_link}</dd></div>\
                    <div><dt>Recommendation</dt><dd>{recommendation}</dd></div>\
                    <div><dt>Advisory Only</dt><dd>{advisory_only}</dd></div>\
                </div>\
                <form method=\"post\" action=\"/v1/operator/review/promotion-readiness/{readiness_id}/capsules\">\
                    <button type=\"submit\">Create Signed Capsule</button>\
                </form>\
                <h2>Lane Summary</h2><table><thead><tr><th>Lane</th><th>Artifacts</th><th>Bundles</th><th>Verifications</th><th>Packets</th></tr></thead><tbody>{lane_rows}</tbody></table>\
                <h2 style=\"margin-top:20px;\">Blocking Gaps</h2><table><thead><tr><th>Lane</th><th>Code</th><th>Details</th></tr></thead><tbody>{gap_rows}</tbody></table>\
            </section>",
            readiness_id = escape_html(&readiness.readiness_id),
            session_link = review_link(
                &format!("/v1/operator/review/sessions/{}", readiness.session_id),
                &readiness.session_id
            ),
            recommendation = render_status_pill(
                readiness.recommendation.as_str(),
                readiness.recommendation.as_str()
            ),
            advisory_only = readiness.advisory_only,
            lane_rows = lane_rows,
            gap_rows = gap_rows
        ),
    )
}

fn render_review_session_handoff_page(handoff: &ReviewSessionMaintenanceHandoff) -> String {
    let mut action_rows = String::new();
    for result in &handoff.action_results {
        action_rows.push_str(&format!(
            "<tr><td><code>{bundle_id}</code></td><td>{action_link}</td><td>{status}</td><td>{verification}</td></tr>",
            bundle_id = escape_html(&result.bundle_id),
            action_link = review_link(
                &format!("/v1/operator/maintenance/actions/{}", result.action_id),
                &result.action_id
            ),
            status = render_maintenance_status_pill(result.status),
            verification = result
                .verification_id
                .as_ref()
                .map(|id| review_link(&format!("/v1/operator/review/verifications/{id}"), id))
                .unwrap_or_else(|| "<span class=\"muted\">none</span>".to_string())
        ));
    }
    if action_rows.is_empty() {
        action_rows.push_str(
            "<tr><td colspan=\"4\" class=\"muted\">No maintenance actions were recorded.</td></tr>",
        );
    }

    let selected_refs = if handoff.selected_artifact_refs.is_empty() {
        "<li class=\"muted\">No selected refs recorded.</li>".to_string()
    } else {
        handoff
            .selected_artifact_refs
            .iter()
            .map(|artifact| {
                format!(
                    "<li><code>{}:{}</code></li>",
                    artifact.kind.as_str(),
                    escape_html(&artifact.id)
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    render_review_layout(
        "Review Session Handoff",
        "Bounded maintenance handoff launched from the evidence workbench. This flow can re-verify evidence bundles but cannot bypass rollout or governance lanes.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Handoff ID</dt><dd><code>{handoff_id}</code></dd></div>\
                    <div><dt>Session ID</dt><dd>{session_link}</dd></div>\
                    <div><dt>Status</dt><dd>{status}</dd></div>\
                    <div><dt>Reason</dt><dd>{reason}</dd></div>\
                    <div><dt>Expected Key</dt><dd>{expected_key}</dd></div>\
                    <div><dt>Derived Bundles</dt><dd>{bundle_count}</dd></div>\
                </div>\
                <h3>Selected Artifact Refs</h3><ul>{selected_refs}</ul>\
                <h3>Maintenance Actions</h3><table><thead><tr><th>Bundle</th><th>Action</th><th>Status</th><th>Verification</th></tr></thead><tbody>{action_rows}</tbody></table>\
            </section>",
            handoff_id = escape_html(&handoff.handoff_id),
            session_link = review_link(
                &format!("/v1/operator/review/sessions/{}", handoff.session_id),
                &handoff.session_id
            ),
            status = render_maintenance_status_pill(handoff.status),
            reason = escape_html(&handoff.reason),
            expected_key = handoff
                .expected_key_id
                .as_deref()
                .map(escape_html)
                .unwrap_or_else(|| "none".to_string()),
            bundle_count = handoff.derived_bundle_ids.len(),
            selected_refs = selected_refs,
            action_rows = action_rows
        ),
    )
}

fn render_review_delegation_page(packet: &ReviewDelegationPacket) -> String {
    let mut lane_rows = String::new();
    for summary in &packet.lane_summaries {
        lane_rows.push_str(&format!(
            "<tr><td>{lane}</td><td>{artifacts}</td><td>{bundles}</td><td>{verifications}</td><td>{packets}</td></tr>",
            lane = escape_html(summary.lane.title()),
            artifacts = summary.artifact_count,
            bundles = summary.evidence_bundle_count,
            verifications = summary.verification_count,
            packets = summary.promotion_packet_count
        ));
    }
    if lane_rows.is_empty() {
        lane_rows.push_str(
            "<tr><td colspan=\"5\" class=\"muted\">No lane summaries preserved.</td></tr>",
        );
    }

    render_review_layout(
        "Review Delegation Packet",
        "Signed advisory-only continuity artifact preserving one review handoff across trust boundaries.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Delegation ID</dt><dd><code>{delegation_id}</code></dd></div>\
                    <div><dt>Session ID</dt><dd>{session_link}</dd></div>\
                    <div><dt>Source Capsule</dt><dd>{capsule_link}</dd></div>\
                    <div><dt>Source Kind</dt><dd><code>{source_kind}</code></dd></div>\
                    <div><dt>Imported Trust</dt><dd>{imported_trust}</dd></div>\
                    <div><dt>Signer Key</dt><dd><code>{signer_key}</code></dd></div>\
                    <div><dt>Delegate Label</dt><dd>{delegate_label}</dd></div>\
                </div>\
                <p>{reason}</p>\
                <h2>Lane Summary</h2><table><thead><tr><th>Lane</th><th>Artifacts</th><th>Bundles</th><th>Verifications</th><th>Packets</th></tr></thead><tbody>{lane_rows}</tbody></table>\
            </section>",
            delegation_id = escape_html(&packet.delegation_id),
            session_link = review_link(
                &format!("/v1/operator/review/sessions/{}", packet.session_id),
                &packet.session_id
            ),
            capsule_link = review_link(
                &format!("/v1/operator/review/capsules/{}", packet.source_capsule_id),
                &packet.source_capsule_id
            ),
            source_kind = escape_html(packet.source_kind.as_str()),
            imported_trust = packet
                .imported_trust_status
                .map(|status| render_status_pill(status.as_str(), status.as_str()))
                .unwrap_or_else(|| "<span class=\"muted\">local capsule</span>".to_string()),
            signer_key = escape_html(&packet.signature.key_id),
            delegate_label = escape_html(packet.delegate_label.as_deref().unwrap_or("none")),
            reason = escape_html(&packet.reason),
            lane_rows = lane_rows
        ),
    )
}

fn render_maintenance_status_pill(status: OperatorMaintenanceStatus) -> String {
    let (label, class_name) = match status {
        OperatorMaintenanceStatus::Applied => ("applied", "passed"),
        OperatorMaintenanceStatus::Blocked => ("blocked", "blocked"),
        OperatorMaintenanceStatus::Failed => ("failed", "failed"),
    };
    render_status_pill(label, class_name)
}

fn render_providence_incident_status(status: ProvidenceIncidentStatus) -> &'static str {
    match status {
        ProvidenceIncidentStatus::Open => "open",
        ProvidenceIncidentStatus::Investigating => "investigating",
        ProvidenceIncidentStatus::Resolved => "resolved",
    }
}

fn render_providence_reconciliation_outcome(
    outcome: ProvidenceReconciliationOutcome,
) -> (&'static str, &'static str) {
    match outcome {
        ProvidenceReconciliationOutcome::InSync => ("in_sync", "passed"),
        ProvidenceReconciliationOutcome::SwarmAhead => ("swarm_ahead", "ready"),
        ProvidenceReconciliationOutcome::ProvidenceAhead => ("providence_ahead", "blocked"),
        ProvidenceReconciliationOutcome::Mismatch => ("mismatch", "failed"),
    }
}

fn render_rehearsal_preview_details(preview: &ResponseRehearsalPreview) -> String {
    let affected_capabilities = if preview.blast_radius.affected_capabilities.is_empty() {
        "<li class=\"muted\">No affected capabilities recorded.</li>".to_string()
    } else {
        preview
            .blast_radius
            .affected_capabilities
            .iter()
            .map(|value| format!("<li><code>{}</code></li>", escape_html(value)))
            .collect::<Vec<_>>()
            .join("")
    };
    let rollback_steps = if preview.rollback.steps.is_empty() {
        "<li class=\"muted\">No explicit rollback steps recorded.</li>".to_string()
    } else {
        preview
            .rollback
            .steps
            .iter()
            .map(|step| format!("<li>{}</li>", escape_html(&step.summary)))
            .collect::<Vec<_>>()
            .join("")
    };

    format!(
        "<div class=\"meta\">\
            <div><dt>Rehearsal ID</dt><dd><code>{rehearsal_id}</code></dd></div>\
            <div><dt>Source Bundle</dt><dd><code>{source_bundle_id}</code></dd></div>\
            <div><dt>Dry Run Only</dt><dd>{dry_run}</dd></div>\
            <div><dt>Blast Radius</dt><dd>{blast_summary}</dd></div>\
            <div><dt>Rollback</dt><dd>{rollback_summary}</dd></div>\
        </div>\
        <p class=\"muted\">{impact_summary}</p>\
        <h3>Affected Capabilities</h3><ul>{affected_capabilities}</ul>\
        <h3>Rollback Steps</h3><ul>{rollback_steps}</ul>",
        rehearsal_id = escape_html(&preview.rehearsal_id),
        source_bundle_id = escape_html(&preview.source_bundle_id),
        dry_run = if preview.simulated_only { "yes" } else { "no" },
        blast_summary = escape_html(&preview.blast_radius.summary),
        rollback_summary = escape_html(&preview.rollback.summary),
        impact_summary = escape_html(&format!(
            "{} scope `{}` with up to {} affected scope(s)",
            format!("{:?}", preview.blast_radius.impact).to_lowercase(),
            preview.blast_radius.scope_value,
            preview.blast_radius.max_affected_scopes,
        )),
        affected_capabilities = affected_capabilities,
        rollback_steps = rollback_steps,
    )
}

fn render_review_home_context_card(context: &ReviewHomeContext) -> String {
    let selected_bundle_card = context
        .selected_bundle
        .as_ref()
        .map(|bundle| {
            format!(
                "<article class=\"card\">\
                    <h2>Scoped Replay</h2>\
                    <div class=\"meta\">\
                        <div><dt>Bundle</dt><dd><code>{bundle_id}</code></dd></div>\
                        <div><dt>Hunt</dt><dd><code>{hunt_id}</code></dd></div>\
                        <div><dt>Response</dt><dd><code>{response_kind}</code></dd></div>\
                    </div>\
                    <p class=\"muted\">{note}</p>\
                    <p>{replay_link}</p>\
                </article>",
                bundle_id = escape_html(&bundle.record.bundle_id),
                hunt_id = escape_html(&bundle.record.hunt_id),
                response_kind = escape_html(&bundle.preview.response_kind),
                note = escape_html(&bundle.preview.note),
                replay_link = review_link(
                    &format!("/v1/operator/replay?bundle_id={}", bundle.record.bundle_id),
                    "Open raw replay JSON"
                ),
            )
        })
        .unwrap_or_else(|| {
            "<article class=\"card\"><h2>Scoped Replay</h2><p class=\"muted\">No replay bundle matched the supplied scope.</p></article>"
                .to_string()
        });

    let rehearsal_card = context
        .latest_rehearsal_bundle
        .as_ref()
        .and_then(|bundle| bundle.bundle.rehearsal.as_ref().map(|preview| (bundle, preview)))
        .map(|(bundle, preview)| {
            let signed_proof = context
                .signed_rehearsal_bundle_id
                .as_deref()
                .map(|bundle_id| {
                    review_link(
                        &format!("/v1/operator/review/evidence/{bundle_id}"),
                        "Open signed rehearsal proof",
                    )
                })
                .unwrap_or_else(|| {
                    format!(
                        "<form method=\"post\" action=\"/v1/operator/review/rehearsals/{bundle_id}/export\">\
                            <button type=\"submit\">Export Signed Rehearsal Proof</button>\
                        </form>",
                        bundle_id = escape_html(&bundle.record.bundle_id),
                    )
                });
            format!(
                "<article class=\"card\">\
                    <h2>Latest Rehearsal Proof</h2>\
                    <p>{signed_proof}</p>\
                    {details}\
                </article>",
                signed_proof = signed_proof,
                details = render_rehearsal_preview_details(preview),
            )
        })
        .unwrap_or_else(|| {
            "<article class=\"card\"><h2>Latest Rehearsal Proof</h2><p class=\"muted\">No persisted dry-run rehearsal is available for this scope yet.</p></article>"
                .to_string()
        });

    let incident_card = context
        .incident
        .as_ref()
        .map(|incident| {
            let reconciliation = incident
                .incident
                .providence_reconciliation
                .as_ref()
                .map(|reconciliation| {
                    let (outcome_label, outcome_class) =
                        render_providence_reconciliation_outcome(reconciliation.outcome);
                    format!(
                        "<div class=\"meta\">\
                            <div><dt>Remote Incident</dt><dd><code>{remote_id}</code></dd></div>\
                            <div><dt>Outcome</dt><dd>{outcome}</dd></div>\
                            <div><dt>Remote Status</dt><dd><code>{remote_status}</code></dd></div>\
                            <div><dt>Needs Review</dt><dd>{needs_review}</dd></div>\
                        </div>\
                        <p class=\"muted\">{summary}</p>",
                        remote_id = escape_html(&reconciliation.remote_incident_id),
                        outcome = render_status_pill(outcome_label, outcome_class),
                        remote_status = escape_html(render_providence_incident_status(
                            reconciliation.remote_status
                        )),
                        needs_review = if reconciliation.needs_review { "yes" } else { "no" },
                        summary = escape_html(&reconciliation.summary),
                    )
                })
                .unwrap_or_else(|| {
                    "<p class=\"muted\">No Providence reconciliation has been recorded for this incident yet.</p>"
                        .to_string()
                });
            format!(
                "<article class=\"card\">\
                    <h2>Providence Reconciliation</h2>\
                    <div class=\"meta\">\
                        <div><dt>Incident</dt><dd><code>{incident_id}</code></dd></div>\
                        <div><dt>Summary</dt><dd>{summary}</dd></div>\
                    </div>\
                    {reconciliation}\
                    <p>{incident_link}</p>\
                </article>",
                incident_id = escape_html(&incident.record.incident_id),
                summary = escape_html(&incident.record.summary),
                reconciliation = reconciliation,
                incident_link = review_link(
                    &format!("/v1/operator/incident?incident_id={}", incident.record.incident_id),
                    "Open raw incident JSON"
                ),
            )
        })
        .unwrap_or_else(|| {
            "<article class=\"card\"><h2>Providence Reconciliation</h2><p class=\"muted\">No correlated incident matched the supplied scope.</p></article>"
                .to_string()
        });

    format!(
        "<section class=\"grid\" style=\"margin-bottom:18px;\">{selected_bundle_card}{rehearsal_card}{incident_card}</section>",
        selected_bundle_card = selected_bundle_card,
        rehearsal_card = rehearsal_card,
        incident_card = incident_card,
    )
}

#[allow(clippy::too_many_arguments)]
fn render_review_home_page(
    runtime_base_url: &str,
    context: Option<&ReviewHomeContext>,
    bundles: &EvidenceBundleList,
    packets: &PromotionEvidencePacketList,
    sessions: &ReviewSessionList,
    capsules: &ReviewCapsuleList,
    imports: &ReviewCapsuleImportList,
    delegations: &ReviewDelegationPacketList,
) -> String {
    let mut bundle_rows = String::new();
    for bundle in &bundles.bundles {
        let verification = bundle
            .latest_verification_status
            .map(|status| render_status_pill(status.as_str(), status.as_str()))
            .unwrap_or_else(|| render_status_pill("unverified", "unverified"));
        bundle_rows.push_str(&format!(
            "<tr><td>{bundle_link}</td><td>{kind}</td><td>{subject}</td><td>{verification}</td></tr>",
            bundle_link = review_link(
                &format!("/v1/operator/review/evidence/{}", bundle.bundle_id),
                &bundle.bundle_id
            ),
            kind = escape_html(bundle.subject_kind.as_str()),
            subject = escape_html(&bundle.subject_id),
            verification = verification
        ));
    }

    let mut packet_rows = String::new();
    for packet in &packets.packets {
        let recommendation = if packet.ready_for_external_review {
            render_status_pill("ready_for_external_review", "ready")
        } else {
            render_status_pill("blocked", "blocked")
        };
        packet_rows.push_str(&format!(
            "<tr><td>{packet_link}</td><td>{promotion}</td><td>{recommendation}</td></tr>",
            packet_link = review_link(
                &format!("/v1/operator/review/promotion-packets/{}", packet.packet_id),
                &packet.packet_id
            ),
            promotion = escape_html(&packet.promotion_id),
            recommendation = recommendation
        ));
    }

    let mut session_rows = String::new();
    for session in &sessions.sessions {
        session_rows.push_str(&format!(
            "<tr><td>{session_link}</td><td>{title}</td><td>{artifacts}</td></tr>",
            session_link = review_link(
                &format!("/v1/operator/review/sessions/{}", session.session_id),
                &session.session_id
            ),
            title = escape_html(session.title.as_deref().unwrap_or("untitled")),
            artifacts = session.artifact_count
        ));
    }
    if session_rows.is_empty() {
        session_rows.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No review sessions created yet.</td></tr>",
        );
    }

    let mut capsule_rows = String::new();
    for capsule in &capsules.capsules {
        capsule_rows.push_str(&format!(
            "<tr><td>{capsule_link}</td><td><code>{source_kind}</code></td><td><code>{key_id}</code></td></tr>",
            capsule_link = review_link(
                &format!("/v1/operator/review/capsules/{}", capsule.capsule_id),
                &capsule.capsule_id
            ),
            source_kind = escape_html(capsule.source_kind.as_str()),
            key_id = escape_html(&capsule.signer_key_id)
        ));
    }
    if capsule_rows.is_empty() {
        capsule_rows.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No review capsules created yet.</td></tr>",
        );
    }

    let mut import_rows = String::new();
    for import in &imports.imports {
        import_rows.push_str(&format!(
            "<tr><td>{import_link}</td><td>{status}</td><td><code>{remote_key}</code></td></tr>",
            import_link = review_link(
                &format!("/v1/operator/review/capsule-imports/{}", import.import_id),
                &import.import_id
            ),
            status = render_status_pill(import.trust_status.as_str(), import.trust_status.as_str()),
            remote_key = escape_html(
                import
                    .remote_signer_key_id
                    .as_deref()
                    .unwrap_or("unavailable")
            )
        ));
    }
    if import_rows.is_empty() {
        import_rows.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No foreign review capsules imported yet.</td></tr>",
        );
    }

    let mut delegation_rows = String::new();
    for delegation in &delegations.delegations {
        delegation_rows.push_str(&format!(
            "<tr><td>{delegation_link}</td><td><code>{source_kind}</code></td><td><code>{capsule_id}</code></td></tr>",
            delegation_link = review_link(
                &format!("/v1/operator/review/delegations/{}", delegation.delegation_id),
                &delegation.delegation_id
            ),
            source_kind = escape_html(delegation.source_kind.as_str()),
            capsule_id = escape_html(&delegation.source_capsule_id)
        ));
    }
    if delegation_rows.is_empty() {
        delegation_rows.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No delegation packets created yet.</td></tr>",
        );
    }

    let demo_dashboard = render_demo_dashboard_panel(runtime_base_url);

    let scoped_context = context
        .map(render_review_home_context_card)
        .unwrap_or_default();

    render_review_layout(
        "Local Evidence Review",
        "Authenticated local evidence workbench layered on the operator API. Portable signed review capsules and imported continuity are available, but rollout and governance remain out of scope.",
        &format!(
            "{demo_dashboard}\
            {scoped_context}\
            <section class=\"grid\">\
                <article class=\"card\"><h2>Review Scope</h2><p>Use this surface to inspect signed evidence bundles, verification reports, and promotion evidence packets without reading store files directly.</p><p class=\"muted\">Authentication stays on the existing bearer-token boundary, and follow-on write actions remain on the existing maintenance or rollout paths.</p></article>\
                <article class=\"card\"><h2>Import Foreign Capsule</h2>\
                    <form class=\"toolbar\" method=\"post\" action=\"/v1/operator/review/capsule-imports\">\
                        <label>Source path<input type=\"text\" name=\"source_path\" placeholder=\"/tmp/review_capsule.json\"></label>\
                        <label>Expected key ID<input type=\"text\" name=\"expected_key_id\" placeholder=\"optional local trust anchor\"></label>\
                        <button type=\"submit\">Import Capsule</button>\
                    </form>\
                    <p class=\"muted\">Imported capsules stay advisory-only and preserve remote signer lineage, local trust status, and related stable refs.</p>\
                </article>\
                <article class=\"card\"><h2>Quick Links</h2><ul>\
                    <li>{sessions_link}</li><li>{evidence}</li><li>{packets}</li><li>{json}</li>\
                </ul></article>\
            </section>\
            <section class=\"grid\" style=\"margin-top:18px;\">\
                <article class=\"card\"><h2>Recent Evidence Bundles</h2><table><thead><tr><th>Bundle</th><th>Kind</th><th>Subject</th><th>Verification</th></tr></thead><tbody>{bundle_rows}</tbody></table></article>\
                <article class=\"card\"><h2>Recent Promotion Packets</h2><table><thead><tr><th>Packet</th><th>Promotion</th><th>Recommendation</th></tr></thead><tbody>{packet_rows}</tbody></table></article>\
            </section>\
            <section class=\"grid\" style=\"margin-top:18px;\">\
                <article class=\"card\"><h2>Recent Review Sessions</h2><table><thead><tr><th>Session</th><th>Title</th><th>Artifacts</th></tr></thead><tbody>{session_rows}</tbody></table></article>\
                <article class=\"card\"><h2>Portable Capsules</h2><table><thead><tr><th>Capsule</th><th>Source</th><th>Signer Key</th></tr></thead><tbody>{capsule_rows}</tbody></table></article>\
            </section>\
            <section class=\"grid\" style=\"margin-top:18px;\">\
                <article class=\"card\"><h2>Imported Capsules</h2><table><thead><tr><th>Import</th><th>Trust</th><th>Remote Key</th></tr></thead><tbody>{import_rows}</tbody></table></article>\
                <article class=\"card\"><h2>Delegation Packets</h2><table><thead><tr><th>Delegation</th><th>Source</th><th>Capsule</th></tr></thead><tbody>{delegation_rows}</tbody></table></article>\
            </section>",
            sessions_link = review_link("/v1/operator/review/sessions", "Open review sessions"),
            evidence = review_link("/v1/operator/review/evidence", "Browse signed evidence"),
            packets = review_link(
                "/v1/operator/review/promotion-packets",
                "Browse promotion evidence packets"
            ),
            json = review_link(
                "/v1/operator/evidence/bundles",
                "Open raw evidence JSON API"
            ),
            demo_dashboard = demo_dashboard,
            scoped_context = scoped_context,
            bundle_rows = bundle_rows,
            packet_rows = packet_rows,
            session_rows = session_rows,
            capsule_rows = capsule_rows,
            import_rows = import_rows,
            delegation_rows = delegation_rows
        ),
    )
}

fn render_review_evidence_list_page(
    list: &EvidenceBundleList,
    verification_status: Option<ReviewEvidenceVerificationFilter>,
) -> String {
    let mut rows = String::new();
    for bundle in &list.bundles {
        let verification = bundle
            .latest_verification_status
            .map(|status| render_status_pill(status.as_str(), status.as_str()))
            .unwrap_or_else(|| render_status_pill("unverified", "unverified"));
        let verification_link = bundle
            .latest_verification_id
            .as_ref()
            .map(|id| review_link(&format!("/v1/operator/review/verifications/{id}"), id))
            .unwrap_or_else(|| "<span class=\"muted\">none</span>".to_string());
        rows.push_str(&format!(
            "<tr><td>{bundle_link}</td><td>{kind}</td><td>{subject}</td><td>{verification}</td><td>{verification_link}</td></tr>",
            bundle_link = review_link(
                &format!("/v1/operator/review/evidence/{}", bundle.bundle_id),
                &bundle.bundle_id
            ),
            kind = escape_html(bundle.subject_kind.as_str()),
            subject = escape_html(&bundle.subject_id),
            verification = verification,
            verification_link = verification_link
        ));
    }

    render_review_layout(
        "Evidence Inspection",
        "Browse signed evidence bundles by subject kind and latest verification state.",
        &format!(
            "<section class=\"card\">\
                <form class=\"toolbar\" method=\"get\" action=\"/v1/operator/review/evidence\">\
                    <label>Subject kind<select name=\"subject_kind\">{subject_options}</select></label>\
                    <label>Verification<select name=\"verification_status\">{verification_options}</select></label>\
                    <label>Limit<input type=\"number\" min=\"1\" name=\"limit\" value=\"{limit}\"></label>\
                    <button type=\"submit\">Apply Filters</button>\
                </form>\
                <p class=\"muted\">Showing {count} evidence bundles from the authenticated evidence store.</p>\
                <table><thead><tr><th>Bundle</th><th>Subject Kind</th><th>Subject ID</th><th>Latest Verification</th><th>Verification Page</th></tr></thead><tbody>{rows}</tbody></table>\
            </section>",
            subject_options = render_subject_kind_options(list.subject_kind),
            verification_options = render_verification_filter_options(verification_status),
            limit = list.total_count.max(1),
            count = list.total_count,
            rows = rows
        ),
    )
}

fn render_review_evidence_bundle_page(
    bundle: &EvidenceBundle,
    latest_verification_status: Option<EvidenceVerificationStatus>,
    latest_verification: Option<&EvidenceVerificationReport>,
) -> String {
    let verification_badge = latest_verification_status
        .map(|status| render_status_pill(status.as_str(), status.as_str()))
        .unwrap_or_else(|| render_status_pill("unverified", "unverified"));
    let verification_link = latest_verification
        .map(|report| {
            review_link(
                &format!(
                    "/v1/operator/review/verifications/{}",
                    report.verification_id
                ),
                &report.verification_id,
            )
        })
        .unwrap_or_else(|| "<span class=\"muted\">none</span>".to_string());

    let subject_target = subject_api_path(bundle.subject.kind, &bundle.subject.stable_id)
        .map(|href| review_link(&href, "Open related raw API artifact"))
        .unwrap_or_else(|| {
            "<span class=\"muted\">No raw API route for this subject kind yet</span>".to_string()
        });

    let mut related_refs = String::new();
    for related in &bundle.subject.related_refs {
        related_refs.push_str(&format!(
            "<li>{kind}: {link}</li>",
            kind = escape_html(&related.kind),
            link = render_related_ref_link(&related.kind, &related.id)
        ));
    }
    if related_refs.is_empty() {
        related_refs.push_str("<li class=\"muted\">No related references recorded.</li>");
    }

    let mut receipt_refs = String::new();
    for reference in &bundle.subject.receipt_chain_refs {
        receipt_refs.push_str(&format!("<li><code>{}</code></li>", escape_html(reference)));
    }
    if receipt_refs.is_empty() {
        receipt_refs.push_str("<li class=\"muted\">No receipt references recorded.</li>");
    }

    render_review_layout(
        "Evidence Bundle Detail",
        "Signed artifact metadata first, canonical payload second. This page stays read-only and points back to the authenticated JSON API when needed.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Bundle ID</dt><dd><code>{bundle_id}</code></dd></div>\
                    <div><dt>Subject</dt><dd>{kind} <code>{subject_id}</code></dd></div>\
                    <div><dt>Latest Verification</dt><dd>{verification_badge}</dd></div>\
                    <div><dt>Signer</dt><dd>{signer} (<code>{key_id}</code>)</dd></div>\
                    <div><dt>Payload SHA-256</dt><dd><code>{payload_sha}</code></dd></div>\
                    <div><dt>Related Artifact</dt><dd>{subject_target}</dd></div>\
                </div>\
                <p><strong>Verification page:</strong> {verification_link}</p>\
                <h3>Related References</h3><ul>{related_refs}</ul>\
                <h3>Receipt Chain References</h3><ul>{receipt_refs}</ul>\
                <details><summary>Canonical payload JSON</summary><pre>{payload}</pre></details>\
                <details><summary>Raw JSON API</summary><p>{raw_link}</p></details>\
            </section>",
            bundle_id = escape_html(&bundle.bundle_id),
            kind = escape_html(bundle.subject.kind.as_str()),
            subject_id = escape_html(&bundle.subject.stable_id),
            verification_badge = verification_badge,
            signer = escape_html(&bundle.signature.signer_id),
            key_id = escape_html(&bundle.signature.key_id),
            payload_sha = escape_html(&bundle.payload_sha256),
            subject_target = subject_target,
            verification_link = verification_link,
            related_refs = related_refs,
            receipt_refs = receipt_refs,
            payload = escape_html(&bundle.canonical_payload),
            raw_link = review_link(
                &format!("/v1/operator/evidence/bundles/{}", bundle.bundle_id),
                "Open the raw JSON bundle response"
            )
        ),
    )
}

fn render_review_evidence_verification_page(report: &EvidenceVerificationReport) -> String {
    let mut checks = String::new();
    for check in &report.checks {
        checks.push_str(&format!(
            "<tr><td>{name}</td><td>{status}</td><td>{details}</td></tr>",
            name = escape_html(&check.name),
            status = if check.passed {
                render_status_pill("passed", "passed")
            } else {
                render_status_pill("failed", "failed")
            },
            details = escape_html(&check.details)
        ));
    }
    if checks.is_empty() {
        checks.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No verification checks recorded.</td></tr>",
        );
    }

    render_review_layout(
        "Evidence Verification Detail",
        "Verification reports show the exact integrity checks applied to one signed evidence bundle.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Verification ID</dt><dd><code>{verification_id}</code></dd></div>\
                    <div><dt>Bundle</dt><dd>{bundle_link}</dd></div>\
                    <div><dt>Status</dt><dd>{status}</dd></div>\
                    <div><dt>Signer</dt><dd>{signer} (<code>{key_id}</code>)</dd></div>\
                    <div><dt>Expected Key</dt><dd>{expected_key}</dd></div>\
                </div>\
                <table><thead><tr><th>Check</th><th>Status</th><th>Details</th></tr></thead><tbody>{checks}</tbody></table>\
                <details><summary>Raw JSON API</summary><p>{raw_link}</p></details>\
            </section>",
            verification_id = escape_html(&report.verification_id),
            bundle_link = review_link(
                &format!("/v1/operator/review/evidence/{}", report.bundle_id),
                &report.bundle_id
            ),
            status = render_status_pill(report.status.as_str(), report.status.as_str()),
            signer = escape_html(&report.signer_id),
            key_id = escape_html(&report.signer_key_id),
            expected_key = report
                .expected_key_id
                .as_deref()
                .map(escape_html)
                .unwrap_or_else(|| "none".to_string()),
            checks = checks,
            raw_link = review_link(
                &format!(
                    "/v1/operator/evidence/verifications/{}",
                    report.verification_id
                ),
                "Open the raw JSON verification response"
            )
        ),
    )
}

fn render_review_promotion_packet_list_page(
    list: &PromotionEvidencePacketList,
    recommendation: Option<PromotionEvidenceRecommendation>,
) -> String {
    let mut rows = String::new();
    for packet in &list.packets {
        let pill = if packet.ready_for_external_review {
            render_status_pill("ready_for_external_review", "ready")
        } else {
            render_status_pill("blocked", "blocked")
        };
        rows.push_str(&format!(
            "<tr><td>{packet_link}</td><td>{promotion_id}</td><td>{recommendation}</td></tr>",
            packet_link = review_link(
                &format!("/v1/operator/review/promotion-packets/{}", packet.packet_id),
                &packet.packet_id
            ),
            promotion_id = escape_html(&packet.promotion_id),
            recommendation = pill
        ));
    }

    render_review_layout(
        "Promotion Evidence Review",
        "Promotion evidence packets stay advisory. This review flow is for operator understanding, not approval or deployment.",
        &format!(
            "<section class=\"card\">\
                <form class=\"toolbar\" method=\"get\" action=\"/v1/operator/review/promotion-packets\">\
                    <label>Recommendation<select name=\"recommendation\">{recommendation_options}</select></label>\
                    <label>Limit<input type=\"number\" min=\"1\" name=\"limit\" value=\"{limit}\"></label>\
                    <button type=\"submit\">Apply Filters</button>\
                </form>\
                <table><thead><tr><th>Packet</th><th>Promotion ID</th><th>Recommendation</th></tr></thead><tbody>{rows}</tbody></table>\
            </section>",
            recommendation_options = render_promotion_recommendation_options(recommendation),
            limit = list.total_count.max(1),
            rows = rows
        ),
    )
}

fn render_review_promotion_packet_page(packet: &PromotionEvidencePacket) -> String {
    let mut attachment_rows = String::new();
    for attachment in &packet.supporting_evidence {
        let bundle_link = attachment
            .bundle_id
            .as_ref()
            .map(|id| review_link(&format!("/v1/operator/review/evidence/{id}"), id))
            .unwrap_or_else(|| "<span class=\"muted\">none</span>".to_string());
        let verification_link = attachment
            .verification_id
            .as_ref()
            .map(|id| review_link(&format!("/v1/operator/review/verifications/{id}"), id))
            .unwrap_or_else(|| "<span class=\"muted\">none</span>".to_string());
        let status = attachment
            .verification_status
            .map(|status| render_status_pill(status.as_str(), status.as_str()))
            .unwrap_or_else(|| render_status_pill("unverified", "unverified"));
        attachment_rows.push_str(&format!(
            "<tr><td>{kind}</td><td><code>{subject_id}</code></td><td>{bundle_link}</td><td>{verification_link}</td><td>{status}</td><td>{details}</td></tr>",
            kind = escape_html(attachment.subject_kind.as_str()),
            subject_id = escape_html(&attachment.subject_id),
            bundle_link = bundle_link,
            verification_link = verification_link,
            status = status,
            details = escape_html(&attachment.details)
        ));
    }
    if attachment_rows.is_empty() {
        attachment_rows.push_str(
            "<tr><td colspan=\"6\" class=\"muted\">No supporting evidence attached.</td></tr>",
        );
    }

    let mut blocking_reasons = String::new();
    for reason in &packet.blocking_reasons {
        blocking_reasons.push_str(&format!(
            "<li><strong>{name}</strong>: {details}</li>",
            name = escape_html(&reason.name),
            details = escape_html(&reason.details)
        ));
    }
    if blocking_reasons.is_empty() {
        blocking_reasons.push_str("<li class=\"muted\">No blocking reasons recorded.</li>");
    }

    let recommendation = render_status_pill(
        packet.recommendation.as_str(),
        match packet.recommendation {
            PromotionEvidenceRecommendation::ReadyForExternalReview => "ready",
            PromotionEvidenceRecommendation::Blocked => "blocked",
        },
    );

    render_review_layout(
        "Promotion Evidence Packet Detail",
        "Promotion evidence packets summarize rollout outcome and supporting signed evidence. They remain advisory and do not authorize rollout.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Packet ID</dt><dd><code>{packet_id}</code></dd></div>\
                    <div><dt>Promotion ID</dt><dd><code>{promotion_id}</code></dd></div>\
                    <div><dt>Recommendation</dt><dd>{recommendation}</dd></div>\
                    <div><dt>Promotion Status</dt><dd>{promotion_status}</dd></div>\
                    <div><dt>Promoted Strategy</dt><dd><code>{promoted_strategy}</code></dd></div>\
                    <div><dt>Fallback Strategy</dt><dd><code>{fallback_strategy}</code></dd></div>\
                    <div><dt>Canary Run</dt><dd><code>{canary_run}</code></dd></div>\
                    <div><dt>Verification ID</dt><dd><code>{verification_id}</code></dd></div>\
                    <div><dt>Shadow ID</dt><dd><code>{shadow_id}</code></dd></div>\
                    <div><dt>Advisory Only</dt><dd>{advisory_only}</dd></div>\
                </div>\
                <p class=\"muted\">Follow-on rollout or maintenance actions still go through the existing authenticated APIs and audit trails. This page is read-only by design.</p>\
                <h3>Blocking Reasons</h3><ul>{blocking_reasons}</ul>\
                <h3>Supporting Evidence</h3><table><thead><tr><th>Kind</th><th>Subject ID</th><th>Bundle</th><th>Verification</th><th>Status</th><th>Details</th></tr></thead><tbody>{attachment_rows}</tbody></table>\
                <details><summary>Raw JSON API</summary><p>{raw_link}</p></details>\
            </section>",
            packet_id = escape_html(&packet.packet_id),
            promotion_id = escape_html(&packet.promotion_id),
            recommendation = recommendation,
            promotion_status =
                escape_html(&format!("{:?}", packet.promotion_status).to_lowercase()),
            promoted_strategy = escape_html(&packet.promoted_strategy_id),
            fallback_strategy = escape_html(&packet.fallback_strategy_id),
            canary_run = escape_html(&packet.canary_run_id),
            verification_id = escape_html(&packet.verification_id),
            shadow_id = escape_html(&packet.shadow_id),
            advisory_only = if packet.advisory_only { "yes" } else { "no" },
            blocking_reasons = blocking_reasons,
            attachment_rows = attachment_rows,
            raw_link = review_link(
                &format!(
                    "/v1/operator/evidence/promotion-packets/{}",
                    packet.packet_id
                ),
                "Open the raw JSON promotion evidence packet"
            )
        ),
    )
}

fn subject_api_path(kind: EvidenceSubjectKind, id: &str) -> Option<String> {
    match kind {
        EvidenceSubjectKind::ReplayBundle => Some(format!("/v1/operator/replay?bundle_id={id}")),
        EvidenceSubjectKind::InvestigationBundle => {
            Some(format!("/v1/operator/investigation?investigation_id={id}"))
        }
        EvidenceSubjectKind::CorrelatedIncident => {
            Some(format!("/v1/operator/incident?incident_id={id}"))
        }
        EvidenceSubjectKind::OperatorMaintenanceAction => {
            Some(format!("/v1/operator/maintenance/actions/{id}"))
        }
        EvidenceSubjectKind::ProductionPromotion
        | EvidenceSubjectKind::CanaryRun
        | EvidenceSubjectKind::DetectorVerification
        | EvidenceSubjectKind::StrategyShadow
        | EvidenceSubjectKind::PromotionReview => None,
    }
}

fn render_related_ref_link(kind: &str, id: &str) -> String {
    if let Some(href) = related_ref_path(kind, id) {
        review_link(&href, id)
    } else {
        format!("<code>{}</code>", escape_html(id))
    }
}

fn related_ref_path(kind: &str, id: &str) -> Option<String> {
    match kind {
        "replay_bundle" => Some(format!("/v1/operator/replay?bundle_id={id}")),
        "investigation_bundle" => Some(format!("/v1/operator/investigation?investigation_id={id}")),
        "correlated_incident" => Some(format!("/v1/operator/incident?incident_id={id}")),
        "operator_maintenance_action" => Some(format!("/v1/operator/maintenance/actions/{id}")),
        "evidence_bundle" => Some(format!("/v1/operator/review/evidence/{id}")),
        "evidence_verification" => Some(format!("/v1/operator/review/verifications/{id}")),
        "promotion_evidence_packet" => Some(format!("/v1/operator/review/promotion-packets/{id}")),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{LocalOperatorSurface, OperatorSurfacePaths};
    use crate::approval::DefaultApprovalHarness;
    use crate::control::{CURRENT_OPERATOR_API_SCHEMA_VERSION, OPERATOR_API_SCHEMA_VERSION_HEADER};
    use crate::evidence::{
        EvidenceBundle, EvidenceRelatedRef, EvidenceSignature, EvidenceSubjectKind,
        EvidenceSubjectMetadata, EvidenceVerificationReport, EvidenceVerificationStatus,
        FileEvidenceBundleStore, FileEvidenceVerificationStore, FilePromotionEvidencePacketStore,
        PromotionEvidenceAttachment, PromotionEvidencePacket, PromotionEvidenceRecommendation,
    };
    use crate::ingest::{DemoProofPackage, IngestState, detect_http_router};
    use crate::replay::{
        ExperimentLineage, ReplayScenarioInput, ReplayScenarioManifest, ReplayScenarioMetadata,
        ReplayScenarioStep,
    };
    use crate::service::EventExecutionContext;
    use axum::Json;
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::extract::State;
    use axum::http::{HeaderMap, Request, StatusCode, header};
    use axum::routing::post;
    use serde_json::{Value, json};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use swarm_core::config::{
        AuditConfig, BundleStoreConfig, CanaryConfig, CorrelationConfig, DetectionConfig,
        DetectorProfilesConfig, InvestigationConfig, NotificationChannelConfig,
        NotificationRateLimitConfig, NotificationRoutingConfig, OperatorAuthConfig,
        OperatorPrincipalConfig, OperatorScope, OperatorSurfaceConfig, PheromoneBackendConfig,
        PheromoneConfig, PolicyConfig, PolicyRuleConfig, PolicyRuleDecision, PromotionConfig,
        QuietHoursConfig, RoutingRule, RuntimeSettings, SwarmConfig, TelemetrySourceConfig,
    };
    use swarm_core::pheromone::{
        ThreatClass, ThreatClassConfig, ThreatIntelEntry, ThreatIntelIndicatorType,
    };
    use swarm_core::types::{
        AgentId, HuntId, ProvidenceIncidentReconciliation, ProvidenceIncidentStatus,
        ProvidenceReconciliationOutcome, ResponseAction, ResponseBlastRadiusImpact,
        ResponseBlastRadiusPreview, ResponseRehearsalPreview, ResponseRehearsalScopeKind,
        ResponseRollbackPreview, ResponseRollbackStep, ResponseRollbackStepKind, Severity,
    };
    use swarm_crypto::{Ed25519Signer, canonical_json_bytes};
    use swarm_policy::ApprovalContext;
    use swarm_response::SwarmFindingEnvelope;
    use swarm_spine::{
        AuditResponseRecord, AuditTrail, CorrelatedIncident, IncidentMemberDecision, IncidentStore,
        PolicyRecord, ReplayBundle, ReplayBundleStore,
    };
    use swarm_whisker::{DetectionFinding, ProcessStartEvent, TelemetryEvent, TelemetryPayload};
    use tokio::sync::{Mutex as AsyncMutex, oneshot};
    use tower::ServiceExt;

    use crate::drafting::EvolutionValidationBundleStatus;
    use crate::evolution::{
        EvolutionProposalBlockingReason, EvolutionProposalProofStatus,
        EvolutionProposalProofSummary, EvolutionProposalReviewState,
    };
    use crate::governance_prep::{
        EvolutionGovernancePacketSetEntryReport, EvolutionGovernancePacketSetReport,
        EvolutionPortfolioHistoryCohortSummary, EvolutionPortfolioHistoryEntryReport,
        EvolutionPortfolioHistoryOutcomeCounts, EvolutionPortfolioHistoryOutcomeKind,
        EvolutionPortfolioHistoryReport, EvolutionPortfolioHistoryReviewDebtKind,
        FileEvolutionGovernancePacketSetStore, FileEvolutionPortfolioHistoryStore,
    };
    use crate::portfolio::{
        EvolutionGovernanceReviewPacketReport, EvolutionPortfolioDecisionRecord,
        EvolutionPortfolioEntryReport, EvolutionPortfolioEntryReviewState,
        EvolutionPortfolioReport, FileEvolutionGovernanceReviewPacketStore,
        FileEvolutionPortfolioStore,
    };
    use crate::review_workbench::DefaultReviewWorkbenchHarness;

    static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn permissive_policy_rules() -> Vec<PolicyRuleConfig> {
        vec![PolicyRuleConfig {
            name: "operator-http-allow-execution".to_string(),
            decision: PolicyRuleDecision::Allow,
            threat_class: ThreatClass::Execution,
            actions: Vec::new(),
            min_severity: Severity::Low,
            max_severity: Severity::Critical,
            time_window_utc: None,
            max_actions_per_agent_per_minute: None,
            reason: Some("operator surface tests allow execution responses".to_string()),
        }]
    }

    fn operator_config() -> SwarmConfig {
        SwarmConfig {
            schema_version: 1,
            name: "operator-http".to_string(),
            description: "operator surface config".to_string(),
            runtime: RuntimeSettings {
                mode: crate::RuntimeMode::DetectOnly,
                demo_mode: false,
                telemetry_sources: vec![TelemetrySourceConfig {
                    name: "synthetic".to_string(),
                    subject: "telemetry.synthetic".to_string(),
                    bridge: None,
                }],
                max_in_flight_actions: 2,
                drain_timeout_ms: 30_000,
                require_durable_live_response: false,
                max_heap_pressure: 0.90,
                secret_dir: None,
                anti_tamper: Default::default(),
                temporal_event_window: swarm_core::config::TemporalEventWindowConfig::default(),
                agent_tick_timeout_ms: 500,
                governance_degraded_tick_threshold: 3,
                partition_contingency_lease_ttl_ms: 300_000,
                partition_contingency_blast_radius_cap: 1,
                max_dead_letter_bytes: None,
            },
            detection: DetectionConfig {
                strategy: "suspicious_process_tree".to_string(),
                strategies: Vec::new(),
                high_confidence_threshold: 0.9,
                medium_confidence_threshold: 0.7,
                profiles: DetectorProfilesConfig::default(),
            },
            pheromone: PheromoneConfig {
                default_half_life_secs: 3600.0,
                evaporation_threshold: 0.01,
                min_sources_for_escalation: 2,
                alert_threshold: 2.0,
                incident_threshold: 5.0,
                deescalation_cooldown_secs: 300,
                response_playbook: Default::default(),
                backend: PheromoneBackendConfig::InMemory,
            },
            policy: PolicyConfig {
                human_gate_severity: swarm_core::types::Severity::High,
                lease_ttl_ms: 60_000,
                rules: permissive_policy_rules(),
                ..PolicyConfig::default()
            },
            response_adapter: swarm_core::config::ResponseAdapterConfig::Sandbox,
            siem_forward: None,
            notification_channels: std::collections::BTreeMap::new(),
            notification_routing: swarm_core::config::NotificationRoutingConfig::default(),
            audit: AuditConfig {
                bundle_store: BundleStoreConfig::Memory,
                recent_decisions_limit: 10,
            },
            investigation: InvestigationConfig {
                enabled: true,
                worker_count: 1,
                max_pending_jobs: 4,
                time_budget_ms: 250,
                bundle_store: BundleStoreConfig::Memory,
                ..InvestigationConfig::default()
            },
            correlation: CorrelationConfig {
                enabled: true,
                time_window_ms: 60_000,
                min_shared_keys: 1,
                candidate_limit: 8,
                incident_store: BundleStoreConfig::Memory,
            },
            canary: CanaryConfig::default(),
            promotion: PromotionConfig::default(),
            evolution: swarm_core::config::EvolutionConfig::default(),
            deception: swarm_core::config::DeceptionConfig::default(),
            memory: swarm_core::config::MemoryConfig::default(),
            identity: swarm_core::config::IdentityConfig::default(),
            platform_api: Default::default(),
            operator: OperatorSurfaceConfig {
                enabled: true,
                bind_addr: "127.0.0.1:7766".to_string(),
                runtime_base_url: "http://127.0.0.1:9090".to_string(),
                public_base_url: "http://127.0.0.1:7766".to_string(),
                allowed_embed_origins: Vec::new(),
                max_list_results: 2,
                widget_token_ttl_secs: 900,
                auth: OperatorAuthConfig {
                    context_token_env: "SWARM_OPERATOR_TEST_TOKEN".to_string(),
                    principals: Vec::new(),
                    operator_id: "local-operator".to_string(),
                    token_env: "SWARM_OPERATOR_TEST_TOKEN".to_string(),
                },
            },
            tls: None,
        }
    }

    fn scoped_operator_config(
        context_token_env: &str,
        principals: Vec<OperatorPrincipalConfig>,
    ) -> SwarmConfig {
        let mut config = operator_config();
        config.operator.auth.context_token_env = context_token_env.to_string();
        config.operator.auth.principals = principals;
        config
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        path.push(format!(
            "swarm-team-six-operator-http-{}-{}-{}",
            label,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            counter
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn event(event_id: &str, command_line: &str) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: event_id.to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword".to_string(),
                process_name: "powershell".to_string(),
                command_line: command_line.to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        }
    }

    fn approval_context(now_ms: i64) -> ApprovalContext {
        ApprovalContext {
            live_mode: true,
            receipt_chain: vec![format!("receipt-upstream-{now_ms}")],
            correlation_id: None,
            now_ms,
        }
    }

    #[test]
    fn control_service_readiness_error_maps_to_internal_api_error() {
        let error = super::map_control_error(crate::control::ControlError::Service(
            crate::service::ServiceError::Readiness {
                component: "substrate",
                source: crate::service::ReadinessError::SubstrateNotDurable {
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
            crate::portfolio::EvolutionPortfolioError::InvalidPortfolioRequest {
                reason: "missing cohort".to_string(),
            },
        );

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.error, "bad_request");
        assert!(error.message.contains("missing cohort"));
    }

    #[test]
    fn review_evidence_artifact_not_found_maps_to_not_found() {
        let error =
            super::map_review_evidence_error(crate::evidence::EvidenceError::ArtifactNotFound {
                kind: "replay_bundle",
                id: "bundle:missing".to_string(),
            });

        assert_eq!(error.status, StatusCode::NOT_FOUND);
        assert_eq!(error.title, "Not Found");
        assert!(error.message.contains("bundle:missing"));
    }

    #[derive(Clone, Default)]
    struct NotificationCaptureState {
        payloads: Arc<AsyncMutex<Vec<Value>>>,
        auth_headers: Arc<AsyncMutex<Vec<Option<String>>>>,
        replay_headers: Arc<AsyncMutex<Vec<Option<String>>>>,
    }

    async fn notification_capture_handler(
        State(state): State<NotificationCaptureState>,
        headers: HeaderMap,
        Json(payload): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        {
            let mut payloads = state.payloads.lock().await;
            payloads.push(payload);
        }
        {
            let mut auth_headers = state.auth_headers.lock().await;
            auth_headers.push(
                headers
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .map(ToString::to_string),
            );
        }
        {
            let mut replay_headers = state.replay_headers.lock().await;
            replay_headers.push(
                headers
                    .get("x-swarm-replay")
                    .and_then(|value| value.to_str().ok())
                    .map(ToString::to_string),
            );
        }
        (StatusCode::OK, Json(json!({"ok": true})))
    }

    async fn spawn_notification_capture_server() -> (
        String,
        NotificationCaptureState,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let state = NotificationCaptureState::default();
        let app = Router::new()
            .route("/", post(notification_capture_handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let server = axum::serve(listener, app).with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            });
            let _ = server.await;
        });
        (format!("http://{address}/"), state, shutdown_tx, handle)
    }

    fn notification_operator_config(target_url: String, dead_letter_path: String) -> SwarmConfig {
        let mut config = operator_config();
        config.notification_channels.insert(
            "pager".to_string(),
            NotificationChannelConfig {
                target_url,
                auth_token: Some("notify-secret".to_string()),
                request_signature: None,
                timeout_ms: 500,
                rate_limit: NotificationRateLimitConfig {
                    max_notifications: 5,
                    window_ms: 60_000,
                },
                quiet_hours: Some(QuietHoursConfig {
                    start_hour_utc: 0,
                    end_hour_utc: 0,
                }),
                dead_letter_path,
            },
        );
        config.notification_routing = NotificationRoutingConfig {
            dedup_window_ms: 1,
            rules: vec![RoutingRule {
                min_severity: Some(Severity::High),
                threat_class: Some(ThreatClass::Execution),
                utc_start_hour: None,
                utc_end_hour: None,
                channels: vec!["pager".to_string()],
            }],
        };
        config
    }

    fn sample_lineage(strategy_id: &str) -> ExperimentLineage {
        ExperimentLineage {
            parent_strategy_id: "office_baseline_control".to_string(),
            mutation: format!("mutation_for_{strategy_id}"),
            rationale: format!("rationale for {strategy_id}"),
        }
    }

    fn sample_governance_packet(
        packet_id: &str,
        strategy_id: &str,
        cohort: &str,
        ready_for_governance: bool,
    ) -> EvolutionGovernanceReviewPacketReport {
        let blocking_reasons = if ready_for_governance {
            Vec::new()
        } else {
            vec![EvolutionProposalBlockingReason {
                source: "governance_packet".to_string(),
                name: "candidate_blocked".to_string(),
                details: "candidate remained blocked during governance packet preparation"
                    .to_string(),
                references: vec![packet_id.to_string()],
            }]
        };
        EvolutionGovernanceReviewPacketReport {
            packet_id: packet_id.to_string(),
            portfolio_id: format!("portfolio:{cohort}"),
            portfolio_name: format!("portfolio {cohort}"),
            entry_id: format!("entry:{packet_id}"),
            selection_id: format!("selection:{strategy_id}"),
            ranking_id: format!("ranking:{strategy_id}"),
            validation_batch_id: format!("validation_batch:{strategy_id}"),
            mutation_spec_id: format!("mutation_spec:{strategy_id}"),
            created_at_ms: 1_710_000_000_000,
            cohort: cohort.to_string(),
            rank: 1,
            strategy_id: strategy_id.to_string(),
            strategy_description: format!("strategy {strategy_id}"),
            score: 0.91,
            summary: format!("summary for {strategy_id}"),
            materialization_id: format!("materialization:{strategy_id}"),
            validation_bundle_id: format!("validation_bundle:{strategy_id}"),
            experiment_id: format!("experiment:{strategy_id}"),
            experiment_name: format!("experiment {strategy_id}"),
            experiment_path: format!("/tmp/{strategy_id}.yaml"),
            lineage: sample_lineage(strategy_id),
            manifest_sha256: format!("manifest_sha_for_{strategy_id}"),
            lineage_sha256: format!("lineage_sha_for_{strategy_id}"),
            verification_id: format!("verification:{strategy_id}"),
            verification_passed: ready_for_governance,
            proof_status: if ready_for_governance {
                EvolutionProposalProofStatus::Proved
            } else {
                EvolutionProposalProofStatus::Missing
            },
            proof: ready_for_governance.then(|| EvolutionProposalProofSummary {
                proof_id: format!("proof:{strategy_id}"),
                proof_system: "repo_owned".to_string(),
                attestation_sha256: format!("attestation_sha_for_{strategy_id}"),
                invariant_count: 4,
            }),
            advisory: None,
            shadow_id: format!("shadow:{strategy_id}"),
            shadow_passed: ready_for_governance,
            validation_status: if ready_for_governance {
                EvolutionValidationBundleStatus::ReadyForQueue
            } else {
                EvolutionValidationBundleStatus::Blocked
            },
            parent_queue_proposal_id: Some(format!("proposal:{strategy_id}")),
            parent_queue_review_state: Some(EvolutionProposalReviewState::AcceptedForCanary),
            selection_review_state: if ready_for_governance {
                EvolutionProposalReviewState::AcceptedForCanary
            } else {
                EvolutionProposalReviewState::Blocked
            },
            portfolio_review_state: if ready_for_governance {
                EvolutionPortfolioEntryReviewState::Included
            } else {
                EvolutionPortfolioEntryReviewState::Blocked
            },
            operator_reason: "prepare for governance-prep review".to_string(),
            ready_for_governance,
            blocking_reasons,
        }
    }

    fn sample_portfolio_report() -> EvolutionPortfolioReport {
        EvolutionPortfolioReport {
            portfolio_id: "portfolio:red".to_string(),
            portfolio_name: "red portfolio".to_string(),
            operator_rationale: "review red cohort".to_string(),
            created_at_ms: 1_710_000_000_100,
            entries: vec![EvolutionPortfolioEntryReport {
                entry_id: "entry:packet:red:ready".to_string(),
                selection_id: "selection:office_red_ready_v1".to_string(),
                ranking_id: "ranking:office_red_ready_v1".to_string(),
                validation_batch_id: "validation_batch:office_red_ready_v1".to_string(),
                mutation_spec_id: "mutation_spec:office_red_ready_v1".to_string(),
                cohort: "red".to_string(),
                rank: 1,
                strategy_id: "office_red_ready_v1".to_string(),
                strategy_description: "strategy office_red_ready_v1".to_string(),
                score: 0.91,
                summary: "summary for office_red_ready_v1".to_string(),
                materialization_id: "materialization:office_red_ready_v1".to_string(),
                validation_bundle_id: "validation_bundle:office_red_ready_v1".to_string(),
                experiment_id: "experiment:office_red_ready_v1".to_string(),
                experiment_name: "experiment office_red_ready_v1".to_string(),
                experiment_path: "/tmp/office_red_ready_v1.yaml".to_string(),
                lineage: sample_lineage("office_red_ready_v1"),
                manifest_sha256: "manifest_sha_for_office_red_ready_v1".to_string(),
                lineage_sha256: "lineage_sha_for_office_red_ready_v1".to_string(),
                verification_id: "verification:office_red_ready_v1".to_string(),
                verification_passed: true,
                proof_status: EvolutionProposalProofStatus::Proved,
                proof: Some(EvolutionProposalProofSummary {
                    proof_id: "proof:office_red_ready_v1".to_string(),
                    proof_system: "repo_owned".to_string(),
                    attestation_sha256: "attestation_sha_for_office_red_ready_v1".to_string(),
                    invariant_count: 4,
                }),
                advisory: None,
                shadow_id: "shadow:office_red_ready_v1".to_string(),
                shadow_passed: true,
                validation_status: EvolutionValidationBundleStatus::ReadyForQueue,
                parent_queue_proposal_id: Some("proposal:office_red_ready_v1".to_string()),
                parent_queue_review_state: Some(EvolutionProposalReviewState::AcceptedForCanary),
                selection_review_state: EvolutionProposalReviewState::AcceptedForCanary,
                portfolio_review_state: EvolutionPortfolioEntryReviewState::Included,
                blocking_reasons: Vec::new(),
                decision_history: vec![EvolutionPortfolioDecisionRecord {
                    decided_at_ms: 1_710_000_000_120,
                    action: crate::portfolio::EvolutionPortfolioDecisionAction::Include,
                    reason: "include the ready portfolio entry".to_string(),
                }],
            }],
        }
    }

    fn sample_packet_set_report() -> EvolutionGovernancePacketSetReport {
        EvolutionGovernancePacketSetReport {
            packet_set_id: "packet_set:red:1".to_string(),
            packet_set_name: "red review set".to_string(),
            operator_rationale: "group red governance packets".to_string(),
            created_at_ms: 1_710_000_000_200,
            parent_packet_set_id: None,
            entries: vec![EvolutionGovernancePacketSetEntryReport {
                packet_set_entry_id: "packet_set_entry:packet:red:ready:0".to_string(),
                source_packet_set_entry_id: None,
                packet_id: "packet:red:ready".to_string(),
                source_packet_created_at_ms: 1_710_000_000_000,
                operator_reason: "prepare for governance-prep review".to_string(),
                portfolio_id: "portfolio:red".to_string(),
                portfolio_name: "red portfolio".to_string(),
                portfolio_entry_id: "entry:packet:red:ready".to_string(),
                selection_id: "selection:office_red_ready_v1".to_string(),
                ranking_id: "ranking:office_red_ready_v1".to_string(),
                validation_batch_id: "validation_batch:office_red_ready_v1".to_string(),
                mutation_spec_id: "mutation_spec:office_red_ready_v1".to_string(),
                cohort: "red".to_string(),
                rank: 1,
                strategy_id: "office_red_ready_v1".to_string(),
                strategy_description: "strategy office_red_ready_v1".to_string(),
                score: 0.91,
                summary: "summary for office_red_ready_v1".to_string(),
                materialization_id: "materialization:office_red_ready_v1".to_string(),
                validation_bundle_id: "validation_bundle:office_red_ready_v1".to_string(),
                experiment_id: "experiment:office_red_ready_v1".to_string(),
                experiment_name: "experiment office_red_ready_v1".to_string(),
                experiment_path: "/tmp/office_red_ready_v1.yaml".to_string(),
                lineage: sample_lineage("office_red_ready_v1"),
                manifest_sha256: "manifest_sha_for_office_red_ready_v1".to_string(),
                lineage_sha256: "lineage_sha_for_office_red_ready_v1".to_string(),
                verification_id: "verification:office_red_ready_v1".to_string(),
                verification_passed: true,
                proof_status: EvolutionProposalProofStatus::Proved,
                proof: Some(EvolutionProposalProofSummary {
                    proof_id: "proof:office_red_ready_v1".to_string(),
                    proof_system: "repo_owned".to_string(),
                    attestation_sha256: "attestation_sha_for_office_red_ready_v1".to_string(),
                    invariant_count: 4,
                }),
                advisory: None,
                shadow_id: "shadow:office_red_ready_v1".to_string(),
                shadow_passed: true,
                validation_status: EvolutionValidationBundleStatus::ReadyForQueue,
                parent_queue_proposal_id: Some("proposal:office_red_ready_v1".to_string()),
                parent_queue_review_state: Some(EvolutionProposalReviewState::AcceptedForCanary),
                selection_review_state: EvolutionProposalReviewState::AcceptedForCanary,
                portfolio_review_state: EvolutionPortfolioEntryReviewState::Included,
                ready_for_governance: true,
                blocking_reasons: Vec::new(),
            }],
        }
    }

    fn sample_portfolio_history_report() -> EvolutionPortfolioHistoryReport {
        EvolutionPortfolioHistoryReport {
            history_id: "portfolio_history:red:1".to_string(),
            packet_set_id: "packet_set:red:1".to_string(),
            packet_set_name: "red review set".to_string(),
            created_at_ms: 1_710_000_000_300,
            outcomes: EvolutionPortfolioHistoryOutcomeCounts {
                entry_count: 1,
                survived_count: 1,
                stable_count: 1,
                ready_for_promotion_review_count: 0,
                blocked_count: 0,
                halted_count: 0,
                unobserved_count: 0,
                review_debt_count: 0,
            },
            cohorts: vec![EvolutionPortfolioHistoryCohortSummary {
                cohort: "red".to_string(),
                entry_count: 1,
                survived_count: 1,
                stable_count: 1,
                blocked_count: 0,
                halted_count: 0,
                unobserved_count: 0,
                review_debt_count: 0,
            }],
            entries: vec![EvolutionPortfolioHistoryEntryReport {
                packet_set_entry_id: "packet_set_entry:packet:red:ready:0".to_string(),
                packet_id: "packet:red:ready".to_string(),
                portfolio_id: "portfolio:red".to_string(),
                portfolio_name: "red portfolio".to_string(),
                portfolio_entry_id: "entry:packet:red:ready".to_string(),
                cohort: "red".to_string(),
                strategy_id: "office_red_ready_v1".to_string(),
                strategy_description: "strategy office_red_ready_v1".to_string(),
                ready_for_governance: true,
                blocking_reasons: Vec::new(),
                memory_ids: vec!["memory:office_red_ready_v1:1".to_string()],
                latest_rollout_state: Some(crate::strategy::StrategyRolloutStateSummary {
                    source_kind: crate::strategy::StrategyMemorySourceKind::Promotion,
                    source_artifact_id: "promotion:office_red_ready_v1".to_string(),
                    outcome_kind: crate::strategy::StrategyMemoryOutcomeKind::StableInProduction,
                    observed_at_ms: 1_710_000_000_250,
                }),
                outcome: EvolutionPortfolioHistoryOutcomeKind::StableInProduction,
                survived_live_rollout: true,
                review_debt: Some(EvolutionPortfolioHistoryReviewDebtKind::AwaitingStableOutcome),
            }],
        }
    }

    fn sample_subject_evidence_bundle(
        kind: EvidenceSubjectKind,
        stable_id: &str,
        payload_sha256: &str,
        canonical_payload: &str,
        related_refs: Vec<EvidenceRelatedRef>,
    ) -> EvidenceBundle {
        EvidenceBundle {
            bundle_id: format!(
                "evidence:{}:{}:local-evidence-signer",
                kind.as_str(),
                stable_id
            ),
            schema_version: "v1".to_string(),
            config_name: "operator-http".to_string(),
            exported_at_ms: 1_710_000_000_500,
            subject: EvidenceSubjectMetadata {
                kind,
                stable_id: stable_id.to_string(),
                display_name: format!("{} {stable_id}", kind.as_str()),
                source_created_at_ms: 1_710_000_000_000,
                receipt_chain_refs: vec![],
                related_refs,
            },
            payload_sha256: payload_sha256.to_string(),
            canonical_payload: canonical_payload.to_string(),
            signature: EvidenceSignature {
                signer_id: "local-evidence-signer".to_string(),
                algorithm: "ed25519".to_string(),
                key_id: "key:red".to_string(),
                public_key_hex: "11".repeat(32),
                signature_hex: "22".repeat(64),
            },
        }
    }

    fn sample_evidence_bundle() -> EvidenceBundle {
        sample_subject_evidence_bundle(
            EvidenceSubjectKind::ProductionPromotion,
            "promotion:red",
            "abcd1234",
            r#"{"promotion_id":"promotion:red","status":"completed"}"#,
            vec![EvidenceRelatedRef {
                kind: "canary_run".to_string(),
                id: "canary:red".to_string(),
            }],
        )
    }

    fn sample_canary_evidence_bundle() -> EvidenceBundle {
        sample_subject_evidence_bundle(
            EvidenceSubjectKind::CanaryRun,
            "canary:red",
            "beefcafe",
            r#"{"run_id":"canary:red","status":"completed"}"#,
            vec![EvidenceRelatedRef {
                kind: "promotion_review".to_string(),
                id: "review:red".to_string(),
            }],
        )
    }

    fn sample_promotion_review_evidence_bundle() -> EvidenceBundle {
        sample_subject_evidence_bundle(
            EvidenceSubjectKind::PromotionReview,
            "review:red",
            "facefeed",
            r#"{"review_id":"review:red","recommendation":"ready_for_manual_review"}"#,
            vec![
                EvidenceRelatedRef {
                    kind: "verification".to_string(),
                    id: "verification:red".to_string(),
                },
                EvidenceRelatedRef {
                    kind: "shadow".to_string(),
                    id: "shadow:red".to_string(),
                },
            ],
        )
    }

    fn sample_subject_verification_report(
        kind: EvidenceSubjectKind,
        stable_id: &str,
        bundle_id: &str,
    ) -> EvidenceVerificationReport {
        EvidenceVerificationReport {
            verification_id: format!("evidence_verification:{bundle_id}"),
            bundle_id: bundle_id.to_string(),
            subject_kind: kind,
            subject_id: stable_id.to_string(),
            verified_at_ms: 1_710_000_000_800,
            status: EvidenceVerificationStatus::Passed,
            signer_id: "local-evidence-signer".to_string(),
            signer_key_id: "key:red".to_string(),
            expected_key_id: Some("key:red".to_string()),
            checks: vec![crate::evidence::EvidenceVerificationCheck {
                name: "canonical_payload".to_string(),
                passed: true,
                details: "canonical payload bytes normalized cleanly".to_string(),
            }],
        }
    }

    fn sample_promotion_evidence_packet() -> PromotionEvidencePacket {
        PromotionEvidencePacket {
            packet_id: "promotion_evidence:promotion:red".to_string(),
            promotion_id: "promotion:red".to_string(),
            created_at_ms: 1_710_000_000_900,
            window_id: "production-primary".to_string(),
            promotion_status: crate::promotion::ProductionPromotionStatus::Completed,
            promoted_strategy_id: "office_red_ready_v1".to_string(),
            fallback_strategy_id: "office_control_v1".to_string(),
            canary_run_id: "canary:red".to_string(),
            verification_id:
                "evidence_verification:evidence:production_promotion:promotion:red:local-evidence-signer"
                    .to_string(),
            shadow_id: "shadow:red".to_string(),
            supporting_evidence: vec![PromotionEvidenceAttachment {
                subject_kind: EvidenceSubjectKind::ProductionPromotion,
                subject_id: "promotion:red".to_string(),
                bundle_id: Some(
                    "evidence:production_promotion:promotion:red:local-evidence-signer"
                        .to_string(),
                ),
                verification_id: Some(
                    "evidence_verification:evidence:production_promotion:promotion:red:local-evidence-signer"
                        .to_string(),
                ),
                verification_status: Some(EvidenceVerificationStatus::Passed),
                details: "production promotion evidence".to_string(),
            }],
            blocking_reasons: vec![],
            recommendation: PromotionEvidenceRecommendation::ReadyForExternalReview,
            advisory_only: true,
        }
    }

    fn surface_paths(root: &std::path::Path) -> OperatorSurfacePaths {
        OperatorSurfacePaths {
            evidence_signer_id: "local-evidence-signer".to_string(),
            evidence_signing_key_env: "SWARM_EVIDENCE_SIGNING_KEY".to_string(),
            verification_results_dir: root.join("detector-verifications"),
            shadow_results_dir: root.join("strategy-shadows"),
            promotion_review_results_dir: root.join("promotion-reviews"),
            canary_results_dir: root.join("canary-runs"),
            promotion_results_dir: root.join("promotions"),
            evolution_ranking_results_dir: root.join("rankings"),
            evolution_selection_results_dir: root.join("selections"),
            evolution_portfolio_results_dir: root.join("portfolios"),
            evolution_governance_review_packet_results_dir: root.join("governance-packets"),
            evolution_packet_set_results_dir: root.join("packet-sets"),
            strategy_memory_results_dir: root.join("strategy-memory"),
            evolution_portfolio_history_results_dir: root.join("portfolio-history"),
            operator_maintenance_results_dir: root.join("operator-maintenance-actions"),
            evidence_results_dir: root.join("evidence-bundles"),
            evidence_verification_results_dir: root.join("evidence-verifications"),
            promotion_evidence_results_dir: root.join("promotion-evidence-packets"),
            review_session_results_dir: root.join("review-sessions"),
            review_session_export_results_dir: root.join("review-session-exports"),
            review_session_readiness_results_dir: root.join("review-session-readiness"),
            review_session_handoff_results_dir: root.join("review-session-handoffs"),
            review_capsule_results_dir: root.join("review-capsules"),
            review_capsule_import_results_dir: root.join("review-capsule-imports"),
            review_delegation_results_dir: root.join("review-delegations"),
            approval_set_results_dir: root.join("approval-sets"),
            approval_ledger_results_dir: root.join("approval-ledgers"),
            approval_verdict_results_dir: root.join("approval-verdicts"),
            approval_receipt_pack_results_dir: root.join("approval-receipt-packs"),
        }
    }

    fn seed_evolution_artifacts(root: &std::path::Path) {
        let paths = surface_paths(root);
        FileEvolutionPortfolioStore::open(&paths.evolution_portfolio_results_dir)
            .unwrap()
            .persist(&sample_portfolio_report())
            .unwrap();
        FileEvolutionGovernanceReviewPacketStore::open(
            &paths.evolution_governance_review_packet_results_dir,
        )
        .unwrap()
        .persist(&sample_governance_packet(
            "packet:red:ready",
            "office_red_ready_v1",
            "red",
            true,
        ))
        .unwrap();
        FileEvolutionGovernancePacketSetStore::open(&paths.evolution_packet_set_results_dir)
            .unwrap()
            .persist(&sample_packet_set_report())
            .unwrap();
        FileEvolutionPortfolioHistoryStore::open(&paths.evolution_portfolio_history_results_dir)
            .unwrap()
            .persist(&sample_portfolio_history_report())
            .unwrap();
    }

    fn seed_evidence_artifacts(root: &std::path::Path) {
        let paths = surface_paths(root);
        let packet = sample_promotion_evidence_packet();

        let bundle_store = FileEvidenceBundleStore::open(&paths.evidence_results_dir).unwrap();
        let verification_store =
            FileEvidenceVerificationStore::open(&paths.evidence_verification_results_dir).unwrap();
        for bundle in [
            sample_evidence_bundle(),
            sample_canary_evidence_bundle(),
            sample_promotion_review_evidence_bundle(),
        ] {
            let bundle_lookup = bundle_store.persist(&bundle).unwrap();
            let verification_lookup = verification_store
                .persist(&sample_subject_verification_report(
                    bundle.subject.kind,
                    &bundle.subject.stable_id,
                    &bundle_lookup.record.bundle_id,
                ))
                .unwrap();
            bundle_store
                .attach_verification(&verification_lookup.record, &bundle_lookup.record.bundle_id)
                .unwrap();
        }
        FilePromotionEvidencePacketStore::open(&paths.promotion_evidence_results_dir)
            .unwrap()
            .persist(&packet)
            .unwrap();
    }

    fn sample_review_scope_rehearsal_bundle() -> ReplayBundle {
        let finding = DetectionFinding {
            finding_id: "finding-hunt-review".to_string(),
            event_id: "hunt-review".to_string(),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence: 0.99,
            evidence: json!({
                "host_id": "host-1",
                "event_id": "hunt-review",
            }),
            strategy_id: "suspicious_process_tree".to_string(),
        };
        ReplayBundle {
            bundle_id: "bundle:rehearsal:hunt-review:1700000000002".to_string(),
            event: event("hunt-review", "powershell -enc review"),
            findings: vec![finding.clone()],
            deposits: Vec::new(),
            action_request: swarm_policy::ActionRequest {
                hunt_id: HuntId("hunt-review".to_string()),
                requested_by: AgentId::new("whisker", "primary"),
                action: ResponseAction::Escalate {
                    summary: "escalate hunt-review".to_string(),
                    urgency: Severity::High,
                },
                severity: Severity::High,
                evidence: json!(SwarmFindingEnvelope::from(&finding)),
            },
            rehearsal: Some(ResponseRehearsalPreview {
                rehearsal_id: "rehearsal:hunt-review".to_string(),
                source_bundle_id: "bundle:source:hunt-review".to_string(),
                prepared_at_ms: 1_700_000_000_002,
                simulated_only: true,
                blast_radius: ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::Host,
                    scope_value: "host-1".to_string(),
                    impact: ResponseBlastRadiusImpact::OperatorEscalationOnly,
                    max_affected_scopes: 1,
                    affected_capabilities: vec!["notify_operator".to_string()],
                    summary: "Escalation stays on the operator lane.".to_string(),
                },
                rollback: ResponseRollbackPreview {
                    required: true,
                    summary: "Close the rehearsal escalation if operators accept it.".to_string(),
                    steps: vec![ResponseRollbackStep {
                        kind: ResponseRollbackStepKind::CloseEscalation,
                        summary: "Close the dry-run escalation receipt.".to_string(),
                    }],
                },
            }),
            audit: AuditTrail {
                trail_id: "trail-hunt-review".to_string(),
                hunt_id: "hunt-review".to_string(),
                related_receipt_ids: vec!["receipt-hunt-review".to_string()],
                detection: finding,
                policy: PolicyRecord {
                    verdict: swarm_policy::PolicyVerdict::Allow,
                    rule_name: "review-surface.allow".to_string(),
                    reason: "review surface rehearsal test".to_string(),
                    lease: None,
                },
                response: AuditResponseRecord::Skipped {
                    reason: "review surface fixture records persisted dry-run proof only"
                        .to_string(),
                },
                created_at_ms: 1_700_000_000_002,
            },
        }
    }

    fn sample_review_scope_incident() -> CorrelatedIncident {
        CorrelatedIncident {
            incident_id: "incident-review".to_string(),
            summary: "Review scope incident".to_string(),
            created_at_ms: 1_700_000_000_003,
            window_start_ms: 1_700_000_000_000,
            window_end_ms: 1_700_000_000_003,
            correlation_keys: vec!["host:host-1".to_string()],
            related_receipt_ids: vec!["receipt-hunt-review".to_string()],
            included_members: vec![IncidentMemberDecision {
                investigation_id: "investigation-review".to_string(),
                hunt_id: "hunt-review".to_string(),
                finding_id: "finding-hunt-review".to_string(),
                reason: "same review hunt".to_string(),
                shared_keys: vec!["host:host-1".to_string()],
                evidence_links: Vec::new(),
                confidence_score: 1.0,
            }],
            rejected_members: Vec::new(),
            graph_dimensions: Vec::new(),
            confidence_score: 1.0,
            trigger_event_id: Some("hunt-review".to_string()),
            trigger_finding_id: Some("finding-hunt-review".to_string()),
            trigger_strategy_id: Some("summary_investigator".to_string()),
            threat_class: Some(ThreatClass::Execution),
            severity: Some(Severity::High),
            external_references: Vec::new(),
            providence_reconciliation: Some(ProvidenceIncidentReconciliation {
                incident_key: "suspicious_process_tree:execution:finding-hunt-review".to_string(),
                remote_incident_id: "prov-review-1".to_string(),
                remote_incident_url: Some(
                    "https://providence.local/incidents/prov-review-1".to_string(),
                ),
                remote_status: ProvidenceIncidentStatus::Investigating,
                remote_severity: Severity::High,
                swarm_status: ProvidenceIncidentStatus::Open,
                swarm_severity: Severity::High,
                remote_updated_at_ms: 1_700_000_000_004,
                reconciled_at_ms: 1_700_000_000_005,
                outcome: ProvidenceReconciliationOutcome::ProvidenceAhead,
                needs_review: true,
                summary: "Providence status advanced while Swarm stayed open.".to_string(),
            }),
            providence_callback_audit_entries: Vec::new(),
            feedback_audit_entries: Vec::new(),
            false_positive_measurements: Vec::new(),
        }
    }

    #[tokio::test]
    async fn status_route_requires_bearer_token() {
        unsafe {
            std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
        }
        let surface = LocalOperatorSurface::from_config("inline", operator_config()).unwrap();
        let app = surface.router();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn status_route_returns_json_when_authorized() {
        unsafe {
            std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
        }
        let surface = LocalOperatorSurface::from_config("inline", operator_config()).unwrap();
        let app = surface.router();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/status")
                    .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["schema_version"], CURRENT_OPERATOR_API_SCHEMA_VERSION);
        assert_eq!(json["origin"], "live_runtime_status");
        assert_eq!(json["config_name"], "operator-http");
    }

    #[tokio::test]
    async fn status_route_rejects_unsupported_schema_version_header() {
        unsafe {
            std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
        }
        let surface = LocalOperatorSurface::from_config("inline", operator_config()).unwrap();
        let app = surface.router();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/status")
                    .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                    .header(OPERATOR_API_SCHEMA_VERSION_HEADER, "99")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["message"]
                .as_str()
                .unwrap_or_default()
                .contains("unsupported operator API schema version")
        );
    }

    #[tokio::test]
    async fn threat_class_config_routes_store_and_list_configs() {
        unsafe {
            std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
        }
        let surface = LocalOperatorSurface::from_config("inline", operator_config()).unwrap();
        let app = surface.router();

        let request = serde_json::to_vec(&ThreatClassConfig {
            threat_class: ThreatClass::Execution,
            half_life_secs: 180.0,
            evaporation_threshold: 0.05,
            alert_threshold: 1.4,
            incident_threshold: 3.6,
        })
        .unwrap();
        let store_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/pheromone/threat-class-configs")
                    .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(request))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(store_response.status(), StatusCode::OK);
        let store_body = to_bytes(store_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let store_json: Value = serde_json::from_slice(&store_body).unwrap();
        assert_eq!(store_json["data"]["threat_class"], "execution");
        assert_eq!(store_json["data"]["half_life_secs"], 180.0);

        let list_response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/pheromone/threat-class-configs")
                    .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_body = to_bytes(list_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let list_json: Value = serde_json::from_slice(&list_body).unwrap();
        assert_eq!(list_json["data"][0]["threat_class"], "execution");
        assert_eq!(list_json["data"][0]["alert_threshold"], 1.4);
    }

    #[tokio::test]
    async fn threat_intel_routes_store_and_query_entries() {
        unsafe {
            std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
        }
        let surface = LocalOperatorSurface::from_config("inline", operator_config()).unwrap();
        let app = surface.router();

        let request = serde_json::to_vec(&ThreatIntelEntry {
            indicator_type: ThreatIntelIndicatorType::Domain,
            value: " Example.COM. ".to_string(),
            confidence: 0.91,
            expires_at: 1_700_000_000_100,
        })
        .unwrap();
        let store_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/threat-intel/entries")
                    .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(request))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(store_response.status(), StatusCode::OK);
        let store_body = to_bytes(store_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let store_json: Value = serde_json::from_slice(&store_body).unwrap();
        assert_eq!(store_json["data"]["indicator_type"], "domain");
        assert_eq!(store_json["data"]["value"], " Example.COM. ");

        let lookup_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/threat-intel/entries?indicator_type=domain&value=example.com&now=1700000000000")
                    .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(lookup_response.status(), StatusCode::OK);
        let lookup_body = to_bytes(lookup_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let lookup_json: Value = serde_json::from_slice(&lookup_body).unwrap();
        assert_eq!(lookup_json["data"]["value"], "example.com");
        assert_eq!(lookup_json["data"]["confidence"], 0.91);

        let expired_response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/threat-intel/entries?indicator_type=domain&value=EXAMPLE.COM.&now=1700000000100")
                    .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(expired_response.status(), StatusCode::OK);
        let expired_body = to_bytes(expired_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let expired_json: Value = serde_json::from_slice(&expired_body).unwrap();
        assert!(expired_json["data"].is_null());
    }

    #[tokio::test]
    async fn notification_dead_letter_routes_list_and_replay_entries() {
        unsafe {
            std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
        }
        let (target_url, capture, shutdown_tx, handle) = spawn_notification_capture_server().await;
        let root = unique_temp_dir("notification-dead-letter");
        let dead_letter_path = root.join("pager.jsonl");
        let surface = LocalOperatorSurface::from_config(
            "inline",
            notification_operator_config(target_url, dead_letter_path.display().to_string()),
        )
        .unwrap();

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
        let _ = surface
            .state
            .control
            .stack
            .process_event(
                &swarm_whisker::SuspiciousProcessTreeDetector::default(),
                &event("evt-http-notify-1", "powershell.exe -enc AAA="),
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &approval_context(1_700_000_000_010),
                    signing_key: &signing_key,
                },
                |_finding| {
                    Some(swarm_core::types::ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert!(capture.payloads.lock().await.is_empty());

        let app = surface.router();
        let list_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/notifications/dead-letter/pager?limit=5")
                    .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_body = to_bytes(list_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let list_json: Value = serde_json::from_slice(&list_body).unwrap();
        assert_eq!(list_json["data"][0]["adapter"], "notification:pager");
        assert_eq!(list_json["data"][0]["details"]["channel"], "pager");
        let receipt_id = list_json["data"][0]["receipt_id"]
            .as_str()
            .unwrap()
            .to_string();

        let replay_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/notifications/dead-letter/pager")
                    .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({ "receipt_ids": [receipt_id] }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay_response.status(), StatusCode::OK);
        let replay_body = to_bytes(replay_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let replay_json: Value = serde_json::from_slice(&replay_body).unwrap();
        assert_eq!(replay_json["data"][0]["status"], "replayed");

        let payloads = capture.payloads.lock().await.clone();
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0]["schema"], "swarm_notification");
        assert_eq!(
            payloads[0]["sample_finding"]["event_id"],
            "evt-http-notify-1"
        );
        assert_eq!(
            payloads[0]["sample_finding"]["evidence"]["host_metadata"]["host_id"],
            "host-1"
        );
        let auth_headers = capture.auth_headers.lock().await.clone();
        assert_eq!(auth_headers[0].as_deref(), Some("Bearer notify-secret"));
        let replay_headers = capture.replay_headers.lock().await.clone();
        assert_eq!(replay_headers[0].as_deref(), Some("true"));

        let _ = shutdown_tx.send(());
        handle.abort();
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn metrics_route_returns_openmetrics_without_auth() {
        unsafe {
            std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
        }
        let surface = LocalOperatorSurface::from_config("inline", operator_config()).unwrap();
        let app = surface.router();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/openmetrics-text; version=1.0.0; charset=utf-8"
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("swarm_detect_latency_microseconds"));
        assert!(text.contains("swarm_policy_latency_microseconds"));
        assert!(text.contains("swarm_response_latency_microseconds"));
    }

    #[tokio::test]
    async fn read_endpoints_return_runtime_and_governance_artifacts() {
        unsafe {
            std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
        }

        let root = unique_temp_dir("read-endpoints");
        seed_evolution_artifacts(&root);
        let paths = surface_paths(&root);
        let surface =
            LocalOperatorSurface::from_config_and_paths("inline", operator_config(), paths)
                .unwrap();

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
        let processed = surface
            .state
            .control
            .stack
            .process_event(
                &swarm_whisker::SuspiciousProcessTreeDetector::default(),
                &event("evt-http-1", "powershell.exe -enc AAA="),
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &approval_context(1_700_000_000_001),
                    signing_key: &signing_key,
                },
                |_finding| {
                    Some(swarm_core::types::ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        let _ = surface
            .state
            .control
            .stack
            .correlate_hunt("evt-http-1")
            .unwrap();

        let app = surface.router();
        let auth = ("authorization", "Bearer secret-token");

        let replay_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/operator/replay?receipt_id={}",
                        processed
                            .replay
                            .record
                            .response_receipt_id
                            .as_deref()
                            .unwrap()
                    ))
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay_response.status(), StatusCode::OK);
        let replay_body = to_bytes(replay_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let replay_json: Value = serde_json::from_slice(&replay_body).unwrap();
        assert_eq!(replay_json["data"]["record"]["hunt_id"], "evt-http-1");

        let portfolio_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/evolution/portfolios/portfolio:red")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(portfolio_response.status(), StatusCode::OK);
        let portfolio_body = to_bytes(portfolio_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let portfolio_json: Value = serde_json::from_slice(&portfolio_body).unwrap();
        assert_eq!(portfolio_json["portfolio_id"], "portfolio:red");

        let packet_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/evolution/governance-packets/packet:red:ready")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(packet_response.status(), StatusCode::OK);

        let packet_set_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/evolution/packet-sets?cohort=red&limit=1")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(packet_set_response.status(), StatusCode::OK);
        let packet_set_body = to_bytes(packet_set_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let packet_set_json: Value = serde_json::from_slice(&packet_set_body).unwrap();
        assert_eq!(packet_set_json["total_count"], 1);
        assert_eq!(
            packet_set_json["packet_sets"][0]["packet_set_id"],
            "packet_set:red:1"
        );

        let history_response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/evolution/portfolio-histories/portfolio_history:red:1")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(history_response.status(), StatusCode::OK);
        let history_body = to_bytes(history_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let history_json: Value = serde_json::from_slice(&history_body).unwrap();
        assert_eq!(history_json["history_id"], "portfolio_history:red:1");
    }

    #[tokio::test]
    async fn evidence_endpoints_return_signed_bundle_views() {
        unsafe {
            std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
        }

        let root = unique_temp_dir("evidence-endpoints");
        seed_evolution_artifacts(&root);
        seed_evidence_artifacts(&root);
        let paths = surface_paths(&root);
        let surface =
            LocalOperatorSurface::from_config_and_paths("inline", operator_config(), paths)
                .unwrap();
        let app = surface.router();
        let auth = ("authorization", "Bearer secret-token");

        let list_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/evidence/bundles?subject_kind=production_promotion&limit=5")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_body = to_bytes(list_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let list_json: Value = serde_json::from_slice(&list_body).unwrap();
        assert_eq!(list_json["total_count"], 1);
        assert_eq!(
            list_json["bundles"][0]["latest_verification_status"],
            "passed"
        );

        let bundle_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(
                        "/v1/operator/evidence/bundles/evidence:production_promotion:promotion:red:local-evidence-signer",
                    )
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bundle_response.status(), StatusCode::OK);
        let bundle_body = to_bytes(bundle_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let bundle_json: Value = serde_json::from_slice(&bundle_body).unwrap();
        assert_eq!(bundle_json["subject"]["stable_id"], "promotion:red");

        let verification_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(
                        "/v1/operator/evidence/verifications/evidence_verification:evidence:production_promotion:promotion:red:local-evidence-signer",
                    )
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verification_response.status(), StatusCode::OK);
        let verification_body = to_bytes(verification_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let verification_json: Value = serde_json::from_slice(&verification_body).unwrap();
        assert_eq!(verification_json["status"], "passed");

        let packet_response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/evidence/promotion-packets/promotion_evidence:promotion:red")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(packet_response.status(), StatusCode::OK);
        let packet_body = to_bytes(packet_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let packet_json: Value = serde_json::from_slice(&packet_body).unwrap();
        assert_eq!(packet_json["recommendation"], "ready_for_external_review");
    }

    #[tokio::test]
    async fn approval_vote_endpoint_resumes_demo_runtime_and_proof_export() {
        unsafe {
            std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
            std::env::set_var("SWARM_EVIDENCE_SIGNING_KEY", "operator-demo-proof-key");
        }

        let root = unique_temp_dir("approval-resume");
        let operator_vote_signer = Ed25519Signer::from_secret_material("local-operator-vote-key");
        let operator_voter_id = format!("swarm:ed25519:{}", operator_vote_signer.public_key_hex());
        let runtime_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let runtime_addr = runtime_listener.local_addr().unwrap();
        let runtime_base_url = format!("http://{}", runtime_addr);

        let runtime_config_path = root.join("runtime-config.yaml");
        let mut runtime_config = operator_config();
        runtime_config.runtime.mode = crate::RuntimeMode::LiveResponse;
        runtime_config.runtime.demo_mode = true;
        runtime_config.policy.human_gate_severity = swarm_core::types::Severity::Low;
        runtime_config.operator.runtime_base_url = runtime_base_url.clone();
        runtime_config.operator.auth.operator_id = operator_voter_id.clone();
        let runtime_harness = DefaultApprovalHarness::from_path(
            &runtime_config_path,
            root.join("approval-verdicts"),
            root.join("approval-receipt-packs"),
            root.join("approval-sets"),
            root.join("approval-ledgers"),
        )
        .unwrap();
        let runtime_state = IngestState::from_config(runtime_config_path, runtime_config)
            .unwrap()
            .with_approval_harness(runtime_harness.clone());
        let runtime_server = tokio::spawn(async move {
            axum::serve(runtime_listener, detect_http_router(runtime_state))
                .await
                .unwrap();
        });

        let scenario_path = root.join("human-gate-demo.yaml");
        let manifest = ReplayScenarioManifest {
            name: "operator approval replay".to_string(),
            description: "operator approval replay scenario".to_string(),
            seed_time_ms: 1_700_000_200_000,
            requested_by: "demo-operator".to_string(),
            receipt_chain: Vec::new(),
            metadata: ReplayScenarioMetadata::default(),
            input: ReplayScenarioInput::Events {
                events: vec![ReplayScenarioStep {
                    action: ResponseAction::IsolateHost {
                        host_id: "host-1".to_string(),
                    },
                    event: event("evt-approval-1", "powershell.exe -enc AAA="),
                }],
            },
            expectations: Default::default(),
        };
        fs::write(&scenario_path, serde_yaml::to_string(&manifest).unwrap()).unwrap();

        let replay_response = reqwest::Client::new()
            .post(format!("{runtime_base_url}/v1/demo/replay"))
            .json(&json!({
                "scenario_path": scenario_path.display().to_string(),
                "pace_ms": 0,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(replay_response.status(), reqwest::StatusCode::OK);
        let replay_json: Value = replay_response.json().await.unwrap();
        let run_id = replay_json["run_id"].as_str().unwrap().to_string();

        let approval_sets = runtime_harness.list_approval_sets().unwrap();
        assert_eq!(approval_sets.total_count, 1);
        let approval_set_id = approval_sets.sets[0].set_id.clone();
        let approval_ledgers = runtime_harness
            .list_ledgers(Some(&approval_set_id))
            .unwrap();
        assert_eq!(approval_ledgers.total_count, 1);
        let approval_ledger_id = approval_ledgers.ledgers[0].ledger_id.clone();

        let mut operator_demo_config = operator_config();
        operator_demo_config.operator.runtime_base_url = runtime_base_url.clone();
        operator_demo_config.operator.auth.operator_id = operator_voter_id.clone();
        let surface = LocalOperatorSurface::from_config_and_paths(
            "inline",
            operator_demo_config,
            surface_paths(&root),
        )
        .unwrap();
        let app = surface.router();
        let vote_payload = canonical_json_bytes(&json!({
            "approval_set_id": approval_set_id.clone(),
            "ledger_id": approval_ledger_id.clone(),
            "voter_id": operator_voter_id.clone(),
        }))
        .unwrap();
        let signature = operator_vote_signer.sign(&vote_payload);

        let vote_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/v1/operator/approval-ledgers/{approval_ledger_id}/vote"
                    ))
                    .header("authorization", "Bearer secret-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "voter_id": operator_voter_id,
                            "signature": signature,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(vote_response.status(), StatusCode::OK);
        let vote_body = to_bytes(vote_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let vote_json: Value = serde_json::from_slice(&vote_body).unwrap();
        assert_eq!(vote_json["quorum_state"]["quorum_met"], true);

        let proof_response = reqwest::Client::new()
            .get(format!("{runtime_base_url}/v1/demo/proof"))
            .query(&[("run_id", run_id.clone())])
            .send()
            .await
            .unwrap();
        assert_eq!(proof_response.status(), reqwest::StatusCode::OK);
        let proof: DemoProofPackage = proof_response.json().await.unwrap();
        assert_eq!(proof.run_id, run_id);
        assert_eq!(proof.signed_receipts.len(), 1);
        assert!(
            proof
                .decision_timeline
                .iter()
                .any(|entry| entry.stage == "approval_resumed")
        );
        assert!(!proof.final_incident.incident_id.is_empty());

        runtime_server.abort();
    }

    #[tokio::test]
    async fn review_surface_renders_html_shell_and_evidence_pages() {
        unsafe {
            std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
        }

        let root = unique_temp_dir("review-html-evidence");
        seed_evolution_artifacts(&root);
        seed_evidence_artifacts(&root);
        let surface = LocalOperatorSurface::from_config_and_paths(
            "inline",
            operator_config(),
            surface_paths(&root),
        )
        .unwrap();
        let app = surface.router();
        let auth = ("authorization", "Bearer secret-token");

        let home_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/review")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(home_response.status(), StatusCode::OK);
        assert_eq!(
            home_response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "text/html; charset=utf-8"
        );
        let home_body = to_bytes(home_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let home_html = String::from_utf8(home_body.to_vec()).unwrap();
        assert!(home_html.contains("Local Evidence Review"));
        assert!(home_html.contains("Live Demo Dashboard"));
        assert!(home_html.contains("/v1/demo/dashboard"));
        assert!(home_html.contains("/v1/events/stream"));
        assert!(home_html.contains("/v1/operator/review/evidence"));
        assert!(home_html.contains("promotion_evidence:promotion:red"));

        let list_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/review/evidence?subject_kind=production_promotion&verification_status=passed&limit=5")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_body = to_bytes(list_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let list_html = String::from_utf8(list_body.to_vec()).unwrap();
        assert!(list_html.contains("Evidence Inspection"));
        assert!(list_html.contains("production_promotion"));
        assert!(
            list_html.contains("evidence:production_promotion:promotion:red:local-evidence-signer")
        );

        let bundle_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/review/evidence/evidence:production_promotion:promotion:red:local-evidence-signer")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bundle_response.status(), StatusCode::OK);
        let bundle_body = to_bytes(bundle_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let bundle_html = String::from_utf8(bundle_body.to_vec()).unwrap();
        assert!(bundle_html.contains("Evidence Bundle Detail"));
        assert!(bundle_html.contains("promotion:red"));
        assert!(bundle_html.contains("canonical payload"));

        let verification_response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/review/verifications/evidence_verification:evidence:production_promotion:promotion:red:local-evidence-signer")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verification_response.status(), StatusCode::OK);
        let verification_body = to_bytes(verification_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let verification_html = String::from_utf8(verification_body.to_vec()).unwrap();
        assert!(verification_html.contains("Evidence Verification Detail"));
        assert!(verification_html.contains("canonical_payload"));
        assert!(verification_html.contains("canonical payload bytes normalized cleanly"));
    }

    #[tokio::test]
    async fn review_surface_scoped_context_renders_rehearsal_and_exports_signed_proof() {
        unsafe {
            std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
            std::env::set_var(
                "SWARM_EVIDENCE_SIGNING_KEY",
                "review-evidence-export-secret-material",
            );
        }

        let root = unique_temp_dir("review-scoped-rehearsal");
        seed_evolution_artifacts(&root);
        seed_evidence_artifacts(&root);
        let surface = LocalOperatorSurface::from_config_and_paths(
            "inline",
            operator_config(),
            surface_paths(&root),
        )
        .unwrap();
        surface
            .state
            .control
            .stack
            .replay_store
            .persist(&sample_review_scope_rehearsal_bundle())
            .unwrap();
        surface
            .state
            .control
            .stack
            .incident_store
            .persist(&sample_review_scope_incident())
            .unwrap();
        let app = surface.router();
        let auth = ("authorization", "Bearer secret-token");

        let home_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/review?hunt_id=hunt-review&incident_id=incident-review")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(home_response.status(), StatusCode::OK);
        let home_body = to_bytes(home_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let home_html = String::from_utf8(home_body.to_vec()).unwrap();
        assert!(home_html.contains("Latest Rehearsal Proof"));
        assert!(home_html.contains("Providence Reconciliation"));
        assert!(home_html.contains("Providence status advanced while Swarm stayed open."));
        assert!(home_html.contains("bundle:rehearsal:hunt-review:1700000000002"));
        assert!(home_html.contains(
            "/v1/operator/review/rehearsals/bundle:rehearsal:hunt-review:1700000000002/export"
        ));

        let export_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/review/rehearsals/bundle:rehearsal:hunt-review:1700000000002/export")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(export_response.status(), StatusCode::SEE_OTHER);
        let location = export_response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(
            location,
            "/v1/operator/review/evidence/evidence:replay_bundle:bundle:rehearsal:hunt-review:1700000000002:local-evidence-signer"
        );

        let exported = surface
            .state
            .evidence
            .as_ref()
            .unwrap()
            .find_bundle_by_subject(
                EvidenceSubjectKind::ReplayBundle,
                "bundle:rehearsal:hunt-review:1700000000002",
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            exported.bundle.subject.stable_id,
            "bundle:rehearsal:hunt-review:1700000000002"
        );
        assert_eq!(exported.bundle.signature.signer_id, "local-evidence-signer");

        let refreshed_response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/review?hunt_id=hunt-review&incident_id=incident-review")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(refreshed_response.status(), StatusCode::OK);
        let refreshed_body = to_bytes(refreshed_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let refreshed_html = String::from_utf8(refreshed_body.to_vec()).unwrap();
        assert!(refreshed_html.contains("Open signed rehearsal proof"));
        assert!(refreshed_html.contains(&location));
    }

    #[tokio::test]
    async fn review_surface_renders_promotion_packet_pages() {
        unsafe {
            std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
        }

        let root = unique_temp_dir("review-html-packets");
        seed_evolution_artifacts(&root);
        seed_evidence_artifacts(&root);
        let surface = LocalOperatorSurface::from_config_and_paths(
            "inline",
            operator_config(),
            surface_paths(&root),
        )
        .unwrap();
        let app = surface.router();
        let auth = ("authorization", "Bearer secret-token");

        let list_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/review/promotion-packets?recommendation=ready&limit=5")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_body = to_bytes(list_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let list_html = String::from_utf8(list_body.to_vec()).unwrap();
        assert!(list_html.contains("Promotion Evidence Review"));
        assert!(list_html.contains("promotion_evidence:promotion:red"));
        assert!(list_html.contains("ready_for_external_review"));

        let detail_response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/review/promotion-packets/promotion_evidence:promotion:red")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(detail_response.status(), StatusCode::OK);
        let detail_body = to_bytes(detail_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let detail_html = String::from_utf8(detail_body.to_vec()).unwrap();
        assert!(detail_html.contains("Promotion Evidence Packet Detail"));
        assert!(detail_html.contains("office_red_ready_v1"));
        assert!(detail_html.contains("office_control_v1"));
        assert!(detail_html.contains("advisory"));
    }

    #[tokio::test]
    async fn maintenance_endpoints_persist_audit_records() {
        unsafe {
            std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
        }

        let root = unique_temp_dir("maintenance-endpoints");
        seed_evolution_artifacts(&root);
        let paths = surface_paths(&root);
        let surface =
            LocalOperatorSurface::from_config_and_paths("inline", operator_config(), paths)
                .unwrap();
        let app = surface.router();
        let auth = ("authorization", "Bearer secret-token");

        let applied_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/maintenance/actions")
                    .header(auth.0, auth.1)
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "action": "refresh_portfolio_history",
                            "packet_set_id": "packet_set:red:1",
                            "reason": "refresh local review snapshot"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(applied_response.status(), StatusCode::OK);
        let applied_body = to_bytes(applied_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let applied_json: Value = serde_json::from_slice(&applied_body).unwrap();
        let applied_action_id = applied_json["action_id"].as_str().unwrap().to_string();
        assert_eq!(applied_json["actor"], "local-operator");
        assert_eq!(applied_json["status"], "applied");
        assert_eq!(applied_json["reason"], "refresh local review snapshot");
        assert_eq!(applied_json["artifacts"][0]["kind"], "portfolio_history");

        let blocked_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/maintenance/actions")
                    .header(auth.0, auth.1)
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "action": "packet_set_split",
                            "parent_packet_set_id": "packet_set:red:1",
                            "name": "red subset",
                            "packet_ids": ["packet:missing"],
                            "reason": "test blocked maintenance flow"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blocked_response.status(), StatusCode::CONFLICT);
        let blocked_body = to_bytes(blocked_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let blocked_json: Value = serde_json::from_slice(&blocked_body).unwrap();
        let blocked_action_id = blocked_json["action_id"].as_str().unwrap().to_string();
        assert_eq!(blocked_json["status"], "blocked");
        assert_eq!(blocked_json["target_kind"], "packet_set");
        assert!(
            blocked_json["summary"]
                .as_str()
                .unwrap()
                .contains("packet:missing")
        );

        let lookup_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/operator/maintenance/actions/{blocked_action_id}"
                    ))
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(lookup_response.status(), StatusCode::OK);
        let lookup_body = to_bytes(lookup_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let lookup_json: Value = serde_json::from_slice(&lookup_body).unwrap();
        assert_eq!(lookup_json["action_id"], blocked_action_id);
        assert_eq!(lookup_json["status"], "blocked");

        let blocked_list_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/maintenance/actions?status=blocked&limit=5")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blocked_list_response.status(), StatusCode::OK);
        let blocked_list_body = to_bytes(blocked_list_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let blocked_list_json: Value = serde_json::from_slice(&blocked_list_body).unwrap();
        assert_eq!(blocked_list_json["total_count"], 1);
        assert_eq!(
            blocked_list_json["actions"][0]["action_id"],
            blocked_action_id
        );

        let all_actions_response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/maintenance/actions?limit=5")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(all_actions_response.status(), StatusCode::OK);
        let all_actions_body = to_bytes(all_actions_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let all_actions_json: Value = serde_json::from_slice(&all_actions_body).unwrap();
        assert_eq!(all_actions_json["total_count"], 2);
        let action_ids = all_actions_json["actions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["action_id"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert!(action_ids.contains(&applied_action_id));
        assert!(action_ids.contains(&blocked_action_id));
    }

    #[tokio::test]
    async fn scoped_operator_principals_gate_actions_and_preserve_actor_identity() {
        const READ_ENV: &str = "SWARM_OPERATOR_SCOPE_READ_TOKEN";
        const REHEARSE_ENV: &str = "SWARM_OPERATOR_SCOPE_REHEARSE_TOKEN";
        const APPROVE_ENV: &str = "SWARM_OPERATOR_SCOPE_APPROVE_TOKEN";
        const APPROVE2_ENV: &str = "SWARM_OPERATOR_SCOPE_APPROVE2_TOKEN";
        const MAINT_ENV: &str = "SWARM_OPERATOR_SCOPE_MAINT_TOKEN";
        const READ_TOKEN: &str = "scope-read-secret";
        const REHEARSE_TOKEN: &str = "scope-rehearse-secret";
        const APPROVE_TOKEN: &str = "scope-approve-secret";
        const APPROVE2_TOKEN: &str = "scope-approve-secret-2";
        const MAINT_TOKEN: &str = "scope-maint-secret";

        unsafe {
            std::env::set_var(READ_ENV, READ_TOKEN);
            std::env::set_var(REHEARSE_ENV, REHEARSE_TOKEN);
            std::env::set_var(APPROVE_ENV, APPROVE_TOKEN);
            std::env::set_var(APPROVE2_ENV, APPROVE2_TOKEN);
            std::env::set_var(MAINT_ENV, MAINT_TOKEN);
            std::env::set_var("SWARM_EVIDENCE_SIGNING_KEY", "scope-evidence-signing-key");
        }

        let approve_signer = Ed25519Signer::from_secret_material("scope-approve-voter-key");
        let approver_id = format!("swarm:ed25519:{}", approve_signer.public_key_hex());
        let second_approver_id = "approver-2".to_string();
        let maintainer_id = "maintainer-1".to_string();
        let config = scoped_operator_config(
            READ_ENV,
            vec![
                OperatorPrincipalConfig {
                    operator_id: "reader-1".to_string(),
                    token_env: READ_ENV.to_string(),
                    scopes: vec![OperatorScope::Read],
                },
                OperatorPrincipalConfig {
                    operator_id: "rehearser-1".to_string(),
                    token_env: REHEARSE_ENV.to_string(),
                    scopes: vec![OperatorScope::Rehearse],
                },
                OperatorPrincipalConfig {
                    operator_id: approver_id.clone(),
                    token_env: APPROVE_ENV.to_string(),
                    scopes: vec![OperatorScope::Approve],
                },
                OperatorPrincipalConfig {
                    operator_id: second_approver_id.clone(),
                    token_env: APPROVE2_ENV.to_string(),
                    scopes: vec![OperatorScope::Approve],
                },
                OperatorPrincipalConfig {
                    operator_id: maintainer_id.clone(),
                    token_env: MAINT_ENV.to_string(),
                    scopes: vec![OperatorScope::Maintenance],
                },
            ],
        );

        let root = unique_temp_dir("scoped-operator-principals");
        seed_evolution_artifacts(&root);
        let surface =
            LocalOperatorSurface::from_config_and_paths("inline", config, surface_paths(&root))
                .unwrap();
        surface
            .state
            .control
            .stack
            .replay_store
            .persist(&sample_review_scope_rehearsal_bundle())
            .unwrap();
        let app = surface.router();

        let read_status = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/status")
                    .header("authorization", format!("Bearer {READ_TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(read_status.status(), StatusCode::OK);

        let read_maintenance = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/maintenance/actions")
                    .header("authorization", format!("Bearer {READ_TOKEN}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "action": "refresh_portfolio_history",
                            "packet_set_id": "packet_set:red:1",
                            "reason": "reader should not be allowed"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(read_maintenance.status(), StatusCode::FORBIDDEN);

        let read_rehearsal_export = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/review/rehearsals/bundle:rehearsal:hunt-review:1700000000002/export")
                    .header("authorization", format!("Bearer {READ_TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(read_rehearsal_export.status(), StatusCode::FORBIDDEN);

        let rehearse_export = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/review/rehearsals/bundle:rehearsal:hunt-review:1700000000002/export")
                    .header("authorization", format!("Bearer {REHEARSE_TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rehearse_export.status(), StatusCode::SEE_OTHER);

        let invalid_set_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/approval-sets")
                    .header("authorization", format!("Bearer {APPROVE_TOKEN}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "eligible_voters": ["reader-1"],
                            "threshold_required": 1,
                            "promotion_evidence_ref": "promotion_evidence:promotion:red"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid_set_response.status(), StatusCode::BAD_REQUEST);

        let create_set_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/approval-sets")
                    .header("authorization", format!("Bearer {APPROVE_TOKEN}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "eligible_voters": [approver_id.clone(), second_approver_id.clone()],
                            "threshold_required": 2,
                            "promotion_evidence_ref": "promotion_evidence:promotion:red"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_set_response.status(), StatusCode::CREATED);
        let create_set_body = to_bytes(create_set_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let create_set_json: Value = serde_json::from_slice(&create_set_body).unwrap();
        let approval_set_id = create_set_json["set_id"].as_str().unwrap().to_string();

        let ledgers = surface
            .state
            .approval
            .as_ref()
            .unwrap()
            .list_ledgers(Some(&approval_set_id))
            .unwrap();
        let approval_ledger_id = ledgers.ledgers[0].ledger_id.clone();
        let vote_signature = approve_signer.sign(
            &canonical_json_bytes(&json!({
                "approval_set_id": approval_set_id,
                "ledger_id": approval_ledger_id,
                "voter_id": approver_id,
            }))
            .unwrap(),
        );

        let maintenance_vote = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/v1/operator/approval-ledgers/{approval_ledger_id}/vote"
                    ))
                    .header("authorization", format!("Bearer {MAINT_TOKEN}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "voter_id": approver_id,
                            "signature": vote_signature.clone(),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(maintenance_vote.status(), StatusCode::FORBIDDEN);

        let approval_vote = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/v1/operator/approval-ledgers/{approval_ledger_id}/vote"
                    ))
                    .header("authorization", format!("Bearer {APPROVE_TOKEN}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "voter_id": approver_id,
                            "signature": vote_signature,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(approval_vote.status(), StatusCode::OK);
        let approval_vote_body = to_bytes(approval_vote.into_body(), usize::MAX)
            .await
            .unwrap();
        let approval_vote_json: Value = serde_json::from_slice(&approval_vote_body).unwrap();
        assert_eq!(
            approval_vote_json["report"]["entries"][0]["voter_id"],
            approver_id.as_str()
        );

        let maintenance_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/maintenance/actions")
                    .header("authorization", format!("Bearer {MAINT_TOKEN}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "action": "refresh_portfolio_history",
                            "packet_set_id": "packet_set:red:1",
                            "reason": "maintainer refresh"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(maintenance_response.status(), StatusCode::OK);
        let maintenance_body = to_bytes(maintenance_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let maintenance_json: Value = serde_json::from_slice(&maintenance_body).unwrap();
        assert_eq!(maintenance_json["actor"], maintainer_id);
    }

    #[tokio::test]
    async fn review_workbench_routes_create_export_and_handoff_sessions() {
        unsafe {
            std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
            std::env::set_var("SWARM_EVIDENCE_SIGNING_KEY", "review-workbench-test-key");
        }

        let root = unique_temp_dir("review-workbench");
        seed_evolution_artifacts(&root);
        seed_evidence_artifacts(&root);
        let surface = LocalOperatorSurface::from_config_and_paths(
            "inline",
            operator_config(),
            surface_paths(&root),
        )
        .unwrap();
        let app = surface.router();
        let auth = ("authorization", "Bearer secret-token");
        let create_body =
            "title=red+lane+review&notes=compare+promotion+lanes&artifact_refs=promotion_review%3Areview%3Ared%0Acanary_run%3Acanary%3Ared%0Aproduction_promotion%3Apromotion%3Ared"
                .to_string();
        let create_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/review/sessions")
                    .header(auth.0, auth.1)
                    .header(
                        axum::http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(Body::from(create_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_response.status(), StatusCode::SEE_OTHER);
        let session_location = create_response
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(session_location.starts_with("/v1/operator/review/sessions/review_session:"));
        let session_id = session_location
            .trim_start_matches("/v1/operator/review/sessions/")
            .to_string();

        let session_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&session_location)
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(session_response.status(), StatusCode::OK);
        let session_body = to_bytes(session_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let session_html = String::from_utf8(session_body.to_vec()).unwrap();
        assert!(session_html.contains("Review Session Detail"));
        assert!(session_html.contains("Cross-Lane Summary"));
        assert!(session_html.contains("Portable Capsules"));
        assert!(session_html.contains("Governance Prep"));
        assert!(session_html.contains("Canary"));
        assert!(session_html.contains("Production"));
        assert!(session_html.contains("review:red"));
        assert!(session_html.contains("canary:red"));
        assert!(session_html.contains("promotion:red"));

        let export_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/operator/review/sessions/{session_id}/export"))
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(export_response.status(), StatusCode::SEE_OTHER);
        let export_location = export_response
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(export_location.starts_with("/v1/operator/review/exports/review_session_export:"));
        let export_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&export_location)
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(export_page.status(), StatusCode::OK);
        let export_body = to_bytes(export_page.into_body(), usize::MAX).await.unwrap();
        let export_html = String::from_utf8(export_body.to_vec()).unwrap();
        assert!(export_html.contains("Review Session Export"));
        assert!(export_html.contains("abcd1234"));
        assert!(export_html.contains("Cross-Lane Summary"));

        let capsule_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/v1/operator/review/sessions/{session_id}/capsules"
                    ))
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(capsule_response.status(), StatusCode::SEE_OTHER);
        let capsule_location = capsule_response
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(capsule_location.starts_with("/v1/operator/review/capsules/review_capsule:"));
        let capsule_id = capsule_location
            .trim_start_matches("/v1/operator/review/capsules/")
            .to_string();
        let capsule_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&capsule_location)
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(capsule_page.status(), StatusCode::OK);
        let capsule_body = to_bytes(capsule_page.into_body(), usize::MAX)
            .await
            .unwrap();
        let capsule_html = String::from_utf8(capsule_body.to_vec()).unwrap();
        assert!(capsule_html.contains("Portable Review Capsule"));
        assert!(capsule_html.contains("Create Delegation Packet"));

        let readiness_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/v1/operator/review/sessions/{session_id}/promotion-readiness"
                    ))
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(readiness_response.status(), StatusCode::SEE_OTHER);
        let readiness_location = readiness_response
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            readiness_location
                .starts_with("/v1/operator/review/promotion-readiness/review_session_readiness:")
        );
        let readiness_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&readiness_location)
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(readiness_page.status(), StatusCode::OK);
        let readiness_body = to_bytes(readiness_page.into_body(), usize::MAX)
            .await
            .unwrap();
        let readiness_html = String::from_utf8(readiness_body.to_vec()).unwrap();
        assert!(readiness_html.contains("Promotion Readiness Review"));
        assert!(readiness_html.contains("ready_for_advisory_promotion_review"));

        let readiness_capsule_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/v1/operator/review/promotion-readiness/{}/capsules",
                        readiness_location
                            .trim_start_matches("/v1/operator/review/promotion-readiness/")
                    ))
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(readiness_capsule_response.status(), StatusCode::SEE_OTHER);

        let workbench = DefaultReviewWorkbenchHarness::from_paths(&surface_paths(&root)).unwrap();
        let capsule_lookup = workbench.load_capsule(&capsule_id).unwrap().unwrap();
        let import_body = format!("source_path={}", capsule_lookup.record.bundle_path);
        let import_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/review/capsule-imports")
                    .header(auth.0, auth.1)
                    .header(
                        axum::http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(Body::from(import_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(import_response.status(), StatusCode::SEE_OTHER);
        let import_location = import_response
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            import_location
                .starts_with("/v1/operator/review/capsule-imports/review_capsule_import:")
        );
        let import_id = import_location
            .trim_start_matches("/v1/operator/review/capsule-imports/")
            .to_string();
        let import_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&import_location)
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(import_page.status(), StatusCode::OK);
        let import_body = to_bytes(import_page.into_body(), usize::MAX).await.unwrap();
        let import_html = String::from_utf8(import_body.to_vec()).unwrap();
        assert!(import_html.contains("Imported Review Capsule"));
        assert!(import_html.contains("trusted"));

        let delegation_body = "reason=preserve+review+continuity+for+external+inspection&delegate_label=remote+review+board";
        let delegation_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/v1/operator/review/capsule-imports/{import_id}/delegations"
                    ))
                    .header(auth.0, auth.1)
                    .header(
                        axum::http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(Body::from(delegation_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delegation_response.status(), StatusCode::SEE_OTHER);
        let delegation_location = delegation_response
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            delegation_location.starts_with("/v1/operator/review/delegations/review_delegation:")
        );
        let delegation_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&delegation_location)
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delegation_page.status(), StatusCode::OK);
        let delegation_body = to_bytes(delegation_page.into_body(), usize::MAX)
            .await
            .unwrap();
        let delegation_html = String::from_utf8(delegation_body.to_vec()).unwrap();
        assert!(delegation_html.contains("Review Delegation Packet"));
        assert!(delegation_html.contains("remote review board"));

        let handoff_body = "reason=re-verify+selected+evidence+from+review&selected_artifact_refs=production_promotion%3Apromotion%3Ared".to_string();
        let handoff_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/v1/operator/review/sessions/{session_id}/handoffs/reverify"
                    ))
                    .header(auth.0, auth.1)
                    .header(
                        axum::http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(Body::from(handoff_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(handoff_response.status(), StatusCode::SEE_OTHER);
        let handoff_location = handoff_response
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(handoff_location.starts_with("/v1/operator/review/handoffs/review_handoff:"));
        let handoff_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&handoff_location)
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(handoff_page.status(), StatusCode::OK);
        let handoff_body = to_bytes(handoff_page.into_body(), usize::MAX)
            .await
            .unwrap();
        let handoff_html = String::from_utf8(handoff_body.to_vec()).unwrap();
        assert!(handoff_html.contains("Review Session Handoff"));
        assert!(handoff_html.contains("blocked"));
        assert!(handoff_html.contains("/v1/operator/maintenance/actions/"));

        let maintenance_response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/maintenance/actions?status=blocked&limit=10")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(maintenance_response.status(), StatusCode::OK);
        let maintenance_body = to_bytes(maintenance_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let maintenance_json: Value = serde_json::from_slice(&maintenance_body).unwrap();
        assert_eq!(maintenance_json["total_count"], 1);
        assert_eq!(
            maintenance_json["actions"][0]["target_kind"],
            "evidence_bundle"
        );
    }
}
