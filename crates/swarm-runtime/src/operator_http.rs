use crate::config::{RuntimeConfigError, load_config};
use crate::control::{
    ControlEnvelope, ControlError, DefaultControlPlane, IncidentArtifactView,
    IncidentLookupSelector, InvestigationArtifactView, InvestigationLookupSelector,
    ReplayArtifactView, ReplayLookupSelector,
};
use crate::evidence::{
    EvidenceBundle, EvidenceBundleList, EvidenceSubjectKind, EvidenceVerificationReport,
    EvidenceVerificationStatus, OperatorEvidenceReadService, PromotionEvidencePacket,
    PromotionEvidencePacketList, PromotionEvidenceRecommendation,
};
use crate::governance_prep::{
    DefaultEvolutionGovernancePrepHarness, EvolutionGovernancePacketSetList,
    EvolutionPortfolioHistoryList,
};
use crate::operator_maintenance::{
    OperatorMaintenanceError, OperatorMaintenanceExecution, OperatorMaintenanceList,
    OperatorMaintenanceRecord, OperatorMaintenanceRequest, OperatorMaintenanceService,
    OperatorMaintenanceStatus,
};
use crate::portfolio::{
    DefaultEvolutionPortfolioHarness, EvolutionPortfolioEntryReviewState, EvolutionPortfolioList,
};
use crate::review_workbench::{
    DefaultReviewWorkbenchHarness, ReviewArtifactRef, ReviewArtifactRefKind,
    ReviewSessionCreateRequest, ReviewSessionExport, ReviewSessionList,
    ReviewSessionMaintenanceHandoff, ReviewSessionMaintenanceHandoffList, ReviewSessionResolved,
    ReviewSessionReverifyRequest, ReviewWorkbenchError,
};
use crate::service::OperatorStatusReport;
use axum::extract::{Form, Path as RoutePath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use swarm_core::config::SwarmConfig;

/// Result directories required to expose evolution review artifacts through HTTP.
#[derive(Debug, Clone)]
pub struct OperatorSurfacePaths {
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
    pub review_session_handoff_results_dir: PathBuf,
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
    Serve(#[from] std::io::Error),
}

#[derive(Clone)]
pub struct LocalOperatorSurface {
    bind_addr: SocketAddr,
    state: OperatorHttpState,
}

#[derive(Clone)]
struct OperatorHttpState {
    control: Arc<DefaultControlPlane>,
    portfolio: Option<Arc<DefaultEvolutionPortfolioHarness>>,
    governance_prep: Option<Arc<DefaultEvolutionGovernancePrepHarness>>,
    maintenance: Option<Arc<OperatorMaintenanceService>>,
    evidence: Option<Arc<OperatorEvidenceReadService>>,
    workbench: Option<Arc<DefaultReviewWorkbenchHarness>>,
    max_list_results: usize,
}

#[derive(Debug, Clone)]
struct OperatorAuthState {
    expected_token: Arc<str>,
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

        std::env::var(&config.operator.auth.token_env)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| OperatorHttpError::MissingTokenEnv {
                env_name: config.operator.auth.token_env.clone(),
            })?;

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

        let config_path = config_path.into();
        let control = DefaultControlPlane::from_config(config_path.clone(), config.clone())?;
        let (portfolio, governance_prep, maintenance, evidence, workbench) =
            if let Some(paths) = paths {
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
                let maintenance = OperatorMaintenanceService::from_paths(
                    config.operator.auth.operator_id.clone(),
                    &paths,
                )?;
                let evidence = OperatorEvidenceReadService::from_store_paths(
                    &paths.evidence_results_dir,
                    &paths.evidence_verification_results_dir,
                    &paths.promotion_evidence_results_dir,
                )?;
                let workbench = DefaultReviewWorkbenchHarness::from_paths(
                    config.operator.auth.operator_id.clone(),
                    &paths,
                )?;
                (
                    Some(Arc::new(portfolio)),
                    Some(Arc::new(governance_prep)),
                    Some(Arc::new(maintenance)),
                    Some(Arc::new(evidence)),
                    Some(Arc::new(workbench)),
                )
            } else {
                (None, None, None, None, None)
            };

        Ok(Self {
            bind_addr,
            state: OperatorHttpState {
                control: Arc::new(control),
                portfolio,
                governance_prep,
                maintenance,
                evidence,
                workbench,
                max_list_results: config.operator.max_list_results,
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
    pub fn router(&self, token: String) -> Router {
        let auth_state = OperatorAuthState {
            expected_token: Arc::from(token),
        };

        Router::new()
            .route("/v1/operator/status", get(status_handler))
            .route("/v1/operator/replay", get(replay_handler))
            .route("/v1/operator/investigation", get(investigation_handler))
            .route("/v1/operator/incident", get(incident_handler))
            .route("/v1/operator/review", get(review_home_handler))
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
                "/v1/operator/review/sessions/{session_id}/handoffs/reverify",
                post(review_session_handoff_handler),
            )
            .route(
                "/v1/operator/review/exports/{export_id}",
                get(review_session_export_page_handler),
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
                auth_state,
                require_bearer_auth,
            ))
    }

    /// Serve the authenticated operator surface until the process exits.
    pub async fn serve(self) -> Result<(), OperatorHttpError> {
        let token_env = self
            .state
            .control
            .stack
            .service
            .config
            .operator
            .auth
            .token_env
            .clone();
        let token = std::env::var(&token_env)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .ok_or(OperatorHttpError::MissingTokenEnv {
                env_name: token_env,
            })?;
        let listener = tokio::net::TcpListener::bind(self.bind_addr)
            .await
            .map_err(|source| OperatorHttpError::Bind {
                bind_addr: self.bind_addr,
                source,
            })?;
        axum::serve(listener, self.router(token))
            .await
            .map_err(OperatorHttpError::Serve)
    }
}

async fn status_handler(
    State(state): State<OperatorHttpState>,
) -> Result<Json<ControlEnvelope<OperatorStatusReport>>, OperatorApiError> {
    let status = state
        .control
        .status()
        .await
        .map_err(|error| OperatorApiError::internal(error.to_string()))?;
    Ok(Json(status))
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
) -> Result<Html<String>, OperatorReviewError> {
    let service = review_evidence_service(&state)?;
    let workbench = review_workbench_service(&state)?;
    let bundles = limit_evidence_bundle_list(
        service
            .list_bundles(None)
            .map_err(|error| OperatorReviewError::internal(error.to_string()))?,
        Some(state.max_list_results),
        state.max_list_results,
    );
    let packets = limit_promotion_packet_list(
        service
            .list_promotion_evidence_packets()
            .map_err(|error| OperatorReviewError::internal(error.to_string()))?,
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
    Ok(Html(render_review_home_page(&bundles, &packets, &sessions)))
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
    Ok(Html(render_review_session_page(
        &resolved,
        &exports.exports,
        &handoffs.handoffs,
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

async fn review_session_handoff_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(session_id): RoutePath<String>,
    Form(form): Form<ReviewSessionHandoffForm>,
) -> Result<Redirect, OperatorReviewError> {
    let service = review_workbench_service(&state)?;
    let selected_artifact_refs = form
        .selected_artifact_refs
        .as_deref()
        .map(parse_review_artifact_refs_text)
        .transpose()?
        .unwrap_or_default();
    let lookup = service
        .create_reverify_handoff(ReviewSessionReverifyRequest {
            session_id,
            selected_artifact_refs,
            expected_key_id: normalize_form_optional_text(form.expected_key_id),
            reason: form.reason,
        })
        .map_err(map_review_workbench_error)?;
    Ok(Redirect::to(&format!(
        "/v1/operator/review/handoffs/{}",
        lookup.handoff.handoff_id
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
        .map_err(|error| OperatorReviewError::internal(error.to_string()))?;
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
        .map_err(|error| OperatorReviewError::internal(error.to_string()))?
        .ok_or_else(|| {
            OperatorReviewError::not_found(format!("evidence bundle `{bundle_id}` was not found"))
        })?;
    let latest_verification =
        if let Some(verification_id) = lookup.record.latest_verification_id.as_deref() {
            service
                .load_verification(verification_id)
                .map_err(|error| OperatorReviewError::internal(error.to_string()))?
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
        .map_err(|error| OperatorReviewError::internal(error.to_string()))?
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
        .map_err(|error| OperatorReviewError::internal(error.to_string()))?;
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
        .map_err(|error| OperatorReviewError::internal(error.to_string()))?
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
        .map_err(|error| OperatorApiError::internal(error.to_string()))?
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
        .map_err(|error| OperatorApiError::internal(error.to_string()))?;
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
        .map_err(|error| OperatorApiError::internal(error.to_string()))?
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
        .map_err(|error| OperatorApiError::internal(error.to_string()))?
        .ok_or_else(|| {
            OperatorApiError::not_found(format!(
                "promotion evidence packet `{packet_id}` was not found"
            ))
        })?;
    Ok(Json(lookup.packet))
}

async fn portfolio_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(portfolio_id): RoutePath<String>,
) -> Result<Json<crate::portfolio::EvolutionPortfolioReport>, OperatorApiError> {
    let harness = portfolio_harness(&state)?;
    let lookup = harness
        .load_portfolio(&portfolio_id)
        .map_err(|error| OperatorApiError::internal(error.to_string()))?
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
        .map_err(|error| OperatorApiError::internal(error.to_string()))?;
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
        .map_err(|error| OperatorApiError::internal(error.to_string()))?
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
        .map_err(|error| OperatorApiError::internal(error.to_string()))?
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
        .map_err(|error| OperatorApiError::internal(error.to_string()))?;
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
        .map_err(|error| OperatorApiError::internal(error.to_string()))?
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
        .map_err(|error| OperatorApiError::internal(error.to_string()))?;
    Ok(Json(limit_portfolio_history_list(
        list,
        query.limit,
        state.max_list_results,
    )))
}

async fn maintenance_action_handler(
    State(state): State<OperatorHttpState>,
    Json(request): Json<OperatorMaintenanceRequest>,
) -> Response {
    let service = match maintenance_service(&state) {
        Ok(service) => service,
        Err(error) => return error.into_response(),
    };
    match service.execute(request) {
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
        Err(error) => OperatorApiError::internal(error.to_string()).into_response(),
    }
}

async fn maintenance_action_lookup_handler(
    State(state): State<OperatorHttpState>,
    RoutePath(action_id): RoutePath<String>,
) -> Result<Json<OperatorMaintenanceRecord>, OperatorApiError> {
    let service = maintenance_service(&state)?;
    let lookup = service
        .load(&action_id)
        .map_err(|error| OperatorApiError::internal(error.to_string()))?
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
    let list = service
        .list(status)
        .map_err(|error| OperatorApiError::internal(error.to_string()))?;
    Ok(Json(limit_maintenance_list(
        list,
        query.limit,
        state.max_list_results,
    )))
}

async fn require_bearer_auth(
    State(auth): State<OperatorAuthState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, OperatorApiError> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| OperatorApiError::unauthorized("missing Authorization header"))?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or_else(|| OperatorApiError::unauthorized("expected Authorization: Bearer <token>"))?;
    if token != auth.expected_token.as_ref() {
        return Err(OperatorApiError::unauthorized("invalid bearer token"));
    }

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
    } else {
        Ok(ReplayLookupSelector::ReceiptId(
            query.receipt_id.as_deref().expect("receipt selector"),
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
    } else {
        Ok(InvestigationLookupSelector::ReceiptId(
            query.receipt_id.as_deref().expect("receipt selector"),
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
    } else {
        Ok(IncidentLookupSelector::HuntId(
            query.hunt_id.as_deref().expect("hunt selector"),
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

fn map_control_error(error: ControlError) -> OperatorApiError {
    match error {
        ControlError::NotFound { entity, lookup } => {
            OperatorApiError::not_found(format!("{entity} `{lookup}` was not found"))
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

fn review_workbench_service(
    state: &OperatorHttpState,
) -> Result<&DefaultReviewWorkbenchHarness, OperatorReviewError> {
    state
        .workbench
        .as_deref()
        .ok_or_else(|| OperatorReviewError::internal("review workbench stores are not configured"))
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
        ReviewWorkbenchError::HandoffNotFound { handoff_id } => OperatorReviewError::not_found(
            format!("review session handoff `{handoff_id}` was not found"),
        ),
        other => OperatorReviewError::internal(other.to_string()),
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
            "@media (max-width:760px){.hero{flex-direction:column;}.nav{justify-content:flex-start;}}"
        )
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
                        <label style=\"min-width:100%;\">Artifact refs<textarea name=\"artifact_refs\" rows=\"6\" placeholder=\"evidence_bundle:...&#10;evidence_verification:...&#10;promotion_evidence_packet:...\"></textarea></label>\
                        <button type=\"submit\">Create Review Session</button>\
                    </form>\
                    <p class=\"muted\">One artifact ref per line. Supported kinds: <code>evidence_bundle</code>, <code>evidence_verification</code>, <code>promotion_evidence_packet</code>.</p>\
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
    handoffs: &[crate::review_workbench::ReviewSessionMaintenanceHandoffRecord],
) -> String {
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

    render_review_layout(
        "Review Session Detail",
        "Compare the reviewed evidence set, export a stable snapshot, or launch one bounded evidence re-verification handoff.",
        &format!(
            "<section class=\"card\">\
                <div class=\"meta\">\
                    <div><dt>Session ID</dt><dd><code>{session_id}</code></dd></div>\
                    <div><dt>Title</dt><dd>{title}</dd></div>\
                    <div><dt>Artifacts</dt><dd>{artifact_count}</dd></div>\
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
                <article class=\"card\"><h2>Evidence Bundles</h2><table><thead><tr><th>Bundle</th><th>Kind</th><th>Subject</th><th>Verification</th></tr></thead><tbody>{bundle_rows}</tbody></table></article>\
                <article class=\"card\"><h2>Verification Reports</h2><table><thead><tr><th>Verification</th><th>Bundle</th><th>Status</th><th>Signer Key</th></tr></thead><tbody>{verification_rows}</tbody></table></article>\
            </section>\
            <section class=\"grid\" style=\"margin-top:18px;\">\
                <article class=\"card\"><h2>Promotion Evidence Packets</h2><table><thead><tr><th>Packet</th><th>Promotion</th><th>Recommendation</th><th>Attachments</th></tr></thead><tbody>{packet_rows}</tbody></table></article>\
                <article class=\"card\"><h2>Recent Exports</h2><table><thead><tr><th>Export</th><th>Artifacts</th></tr></thead><tbody>{export_rows}</tbody></table>\
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
            notes = escape_html(resolved.session.report.notes.as_deref().unwrap_or("none")),
            bundle_rows = bundle_rows,
            verification_rows = verification_rows,
            packet_rows = packet_rows,
            export_rows = export_rows,
            handoff_rows = handoff_rows
        ),
    )
}

fn render_review_session_export_page(export: &ReviewSessionExport) -> String {
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
                    <div><dt>Title</dt><dd>{title}</dd></div>\
                </div>\
                <p class=\"muted\">This export preserves digests, signer metadata, verification state, and related stable references without rereading raw store files.</p>\
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
            title = escape_html(export.title.as_deref().unwrap_or("untitled")),
            bundle_rows = bundle_rows,
            verification_rows = verification_rows,
            packet_rows = packet_rows
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

fn render_maintenance_status_pill(status: OperatorMaintenanceStatus) -> String {
    let (label, class_name) = match status {
        OperatorMaintenanceStatus::Applied => ("applied", "passed"),
        OperatorMaintenanceStatus::Blocked => ("blocked", "blocked"),
        OperatorMaintenanceStatus::Failed => ("failed", "failed"),
    };
    render_status_pill(label, class_name)
}

fn render_review_home_page(
    bundles: &EvidenceBundleList,
    packets: &PromotionEvidencePacketList,
    sessions: &ReviewSessionList,
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

    render_review_layout(
        "Local Evidence Review",
        "Authenticated local evidence workbench layered on the operator API. Session export and bounded maintenance handoff are available, but rollout and governance remain out of scope.",
        &format!(
            "<section class=\"grid\">\
                <article class=\"card\"><h2>Review Scope</h2><p>Use this surface to inspect signed evidence bundles, verification reports, and promotion evidence packets without reading store files directly.</p><p class=\"muted\">Authentication stays on the existing bearer-token boundary, and follow-on write actions remain on the existing maintenance or rollout paths.</p></article>\
                <article class=\"card\"><h2>Quick Links</h2><ul>\
                    <li>{sessions_link}</li><li>{evidence}</li><li>{packets}</li><li>{json}</li>\
                </ul></article>\
            </section>\
            <section class=\"grid\" style=\"margin-top:18px;\">\
                <article class=\"card\"><h2>Recent Evidence Bundles</h2><table><thead><tr><th>Bundle</th><th>Kind</th><th>Subject</th><th>Verification</th></tr></thead><tbody>{bundle_rows}</tbody></table></article>\
                <article class=\"card\"><h2>Recent Promotion Packets</h2><table><thead><tr><th>Packet</th><th>Promotion</th><th>Recommendation</th></tr></thead><tbody>{packet_rows}</tbody></table></article>\
            </section>\
            <section class=\"card\" style=\"margin-top:18px;\"><h2>Recent Review Sessions</h2><table><thead><tr><th>Session</th><th>Title</th><th>Artifacts</th></tr></thead><tbody>{session_rows}</tbody></table></section>",
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
            bundle_rows = bundle_rows,
            packet_rows = packet_rows,
            session_rows = session_rows
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
mod tests {
    use super::{LocalOperatorSurface, OperatorSurfacePaths};
    use crate::evidence::{
        EvidenceBundle, EvidenceRelatedRef, EvidenceSignature, EvidenceSubjectKind,
        EvidenceSubjectMetadata, EvidenceVerificationReport, EvidenceVerificationStatus,
        FileEvidenceBundleStore, FileEvidenceVerificationStore, FilePromotionEvidencePacketStore,
        PromotionEvidenceAttachment, PromotionEvidencePacket, PromotionEvidenceRecommendation,
    };
    use crate::service::EventExecutionContext;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use serde_json::{Value, json};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use swarm_core::config::{
        AuditConfig, BundleStoreConfig, CanaryConfig, CorrelationConfig, DetectionConfig,
        InvestigationConfig, OperatorAuthConfig, OperatorSurfaceConfig, PheromoneBackendConfig,
        PheromoneConfig, PolicyConfig, PromotionConfig, RuntimeSettings, SwarmConfig,
        TelemetrySourceConfig,
    };
    use swarm_core::types::AgentId;
    use swarm_policy::ApprovalContext;
    use swarm_whisker::{ProcessStartEvent, TelemetryEvent, TelemetryPayload};
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
    use crate::replay::ExperimentLineage;

    static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn operator_config() -> SwarmConfig {
        SwarmConfig {
            name: "operator-http".to_string(),
            description: "operator surface config".to_string(),
            runtime: RuntimeSettings {
                mode: crate::RuntimeMode::DetectOnly,
                telemetry_sources: vec![TelemetrySourceConfig {
                    name: "synthetic".to_string(),
                    subject: "telemetry.synthetic".to_string(),
                }],
                max_in_flight_actions: 2,
                require_durable_live_response: false,
            },
            detection: DetectionConfig {
                strategy: "suspicious_process_tree".to_string(),
                high_confidence_threshold: 0.9,
                medium_confidence_threshold: 0.7,
            },
            pheromone: PheromoneConfig {
                default_half_life_secs: 3600.0,
                evaporation_threshold: 0.01,
                min_sources_for_escalation: 2,
                alert_threshold: 2.0,
                incident_threshold: 5.0,
                backend: PheromoneBackendConfig::InMemory,
            },
            policy: PolicyConfig {
                human_gate_severity: swarm_core::types::Severity::High,
                lease_ttl_ms: 60_000,
            },
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
            operator: OperatorSurfaceConfig {
                enabled: true,
                bind_addr: "127.0.0.1:7766".to_string(),
                max_list_results: 2,
                auth: OperatorAuthConfig {
                    operator_id: "local-operator".to_string(),
                    token_env: "SWARM_OPERATOR_TEST_TOKEN".to_string(),
                },
            },
        }
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
            }),
        }
    }

    fn approval_context(now_ms: i64) -> ApprovalContext {
        ApprovalContext {
            live_mode: true,
            receipt_chain: vec![format!("receipt-upstream-{now_ms}")],
            now_ms,
        }
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

    fn sample_evidence_bundle() -> EvidenceBundle {
        EvidenceBundle {
            bundle_id: "evidence:production_promotion:promotion:red:local-evidence-signer"
                .to_string(),
            schema_version: "v1".to_string(),
            config_name: "operator-http".to_string(),
            exported_at_ms: 1_710_000_000_500,
            subject: EvidenceSubjectMetadata {
                kind: EvidenceSubjectKind::ProductionPromotion,
                stable_id: "promotion:red".to_string(),
                display_name: "production promotion promotion:red".to_string(),
                source_created_at_ms: 1_710_000_000_000,
                receipt_chain_refs: vec![],
                related_refs: vec![EvidenceRelatedRef {
                    kind: "canary_run".to_string(),
                    id: "canary:red".to_string(),
                }],
            },
            payload_sha256: "abcd1234".to_string(),
            canonical_payload: r#"{"promotion_id":"promotion:red","status":"completed"}"#
                .to_string(),
            signature: EvidenceSignature {
                signer_id: "local-evidence-signer".to_string(),
                algorithm: "ed25519".to_string(),
                key_id: "key:red".to_string(),
                public_key_hex: "11".repeat(32),
                signature_hex: "22".repeat(64),
            },
        }
    }

    fn sample_evidence_verification_report() -> EvidenceVerificationReport {
        EvidenceVerificationReport {
            verification_id:
                "evidence_verification:evidence:production_promotion:promotion:red:local-evidence-signer"
                    .to_string(),
            bundle_id: "evidence:production_promotion:promotion:red:local-evidence-signer"
                .to_string(),
            subject_kind: EvidenceSubjectKind::ProductionPromotion,
            subject_id: "promotion:red".to_string(),
            verified_at_ms: 1_710_000_000_800,
            status: EvidenceVerificationStatus::Passed,
            signer_id: "local-evidence-signer".to_string(),
            signer_key_id: "key:red".to_string(),
            expected_key_id: Some("key:red".to_string()),
            checks: vec![
                crate::evidence::EvidenceVerificationCheck {
                    name: "canonical_payload".to_string(),
                    passed: true,
                    details: "canonical payload bytes normalized cleanly".to_string(),
                },
                crate::evidence::EvidenceVerificationCheck {
                    name: "payload_sha256".to_string(),
                    passed: true,
                    details: "payload hash matches canonical payload bytes".to_string(),
                },
            ],
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

    fn surface_paths(root: &PathBuf) -> OperatorSurfacePaths {
        OperatorSurfacePaths {
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
            review_session_handoff_results_dir: root.join("review-session-handoffs"),
        }
    }

    fn seed_evolution_artifacts(root: &PathBuf) {
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

    fn seed_evidence_artifacts(root: &PathBuf) {
        let paths = surface_paths(root);
        let bundle = sample_evidence_bundle();
        let verification = sample_evidence_verification_report();
        let packet = sample_promotion_evidence_packet();

        let bundle_store = FileEvidenceBundleStore::open(&paths.evidence_results_dir).unwrap();
        let bundle_lookup = bundle_store.persist(&bundle).unwrap();
        let verification_lookup =
            FileEvidenceVerificationStore::open(&paths.evidence_verification_results_dir)
                .unwrap()
                .persist(&verification)
                .unwrap();
        bundle_store
            .attach_verification(&verification_lookup.record, &bundle_lookup.record.bundle_id)
            .unwrap();
        FilePromotionEvidencePacketStore::open(&paths.promotion_evidence_results_dir)
            .unwrap()
            .persist(&packet)
            .unwrap();
    }

    #[tokio::test]
    async fn status_route_requires_bearer_token() {
        unsafe {
            std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
        }
        let surface = LocalOperatorSurface::from_config("inline", operator_config()).unwrap();
        let app = surface.router("secret-token".to_string());

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
        let app = surface.router("secret-token".to_string());

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
        assert_eq!(json["origin"], "live_runtime_status");
        assert_eq!(json["config_name"], "operator-http");
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

        let agent_id = AgentId("whisker-a".to_string());
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

        let app = surface.router("secret-token".to_string());
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
        let app = surface.router("secret-token".to_string());
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
        let app = surface.router("secret-token".to_string());
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
        assert!(verification_html.contains("payload_sha256"));
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
        let app = surface.router("secret-token".to_string());
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
        let app = surface.router("secret-token".to_string());
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
    async fn review_workbench_routes_create_export_and_handoff_sessions() {
        unsafe {
            std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
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
        let app = surface.router("secret-token".to_string());
        let auth = ("authorization", "Bearer secret-token");
        let bundle_id = "evidence:production_promotion:promotion:red:local-evidence-signer";
        let verification_id = "evidence_verification:evidence:production_promotion:promotion:red:local-evidence-signer";
        let packet_id = "promotion_evidence:promotion:red";
        let create_body = format!(
            "title=red+evidence+review&notes=compare+promotion+evidence&artifact_refs=evidence_bundle%3A{bundle}%0Aevidence_verification%3A{verification}%0Apromotion_evidence_packet%3A{packet}",
            bundle = bundle_id.replace(':', "%3A"),
            verification = verification_id.replace(':', "%3A"),
            packet = packet_id.replace(':', "%3A"),
        );
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
        assert!(session_html.contains(bundle_id));
        assert!(session_html.contains(packet_id));

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

        let handoff_body = format!(
            "reason=re-verify+selected+evidence+from+review&selected_artifact_refs=evidence_bundle%3A{}",
            bundle_id.replace(':', "%3A"),
        );
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
