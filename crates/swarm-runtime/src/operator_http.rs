use crate::config::{RuntimeConfigError, load_config};
use crate::control::{
    ControlEnvelope, ControlError, DefaultControlPlane, IncidentArtifactView,
    IncidentLookupSelector, InvestigationArtifactView, InvestigationLookupSelector,
    ReplayArtifactView, ReplayLookupSelector,
};
use crate::evidence::{
    EvidenceBundle, EvidenceBundleList, EvidenceSubjectKind, EvidenceVerificationReport,
    OperatorEvidenceReadService, PromotionEvidencePacket,
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
use crate::service::OperatorStatusReport;
use axum::extract::{Path as RoutePath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
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

struct OperatorApiError {
    status: StatusCode,
    error: &'static str,
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
        let (portfolio, governance_prep, maintenance, evidence) = if let Some(paths) = paths {
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
            (
                Some(Arc::new(portfolio)),
                Some(Arc::new(governance_prep)),
                Some(Arc::new(maintenance)),
                Some(Arc::new(evidence)),
            )
        } else {
            (None, None, None, None)
        };

        Ok(Self {
            bind_addr,
            state: OperatorHttpState {
                control: Arc::new(control),
                portfolio,
                governance_prep,
                maintenance,
                evidence,
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
            checks: vec![],
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
}
