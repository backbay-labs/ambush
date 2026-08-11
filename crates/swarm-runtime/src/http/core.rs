use super::auth::{
    AuthenticatedOperatorPrincipal, OperatorAuthState, require_bearer_auth,
    require_operator_api_scope, require_operator_review_scope,
    require_supported_operator_api_schema_version,
};
use super::error::{
    OperatorApiError, OperatorReviewError, map_approval_error, map_control_error,
    map_control_review_error, map_evidence_api_error, map_governance_prep_error,
    map_maintenance_error, map_portfolio_error, map_review_evidence_error,
    map_review_workbench_error,
};
use super::helpers::{
    approval_harness, effective_limit, evidence_harness_paths, evidence_service,
    filter_review_evidence_list, filter_review_promotion_packet_list, governance_harness,
    limit_approval_ledger_list, limit_approval_set_list, limit_evidence_bundle_list,
    limit_maintenance_list, limit_packet_set_list, limit_portfolio_history_list,
    limit_portfolio_list, limit_promotion_packet_list, limit_review_capsule_import_list,
    limit_review_capsule_list, limit_review_delegation_list, limit_review_session_export_list,
    limit_review_session_handoff_list, limit_review_session_list,
    limit_review_session_promotion_readiness_list, maintenance_service,
    normalize_form_optional_text, now_ms, parse_evidence_subject_kind, parse_incident_selector,
    parse_investigation_selector, parse_maintenance_status, parse_portfolio_review_state,
    parse_replay_selector, parse_review_artifact_refs_text, parse_review_evidence_subject_kind,
    parse_review_evidence_verification_status, parse_review_promotion_recommendation,
    portfolio_harness, review_evidence_harness, review_evidence_secret_material,
    review_evidence_service, review_workbench_service,
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
use crate::approval::{
    ApprovalError, ApprovalLedgerList, ApprovalLedgerLookup, ApprovalSetList, ApprovalSetReport,
    ApprovalVerdictStatus, DefaultApprovalHarness, ThresholdRule,
};
use crate::config::{RuntimeConfigError, load_config};
use crate::control::{
    ControlEnvelope, ControlError, DefaultControlPlane, IncidentArtifactView,
    IncidentLookupSelector, InvestigationArtifactView, ReplayArtifactView, ReplayLookupSelector,
};
use crate::detection::metrics::{CriticalPathMetrics, encode_metrics};
use crate::evidence::{
    DefaultEvidenceHarness, EvidenceBundle, EvidenceBundleList, EvidenceExportRequest,
    EvidenceSubjectKind, EvidenceVerificationReport, OperatorEvidenceReadService,
    PromotionEvidencePacket,
};
use crate::governance_prep::{
    DefaultEvolutionGovernancePrepHarness, EvolutionGovernancePacketSetList,
    EvolutionPortfolioHistoryList,
};
use crate::http::rate_limit::HttpRateLimiter;
use crate::operator_maintenance::{
    OperatorMaintenanceError, OperatorMaintenanceExecution, OperatorMaintenanceList,
    OperatorMaintenanceRecord, OperatorMaintenanceRequest, OperatorMaintenanceService,
};
use crate::portfolio::{DefaultEvolutionPortfolioHarness, EvolutionPortfolioList};
use crate::review_workbench::{
    DefaultReviewWorkbenchHarness, ReviewCapsuleImportRequest, ReviewDelegationCreateRequest,
    ReviewSessionCreateRequest, ReviewSessionReverifyRequest, ReviewWorkbenchError,
};
use crate::serve::{ServeError, serve_with_listener};
use crate::service::OperatorStatusReport;
use axum::extract::{Extension, Form, Path as RoutePath, Query, State};
use axum::http::{StatusCode, header};
use axum::middleware;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use swarm_core::config::{OperatorScope, SwarmConfig};
use swarm_core::pheromone::{ThreatClassConfig, ThreatIntelEntry, ThreatIntelIndicatorType};
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
pub(super) struct OperatorHttpState {
    auth: OperatorAuthState,
    rate_limiter: HttpRateLimiter,
    control: Arc<DefaultControlPlane>,
    pub(super) portfolio: Option<Arc<DefaultEvolutionPortfolioHarness>>,
    pub(super) governance_prep: Option<Arc<DefaultEvolutionGovernancePrepHarness>>,
    pub(super) maintenance: Option<Arc<OperatorMaintenanceService>>,
    pub(super) evidence: Option<Arc<OperatorEvidenceReadService>>,
    pub(super) evidence_harness: Option<Arc<DefaultEvidenceHarness>>,
    pub(super) workbench: Option<Arc<DefaultReviewWorkbenchHarness>>,
    pub(super) approval: Option<Arc<DefaultApprovalHarness>>,
    prometheus: Option<CriticalPathMetrics>,
    runtime_base_url: String,
    max_list_results: usize,
    approval_receipt_signer_id: String,
    pub(super) approval_receipt_signing_key_env: String,
}

#[derive(Debug, Clone)]
pub(super) struct OperatorRequestGuardState {
    pub(super) auth: OperatorAuthState,
    pub(super) rate_limiter: HttpRateLimiter,
}

#[derive(Debug, Deserialize)]
pub(super) struct ReplayLookupQuery {
    pub(super) bundle_id: Option<String>,
    pub(super) hunt_id: Option<String>,
    pub(super) receipt_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct InvestigationLookupQuery {
    pub(super) investigation_id: Option<String>,
    pub(super) hunt_id: Option<String>,
    pub(super) receipt_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct IncidentLookupQuery {
    pub(super) incident_id: Option<String>,
    pub(super) hunt_id: Option<String>,
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

#[derive(Debug, Clone)]
pub(super) struct ReviewHomeContext {
    pub(super) selected_bundle: Option<ReplayArtifactView>,
    pub(super) latest_rehearsal_bundle: Option<ReplayArtifactView>,
    pub(super) incident: Option<IncidentArtifactView>,
    pub(super) signed_rehearsal_bundle_id: Option<String>,
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
        let rate_limiter = HttpRateLimiter::new("operator", config.operator.rate_limit.clone());

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
                rate_limiter,
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
                OperatorRequestGuardState {
                    auth: self.state.auth.clone(),
                    rate_limiter: self.state.rate_limiter.clone(),
                },
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
    let mut status = state.control.status().await.map_err(map_control_error)?;
    status.data.rate_limit = state.rate_limiter.status();
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
                threat_intel_feeds: vec![],
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
                rate_limit: Default::default(),
                auth: OperatorAuthConfig {
                    context_token_env: "SWARM_OPERATOR_TEST_TOKEN".to_string(),
                    principals: Vec::new(),
                    operator_id: "local-operator".to_string(),
                    token_env: "SWARM_OPERATOR_TEST_TOKEN".to_string(),
                    token_expires_at_ms: None,
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
                auth_token: Some("notify-secret".into()),
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
    async fn status_route_allows_configured_burst_before_rate_limit_rejection() {
        unsafe {
            std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
        }
        let mut config = operator_config();
        config.operator.rate_limit.burst_max_requests = 2;
        config.operator.rate_limit.burst_window_ms = 1_000;
        config.operator.rate_limit.sustained_max_requests = 10;
        config.operator.rate_limit.sustained_window_ms = 60_000;
        config.operator.rate_limit.trust_forwarded_headers = true;
        let surface = LocalOperatorSurface::from_config("inline", config).unwrap();
        let app = surface.router();

        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/v1/operator/status")
                        .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                        .header("x-forwarded-for", "198.51.100.10")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        let rejected = app
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/status")
                    .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                    .header("x-forwarded-for", "198.51.100.10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(rejected.headers().get(header::RETRY_AFTER).unwrap(), "1");
        let body = to_bytes(rejected.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["message"]
                .as_str()
                .unwrap_or_default()
                .contains("burst rate limit exceeded"),
            "expected burst limiter rejection context: {json:?}"
        );
    }

    #[tokio::test]
    async fn status_route_recovers_after_rate_limit_window_refills() {
        unsafe {
            std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
        }
        let mut config = operator_config();
        config.operator.rate_limit.burst_max_requests = 1;
        config.operator.rate_limit.burst_window_ms = 20;
        config.operator.rate_limit.sustained_max_requests = 10;
        config.operator.rate_limit.sustained_window_ms = 1_000;
        config.operator.rate_limit.trust_forwarded_headers = true;
        let surface = LocalOperatorSurface::from_config("inline", config).unwrap();
        let app = surface.router();

        let initial = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/status")
                    .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                    .header("x-forwarded-for", "198.51.100.11")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(initial.status(), StatusCode::OK);

        let rejected = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/status")
                    .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                    .header("x-forwarded-for", "198.51.100.11")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);

        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        let recovered = app
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/status")
                    .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                    .header("x-forwarded-for", "198.51.100.11")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recovered.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn status_route_reloads_rotated_bearer_token_without_rebuild() {
        let token_env = "SWARM_OPERATOR_ROTATION_TEST_TOKEN";
        unsafe {
            std::env::set_var(token_env, "initial-token");
        }
        let mut config = operator_config();
        config.operator.auth.token_env = token_env.to_string();
        config.operator.auth.context_token_env = token_env.to_string();
        let surface = LocalOperatorSurface::from_config("inline", config).unwrap();
        let app = surface.router();

        let initial = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/status")
                    .header(axum::http::header::AUTHORIZATION, "Bearer initial-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(initial.status(), StatusCode::OK);

        unsafe {
            std::env::set_var(token_env, "rotated-token");
        }

        let stale = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/status")
                    .header(axum::http::header::AUTHORIZATION, "Bearer initial-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);

        let rotated = app
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/status")
                    .header(axum::http::header::AUTHORIZATION, "Bearer rotated-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rotated.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn status_route_rejects_expired_bearer_token_with_context() {
        let token_env = "SWARM_OPERATOR_EXPIRED_TEST_TOKEN";
        unsafe {
            std::env::set_var(token_env, "expired-token");
        }
        let mut config = operator_config();
        config.operator.auth.token_env = token_env.to_string();
        config.operator.auth.context_token_env = token_env.to_string();
        config.operator.auth.token_expires_at_ms = Some(1);
        let surface = LocalOperatorSurface::from_config("inline", config).unwrap();
        let app = surface.router();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/status")
                    .header(axum::http::header::AUTHORIZATION, "Bearer expired-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["message"]
                .as_str()
                .unwrap_or_default()
                .contains("expired at"),
            "expected expiry context in operator auth error: {json:?}"
        );
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
            source: "operator".to_string(),
            indicator_id: None,
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
        // Lowering `human_gate_severity` is not sufficient on its own. `operator_config()`
        // inherits `permissive_policy_rules()`, whose sole rule has an empty `actions`
        // selector -- a wildcard that matches `IsolateHost`, returns Allow, and short
        // circuits the static human gate (the first matching rule decides outright; see
        // docs/CONSENSUS.md "Human Approval Boundary"). Without this, no approval set is
        // ever registered and `total_count` below is 0.
        //
        // Scope the inherited allow off destructive actions so `IsolateHost` reaches
        // `static.human_gate`, mirroring the fixture shape already used in
        // `ingest/tests.rs` `permissive_policy_rules`. Scoped to this test's own
        // `runtime_config`: `operator_config()` has dozens of consumers in this module.
        for rule in &mut runtime_config.policy.rules {
            rule.actions = vec![swarm_core::config::PolicyActionSelector::Escalate];
        }
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
                    token_expires_at_ms: None,
                    scopes: vec![OperatorScope::Read],
                },
                OperatorPrincipalConfig {
                    operator_id: "rehearser-1".to_string(),
                    token_env: REHEARSE_ENV.to_string(),
                    token_expires_at_ms: None,
                    scopes: vec![OperatorScope::Rehearse],
                },
                OperatorPrincipalConfig {
                    operator_id: approver_id.clone(),
                    token_env: APPROVE_ENV.to_string(),
                    token_expires_at_ms: None,
                    scopes: vec![OperatorScope::Approve],
                },
                OperatorPrincipalConfig {
                    operator_id: second_approver_id.clone(),
                    token_env: APPROVE2_ENV.to_string(),
                    token_expires_at_ms: None,
                    scopes: vec![OperatorScope::Approve],
                },
                OperatorPrincipalConfig {
                    operator_id: maintainer_id.clone(),
                    token_env: MAINT_ENV.to_string(),
                    token_expires_at_ms: None,
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
