use super::approval::{
    approval_ledger_handler, approval_ledger_list_handler, approval_set_create_handler,
    approval_set_handler, approval_set_list_handler, approval_vote_append_handler,
};
use super::auth::{
    OperatorAuthState, require_bearer_auth, require_supported_operator_api_schema_version,
};
use super::control::{
    incident_handler, investigation_handler, metrics_handler,
    notification_dead_letter_list_handler, notification_dead_letter_replay_handler, replay_handler,
    status_handler, threat_class_config_list_handler, threat_class_config_upsert_handler,
    threat_intel_entry_lookup_handler, threat_intel_entry_upsert_handler,
};
use super::evidence::{
    evidence_bundle_handler, evidence_bundle_list_handler, evidence_verification_handler,
    promotion_evidence_packet_handler,
};
use super::evolution::{
    governance_packet_handler, packet_set_handler, packet_set_list_handler, portfolio_handler,
    portfolio_history_handler, portfolio_history_list_handler, portfolio_list_handler,
};
use super::helpers::evidence_harness_paths;
use super::maintenance::{
    maintenance_action_handler, maintenance_action_list_handler, maintenance_action_lookup_handler,
};
use super::review::{
    review_capsule_delegation_handler, review_capsule_import_delegation_handler,
    review_capsule_import_handler, review_capsule_import_page_handler, review_capsule_page_handler,
    review_delegation_page_handler, review_evidence_bundle_handler, review_evidence_list_handler,
    review_evidence_verification_handler, review_home_handler, review_promotion_packet_handler,
    review_promotion_packet_list_handler, review_rehearsal_export_handler,
    review_session_capsule_handler, review_session_create_handler, review_session_export_handler,
    review_session_export_page_handler, review_session_handler, review_session_handoff_handler,
    review_session_handoff_page_handler, review_session_list_handler,
    review_session_promotion_readiness_handler, review_session_promotion_readiness_page_handler,
    review_session_readiness_capsule_handler,
};
use crate::serve::{ServeError, serve_with_listener};
use axum::Router;
use axum::middleware;
use axum::routing::{get, post};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use swarm_core::config::{OperatorSurfacePaths, SwarmConfig};
use swarm_runtime::approval::{ApprovalError, DefaultApprovalHarness};
use swarm_runtime::config::{RuntimeConfigError, load_config};
use swarm_runtime::control::{ControlError, DefaultControlPlane};
use swarm_runtime::detection::metrics::CriticalPathMetrics;
use swarm_runtime::evidence::{DefaultEvidenceHarness, OperatorEvidenceReadService};
use swarm_runtime::governance_prep::DefaultEvolutionGovernancePrepHarness;
use swarm_runtime::http::rate_limit::HttpRateLimiter;
use swarm_runtime::operator_maintenance::{OperatorMaintenanceError, OperatorMaintenanceService};
use swarm_runtime::portfolio::DefaultEvolutionPortfolioHarness;
use swarm_runtime_workbench::review_workbench::{
    DefaultReviewWorkbenchHarness, ReviewWorkbenchError,
};

/// Errors raised while building or serving the authenticated operator surface.
#[derive(Debug, thiserror::Error)]
pub enum OperatorHttpError {
    #[error(transparent)]
    Config(#[from] RuntimeConfigError),

    #[error(transparent)]
    Control(#[from] ControlError),

    #[error(transparent)]
    Evidence(#[from] swarm_runtime::evidence::EvidenceError),

    #[error(transparent)]
    Portfolio(#[from] swarm_runtime::portfolio::EvolutionPortfolioError),

    #[error(transparent)]
    GovernancePrep(#[from] swarm_runtime::governance_prep::EvolutionGovernancePrepError),

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
    pub(super) state: OperatorHttpState,
}

#[derive(Clone)]
pub(super) struct OperatorHttpState {
    pub(super) auth: OperatorAuthState,
    pub(super) rate_limiter: HttpRateLimiter,
    pub(super) control: Arc<DefaultControlPlane>,
    pub(super) portfolio: Option<Arc<DefaultEvolutionPortfolioHarness>>,
    pub(super) governance_prep: Option<Arc<DefaultEvolutionGovernancePrepHarness>>,
    pub(super) maintenance: Option<Arc<OperatorMaintenanceService>>,
    pub(super) evidence: Option<Arc<OperatorEvidenceReadService>>,
    pub(super) evidence_harness: Option<Arc<DefaultEvidenceHarness>>,
    pub(super) workbench: Option<Arc<DefaultReviewWorkbenchHarness>>,
    pub(super) approval: Option<Arc<DefaultApprovalHarness>>,
    pub(super) prometheus: Option<CriticalPathMetrics>,
    pub(super) runtime_base_url: String,
    pub(super) max_list_results: usize,
    pub(super) approval_receipt_signer_id: String,
    pub(super) approval_receipt_signing_key_env: String,
}

#[derive(Debug, Clone)]
pub(super) struct OperatorRequestGuardState {
    pub(super) auth: OperatorAuthState,
    pub(super) rate_limiter: HttpRateLimiter,
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
