use crate::config::{RuntimeConfigError, load_config};
use crate::control::{ControlEnvelope, ControlError, DefaultControlPlane};
use crate::service::OperatorStatusReport;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use swarm_core::config::SwarmConfig;

/// Errors raised while building or serving the authenticated operator surface.
#[derive(Debug, thiserror::Error)]
pub enum OperatorHttpError {
    #[error(transparent)]
    Config(#[from] RuntimeConfigError),

    #[error(transparent)]
    Control(#[from] ControlError),

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
        if !config.operator.enabled {
            return Err(OperatorHttpError::Disabled);
        }

        let env_name = config.operator.auth.token_env.clone();
        let _token = std::env::var(&env_name)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| OperatorHttpError::MissingTokenEnv {
                env_name: env_name.clone(),
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

        let control = DefaultControlPlane::from_config(config_path, config)?;
        Ok(Self {
            bind_addr,
            state: OperatorHttpState {
                control: Arc::new(control),
            },
        })
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

#[cfg(test)]
mod tests {
    use super::LocalOperatorSurface;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use serde_json::Value;
    use swarm_core::config::{
        AuditConfig, BundleStoreConfig, CanaryConfig, CorrelationConfig, DetectionConfig,
        InvestigationConfig, OperatorSurfaceConfig, PheromoneBackendConfig, PheromoneConfig,
        PolicyConfig, PromotionConfig, RuntimeSettings, SwarmConfig, TelemetrySourceConfig,
    };
    use tower::ServiceExt;

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
                enabled: false,
                worker_count: 1,
                max_pending_jobs: 4,
                time_budget_ms: 250,
                bundle_store: BundleStoreConfig::Memory,
            },
            correlation: CorrelationConfig {
                enabled: false,
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
                max_list_results: 50,
                auth: swarm_core::config::OperatorAuthConfig {
                    operator_id: "local-operator".to_string(),
                    token_env: "SWARM_OPERATOR_TEST_TOKEN".to_string(),
                },
            },
        }
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
}
