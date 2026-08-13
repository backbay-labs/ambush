use super::error::{OperatorApiError, OperatorReviewError, map_operator_rate_limit_rejection};
use super::helpers::now_ms;
use super::state::{OperatorHttpError, OperatorRequestGuardState};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;
use std::sync::Arc;
use swarm_core::config::{OperatorScope, SwarmConfig};
use swarm_ingest_runtime::control::{
    OPERATOR_API_SCHEMA_VERSION_HEADER, resolve_operator_api_schema_version,
};
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub(super) struct AuthenticatedOperatorPrincipal {
    pub(super) operator_id: Arc<str>,
    scopes: Vec<OperatorScope>,
}

impl AuthenticatedOperatorPrincipal {
    fn has_scope(&self, scope: OperatorScope) -> bool {
        self.scopes.contains(&scope)
    }
}

#[derive(Debug, Clone)]
struct ConfiguredOperatorPrincipal {
    principal: AuthenticatedOperatorPrincipal,
    token_env: Arc<str>,
    token_expires_at_ms: Option<i64>,
}

#[derive(Debug, Clone)]
pub(super) struct OperatorAuthState {
    principals: Arc<Vec<ConfiguredOperatorPrincipal>>,
}

#[derive(Debug, Clone)]
enum OperatorBearerAuthFailure {
    Invalid,
    Expired {
        operator_id: Arc<str>,
        expires_at_ms: i64,
    },
}

fn read_operator_token_from_env(env_name: &str) -> Option<Zeroizing<String>> {
    let mut token = std::env::var(env_name).ok().map(Zeroizing::new)?;
    while matches!(token.as_bytes().last(), Some(b'\n' | b'\r')) {
        token.pop();
    }
    (!token.is_empty()).then_some(token)
}

impl OperatorAuthState {
    pub(super) fn from_config(config: &SwarmConfig) -> Result<Self, OperatorHttpError> {
        let principals = config
            .operator
            .auth
            .effective_principals()
            .into_iter()
            .map(|principal| {
                if read_operator_token_from_env(&principal.token_env).is_none() {
                    return Err(OperatorHttpError::MissingTokenEnv {
                        env_name: principal.token_env.clone(),
                    });
                }
                Ok(ConfiguredOperatorPrincipal {
                    principal: AuthenticatedOperatorPrincipal {
                        operator_id: Arc::from(principal.operator_id),
                        scopes: principal.scopes,
                    },
                    token_env: Arc::from(principal.token_env),
                    token_expires_at_ms: principal.token_expires_at_ms,
                })
            })
            .collect::<Result<Vec<_>, OperatorHttpError>>()?;
        Ok(Self {
            principals: Arc::new(principals),
        })
    }

    fn authenticate(
        &self,
        token: &str,
        now_ms: i64,
    ) -> Result<AuthenticatedOperatorPrincipal, OperatorBearerAuthFailure> {
        let mut expired = None;
        for principal in self.principals.iter() {
            let Some(expected_token) = read_operator_token_from_env(principal.token_env.as_ref())
            else {
                continue;
            };
            if expected_token.as_str() != token {
                continue;
            }
            if let Some(expires_at_ms) = principal.token_expires_at_ms
                && now_ms > expires_at_ms
            {
                expired = Some(OperatorBearerAuthFailure::Expired {
                    operator_id: principal.principal.operator_id.clone(),
                    expires_at_ms,
                });
                continue;
            }
            return Ok(principal.principal.clone());
        }
        Err(expired.unwrap_or(OperatorBearerAuthFailure::Invalid))
    }

    pub(super) fn operator_has_scope(&self, operator_id: &str, scope: OperatorScope) -> bool {
        self.principals.iter().any(|principal| {
            principal.principal.operator_id.as_ref() == operator_id
                && principal.principal.has_scope(scope)
        })
    }
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

pub(super) async fn require_supported_operator_api_schema_version(
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, OperatorApiError> {
    let requested = parse_requested_operator_api_schema_version(&headers)?;
    resolve_operator_api_schema_version(requested).map_err(OperatorApiError::bad_request)?;
    Ok(next.run(request).await)
}

pub(super) fn require_operator_api_scope(
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

pub(super) fn require_operator_review_scope(
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

pub(super) async fn require_bearer_auth(
    State(state): State<OperatorRequestGuardState>,
    headers: HeaderMap,
    mut request: axum::extract::Request,
    next: Next,
) -> Result<Response, OperatorApiError> {
    let peer_addr = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0);
    state
        .rate_limiter
        .check_request(&headers, peer_addr, request.uri().path(), now_ms())
        .map_err(map_operator_rate_limit_rejection)?;
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| OperatorApiError::unauthorized("missing Authorization header"))?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or_else(|| OperatorApiError::unauthorized("expected Authorization: Bearer <token>"))?;
    let principal = state
        .auth
        .authenticate(token, now_ms())
        .map_err(|error| match error {
            OperatorBearerAuthFailure::Invalid => {
                OperatorApiError::unauthorized("invalid bearer token")
            }
            OperatorBearerAuthFailure::Expired {
                operator_id,
                expires_at_ms,
            } => OperatorApiError::unauthorized(format!(
                "bearer token for operator `{operator_id}` expired at {expires_at_ms}"
            )),
        })?;
    request.extensions_mut().insert(principal);

    Ok(next.run(request).await)
}
