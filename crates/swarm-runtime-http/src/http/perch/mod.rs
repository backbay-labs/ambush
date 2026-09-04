//! First-card operator routes, grown only with implemented handlers and mounted on the
//! daemon's own listener beside `containment_operator_router`. Every route: bearer +
//! schema-version middleware, then an explicit scope check in the handler (ADR 0012 clause 1).
//!
//! # Why these routes are mounted by `swarm_detect`, not `LocalOperatorSurface`
//!
//! Each handler reads or writes the daemon's live [`IngestState`] — the ONE incident
//! store the tuning report reads and the ONE runtime-event broadcaster the bridge
//! subscribes to. `LocalOperatorSurface` builds its own control plane in its own
//! process, so a measurement written there would be invisible to the daemon.
//!
//! # The path inventory (00-DECISIONS W3-28)
//!
//! [`PERCH_ROUTER_PATHS`] lists mounted routes only. It grows in the same commit as
//! the handler it names, and `tests::perch_paths_are_disjoint_from_the_containment_router`
//! asserts its exact length after every change; no future path is predeclared.

mod feedback;
pub mod holds;
mod incidents;
mod reviewed;
#[cfg(test)]
mod tests;

use super::auth::{
    OperatorAuthState, require_bearer_auth, require_supported_operator_api_schema_version,
};
use super::error::OperatorApiError;
use super::state::{OperatorHttpError, OperatorRequestGuardState};
use axum::{
    Router, middleware,
    routing::{get, post},
};
use swarm_core::config::SwarmConfig;
use swarm_core::http_rate_limit::HttpRateLimiter;
use swarm_ingest_runtime::ingest::IngestState;
use swarm_ingest_runtime::perch_ops::PerchOpsError;

/// State the perch routes run against: the daemon's live ingest state.
#[derive(Clone)]
pub(super) struct PerchHttpState {
    pub(super) ingest: IngestState,
}

/// The paths this router declares — mounted routes only — for the disjointness
/// test against the other operator router.
pub const PERCH_ROUTER_PATHS: [&str; 5] = [
    "/v1/response/holds",
    "/v1/response/holds/{hold_id}",
    "/v1/operator/findings/reviewed",
    "/v1/operator/findings/{finding_id}/feedback",
    "/v1/operator/incidents",
];

/// Build the perch operator router over the daemon's live [`IngestState`].
///
/// Fails when a configured bearer token env is missing, exactly as
/// `containment_operator_router` does, so a misconfigured operator surface is
/// reported rather than silently shipping a daemon without these routes.
pub fn perch_operator_router(
    config: &SwarmConfig,
    ingest: IngestState,
) -> Result<Router, OperatorHttpError> {
    let auth = OperatorAuthState::from_config(config)?;
    Ok(perch_operator_router_with_auth(config, ingest, auth))
}

/// The same router over a caller-supplied auth state; unit tests use it with an
/// in-memory bearer so no process-global env is touched.
#[cfg(test)]
pub(super) fn perch_operator_router_for_test(
    config: &SwarmConfig,
    ingest: IngestState,
    auth: OperatorAuthState,
) -> Router {
    perch_operator_router_with_auth(config, ingest, auth)
}

fn perch_operator_router_with_auth(
    config: &SwarmConfig,
    ingest: IngestState,
    auth: OperatorAuthState,
) -> Router {
    let rate_limiter = HttpRateLimiter::new("operator-perch", config.operator.rate_limit.clone());
    Router::new()
        .route(PERCH_ROUTER_PATHS[0], get(holds::hold_list_handler))
        .route(PERCH_ROUTER_PATHS[1], get(holds::hold_detail_handler))
        .route(
            PERCH_ROUTER_PATHS[2],
            get(reviewed::reviewed_findings_handler),
        )
        .route(
            PERCH_ROUTER_PATHS[3],
            post(feedback::finding_feedback_handler),
        )
        .route(
            PERCH_ROUTER_PATHS[4],
            post(incidents::mint_incident_handler),
        )
        .with_state(PerchHttpState { ingest })
        .layer(middleware::from_fn_with_state(
            OperatorRequestGuardState { auth, rate_limiter },
            require_bearer_auth,
        ))
        .layer(middleware::from_fn(
            require_supported_operator_api_schema_version,
        ))
}

/// Map an engine failure onto the operator API error body.
pub(super) fn map_perch_error(error: PerchOpsError) -> OperatorApiError {
    match error {
        PerchOpsError::NotFound(message) => OperatorApiError::not_found(message),
        PerchOpsError::BadRequest(message) => OperatorApiError::bad_request(message),
        PerchOpsError::Internal(message) => OperatorApiError::internal(message),
    }
}
