//! B3r — `GET /v1/operator/findings/reviewed`. `OperatorScope::Read`.

use super::super::auth::{AuthenticatedOperatorPrincipal, require_operator_api_scope};
use super::super::error::OperatorApiError;
use super::super::helpers::now_ms;
use super::{PerchHttpState, map_perch_error};
use axum::Json;
use axum::extract::{Extension, Query, State};
use serde::Deserialize;
use swarm_core::config::OperatorScope;
use swarm_ingest_runtime::perch_ops::reviewed::{ReviewedFindingsResponse, reviewed_findings};

/// Query of `GET /v1/operator/findings/reviewed`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReviewedQuery {
    /// Lower bound on `reviewed_at_ms`. Absent means the whole answerable window.
    since_ms: Option<i64>,
    /// Maximum reviewed findings to return; clamped to `1..=1000`, default 50.
    limit: Option<usize>,
}

pub(super) async fn reviewed_findings_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<PerchHttpState>,
    Query(query): Query<ReviewedQuery>,
) -> Result<Json<ReviewedFindingsResponse>, OperatorApiError> {
    require_operator_api_scope(&principal, OperatorScope::Read, "read")?;
    let limit = effective_limit(query.limit);
    reviewed_findings(&state.ingest, query.since_ms, limit, now_ms())
        .map(Json)
        .map_err(map_perch_error)
}

/// The published contract's default and cap for `limit`
/// (`docs/plans/ambush-ui/build/openapi/perch-operator-v1.yaml`, `ReviewLimit`: values above
/// 500 are capped; 00-DECISIONS W3-31 rules the OpenAPI over the plan's 50/1000).
pub(crate) const REVIEW_LIMIT_DEFAULT: usize = 200;
/// See [`REVIEW_LIMIT_DEFAULT`].
pub(crate) const REVIEW_LIMIT_MAX: usize = 500;

/// Resolve the caller's `limit` to the window size B3r reads: the contract default when
/// absent, never zero, never above the cap.
pub(crate) fn effective_limit(requested: Option<usize>) -> usize {
    requested
        .unwrap_or(REVIEW_LIMIT_DEFAULT)
        .clamp(1, REVIEW_LIMIT_MAX)
}

#[cfg(test)]
mod limit_tests {
    use super::*;

    #[test]
    fn limit_follows_the_published_contract() {
        assert_eq!(effective_limit(None), 200);
        assert_eq!(effective_limit(Some(0)), 1);
        assert_eq!(effective_limit(Some(10)), 10);
        assert_eq!(effective_limit(Some(500)), 500);
        assert_eq!(effective_limit(Some(9_999)), 500);
    }
}
