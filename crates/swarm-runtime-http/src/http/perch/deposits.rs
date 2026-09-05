//! `GET /v1/operator/pheromone/deposits` — B4.
//!
//! NOT a pass-through of `query_deposits`. The console shows a concentration
//! number and the rows behind it; both come from one reduction, so the total
//! and the list cannot disagree. The engine op owns that reduction and this
//! module only shapes it for the wire.

use axum::Json;
use axum::extract::{Extension, Query, State};
use serde::{Deserialize, Serialize};
use swarm_core::agent::AgentRole;
use swarm_core::config::OperatorScope;
use swarm_core::pheromone::{
    PheromoneConcentration, PheromoneDeposit, ThreatClass, ThreatClassPolicy,
};
use swarm_core::types::Severity;
use swarm_ingest_runtime::control::CURRENT_OPERATOR_API_SCHEMA_VERSION;
use swarm_ingest_runtime::ingest::perch_ops::deposits::{
    PERCH_DEPOSITS_MAX_LIMIT, PerchDepositsError, PerchDepositsQuery, read_deposits,
};
use swarm_pheromone::PerchSuppressionRecord;

use super::PerchHttpState;
use crate::http::auth::{AuthenticatedOperatorPrincipal, require_operator_api_scope};
use crate::http::error::OperatorApiError;

/// Query of `GET /v1/operator/pheromone/deposits`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepositsQuery {
    /// Required. Concentration is per class, so there is no "all classes" read.
    pub threat_class: Option<ThreatClass>,
    pub since_seconds: Option<i64>,
    pub host_id: Option<String>,
    /// 1..=1000, default 500. `0` is refused here: on `DepositQuery` it means
    /// UNLIMITED, and a route that quietly served everything on a typo would be
    /// a denial of service against the renderer.
    pub limit: Option<usize>,
    /// Unix SECONDS. Absent means now.
    pub now_seconds: Option<i64>,
}

/// `PheromoneDeposit` minus its byte arrays, plus the strength it contributes.
///
/// The signature and the agent key are deliberately absent: they are the
/// substrate's admission evidence, not the console's, and shipping them would
/// invite a client to re-verify with a rule of its own.
#[derive(Debug, Clone, Serialize)]
pub struct PheromoneDepositView {
    pub event_id: String,
    pub threat_class: ThreatClass,
    pub severity: Severity,
    pub confidence: f64,
    pub timestamp: i64,
    pub decay_half_life: f64,
    pub agent_id: String,
    pub agent_role: Option<AgentRole>,
    pub agent_identity: String,
    pub host_id: Option<String>,
    pub strategy_id: Option<String>,
    /// What this row contributes to `concentration.total_strength` at
    /// `now_seconds`, so the console never recomputes decay itself.
    pub strength_at_now: f64,
}

impl PheromoneDepositView {
    fn from_deposit(deposit: &PheromoneDeposit, now_seconds: i64) -> Self {
        let host_id = deposit
            .indicator
            .get("host_id")
            .and_then(serde_json::Value::as_str)
            .or_else(|| {
                deposit
                    .indicator
                    .pointer("/evidence/host_metadata/host_id")
                    .and_then(serde_json::Value::as_str)
            })
            .map(str::to_string);
        // The strategy is the segment after the LAST colon of a scoped id; the
        // agent half keeps its own colons (`swarm:ed25519:…`).
        let strategy_id = deposit
            .agent_id
            .0
            .rfind(':')
            .map(|cut| deposit.agent_id.0[cut + 1..].to_string());
        Self {
            event_id: deposit
                .indicator
                .get("event_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
            threat_class: deposit.threat_class.clone(),
            severity: deposit.severity,
            confidence: deposit.confidence,
            timestamp: deposit.timestamp,
            decay_half_life: deposit.decay_half_life,
            agent_id: deposit.agent_id.0.clone(),
            agent_role: deposit.agent_role,
            agent_identity: deposit.agent_identity.clone(),
            host_id,
            strategy_id,
            strength_at_now: deposit.strength_at(now_seconds),
        }
    }
}

/// Response of `GET /v1/operator/pheromone/deposits`.
#[derive(Debug, Clone, Serialize)]
pub struct DepositsResponse {
    pub schema_version: u32,
    pub now_seconds: i64,
    pub threat_class: ThreatClass,
    pub policy: ThreatClassPolicy,
    /// Of the WHOLE class, not of `deposits`, which honours the query filters.
    pub concentration: PheromoneConcentration,
    pub deposits: Vec<PheromoneDepositView>,
    pub suppressed: Vec<PerchSuppressionRecord>,
    pub source_ids: Vec<String>,
    pub distinct_agents: usize,
    pub unscoped_source_ids: Vec<String>,
    /// True when the slice was cut by `limit`. The counts above are unaffected.
    pub truncated: bool,
}

pub(super) async fn deposit_list_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<PerchHttpState>,
    Query(query): Query<DepositsQuery>,
) -> Result<Json<DepositsResponse>, OperatorApiError> {
    require_operator_api_scope(&principal, OperatorScope::Read, "read")?;
    let threat_class = query.threat_class.ok_or_else(|| {
        OperatorApiError::bad_request("threat_class is required; concentration is per class")
    })?;
    let limit = query.limit.unwrap_or(500);
    if limit == 0 || limit > PERCH_DEPOSITS_MAX_LIMIT {
        return Err(OperatorApiError::bad_request(format!(
            "limit must be between 1 and {PERCH_DEPOSITS_MAX_LIMIT}; 0 is not unlimited on this route"
        )));
    }
    let read = read_deposits(
        &state.ingest,
        PerchDepositsQuery {
            threat_class,
            since_seconds: query.since_seconds,
            host_id: query.host_id,
            limit,
            now_seconds: query.now_seconds,
        },
    )
    .await
    .map_err(|error| match error {
        PerchDepositsError::InvalidLimit(_) => OperatorApiError::bad_request(error.to_string()),
        PerchDepositsError::Substrate(inner) => OperatorApiError::internal(inner.to_string()),
    })?;
    let now_seconds = read.now_seconds;
    Ok(Json(DepositsResponse {
        schema_version: CURRENT_OPERATOR_API_SCHEMA_VERSION,
        now_seconds,
        threat_class: read.threat_class,
        policy: read.policy,
        concentration: read.concentration,
        deposits: read
            .deposits
            .iter()
            .map(|deposit| PheromoneDepositView::from_deposit(deposit, now_seconds))
            .collect(),
        suppressed: read.suppressed,
        source_ids: read.source_ids,
        distinct_agents: read.distinct_agents,
        unscoped_source_ids: read.unscoped_source_ids,
        truncated: read.truncated,
    }))
}
