//! B4 — the class slice the operator console reads.
//!
//! The console shows a concentration number and the rows behind it. Both come
//! from one reduction (`swarm_pheromone::perch_deposit_slice`), because a list
//! selected by a filter written separately from the sum would drift and the
//! surface whose whole job is to be trustworthy would show a total its own
//! rows do not add up to.
//!
//! The COUNTS are of the whole class. The `deposits` array honours the
//! caller's `since`/`host` filters. A client that summed the array and
//! compared it to `concentration.total_strength` would be comparing two
//! different questions, so the two are named separately in the response.

use swarm_core::pheromone::{
    PheromoneConcentration, PheromoneDeposit, ThreatClass, ThreatClassPolicy,
};
use swarm_pheromone::{
    DepositQuery, PerchSuppressionRecord, PheromoneSubstrate, SubstrateError, perch_deposit_slice,
};

use crate::ingest::IngestState;

/// The largest slice the route will serve. An unbounded slice on a wall screen
/// is a denial of service against the renderer.
pub const PERCH_DEPOSITS_MAX_LIMIT: usize = 1_000;

/// The query, already validated by the HTTP layer except for `limit`, which is
/// checked here so the engine op refuses `0` even when called from a test.
#[derive(Debug, Clone)]
pub struct PerchDepositsQuery {
    pub threat_class: ThreatClass,
    pub since_seconds: Option<i64>,
    pub host_id: Option<String>,
    pub limit: usize,
    pub now_seconds: Option<i64>,
}

/// What the route serializes. Field names match the OpenAPI document.
#[derive(Debug, Clone)]
pub struct PerchDepositsRead {
    pub now_seconds: i64,
    pub threat_class: ThreatClass,
    pub policy: ThreatClassPolicy,
    pub concentration: PheromoneConcentration,
    pub deposits: Vec<PheromoneDeposit>,
    pub suppressed: Vec<PerchSuppressionRecord>,
    pub source_ids: Vec<String>,
    pub distinct_agents: usize,
    pub unscoped_source_ids: Vec<String>,
    pub truncated: bool,
}

/// Why a deposits read failed.
#[derive(Debug, thiserror::Error)]
pub enum PerchDepositsError {
    /// The caller asked for nothing, or for more than the renderer can take.
    #[error("limit must be between 1 and {PERCH_DEPOSITS_MAX_LIMIT}; got {0}")]
    InvalidLimit(usize),
    /// The substrate could not answer.
    #[error("substrate: {0}")]
    Substrate(#[from] SubstrateError),
}

/// The M in "N sources / M agents", computed here so two clients cannot derive
/// it two ways.
///
/// A source id is `{agent}:{strategy}`. Split once from the RIGHT, because an
/// agent id contains colons of its own (`swarm:ed25519:…`). An id with no colon
/// never came through `resolve_deposits`; it is its own agent and is also
/// reported by name, so a caller can see which ids the split did not apply to
/// rather than reading a count that quietly folded them in.
#[must_use]
pub fn distinct_agents(source_ids: &[String]) -> (usize, Vec<String>) {
    let mut agents = std::collections::BTreeSet::new();
    let mut unscoped = Vec::new();
    for id in source_ids {
        match id.rfind(':') {
            Some(cut) => {
                agents.insert(&id[..cut]);
            }
            None => {
                agents.insert(id.as_str());
                unscoped.push(id.clone());
            }
        }
    }
    (agents.len(), unscoped)
}

/// Read the class slice the way the monitor reads it, and serve the number the
/// substrate itself computes beside it.
///
/// # Errors
///
/// [`PerchDepositsError::InvalidLimit`] when `limit` is 0 or above
/// [`PERCH_DEPOSITS_MAX_LIMIT`]; [`PerchDepositsError::Substrate`] when the
/// substrate cannot answer.
pub async fn read_deposits(
    state: &IngestState,
    query: PerchDepositsQuery,
) -> Result<PerchDepositsRead, PerchDepositsError> {
    if query.limit == 0 || query.limit > PERCH_DEPOSITS_MAX_LIMIT {
        return Err(PerchDepositsError::InvalidLimit(query.limit));
    }
    let now_seconds = query
        .now_seconds
        .unwrap_or_else(|| swarm_runtime::runtime_events::now_ms().div_euclid(1_000));
    let substrate = state.current_substrate();
    let pheromone = state.current_pheromone_config();
    let override_config = substrate
        .query_threat_class_config(&query.threat_class)
        .await?;
    let policy = pheromone.resolve_threat_class_policy(override_config.as_ref());

    // The whole class, suppressed rows included, so the slice can name what left.
    let raw = substrate
        .query_deposits(DepositQuery {
            threat_class: Some(query.threat_class.clone()),
            since_timestamp: None,
            host_id: None,
            limit: 0,
            include_suppressed: true,
        })
        .await?;
    let slice = perch_deposit_slice(&raw, &query.threat_class, now_seconds, &policy);
    let concentration = substrate
        .query_concentration(&query.threat_class, now_seconds)
        .await?;
    let (distinct_agents, unscoped_source_ids) = distinct_agents(&slice.source_ids);

    // The `deposits` array honours the caller's filters; the counts above do not.
    let mut deposits: Vec<PheromoneDeposit> = slice
        .kept
        .into_iter()
        .filter(|deposit| {
            query
                .since_seconds
                .is_none_or(|since| deposit.timestamp >= since)
        })
        .filter(|deposit| {
            query.host_id.as_deref().is_none_or(|host| {
                deposit
                    .indicator
                    .get("host_id")
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| {
                        deposit
                            .indicator
                            .pointer("/evidence/host_metadata/host_id")
                            .and_then(serde_json::Value::as_str)
                    })
                    == Some(host)
            })
        })
        .collect();
    // Newest first, ties broken by event id so two reads of one substrate agree.
    deposits.sort_by(|a, b| {
        b.timestamp.cmp(&a.timestamp).then_with(|| {
            let ea = a
                .indicator
                .get("event_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let eb = b
                .indicator
                .get("event_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            ea.cmp(eb)
        })
    });
    let truncated = deposits.len() > query.limit;
    deposits.truncate(query.limit);

    Ok(PerchDepositsRead {
        now_seconds,
        threat_class: query.threat_class,
        policy,
        concentration,
        deposits,
        suppressed: slice.suppressed,
        source_ids: slice.source_ids,
        distinct_agents,
        unscoped_source_ids,
        truncated,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use swarm_core::pheromone::ThreatClass;

    /// The number the console shows and the rows it lists are one reduction.
    #[tokio::test]
    async fn read_deposits_serves_the_concentration_the_monitor_acts_on() {
        let state = super::super::test_support::ingest_state_with_in_memory_substrate();
        let now = 1_773_739_125;
        super::super::test_support::seed_execution_scenario(&state, now).await;

        let read = read_deposits(
            &state,
            PerchDepositsQuery {
                threat_class: ThreatClass::Execution,
                since_seconds: None,
                host_id: None,
                limit: 500,
                now_seconds: Some(now),
            },
        )
        .await
        .unwrap();

        let served = state
            .current_substrate()
            .query_concentration(&ThreatClass::Execution, now)
            .await
            .unwrap();
        assert_eq!(read.concentration.total_strength, served.total_strength);
        assert_eq!(read.source_ids.len(), served.distinct_sources);
        assert_eq!(read.distinct_agents, 1, "one agent, two strategies");
        assert!(read.unscoped_source_ids.is_empty());
        assert!(!read.truncated);
        assert_eq!(read.now_seconds, now);
    }

    /// A cut slice says it was cut, and the counts stay counts of the class.
    #[tokio::test]
    async fn a_limit_of_zero_is_refused_and_a_cut_slice_says_so() {
        let state = super::super::test_support::ingest_state_with_in_memory_substrate();
        super::super::test_support::seed_execution_scenario(&state, 1_773_739_125).await;

        let zero = read_deposits(
            &state,
            PerchDepositsQuery {
                threat_class: ThreatClass::Execution,
                since_seconds: None,
                host_id: None,
                limit: 0,
                now_seconds: None,
            },
        )
        .await;
        assert!(matches!(zero, Err(PerchDepositsError::InvalidLimit(0))));

        let one = read_deposits(
            &state,
            PerchDepositsQuery {
                threat_class: ThreatClass::Execution,
                since_seconds: None,
                host_id: None,
                limit: 1,
                now_seconds: Some(1_773_739_125),
            },
        )
        .await
        .unwrap();
        assert_eq!(one.deposits.len(), 1);
        assert!(one.truncated);
        // `source_ids` is computed over the UNTRUNCATED class slice, so it still
        // equals `distinct_sources`. A truncation that changed the counts would
        // make the console's "N sources" depend on its own page size.
        assert_eq!(one.source_ids.len(), one.concentration.distinct_sources);
    }
}
