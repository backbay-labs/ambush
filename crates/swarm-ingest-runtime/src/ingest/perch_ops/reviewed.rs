//! B3r — the engine half of `GET /v1/operator/findings/reviewed`.
//!
//! Walks `incident_store.recent(window)` and flattens every
//! `false_positive_measurements` entry — the same source
//! `build_alert_tuning_report` reads — and reports the window honestly
//! (12-BACKEND-BILL-API.md §10, commitment C8): a `since_ms` older than the
//! oldest incident in the window is unanswerable, and the response says so
//! rather than returning a short list that renders as a quiet week.

use super::super::IngestState;
use super::PerchOpsError;
use serde::{Deserialize, Serialize};
use swarm_core::config::BundleStoreConfig;
use swarm_core::types::ProvidenceFeedbackAction;
use swarm_spine::IncidentStore;

/// One reviewed finding: a `FalsePositiveMeasurement` flattened with the
/// incident it is attached to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewedFinding {
    /// The finding the verdict was recorded on.
    pub finding_id: String,
    /// When the verdict was recorded (unix ms).
    pub reviewed_at_ms: i64,
    /// The recorded action; only `dismiss` sets `false_positive`.
    pub action: ProvidenceFeedbackAction,
    /// Who recorded it — the authenticated `operator_id` on the B3 path.
    pub analyst_id: String,
    /// True only for `dismiss`; `confirm` and `investigate` still move the
    /// `reviewed_findings` denominator.
    pub false_positive: bool,
    /// The incident carrying the measurement.
    pub incident_id: String,
    /// The detector the measurement is attributed to.
    pub strategy_id: String,
    /// The host, when one was resolvable from the incident's keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
}

/// Response of `GET /v1/operator/findings/reviewed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewedFindingsResponse {
    /// Response schema version; `1`.
    pub schema_version: u32,
    /// The instant the window was read at (unix ms).
    pub observed_at_ms: i64,
    /// Reviewed findings, `reviewed_at_ms` descending then `finding_id`
    /// ascending, truncated to the requested limit.
    pub reviewed: Vec<ReviewedFinding>,
    /// How many incidents `incident_store.recent(window)` returned.
    pub window_incident_count: usize,
    /// True when the store filled the window exactly, so older measurements
    /// exist that this route cannot see.
    pub window_is_truncated: bool,
    /// `created_at_ms` of the oldest incident in the window; `None` when the
    /// window is empty.
    pub window_oldest_incident_at_ms: Option<i64>,
    /// False when the incident store is in-memory, in which case a daemon
    /// restart destroys every measurement ever written.
    pub store_durable: bool,
}

/// Flatten the measurements inside the daemon's recent-incident window.
///
/// `window = max(limit, audit.recent_decisions_limit)`, so raising the config
/// value later widens this route with no code change. `since_ms` filters on
/// `reviewed_at_ms`; the window fields are reported regardless of the filter.
pub fn reviewed_findings(
    state: &IngestState,
    since_ms: Option<i64>,
    limit: usize,
    now_ms: i64,
) -> Result<ReviewedFindingsResponse, PerchOpsError> {
    let stack = state.stack.load_full();
    let config = &stack.service.config;
    let window = limit.max(config.audit.recent_decisions_limit);
    let records = state.current_incident_store().recent(window)?;
    let window_incident_count = records.len();
    let window_is_truncated = window_incident_count >= window;
    let window_oldest_incident_at_ms = records.iter().map(|record| record.created_at_ms).min();
    let mut reviewed: Vec<ReviewedFinding> = records
        .iter()
        .flat_map(|record| {
            record
                .false_positive_measurements
                .iter()
                .map(move |measurement| ReviewedFinding {
                    finding_id: measurement.finding_id.clone(),
                    reviewed_at_ms: measurement.reviewed_at_ms,
                    action: measurement.action,
                    analyst_id: measurement.analyst_id.clone(),
                    false_positive: measurement.false_positive,
                    incident_id: record.incident_id.clone(),
                    strategy_id: measurement.strategy_id.clone(),
                    host_id: measurement.host_id.clone(),
                })
        })
        .filter(|finding| since_ms.is_none_or(|since| finding.reviewed_at_ms >= since))
        .collect();
    // The order `upsert_false_positive_measurement` imposes within one incident,
    // applied across incidents: reviewed_at_ms DESC, finding_id ASC.
    reviewed.sort_by(|left, right| {
        right
            .reviewed_at_ms
            .cmp(&left.reviewed_at_ms)
            .then_with(|| left.finding_id.cmp(&right.finding_id))
    });
    reviewed.truncate(limit);
    Ok(ReviewedFindingsResponse {
        schema_version: 1,
        observed_at_ms: now_ms,
        reviewed,
        window_incident_count,
        window_is_truncated,
        window_oldest_incident_at_ms,
        store_durable: !matches!(config.correlation.incident_store, BundleStoreConfig::Memory),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::super::test_support::{perch_incident, test_state};
    use super::reviewed_findings;
    use swarm_core::types::ProvidenceFeedbackAction;
    use swarm_spine::{FalsePositiveMeasurement, IncidentStore};

    #[test]
    fn reviewed_findings_flatten_measurements_and_report_the_window() {
        let state = test_state();
        let store = state.current_incident_store();
        let mut incident = perch_incident("hunt-1", "f-1", 1_000);
        incident.upsert_false_positive_measurement(FalsePositiveMeasurement {
            finding_id: "f-1".into(),
            hunt_id: "hunt-1".into(),
            strategy_id: "suspicious_process_tree".into(),
            host_id: Some("host-ops-1".into()),
            feedback_id: "perch-feedback:f-1:aa".into(),
            reviewed_at_ms: 5_000,
            analyst_id: "ops".into(),
            action: ProvidenceFeedbackAction::Dismiss,
            reason: None,
            soar_lineage: None,
            false_positive: true,
        });
        store.persist(&incident).unwrap();

        let out = reviewed_findings(&state, None, 50, 9_000).unwrap();
        assert_eq!(out.schema_version, 1);
        assert_eq!(out.observed_at_ms, 9_000);
        assert_eq!(out.reviewed.len(), 1);
        assert_eq!(out.reviewed[0].finding_id, "f-1");
        assert_eq!(out.reviewed[0].strategy_id, "suspicious_process_tree");
        assert_eq!(out.reviewed[0].host_id.as_deref(), Some("host-ops-1"));
        assert_eq!(out.reviewed[0].incident_id, incident.incident_id);
        assert_eq!(out.reviewed[0].analyst_id, "ops");
        assert_eq!(out.reviewed[0].reviewed_at_ms, 5_000);
        assert!(out.reviewed[0].false_positive);
        assert_eq!(out.window_incident_count, 1);
        assert!(!out.window_is_truncated);
        assert_eq!(out.window_oldest_incident_at_ms, Some(1_000));
        assert!(
            !out.store_durable,
            "the test config's incident store is Memory"
        );

        let none = reviewed_findings(&state, Some(6_000), 50, 9_000).unwrap();
        assert!(
            none.reviewed.is_empty(),
            "since_ms filters on reviewed_at_ms"
        );
        assert_eq!(
            none.window_incident_count, 1,
            "the window is reported even when the filter empties the list"
        );
    }

    #[test]
    fn reviewed_findings_order_newest_first_and_truncate_to_the_limit() {
        let state = test_state();
        let store = state.current_incident_store();
        for (index, finding) in ["f-b", "f-a", "f-c"].iter().enumerate() {
            let created_at_ms = 1_000 + index as i64;
            let mut incident = perch_incident(&format!("hunt-{index}"), finding, created_at_ms);
            incident.upsert_false_positive_measurement(FalsePositiveMeasurement {
                finding_id: (*finding).into(),
                hunt_id: format!("hunt-{index}"),
                strategy_id: "suspicious_process_tree".into(),
                host_id: None,
                feedback_id: format!("perch-feedback:{finding}:aa"),
                // f-b and f-a share an instant; f-c is newest.
                reviewed_at_ms: if *finding == "f-c" { 7_000 } else { 5_000 },
                analyst_id: "ops".into(),
                action: ProvidenceFeedbackAction::Confirm,
                reason: None,
                soar_lineage: None,
                false_positive: false,
            });
            store.persist(&incident).unwrap();
        }

        let out = reviewed_findings(&state, None, 2, 9_000).unwrap();
        let ids: Vec<&str> = out.reviewed.iter().map(|r| r.finding_id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["f-c", "f-a"],
            "reviewed_at_ms DESC, then finding_id ASC, then truncated to `limit`"
        );
        assert_eq!(out.window_incident_count, 3);
        assert_eq!(out.window_oldest_incident_at_ms, Some(1_000));
        assert!(
            !out.window_is_truncated,
            "three incidents inside a window of max(limit, recent_decisions_limit) = 20"
        );
    }

    #[test]
    fn the_window_is_reported_truncated_when_the_store_fills_it() {
        let state = test_state();
        let store = state.current_incident_store();
        // recent_decisions_limit is 20 in the test config; a limit of 1 keeps the
        // window at 20, so 20 incidents fill it exactly and the flag must say so.
        for index in 0..20_i64 {
            store
                .persist(&perch_incident(
                    &format!("hunt-{index}"),
                    "f",
                    1_000 + index,
                ))
                .unwrap();
        }
        let out = reviewed_findings(&state, None, 1, 9_000).unwrap();
        assert_eq!(out.window_incident_count, 20);
        assert!(out.window_is_truncated);
        assert_eq!(out.window_oldest_incident_at_ms, Some(1_000));
    }
}
