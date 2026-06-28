use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use swarm_spine::{FalsePositiveMeasurement, IncidentRecord};

const MAX_ALERT_TUNING_RECOMMENDATIONS: usize = 6;
const HOST_EXCLUSION_MIN_REVIEWED: usize = 2;
const HOST_EXCLUSION_MIN_FALSE_POSITIVE: usize = 2;
const HOST_EXCLUSION_MIN_RATE: f64 = 0.75;
const DETECTOR_THRESHOLD_MIN_REVIEWED: usize = 4;
const DETECTOR_THRESHOLD_MIN_FALSE_POSITIVE: usize = 2;
const DETECTOR_THRESHOLD_MIN_RATE: f64 = 0.50;
const DETECTOR_RULE_MIN_REVIEWED: usize = 3;
const DETECTOR_RULE_MIN_FALSE_POSITIVE: usize = 2;
const DETECTOR_RULE_MIN_RATE: f64 = 0.34;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertTuningRecommendationKind {
    HostExclusionReview,
    DetectorThresholdReview,
    DetectorRuleReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertTuningRecommendationPriority {
    High,
    Medium,
    Low,
}

impl AlertTuningRecommendationPriority {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertTuningRecommendation {
    pub kind: AlertTuningRecommendationKind,
    pub priority: AlertTuningRecommendationPriority,
    pub summary: String,
    pub next_step: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    pub reviewed_findings: usize,
    pub false_positive_findings: usize,
    pub false_positive_rate: f64,
    #[serde(default)]
    pub supporting_signals: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AlertTuningReport {
    pub reviewed_findings: usize,
    pub false_positive_findings: usize,
    pub recommendation_count: usize,
    #[serde(default)]
    pub recommendations: Vec<AlertTuningRecommendation>,
}

#[derive(Debug, Clone, Default)]
struct RecommendationCount {
    reviewed_findings: usize,
    false_positive_findings: usize,
    latest_feedback_at_ms: Option<i64>,
    false_positive_hosts: BTreeSet<String>,
}

pub fn build_alert_tuning_report(records: &[IncidentRecord]) -> AlertTuningReport {
    let measurements = dedupe_measurements(records);
    let reviewed_findings = measurements.len();
    let false_positive_findings = measurements
        .iter()
        .filter(|entry| entry.false_positive)
        .count();

    let mut detector_counts: BTreeMap<String, RecommendationCount> = BTreeMap::new();
    let mut detector_host_counts: BTreeMap<(String, String), RecommendationCount> = BTreeMap::new();

    for measurement in &measurements {
        let detector = detector_counts
            .entry(measurement.strategy_id.clone())
            .or_default();
        detector.reviewed_findings += 1;
        detector.latest_feedback_at_ms = max_optional_timestamp(
            detector.latest_feedback_at_ms,
            Some(measurement.reviewed_at_ms),
        );
        if measurement.false_positive {
            detector.false_positive_findings += 1;
            if let Some(host_id) = &measurement.host_id {
                detector.false_positive_hosts.insert(host_id.clone());
            }
        }

        if let Some(host_id) = &measurement.host_id {
            let detector_host = detector_host_counts
                .entry((measurement.strategy_id.clone(), host_id.clone()))
                .or_default();
            detector_host.reviewed_findings += 1;
            detector_host.latest_feedback_at_ms = max_optional_timestamp(
                detector_host.latest_feedback_at_ms,
                Some(measurement.reviewed_at_ms),
            );
            if measurement.false_positive {
                detector_host.false_positive_findings += 1;
                detector_host.false_positive_hosts.insert(host_id.clone());
            }
        }
    }

    let mut recommendations = Vec::new();
    for ((strategy_id, host_id), counts) in &detector_host_counts {
        let false_positive_rate = rate(counts.false_positive_findings, counts.reviewed_findings);
        if counts.reviewed_findings < HOST_EXCLUSION_MIN_REVIEWED
            || counts.false_positive_findings < HOST_EXCLUSION_MIN_FALSE_POSITIVE
            || false_positive_rate < HOST_EXCLUSION_MIN_RATE
        {
            continue;
        }
        recommendations.push(AlertTuningRecommendation {
            kind: AlertTuningRecommendationKind::HostExclusionReview,
            priority: if counts.false_positive_findings >= 3 || false_positive_rate >= 0.9 {
                AlertTuningRecommendationPriority::High
            } else {
                AlertTuningRecommendationPriority::Medium
            },
            summary: format!(
                "Review a scoped exclusion for host `{host_id}` on detector `{strategy_id}`."
            ),
            next_step: format!(
                "Validate whether `{host_id}` represents approved automation or admin activity and, if so, prefer a host-scoped exclusion for `{strategy_id}` instead of broad detector suppression."
            ),
            strategy_id: Some(strategy_id.clone()),
            host_id: Some(host_id.clone()),
            reviewed_findings: counts.reviewed_findings,
            false_positive_findings: counts.false_positive_findings,
            false_positive_rate,
            supporting_signals: vec![
                format!(
                    "{} of {} recent reviewed findings for `{}` on `{}` were dismissed as false positives.",
                    counts.false_positive_findings,
                    counts.reviewed_findings,
                    strategy_id,
                    host_id
                ),
                "The noise is localized to one detector-host slice, so a scoped exclusion is safer than a global threshold change.".to_string(),
            ],
        });
    }

    let mut threshold_reviewed = BTreeSet::new();
    for (strategy_id, counts) in &detector_counts {
        let false_positive_rate = rate(counts.false_positive_findings, counts.reviewed_findings);
        let distinct_false_positive_hosts = counts.false_positive_hosts.len();
        if counts.reviewed_findings >= DETECTOR_THRESHOLD_MIN_REVIEWED
            && counts.false_positive_findings >= DETECTOR_THRESHOLD_MIN_FALSE_POSITIVE
            && false_positive_rate >= DETECTOR_THRESHOLD_MIN_RATE
            && distinct_false_positive_hosts >= 2
        {
            threshold_reviewed.insert(strategy_id.clone());
            recommendations.push(AlertTuningRecommendation {
                kind: AlertTuningRecommendationKind::DetectorThresholdReview,
                priority: if false_positive_rate >= 0.75
                    || counts.false_positive_findings >= 4
                {
                    AlertTuningRecommendationPriority::High
                } else {
                    AlertTuningRecommendationPriority::Medium
                },
                summary: format!("Review detector thresholding for `{strategy_id}`."),
                next_step: format!(
                    "Re-evaluate the confidence, suppression, or correlation thresholds for `{strategy_id}` before broadening host-specific exclusions."
                ),
                strategy_id: Some(strategy_id.clone()),
                host_id: None,
                reviewed_findings: counts.reviewed_findings,
                false_positive_findings: counts.false_positive_findings,
                false_positive_rate,
                supporting_signals: vec![
                    format!(
                        "{} of {} recent reviewed findings for `{}` were dismissed as false positives.",
                        counts.false_positive_findings,
                        counts.reviewed_findings,
                        strategy_id
                    ),
                    format!(
                        "Recent false positives for `{}` spanned {} host(s), which points to detector sensitivity rather than one local exception.",
                        strategy_id, distinct_false_positive_hosts
                    ),
                ],
            });
        }
    }

    for (strategy_id, counts) in &detector_counts {
        if threshold_reviewed.contains(strategy_id) {
            continue;
        }
        let false_positive_rate = rate(counts.false_positive_findings, counts.reviewed_findings);
        if counts.reviewed_findings < DETECTOR_RULE_MIN_REVIEWED
            || counts.false_positive_findings < DETECTOR_RULE_MIN_FALSE_POSITIVE
            || false_positive_rate < DETECTOR_RULE_MIN_RATE
        {
            continue;
        }
        recommendations.push(AlertTuningRecommendation {
            kind: AlertTuningRecommendationKind::DetectorRuleReview,
            priority: AlertTuningRecommendationPriority::Low,
            summary: format!("Inspect detector rule logic for `{strategy_id}` before wider rollout."),
            next_step: format!(
                "Review the evidence predicates, environmental filters, or suppression logic for `{strategy_id}` and compare them against the recent dismissed findings."
            ),
            strategy_id: Some(strategy_id.clone()),
            host_id: None,
            reviewed_findings: counts.reviewed_findings,
            false_positive_findings: counts.false_positive_findings,
            false_positive_rate,
            supporting_signals: vec![
                format!(
                    "{} of {} recent reviewed findings for `{}` were dismissed as false positives.",
                    counts.false_positive_findings,
                    counts.reviewed_findings,
                    strategy_id
                ),
                "The sample is large enough to justify targeted rule inspection, but not yet broad enough for an automatic threshold-wide recommendation.".to_string(),
            ],
        });
    }

    recommendations.sort_by(compare_recommendations);
    recommendations.truncate(MAX_ALERT_TUNING_RECOMMENDATIONS);

    AlertTuningReport {
        reviewed_findings,
        false_positive_findings,
        recommendation_count: recommendations.len(),
        recommendations,
    }
}

fn dedupe_measurements(records: &[IncidentRecord]) -> Vec<FalsePositiveMeasurement> {
    let mut by_finding: BTreeMap<String, FalsePositiveMeasurement> = BTreeMap::new();
    for record in records {
        for measurement in &record.false_positive_measurements {
            let replace = by_finding
                .get(&measurement.finding_id)
                .is_none_or(|current| measurement.reviewed_at_ms >= current.reviewed_at_ms);
            if replace {
                by_finding.insert(measurement.finding_id.clone(), measurement.clone());
            }
        }
    }
    by_finding.into_values().collect()
}

fn compare_recommendations(
    left: &AlertTuningRecommendation,
    right: &AlertTuningRecommendation,
) -> Ordering {
    right
        .priority
        .rank()
        .cmp(&left.priority.rank())
        .then_with(|| {
            right
                .false_positive_findings
                .cmp(&left.false_positive_findings)
        })
        .then_with(|| {
            right
                .false_positive_rate
                .partial_cmp(&left.false_positive_rate)
                .unwrap_or(Ordering::Equal)
        })
        .then_with(|| right.reviewed_findings.cmp(&left.reviewed_findings))
        .then_with(|| left.summary.cmp(&right.summary))
}

fn rate(false_positive_findings: usize, reviewed_findings: usize) -> f64 {
    if reviewed_findings == 0 {
        0.0
    } else {
        false_positive_findings as f64 / reviewed_findings as f64
    }
}

fn max_optional_timestamp(current: Option<i64>, candidate: Option<i64>) -> Option<i64> {
    match (current, candidate) {
        (Some(current), Some(candidate)) => Some(current.max(candidate)),
        (Some(current), None) => Some(current),
        (None, Some(candidate)) => Some(candidate),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AlertTuningRecommendationKind, AlertTuningRecommendationPriority, build_alert_tuning_report,
    };
    use swarm_core::ThreatClass;
    use swarm_core::types::{ProvidenceFeedbackAction, Severity};
    use swarm_spine::{FalsePositiveMeasurement, IncidentRecord};

    fn incident_record(
        incident_id: &str,
        created_at_ms: i64,
        measurements: Vec<FalsePositiveMeasurement>,
    ) -> IncidentRecord {
        IncidentRecord {
            incident_id: incident_id.to_string(),
            summary: format!("incident {incident_id}"),
            created_at_ms,
            included_hunt_ids: measurements
                .iter()
                .map(|measurement| measurement.hunt_id.clone())
                .collect(),
            included_investigation_ids: Vec::new(),
            related_receipt_ids: Vec::new(),
            correlation_keys: Vec::new(),
            bundle_path: "memory".to_string(),
            graph_dimensions: Vec::new(),
            confidence_score: 1.0,
            trigger_event_id: None,
            trigger_finding_id: None,
            trigger_strategy_id: None,
            threat_class: Some(ThreatClass::Execution),
            severity: Some(Severity::High),
            external_references: Vec::new(),
            providence_reconciliation: None,
            providence_callback_audit_entries: Vec::new(),
            feedback_audit_entries: Vec::new(),
            false_positive_measurements: measurements,
        }
    }

    fn measurement(
        finding_id: &str,
        hunt_id: &str,
        strategy_id: &str,
        host_id: &str,
        action: ProvidenceFeedbackAction,
        reviewed_at_ms: i64,
    ) -> FalsePositiveMeasurement {
        FalsePositiveMeasurement {
            finding_id: finding_id.to_string(),
            hunt_id: hunt_id.to_string(),
            strategy_id: strategy_id.to_string(),
            host_id: Some(host_id.to_string()),
            feedback_id: format!("feedback:{finding_id}"),
            reviewed_at_ms,
            analyst_id: "analyst-test".to_string(),
            action,
            reason: Some("fixture".to_string()),
            false_positive: matches!(action, ProvidenceFeedbackAction::Dismiss),
        }
    }

    #[test]
    fn emits_host_exclusion_review_for_repeated_localized_false_positives() {
        let records = vec![
            incident_record(
                "incident-1",
                1_700_000_000_000,
                vec![measurement(
                    "finding-1",
                    "hunt-1",
                    "suspicious_process_tree",
                    "host-a",
                    ProvidenceFeedbackAction::Dismiss,
                    1_700_000_000_010,
                )],
            ),
            incident_record(
                "incident-2",
                1_700_000_000_100,
                vec![measurement(
                    "finding-2",
                    "hunt-2",
                    "suspicious_process_tree",
                    "host-a",
                    ProvidenceFeedbackAction::Dismiss,
                    1_700_000_000_110,
                )],
            ),
            incident_record(
                "incident-3",
                1_700_000_000_200,
                vec![measurement(
                    "finding-3",
                    "hunt-3",
                    "suspicious_process_tree",
                    "host-b",
                    ProvidenceFeedbackAction::Confirm,
                    1_700_000_000_210,
                )],
            ),
        ];

        let report = build_alert_tuning_report(&records);
        let recommendation = report
            .recommendations
            .iter()
            .find(|entry| {
                entry.kind == AlertTuningRecommendationKind::HostExclusionReview
                    && entry.host_id.as_deref() == Some("host-a")
            })
            .unwrap();
        assert_eq!(
            recommendation.priority,
            AlertTuningRecommendationPriority::High
        );
        assert_eq!(recommendation.reviewed_findings, 2);
        assert_eq!(recommendation.false_positive_findings, 2);
    }

    #[test]
    fn emits_detector_threshold_review_when_false_positives_span_hosts() {
        let records = vec![
            incident_record(
                "incident-1",
                1_700_000_001_000,
                vec![measurement(
                    "finding-1",
                    "hunt-1",
                    "suspicious_process_tree",
                    "host-a",
                    ProvidenceFeedbackAction::Dismiss,
                    1_700_000_001_010,
                )],
            ),
            incident_record(
                "incident-2",
                1_700_000_001_100,
                vec![measurement(
                    "finding-2",
                    "hunt-2",
                    "suspicious_process_tree",
                    "host-b",
                    ProvidenceFeedbackAction::Dismiss,
                    1_700_000_001_110,
                )],
            ),
            incident_record(
                "incident-3",
                1_700_000_001_200,
                vec![measurement(
                    "finding-3",
                    "hunt-3",
                    "suspicious_process_tree",
                    "host-c",
                    ProvidenceFeedbackAction::Dismiss,
                    1_700_000_001_210,
                )],
            ),
            incident_record(
                "incident-4",
                1_700_000_001_300,
                vec![measurement(
                    "finding-4",
                    "hunt-4",
                    "suspicious_process_tree",
                    "host-d",
                    ProvidenceFeedbackAction::Confirm,
                    1_700_000_001_310,
                )],
            ),
            incident_record(
                "incident-5",
                1_700_000_001_400,
                vec![measurement(
                    "finding-5",
                    "hunt-5",
                    "suspicious_process_tree",
                    "host-e",
                    ProvidenceFeedbackAction::Confirm,
                    1_700_000_001_410,
                )],
            ),
        ];

        let report = build_alert_tuning_report(&records);
        let recommendation = report
            .recommendations
            .iter()
            .find(|entry| {
                entry.kind == AlertTuningRecommendationKind::DetectorThresholdReview
                    && entry.strategy_id.as_deref() == Some("suspicious_process_tree")
            })
            .unwrap();
        assert_eq!(
            recommendation.priority,
            AlertTuningRecommendationPriority::Medium
        );
        assert_eq!(recommendation.reviewed_findings, 5);
        assert_eq!(recommendation.false_positive_findings, 3);
    }
}
