use super::metrics::{scenario_detected, scenario_is_benign, suite_metrics};
use super::types::{
    DetectorVerificationReport, PromotionReviewBlockingReason, ReplayScenarioClass,
    ReplaySuiteReport, StrategyShadowReport, VerificationCounterexample,
    VerificationInvariantResult, VerificationThreatClassTemplate,
};
use crate::detector_factory::RuntimeDetector;
use serde_json::json;
use swarm_whisker::DetectionStrategy;

pub(super) fn verify_known_bad_coverage(report: &ReplaySuiteReport) -> VerificationInvariantResult {
    let counterexamples = report
        .scenario_reports
        .iter()
        .filter(|scenario| {
            scenario.metadata.class == ReplayScenarioClass::Adversarial
                && !scenario_detected(scenario)
        })
        .map(|scenario| VerificationCounterexample {
            subject: scenario.scenario_name.clone(),
            reference: scenario.scenario_path.clone(),
            details: "expected at least one detection on adversarial coverage scenario".to_string(),
        })
        .collect::<Vec<_>>();
    let missed = counterexamples.len();
    VerificationInvariantResult {
        name: "known_bad_coverage".to_string(),
        passed: missed == 0,
        expected: json!(0),
        actual: json!(missed),
        details: if missed == 0 {
            "candidate preserved detection across all adversarial verification scenarios"
                .to_string()
        } else {
            "candidate missed one or more adversarial verification scenarios".to_string()
        },
        counterexamples,
    }
}

pub(super) fn verify_canonical_templates(
    detector: &RuntimeDetector,
    templates: &[VerificationThreatClassTemplate],
) -> VerificationInvariantResult {
    let counterexamples = templates
        .iter()
        .filter_map(|template| {
            let matches = detector.evaluate(&template.event);
            let matched = matches
                .iter()
                .any(|finding| finding.threat_class == template.threat_class);
            if matched {
                None
            } else {
                Some(VerificationCounterexample {
                    subject: template.name.clone(),
                    reference: template.event.event_id.clone(),
                    details: format!(
                        "expected threat_class {:?} but candidate emitted no matching finding",
                        template.threat_class
                    ),
                })
            }
        })
        .collect::<Vec<_>>();
    let missed = counterexamples.len();
    VerificationInvariantResult {
        name: "threat_class_templates".to_string(),
        passed: missed == 0,
        expected: json!(0),
        actual: json!(missed),
        details: if missed == 0 {
            "candidate matched every canonical threat-class template".to_string()
        } else {
            "candidate failed one or more canonical threat-class templates".to_string()
        },
        counterexamples,
    }
}

pub(super) fn verify_false_positive_bound(
    benign_report: &ReplaySuiteReport,
    max_false_positive_rate: f64,
) -> VerificationInvariantResult {
    let metrics = suite_metrics(benign_report);
    let counterexamples = benign_report
        .scenario_reports
        .iter()
        .filter(|scenario| scenario_is_benign(scenario) && scenario_detected(scenario))
        .map(|scenario| VerificationCounterexample {
            subject: scenario.scenario_name.clone(),
            reference: scenario.scenario_path.clone(),
            details: "candidate produced a detection on a benign control scenario".to_string(),
        })
        .collect::<Vec<_>>();
    VerificationInvariantResult {
        name: "false_positive_bound".to_string(),
        passed: metrics.false_positive_rate <= max_false_positive_rate,
        expected: json!(max_false_positive_rate),
        actual: json!(metrics.false_positive_rate),
        details: if metrics.false_positive_rate <= max_false_positive_rate {
            "candidate stayed within the verification false-positive bound".to_string()
        } else {
            "candidate exceeded the verification false-positive bound".to_string()
        },
        counterexamples,
    }
}

pub(super) fn verify_detect_latency_budget(
    reports: &[&ReplaySuiteReport],
    max_detect_latency_us: u64,
) -> VerificationInvariantResult {
    let mut worst_case = 0u64;
    let mut worst_reference = None::<VerificationCounterexample>;
    for report in reports {
        for scenario in &report.scenario_reports {
            let scenario_latency = scenario.evaluation.performance.detect.max_latency_us;
            if scenario_latency > worst_case {
                worst_case = scenario_latency;
                worst_reference = Some(VerificationCounterexample {
                    subject: scenario.scenario_name.clone(),
                    reference: scenario.scenario_path.clone(),
                    details: format!("scenario reached detect latency {}us", scenario_latency),
                });
            }
        }
    }

    VerificationInvariantResult {
        name: "detect_latency_budget".to_string(),
        passed: worst_case <= max_detect_latency_us,
        expected: json!(max_detect_latency_us),
        actual: json!(worst_case),
        details: if worst_case <= max_detect_latency_us {
            "candidate stayed within the verification detect-latency budget".to_string()
        } else {
            "candidate exceeded the verification detect-latency budget".to_string()
        },
        counterexamples: if worst_case <= max_detect_latency_us {
            Vec::new()
        } else {
            worst_reference.into_iter().collect()
        },
    }
}

pub(super) fn verify_total_detection_budget(
    reports: &[&ReplaySuiteReport],
    max_total_detections: usize,
) -> VerificationInvariantResult {
    let mut total_detections = 0usize;
    let mut by_scenario = Vec::new();
    for report in reports {
        for scenario in &report.scenario_reports {
            let count = scenario
                .evaluation
                .deterministic_summary
                .replay_bundle_count;
            total_detections += count;
            if count > 0 {
                by_scenario.push((scenario, count));
            }
        }
    }
    by_scenario.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    let counterexamples = if total_detections > max_total_detections {
        by_scenario
            .into_iter()
            .take(3)
            .map(|(scenario, count)| VerificationCounterexample {
                subject: scenario.scenario_name.clone(),
                reference: scenario.scenario_path.clone(),
                details: format!("scenario contributed {} detections", count),
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    VerificationInvariantResult {
        name: "total_detection_budget".to_string(),
        passed: total_detections <= max_total_detections,
        expected: json!(max_total_detections),
        actual: json!(total_detections),
        details: if total_detections <= max_total_detections {
            "candidate stayed within the verification detection-volume budget".to_string()
        } else {
            "candidate exceeded the verification detection-volume budget".to_string()
        },
        counterexamples,
    }
}

pub(super) fn collect_review_blocking_reasons(
    verification: &DetectorVerificationReport,
    shadow: &StrategyShadowReport,
) -> Vec<PromotionReviewBlockingReason> {
    let mut reasons = verification
        .invariants
        .iter()
        .filter(|invariant| !invariant.passed)
        .map(|invariant| PromotionReviewBlockingReason {
            source: "verification".to_string(),
            name: invariant.name.clone(),
            details: invariant.details.clone(),
            references: invariant
                .counterexamples
                .iter()
                .map(|counterexample| {
                    format!("{} | {}", counterexample.subject, counterexample.reference)
                })
                .collect(),
        })
        .collect::<Vec<_>>();

    reasons.extend(shadow.gates.iter().filter(|gate| !gate.passed).map(|gate| {
        PromotionReviewBlockingReason {
            source: "shadow_gate".to_string(),
            name: gate.name.clone(),
            details: gate.details.clone(),
            references: shadow
                .comparison
                .scenario_regressions
                .iter()
                .map(|regression| {
                    format!(
                        "{} | {}",
                        regression.scenario_name, regression.scenario_path
                    )
                })
                .collect(),
        }
    }));

    reasons
}
