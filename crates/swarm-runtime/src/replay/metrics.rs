use super::helpers::shadow_id_for_report;
use super::types::{
    ExperimentGateConfig, ExperimentGateResult, ReplayScenarioClass, ReplaySuiteReport,
    ReplaySuiteScenarioReport, ReplayTechniqueGroupReport, StrategyExperimentComparison,
    StrategyExperimentMetricDelta, StrategyExperimentMetrics, StrategyExperimentReport,
    StrategyScenarioRegression, StrategyShadowReport, StrategyTechniqueRegression,
};
use serde_json::json;
use std::collections::BTreeMap;

pub(super) fn technique_groups_from_suite(
    reports: &[ReplaySuiteScenarioReport],
) -> Vec<ReplayTechniqueGroupReport> {
    let mut groups = BTreeMap::<String, ReplayTechniqueGroupReport>::new();
    for report in reports {
        for technique in &report.metadata.techniques {
            let entry =
                groups
                    .entry(technique.clone())
                    .or_insert_with(|| ReplayTechniqueGroupReport {
                        technique: technique.clone(),
                        total_scenarios: 0,
                        failing_scenarios: Vec::new(),
                    });
            entry.total_scenarios += 1;
            if !report.evaluation.passed {
                entry.failing_scenarios.push(report.scenario_name.clone());
            }
        }
    }

    groups.into_values().collect()
}

pub(super) fn compare_suite_reports(
    baseline: &ReplaySuiteReport,
    candidate: &ReplaySuiteReport,
) -> StrategyExperimentComparison {
    let baseline_metrics = suite_metrics(baseline);
    let candidate_metrics = suite_metrics(candidate);
    let baseline_by_path = baseline
        .scenario_reports
        .iter()
        .map(|report| (report.scenario_path.as_str(), report))
        .collect::<BTreeMap<_, _>>();
    let candidate_by_path = candidate
        .scenario_reports
        .iter()
        .map(|report| (report.scenario_path.as_str(), report))
        .collect::<BTreeMap<_, _>>();

    let mut scenario_regressions = Vec::new();
    for (scenario_path, baseline_report) in baseline_by_path {
        let Some(candidate_report) = candidate_by_path.get(scenario_path) else {
            continue;
        };

        if scenario_expected_positive(baseline_report)
            && scenario_detected(baseline_report)
            && !scenario_detected(candidate_report)
        {
            scenario_regressions.push(StrategyScenarioRegression {
                scenario_name: baseline_report.scenario_name.clone(),
                scenario_path: baseline_report.scenario_path.clone(),
                class: baseline_report.metadata.class,
                techniques: baseline_report.metadata.techniques.clone(),
                reason: "candidate missed expected adversarial detection".to_string(),
            });
        } else if scenario_is_benign(baseline_report)
            && !scenario_detected(baseline_report)
            && scenario_detected(candidate_report)
        {
            scenario_regressions.push(StrategyScenarioRegression {
                scenario_name: baseline_report.scenario_name.clone(),
                scenario_path: baseline_report.scenario_path.clone(),
                class: baseline_report.metadata.class,
                techniques: baseline_report.metadata.techniques.clone(),
                reason: "candidate introduced a benign false positive".to_string(),
            });
        }
    }

    let mut technique_groups = BTreeMap::<String, Vec<String>>::new();
    for regression in &scenario_regressions {
        if regression.class != ReplayScenarioClass::Adversarial {
            continue;
        }
        for technique in &regression.techniques {
            technique_groups
                .entry(technique.clone())
                .or_default()
                .push(regression.scenario_name.clone());
        }
    }
    let technique_regressions = technique_groups
        .into_iter()
        .map(|(technique, mut scenarios)| {
            scenarios.sort();
            scenarios.dedup();
            StrategyTechniqueRegression {
                technique,
                scenarios,
            }
        })
        .collect::<Vec<_>>();

    StrategyExperimentComparison {
        delta: StrategyExperimentMetricDelta {
            detection_rate_delta: candidate_metrics.detection_rate
                - baseline_metrics.detection_rate,
            false_positive_rate_delta: candidate_metrics.false_positive_rate
                - baseline_metrics.false_positive_rate,
            max_detect_latency_delta_us: candidate_metrics.max_detect_latency_us as i64
                - baseline_metrics.max_detect_latency_us as i64,
            false_positive_scenario_delta: candidate_metrics.false_positive_scenarios as i64
                - baseline_metrics.false_positive_scenarios as i64,
        },
        baseline: baseline_metrics,
        candidate: candidate_metrics,
        scenario_regressions,
        technique_regressions,
    }
}

pub(super) fn shadow_report_from_experiment(
    report: &StrategyExperimentReport,
    source_artifacts: Vec<String>,
) -> StrategyShadowReport {
    StrategyShadowReport {
        shadow_id: shadow_id_for_report(report),
        experiment_id: report.experiment_id.clone(),
        experiment_name: report.experiment_name.clone(),
        created_at_ms: report.created_at_ms,
        source_artifacts,
        suite_name: report.suite_name.clone(),
        suite_path: report.suite_path.clone(),
        corpus_version: report.corpus_version.clone(),
        lineage: report.lineage.clone(),
        baseline_strategy_id: report.baseline_strategy_id.clone(),
        candidate_strategy_id: report.candidate_strategy_id.clone(),
        candidate_description: report.candidate_description.clone(),
        comparison: report.comparison.clone(),
        gates: report.gates.clone(),
        passed: report.passed,
    }
}

pub(super) fn suite_metrics(report: &ReplaySuiteReport) -> StrategyExperimentMetrics {
    let mut adversarial_scenarios = 0usize;
    let mut benign_scenarios = 0usize;
    let mut true_positive_scenarios = 0usize;
    let mut false_negative_scenarios = 0usize;
    let mut true_negative_scenarios = 0usize;
    let mut false_positive_scenarios = 0usize;
    let mut max_detect_latency_us = 0u64;

    for scenario in &report.scenario_reports {
        max_detect_latency_us =
            max_detect_latency_us.max(scenario.evaluation.performance.detect.max_latency_us);

        if scenario_expected_positive(scenario) {
            adversarial_scenarios += 1;
            if scenario_detected(scenario) {
                true_positive_scenarios += 1;
            } else {
                false_negative_scenarios += 1;
            }
        } else if scenario_is_benign(scenario) {
            benign_scenarios += 1;
            if scenario_detected(scenario) {
                false_positive_scenarios += 1;
            } else {
                true_negative_scenarios += 1;
            }
        }
    }

    StrategyExperimentMetrics {
        total_scenarios: report.total_scenarios,
        adversarial_scenarios,
        benign_scenarios,
        true_positive_scenarios,
        false_negative_scenarios,
        true_negative_scenarios,
        false_positive_scenarios,
        detection_rate: ratio(true_positive_scenarios, adversarial_scenarios),
        false_positive_rate: ratio(false_positive_scenarios, benign_scenarios),
        max_detect_latency_us,
    }
}

fn scenario_expected_positive(report: &ReplaySuiteScenarioReport) -> bool {
    report.metadata.class == ReplayScenarioClass::Adversarial
}

pub(super) fn scenario_is_benign(report: &ReplaySuiteScenarioReport) -> bool {
    report.metadata.class == ReplayScenarioClass::Benign
}

pub(super) fn scenario_detected(report: &ReplaySuiteScenarioReport) -> bool {
    report.evaluation.deterministic_summary.replay_bundle_count > 0
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

pub(super) fn evaluate_experiment_gates(
    config: &ExperimentGateConfig,
    comparison: &StrategyExperimentComparison,
) -> Vec<ExperimentGateResult> {
    let mut gates = Vec::new();
    if config.require_known_bad_coverage {
        let misses = comparison
            .scenario_regressions
            .iter()
            .filter(|regression| regression.class == ReplayScenarioClass::Adversarial)
            .count();
        gates.push(ExperimentGateResult {
            name: "known_bad_coverage".to_string(),
            passed: misses == 0,
            expected: json!(0),
            actual: json!(misses),
            details: if misses == 0 {
                "candidate preserved adversarial scenario coverage".to_string()
            } else {
                "candidate missed expected adversarial detections".to_string()
            },
        });
    }

    let false_positive_delta = comparison.delta.false_positive_scenario_delta;
    gates.push(ExperimentGateResult {
        name: "false_positive_delta".to_string(),
        passed: false_positive_delta <= config.max_false_positive_delta,
        expected: json!(config.max_false_positive_delta),
        actual: json!(false_positive_delta),
        details: if false_positive_delta <= config.max_false_positive_delta {
            "candidate stayed within the configured false-positive delta".to_string()
        } else {
            "candidate exceeded the configured false-positive delta".to_string()
        },
    });

    let latency_delta = comparison.delta.max_detect_latency_delta_us;
    gates.push(ExperimentGateResult {
        name: "max_detect_latency_delta_us".to_string(),
        passed: latency_delta <= config.max_detect_latency_delta_us as i64,
        expected: json!(config.max_detect_latency_delta_us),
        actual: json!(latency_delta),
        details: if latency_delta <= config.max_detect_latency_delta_us as i64 {
            "candidate stayed within the configured detect-latency delta".to_string()
        } else {
            "candidate exceeded the configured detect-latency delta".to_string()
        },
    });

    gates
}
