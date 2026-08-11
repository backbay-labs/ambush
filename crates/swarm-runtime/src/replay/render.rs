use super::types::{
    DetectorVerificationReport, PromotionReviewPacket, PromotionReviewRecommendation,
    ReplayEvaluationReport, ReplayRunBundle, ReplaySuiteReport, ReplaySuiteSourceKind,
    StrategyExperimentReport, StrategyShadowReport,
};

/// Render one replay run in a concise operator-friendly format.
pub fn render_replay_run(run: &ReplayRunBundle) -> String {
    let mut lines = vec![
        "Ambush Replay Run".to_string(),
        format!("Scenario: {}", run.scenario_name),
        format!("Run: {}", run.run_id),
        format!("Source: {:?}", run.input_kind),
        format!(
            "Bundles: {} | investigations: {} | incidents: {}",
            run.deterministic_summary.replay_bundle_count,
            run.deterministic_summary.investigation_count,
            run.deterministic_summary.incident_count
        ),
    ];

    if !run.deterministic_summary.hunts.is_empty() {
        lines.push("Hunts:".to_string());
        for hunt in &run.deterministic_summary.hunts {
            lines.push(format!(
                "- {} action={} verdict={:?} response={}",
                hunt.hunt_id, hunt.action_kind, hunt.policy_verdict, hunt.response_kind
            ));
        }
    }

    if !run.deterministic_summary.incident_hunt_groups.is_empty() {
        lines.push("Incident groups:".to_string());
        for group in &run.deterministic_summary.incident_hunt_groups {
            lines.push(format!("- {}", group.join(", ")));
        }
    }

    lines.join("\n")
}

/// Render one evaluation report for operator review or CI failure output.
pub fn render_evaluation_report(report: &ReplayEvaluationReport) -> String {
    let mut lines = vec![
        "Ambush Replay Evaluation".to_string(),
        format!("Scenario: {}", report.scenario_name),
        format!("Run: {}", report.run_id),
        format!("Status: {}", if report.passed { "pass" } else { "fail" }),
    ];

    for check in &report.checks {
        lines.push(format!(
            "- [{}] {} | expected={} actual={} | {}",
            if check.passed { "pass" } else { "fail" },
            check.name,
            check.expected,
            check.actual,
            check.details
        ));
    }

    lines.join("\n")
}

/// Render a whole-suite replay evaluation report.
pub fn render_suite_report(report: &ReplaySuiteReport) -> String {
    let mut lines = vec![
        "Ambush Replay Suite".to_string(),
        format!("Source: {}", report.source),
        format!(
            "Selection: {}",
            match report.source_kind {
                ReplaySuiteSourceKind::ScenariosDir => "tracked directory",
                ReplaySuiteSourceKind::SuiteManifest => "named suite",
                ReplaySuiteSourceKind::ScenarioList => "explicit scenario list",
            }
        ),
        format!(
            "Suite: {}",
            report
                .suite_name
                .as_deref()
                .unwrap_or("tracked_scenarios_directory")
        ),
        format!("Status: {}", if report.passed { "pass" } else { "fail" }),
        format!(
            "Totals: {} total | {} passed | {} failed",
            report.total_scenarios, report.passed_scenarios, report.failed_scenarios
        ),
    ];

    if let Some(corpus_version) = &report.corpus_version {
        lines.push(format!("Corpus version: {corpus_version}"));
    }

    if !report.technique_groups.is_empty() {
        lines.push("Techniques:".to_string());
        for group in &report.technique_groups {
            lines.push(format!(
                "- {} | scenarios={} | failing={}",
                group.technique,
                group.total_scenarios,
                group.failing_scenarios.len()
            ));
        }
    }

    for scenario_report in &report.scenario_reports {
        lines.push(format!(
            "- {} [{:?}] [{}]",
            scenario_report.scenario_name,
            scenario_report.metadata.class,
            if scenario_report.evaluation.passed {
                "pass"
            } else {
                "fail"
            }
        ));
        if !scenario_report.metadata.techniques.is_empty() {
            lines.push(format!(
                "  techniques: {}",
                scenario_report.metadata.techniques.join(", ")
            ));
        }
        for check in scenario_report
            .evaluation
            .checks
            .iter()
            .filter(|check| !check.passed)
        {
            lines.push(format!(
                "  failing check: {} | expected={} actual={} | {}",
                check.name, check.expected, check.actual, check.details
            ));
        }
    }

    lines.join("\n")
}

/// Render one persisted detector experiment report.
pub fn render_experiment_report(report: &StrategyExperimentReport) -> String {
    let mut lines = vec![
        "Ambush Detector Experiment".to_string(),
        format!("Experiment: {}", report.experiment_name),
        format!("Experiment ID: {}", report.experiment_id),
        format!("Suite: {} ({})", report.suite_name, report.corpus_version),
        format!("Baseline: {}", report.baseline_strategy_id),
        format!("Candidate: {}", report.candidate_strategy_id),
        format!("Status: {}", if report.passed { "pass" } else { "fail" }),
        format!(
            "Detection rate: {:.2} -> {:.2}",
            report.comparison.baseline.detection_rate, report.comparison.candidate.detection_rate
        ),
        format!(
            "False positive rate: {:.2} -> {:.2}",
            report.comparison.baseline.false_positive_rate,
            report.comparison.candidate.false_positive_rate
        ),
        format!(
            "Max detect latency us: {} -> {}",
            report.comparison.baseline.max_detect_latency_us,
            report.comparison.candidate.max_detect_latency_us
        ),
    ];

    lines.push("Gates:".to_string());
    for gate in &report.gates {
        lines.push(format!(
            "- [{}] {} | expected={} actual={} | {}",
            if gate.passed { "pass" } else { "fail" },
            gate.name,
            gate.expected,
            gate.actual,
            gate.details
        ));
    }

    if !report.comparison.scenario_regressions.is_empty() {
        lines.push("Scenario regressions:".to_string());
        for regression in &report.comparison.scenario_regressions {
            lines.push(format!(
                "- {} [{:?}] | {}",
                regression.scenario_name, regression.class, regression.reason
            ));
        }
    }

    if !report.comparison.technique_regressions.is_empty() {
        lines.push("Technique regressions:".to_string());
        for regression in &report.comparison.technique_regressions {
            lines.push(format!(
                "- {} | {}",
                regression.technique,
                regression.scenarios.join(", ")
            ));
        }
    }

    lines.join("\n")
}

/// Render one persisted detector verification report.
pub fn render_verification_report(report: &DetectorVerificationReport) -> String {
    let mut lines = vec![
        "Ambush Detector Verification".to_string(),
        format!("Experiment: {}", report.experiment_name),
        format!("Verification ID: {}", report.verification_id),
        format!("Corpus: {}", report.corpus_name),
        format!("Candidate: {}", report.candidate_strategy_id),
        format!("Status: {}", if report.passed { "pass" } else { "fail" }),
    ];

    lines.push("Invariants:".to_string());
    for invariant in &report.invariants {
        lines.push(format!(
            "- [{}] {} | expected={} actual={} | {}",
            if invariant.passed { "pass" } else { "fail" },
            invariant.name,
            invariant.expected,
            invariant.actual,
            invariant.details
        ));
        for counterexample in &invariant.counterexamples {
            lines.push(format!(
                "  counterexample: {} | {} | {}",
                counterexample.subject, counterexample.reference, counterexample.details
            ));
        }
    }

    lines.join("\n")
}

/// Render one persisted shadow comparison report.
pub fn render_shadow_report(report: &StrategyShadowReport) -> String {
    let mut lines = vec![
        "Ambush Shadow Evaluation".to_string(),
        format!("Experiment: {}", report.experiment_name),
        format!("Shadow ID: {}", report.shadow_id),
        format!("Suite: {} ({})", report.suite_name, report.corpus_version),
        format!("Baseline: {}", report.baseline_strategy_id),
        format!("Candidate: {}", report.candidate_strategy_id),
        format!("Status: {}", if report.passed { "pass" } else { "fail" }),
        format!("Source artifacts: {}", report.source_artifacts.len()),
        format!(
            "Detection rate delta: {:.2}",
            report.comparison.delta.detection_rate_delta
        ),
        format!(
            "False positive rate delta: {:.2}",
            report.comparison.delta.false_positive_rate_delta
        ),
        format!(
            "Max detect latency delta us: {}",
            report.comparison.delta.max_detect_latency_delta_us
        ),
    ];

    lines.push("Shadow gates:".to_string());
    for gate in &report.gates {
        lines.push(format!(
            "- [{}] {} | expected={} actual={} | {}",
            if gate.passed { "pass" } else { "fail" },
            gate.name,
            gate.expected,
            gate.actual,
            gate.details
        ));
    }

    if !report.comparison.scenario_regressions.is_empty() {
        lines.push("Scenario regressions:".to_string());
        for regression in &report.comparison.scenario_regressions {
            lines.push(format!(
                "- {} [{:?}] | {}",
                regression.scenario_name, regression.class, regression.reason
            ));
        }
    }

    lines.join("\n")
}

/// Render one persisted promotion review packet.
pub fn render_promotion_review_packet(packet: &PromotionReviewPacket) -> String {
    let mut lines = vec![
        "Ambush Promotion Review Packet".to_string(),
        format!("Experiment: {}", packet.experiment_name),
        format!("Review ID: {}", packet.review_id),
        format!("Candidate: {}", packet.candidate_strategy_id),
        format!("Verification: {}", packet.verification_id),
        format!("Shadow: {}", packet.shadow_id),
        format!(
            "Recommendation: {}",
            match packet.recommendation {
                PromotionReviewRecommendation::ReadyForManualReview => {
                    "ready_for_manual_review"
                }
                PromotionReviewRecommendation::Blocked => "blocked",
            }
        ),
        format!(
            "Deltas: detection={:.2} false_positive={:.2} detect_latency_us={}",
            packet.detection_rate_delta,
            packet.false_positive_rate_delta,
            packet.max_detect_latency_delta_us
        ),
    ];

    if packet.blocking_reasons.is_empty() {
        lines.push("Blocking reasons: none".to_string());
    } else {
        lines.push("Blocking reasons:".to_string());
        for reason in &packet.blocking_reasons {
            lines.push(format!(
                "- {}:{} | {}",
                reason.source, reason.name, reason.details
            ));
            for reference in &reason.references {
                lines.push(format!("  reference: {}", reference));
            }
        }
    }

    lines.join("\n")
}
