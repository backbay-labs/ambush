use super::metrics::{scenario_detected, scenario_is_benign, suite_metrics};
use super::types::{
    DetectorVerificationReport, PromotionReviewBlockingReason, ReplayScenarioClass,
    ReplaySuiteReport, StrategyShadowReport, VerificationCounterexample,
    VerificationInvariantResult, VerificationObservation, VerificationObservationSource,
    VerificationThreatClassTemplate,
};
use crate::detector_factory::RuntimeDetector;
use serde_json::json;
use std::collections::BTreeSet;
use std::path::PathBuf;
use swarm_whisker::DetectionStrategy;

/// Fails closed on any verification scenario that declares no enforceable class.
///
/// This is the precondition the other two safety invariants are written on top
/// of. `verify_known_bad_coverage` demands a detection only from `Adversarial`
/// scenarios; `verify_false_positive_bound` draws counterexamples only from
/// `Benign` ones. `Mixed` matches NEITHER predicate, so a `Mixed` scenario is
/// exempt from both invariants simultaneously and contributes to neither
/// denominator. Without this check it passes vacuously, and the verification
/// report -- signed evidence -- attests to checks that never looked at it.
///
/// SECOND LINE, not the first. Both spellings are now refused at load: an
/// ABSENT `class:` by serde (the field is mandatory and `ReplayScenarioClass`
/// has no `Default`), an explicit `class: mixed` by
/// `validation::validate_manifest`. The loader is where the precondition
/// belongs, because eight other sites read `metadata.class` and had no
/// equivalent check -- see the comment there.
///
/// This is retained anyway. The verification report is signed evidence, and a
/// reader of the bundle should see the corpus assert the property rather than
/// have to know which loader enforced it; and "there is exactly one
/// deserialization entry point for a scenario manifest" is a fact about
/// today's tree, not a guarantee about tomorrow's.
pub(super) fn verify_scenario_class_declared(
    reports: &[&ReplaySuiteReport],
) -> VerificationInvariantResult {
    let counterexamples = reports
        .iter()
        .flat_map(|report| report.scenario_reports.iter())
        .filter(|scenario| scenario.metadata.class == ReplayScenarioClass::Mixed)
        .map(|scenario| VerificationCounterexample {
            subject: scenario.scenario_name.clone(),
            reference: scenario.scenario_path.clone(),
            details: concat!(
                "scenario declares class `mixed`, which no safety invariant ",
                "constrains; classify it `adversarial` or `benign`"
            )
            .to_string(),
        })
        .collect::<Vec<_>>();
    let unclassified = counterexamples.len();
    VerificationInvariantResult {
        name: "scenario_class_declared".to_string(),
        passed: unclassified == 0,
        expected: json!(0),
        actual: json!(unclassified),
        details: if unclassified == 0 {
            "every verification scenario declared a class an invariant can enforce".to_string()
        } else {
            "verification corpus contains scenarios no safety invariant constrains".to_string()
        },
        counterexamples,
    }
}

/// Fails closed on any verification scenario whose declared class no invariant
/// is actually responsible for.
///
/// `verify_scenario_class_declared` proves a scenario HAS a class some
/// invariant could enforce. It does not prove that any invariant did. The two
/// halves of the corpus are read separately, and each reader acts on one class
/// only: `verify_known_bad_coverage` sees the known-bad report and acts on
/// `Adversarial`; `verify_false_positive_bound` sees the benign report and acts
/// on `Benign`. So a class is enforceable only where it is also READ:
///
///   `benign` only in `known_bad.suite`
///       -> `known_bad_coverage` skips it, `false_positive_bound` never sees
///          it, and its detections land in neither the numerator nor the
///          denominator of the false-positive rate. It can fire a real
///          detection -- a false positive by definition -- while the report
///          records `false_positive_bound` as 0.0 and `passed: true`.
///
///   `adversarial` only in `benign_controls.scenarios`
///       -> `false_positive_bound` filters it out as not benign, and
///          `known_bad_coverage` never sees it, so nothing demands the
///          detection its class promises. It can miss detection entirely and
///          still pass.
///
/// Both spellings are a malformed corpus, and the repo contract is that weak
/// input fails closed. This is the same family as `scenario_class_declared`
/// and reports the same way: a named gating invariant carrying the offending
/// scenario as its own counterexample, rather than a borrowed failure from an
/// invariant that means something else.
///
/// A COVERAGE CHECK, NOT A SUITE-ROLE CHECK. A scenario listed in BOTH halves
/// is correct, and the shipped corpus depends on it: `hellcat-office-v1` is a
/// full replay suite that carries `benign-baseline` and
/// `python-maintenance-benign` so its own experiment metrics have a
/// false-positive denominator, and `office-detector-safety-v1` names those same
/// two files as its benign controls. Replay is deterministic -- the same
/// fixture through the same detector produces the same bundles -- so the
/// benign-half evaluation of such a scenario is what `false_positive_bound`
/// bounds, and the known-bad-half copy is genuinely covered. Demanding that a
/// scenario's class match the role of the suite it sits in would fail that
/// corpus for being correct, and would push benign controls out of the replay
/// suites that measure against them.
pub(super) fn verify_scenario_class_enforced(
    known_bad_report: &ReplaySuiteReport,
    benign_report: &ReplaySuiteReport,
) -> VerificationInvariantResult {
    let known_bad_fixtures = scenario_identities(known_bad_report);
    let benign_fixtures = scenario_identities(benign_report);

    let mut counterexamples = Vec::new();
    for scenario in &known_bad_report.scenario_reports {
        if scenario.metadata.class == ReplayScenarioClass::Benign
            && !benign_fixtures.contains(&scenario_identity(&scenario.scenario_path))
        {
            counterexamples.push(VerificationCounterexample {
                subject: scenario.scenario_name.clone(),
                reference: scenario.scenario_path.clone(),
                details: concat!(
                    "scenario declares class `benign` but is listed only in the known-bad ",
                    "suite, where no invariant bounds its detections; list it under ",
                    "`benign_controls.scenarios` so `false_positive_bound` sees it, or ",
                    "reclassify it `adversarial`"
                )
                .to_string(),
            });
        }
    }
    for scenario in &benign_report.scenario_reports {
        if scenario.metadata.class == ReplayScenarioClass::Adversarial
            && !known_bad_fixtures.contains(&scenario_identity(&scenario.scenario_path))
        {
            counterexamples.push(VerificationCounterexample {
                subject: scenario.scenario_name.clone(),
                reference: scenario.scenario_path.clone(),
                details: concat!(
                    "scenario declares class `adversarial` but is listed only in the benign ",
                    "controls, where no invariant demands the detection it promises; list it ",
                    "in the `known_bad.suite` so `known_bad_coverage` sees it, or reclassify ",
                    "it `benign`"
                )
                .to_string(),
            });
        }
    }

    let unenforced = counterexamples.len();
    VerificationInvariantResult {
        name: "scenario_class_enforced".to_string(),
        passed: unenforced == 0,
        expected: json!(0),
        actual: json!(unenforced),
        details: if unenforced == 0 {
            "every verification scenario sits in the corpus half that enforces its class"
                .to_string()
        } else {
            "verification corpus contains scenarios whose declared class no invariant enforces"
                .to_string()
        },
        counterexamples,
    }
}

fn scenario_identities(report: &ReplaySuiteReport) -> BTreeSet<PathBuf> {
    report
        .scenario_reports
        .iter()
        .map(|scenario| scenario_identity(&scenario.scenario_path))
        .collect()
}

/// Identity of the FIXTURE a scenario report was produced from.
///
/// The two halves of a corpus reference the same file through different roots
/// -- the known-bad suite resolves `../scenarios/x.yaml` against
/// `scenario-suites/`, the benign controls resolve it against `verifications/`
/// -- so the recorded path strings differ for what is one file. The shipped
/// corpus records exactly that: `experiments/../verifications/../scenario-suites/../scenarios/benign-baseline.yaml`
/// on the known-bad side and `experiments/../verifications/../scenarios/benign-baseline.yaml`
/// on the benign side. Comparing raw strings would report its dual-listed
/// benign controls as uncovered.
///
/// `canonicalize` resolves `..` and symlinks against the filesystem, and every
/// one of these files was just read to produce the report being checked. If it
/// fails anyway -- the file moved underfoot -- the raw path is kept, which can
/// only ever fail to match, and failing to match reports the scenario as
/// unenforced. That is the fail-closed direction.
fn scenario_identity(path: &str) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path))
}

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

/// Records the worst-case detect-stage latency measured across the verification
/// suites as a NON-GATING observation.
///
/// This used to be a gating invariant, and it was the only one whose verdict was
/// not a function of the fixtures. `max_latency_us` is a wall-clock `Instant`
/// delta, so it measures the machine, the build profile, and whatever else the
/// scheduler was running -- not the candidate. Two runs of an identical
/// candidate over identical fixtures reached opposite verdicts on the same
/// machine minutes apart, which is what `replay::tests::
/// verification_verdict_is_invariant_under_detect_stage_load` pins down.
///
/// The measurement is still taken and still recorded in full, including which
/// scenario was slowest. Only its authority to fail a verification is removed.
/// Re-earning a latency gate means counting work rather than reading a clock,
/// which is a cost model, not a rename.
pub(super) fn observe_detect_latency(
    reports: &[&ReplaySuiteReport],
    advisory_max_detect_latency_us: u64,
) -> VerificationObservation {
    let mut worst_case = 0u64;
    let mut worst_source = None::<VerificationObservationSource>;
    for report in reports {
        for scenario in &report.scenario_reports {
            let scenario_latency = scenario.evaluation.performance.detect.max_latency_us;
            if scenario_latency > worst_case {
                worst_case = scenario_latency;
                worst_source = Some(VerificationObservationSource {
                    subject: scenario.scenario_name.clone(),
                    reference: scenario.scenario_path.clone(),
                    details: format!("scenario reached detect latency {}us", scenario_latency),
                });
            }
        }
    }
    let within_advisory_budget = worst_case <= advisory_max_detect_latency_us;

    VerificationObservation {
        name: "detect_latency_budget".to_string(),
        advisory_budget: json!(advisory_max_detect_latency_us),
        observed: json!(worst_case),
        within_advisory_budget,
        details: if within_advisory_budget {
            format!(
                "worst-case detect latency {}us stayed within the advisory budget {}us \
                 (non-gating wall-clock measurement)",
                worst_case, advisory_max_detect_latency_us
            )
        } else {
            format!(
                "worst-case detect latency {}us exceeded the advisory budget {}us \
                 (non-gating wall-clock measurement; recorded, not enforced)",
                worst_case, advisory_max_detect_latency_us
            )
        },
        sources: worst_source.into_iter().collect(),
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
