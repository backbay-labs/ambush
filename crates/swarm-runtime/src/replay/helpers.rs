use super::types::{
    DetectorExperimentManifest, ReplayEvaluationCheck, ReplayEvaluationObservation,
    ReplayHarnessError, ReplayScenarioManifest, StrategyExperimentReport, StrategyShadowReport,
    VerificationCorpusManifest,
};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn equality_check(
    name: &str,
    expected: serde_json::Value,
    actual: serde_json::Value,
    success_details: &str,
) -> ReplayEvaluationCheck {
    let passed = expected == actual;
    ReplayEvaluationCheck {
        name: name.to_string(),
        passed,
        expected,
        actual,
        details: if passed {
            success_details.to_string()
        } else {
            format!("{name} did not match expected replay output")
        },
    }
}

/// Records one stage latency measured during a replay run as a NON-GATING
/// observation.
///
/// This used to be `latency_check`, and the three checks it produced were the
/// only entries in `ReplayEvaluationReport::checks` whose verdict was not a
/// function of the fixture. `expected_max <= actual_max` compared a manifest
/// constant against a wall-clock `Instant` delta captured in
/// `service::runtime_service`, so it measured the machine, the build profile,
/// and whatever else the scheduler was running -- not the scenario. That verdict
/// reached `ReplaySuiteReport::passed` and then `std::process::exit(1)` in
/// `swarmctl replay-evaluate`, a command `CONTRIBUTING.md` and `README.md` tell
/// contributors to run, which is what
/// `replay::tests::replay_evaluation_verdict_is_invariant_under_detect_stage_load`
/// pins down.
///
/// The measurement is still taken and still recorded in full, with the
/// manifest budget beside it. Only its authority to fail an evaluation is
/// removed. Re-earning a latency gate means counting work rather than reading a
/// clock, which is a cost model, not a rename.
pub(super) fn latency_observation(
    name: &str,
    advisory_max: u64,
    observed: u64,
) -> ReplayEvaluationObservation {
    let within_advisory_budget = observed <= advisory_max;
    ReplayEvaluationObservation {
        name: name.to_string(),
        advisory_budget: json!(advisory_max),
        observed: json!(observed),
        within_advisory_budget,
        details: if within_advisory_budget {
            format!(
                "{name} observed {observed}us stayed within the advisory budget \
                 {advisory_max}us (non-gating wall-clock measurement)"
            )
        } else {
            format!(
                "{name} observed {observed}us exceeded the advisory budget {advisory_max}us \
                 (non-gating wall-clock measurement; recorded, not enforced)"
            )
        },
    }
}

pub(super) fn run_id_for_manifest(manifest: &ReplayScenarioManifest) -> String {
    format!("replay_run:{}:{}", manifest.name, manifest.seed_time_ms)
}

pub(super) fn experiment_id_for_manifest(manifest: &DetectorExperimentManifest) -> String {
    format!(
        "experiment:{}:{}",
        manifest.name,
        manifest.candidate.strategy_id()
    )
}

pub(super) fn verification_id_for_experiment(
    experiment: &DetectorExperimentManifest,
    corpus: &VerificationCorpusManifest,
) -> String {
    format!(
        "verification:{}:{}:{}",
        experiment.name,
        experiment.candidate.strategy_id(),
        corpus.name
    )
}

pub(super) fn shadow_id_for_report(report: &StrategyExperimentReport) -> String {
    format!(
        "shadow:{}:{}:{}",
        report.experiment_name, report.candidate_strategy_id, report.corpus_version
    )
}

pub(super) fn promotion_review_id_for_packet(
    experiment: &DetectorExperimentManifest,
    shadow: &StrategyShadowReport,
) -> String {
    format!(
        "promotion_review:{}:{}:{}",
        experiment.name,
        experiment.candidate.strategy_id(),
        shadow.corpus_version
    )
}

pub(super) fn resolve_relative_path(manifest_path: &Path, referenced: &str) -> PathBuf {
    let candidate = PathBuf::from(referenced);
    if candidate.is_absolute() {
        candidate
    } else {
        manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(candidate)
    }
}

pub fn resolve_manifest_relative_path(manifest_path: &Path, referenced: &str) -> PathBuf {
    resolve_relative_path(manifest_path, referenced)
}

pub fn scenario_paths_in_dir(scenarios_dir: &Path) -> Result<Vec<PathBuf>, ReplayHarnessError> {
    let entries =
        fs::read_dir(scenarios_dir).map_err(|source| ReplayHarnessError::ScenarioRead {
            path: scenarios_dir.to_path_buf(),
            source,
        })?;
    let mut paths = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("yaml"))
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

pub(super) fn normalize_groups(groups: &[Vec<String>]) -> Vec<Vec<String>> {
    let mut normalized = groups
        .iter()
        .map(|group| {
            let mut sorted = group.clone();
            sorted.sort();
            sorted.dedup();
            sorted
        })
        .collect::<Vec<_>>();
    normalized.sort();
    normalized
}

pub(super) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
