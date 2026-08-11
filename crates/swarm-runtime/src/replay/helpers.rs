use super::types::{
    DetectorExperimentManifest, ReplayEvaluationCheck, ReplayHarnessError, ReplayScenarioManifest,
    StrategyExperimentReport, StrategyShadowReport, VerificationCorpusManifest,
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

pub(super) fn latency_check(
    name: &str,
    expected_max: u64,
    actual_max: u64,
) -> ReplayEvaluationCheck {
    let passed = actual_max <= expected_max;
    ReplayEvaluationCheck {
        name: name.to_string(),
        passed,
        expected: json!(expected_max),
        actual: json!(actual_max),
        details: if passed {
            format!("{name} stayed within configured replay threshold")
        } else {
            format!("{name} exceeded configured replay threshold")
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
