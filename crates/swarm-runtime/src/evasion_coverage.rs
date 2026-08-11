use crate::config::{
    DetectorProfileError, RuntimeConfigError, fileless_execution_profile, lateral_movement_profile,
    supply_chain_profile, suspicious_process_tree_profile, suspicious_scripting_profile,
};
use crate::detection::metrics::CriticalPathMetrics;
use crate::detector_factory::{DetectorFactoryError, build_detector_from_strategy};
use crate::replay::{
    ReplayHarnessError, ReplayScenarioClass, ReplayScenarioInput, load_replay_suite_manifest,
    load_scenario_manifest, resolve_manifest_relative_path,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::SwarmConfig;
use swarm_core::pheromone::ThreatClass;
use swarm_core::telemetry::{TelemetryEvent, TelemetryPayload};
use swarm_whisker::{CommandLineNormalizationProfile, DetectionStrategy};

pub const REPO_EVASION_SUITE_PATH: &str = "scenario-suites/evasion-breadth-v1.yaml";
pub const REPO_EVASION_CATALOG_PATH: &str = "rulesets/evasion/attack-technique-catalog.yaml";
pub const REPO_COMMAND_LINE_DEOBF_SUITE_PATH: &str =
    "scenario-suites/command-line-deobfuscation-v1.yaml";
pub const REPO_COMMAND_LINE_DEOBF_CATALOG_PATH: &str =
    "rulesets/evasion/command-line-deobfuscation-catalog.yaml";

const EVASION_COVERAGE_DETECTORS: [&str; 11] = [
    "suspicious_process_tree",
    "fileless_execution",
    "behavioral_anomaly",
    "dns_exfiltration",
    "lateral_movement",
    "credential_access",
    "suspicious_scripting",
    "persistence",
    "supply_chain",
    "network_connect",
    "infrastructure_anomaly",
];
const COMMAND_LINE_NORMALIZATION_DETECTORS: [&str; 5] = [
    "suspicious_process_tree",
    "fileless_execution",
    "lateral_movement",
    "suspicious_scripting",
    "supply_chain",
];
const COMMAND_LINE_BENCHMARK_DETECTORS: [&str; 2] = ["suspicious_scripting", "fileless_execution"];

#[derive(Debug, thiserror::Error)]
pub enum EvasionCoverageError {
    #[error(transparent)]
    Replay(#[from] ReplayHarnessError),

    #[error(transparent)]
    DetectorFactory(#[from] DetectorFactoryError),

    #[error(transparent)]
    DetectorProfile(#[from] DetectorProfileError),

    #[error("failed to read evasion catalog `{path}`: {source}")]
    CatalogRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evasion catalog `{path}`: {source}")]
    CatalogParse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("invalid evasion catalog `{path}`: {reason}")]
    CatalogValidation { path: PathBuf, reason: String },

    #[error("invalid evasion coverage request: {0}")]
    InvalidRequest(String),

    #[error(transparent)]
    Config(#[from] RuntimeConfigError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvasionTechniqueCatalog {
    pub schema_version: u32,
    pub suite: String,
    pub detectors: Vec<EvasionTechniqueCatalogDetector>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvasionTechniqueCatalogDetector {
    pub detector: String,
    #[serde(default)]
    pub intentionally_uncovered: Vec<EvasionTechniqueGap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvasionTechniqueGap {
    pub technique: String,
    pub threat_class: ThreatClass,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionThreatClassCoverage {
    pub threat_class: ThreatClass,
    pub total_payloads: usize,
    pub detected_payloads: usize,
    pub catch_rate: f64,
    pub scenario_count: usize,
    pub techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionScenarioCoverage {
    pub scenario_name: String,
    pub threat_class: ThreatClass,
    pub total_payloads: usize,
    pub detected_payloads: usize,
    pub catch_rate: f64,
    pub techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorEvasionCoverageReport {
    pub detector: String,
    pub total_payloads: usize,
    pub detected_payloads: usize,
    pub catch_rate: f64,
    pub threat_classes: Vec<EvasionThreatClassCoverage>,
    pub scenarios: Vec<EvasionScenarioCoverage>,
    pub intentionally_uncovered: Vec<EvasionTechniqueGap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionCoverageSnapshot {
    pub generated_at_ms: i64,
    pub suite_name: String,
    pub suite_path: String,
    pub corpus_version: String,
    pub detectors: Vec<DetectorEvasionCoverageReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdversaryTechniqueStatus {
    Detected,
    Partial,
    NotCovered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdversaryTechniqueOccurrenceReport {
    pub scenario_name: String,
    pub threat_class: ThreatClass,
    pub mapped_detectors: Vec<String>,
    pub catch_rate: f64,
    pub status: AdversaryTechniqueStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdversaryTechniqueCoverageReport {
    pub technique: String,
    pub mapped_detectors: Vec<String>,
    pub status: AdversaryTechniqueStatus,
    pub occurrences: Vec<AdversaryTechniqueOccurrenceReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdversaryEmulationCoverageReport {
    pub generated_at_ms: i64,
    pub suite_name: String,
    pub suite_path: String,
    pub corpus_version: String,
    pub scenario_count: usize,
    pub technique_count: usize,
    pub detected_technique_count: usize,
    pub partial_technique_count: usize,
    pub not_covered_technique_count: usize,
    pub coverage_percent: f64,
    pub techniques: Vec<AdversaryTechniqueCoverageReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandLineNormalizationCatchRateDelta {
    pub detector: String,
    pub threat_class: ThreatClass,
    pub total_payloads: usize,
    pub baseline_detected_payloads: usize,
    pub normalized_detected_payloads: usize,
    pub baseline_catch_rate: f64,
    pub normalized_catch_rate: f64,
    pub catch_rate_delta: f64,
    pub scenario_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandLineNormalizationBenchmark {
    pub generated_at_ms: i64,
    pub suite_name: String,
    pub suite_path: String,
    pub corpus_version: String,
    pub scenario_names: Vec<String>,
    pub detector_deltas: Vec<CommandLineNormalizationCatchRateDelta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandLineNormalizationFalsePositiveDelta {
    pub detector: String,
    pub total_benign_payloads: usize,
    pub baseline_false_positive_payloads: usize,
    pub normalized_false_positive_payloads: usize,
    pub false_positive_delta: isize,
    pub scenario_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandLineNormalizationFalsePositiveReport {
    pub generated_at_ms: i64,
    pub suite_name: String,
    pub suite_path: String,
    pub corpus_version: String,
    pub scenario_names: Vec<String>,
    pub detector_results: Vec<CommandLineNormalizationFalsePositiveDelta>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvasionActionableGap {
    pub threat_class: ThreatClass,
    pub total_payloads: usize,
    pub detected_payloads: usize,
    pub missed_payloads: usize,
    pub catch_rate: f64,
    pub actionable_techniques: Vec<String>,
}

#[derive(Debug, Default)]
struct ThreatClassAccumulator {
    total_payloads: usize,
    detected_payloads: usize,
    scenario_names: BTreeSet<String>,
    techniques: BTreeSet<String>,
}

#[derive(Debug)]
struct LoadedAdversarialScenario {
    name: String,
    threat_class: ThreatClass,
    techniques: Vec<String>,
    events: Vec<TelemetryEvent>,
}

#[derive(Debug)]
struct LoadedBenignScenario {
    name: String,
    events: Vec<TelemetryEvent>,
}

pub fn evaluate_repo_evasion_coverage(
    config: &SwarmConfig,
    repo_root: &Path,
) -> Result<EvasionCoverageSnapshot, EvasionCoverageError> {
    evaluate_evasion_coverage(
        config,
        repo_root,
        &repo_root.join(REPO_EVASION_SUITE_PATH),
        &repo_root.join(REPO_EVASION_CATALOG_PATH),
    )
}

pub fn summarize_repo_adversary_emulation_coverage(
    config: &SwarmConfig,
    repo_root: &Path,
) -> Result<AdversaryEmulationCoverageReport, EvasionCoverageError> {
    let snapshot = evaluate_repo_evasion_coverage(config, repo_root)?;
    let scenarios = load_adversarial_scenarios(&repo_root.join(REPO_EVASION_SUITE_PATH))?;
    let mut techniques = BTreeMap::<String, Vec<AdversaryTechniqueOccurrenceReport>>::new();

    for scenario in scenarios {
        let mapped_detectors = mapped_detectors_for_adversary_scenario(&scenario.name)?;
        let best_catch_rate = mapped_detectors
            .iter()
            .filter_map(|detector| {
                scenario_coverage(&snapshot, detector, &scenario.name).map(|entry| entry.catch_rate)
            })
            .fold(0.0f64, f64::max);
        let all_intentionally_uncovered = mapped_detectors.iter().all(|detector| {
            detector_intentionally_uncovered(
                &snapshot,
                detector,
                &scenario.threat_class,
                &scenario.techniques,
            )
        });
        let status = if all_intentionally_uncovered {
            if best_catch_rate > 0.0 {
                AdversaryTechniqueStatus::Partial
            } else {
                AdversaryTechniqueStatus::NotCovered
            }
        } else if best_catch_rate >= 0.999_999 {
            AdversaryTechniqueStatus::Detected
        } else if best_catch_rate > 0.0 {
            AdversaryTechniqueStatus::Partial
        } else {
            AdversaryTechniqueStatus::NotCovered
        };

        for technique in scenario.techniques {
            techniques
                .entry(technique)
                .or_default()
                .push(AdversaryTechniqueOccurrenceReport {
                    scenario_name: scenario.name.clone(),
                    threat_class: scenario.threat_class.clone(),
                    mapped_detectors: mapped_detectors
                        .iter()
                        .map(|detector| detector.to_string())
                        .collect(),
                    catch_rate: best_catch_rate,
                    status,
                });
        }
    }

    let mut reports = techniques
        .into_iter()
        .map(|(technique, mut occurrences)| {
            occurrences.sort_by(|left, right| {
                left.scenario_name
                    .cmp(&right.scenario_name)
                    .then_with(|| left.mapped_detectors.cmp(&right.mapped_detectors))
            });
            let status = if occurrences
                .iter()
                .all(|entry| entry.status == AdversaryTechniqueStatus::Detected)
            {
                AdversaryTechniqueStatus::Detected
            } else if occurrences
                .iter()
                .any(|entry| entry.status != AdversaryTechniqueStatus::NotCovered)
            {
                AdversaryTechniqueStatus::Partial
            } else {
                AdversaryTechniqueStatus::NotCovered
            };
            let mapped_detectors = occurrences
                .iter()
                .flat_map(|entry| entry.mapped_detectors.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            AdversaryTechniqueCoverageReport {
                technique,
                mapped_detectors,
                status,
                occurrences,
            }
        })
        .collect::<Vec<_>>();
    reports.sort_by(|left, right| left.technique.cmp(&right.technique));

    let detected_technique_count = reports
        .iter()
        .filter(|entry| entry.status == AdversaryTechniqueStatus::Detected)
        .count();
    let partial_technique_count = reports
        .iter()
        .filter(|entry| entry.status == AdversaryTechniqueStatus::Partial)
        .count();
    let not_covered_technique_count = reports
        .iter()
        .filter(|entry| entry.status == AdversaryTechniqueStatus::NotCovered)
        .count();
    let technique_count = reports.len();

    Ok(AdversaryEmulationCoverageReport {
        generated_at_ms: snapshot.generated_at_ms,
        suite_name: snapshot.suite_name,
        suite_path: snapshot.suite_path,
        corpus_version: snapshot.corpus_version,
        scenario_count: reports
            .iter()
            .flat_map(|entry| {
                entry
                    .occurrences
                    .iter()
                    .map(|occurrence| occurrence.scenario_name.clone())
            })
            .collect::<BTreeSet<_>>()
            .len(),
        technique_count,
        detected_technique_count,
        partial_technique_count,
        not_covered_technique_count,
        coverage_percent: ratio(
            detected_technique_count + partial_technique_count,
            technique_count,
        ),
        techniques: reports,
    })
}

pub fn evaluate_repo_command_line_normalization_benchmark(
    config: &SwarmConfig,
    repo_root: &Path,
) -> Result<CommandLineNormalizationBenchmark, EvasionCoverageError> {
    evaluate_command_line_normalization_benchmark(
        config,
        repo_root,
        &repo_root.join(REPO_COMMAND_LINE_DEOBF_SUITE_PATH),
        &repo_root.join(REPO_COMMAND_LINE_DEOBF_CATALOG_PATH),
    )
}

pub fn evaluate_repo_command_line_normalization_false_positive_regression(
    config: &SwarmConfig,
    repo_root: &Path,
) -> Result<CommandLineNormalizationFalsePositiveReport, EvasionCoverageError> {
    evaluate_command_line_normalization_false_positive_regression(
        config,
        repo_root,
        &repo_root.join(REPO_COMMAND_LINE_DEOBF_SUITE_PATH),
    )
}

pub fn resolve_repo_root(config_path: &Path) -> PathBuf {
    let mut candidates = Vec::new();
    if let Some(parent) = config_path.parent() {
        candidates.push(parent.to_path_buf());
        candidates.extend(parent.ancestors().skip(1).map(Path::to_path_buf));
    }
    if let Ok(current_dir) = std::env::current_dir() {
        candidates.push(current_dir.clone());
        candidates.extend(current_dir.ancestors().skip(1).map(Path::to_path_buf));
    }

    candidates
        .into_iter()
        .find(|candidate| {
            candidate.join(REPO_EVASION_SUITE_PATH).exists()
                && candidate.join(REPO_EVASION_CATALOG_PATH).exists()
        })
        .unwrap_or_else(|| {
            config_path
                .parent()
                .and_then(|path| path.parent())
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf()
        })
}

pub fn evaluate_evasion_coverage(
    config: &SwarmConfig,
    repo_root: &Path,
    suite_path: &Path,
    catalog_path: &Path,
) -> Result<EvasionCoverageSnapshot, EvasionCoverageError> {
    let suite = load_replay_suite_manifest(suite_path)?;
    let scenarios = load_adversarial_scenarios(suite_path)?;
    if scenarios.is_empty() {
        return Err(EvasionCoverageError::InvalidRequest(
            "evasion suite must include at least one adversarial scenario".to_string(),
        ));
    }
    let catalog = load_catalog(repo_root, catalog_path)?;
    if catalog.suite
        != suite_path
            .strip_prefix(repo_root)
            .unwrap_or(suite_path)
            .display()
            .to_string()
        && catalog.suite != suite_path.display().to_string()
    {
        return Err(EvasionCoverageError::CatalogValidation {
            path: catalog_path.to_path_buf(),
            reason: format!(
                "catalog suite `{}` does not match requested suite `{}`",
                catalog.suite,
                suite_path.display()
            ),
        });
    }

    let catalog_by_detector = catalog
        .detectors
        .into_iter()
        .map(|entry| (entry.detector, entry.intentionally_uncovered))
        .collect::<BTreeMap<_, _>>();

    let mut detectors = Vec::with_capacity(EVASION_COVERAGE_DETECTORS.len());
    for detector_id in EVASION_COVERAGE_DETECTORS {
        let detector = build_detector_from_strategy(detector_id, &config.detection)?;
        let mut by_threat_class = BTreeMap::<ThreatClass, ThreatClassAccumulator>::new();
        let mut scenario_reports = Vec::with_capacity(scenarios.len());

        for scenario in &scenarios {
            let entry = by_threat_class
                .entry(scenario.threat_class.clone())
                .or_default();
            entry.scenario_names.insert(scenario.name.clone());
            for technique in &scenario.techniques {
                entry.techniques.insert(technique.clone());
            }
            let mut scenario_detected_payloads = 0usize;
            for event in &scenario.events {
                entry.total_payloads += 1;
                let detected = detector
                    .evaluate(event)
                    .iter()
                    .any(|finding| finding.threat_class == scenario.threat_class);
                if detected {
                    entry.detected_payloads += 1;
                    scenario_detected_payloads += 1;
                }
            }
            scenario_reports.push(EvasionScenarioCoverage {
                scenario_name: scenario.name.clone(),
                threat_class: scenario.threat_class.clone(),
                total_payloads: scenario.events.len(),
                detected_payloads: scenario_detected_payloads,
                catch_rate: ratio(scenario_detected_payloads, scenario.events.len()),
                techniques: scenario.techniques.clone(),
            });
        }

        let threat_classes = by_threat_class
            .into_iter()
            .map(|(threat_class, acc)| EvasionThreatClassCoverage {
                threat_class,
                total_payloads: acc.total_payloads,
                detected_payloads: acc.detected_payloads,
                catch_rate: ratio(acc.detected_payloads, acc.total_payloads),
                scenario_count: acc.scenario_names.len(),
                techniques: acc.techniques.into_iter().collect(),
            })
            .collect::<Vec<_>>();
        let total_payloads = threat_classes
            .iter()
            .map(|entry| entry.total_payloads)
            .sum::<usize>();
        let detected_payloads = threat_classes
            .iter()
            .map(|entry| entry.detected_payloads)
            .sum::<usize>();
        detectors.push(DetectorEvasionCoverageReport {
            detector: detector_id.to_string(),
            total_payloads,
            detected_payloads,
            catch_rate: ratio(detected_payloads, total_payloads),
            threat_classes,
            scenarios: scenario_reports,
            intentionally_uncovered: catalog_by_detector
                .get(detector_id)
                .cloned()
                .unwrap_or_default(),
        });
    }

    Ok(EvasionCoverageSnapshot {
        generated_at_ms: now_ms(),
        suite_name: suite.name,
        suite_path: suite_path.display().to_string(),
        corpus_version: suite.corpus_version,
        detectors,
    })
}

pub fn evaluate_command_line_normalization_benchmark(
    config: &SwarmConfig,
    repo_root: &Path,
    suite_path: &Path,
    catalog_path: &Path,
) -> Result<CommandLineNormalizationBenchmark, EvasionCoverageError> {
    let baseline_config = config_without_command_line_normalization(config)?;
    let baseline =
        evaluate_evasion_coverage(&baseline_config, repo_root, suite_path, catalog_path)?;
    let normalized = evaluate_evasion_coverage(config, repo_root, suite_path, catalog_path)?;
    let scenarios = load_adversarial_scenarios(suite_path)?;
    let scenario_names = scenarios
        .iter()
        .map(|scenario| scenario.name.clone())
        .collect::<Vec<_>>();
    let scenario_names_by_threat = scenarios.iter().fold(
        BTreeMap::<ThreatClass, BTreeSet<String>>::new(),
        |mut acc, scenario| {
            acc.entry(scenario.threat_class.clone())
                .or_default()
                .insert(scenario.name.clone());
            acc
        },
    );

    let mut detector_deltas = Vec::new();
    for detector in COMMAND_LINE_BENCHMARK_DETECTORS {
        for threat_class in [ThreatClass::Execution, ThreatClass::DefenseEvasion] {
            let baseline_entry = threat_class_coverage(&baseline, detector, &threat_class);
            let normalized_entry = threat_class_coverage(&normalized, detector, &threat_class);
            let total_payloads = baseline_entry
                .map(|entry| entry.total_payloads)
                .or_else(|| normalized_entry.map(|entry| entry.total_payloads))
                .unwrap_or_default();
            if total_payloads == 0 {
                continue;
            }

            let baseline_detected_payloads = baseline_entry
                .map(|entry| entry.detected_payloads)
                .unwrap_or_default();
            let normalized_detected_payloads = normalized_entry
                .map(|entry| entry.detected_payloads)
                .unwrap_or_default();
            detector_deltas.push(CommandLineNormalizationCatchRateDelta {
                detector: detector.to_string(),
                threat_class: threat_class.clone(),
                total_payloads,
                baseline_detected_payloads,
                normalized_detected_payloads,
                baseline_catch_rate: ratio(baseline_detected_payloads, total_payloads),
                normalized_catch_rate: ratio(normalized_detected_payloads, total_payloads),
                catch_rate_delta: ratio(normalized_detected_payloads, total_payloads)
                    - ratio(baseline_detected_payloads, total_payloads),
                scenario_names: scenario_names_by_threat
                    .get(&threat_class)
                    .map(|names| names.iter().cloned().collect())
                    .unwrap_or_default(),
            });
        }
    }

    Ok(CommandLineNormalizationBenchmark {
        generated_at_ms: now_ms(),
        suite_name: normalized.suite_name.clone(),
        suite_path: normalized.suite_path.clone(),
        corpus_version: normalized.corpus_version.clone(),
        scenario_names,
        detector_deltas,
    })
}

pub fn evaluate_command_line_normalization_false_positive_regression(
    config: &SwarmConfig,
    _repo_root: &Path,
    suite_path: &Path,
) -> Result<CommandLineNormalizationFalsePositiveReport, EvasionCoverageError> {
    let suite = load_replay_suite_manifest(suite_path)?;
    let benign_scenarios = load_benign_scenarios(suite_path)?;
    let baseline_config = config_without_command_line_normalization(config)?;

    let mut detector_results = Vec::new();
    for detector in COMMAND_LINE_NORMALIZATION_DETECTORS {
        let baseline_detector = build_detector_from_strategy(detector, &baseline_config.detection)?;
        let normalized_detector = build_detector_from_strategy(detector, &config.detection)?;
        let total_benign_payloads = benign_scenarios
            .iter()
            .map(|scenario| scenario.events.len())
            .sum::<usize>();
        let baseline_false_positive_payloads = benign_scenarios
            .iter()
            .flat_map(|scenario| scenario.events.iter())
            .filter(|event| !baseline_detector.evaluate(event).is_empty())
            .count();
        let normalized_false_positive_payloads = benign_scenarios
            .iter()
            .flat_map(|scenario| scenario.events.iter())
            .filter(|event| !normalized_detector.evaluate(event).is_empty())
            .count();
        detector_results.push(CommandLineNormalizationFalsePositiveDelta {
            detector: detector.to_string(),
            total_benign_payloads,
            baseline_false_positive_payloads,
            normalized_false_positive_payloads,
            false_positive_delta: normalized_false_positive_payloads as isize
                - baseline_false_positive_payloads as isize,
            scenario_names: benign_scenarios
                .iter()
                .map(|scenario| scenario.name.clone())
                .collect(),
        });
    }

    Ok(CommandLineNormalizationFalsePositiveReport {
        generated_at_ms: now_ms(),
        suite_name: suite.name,
        suite_path: suite_path.display().to_string(),
        corpus_version: suite.corpus_version,
        scenario_names: benign_scenarios
            .iter()
            .map(|scenario| scenario.name.clone())
            .collect(),
        detector_results,
    })
}

pub fn publish_snapshot_to_metrics(
    metrics: &CriticalPathMetrics,
    snapshot: &EvasionCoverageSnapshot,
) {
    for detector in &snapshot.detectors {
        metrics.observe_evasion_coverage(
            &detector.detector,
            "all",
            &snapshot.suite_name,
            detector.total_payloads as u64,
            detector.detected_payloads as u64,
            detector.catch_rate,
        );
        for threat_class in &detector.threat_classes {
            metrics.observe_evasion_coverage(
                &detector.detector,
                &threat_class_slug(&threat_class.threat_class),
                &snapshot.suite_name,
                threat_class.total_payloads as u64,
                threat_class.detected_payloads as u64,
                threat_class.catch_rate,
            );
        }
    }
}

pub fn actionable_gaps_for_detector(
    snapshot: &EvasionCoverageSnapshot,
    detector: &str,
) -> Vec<EvasionActionableGap> {
    let Some(report) = snapshot
        .detectors
        .iter()
        .find(|entry| entry.detector == detector)
    else {
        return Vec::new();
    };
    let intentionally_uncovered = report.intentionally_uncovered.iter().fold(
        BTreeMap::<ThreatClass, BTreeSet<String>>::new(),
        |mut acc, gap| {
            acc.entry(gap.threat_class.clone())
                .or_default()
                .insert(gap.technique.clone());
            acc
        },
    );

    let mut gaps = report
        .threat_classes
        .iter()
        .filter_map(|entry| {
            let actionable_techniques = entry
                .techniques
                .iter()
                .filter(|technique| {
                    !intentionally_uncovered
                        .get(&entry.threat_class)
                        .is_some_and(|excluded| excluded.contains(*technique))
                })
                .cloned()
                .collect::<Vec<_>>();
            let missed_payloads = entry.total_payloads.saturating_sub(entry.detected_payloads);
            if missed_payloads == 0 || actionable_techniques.is_empty() {
                return None;
            }
            Some(EvasionActionableGap {
                threat_class: entry.threat_class.clone(),
                total_payloads: entry.total_payloads,
                detected_payloads: entry.detected_payloads,
                missed_payloads,
                catch_rate: entry.catch_rate,
                actionable_techniques,
            })
        })
        .collect::<Vec<_>>();
    gaps.sort_by(|left, right| {
        right
            .missed_payloads
            .cmp(&left.missed_payloads)
            .then_with(|| {
                left.catch_rate
                    .partial_cmp(&right.catch_rate)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| {
                threat_class_slug(&left.threat_class).cmp(&threat_class_slug(&right.threat_class))
            })
    });
    gaps
}

fn mapped_detectors_for_adversary_scenario(
    scenario_name: &str,
) -> Result<&'static [&'static str], EvasionCoverageError> {
    match scenario_name {
        "evasion_execution_office_chains" => {
            Ok(&["suspicious_process_tree", "suspicious_scripting"])
        }
        "evasion_defense_evasion_fileless" => Ok(&["fileless_execution", "suspicious_scripting"]),
        "evasion_command_and_control_network" => Ok(&["network_connect"]),
        "evasion_data_exfiltration_dns" => Ok(&["dns_exfiltration"]),
        "evasion_lateral_movement_remote_admin" => Ok(&["lateral_movement"]),
        "evasion_credential_access_harvest" => Ok(&["credential_access"]),
        "evasion_persistence_autostart" => Ok(&["persistence"]),
        other => Err(EvasionCoverageError::InvalidRequest(format!(
            "no mapped detector set for adversarial scenario `{other}`"
        ))),
    }
}

fn detector_intentionally_uncovered(
    snapshot: &EvasionCoverageSnapshot,
    detector: &str,
    threat_class: &ThreatClass,
    techniques: &[String],
) -> bool {
    snapshot
        .detectors
        .iter()
        .find(|entry| entry.detector == detector)
        .is_some_and(|entry| {
            techniques.iter().all(|technique| {
                entry
                    .intentionally_uncovered
                    .iter()
                    .any(|gap| gap.technique == *technique && gap.threat_class == *threat_class)
            })
        })
}

fn load_catalog(
    repo_root: &Path,
    catalog_path: &Path,
) -> Result<EvasionTechniqueCatalog, EvasionCoverageError> {
    let raw =
        fs::read_to_string(catalog_path).map_err(|source| EvasionCoverageError::CatalogRead {
            path: catalog_path.to_path_buf(),
            source,
        })?;
    let catalog = serde_yaml::from_str::<EvasionTechniqueCatalog>(&raw).map_err(|source| {
        EvasionCoverageError::CatalogParse {
            path: catalog_path.to_path_buf(),
            source,
        }
    })?;
    validate_catalog(repo_root, catalog_path, &catalog)?;
    Ok(catalog)
}

fn validate_catalog(
    repo_root: &Path,
    catalog_path: &Path,
    catalog: &EvasionTechniqueCatalog,
) -> Result<(), EvasionCoverageError> {
    if catalog.schema_version != 1 {
        return Err(EvasionCoverageError::CatalogValidation {
            path: catalog_path.to_path_buf(),
            reason: format!("unsupported schema_version `{}`", catalog.schema_version),
        });
    }
    if catalog.suite.trim().is_empty() {
        return Err(EvasionCoverageError::CatalogValidation {
            path: catalog_path.to_path_buf(),
            reason: "suite must not be empty".to_string(),
        });
    }
    let suite_path = repo_root.join(&catalog.suite);
    if !suite_path.exists() {
        return Err(EvasionCoverageError::CatalogValidation {
            path: catalog_path.to_path_buf(),
            reason: format!("referenced suite `{}` does not exist", suite_path.display()),
        });
    }
    for detector in &catalog.detectors {
        if detector.detector.trim().is_empty() {
            return Err(EvasionCoverageError::CatalogValidation {
                path: catalog_path.to_path_buf(),
                reason: "detector name must not be empty".to_string(),
            });
        }
        if !EVASION_COVERAGE_DETECTORS.contains(&detector.detector.as_str()) {
            return Err(EvasionCoverageError::CatalogValidation {
                path: catalog_path.to_path_buf(),
                reason: format!("unsupported detector `{}`", detector.detector),
            });
        }
        for gap in &detector.intentionally_uncovered {
            if gap.technique.trim().is_empty() {
                return Err(EvasionCoverageError::CatalogValidation {
                    path: catalog_path.to_path_buf(),
                    reason: format!(
                        "detector `{}` has an intentionally uncovered technique with an empty technique id",
                        detector.detector
                    ),
                });
            }
            if gap.rationale.trim().is_empty() {
                return Err(EvasionCoverageError::CatalogValidation {
                    path: catalog_path.to_path_buf(),
                    reason: format!(
                        "detector `{}` technique `{}` must include rationale",
                        detector.detector, gap.technique
                    ),
                });
            }
        }
    }
    Ok(())
}

fn load_adversarial_scenarios(
    suite_path: &Path,
) -> Result<Vec<LoadedAdversarialScenario>, EvasionCoverageError> {
    let suite = load_replay_suite_manifest(suite_path)?;
    let mut scenarios = Vec::new();
    for scenario_ref in &suite.scenarios {
        let path = resolve_manifest_relative_path(suite_path, scenario_ref);
        let loaded = load_scenario_manifest(&path)?;
        if loaded.manifest.metadata.class != ReplayScenarioClass::Adversarial {
            continue;
        }
        let events = match loaded.manifest.input {
            ReplayScenarioInput::Events { events } => events
                .into_iter()
                .map(|step| step.event)
                .collect::<Vec<_>>(),
            ReplayScenarioInput::ReplayBundles { .. } => {
                return Err(EvasionCoverageError::InvalidRequest(format!(
                    "scenario `{}` uses replay bundles; evasion coverage requires event-backed scenarios",
                    loaded.manifest.name
                )));
            }
        };
        let threat_class = loaded
            .manifest
            .metadata
            .threat_class
            .clone()
            .or_else(|| {
                events
                    .first()
                    .map(|event| threat_class_from_payload(&event.payload))
            })
            .ok_or_else(|| {
                EvasionCoverageError::InvalidRequest(format!(
                    "scenario `{}` could not derive a threat class",
                    loaded.manifest.name
                ))
            })?;
        scenarios.push(LoadedAdversarialScenario {
            name: loaded.manifest.name,
            threat_class,
            techniques: loaded.manifest.metadata.techniques,
            events,
        });
    }
    Ok(scenarios)
}

fn load_benign_scenarios(
    suite_path: &Path,
) -> Result<Vec<LoadedBenignScenario>, EvasionCoverageError> {
    let suite = load_replay_suite_manifest(suite_path)?;
    let mut scenarios = Vec::new();
    for scenario_ref in &suite.scenarios {
        let path = resolve_manifest_relative_path(suite_path, scenario_ref);
        let loaded = load_scenario_manifest(&path)?;
        if loaded.manifest.metadata.class != ReplayScenarioClass::Benign {
            continue;
        }
        let events = match loaded.manifest.input {
            ReplayScenarioInput::Events { events } => events
                .into_iter()
                .map(|step| step.event)
                .collect::<Vec<_>>(),
            ReplayScenarioInput::ReplayBundles { .. } => {
                return Err(EvasionCoverageError::InvalidRequest(format!(
                    "scenario `{}` uses replay bundles; benign regression requires event-backed scenarios",
                    loaded.manifest.name
                )));
            }
        };
        scenarios.push(LoadedBenignScenario {
            name: loaded.manifest.name,
            events,
        });
    }
    Ok(scenarios)
}

fn config_without_command_line_normalization(
    config: &SwarmConfig,
) -> Result<SwarmConfig, EvasionCoverageError> {
    let mut baseline = config.clone();
    let disabled = CommandLineNormalizationProfile {
        strip_caret_escapes: false,
        expand_environment_variables: false,
        normalize_unicode_homoglyphs: false,
        decode_encoded_arguments: false,
    };

    let mut profile = suspicious_process_tree_profile(&baseline.detection)?;
    profile.command_line_normalization = disabled.clone();
    baseline.detection.profiles.suspicious_process_tree =
        Some(serialize_profile(profile, "suspicious_process_tree")?);

    let mut profile = fileless_execution_profile(&baseline.detection)?;
    profile.command_line_normalization = disabled.clone();
    baseline.detection.profiles.fileless_execution =
        Some(serialize_profile(profile, "fileless_execution")?);

    let mut profile = lateral_movement_profile(&baseline.detection)?;
    profile.command_line_normalization = disabled.clone();
    baseline.detection.profiles.lateral_movement =
        Some(serialize_profile(profile, "lateral_movement")?);

    let mut profile = suspicious_scripting_profile(&baseline.detection)?;
    profile.command_line_normalization = disabled.clone();
    baseline.detection.profiles.suspicious_scripting =
        Some(serialize_profile(profile, "suspicious_scripting")?);

    let mut profile = supply_chain_profile(&baseline.detection)?;
    profile.command_line_normalization = disabled;
    baseline.detection.profiles.supply_chain = Some(serialize_profile(profile, "supply_chain")?);

    Ok(baseline)
}

fn serialize_profile<T: Serialize>(
    profile: T,
    strategy: &'static str,
) -> Result<serde_json::Value, EvasionCoverageError> {
    serde_json::to_value(profile).map_err(|source| {
        EvasionCoverageError::InvalidRequest(format!(
            "failed to serialize detector profile `{strategy}`: {source}"
        ))
    })
}

fn threat_class_coverage<'a>(
    snapshot: &'a EvasionCoverageSnapshot,
    detector: &str,
    threat_class: &ThreatClass,
) -> Option<&'a EvasionThreatClassCoverage> {
    snapshot
        .detectors
        .iter()
        .find(|entry| entry.detector == detector)
        .and_then(|report| {
            report
                .threat_classes
                .iter()
                .find(|entry| &entry.threat_class == threat_class)
        })
}

fn scenario_coverage<'a>(
    snapshot: &'a EvasionCoverageSnapshot,
    detector: &str,
    scenario_name: &str,
) -> Option<&'a EvasionScenarioCoverage> {
    snapshot
        .detectors
        .iter()
        .find(|entry| entry.detector == detector)
        .and_then(|report| {
            report
                .scenarios
                .iter()
                .find(|entry| entry.scenario_name == scenario_name)
        })
}

fn threat_class_from_payload(payload: &TelemetryPayload) -> ThreatClass {
    match payload {
        TelemetryPayload::ProcessStart(_) => ThreatClass::Execution,
        TelemetryPayload::ProcessMemoryAccess(access) => {
            let target = access.target_process.to_ascii_lowercase();
            if ["lsass", "winlogon", "wininit", "services", "csrss"]
                .iter()
                .any(|value| target.contains(value))
            {
                ThreatClass::PrivilegeEscalation
            } else {
                ThreatClass::DefenseEvasion
            }
        }
        TelemetryPayload::NetworkConnect(_) => ThreatClass::CommandAndControl,
        TelemetryPayload::DnsQuery(_) => ThreatClass::DataExfiltration,
        TelemetryPayload::CloudTrail(_) => ThreatClass::CredentialAccess,
        TelemetryPayload::KubernetesAudit(_) => ThreatClass::PrivilegeEscalation,
        TelemetryPayload::RegistryPersistence(_) | TelemetryPayload::FilePersistence(_) => {
            ThreatClass::Persistence
        }
        TelemetryPayload::RegistryAccess(_) => ThreatClass::CredentialAccess,
        TelemetryPayload::AuthenticationEvent(_) => ThreatClass::LateralMovement,
        TelemetryPayload::InfrastructureHealth(_)
        | TelemetryPayload::ThermalAnomaly(_)
        | TelemetryPayload::ResourceExhaustion(_) => ThreatClass::Impact,
    }
}

fn threat_class_slug(threat_class: &ThreatClass) -> String {
    serde_json::to_value(threat_class)
        .ok()
        .and_then(|value| value.as_str().map(ToString::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        (numerator as f64 / denominator as f64).clamp(0.0, 1.0)
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        REPO_COMMAND_LINE_DEOBF_CATALOG_PATH, REPO_COMMAND_LINE_DEOBF_SUITE_PATH,
        REPO_EVASION_CATALOG_PATH, REPO_EVASION_SUITE_PATH, actionable_gaps_for_detector,
        evaluate_repo_command_line_normalization_benchmark,
        evaluate_repo_command_line_normalization_false_positive_regression,
        evaluate_repo_evasion_coverage, resolve_repo_root,
        summarize_repo_adversary_emulation_coverage,
    };
    use crate::config::load_config;
    use std::path::{Path, PathBuf};
    use swarm_core::pheromone::ThreatClass;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("workspace root")
            .to_path_buf()
    }

    #[test]
    fn repo_evasion_snapshot_provides_ten_payloads_per_threat_class() {
        let root = repo_root();
        let config = load_config(root.join("rulesets/default.yaml")).unwrap();
        let snapshot = evaluate_repo_evasion_coverage(&config, &root).unwrap();

        assert!(snapshot.suite_path.ends_with(REPO_EVASION_SUITE_PATH));
        let suspicious = snapshot
            .detectors
            .iter()
            .find(|detector| detector.detector == "suspicious_process_tree")
            .expect("suspicious_process_tree coverage");
        for entry in &suspicious.threat_classes {
            assert!(
                entry.total_payloads >= 10,
                "expected at least ten payloads for {:?}, got {}",
                entry.threat_class,
                entry.total_payloads
            );
        }
    }

    #[test]
    fn repo_evasion_snapshot_loads_catalog_rationales() {
        let root = repo_root();
        let config = load_config(root.join("rulesets/default.yaml")).unwrap();
        let snapshot = evaluate_repo_evasion_coverage(&config, &root).unwrap();

        let fileless = snapshot
            .detectors
            .iter()
            .find(|detector| detector.detector == "fileless_execution")
            .expect("fileless coverage");
        assert!(!fileless.intentionally_uncovered.is_empty());
        assert!(root.join(REPO_EVASION_CATALOG_PATH).exists());
    }

    #[test]
    fn resolve_repo_root_falls_back_to_workspace_when_config_is_external() {
        let root = repo_root();
        let resolved = resolve_repo_root(Path::new("/tmp/swarm-mounted/default.yaml"));
        assert_eq!(resolved, root);
    }

    #[test]
    fn actionable_gaps_exclude_intentionally_uncovered_techniques() {
        let root = repo_root();
        let config = load_config(root.join("rulesets/default.yaml")).unwrap();
        let snapshot = evaluate_repo_evasion_coverage(&config, &root).unwrap();
        let gaps = actionable_gaps_for_detector(&snapshot, "fileless_execution");
        assert!(!gaps.is_empty());
        assert!(gaps.iter().all(|gap| gap.missed_payloads > 0));
        assert!(
            gaps.iter()
                .flat_map(|gap| gap.actionable_techniques.iter())
                .all(|technique| technique != "T1620")
        );
    }

    #[test]
    fn command_line_normalization_benchmark_improves_execution_and_defense_evasion() {
        let root = repo_root();
        let config = load_config(root.join("rulesets/default.yaml")).unwrap();
        let benchmark = evaluate_repo_command_line_normalization_benchmark(&config, &root).unwrap();

        assert!(
            benchmark
                .suite_path
                .ends_with(REPO_COMMAND_LINE_DEOBF_SUITE_PATH)
        );
        let execution = benchmark
            .detector_deltas
            .iter()
            .find(|delta| {
                delta.detector == "suspicious_scripting"
                    && delta.threat_class == ThreatClass::Execution
            })
            .expect("execution benchmark delta");
        assert!(
            execution.catch_rate_delta >= 0.15,
            "expected execution catch-rate improvement >= 0.15, got {}",
            execution.catch_rate_delta
        );
        assert!(
            execution
                .scenario_names
                .iter()
                .any(|name| { name == "command_line_deobfuscation_execution" })
        );

        let defense_evasion = benchmark
            .detector_deltas
            .iter()
            .find(|delta| {
                delta.detector == "fileless_execution"
                    && delta.threat_class == ThreatClass::DefenseEvasion
            })
            .expect("defense evasion benchmark delta");
        assert!(
            defense_evasion.catch_rate_delta >= 0.15,
            "expected defense-evasion catch-rate improvement >= 0.15, got {}",
            defense_evasion.catch_rate_delta
        );
        assert!(root.join(REPO_COMMAND_LINE_DEOBF_CATALOG_PATH).exists());
    }

    #[test]
    fn command_line_normalization_regression_stays_zero_on_benign_controls() {
        let root = repo_root();
        let config = load_config(root.join("rulesets/default.yaml")).unwrap();
        let regression =
            evaluate_repo_command_line_normalization_false_positive_regression(&config, &root)
                .unwrap();

        assert!(
            regression
                .suite_path
                .ends_with(REPO_COMMAND_LINE_DEOBF_SUITE_PATH)
        );
        assert!(
            regression
                .scenario_names
                .iter()
                .any(|name| name == "command_line_deobfuscation_benign")
        );
        assert!(regression.detector_results.iter().all(|result| {
            result.baseline_false_positive_payloads == 0
                && result.normalized_false_positive_payloads == 0
                && result.false_positive_delta == 0
        }));
    }

    #[test]
    fn repo_adversary_emulation_coverage_report_meets_floor() {
        let root = repo_root();
        let config = load_config(root.join("rulesets/default.yaml")).unwrap();
        let report = summarize_repo_adversary_emulation_coverage(&config, &root).unwrap();

        assert_eq!(report.scenario_count, 7);
        assert!(
            report.technique_count >= 20,
            "expected at least twenty mapped techniques, got {}",
            report.technique_count
        );
        assert!(
            report.coverage_percent >= 0.60,
            "expected coverage floor >= 0.60, got {}",
            report.coverage_percent
        );
        assert!(
            report
                .techniques
                .iter()
                .any(|entry| entry.technique == "T1047"),
            "expected WMI lateral movement technique mapping"
        );
    }
}
