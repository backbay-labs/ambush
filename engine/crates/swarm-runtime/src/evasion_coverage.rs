use crate::config::RuntimeConfigError;
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
use swarm_whisker::DetectionStrategy;

pub const REPO_EVASION_SUITE_PATH: &str = "scenario-suites/evasion-breadth-v1.yaml";
pub const REPO_EVASION_CATALOG_PATH: &str = "rulesets/evasion/attack-technique-catalog.yaml";

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

#[derive(Debug, thiserror::Error)]
pub enum EvasionCoverageError {
    #[error(transparent)]
    Replay(#[from] ReplayHarnessError),

    #[error(transparent)]
    DetectorFactory(#[from] DetectorFactoryError),

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
pub struct DetectorEvasionCoverageReport {
    pub detector: String,
    pub total_payloads: usize,
    pub detected_payloads: usize,
    pub catch_rate: f64,
    pub threat_classes: Vec<EvasionThreatClassCoverage>,
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

        for scenario in &scenarios {
            let entry = by_threat_class
                .entry(scenario.threat_class.clone())
                .or_default();
            entry.scenario_names.insert(scenario.name.clone());
            for technique in &scenario.techniques {
                entry.techniques.insert(technique.clone());
            }
            for event in &scenario.events {
                entry.total_payloads += 1;
                let detected = detector
                    .evaluate(event)
                    .iter()
                    .any(|finding| finding.threat_class == scenario.threat_class);
                if detected {
                    entry.detected_payloads += 1;
                }
            }
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
        REPO_EVASION_CATALOG_PATH, REPO_EVASION_SUITE_PATH, actionable_gaps_for_detector,
        evaluate_repo_evasion_coverage, resolve_repo_root,
    };
    use crate::config::load_config;
    use std::path::{Path, PathBuf};

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
}
