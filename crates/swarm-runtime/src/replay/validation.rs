use super::types::{
    DetectorCandidateManifest, DetectorExperimentManifest, LoadedDetectorExperiment,
    LoadedReplayScenario, LoadedReplaySuite, ReplayHarnessError, ReplayScenarioInput,
    ReplayScenarioManifest, ReplaySuiteManifest, VerificationCorpusManifest,
};
use std::fs;
use std::path::Path;

pub fn load_scenario_manifest(
    path: impl AsRef<Path>,
) -> Result<LoadedReplayScenario, ReplayHarnessError> {
    let path = path.as_ref().to_path_buf();
    let raw = fs::read_to_string(&path).map_err(|source| ReplayHarnessError::ScenarioRead {
        path: path.clone(),
        source,
    })?;
    let manifest = serde_yaml::from_str::<ReplayScenarioManifest>(&raw).map_err(|source| {
        ReplayHarnessError::ScenarioParse {
            path: path.clone(),
            source,
        }
    })?;
    validate_manifest(&path, &manifest)?;
    Ok(LoadedReplayScenario { path, manifest })
}

pub fn load_replay_suite_manifest(
    path: impl AsRef<Path>,
) -> Result<ReplaySuiteManifest, ReplayHarnessError> {
    Ok(load_suite_manifest(path)?.manifest)
}

pub(super) fn load_suite_manifest(
    path: impl AsRef<Path>,
) -> Result<LoadedReplaySuite, ReplayHarnessError> {
    let path = path.as_ref().to_path_buf();
    let raw = fs::read_to_string(&path).map_err(|source| ReplayHarnessError::SuiteRead {
        path: path.clone(),
        source,
    })?;
    let manifest = serde_yaml::from_str::<ReplaySuiteManifest>(&raw).map_err(|source| {
        ReplayHarnessError::SuiteParse {
            path: path.clone(),
            source,
        }
    })?;
    validate_suite_manifest(&path, &manifest)?;
    Ok(LoadedReplaySuite { path, manifest })
}

pub(super) fn load_experiment_manifest(
    path: impl AsRef<Path>,
) -> Result<LoadedDetectorExperiment, ReplayHarnessError> {
    let path = path.as_ref().to_path_buf();
    let raw = fs::read_to_string(&path).map_err(|source| ReplayHarnessError::ExperimentRead {
        path: path.clone(),
        source,
    })?;
    let manifest = serde_yaml::from_str::<DetectorExperimentManifest>(&raw).map_err(|source| {
        ReplayHarnessError::ExperimentParse {
            path: path.clone(),
            source,
        }
    })?;
    validate_experiment_manifest(&path, &manifest)?;
    Ok(LoadedDetectorExperiment { path, manifest })
}

pub fn load_detector_experiment_manifest(
    path: impl AsRef<Path>,
) -> Result<DetectorExperimentManifest, ReplayHarnessError> {
    Ok(load_experiment_manifest(path)?.manifest)
}

pub fn load_verification_manifest(
    path: impl AsRef<Path>,
) -> Result<VerificationCorpusManifest, ReplayHarnessError> {
    let path = path.as_ref().to_path_buf();
    let raw = fs::read_to_string(&path).map_err(|source| ReplayHarnessError::VerificationRead {
        path: path.clone(),
        source,
    })?;
    let manifest = serde_yaml::from_str::<VerificationCorpusManifest>(&raw).map_err(|source| {
        ReplayHarnessError::VerificationParse {
            path: path.clone(),
            source,
        }
    })?;
    validate_verification_manifest(&path, &manifest)?;
    Ok(manifest)
}

fn validate_manifest(
    path: &Path,
    manifest: &ReplayScenarioManifest,
) -> Result<(), ReplayHarnessError> {
    if manifest.name.trim().is_empty() {
        return Err(ReplayHarnessError::ScenarioValidation {
            path: path.to_path_buf(),
            reason: "scenario name must not be empty".to_string(),
        });
    }
    if manifest.description.trim().is_empty() {
        return Err(ReplayHarnessError::ScenarioValidation {
            path: path.to_path_buf(),
            reason: "scenario description must not be empty".to_string(),
        });
    }
    if manifest.seed_time_ms <= 0 {
        return Err(ReplayHarnessError::ScenarioValidation {
            path: path.to_path_buf(),
            reason: "seed_time_ms must be greater than zero".to_string(),
        });
    }
    if manifest.requested_by.trim().is_empty() {
        return Err(ReplayHarnessError::ScenarioValidation {
            path: path.to_path_buf(),
            reason: "requested_by must not be empty".to_string(),
        });
    }
    match &manifest.input {
        ReplayScenarioInput::Events { events } if events.is_empty() => {
            return Err(ReplayHarnessError::ScenarioValidation {
                path: path.to_path_buf(),
                reason: "event-backed scenarios must include at least one event".to_string(),
            });
        }
        ReplayScenarioInput::ReplayBundles { paths } if paths.is_empty() => {
            return Err(ReplayHarnessError::ScenarioValidation {
                path: path.to_path_buf(),
                reason: "bundle-backed scenarios must include at least one path".to_string(),
            });
        }
        ReplayScenarioInput::Events { .. } | ReplayScenarioInput::ReplayBundles { .. } => {}
    }
    Ok(())
}

fn validate_suite_manifest(
    path: &Path,
    manifest: &ReplaySuiteManifest,
) -> Result<(), ReplayHarnessError> {
    if manifest.name.trim().is_empty() {
        return Err(ReplayHarnessError::SuiteValidation {
            path: path.to_path_buf(),
            reason: "suite name must not be empty".to_string(),
        });
    }
    if manifest.description.trim().is_empty() {
        return Err(ReplayHarnessError::SuiteValidation {
            path: path.to_path_buf(),
            reason: "suite description must not be empty".to_string(),
        });
    }
    if manifest.corpus_version.trim().is_empty() {
        return Err(ReplayHarnessError::SuiteValidation {
            path: path.to_path_buf(),
            reason: "corpus_version must not be empty".to_string(),
        });
    }
    if manifest.scenarios.is_empty() {
        return Err(ReplayHarnessError::SuiteValidation {
            path: path.to_path_buf(),
            reason: "suite must reference at least one scenario".to_string(),
        });
    }
    Ok(())
}

fn validate_experiment_manifest(
    path: &Path,
    manifest: &DetectorExperimentManifest,
) -> Result<(), ReplayHarnessError> {
    if manifest.name.trim().is_empty() {
        return Err(ReplayHarnessError::ExperimentValidation {
            path: path.to_path_buf(),
            reason: "experiment name must not be empty".to_string(),
        });
    }
    if manifest.description.trim().is_empty() {
        return Err(ReplayHarnessError::ExperimentValidation {
            path: path.to_path_buf(),
            reason: "experiment description must not be empty".to_string(),
        });
    }
    if manifest.corpus.suite.trim().is_empty() {
        return Err(ReplayHarnessError::ExperimentValidation {
            path: path.to_path_buf(),
            reason: "experiment must reference a suite path".to_string(),
        });
    }
    if manifest.verification.corpus.trim().is_empty() {
        return Err(ReplayHarnessError::ExperimentValidation {
            path: path.to_path_buf(),
            reason: "experiment must reference a verification corpus path".to_string(),
        });
    }
    if manifest.lineage.parent_strategy_id.trim().is_empty() {
        return Err(ReplayHarnessError::ExperimentValidation {
            path: path.to_path_buf(),
            reason: "lineage.parent_strategy_id must not be empty".to_string(),
        });
    }
    if manifest.lineage.mutation.trim().is_empty() {
        return Err(ReplayHarnessError::ExperimentValidation {
            path: path.to_path_buf(),
            reason: "lineage.mutation must not be empty".to_string(),
        });
    }
    if manifest.lineage.rationale.trim().is_empty() {
        return Err(ReplayHarnessError::ExperimentValidation {
            path: path.to_path_buf(),
            reason: "lineage.rationale must not be empty".to_string(),
        });
    }
    match &manifest.candidate {
        DetectorCandidateManifest::SuspiciousProcessTree {
            strategy_id,
            description,
            profile,
        } => {
            if strategy_id.trim().is_empty() {
                return Err(ReplayHarnessError::ExperimentValidation {
                    path: path.to_path_buf(),
                    reason: "candidate strategy_id must not be empty".to_string(),
                });
            }
            if description.trim().is_empty() {
                return Err(ReplayHarnessError::ExperimentValidation {
                    path: path.to_path_buf(),
                    reason: "candidate description must not be empty".to_string(),
                });
            }
            if profile.suspicious_parents.is_empty() || profile.suspicious_children.is_empty() {
                return Err(ReplayHarnessError::ExperimentValidation {
                    path: path.to_path_buf(),
                    reason: "candidate profile must include suspicious parents and children"
                        .to_string(),
                });
            }
        }
        DetectorCandidateManifest::DnsExfiltration {
            strategy_id,
            description,
            ..
        }
        | DetectorCandidateManifest::FilelessExecution {
            strategy_id,
            description,
            ..
        }
        | DetectorCandidateManifest::BehavioralAnomaly {
            strategy_id,
            description,
            ..
        }
        | DetectorCandidateManifest::LateralMovement {
            strategy_id,
            description,
            ..
        }
        | DetectorCandidateManifest::CredentialAccess {
            strategy_id,
            description,
            ..
        }
        | DetectorCandidateManifest::SuspiciousScripting {
            strategy_id,
            description,
            ..
        }
        | DetectorCandidateManifest::Persistence {
            strategy_id,
            description,
            ..
        }
        | DetectorCandidateManifest::SupplyChain {
            strategy_id,
            description,
            ..
        }
        | DetectorCandidateManifest::NetworkConnect {
            strategy_id,
            description,
            ..
        } => {
            if strategy_id.trim().is_empty() {
                return Err(ReplayHarnessError::ExperimentValidation {
                    path: path.to_path_buf(),
                    reason: "candidate strategy_id must not be empty".to_string(),
                });
            }
            if description.trim().is_empty() {
                return Err(ReplayHarnessError::ExperimentValidation {
                    path: path.to_path_buf(),
                    reason: "candidate description must not be empty".to_string(),
                });
            }
        }
    }
    Ok(())
}

fn validate_verification_manifest(
    path: &Path,
    manifest: &VerificationCorpusManifest,
) -> Result<(), ReplayHarnessError> {
    if manifest.name.trim().is_empty() {
        return Err(ReplayHarnessError::VerificationValidation {
            path: path.to_path_buf(),
            reason: "verification corpus name must not be empty".to_string(),
        });
    }
    if manifest.description.trim().is_empty() {
        return Err(ReplayHarnessError::VerificationValidation {
            path: path.to_path_buf(),
            reason: "verification corpus description must not be empty".to_string(),
        });
    }
    if manifest.known_bad.suite.trim().is_empty() {
        return Err(ReplayHarnessError::VerificationValidation {
            path: path.to_path_buf(),
            reason: "known_bad.suite must not be empty".to_string(),
        });
    }
    if manifest.benign_controls.scenarios.is_empty() {
        return Err(ReplayHarnessError::VerificationValidation {
            path: path.to_path_buf(),
            reason: "benign_controls.scenarios must include at least one scenario".to_string(),
        });
    }
    if manifest.canonical_templates.is_empty() {
        return Err(ReplayHarnessError::VerificationValidation {
            path: path.to_path_buf(),
            reason: "canonical_templates must include at least one threat-class template"
                .to_string(),
        });
    }
    if manifest.resource_budgets.max_detect_latency_us == 0 {
        return Err(ReplayHarnessError::VerificationValidation {
            path: path.to_path_buf(),
            reason: "resource_budgets.max_detect_latency_us must be greater than zero".to_string(),
        });
    }
    if !(0.0..=1.0).contains(&manifest.resource_budgets.max_false_positive_rate) {
        return Err(ReplayHarnessError::VerificationValidation {
            path: path.to_path_buf(),
            reason: "resource_budgets.max_false_positive_rate must be between 0.0 and 1.0"
                .to_string(),
        });
    }
    if manifest.resource_budgets.max_total_detections == 0 {
        return Err(ReplayHarnessError::VerificationValidation {
            path: path.to_path_buf(),
            reason: "resource_budgets.max_total_detections must be greater than zero".to_string(),
        });
    }
    for template in &manifest.canonical_templates {
        if template.name.trim().is_empty() {
            return Err(ReplayHarnessError::VerificationValidation {
                path: path.to_path_buf(),
                reason: "canonical template names must not be empty".to_string(),
            });
        }
        if template.event.event_id.trim().is_empty() {
            return Err(ReplayHarnessError::VerificationValidation {
                path: path.to_path_buf(),
                reason: "canonical template event_id must not be empty".to_string(),
            });
        }
        if template.event.source.trim().is_empty() {
            return Err(ReplayHarnessError::VerificationValidation {
                path: path.to_path_buf(),
                reason: "canonical template source must not be empty".to_string(),
            });
        }
        if template.event.timestamp <= 0 {
            return Err(ReplayHarnessError::VerificationValidation {
                path: path.to_path_buf(),
                reason: "canonical template timestamps must be greater than zero".to_string(),
            });
        }
    }
    Ok(())
}
