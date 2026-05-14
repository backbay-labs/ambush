use super::types::FormalSafetyInvariantEvaluation;
use super::*;

/// Harness that creates proof artifacts from passed verification evidence.
#[derive(Debug, Clone)]
pub struct DefaultFormalSafetyGate {
    config_path: PathBuf,
    config: SwarmConfig,
}

pub struct DefaultEvolutionProofHarness {
    pub config_path: PathBuf,
    pub config: SwarmConfig,
    pub store: FileEvolutionProofStore,
}

impl DefaultFormalSafetyGate {
    pub fn from_path(config_path: impl AsRef<Path>) -> Result<Self, FormalSafetyGateError> {
        let config_path = config_path.as_ref();
        let config =
            load_config(config_path).map_err(|error| FormalSafetyGateError::Validation {
                path: config_path.to_path_buf(),
                reason: error.to_string(),
            })?;
        Ok(Self {
            config_path: config_path.to_path_buf(),
            config,
        })
    }

    pub fn from_config(config_path: impl Into<PathBuf>, config: SwarmConfig) -> Self {
        Self {
            config_path: config_path.into(),
            config,
        }
    }

    fn load_bundles(
        &self,
    ) -> Result<Vec<(PathBuf, FormalSafetyInvariantBundle, String)>, FormalSafetyGateError> {
        let mut bundles = Vec::new();
        for bundle_path in &self.config.evolution.safety_gate.invariant_bundle_paths {
            let resolved = resolve_config_relative_path(&self.config_path, bundle_path);
            let raw =
                fs::read_to_string(&resolved).map_err(|source| FormalSafetyGateError::Read {
                    path: resolved.clone(),
                    source,
                })?;
            let bundle: FormalSafetyInvariantBundle =
                serde_yaml::from_str(&raw).map_err(|source| FormalSafetyGateError::Parse {
                    path: resolved.clone(),
                    source,
                })?;
            validate_formal_safety_bundle(&resolved, &bundle)?;
            let bundle_hash = sha256_hex(&bundle)?;
            bundles.push((resolved, bundle, bundle_hash));
        }
        Ok(bundles)
    }

    fn persist_formal_safety_proof(
        &self,
        candidate: &StrategyGenome,
        bundle_sha256: &[String],
        verdicts: &[FormalSafetyInvariantVerdict],
        solver_summary: Option<&EvolutionSolverProofSummary>,
        solver_artifacts: &[EvolutionSolverInvariantArtifact],
    ) -> Result<EvolutionProofLookup, FormalSafetyGateError> {
        let proofs_dir = resolve_config_relative_path(
            &self.config_path,
            &self.config.evolution.paths.evolution_proof_results_dir,
        );
        let store = FileEvolutionProofStore::open(&proofs_dir)?;
        let experiment_manifest_sha256 = sha256_hex(&candidate.experiment)?;
        let verification_report_sha256 = sha256_hex(&candidate.verification)?;
        let lineage_sha256 = sha256_hex(&candidate.experiment.lineage)?;
        let created_at_ms = now_ms();
        let invariants = verdicts
            .iter()
            .map(|verdict| EvolutionProofInvariant {
                name: verdict.name.clone(),
                claim: if verdict.passed {
                    format!("formal safety invariant `{}` passed", verdict.name)
                } else {
                    format!("formal safety invariant `{}` failed", verdict.name)
                },
                details: verdict.details.clone(),
                counterexamples: verdict.counterexamples.clone(),
            })
            .collect::<Vec<_>>();
        let attestation_sha256 = sha256_hex(&ProofAttestationPayload {
            experiment_manifest_sha256: experiment_manifest_sha256.clone(),
            verification_report_sha256: verification_report_sha256.clone(),
            lineage_sha256: lineage_sha256.clone(),
            invariant_names: invariants.iter().map(|entry| entry.name.clone()).collect(),
            solver_signature_sha256: solver_summary
                .map(|summary| summary.proof_signature_sha256.clone()),
            solver_artifact_attestations: solver_artifacts
                .iter()
                .map(|artifact| artifact.attestation_sha256.clone())
                .collect(),
        })?;
        let report = EvolutionProofReport {
            proof_id: proof_id(
                &candidate.experiment.name,
                candidate.experiment.candidate.strategy_id(),
                created_at_ms,
            ),
            experiment_id: experiment_id_for_manifest(&candidate.experiment),
            experiment_name: candidate.experiment.name.clone(),
            verification_id: candidate.verification.verification_id.clone(),
            created_at_ms,
            strategy_id: candidate.experiment.candidate.strategy_id().to_string(),
            candidate_description: candidate.experiment.candidate.description().to_string(),
            lineage: candidate.experiment.lineage.clone(),
            corpus_name: candidate.verification.corpus_name.clone(),
            proof_system: if solver_summary.is_some() {
                "formal_safety_gate_v2+z3_smt_v1".to_string()
            } else {
                "formal_safety_gate_v2".to_string()
            },
            experiment_manifest_sha256,
            strategy_genome_sha256: sha256_hex(&candidate.experiment.candidate)?,
            verification_report_sha256,
            lineage_sha256,
            attestation_sha256,
            invariants,
            formal_safety_bundle_sha256: bundle_sha256.to_vec(),
            solver_summary: solver_summary.cloned(),
            solver_artifacts: solver_artifacts.to_vec(),
        };
        let record = store.persist(&report)?;
        Ok(EvolutionProofLookup { record, report })
    }
}

impl FormalSafetyGate for DefaultFormalSafetyGate {
    fn verify(
        &self,
        candidate: &StrategyGenome,
    ) -> Result<FormalSafetyVerificationReport, FormalSafetyGateError> {
        let bundles = self.load_bundles()?;
        let verification_manifest =
            load_verification_manifest(&candidate.verification.corpus_path)?;
        let candidate_value = serde_json::to_value(&candidate.experiment)?;
        let mut verdicts = Vec::new();
        let mut solver_artifacts = Vec::new();
        let mut bundle_paths = Vec::new();
        let mut bundle_sha256 = Vec::new();

        for (bundle_path, bundle, bundle_hash) in bundles {
            bundle_paths.push(bundle_path.display().to_string());
            bundle_sha256.push(bundle_hash);
            for invariant in &bundle.invariants {
                let evaluation = evaluate_formal_safety_invariant(
                    &bundle_path,
                    invariant,
                    candidate,
                    &verification_manifest,
                    &candidate_value,
                    self.config.evolution.safety_gate.enable_z3,
                )?;
                if let Some(artifact) = evaluation.solver_artifact {
                    solver_artifacts.push(artifact);
                }
                verdicts.push(evaluation.verdict);
            }
        }

        let solver_summary = summarize_solver_artifacts(&solver_artifacts)?;
        let persisted_proof_id = if solver_summary.is_some() {
            Some(
                self.persist_formal_safety_proof(
                    candidate,
                    &bundle_sha256,
                    &verdicts,
                    solver_summary.as_ref(),
                    &solver_artifacts,
                )?
                .record
                .proof_id,
            )
        } else {
            None
        };

        Ok(FormalSafetyVerificationReport {
            passed: verdicts.iter().all(|verdict| verdict.passed),
            bundle_paths,
            bundle_sha256,
            invariants: verdicts,
            persisted_proof_id,
            solver_summary,
        })
    }
}

impl DefaultEvolutionProofHarness {
    pub fn from_path(
        config_path: impl AsRef<Path>,
        results_dir: impl AsRef<Path>,
    ) -> Result<Self, EvolutionQueueError> {
        let config_path = config_path.as_ref();
        let config = load_config(config_path)?;
        Self::from_config(config_path, config, results_dir)
    }

    pub fn from_config(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
        results_dir: impl AsRef<Path>,
    ) -> Result<Self, EvolutionQueueError> {
        Ok(Self {
            config_path: config_path.into(),
            config,
            store: FileEvolutionProofStore::open(results_dir)?,
        })
    }

    pub fn create_proof(
        &self,
        experiment_path: impl AsRef<Path>,
        verification_results_dir: impl AsRef<Path>,
        verification_id: &str,
    ) -> Result<EvolutionProofLookup, EvolutionQueueError> {
        let experiment_path = experiment_path.as_ref();
        let manifest = load_detector_experiment_manifest(experiment_path)?;
        let experiment_id = experiment_id_for_manifest(&manifest);
        let verification_store = FileVerificationStore::open(verification_results_dir)?;
        let verification = verification_store.load(verification_id)?.ok_or_else(|| {
            EvolutionQueueError::VerificationNotFound {
                verification_id: verification_id.to_string(),
            }
        })?;

        if verification.report.experiment_id != experiment_id {
            return Err(EvolutionQueueError::Replay(
                ReplayHarnessError::ReviewValidation {
                    reason: format!(
                        "verification `{}` does not belong to experiment `{}`",
                        verification_id, experiment_id
                    ),
                },
            ));
        }
        if !verification.report.passed {
            return Err(EvolutionQueueError::VerificationFailed {
                verification_id: verification_id.to_string(),
            });
        }
        if verification
            .report
            .invariants
            .iter()
            .any(|invariant| !invariant.passed)
        {
            return Err(EvolutionQueueError::VerificationFailed {
                verification_id: verification_id.to_string(),
            });
        }

        let experiment_manifest_sha256 = sha256_hex(&manifest)?;
        let verification_report_sha256 = sha256_hex(&verification.report)?;
        let lineage_sha256 = sha256_hex(&manifest.lineage)?;
        let invariants = verification
            .report
            .invariants
            .iter()
            .map(|invariant| EvolutionProofInvariant {
                name: invariant.name.clone(),
                claim: format!("verification invariant `{}` passed", invariant.name),
                details: invariant.details.clone(),
                counterexamples: invariant.counterexamples.clone(),
            })
            .collect::<Vec<_>>();
        let attestation_sha256 = sha256_hex(&ProofAttestationPayload {
            experiment_manifest_sha256: experiment_manifest_sha256.clone(),
            verification_report_sha256: verification_report_sha256.clone(),
            lineage_sha256: lineage_sha256.clone(),
            invariant_names: invariants.iter().map(|entry| entry.name.clone()).collect(),
            solver_signature_sha256: None,
            solver_artifact_attestations: Vec::new(),
        })?;
        let created_at_ms = now_ms();
        let report = EvolutionProofReport {
            proof_id: proof_id(
                &manifest.name,
                manifest.candidate.strategy_id(),
                created_at_ms,
            ),
            experiment_id,
            experiment_name: manifest.name.clone(),
            verification_id: verification.report.verification_id.clone(),
            created_at_ms,
            strategy_id: manifest.candidate.strategy_id().to_string(),
            candidate_description: manifest.candidate.description().to_string(),
            lineage: manifest.lineage.clone(),
            corpus_name: verification.report.corpus_name.clone(),
            proof_system: "verification_attestation_v1".to_string(),
            experiment_manifest_sha256: experiment_manifest_sha256.clone(),
            strategy_genome_sha256: experiment_manifest_sha256,
            verification_report_sha256,
            lineage_sha256,
            attestation_sha256,
            invariants,
            formal_safety_bundle_sha256: Vec::new(),
            solver_summary: None,
            solver_artifacts: Vec::new(),
        };
        let record = self.store.persist(&report)?;
        Ok(EvolutionProofLookup { record, report })
    }

    pub fn load_proof(
        &self,
        proof_id: &str,
    ) -> Result<Option<EvolutionProofLookup>, EvolutionQueueError> {
        Ok(self.store.load(proof_id)?)
    }
}

/// Harness that builds and manages the verified evolution proposal queue.
fn validate_formal_safety_bundle(
    path: &Path,
    bundle: &FormalSafetyInvariantBundle,
) -> Result<(), FormalSafetyGateError> {
    if bundle.schema_version == 0 {
        return Err(FormalSafetyGateError::Validation {
            path: path.to_path_buf(),
            reason: "schema_version must be greater than zero".to_string(),
        });
    }
    if bundle.name.trim().is_empty() {
        return Err(FormalSafetyGateError::Validation {
            path: path.to_path_buf(),
            reason: "name must not be empty".to_string(),
        });
    }
    if bundle.invariants.is_empty() {
        return Err(FormalSafetyGateError::Validation {
            path: path.to_path_buf(),
            reason: "invariants must include at least one rule".to_string(),
        });
    }
    for invariant in &bundle.invariants {
        match invariant {
            FormalSafetyInvariantSpec::CoverageFloor {
                name,
                corpus_path,
                min_ratio,
                ..
            } => {
                if name.trim().is_empty() || corpus_path.trim().is_empty() {
                    return Err(FormalSafetyGateError::Validation {
                        path: path.to_path_buf(),
                        reason: "coverage_floor invariants require non-empty name and corpus_path"
                            .to_string(),
                    });
                }
                if !(0.0..=1.0).contains(min_ratio) {
                    return Err(FormalSafetyGateError::Validation {
                        path: path.to_path_buf(),
                        reason: format!(
                            "coverage_floor invariant `{name}` min_ratio must be between 0.0 and 1.0"
                        ),
                    });
                }
            }
            FormalSafetyInvariantSpec::FpCeiling {
                name,
                corpus_path,
                max_rate,
            } => {
                if name.trim().is_empty() || corpus_path.trim().is_empty() {
                    return Err(FormalSafetyGateError::Validation {
                        path: path.to_path_buf(),
                        reason: "fp_ceiling invariants require non-empty name and corpus_path"
                            .to_string(),
                    });
                }
                if !(0.0..=1.0).contains(max_rate) {
                    return Err(FormalSafetyGateError::Validation {
                        path: path.to_path_buf(),
                        reason: format!(
                            "fp_ceiling invariant `{name}` max_rate must be between 0.0 and 1.0"
                        ),
                    });
                }
            }
            FormalSafetyInvariantSpec::LatencyBudget {
                name,
                corpus_path,
                max_detect_latency_us,
            } => {
                if name.trim().is_empty() || corpus_path.trim().is_empty() {
                    return Err(FormalSafetyGateError::Validation {
                        path: path.to_path_buf(),
                        reason: "latency_budget invariants require non-empty name and corpus_path"
                            .to_string(),
                    });
                }
                if *max_detect_latency_us == 0 {
                    return Err(FormalSafetyGateError::Validation {
                        path: path.to_path_buf(),
                        reason: format!(
                            "latency_budget invariant `{name}` max_detect_latency_us must be greater than zero"
                        ),
                    });
                }
            }
            FormalSafetyInvariantSpec::ParameterBounds {
                name,
                json_pointer,
                min,
                max,
            } => {
                if name.trim().is_empty() || json_pointer.trim().is_empty() {
                    return Err(FormalSafetyGateError::Validation {
                        path: path.to_path_buf(),
                        reason:
                            "parameter_bounds invariants require non-empty name and json_pointer"
                                .to_string(),
                    });
                }
                if let (Some(min), Some(max)) = (min, max)
                    && min > max
                {
                    return Err(FormalSafetyGateError::Validation {
                        path: path.to_path_buf(),
                        reason: format!(
                            "parameter_bounds invariant `{name}` min cannot exceed max"
                        ),
                    });
                }
            }
            FormalSafetyInvariantSpec::CustomZ3 { name, query } => {
                if name.trim().is_empty() || query.trim().is_empty() {
                    return Err(FormalSafetyGateError::Validation {
                        path: path.to_path_buf(),
                        reason: "custom_z3 invariants require non-empty name and query".to_string(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn evaluate_formal_safety_invariant(
    bundle_path: &Path,
    invariant: &FormalSafetyInvariantSpec,
    candidate: &StrategyGenome,
    verification_manifest: &crate::replay::VerificationCorpusManifest,
    candidate_value: &JsonValue,
    z3_enabled: bool,
) -> Result<FormalSafetyInvariantEvaluation, FormalSafetyGateError> {
    match invariant {
        FormalSafetyInvariantSpec::CoverageFloor {
            name,
            corpus_path,
            source,
            min_ratio,
        } => Ok(plain_invariant_evaluation(evaluate_coverage_floor(
            bundle_path,
            name,
            corpus_path,
            *source,
            *min_ratio,
            candidate,
            verification_manifest,
        )?)),
        FormalSafetyInvariantSpec::FpCeiling {
            name,
            corpus_path,
            max_rate,
        } => Ok(plain_invariant_evaluation(evaluate_fp_ceiling(
            bundle_path,
            name,
            corpus_path,
            *max_rate,
            candidate,
        )?)),
        FormalSafetyInvariantSpec::LatencyBudget {
            name,
            corpus_path,
            max_detect_latency_us,
        } => Ok(plain_invariant_evaluation(evaluate_latency_budget(
            bundle_path,
            name,
            corpus_path,
            *max_detect_latency_us,
            candidate,
        )?)),
        FormalSafetyInvariantSpec::ParameterBounds {
            name,
            json_pointer,
            min,
            max,
        } => Ok(plain_invariant_evaluation(evaluate_parameter_bounds(
            name,
            json_pointer,
            *min,
            *max,
            candidate_value,
        ))),
        FormalSafetyInvariantSpec::CustomZ3 { name, query } => evaluate_custom_z3_invariant(
            bundle_path,
            name,
            query,
            candidate,
            candidate_value,
            z3_enabled,
        ),
    }
}

fn plain_invariant_evaluation(
    verdict: FormalSafetyInvariantVerdict,
) -> FormalSafetyInvariantEvaluation {
    FormalSafetyInvariantEvaluation {
        verdict,
        solver_artifact: None,
    }
}

fn z3_timeout_ms() -> u64 {
    std::env::var("SWARM_EVOLUTION_Z3_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_Z3_TIMEOUT_MS)
}

fn compile_custom_z3_query(
    bundle_path: &Path,
    query: &str,
    candidate_value: &JsonValue,
) -> Result<String, FormalSafetyGateError> {
    let mut compiled = String::with_capacity(query.len());
    let mut cursor = 0usize;
    while let Some(start_offset) = query[cursor..].find("{{") {
        let start = cursor + start_offset;
        compiled.push_str(&query[cursor..start]);
        let replacement_start = start + 2;
        let Some(end_offset) = query[replacement_start..].find("}}") else {
            return Err(FormalSafetyGateError::Validation {
                path: bundle_path.to_path_buf(),
                reason: "custom_z3 query contains an unterminated `{{ ... }}` placeholder"
                    .to_string(),
            });
        };
        let end = replacement_start + end_offset;
        let pointer = query[replacement_start..end].trim();
        if pointer.is_empty() {
            return Err(FormalSafetyGateError::Validation {
                path: bundle_path.to_path_buf(),
                reason: "custom_z3 placeholders must reference a non-empty JSON pointer"
                    .to_string(),
            });
        }
        let Some(value) = candidate_value.pointer(pointer) else {
            return Err(FormalSafetyGateError::Validation {
                path: bundle_path.to_path_buf(),
                reason: format!("custom_z3 query references missing candidate pointer `{pointer}`"),
            });
        };
        compiled.push_str(&json_value_to_smt_literal(bundle_path, pointer, value)?);
        cursor = end + 2;
    }
    compiled.push_str(&query[cursor..]);
    if !compiled.contains("(check-sat") {
        compiled.push_str("\n(check-sat)\n");
    }
    Ok(compiled)
}

fn json_value_to_smt_literal(
    bundle_path: &Path,
    pointer: &str,
    value: &JsonValue,
) -> Result<String, FormalSafetyGateError> {
    match value {
        JsonValue::Bool(value) => Ok(if *value { "true" } else { "false" }.to_string()),
        JsonValue::Number(value) => Ok(value.to_string()),
        JsonValue::String(value) => Ok(format!("\"{}\"", value.replace('"', "\\\""))),
        JsonValue::Null | JsonValue::Array(_) | JsonValue::Object(_) => {
            Err(FormalSafetyGateError::Validation {
                path: bundle_path.to_path_buf(),
                reason: format!(
                    "custom_z3 query pointer `{pointer}` resolved to a non-scalar JSON value"
                ),
            })
        }
    }
}

fn build_solver_artifact(
    invariant_name: &str,
    status: EvolutionSolverProofStatus,
    timeout_ms: u64,
    duration_ms: u64,
    compiled_query: &str,
    counterexamples: Vec<EvolutionSolverCounterexample>,
    reason_unknown: Option<String>,
) -> Result<EvolutionSolverInvariantArtifact, FormalSafetyGateError> {
    let compiled_query_sha256 = sha256_hex(&compiled_query)?;
    let attestation_sha256 = sha256_hex(&SolverArtifactAttestationPayload {
        invariant_name: invariant_name.to_string(),
        status,
        timeout_ms,
        duration_ms,
        compiled_query_sha256: compiled_query_sha256.clone(),
        reason_unknown: reason_unknown.clone(),
        counterexamples: counterexamples.clone(),
    })?;
    Ok(EvolutionSolverInvariantArtifact {
        invariant_name: invariant_name.to_string(),
        solver: "z3".to_string(),
        status,
        timeout_ms,
        duration_ms,
        compiled_query_sha256,
        attestation_sha256,
        counterexamples,
        reason_unknown,
    })
}

fn summarize_solver_artifacts(
    artifacts: &[EvolutionSolverInvariantArtifact],
) -> Result<Option<EvolutionSolverProofSummary>, FormalSafetyGateError> {
    if artifacts.is_empty() {
        return Ok(None);
    }

    let proved_count = artifacts
        .iter()
        .filter(|artifact| artifact.status == EvolutionSolverProofStatus::Proved)
        .count();
    let counterexample_invariant_count = artifacts
        .iter()
        .filter(|artifact| artifact.status == EvolutionSolverProofStatus::Counterexample)
        .count();
    let counterexample_binding_count = artifacts
        .iter()
        .map(|artifact| artifact.counterexamples.len())
        .sum();
    let timed_out_count = artifacts
        .iter()
        .filter(|artifact| artifact.status == EvolutionSolverProofStatus::Timeout)
        .count();
    let disabled_count = artifacts
        .iter()
        .filter(|artifact| artifact.status == EvolutionSolverProofStatus::Disabled)
        .count();
    let error_count = artifacts
        .iter()
        .filter(|artifact| artifact.status == EvolutionSolverProofStatus::Error)
        .count();
    let status = if timed_out_count > 0 {
        EvolutionSolverProofStatus::Timeout
    } else if counterexample_invariant_count > 0 {
        EvolutionSolverProofStatus::Counterexample
    } else if error_count > 0 {
        EvolutionSolverProofStatus::Error
    } else if disabled_count > 0 {
        EvolutionSolverProofStatus::Disabled
    } else {
        EvolutionSolverProofStatus::Proved
    };
    let timeout_ms = artifacts
        .iter()
        .map(|artifact| artifact.timeout_ms)
        .max()
        .unwrap_or(DEFAULT_Z3_TIMEOUT_MS);
    let proof_signature_sha256 = sha256_hex(
        &artifacts
            .iter()
            .map(|artifact| artifact.attestation_sha256.clone())
            .collect::<Vec<_>>(),
    )?;

    Ok(Some(EvolutionSolverProofSummary {
        status,
        invariant_count: artifacts.len(),
        proved_count,
        counterexample_invariant_count,
        counterexample_binding_count,
        timed_out_count,
        disabled_count,
        error_count,
        timeout_ms,
        proof_signature_sha256,
    }))
}

fn evaluate_custom_z3_invariant(
    bundle_path: &Path,
    name: &str,
    query: &str,
    candidate: &StrategyGenome,
    candidate_value: &JsonValue,
    z3_enabled: bool,
) -> Result<FormalSafetyInvariantEvaluation, FormalSafetyGateError> {
    let timeout_ms = z3_timeout_ms();
    let compiled_query = compile_custom_z3_query(bundle_path, query, candidate_value)?;
    evaluate_custom_z3_invariant_impl(
        bundle_path,
        name,
        compiled_query,
        candidate,
        timeout_ms,
        z3_enabled,
    )
}

#[cfg(feature = "z3")]
fn evaluate_custom_z3_invariant_impl(
    bundle_path: &Path,
    name: &str,
    compiled_query: String,
    candidate: &StrategyGenome,
    timeout_ms: u64,
    z3_enabled: bool,
) -> Result<FormalSafetyInvariantEvaluation, FormalSafetyGateError> {
    if !z3_enabled {
        return disabled_custom_z3_evaluation(
            bundle_path,
            name,
            compiled_query,
            candidate,
            timeout_ms,
        );
    }

    let started_at = std::time::Instant::now();
    let mut config = Z3Config::new();
    config.set_timeout_msec(timeout_ms);
    with_z3_config(&config, || {
        let solver = Z3Solver::new();
        let mut params = Z3Params::new();
        params.set_u32("timeout", timeout_ms as u32);
        solver.set_params(&params);
        solver.from_string(compiled_query.clone());
        let result = solver.check();
        let duration_ms = started_at.elapsed().as_millis() as u64;

        match result {
            SatResult::Unsat => {
                let artifact = build_solver_artifact(
                    name,
                    EvolutionSolverProofStatus::Proved,
                    timeout_ms,
                    duration_ms,
                    &compiled_query,
                    Vec::new(),
                    None,
                )?;
                Ok(FormalSafetyInvariantEvaluation {
                    verdict: FormalSafetyInvariantVerdict {
                        name: name.to_string(),
                        passed: true,
                        details: format!(
                            "custom_z3 invariant proved with Z3 in {duration_ms}ms (timeout={}ms)",
                            timeout_ms
                        ),
                        counterexamples: Vec::new(),
                    },
                    solver_artifact: Some(artifact),
                })
            }
            SatResult::Sat => {
                let counterexamples = solver
                    .get_model()
                    .map(|model| extract_model_counterexamples(&model))
                    .unwrap_or_default();
                let artifact = build_solver_artifact(
                    name,
                    EvolutionSolverProofStatus::Counterexample,
                    timeout_ms,
                    duration_ms,
                    &compiled_query,
                    counterexamples.clone(),
                    None,
                )?;
                Ok(FormalSafetyInvariantEvaluation {
                    verdict: FormalSafetyInvariantVerdict {
                        name: name.to_string(),
                        passed: false,
                        details: format!(
                            "custom_z3 invariant produced a counterexample in {duration_ms}ms"
                        ),
                        counterexamples: counterexamples
                            .iter()
                            .map(|counterexample| VerificationCounterexample {
                                subject: counterexample.name.clone(),
                                reference: bundle_path.display().to_string(),
                                details: counterexample.value.clone(),
                            })
                            .collect(),
                    },
                    solver_artifact: Some(artifact),
                })
            }
            SatResult::Unknown => {
                let reason_unknown = solver.get_reason_unknown();
                let status = if reason_unknown
                    .as_deref()
                    .map(|reason| {
                        let normalized = reason.to_ascii_lowercase();
                        normalized.contains("timeout") || normalized.contains("canceled")
                    })
                    .unwrap_or(false)
                {
                    EvolutionSolverProofStatus::Timeout
                } else {
                    EvolutionSolverProofStatus::Error
                };
                let details = if status == EvolutionSolverProofStatus::Timeout {
                    format!(
                        "custom_z3 invariant timed out after {duration_ms}ms (timeout={}ms)",
                        timeout_ms
                    )
                } else {
                    format!(
                        "custom_z3 invariant returned unknown after {duration_ms}ms ({})",
                        reason_unknown
                            .clone()
                            .unwrap_or_else(|| "no solver reason provided".to_string())
                    )
                };
                let artifact = build_solver_artifact(
                    name,
                    status,
                    timeout_ms,
                    duration_ms,
                    &compiled_query,
                    Vec::new(),
                    reason_unknown.clone(),
                )?;
                Ok(FormalSafetyInvariantEvaluation {
                    verdict: FormalSafetyInvariantVerdict {
                        name: name.to_string(),
                        passed: false,
                        details: details.clone(),
                        counterexamples: vec![VerificationCounterexample {
                            subject: candidate.strategy_id.clone(),
                            reference: bundle_path.display().to_string(),
                            details,
                        }],
                    },
                    solver_artifact: Some(artifact),
                })
            }
        }
    })
}

#[cfg(not(feature = "z3"))]
fn evaluate_custom_z3_invariant_impl(
    bundle_path: &Path,
    name: &str,
    compiled_query: String,
    candidate: &StrategyGenome,
    timeout_ms: u64,
    _z3_enabled: bool,
) -> Result<FormalSafetyInvariantEvaluation, FormalSafetyGateError> {
    disabled_custom_z3_evaluation(bundle_path, name, compiled_query, candidate, timeout_ms)
}

fn disabled_custom_z3_evaluation(
    bundle_path: &Path,
    name: &str,
    compiled_query: String,
    candidate: &StrategyGenome,
    timeout_ms: u64,
) -> Result<FormalSafetyInvariantEvaluation, FormalSafetyGateError> {
    let artifact = build_solver_artifact(
        name,
        EvolutionSolverProofStatus::Disabled,
        timeout_ms,
        0,
        &compiled_query,
        Vec::new(),
        Some("the optional Z3-backed verifier is not enabled in this build or config".to_string()),
    )?;
    Ok(FormalSafetyInvariantEvaluation {
        verdict: FormalSafetyInvariantVerdict {
            name: name.to_string(),
            passed: false,
            details:
                "custom_z3 invariants require the optional Z3-backed verifier, which is not enabled in this build"
                    .to_string(),
            counterexamples: vec![VerificationCounterexample {
                subject: candidate.strategy_id.clone(),
                reference: bundle_path.display().to_string(),
                details:
                    "custom_z3 invariant cannot be evaluated without the optional solver lane"
                        .to_string(),
            }],
        },
        solver_artifact: Some(artifact),
    })
}

#[cfg(feature = "z3")]
fn extract_model_counterexamples(model: &z3::Model) -> Vec<EvolutionSolverCounterexample> {
    model
        .iter()
        .filter_map(|decl| {
            let applied = decl.apply(&[]);
            model
                .eval(&applied, true)
                .map(|value| EvolutionSolverCounterexample {
                    name: decl.name(),
                    value: value.to_string(),
                })
        })
        .collect()
}

fn evaluate_coverage_floor(
    bundle_path: &Path,
    name: &str,
    corpus_path: &str,
    source: FormalSafetyCoverageSource,
    min_ratio: f64,
    candidate: &StrategyGenome,
    verification_manifest: &crate::replay::VerificationCorpusManifest,
) -> Result<FormalSafetyInvariantVerdict, FormalSafetyGateError> {
    ensure_matching_corpus(
        bundle_path,
        corpus_path,
        &candidate.verification.corpus_path,
    )?;
    let (verification_invariant_name, total, details_suffix) = match source {
        FormalSafetyCoverageSource::KnownBadCoverage => {
            let known_bad_suite_path = resolve_relative_path_local(
                Path::new(&candidate.verification.corpus_path),
                &verification_manifest.known_bad.suite,
            );
            let raw = fs::read_to_string(&known_bad_suite_path).map_err(|source| {
                FormalSafetyGateError::Read {
                    path: known_bad_suite_path.clone(),
                    source,
                }
            })?;
            let suite: ReplaySuiteManifest =
                serde_yaml::from_str(&raw).map_err(|source| FormalSafetyGateError::Parse {
                    path: known_bad_suite_path.clone(),
                    source,
                })?;
            (
                "known_bad_coverage",
                suite.scenarios.len(),
                "verification adversarial scenarios",
            )
        }
        FormalSafetyCoverageSource::ThreatClassTemplates => (
            "threat_class_templates",
            verification_manifest.canonical_templates.len(),
            "canonical threat-class templates",
        ),
    };
    let invariant = candidate
        .verification
        .invariants
        .iter()
        .find(|entry| entry.name == verification_invariant_name);
    let missed = invariant
        .map(|entry| entry.counterexamples.len())
        .unwrap_or(total);
    let ratio = if total == 0 {
        0.0
    } else {
        (total.saturating_sub(missed)) as f64 / total as f64
    };
    let counterexamples = invariant
        .map(|entry| entry.counterexamples.clone())
        .unwrap_or_else(|| {
            vec![VerificationCounterexample {
                subject: candidate.strategy_id.clone(),
                reference: candidate.verification.verification_id.clone(),
                details: format!(
                    "verification invariant `{verification_invariant_name}` was not found while evaluating coverage floor"
                ),
            }]
        });
    Ok(FormalSafetyInvariantVerdict {
        name: name.to_string(),
        passed: ratio >= min_ratio,
        details: if ratio >= min_ratio {
            format!(
                "candidate preserved {:.2}% of the required {}",
                ratio * 100.0,
                details_suffix
            )
        } else {
            format!(
                "candidate preserved only {:.2}% of the required {}",
                ratio * 100.0,
                details_suffix
            )
        },
        counterexamples: if ratio >= min_ratio {
            Vec::new()
        } else {
            counterexamples
        },
    })
}

fn evaluate_fp_ceiling(
    bundle_path: &Path,
    name: &str,
    corpus_path: &str,
    max_rate: f64,
    candidate: &StrategyGenome,
) -> Result<FormalSafetyInvariantVerdict, FormalSafetyGateError> {
    ensure_matching_corpus(
        bundle_path,
        corpus_path,
        &candidate.verification.corpus_path,
    )?;
    let invariant = candidate
        .verification
        .invariants
        .iter()
        .find(|entry| entry.name == "false_positive_bound");
    let actual = invariant
        .and_then(|entry| entry.actual.as_f64())
        .unwrap_or(1.0);
    let counterexamples = invariant
        .map(|entry| entry.counterexamples.clone())
        .unwrap_or_else(|| {
            vec![VerificationCounterexample {
                subject: candidate.strategy_id.clone(),
                reference: candidate.verification.verification_id.clone(),
                details: "verification invariant `false_positive_bound` was not found".to_string(),
            }]
        });
    Ok(FormalSafetyInvariantVerdict {
        name: name.to_string(),
        passed: actual <= max_rate,
        details: if actual <= max_rate {
            format!(
                "candidate false-positive rate {:.4} stayed within ceiling {:.4}",
                actual, max_rate
            )
        } else {
            format!(
                "candidate false-positive rate {:.4} exceeded ceiling {:.4}",
                actual, max_rate
            )
        },
        counterexamples: if actual <= max_rate {
            Vec::new()
        } else {
            counterexamples
        },
    })
}

fn evaluate_latency_budget(
    bundle_path: &Path,
    name: &str,
    corpus_path: &str,
    max_detect_latency_us: u64,
    candidate: &StrategyGenome,
) -> Result<FormalSafetyInvariantVerdict, FormalSafetyGateError> {
    ensure_matching_corpus(
        bundle_path,
        corpus_path,
        &candidate.verification.corpus_path,
    )?;
    let invariant = candidate
        .verification
        .invariants
        .iter()
        .find(|entry| entry.name == "detect_latency_budget");
    let actual = invariant
        .and_then(|entry| entry.actual.as_u64())
        .unwrap_or(u64::MAX);
    let counterexamples = invariant
        .map(|entry| entry.counterexamples.clone())
        .unwrap_or_else(|| {
            vec![VerificationCounterexample {
                subject: candidate.strategy_id.clone(),
                reference: candidate.verification.verification_id.clone(),
                details: "verification invariant `detect_latency_budget` was not found".to_string(),
            }]
        });
    Ok(FormalSafetyInvariantVerdict {
        name: name.to_string(),
        passed: actual <= max_detect_latency_us,
        details: if actual <= max_detect_latency_us {
            format!(
                "candidate detect latency {}us stayed within budget {}us",
                actual, max_detect_latency_us
            )
        } else {
            format!(
                "candidate detect latency {}us exceeded budget {}us",
                actual, max_detect_latency_us
            )
        },
        counterexamples: if actual <= max_detect_latency_us {
            Vec::new()
        } else {
            counterexamples
        },
    })
}

fn evaluate_parameter_bounds(
    name: &str,
    json_pointer: &str,
    min: Option<f64>,
    max: Option<f64>,
    candidate_value: &JsonValue,
) -> FormalSafetyInvariantVerdict {
    let Some(value) = candidate_value.pointer(json_pointer) else {
        return FormalSafetyInvariantVerdict {
            name: name.to_string(),
            passed: false,
            details: format!("candidate genome does not contain json pointer `{json_pointer}`"),
            counterexamples: vec![VerificationCounterexample {
                subject: name.to_string(),
                reference: json_pointer.to_string(),
                details: "pointer was missing from the candidate genome".to_string(),
            }],
        };
    };
    let Some(number) = value.as_f64() else {
        return FormalSafetyInvariantVerdict {
            name: name.to_string(),
            passed: false,
            details: format!("candidate value at `{json_pointer}` is not numeric"),
            counterexamples: vec![VerificationCounterexample {
                subject: name.to_string(),
                reference: json_pointer.to_string(),
                details: format!("encountered non-numeric value `{value}`"),
            }],
        };
    };

    let mut details = Vec::new();
    let mut passed = true;
    if let Some(min) = min
        && number < min
    {
        passed = false;
        details.push(format!("value {number:.4} is below minimum {min:.4}"));
    }
    if let Some(max) = max
        && number > max
    {
        passed = false;
        details.push(format!("value {number:.4} exceeds maximum {max:.4}"));
    }

    FormalSafetyInvariantVerdict {
        name: name.to_string(),
        passed,
        details: if passed {
            let mut bounds = Vec::new();
            if let Some(min) = min {
                bounds.push(format!("min={min:.4}"));
            }
            if let Some(max) = max {
                bounds.push(format!("max={max:.4}"));
            }
            format!(
                "candidate value at `{json_pointer}` ({number:.4}) satisfied {}",
                bounds.join(", ")
            )
        } else {
            details.join("; ")
        },
        counterexamples: if passed {
            Vec::new()
        } else {
            vec![VerificationCounterexample {
                subject: name.to_string(),
                reference: json_pointer.to_string(),
                details: details.join("; "),
            }]
        },
    }
}

fn ensure_matching_corpus(
    bundle_path: &Path,
    expected_corpus_path: &str,
    actual_corpus_path: &str,
) -> Result<(), FormalSafetyGateError> {
    let expected = normalize_existing_path(resolve_relative_path_local(
        bundle_path,
        expected_corpus_path,
    ));
    let actual = normalize_existing_path(PathBuf::from(actual_corpus_path));
    if expected != actual {
        return Err(FormalSafetyGateError::Validation {
            path: bundle_path.to_path_buf(),
            reason: format!(
                "bundle references verification corpus `{}` but candidate used `{}`",
                expected.display(),
                actual.display()
            ),
        });
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct ProofAttestationPayload {
    experiment_manifest_sha256: String,
    verification_report_sha256: String,
    lineage_sha256: String,
    invariant_names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    solver_signature_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    solver_artifact_attestations: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SolverArtifactAttestationPayload {
    invariant_name: String,
    status: EvolutionSolverProofStatus,
    timeout_ms: u64,
    duration_ms: u64,
    compiled_query_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_unknown: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    counterexamples: Vec<EvolutionSolverCounterexample>,
}
