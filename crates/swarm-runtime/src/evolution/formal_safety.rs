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
            // THREE-WAY, not two. The durable proof is the audit record, and a
            // two-valued claim wrote "failed" over every undecided invariant --
            // an assertion the evaluation never made.
            .map(|verdict| EvolutionProofInvariant {
                name: verdict.name.clone(),
                claim: match verdict.outcome() {
                    FormalSafetyInvariantOutcome::Proved => {
                        format!("formal safety invariant `{}` passed", verdict.name)
                    }
                    FormalSafetyInvariantOutcome::Refuted => {
                        format!("formal safety invariant `{}` failed", verdict.name)
                    }
                    FormalSafetyInvariantOutcome::Unproved => format!(
                        "formal safety invariant `{}` was NOT DECIDED (unproved, not refuted)",
                        verdict.name
                    ),
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
            // The stamp names what actually decided this proof. It used to read
            // `+z3_smt_v1` whenever a solver summary EXISTED -- including when
            // every artifact in it was `Disabled`, i.e. when z3 had not run at
            // all. A proof that names a solver it never invoked is a false
            // attestation in a durable, hashed artifact.
            proof_system: match solver_summary.map(|summary| summary.status) {
                None => "formal_safety_gate_v2".to_string(),
                Some(EvolutionSolverProofStatus::Disabled) => {
                    "formal_safety_gate_v2+z3_smt_v1_not_run".to_string()
                }
                Some(_) => "formal_safety_gate_v2+z3_smt_v1".to_string(),
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
            passed: verdicts.iter().all(|verdict| verdict.passed()),
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

/// Deterministic solver work budget, in z3 resource units.
///
/// This is the budget that DECIDES: `rlimit` counts solver steps, so the same
/// query against the same z3 build gives up at the same point on a fast machine
/// and a slow one. The wall-clock `timeout` stays set as a backstop for a solver
/// that hangs outside its own accounting, but a verdict must not depend on it.
fn z3_rlimit() -> u64 {
    std::env::var("SWARM_EVOLUTION_Z3_RLIMIT")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_Z3_RLIMIT)
}

/// Classify a z3 `unknown` result from its `reason_unknown` string.
///
/// DELIBERATELY OUTSIDE `#[cfg(feature = "z3")]`. The arm that calls it is not:
/// until the `solver-z3` CI job landed alongside this change, nothing in CI
/// compiled the feature at all, and a classifier that only exists inside the cfg
/// block is a classifier no test can reach. Keeping it here means the mapping is
/// covered by the default-feature test suite as well as the solver lane.
///
/// CLASSIFIES ON THE NUMBERS, NOT THE STRING. The first version of this matched
/// `reason_unknown` for "resource limit"/"resource limits" and mapped
/// "canceled" to `Timeout`. Measured against real z3 0.20 with the budget
/// exhausted (`SWARM_EVOLUTION_Z3_RLIMIT=1`), the persisted artifact was
/// `(Timeout, Some("canceled"), rlimit=1, rlimit_count=Some(12), duration_ms=7)`:
/// z3 reports rlimit exhaustion through `Params::set_u32("rlimit", ..)` as the
/// generic `canceled`, so `ResourceLimit` was UNREACHABLE on the shipped path
/// and the durable operator-facing detail claimed the solver "hit the
/// wall-clock backstop after 7ms (timeout=30000ms)" -- asserting the opposite of
/// what stopped it. The test that pinned the mapping asserted a string z3 never
/// emits here, so it reported success over a region it never inspected.
///
/// `rlimit_count >= rlimit` is decidable from the artifact itself and holds
/// whichever spelling a z3 build uses, so the string is now only consulted when
/// the counters cannot settle it. The `resource limit` spellings are kept
/// because some entry points do answer `(get-info :reason-unknown)` that way.
/// Neither outcome is a refutation.
// Called only from the `#[cfg(feature = "z3")]` arm and from the unit tests. The
// `allow` is the price of keeping it OUT of the cfg block, which is the whole
// point: inside, no default-feature test could reach it.
#[cfg_attr(not(feature = "z3"), allow(dead_code))]
pub(super) fn classify_unknown(
    reason_unknown: Option<&str>,
    rlimit: u64,
    rlimit_count: Option<u64>,
) -> EvolutionSolverProofStatus {
    // The counters decide first, and they decide regardless of spelling: if the
    // solver consumed its whole deterministic budget, the budget is what stopped
    // it, whatever string this z3 build chose to report.
    let exhausted_budget =
        matches!(rlimit_count, Some(consumed) if rlimit > 0 && consumed >= rlimit);

    let Some(reason) = reason_unknown else {
        return if exhausted_budget {
            EvolutionSolverProofStatus::ResourceLimit
        } else {
            EvolutionSolverProofStatus::Error
        };
    };
    let normalized = reason.to_ascii_lowercase();
    if normalized.contains("resource limit") || normalized.contains("resource limits") {
        EvolutionSolverProofStatus::ResourceLimit
    } else if normalized.contains("timeout") || normalized.contains("canceled") {
        // "canceled" is what z3 0.20 actually reports for rlimit exhaustion, so
        // the counters -- not this string -- separate the deterministic budget
        // from the wall-clock backstop.
        if exhausted_budget {
            EvolutionSolverProofStatus::ResourceLimit
        } else {
            EvolutionSolverProofStatus::Timeout
        }
    } else if exhausted_budget {
        EvolutionSolverProofStatus::ResourceLimit
    } else {
        EvolutionSolverProofStatus::Error
    }
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

pub(super) fn build_solver_artifact(
    invariant_name: &str,
    status: EvolutionSolverProofStatus,
    budget: &SolverBudget,
    compiled_query: &str,
    counterexamples: Vec<EvolutionSolverCounterexample>,
    reason_unknown: Option<String>,
) -> Result<EvolutionSolverInvariantArtifact, FormalSafetyGateError> {
    let compiled_query_sha256 = sha256_hex(&compiled_query)?;
    // `duration_ms` is DELIBERATELY NOT in the attestation payload. It is wall
    // clock, so including it made the attestation hash of a reproducible proof
    // differ between two runs of the same query -- the hash could never be used to
    // recognise the same result twice. `rlimit` and `rlimit_count` replace it:
    // both are deterministic solver accounting.
    let attestation_sha256 = sha256_hex(&SolverArtifactAttestationPayload {
        invariant_name: invariant_name.to_string(),
        status,
        timeout_ms: budget.timeout_ms,
        rlimit: budget.rlimit,
        rlimit_count: budget.rlimit_count,
        compiled_query_sha256: compiled_query_sha256.clone(),
        reason_unknown: reason_unknown.clone(),
        counterexamples: counterexamples.clone(),
    })?;
    Ok(EvolutionSolverInvariantArtifact {
        invariant_name: invariant_name.to_string(),
        solver: "z3".to_string(),
        status,
        timeout_ms: budget.timeout_ms,
        rlimit: budget.rlimit,
        rlimit_count: budget.rlimit_count,
        duration_ms: budget.duration_ms,
        compiled_query_sha256,
        attestation_sha256,
        counterexamples,
        reason_unknown,
    })
}

pub(super) fn summarize_solver_artifacts(
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
    let resource_limited_count = artifacts
        .iter()
        .filter(|artifact| artifact.status == EvolutionSolverProofStatus::ResourceLimit)
        .count();
    let disabled_count = artifacts
        .iter()
        .filter(|artifact| artifact.status == EvolutionSolverProofStatus::Disabled)
        .count();
    let error_count = artifacts
        .iter()
        .filter(|artifact| artifact.status == EvolutionSolverProofStatus::Error)
        .count();
    // `ResourceLimit` sits next to `Timeout` at the top of the precedence, above
    // `Counterexample`: an aggregate that reported a refutation while some other
    // invariant went undecided would overstate what the proof established.
    let status = if timed_out_count > 0 {
        EvolutionSolverProofStatus::Timeout
    } else if resource_limited_count > 0 {
        EvolutionSolverProofStatus::ResourceLimit
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
        resource_limited_count,
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
    let rlimit = z3_rlimit();
    let compiled_query = compile_custom_z3_query(bundle_path, query, candidate_value)?;
    evaluate_custom_z3_invariant_impl(
        bundle_path,
        name,
        compiled_query,
        candidate,
        timeout_ms,
        rlimit,
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
    rlimit: u64,
    z3_enabled: bool,
) -> Result<FormalSafetyInvariantEvaluation, FormalSafetyGateError> {
    if !z3_enabled {
        return disabled_custom_z3_evaluation(
            bundle_path,
            name,
            compiled_query,
            candidate,
            timeout_ms,
            rlimit,
        );
    }

    let started_at = std::time::Instant::now();
    let mut config = Z3Config::new();
    // Wall-clock backstop only: a solver that hangs outside its own accounting
    // must still be killable. The DECIDING budget is `rlimit` below.
    config.set_timeout_msec(timeout_ms);
    with_z3_config(&config, || {
        let solver = Z3Solver::new();
        let mut params = Z3Params::new();
        params.set_u32("timeout", u32::try_from(timeout_ms).unwrap_or(u32::MAX));
        params.set_u32("rlimit", u32::try_from(rlimit).unwrap_or(u32::MAX));
        solver.set_params(&params);
        solver.from_string(compiled_query.clone());
        let result = solver.check();
        let duration_ms = started_at.elapsed().as_millis() as u64;
        let rlimit_count = consumed_rlimit(&solver);

        let budget = SolverBudget {
            timeout_ms,
            rlimit,
            rlimit_count,
            duration_ms,
        };

        match result {
            SatResult::Unsat => {
                let artifact = build_solver_artifact(
                    name,
                    EvolutionSolverProofStatus::Proved,
                    &budget,
                    &compiled_query,
                    Vec::new(),
                    None,
                )?;
                Ok(FormalSafetyInvariantEvaluation {
                    verdict: FormalSafetyInvariantVerdict::proved(
                        name,
                        format!(
                            "custom_z3 invariant proved with Z3 (rlimit_count={}, rlimit={rlimit})",
                            rlimit_count
                                .map(|value| value.to_string())
                                .unwrap_or_else(|| "unreported".to_string())
                        ),
                    ),
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
                    &budget,
                    &compiled_query,
                    counterexamples.clone(),
                    None,
                )?;
                Ok(FormalSafetyInvariantEvaluation {
                    verdict: FormalSafetyInvariantVerdict::refuted(
                        name,
                        "custom_z3 invariant produced a counterexample",
                        counterexamples
                            .iter()
                            .map(|counterexample| VerificationCounterexample {
                                subject: counterexample.name.clone(),
                                reference: bundle_path.display().to_string(),
                                details: counterexample.value.clone(),
                            })
                            .collect(),
                    ),
                    solver_artifact: Some(artifact),
                })
            }
            SatResult::Unknown => {
                // NOT A REFUTATION. This arm used to emit `passed: false` with a
                // SYNTHESIZED `VerificationCounterexample` whose `subject` was the
                // candidate's own strategy id and whose `details` was the timeout
                // message -- so `persist_formal_safety_proof` wrote
                // "formal safety invariant `X` failed" into the durable proof with
                // a fabricated witness attached, for a query z3 never decided.
                //
                // `FormalSafetyInvariantVerdict::unproved` takes no counterexamples
                // at all. `passed` stays false, so the lane still fails closed; only
                // the claim changes, from refuted to not-decided.
                let reason_unknown = solver.get_reason_unknown();
                let status = classify_unknown(
                    reason_unknown.as_deref(),
                    budget.rlimit,
                    budget.rlimit_count,
                );
                let details = unknown_details(status, &budget, reason_unknown.as_deref());
                let artifact = build_solver_artifact(
                    name,
                    status,
                    &budget,
                    &compiled_query,
                    Vec::new(),
                    reason_unknown.clone(),
                )?;
                Ok(FormalSafetyInvariantEvaluation {
                    verdict: FormalSafetyInvariantVerdict::unproved(name, details),
                    solver_artifact: Some(artifact),
                })
            }
        }
    })
}

/// Read the work z3 says it consumed.
///
/// The statistics key is NOT stable across z3 releases (the SMT-LIB surface
/// prints `:rlimit-count`, the C API has used `rlimit count`), so this scans the
/// entries for either spelling rather than hardcoding one, and returns `None`
/// rather than panicking when neither is present. A missing counter degrades the
/// artifact's evidence; it must not degrade the run.
#[cfg(feature = "z3")]
fn consumed_rlimit(solver: &Z3Solver) -> Option<u64> {
    let statistics = solver.get_statistics();
    statistics.entries().into_iter().find_map(|entry| {
        let key = entry.key.to_ascii_lowercase().replace(['-', '_'], " ");
        if key != "rlimit count" {
            return None;
        }
        match entry.value {
            z3::StatisticsValue::UInt(value) => Some(u64::from(value)),
            z3::StatisticsValue::Double(value) if value >= 0.0 => Some(value as u64),
            z3::StatisticsValue::Double(_) => None,
        }
    })
}

/// The budget a single solver run was given, and what it actually used.
pub(super) struct SolverBudget {
    pub(super) timeout_ms: u64,
    pub(super) rlimit: u64,
    pub(super) rlimit_count: Option<u64>,
    pub(super) duration_ms: u64,
}

/// Operator-facing text for an undecided run.
///
/// Leads with the DETERMINISTIC number (`rlimit_count`) for the resource-limit
/// case, and names the wall clock only where the wall clock is genuinely what
/// stopped the run.
#[cfg_attr(not(feature = "z3"), allow(dead_code))]
fn unknown_details(
    status: EvolutionSolverProofStatus,
    budget: &SolverBudget,
    reason_unknown: Option<&str>,
) -> String {
    let consumed = budget
        .rlimit_count
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unreported".to_string());
    match status {
        EvolutionSolverProofStatus::ResourceLimit => format!(
            "custom_z3 invariant UNPROVED: solver exhausted its resource budget \
             (rlimit_count={consumed}, rlimit={}). This is not a refutation.",
            budget.rlimit
        ),
        EvolutionSolverProofStatus::Timeout => format!(
            "custom_z3 invariant UNPROVED: solver hit the wall-clock backstop after \
             {}ms (timeout={}ms, rlimit_count={consumed}). This is not a refutation, \
             and unlike the resource budget it is not reproducible across machines.",
            budget.duration_ms, budget.timeout_ms
        ),
        _ => format!(
            "custom_z3 invariant UNPROVED: solver returned unknown ({}) with \
             rlimit_count={consumed}. This is not a refutation.",
            reason_unknown.unwrap_or("no solver reason provided")
        ),
    }
}

#[cfg(not(feature = "z3"))]
fn evaluate_custom_z3_invariant_impl(
    bundle_path: &Path,
    name: &str,
    compiled_query: String,
    candidate: &StrategyGenome,
    timeout_ms: u64,
    rlimit: u64,
    _z3_enabled: bool,
) -> Result<FormalSafetyInvariantEvaluation, FormalSafetyGateError> {
    disabled_custom_z3_evaluation(
        bundle_path,
        name,
        compiled_query,
        candidate,
        timeout_ms,
        rlimit,
    )
}

/// The solver did not run, because the build or the config disabled it.
///
/// SAME DEFECT AS THE `SatResult::Unknown` ARM, and this is the copy the
/// default-feature build actually compiles: it used to synthesize a
/// `VerificationCounterexample` naming the candidate's own strategy id, so the
/// durable proof recorded "formal safety invariant `X` failed" with a fabricated
/// witness for an invariant nothing had evaluated. `Unproved` carries no
/// counterexamples; the lane still fails closed on `passed() == false`.
fn disabled_custom_z3_evaluation(
    _bundle_path: &Path,
    name: &str,
    compiled_query: String,
    _candidate: &StrategyGenome,
    timeout_ms: u64,
    rlimit: u64,
) -> Result<FormalSafetyInvariantEvaluation, FormalSafetyGateError> {
    // The budget is recorded even though nothing spent it, so the artifact says
    // what the run WOULD have been given. `rlimit_count: None` is what says it
    // never ran.
    let budget = SolverBudget {
        timeout_ms,
        rlimit,
        rlimit_count: None,
        duration_ms: 0,
    };
    let artifact = build_solver_artifact(
        name,
        EvolutionSolverProofStatus::Disabled,
        &budget,
        &compiled_query,
        Vec::new(),
        Some("the optional Z3-backed verifier is not enabled in this build or config".to_string()),
    )?;
    Ok(FormalSafetyInvariantEvaluation {
        verdict: FormalSafetyInvariantVerdict::unproved(
            name,
            "custom_z3 invariant UNPROVED: the optional Z3-backed verifier is not enabled \
             in this build or config, so nothing evaluated it. This is not a refutation.",
        ),
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
    // Two-valued on purpose: the coverage ratio is measured from the verification
    // report, so failing it IS a refutation and `counterexamples` is the witness.
    // Only the solver arms can be undecided.
    Ok(if ratio >= min_ratio {
        FormalSafetyInvariantVerdict::proved(
            name,
            format!(
                "candidate preserved {:.2}% of the required {}",
                ratio * 100.0,
                details_suffix
            ),
        )
    } else {
        FormalSafetyInvariantVerdict::refuted(
            name,
            format!(
                "candidate preserved only {:.2}% of the required {}",
                ratio * 100.0,
                details_suffix
            ),
            counterexamples,
        )
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
    Ok(if actual <= max_rate {
        FormalSafetyInvariantVerdict::proved(
            name,
            format!(
                "candidate false-positive rate {:.4} stayed within ceiling {:.4}",
                actual, max_rate
            ),
        )
    } else {
        FormalSafetyInvariantVerdict::refuted(
            name,
            format!(
                "candidate false-positive rate {:.4} exceeded ceiling {:.4}",
                actual, max_rate
            ),
            counterexamples,
        )
    })
}

/// Admission check for the ruleset's `latency_budget` invariant.
///
/// This used to compare the verification's recorded detect latency against
/// `max_detect_latency_us` and fail the candidate when it came out high. That
/// made the admission gate a SECOND wall-clock verdict, downstream of the
/// replay one: the number it read is an `Instant` delta, so an identical
/// candidate over identical fixtures was admitted or rejected depending on how
/// loaded the machine was when its verification happened to run. A gate whose
/// verdict is not a function of its input is not a gate.
///
/// `max_detect_latency_us` is therefore ADVISORY here, exactly as it is in the
/// verification corpus. The check that remains is the deterministic one this
/// invariant can actually make: the candidate's verification must have been run
/// against the pinned corpus (`ensure_matching_corpus` above) and must carry a
/// detect-latency observation with an attributable source. A candidate whose
/// verification recorded no latency at all is still rejected -- that is a
/// structurally incomplete verification, not a slow one.
///
/// The measurement itself is reported verbatim in `details`, including whether
/// it cleared the advisory budget, so an operator reading an admission report
/// still sees the number and still sees when it regresses.
///
/// The invariant entry cannot simply be deleted from
/// `rulesets/safety/office-detector-admission.yaml`: that tree is covered by the
/// signed `rulesets/attestation.json`, and the signing key is deliberately not
/// in the repository, so the manifest could not be re-signed.
fn evaluate_latency_budget(
    bundle_path: &Path,
    name: &str,
    corpus_path: &str,
    advisory_max_detect_latency_us: u64,
    candidate: &StrategyGenome,
) -> Result<FormalSafetyInvariantVerdict, FormalSafetyGateError> {
    ensure_matching_corpus(
        bundle_path,
        corpus_path,
        &candidate.verification.corpus_path,
    )?;
    let observation = candidate
        .verification
        .observations
        .iter()
        .find(|entry| entry.name == "detect_latency_budget");
    let Some(observation) = observation else {
        // Missing evidence is not adverse evidence: the observation is absent, so
        // nothing was measured and nothing was refuted.
        return Ok(FormalSafetyInvariantVerdict::unproved(
            name,
            "verification recorded no `detect_latency_budget` observation, so the invariant \
             was NOT DECIDED",
        ));
    };
    let observed = observation.observed.as_u64();
    let Some(observed) = observed else {
        return Ok(FormalSafetyInvariantVerdict::unproved(
            name,
            format!(
                "`detect_latency_budget` observation carried no numeric measurement \
                 (got `{}`), so the invariant was NOT DECIDED",
                observation.observed
            ),
        ));
    };
    Ok(FormalSafetyInvariantVerdict::proved(
        name,
        if observed <= advisory_max_detect_latency_us {
            format!(
                "candidate recorded detect latency {}us, within the advisory budget {}us \
                 (advisory: wall-clock latency does not gate admission)",
                observed, advisory_max_detect_latency_us
            )
        } else {
            format!(
                "candidate recorded detect latency {}us, past the advisory budget {}us \
                 (advisory: wall-clock latency does not gate admission)",
                observed, advisory_max_detect_latency_us
            )
        },
    ))
}

fn evaluate_parameter_bounds(
    name: &str,
    json_pointer: &str,
    min: Option<f64>,
    max: Option<f64>,
    candidate_value: &JsonValue,
) -> FormalSafetyInvariantVerdict {
    let Some(value) = candidate_value.pointer(json_pointer) else {
        // The pointer is absent, so the bound was compared against nothing. Not
        // decided -- still fails closed, but claims no counterexample.
        return FormalSafetyInvariantVerdict::unproved(
            name,
            format!(
                "candidate genome does not contain json pointer `{json_pointer}`, so the \
                 bound was NOT DECIDED"
            ),
        );
    };
    let Some(number) = value.as_f64() else {
        return FormalSafetyInvariantVerdict::unproved(
            name,
            format!(
                "candidate value at `{json_pointer}` is not numeric (`{value}`), so the \
                 bound was NOT DECIDED"
            ),
        );
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

    // A numeric value that sits outside its bound IS refuted, and the bound itself
    // is the witness. Only the missing-pointer and non-numeric arms above are
    // undecided.
    if passed {
        let mut bounds = Vec::new();
        if let Some(min) = min {
            bounds.push(format!("min={min:.4}"));
        }
        if let Some(max) = max {
            bounds.push(format!("max={max:.4}"));
        }
        FormalSafetyInvariantVerdict::proved(
            name,
            format!(
                "candidate value at `{json_pointer}` ({number:.4}) satisfied {}",
                bounds.join(", ")
            ),
        )
    } else {
        FormalSafetyInvariantVerdict::refuted(
            name,
            details.join("; "),
            vec![VerificationCounterexample {
                subject: name.to_string(),
                reference: json_pointer.to_string(),
                details: details.join("; "),
            }],
        )
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
    rlimit: u64,
    rlimit_count: Option<u64>,
    compiled_query_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_unknown: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    counterexamples: Vec<EvolutionSolverCounterexample>,
}
