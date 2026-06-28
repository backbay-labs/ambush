use super::types::{
    EvolutionAssuranceCaseKind, EvolutionAssuranceCaseReport, EvolutionAssuranceWaiverPayload,
};
use super::*;

pub(crate) fn evaluate_proposal_assurance(
    config_path: &Path,
    config: &SwarmConfig,
    manifest: &DetectorExperimentManifest,
    proof: Option<&EvolutionProofReport>,
    blocking_reasons: &mut Vec<EvolutionProposalBlockingReason>,
) -> EvolutionProposalAssuranceSummary {
    let detector = assurance_detector_id(&manifest.candidate).to_string();
    let required_catch_rate = config
        .evolution
        .assurance
        .coverage_overrides
        .iter()
        .find(|override_config| override_config.detector == detector)
        .map(|override_config| override_config.min_catch_rate)
        .unwrap_or(config.evolution.assurance.min_detector_catch_rate);
    let mut assurance_blocked = false;
    let (suite_name, corpus_version, actual_catch_rate, actionable_gap_count) =
        match evaluate_repo_evasion_coverage(config, &resolve_repo_root(config_path)) {
            Ok(snapshot) => {
                let actionable_gap_count = actionable_gaps_for_detector(&snapshot, &detector).len();
                match snapshot
                    .detectors
                    .iter()
                    .find(|entry| entry.detector == detector)
                {
                    Some(report) => {
                        if report.catch_rate < required_catch_rate {
                            assurance_blocked = true;
                            blocking_reasons.push(EvolutionProposalBlockingReason {
                                source: "assurance".to_string(),
                                name: "coverage_floor_not_met".to_string(),
                                details: format!(
                                    "detector `{}` catch rate {:.3} is below assurance floor {:.3}",
                                    detector, report.catch_rate, required_catch_rate
                                ),
                                references: vec![
                                    snapshot.suite_name.clone(),
                                    snapshot.corpus_version.clone(),
                                ],
                            });
                        }
                        (
                            Some(snapshot.suite_name),
                            Some(snapshot.corpus_version),
                            Some(report.catch_rate),
                            actionable_gap_count,
                        )
                    }
                    None => {
                        assurance_blocked = true;
                        blocking_reasons.push(EvolutionProposalBlockingReason {
                            source: "assurance".to_string(),
                            name: "missing_detector_coverage".to_string(),
                            details: format!(
                                "repo-owned evasion coverage does not include detector `{}`",
                                detector
                            ),
                            references: vec![detector.clone()],
                        });
                        (
                            Some(snapshot.suite_name),
                            Some(snapshot.corpus_version),
                            None,
                            actionable_gap_count,
                        )
                    }
                }
            }
            Err(error) => {
                assurance_blocked = true;
                blocking_reasons.push(EvolutionProposalBlockingReason {
                    source: "assurance".to_string(),
                    name: "coverage_evaluation_failed".to_string(),
                    details: error.to_string(),
                    references: vec![detector.clone()],
                });
                (None, None, None, 0)
            }
        };

    let allowed_solver_statuses = config
        .evolution
        .assurance
        .allowed_solver_statuses
        .iter()
        .copied()
        .map(map_assurance_solver_status)
        .collect::<Vec<_>>();
    let solver_status =
        proof.and_then(|report| report.solver_summary.as_ref().map(|summary| summary.status));
    if let Some(status) = solver_status {
        if !allowed_solver_statuses.contains(&status) {
            assurance_blocked = true;
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "assurance".to_string(),
                name: "solver_status_not_allowed".to_string(),
                details: format!(
                    "solver proof status `{}` is not allowed by assurance policy",
                    solver_proof_status_label(status)
                ),
                references: proof
                    .map(|report| report.proof_id.clone())
                    .into_iter()
                    .collect(),
            });
        }
    } else if config.evolution.assurance.require_solver_summary {
        assurance_blocked = true;
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "assurance".to_string(),
            name: "missing_solver_summary".to_string(),
            details: "assurance policy requires a solver proof summary".to_string(),
            references: proof
                .map(|report| report.proof_id.clone())
                .into_iter()
                .collect(),
        });
    }

    EvolutionProposalAssuranceSummary {
        decision: if assurance_blocked {
            EvolutionProposalAssuranceDecision::Blocked
        } else {
            EvolutionProposalAssuranceDecision::Passed
        },
        coverage: EvolutionProposalAssuranceCoverageSummary {
            detector,
            suite_name,
            corpus_version,
            required_catch_rate,
            actual_catch_rate,
            actionable_gap_count,
        },
        solver: EvolutionProposalAssuranceSolverSummary {
            required: config.evolution.assurance.require_solver_summary,
            status: solver_status,
            allowed_statuses: allowed_solver_statuses,
        },
        harvested_case_ids: Vec::new(),
        waiver: None,
    }
}

fn assurance_detector_id(candidate: &DetectorCandidateManifest) -> &'static str {
    match candidate {
        DetectorCandidateManifest::SuspiciousProcessTree { .. } => "suspicious_process_tree",
        DetectorCandidateManifest::FilelessExecution { .. } => "fileless_execution",
        DetectorCandidateManifest::BehavioralAnomaly { .. } => "behavioral_anomaly",
        DetectorCandidateManifest::DnsExfiltration { .. } => "dns_exfiltration",
        DetectorCandidateManifest::LateralMovement { .. } => "lateral_movement",
        DetectorCandidateManifest::CredentialAccess { .. } => "credential_access",
        DetectorCandidateManifest::SuspiciousScripting { .. } => "suspicious_scripting",
        DetectorCandidateManifest::Persistence { .. } => "persistence",
        DetectorCandidateManifest::SupplyChain { .. } => "supply_chain",
        DetectorCandidateManifest::NetworkConnect { .. } => "network_connect",
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn persist_harvested_assurance_cases(
    config_path: &Path,
    config: &SwarmConfig,
    proposal_id: &str,
    created_at_ms: i64,
    manifest: &DetectorExperimentManifest,
    verification: Option<&DetectorVerificationLookup>,
    proof: Option<&EvolutionProofReport>,
    assurance: &EvolutionProposalAssuranceSummary,
) -> Result<Vec<String>, EvolutionQueueError> {
    if assurance.decision != EvolutionProposalAssuranceDecision::Blocked {
        return Ok(Vec::new());
    }

    let store = FileEvolutionAssuranceCaseStore::open(resolve_config_relative_path(
        config_path,
        &config.evolution.assurance.harvest.results_dir,
    ))?;
    let mut harvested_case_ids = Vec::new();
    let mut remaining_budget = config.evolution.assurance.harvest.max_cases_per_proposal;

    if remaining_budget > 0 {
        let coverage_cases = harvest_coverage_gap_cases(
            &store,
            config_path,
            config,
            proposal_id,
            created_at_ms,
            manifest,
            verification,
            proof,
            assurance,
            remaining_budget,
        )?;
        remaining_budget = remaining_budget.saturating_sub(coverage_cases.len());
        harvested_case_ids.extend(coverage_cases);
    }

    if remaining_budget > 0 {
        harvested_case_ids.extend(harvest_solver_counterexample_cases(
            &store,
            proposal_id,
            created_at_ms,
            manifest,
            verification,
            proof,
            assurance,
            remaining_budget,
        )?);
    }

    Ok(harvested_case_ids)
}

#[allow(clippy::too_many_arguments)]
fn harvest_coverage_gap_cases(
    store: &FileEvolutionAssuranceCaseStore,
    config_path: &Path,
    config: &SwarmConfig,
    proposal_id: &str,
    created_at_ms: i64,
    manifest: &DetectorExperimentManifest,
    verification: Option<&DetectorVerificationLookup>,
    proof: Option<&EvolutionProofReport>,
    assurance: &EvolutionProposalAssuranceSummary,
    max_cases: usize,
) -> Result<Vec<String>, EvolutionQueueError> {
    let coverage_blocked = assurance
        .coverage
        .actual_catch_rate
        .map(|actual| actual < assurance.coverage.required_catch_rate)
        .unwrap_or(true);
    if !coverage_blocked || assurance.coverage.actionable_gap_count == 0 || max_cases == 0 {
        return Ok(Vec::new());
    }

    let snapshot = match evaluate_repo_evasion_coverage(config, &resolve_repo_root(config_path)) {
        Ok(snapshot) => snapshot,
        Err(_) => return Ok(Vec::new()),
    };
    let gaps = actionable_gaps_for_detector(&snapshot, &assurance.coverage.detector);
    if gaps.is_empty() {
        return Ok(Vec::new());
    }

    let suite_path = normalize_existing_path(PathBuf::from(&snapshot.suite_path));
    let suite = load_replay_suite_manifest(&suite_path)?;
    let mut harvested_case_ids = Vec::new();

    for gap in gaps {
        for scenario_ref in &suite.scenarios {
            if harvested_case_ids.len() >= max_cases {
                return Ok(harvested_case_ids);
            }
            let source_path = resolve_manifest_relative_path(&suite_path, scenario_ref);
            let loaded = load_scenario_manifest(&source_path)?;
            if loaded.manifest.metadata.class != ReplayScenarioClass::Adversarial {
                continue;
            }
            if loaded.manifest.metadata.threat_class.as_ref() != Some(&gap.threat_class) {
                continue;
            }
            if !has_actionable_technique(
                &loaded.manifest.metadata.techniques,
                &gap.actionable_techniques,
            ) {
                continue;
            }

            let case_id = assurance_case_id(
                proposal_id,
                EvolutionAssuranceCaseKind::CoverageGap,
                &loaded.manifest.name,
                harvested_case_ids.len(),
            );
            let scenario = harvested_coverage_gap_scenario(
                &case_id,
                created_at_ms,
                &loaded.manifest,
                proposal_id,
                verification.map(|lookup| lookup.report.verification_id.as_str()),
                proof.map(|report| report.proof_id.as_str()),
                &assurance.coverage.detector,
                config.evolution.assurance.harvest.max_events_per_case,
            );
            let report = EvolutionAssuranceCaseReport {
                case_id: case_id.clone(),
                proposal_id: proposal_id.to_string(),
                created_at_ms,
                strategy_id: manifest.candidate.strategy_id().to_string(),
                detector: assurance.coverage.detector.clone(),
                kind: EvolutionAssuranceCaseKind::CoverageGap,
                scenario_name: scenario.name.clone(),
                scenario_path: String::new(),
                suite_name: assurance.coverage.suite_name.clone(),
                corpus_version: assurance.coverage.corpus_version.clone(),
                verification_id: verification.map(|lookup| lookup.report.verification_id.clone()),
                proof_id: proof.map(|report| report.proof_id.clone()),
                reason_name: "coverage_gap".to_string(),
                reason_details: format!(
                    "scenario `{}` covers detector `{}` gap for {:?}",
                    loaded.manifest.name, assurance.coverage.detector, gap.threat_class
                ),
                threat_class: Some(gap.threat_class.clone()),
                techniques: loaded.manifest.metadata.techniques.clone(),
                counterexample_bindings: Vec::new(),
                source_references: coverage_case_references(
                    &source_path,
                    proposal_id,
                    verification,
                    proof,
                ),
            };
            store.persist(&report, &scenario)?;
            harvested_case_ids.push(case_id);
        }
    }

    Ok(harvested_case_ids)
}

#[allow(clippy::too_many_arguments)]
fn harvest_solver_counterexample_cases(
    store: &FileEvolutionAssuranceCaseStore,
    proposal_id: &str,
    created_at_ms: i64,
    manifest: &DetectorExperimentManifest,
    verification: Option<&DetectorVerificationLookup>,
    proof: Option<&EvolutionProofReport>,
    assurance: &EvolutionProposalAssuranceSummary,
    max_cases: usize,
) -> Result<Vec<String>, EvolutionQueueError> {
    let Some(verification) = verification else {
        return Ok(Vec::new());
    };
    let Some(proof) = proof else {
        return Ok(Vec::new());
    };
    if max_cases == 0 {
        return Ok(Vec::new());
    }

    let bundle_path = normalize_existing_path(PathBuf::from(&verification.record.bundle_path));
    let mut harvested_case_ids = Vec::new();
    for artifact in proof
        .solver_artifacts
        .iter()
        .filter(|artifact| !artifact.counterexamples.is_empty())
    {
        if harvested_case_ids.len() >= max_cases {
            break;
        }
        let case_id = assurance_case_id(
            proposal_id,
            EvolutionAssuranceCaseKind::SolverCounterexample,
            &artifact.invariant_name,
            harvested_case_ids.len(),
        );
        let scenario = harvested_solver_counterexample_scenario(
            &case_id,
            created_at_ms,
            &bundle_path,
            proposal_id,
            &proof.proof_id,
            &verification.report.verification_id,
            &assurance.coverage.detector,
            &artifact.invariant_name,
        );
        let report = EvolutionAssuranceCaseReport {
            case_id: case_id.clone(),
            proposal_id: proposal_id.to_string(),
            created_at_ms,
            strategy_id: manifest.candidate.strategy_id().to_string(),
            detector: assurance.coverage.detector.clone(),
            kind: EvolutionAssuranceCaseKind::SolverCounterexample,
            scenario_name: scenario.name.clone(),
            scenario_path: String::new(),
            suite_name: assurance.coverage.suite_name.clone(),
            corpus_version: assurance.coverage.corpus_version.clone(),
            verification_id: Some(verification.report.verification_id.clone()),
            proof_id: Some(proof.proof_id.clone()),
            reason_name: "solver_counterexample".to_string(),
            reason_details: format!(
                "solver invariant `{}` emitted {} counterexample bindings",
                artifact.invariant_name,
                artifact.counterexamples.len()
            ),
            threat_class: None,
            techniques: Vec::new(),
            counterexample_bindings: artifact.counterexamples.clone(),
            source_references: solver_case_references(&bundle_path, proposal_id, proof),
        };
        store.persist(&report, &scenario)?;
        harvested_case_ids.push(case_id);
    }

    Ok(harvested_case_ids)
}

#[allow(clippy::too_many_arguments)]
fn harvested_coverage_gap_scenario(
    case_id: &str,
    created_at_ms: i64,
    source: &ReplayScenarioManifest,
    proposal_id: &str,
    verification_id: Option<&str>,
    proof_id: Option<&str>,
    detector: &str,
    max_events_per_case: usize,
) -> ReplayScenarioManifest {
    let input = match &source.input {
        ReplayScenarioInput::Events { events } => ReplayScenarioInput::Events {
            events: events.iter().take(max_events_per_case).cloned().collect(),
        },
        ReplayScenarioInput::ReplayBundles { paths } => ReplayScenarioInput::ReplayBundles {
            paths: paths.clone(),
        },
    };
    let mut receipt_chain = source.receipt_chain.clone();
    push_unique_string(&mut receipt_chain, proposal_id.to_string());
    if let Some(verification_id) = verification_id {
        push_unique_string(&mut receipt_chain, verification_id.to_string());
    }
    if let Some(proof_id) = proof_id {
        push_unique_string(&mut receipt_chain, proof_id.to_string());
    }

    let mut metadata = source.metadata.clone();
    push_unique_string(&mut metadata.tags, "assurance_case".to_string());
    push_unique_string(&mut metadata.tags, "coverage_gap".to_string());
    push_unique_string(&mut metadata.tags, detector.to_string());
    push_unique_string(&mut metadata.tags, proposal_id.to_string());

    ReplayScenarioManifest {
        name: format!("{}-harvest", case_id),
        description: format!(
            "Harvested assurance coverage-gap replay derived from `{}`",
            source.name
        ),
        seed_time_ms: created_at_ms,
        requested_by: "evolution-assurance-harvest".to_string(),
        receipt_chain,
        metadata,
        input,
        expectations: source.expectations.clone(),
    }
}

#[allow(clippy::too_many_arguments)]
fn harvested_solver_counterexample_scenario(
    case_id: &str,
    created_at_ms: i64,
    bundle_path: &Path,
    proposal_id: &str,
    proof_id: &str,
    verification_id: &str,
    detector: &str,
    invariant_name: &str,
) -> ReplayScenarioManifest {
    let mut tags = Vec::new();
    push_unique_string(&mut tags, "assurance_case".to_string());
    push_unique_string(&mut tags, "solver_counterexample".to_string());
    push_unique_string(&mut tags, detector.to_string());
    push_unique_string(&mut tags, invariant_name.to_string());

    ReplayScenarioManifest {
        name: format!("{}-solver", case_id),
        description: format!(
            "Harvested solver counterexample replay for invariant `{}`",
            invariant_name
        ),
        seed_time_ms: created_at_ms,
        requested_by: "evolution-assurance-harvest".to_string(),
        receipt_chain: vec![
            proposal_id.to_string(),
            verification_id.to_string(),
            proof_id.to_string(),
        ],
        metadata: ReplayScenarioMetadata {
            class: ReplayScenarioClass::Mixed,
            threat_class: None,
            campaign: None,
            techniques: Vec::new(),
            tags,
        },
        input: ReplayScenarioInput::ReplayBundles {
            paths: vec![bundle_path.display().to_string()],
        },
        expectations: ReplayExpectations::default(),
    }
}

fn has_actionable_technique(candidate: &[String], actionable: &[String]) -> bool {
    candidate.is_empty()
        || actionable.is_empty()
        || candidate
            .iter()
            .any(|technique| actionable.iter().any(|expected| expected == technique))
}

fn coverage_case_references(
    source_path: &Path,
    proposal_id: &str,
    verification: Option<&DetectorVerificationLookup>,
    proof: Option<&EvolutionProofReport>,
) -> Vec<String> {
    let mut references = vec![
        normalize_existing_path(source_path.to_path_buf())
            .display()
            .to_string(),
    ];
    push_unique_string(&mut references, proposal_id.to_string());
    if let Some(verification) = verification {
        push_unique_string(&mut references, verification.report.verification_id.clone());
    }
    if let Some(proof) = proof {
        push_unique_string(&mut references, proof.proof_id.clone());
    }
    references
}

fn solver_case_references(
    bundle_path: &Path,
    proposal_id: &str,
    proof: &EvolutionProofReport,
) -> Vec<String> {
    let mut references = vec![bundle_path.display().to_string(), proposal_id.to_string()];
    push_unique_string(&mut references, proof.proof_id.clone());
    references
}

fn assurance_case_id(
    proposal_id: &str,
    kind: EvolutionAssuranceCaseKind,
    seed: &str,
    ordinal: usize,
) -> String {
    format!(
        "evolution_assurance_case:{}:{}:{}:{}",
        proposal_id,
        assurance_case_kind_label(kind),
        sanitize_id(seed),
        ordinal
    )
}

fn assurance_case_kind_label(kind: EvolutionAssuranceCaseKind) -> &'static str {
    match kind {
        EvolutionAssuranceCaseKind::CoverageGap => "coverage_gap",
        EvolutionAssuranceCaseKind::SolverCounterexample => "solver_counterexample",
    }
}

fn push_unique_string(values: &mut Vec<String>, candidate: String) {
    if candidate.is_empty() || values.iter().any(|existing| existing == &candidate) {
        return;
    }
    values.push(candidate);
}

fn assurance_sha256(summary: &EvolutionProposalAssuranceSummary) -> Result<String, String> {
    let mut canonical_summary = summary.clone();
    canonical_summary.waiver = None;
    let payload = canonical_json_bytes(&canonical_summary)
        .map_err(|error| format!("failed to canonicalize assurance lineage: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(payload)))
}

fn assurance_waiver_payload<'a>(
    waiver: &'a EvolutionAssuranceWaiverSummary,
) -> EvolutionAssuranceWaiverPayload<'a> {
    EvolutionAssuranceWaiverPayload {
        waiver_id: &waiver.waiver_id,
        operator_id: &waiver.operator_id,
        issued_at_ms: waiver.issued_at_ms,
        expires_at_ms: waiver.expires_at_ms,
        reason: &waiver.reason,
        waived_gap_count: waiver.waived_gap_count,
        assurance_sha256: &waiver.assurance_sha256,
    }
}

pub(crate) fn build_assurance_waiver_summary(
    proposal_id: &str,
    assurance: &EvolutionProposalAssuranceSummary,
    operator_id: &str,
    signer: &Ed25519Signer,
    issued_at_ms: i64,
    ttl_secs: u64,
    reason: &str,
) -> Result<EvolutionAssuranceWaiverSummary, String> {
    let expires_at_ms = issued_at_ms
        .checked_add((ttl_secs as i64).saturating_mul(1_000))
        .ok_or_else(|| "waiver ttl overflowed the supported timestamp range".to_string())?;
    let assurance_sha256 = assurance_sha256(assurance)?;
    let waiver_id = format!(
        "evolution_assurance_waiver:{}:{}:{}",
        proposal_id,
        sanitize_id(operator_id),
        issued_at_ms
    );
    let mut waiver = EvolutionAssuranceWaiverSummary {
        waiver_id,
        operator_id: operator_id.to_string(),
        issued_at_ms,
        expires_at_ms,
        reason: reason.trim().to_string(),
        waived_gap_count: assurance.coverage.actionable_gap_count,
        assurance_sha256,
        signature: DetachedSignature {
            algorithm: "ed25519".to_string(),
            key_id: String::new(),
            public_key_hex: String::new(),
            signature_hex: String::new(),
        },
    };
    let payload = canonical_json_bytes(&assurance_waiver_payload(&waiver))
        .map_err(|error| format!("failed to canonicalize assurance waiver payload: {error}"))?;
    waiver.signature = signer.sign(&payload);
    Ok(waiver)
}

pub(crate) fn validate_assurance_waiver<'a>(
    assurance: &'a EvolutionProposalAssuranceSummary,
    config: &SwarmConfig,
    current_time_ms: i64,
) -> Result<&'a EvolutionAssuranceWaiverSummary, String> {
    let waiver = assurance
        .waiver
        .as_ref()
        .ok_or_else(|| "assurance waiver is missing".to_string())?;
    if waiver.reason.trim().is_empty() {
        return Err("assurance waiver reason must not be empty".to_string());
    }
    if waiver.expires_at_ms <= waiver.issued_at_ms {
        return Err("assurance waiver expiry must be after its issuance time".to_string());
    }
    if current_time_ms < waiver.issued_at_ms {
        return Err(format!(
            "assurance waiver is not active until {}",
            waiver.issued_at_ms
        ));
    }
    if current_time_ms > waiver.expires_at_ms {
        return Err(format!(
            "assurance waiver expired at {}",
            waiver.expires_at_ms
        ));
    }
    if !config
        .evolution
        .assurance
        .waiver
        .allowed_operator_ids
        .iter()
        .any(|candidate| candidate == &waiver.operator_id)
    {
        return Err(format!(
            "operator `{}` is not allowed to issue assurance waivers",
            waiver.operator_id
        ));
    }
    if assurance.coverage.actionable_gap_count
        > config.evolution.assurance.waiver.max_actionable_gap_count
    {
        return Err(format!(
            "assurance gap count {} exceeds configured waiver limit {}",
            assurance.coverage.actionable_gap_count,
            config.evolution.assurance.waiver.max_actionable_gap_count
        ));
    }
    if waiver.waived_gap_count != assurance.coverage.actionable_gap_count {
        return Err(format!(
            "assurance waiver records {} waived gaps but the assurance lineage carries {} actionable gaps",
            waiver.waived_gap_count, assurance.coverage.actionable_gap_count
        ));
    }
    let expected_operator_id =
        AgentId::from_public_key_hex(&waiver.signature.public_key_hex).to_string();
    if waiver.operator_id != expected_operator_id {
        return Err(format!(
            "assurance waiver signer `{}` does not match recorded operator `{}`",
            expected_operator_id, waiver.operator_id
        ));
    }
    let expected_sha256 = assurance_sha256(assurance)?;
    if waiver.assurance_sha256 != expected_sha256 {
        return Err(
            "assurance waiver does not match the current assurance lineage digest".to_string(),
        );
    }
    let payload = canonical_json_bytes(&assurance_waiver_payload(waiver))
        .map_err(|error| format!("failed to canonicalize assurance waiver payload: {error}"))?;
    verify_detached_signature(&payload, &waiver.signature)
        .map_err(|error| format!("assurance waiver signature verification failed: {error}"))?;
    Ok(waiver)
}

pub(crate) fn active_assurance_waiver<'a>(
    assurance: Option<&'a EvolutionProposalAssuranceSummary>,
    config: &SwarmConfig,
    current_time_ms: i64,
) -> Option<&'a EvolutionAssuranceWaiverSummary> {
    let summary = assurance?;
    if summary.decision != EvolutionProposalAssuranceDecision::Blocked {
        return None;
    }
    validate_assurance_waiver(summary, config, current_time_ms).ok()
}

pub(crate) fn assurance_rollout_state(
    assurance: Option<&EvolutionProposalAssuranceSummary>,
    config: &SwarmConfig,
    current_time_ms: i64,
) -> EvolutionAssuranceRolloutState {
    match assurance {
        Some(summary) if summary.decision == EvolutionProposalAssuranceDecision::Passed => {
            EvolutionAssuranceRolloutState::Clear
        }
        Some(_) if active_assurance_waiver(assurance, config, current_time_ms).is_some() => {
            EvolutionAssuranceRolloutState::Waived
        }
        _ => EvolutionAssuranceRolloutState::Blocked,
    }
}

pub(crate) fn assurance_gate_block_reason(
    assurance: Option<&EvolutionProposalAssuranceSummary>,
    config: &SwarmConfig,
    current_time_ms: i64,
    target: &str,
) -> Option<String> {
    let Some(summary) = assurance else {
        return Some(format!("{target} is missing durable assurance lineage"));
    };
    if summary.decision == EvolutionProposalAssuranceDecision::Passed {
        return None;
    }
    if active_assurance_waiver(Some(summary), config, current_time_ms).is_some() {
        return None;
    }
    let suffix = match validate_assurance_waiver(summary, config, current_time_ms) {
        Ok(_) => String::new(),
        Err(reason) if summary.waiver.is_some() => format!(": {reason}"),
        Err(_) => String::new(),
    };
    Some(format!(
        "assurance decision `{}` does not permit {target}{suffix}",
        assurance_decision_label(summary.decision)
    ))
}

pub(crate) fn proposal_has_active_blocking_reasons(
    report: &EvolutionProposalReport,
    config: &SwarmConfig,
    current_time_ms: i64,
) -> bool {
    report
        .blocking_reasons
        .iter()
        .any(|reason| reason.source != "assurance")
        || assurance_rollout_state(report.assurance.as_ref(), config, current_time_ms)
            == EvolutionAssuranceRolloutState::Blocked
}

pub(crate) fn render_assurance_summary_lines(
    assurance: &EvolutionProposalAssuranceSummary,
) -> Vec<String> {
    let mut lines = vec![
        format!(
            "Assurance: {} | detector={} catch_rate={}/{} solver={}",
            assurance_decision_label(assurance.decision),
            assurance.coverage.detector,
            assurance
                .coverage
                .actual_catch_rate
                .map(|value| format!("{value:.3}"))
                .unwrap_or_else(|| "n/a".to_string()),
            format!("{:.3}", assurance.coverage.required_catch_rate),
            assurance
                .solver
                .status
                .map(solver_proof_status_label)
                .unwrap_or("missing")
        ),
        format!(
            "Assurance gaps: actionable={} suite={} corpus={}",
            assurance.coverage.actionable_gap_count,
            assurance.coverage.suite_name.as_deref().unwrap_or("n/a"),
            assurance
                .coverage
                .corpus_version
                .as_deref()
                .unwrap_or("n/a")
        ),
    ];
    if !assurance.harvested_case_ids.is_empty() {
        lines.push(format!(
            "Assurance harvested cases: {}",
            assurance.harvested_case_ids.join(", ")
        ));
    }
    if let Some(waiver) = &assurance.waiver {
        lines.push(format!(
            "Assurance waiver: {} | operator={} | expires_at={} | waived_gaps={}",
            waiver.waiver_id, waiver.operator_id, waiver.expires_at_ms, waiver.waived_gap_count
        ));
        lines.push(format!("Waiver reason: {}", waiver.reason));
    }
    lines
}

pub(crate) fn proposal_assurance_blocking_reason(
    report: &EvolutionProposalReport,
    config: &SwarmConfig,
    current_time_ms: i64,
) -> EvolutionProposalBlockingReason {
    let details = assurance_gate_block_reason(
        report.assurance.as_ref(),
        config,
        current_time_ms,
        "rollout progression",
    )
    .unwrap_or_else(|| "assurance gate unexpectedly evaluated as satisfied".to_string());
    EvolutionProposalBlockingReason {
        source: "assurance".to_string(),
        name: "assurance_gate_unsatisfied".to_string(),
        details,
        references: report
            .assurance
            .as_ref()
            .map(|summary| summary.harvested_case_ids.clone())
            .filter(|ids| !ids.is_empty())
            .unwrap_or_else(|| vec![report.proposal_id.clone()]),
    }
}
