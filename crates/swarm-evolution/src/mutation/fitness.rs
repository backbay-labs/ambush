use super::*;

pub(crate) fn materialize_variant_report(
    spec: &EvolutionMutationSpecReport,
    variant: &EvolutionMutationVariantSpec,
    request: &EvolutionDraftMaterializationRequest,
    created_at_ms: i64,
) -> Result<EvolutionMaterializationReport, EvolutionMutationError> {
    let base_experiment_path = request.base_experiment_path.as_ref().ok_or_else(|| {
        EvolutionMutationError::InvalidMutationSpecRequest {
            reason: "materialization request is missing a base experiment path".to_string(),
        }
    })?;
    let base_manifest = load_detector_experiment_manifest(base_experiment_path)?;
    let mut profile = match &base_manifest.candidate {
        DetectorCandidateManifest::SuspiciousProcessTree { profile, .. } => profile.clone(),
        DetectorCandidateManifest::FilelessExecution { strategy_id, .. }
        | DetectorCandidateManifest::BehavioralAnomaly { strategy_id, .. }
        | DetectorCandidateManifest::DnsExfiltration { strategy_id, .. }
        | DetectorCandidateManifest::LateralMovement { strategy_id, .. }
        | DetectorCandidateManifest::CredentialAccess { strategy_id, .. }
        | DetectorCandidateManifest::SuspiciousScripting { strategy_id, .. }
        | DetectorCandidateManifest::Persistence { strategy_id, .. }
        | DetectorCandidateManifest::SupplyChain { strategy_id, .. }
        | DetectorCandidateManifest::NetworkConnect { strategy_id, .. } => {
            return Err(ReplayHarnessError::UnsupportedDetector {
                strategy: format!(
                    "mutation materialization not yet supported for detector `{strategy_id}`"
                ),
            }
            .into());
        }
    };
    let applied_changes = apply_profile_overrides(&mut profile, request)?;
    let experiment_name = materialized_experiment_name(&variant.strategy_id, created_at_ms);
    let experiment_path =
        materialized_experiment_path(base_experiment_path, &variant.strategy_id, created_at_ms);
    let manifest = DetectorExperimentManifest {
        name: experiment_name.clone(),
        description: format!(
            "Materialized from mutation spec `{}` variant `{}` using base experiment `{}`",
            spec.mutation_spec_id, variant.variant_id, base_manifest.name
        ),
        corpus: base_manifest.corpus.clone(),
        verification: base_manifest.verification.clone(),
        candidate: DetectorCandidateManifest::SuspiciousProcessTree {
            strategy_id: variant.strategy_id.clone(),
            description: variant.strategy_description.clone(),
            profile: profile.clone(),
        },
        lineage: ExperimentLineage {
            // Rollout validation expects experiment lineage to remain anchored to the
            // configured detector baseline. Autonomous parent-genome lineage stays on
            // `autonomous_lineage`, which preserves the replayable winner ancestry.
            parent_strategy_id: spec.source_lineage.parent_strategy_id.clone(),
            mutation: variant.mutation.clone(),
            rationale: format!("{} | {}", spec.operator_rationale, variant.rationale),
        },
        gates: base_manifest.gates.clone(),
    };

    if let Some(parent) = experiment_path.parent() {
        fs::create_dir_all(parent).map_err(|source| EvolutionMutationError::ManifestWrite {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let raw = serde_yaml::to_string(&manifest).map_err(|source| {
        EvolutionMutationError::ManifestSerialize {
            path: experiment_path.clone(),
            source,
        }
    })?;
    fs::write(&experiment_path, raw).map_err(|source| EvolutionMutationError::ManifestWrite {
        path: experiment_path.clone(),
        source,
    })?;

    Ok(EvolutionMaterializationReport {
        materialization_id: mutation_materialization_id(
            &spec.mutation_spec_id,
            &variant.variant_id,
            created_at_ms,
        ),
        created_at_ms,
        draft_id: spec.draft_id.clone(),
        pressure_id: spec.pressure_id.clone(),
        source_experiment_id: spec.source_experiment_id.clone(),
        source_experiment_name: spec.source_experiment_name.clone(),
        base_experiment_path: spec.base_experiment_path.clone(),
        experiment_id: experiment_id_for_manifest(&manifest),
        experiment_name,
        experiment_path: experiment_path.display().to_string(),
        strategy_id: variant.strategy_id.clone(),
        strategy_description: variant.strategy_description.clone(),
        lineage: manifest.lineage.clone(),
        profile,
        manifest_sha256: sha256_hex(&manifest)?,
        lineage_sha256: sha256_hex(&manifest.lineage)?,
        applied_changes,
    })
}

pub(crate) fn candidate_score(
    entry: &EvolutionMutationValidationEntry,
    queue_review_state: Option<EvolutionProposalReviewState>,
    assurance_case_count: usize,
) -> f64 {
    let mut score = 0.0;
    score += match entry.status {
        EvolutionValidationBundleStatus::ReadyForQueue => 100.0,
        EvolutionValidationBundleStatus::Blocked => 0.0,
    };
    score += match entry.proof_status {
        EvolutionProposalProofStatus::Proved => 15.0,
        EvolutionProposalProofStatus::Inconsistent => -10.0,
        EvolutionProposalProofStatus::Missing => -20.0,
    };
    if let Some(advisory) = &entry.advisory {
        score += advisory.score_delta * 25.0;
        score += advisory.candidate_matching_memory_count as f64;
        score += match advisory.recommendation {
            StrategyAdvisoryRecommendation::CandidatePreferred => 6.0,
            StrategyAdvisoryRecommendation::CandidateAlreadyStableInProduction => 2.0,
            StrategyAdvisoryRecommendation::RetainBaseline => 0.0,
        };
    }
    score -= (entry.blocking_reason_names.len() as f64) * 5.0;
    score += match queue_review_state {
        Some(EvolutionProposalReviewState::PendingReview) => 1.0,
        Some(EvolutionProposalReviewState::AcceptedForCanary) => 2.0,
        Some(EvolutionProposalReviewState::Deferred) => 0.0,
        Some(EvolutionProposalReviewState::Rejected) => -20.0,
        Some(EvolutionProposalReviewState::Blocked) => -20.0,
        None => 0.0,
    };
    score -= (assurance_case_count as f64) * 1.5;
    score
}

pub(crate) fn candidate_summary(
    entry: &EvolutionMutationValidationEntry,
    queue_review_state: Option<EvolutionProposalReviewState>,
    assurance_case_count: usize,
    score: f64,
) -> String {
    format!(
        "status={} proof={} recommendation={} queue_state={} assurance_cases={} score={score:.3}",
        validation_bundle_status_label(entry.status),
        proof_status_label(entry.proof_status),
        advisory_recommendation_label(entry.advisory.as_ref().map(|a| a.recommendation)),
        queue_review_state.map(review_state_label).unwrap_or("none"),
        assurance_case_count,
    )
}

pub(crate) fn population_objectives(
    experiment: &StrategyExperimentReport,
    verification: &DetectorVerificationReport,
) -> Result<EvolutionPopulationFitnessObjectives, EvolutionMutationError> {
    let verification_manifest = load_verification_manifest(&verification.corpus_path)?;
    let template_count = verification_manifest.canonical_templates.len();
    let missed_templates = verification
        .invariants
        .iter()
        .find(|invariant| invariant.name == "threat_class_templates")
        .map(|invariant| invariant.counterexamples.len())
        .unwrap_or(template_count);
    let threat_class_coverage = if template_count == 0 {
        0.0
    } else {
        ((template_count.saturating_sub(missed_templates)) as f64 / template_count as f64)
            .clamp(0.0, 1.0)
    };
    let detection_rate = experiment
        .comparison
        .candidate
        .detection_rate
        .clamp(0.0, 1.0);
    let false_positive_cost = (1.0
        - experiment
            .comparison
            .candidate
            .false_positive_rate
            .clamp(0.0, 1.0))
    .clamp(0.0, 1.0);
    let latency_budget = verification_manifest
        .resource_budgets
        .max_detect_latency_us
        .max(1) as f64;
    let latency_ratio =
        experiment.comparison.candidate.max_detect_latency_us as f64 / latency_budget;
    let speed = (1.0 / (1.0 + latency_ratio.max(0.0))).clamp(0.0, 1.0);

    Ok(EvolutionPopulationFitnessObjectives {
        detection_rate,
        false_positive_cost,
        speed,
        threat_class_coverage,
    })
}

pub(crate) fn population_fitness(
    objectives: &EvolutionPopulationFitnessObjectives,
    weights: &EvolutionFitnessWeightsConfig,
) -> f64 {
    objectives.detection_rate * weights.detection_rate
        + objectives.false_positive_cost * weights.false_positive_cost
        + objectives.speed * weights.speed
        + objectives.threat_class_coverage * weights.threat_class_coverage
}

pub(crate) fn measure_autonomous_fitness(
    experiment_path: &Path,
    lineage: &EvolutionAutonomousVariantLineage,
    objectives: &EvolutionPopulationFitnessObjectives,
    experiment: &StrategyExperimentReport,
    verification: &DetectorVerificationReport,
    weights: &EvolutionFitnessWeightsConfig,
    evasion_pressure: Option<&EvolutionEvasionPressureInput>,
) -> Result<Option<EvolutionAutonomousFitnessMeasurement>, EvolutionMutationError> {
    Ok(measure_benchmark_fitness(
        experiment_path,
        objectives,
        experiment,
        verification,
        weights,
        evasion_pressure,
    )?
    .map(|measurement| EvolutionAutonomousFitnessMeasurement {
        lineage: lineage.clone(),
        corpus_suite_name: measurement.corpus_suite_name,
        corpus_version: measurement.corpus_version,
        measured_event_count: measurement.measured_event_count,
        detected_event_count: measurement.detected_event_count,
        catch_rate: measurement.catch_rate,
        false_positive_rate: measurement.false_positive_rate,
        false_positive_fitness: measurement.false_positive_fitness,
        max_detect_latency_us: measurement.max_detect_latency_us,
        latency_budget_us: measurement.latency_budget_us,
        latency_fitness: measurement.latency_fitness,
        verification_threat_class_coverage: measurement.verification_threat_class_coverage,
        measured_fitness: measurement.measured_fitness,
    }))
}

pub fn summarize_evolution_benchmark_baseline(
    experiment_path: &Path,
    experiment: &StrategyExperimentReport,
    verification: &DetectorVerificationReport,
    weights: &EvolutionFitnessWeightsConfig,
    evasion_pressure: Option<&EvolutionEvasionPressureInput>,
) -> Result<Option<EvolutionBenchmarkBaselineReport>, EvolutionMutationError> {
    let objectives = population_objectives(experiment, verification)?;
    Ok(measure_benchmark_fitness(
        experiment_path,
        &objectives,
        experiment,
        verification,
        weights,
        evasion_pressure,
    )?
    .map(|measurement| EvolutionBenchmarkBaselineReport {
        strategy_id: experiment.candidate_strategy_id.clone(),
        corpus_suite_name: measurement.corpus_suite_name,
        corpus_version: measurement.corpus_version,
        measured_event_count: measurement.measured_event_count,
        detected_event_count: measurement.detected_event_count,
        measured_fitness: measurement.measured_fitness,
        catch_rate: measurement.catch_rate,
        false_positive_rate: measurement.false_positive_rate,
        false_positive_fitness: measurement.false_positive_fitness,
        latency_fitness: measurement.latency_fitness,
        max_detect_latency_us: measurement.max_detect_latency_us,
        latency_budget_us: measurement.latency_budget_us,
    }))
}

pub(crate) fn measure_benchmark_fitness(
    experiment_path: &Path,
    objectives: &EvolutionPopulationFitnessObjectives,
    experiment: &StrategyExperimentReport,
    verification: &DetectorVerificationReport,
    weights: &EvolutionFitnessWeightsConfig,
    evasion_pressure: Option<&EvolutionEvasionPressureInput>,
) -> Result<Option<MeasuredBenchmarkFitness>, EvolutionMutationError> {
    let Some(evasion_pressure) = evasion_pressure else {
        return Ok(None);
    };
    let measured_scenarios = load_evasion_scenarios(&evasion_pressure.suite_path)?;
    let measured_event_count = measured_scenarios
        .iter()
        .map(|scenario| scenario.events.len())
        .sum::<usize>();
    if measured_event_count == 0 {
        return Ok(None);
    }

    let manifest = load_detector_experiment_manifest(experiment_path)?;
    let detector = build_detector_from_candidate(&manifest.candidate)?;
    let detected_event_count = measured_scenarios
        .iter()
        .flat_map(|scenario| {
            scenario.events.iter().map(|event| {
                detector
                    .evaluate(event)
                    .iter()
                    .any(|finding| finding.threat_class == scenario.threat_class)
            })
        })
        .filter(|detected| *detected)
        .count();
    let catch_rate = ratio(detected_event_count, measured_event_count);
    let false_positive_rate = experiment
        .comparison
        .candidate
        .false_positive_rate
        .clamp(0.0, 1.0);
    let false_positive_fitness = (1.0 - false_positive_rate).clamp(0.0, 1.0);
    let latency_budget_us = load_verification_manifest(&verification.corpus_path)?
        .resource_budgets
        .max_detect_latency_us
        .max(1);
    let max_detect_latency_us = experiment.comparison.candidate.max_detect_latency_us;
    let latency_ratio = max_detect_latency_us as f64 / latency_budget_us as f64;
    let latency_fitness = (1.0 / (1.0 + latency_ratio.max(0.0))).clamp(0.0, 1.0);
    let measured_fitness = population_fitness(
        &EvolutionPopulationFitnessObjectives {
            detection_rate: catch_rate,
            false_positive_cost: false_positive_fitness,
            speed: latency_fitness,
            threat_class_coverage: objectives.threat_class_coverage,
        },
        weights,
    );

    Ok(Some(MeasuredBenchmarkFitness {
        corpus_suite_name: evasion_pressure.suite_name.clone(),
        corpus_version: evasion_pressure.corpus_version.clone(),
        measured_event_count,
        detected_event_count,
        catch_rate,
        false_positive_rate,
        false_positive_fitness,
        max_detect_latency_us,
        latency_budget_us,
        latency_fitness,
        verification_threat_class_coverage: objectives.threat_class_coverage,
        measured_fitness,
    }))
}

pub(crate) fn evaluate_population_evasion_pressure(
    experiment_path: &Path,
    input: &EvolutionEvasionPressureInput,
) -> Result<Option<EvolutionPopulationEvasionSummary>, EvolutionMutationError> {
    if input.gaps.is_empty() {
        return Ok(None);
    }
    let manifest = load_detector_experiment_manifest(experiment_path)?;
    let detector = build_detector_from_candidate(&manifest.candidate)?;
    let focused_scenarios = load_focused_evasion_scenarios(&input.suite_path, input)?;
    let focused_event_count = focused_scenarios
        .iter()
        .map(|scenario| scenario.events.len())
        .sum::<usize>();
    if focused_event_count == 0 {
        return Ok(None);
    }
    let detected_event_count = focused_scenarios
        .iter()
        .flat_map(|scenario| {
            scenario.events.iter().map(|event| {
                detector
                    .evaluate(event)
                    .iter()
                    .any(|finding| finding.threat_class == scenario.threat_class)
            })
        })
        .filter(|detected| *detected)
        .count();
    let gap_closure_rate =
        (detected_event_count as f64 / focused_event_count as f64).clamp(0.0, 1.0);
    let threat_classes = input
        .gaps
        .iter()
        .map(|gap| gap.threat_class.clone())
        .collect::<Vec<_>>();
    let actionable_techniques = input
        .gaps
        .iter()
        .flat_map(|gap| gap.actionable_techniques.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    Ok(Some(EvolutionPopulationEvasionSummary {
        detector: input.detector.clone(),
        suite_name: input.suite_name.clone(),
        corpus_version: input.corpus_version.clone(),
        gap_count: input.gaps.len(),
        focused_event_count,
        detected_event_count,
        gap_closure_rate,
        pressure_score: gap_closure_rate,
        threat_classes,
        actionable_techniques,
    }))
}

#[derive(Debug)]
pub(crate) struct LoadedEvasionScenario {
    pub(crate) threat_class: ThreatClass,
    pub(crate) events: Vec<TelemetryEvent>,
    pub(crate) techniques: Vec<String>,
}

pub(crate) fn load_evasion_scenarios(
    suite_path: &Path,
) -> Result<Vec<LoadedEvasionScenario>, EvolutionMutationError> {
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
            ReplayScenarioInput::ReplayBundles { .. } => continue,
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
            .ok_or_else(|| EvolutionMutationError::InvalidMutationSpecRequest {
                reason: format!(
                    "evasion scenario `{}` could not derive a threat class",
                    loaded.manifest.name
                ),
            })?;
        scenarios.push(LoadedEvasionScenario {
            threat_class,
            events,
            techniques: loaded.manifest.metadata.techniques,
        });
    }
    Ok(scenarios)
}

pub(crate) fn load_focused_evasion_scenarios(
    suite_path: &Path,
    input: &EvolutionEvasionPressureInput,
) -> Result<Vec<LoadedEvasionScenario>, EvolutionMutationError> {
    Ok(load_evasion_scenarios(suite_path)?
        .into_iter()
        .filter(|scenario| {
            scenario_matches_evasion_focus(&scenario.threat_class, &scenario.techniques, input)
        })
        .collect())
}

pub(crate) fn scenario_matches_evasion_focus(
    threat_class: &ThreatClass,
    techniques: &[String],
    input: &EvolutionEvasionPressureInput,
) -> bool {
    input.gaps.iter().any(|gap| {
        &gap.threat_class == threat_class
            && techniques
                .iter()
                .any(|technique| gap.actionable_techniques.contains(technique))
    })
}

pub(crate) fn threat_class_from_payload(payload: &TelemetryPayload) -> ThreatClass {
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

pub(crate) fn trim_population_proposal_history(state: &mut EvolutionPopulationState, now_ms: i64) {
    let cutoff_ms = now_ms.saturating_sub(3_600_000);
    state
        .proposal_timestamps_ms
        .retain(|timestamp| *timestamp >= cutoff_ms);
}

pub(crate) fn candidate_genome_hash(
    candidate: &DetectorCandidateManifest,
) -> Result<String, EvolutionMutationError> {
    sha256_hex(candidate)
}

pub(crate) fn threat_class_coverage(
    detector: &impl DetectionStrategy,
    events: &[TelemetryEvent],
) -> Vec<EvolutionEpisodeThreatClassCoverage> {
    let mut coverage = BTreeMap::<ThreatClass, (usize, usize)>::new();

    for event in events {
        let threat_class = threat_class_for_payload(&event.payload);
        let findings = detector.evaluate(event);
        let detected = findings
            .iter()
            .any(|finding| finding.threat_class == threat_class);
        let entry = coverage.entry(threat_class).or_insert((0, 0));
        entry.0 += 1;
        if detected {
            entry.1 += 1;
        }
    }

    coverage
        .into_iter()
        .map(|(threat_class, (total_events, detected_events))| {
            let detection_coverage = ratio(detected_events, total_events);
            EvolutionEpisodeThreatClassCoverage {
                threat_class,
                total_events,
                detected_events,
                detection_coverage,
                evasion_coverage: (1.0 - detection_coverage).clamp(0.0, 1.0),
            }
        })
        .collect()
}

pub(crate) fn overall_event_detection_rate(
    coverage: &[EvolutionEpisodeThreatClassCoverage],
) -> f64 {
    let total_events = coverage
        .iter()
        .map(|entry| entry.total_events)
        .sum::<usize>();
    let detected_events = coverage
        .iter()
        .map(|entry| entry.detected_events)
        .sum::<usize>();
    ratio(detected_events, total_events)
}

pub(crate) fn overall_threat_class_detection_rate(
    coverage: &[EvolutionEpisodeThreatClassCoverage],
) -> f64 {
    if coverage.is_empty() {
        return 0.0;
    }
    (coverage
        .iter()
        .map(|entry| entry.detection_coverage)
        .sum::<f64>()
        / coverage.len() as f64)
        .clamp(0.0, 1.0)
}

pub(crate) fn adversarial_pressure_score(
    event_detection_rate: f64,
    threat_class_detection_rate: f64,
) -> f64 {
    (event_detection_rate * 0.60 + threat_class_detection_rate * 0.40).clamp(0.0, 1.0)
}

pub(crate) fn evolution_episode_id(
    ranking_id: &str,
    strategy_id: &str,
    adversarial_corpus_sequence_id: &str,
) -> String {
    format!(
        "evolution_episode:{}:{}:{}",
        short_digest(ranking_id),
        short_digest(strategy_id),
        short_digest(adversarial_corpus_sequence_id),
    )
}

pub(crate) fn threat_class_for_payload(payload: &TelemetryPayload) -> ThreatClass {
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

pub(crate) fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        (numerator as f64 / denominator as f64).clamp(0.0, 1.0)
    }
}

pub(crate) fn select_population_survivors(
    candidates: Vec<EvolutionPopulationCandidate>,
    population_size: usize,
    pareto_tournament_size: usize,
) -> Vec<EvolutionPopulationCandidate> {
    if candidates.is_empty() {
        return Vec::new();
    }

    let fronts = pareto_fronts(&candidates);
    let mut survivors = Vec::new();
    for (front_index, front) in fronts.into_iter().enumerate() {
        let mut front_candidates = front
            .into_iter()
            .map(|index| {
                let mut candidate = candidates[index].clone();
                candidate.pareto_front = front_index + 1;
                candidate
            })
            .collect::<Vec<_>>();
        front_candidates.sort_by(compare_population_candidates);

        let remaining_slots = population_size.saturating_sub(survivors.len());
        if remaining_slots == 0 {
            break;
        }
        if front_candidates.len() <= remaining_slots {
            survivors.extend(front_candidates);
            continue;
        }

        let tournaments = front_candidates
            .chunks(pareto_tournament_size.max(1))
            .map(|chunk| chunk.to_vec())
            .collect::<Vec<_>>();
        let mut buckets = tournaments;
        while survivors.len() < population_size {
            let mut advanced = false;
            for bucket in &mut buckets {
                if survivors.len() >= population_size {
                    break;
                }
                if let Some(candidate) = bucket.first().cloned() {
                    survivors.push(candidate);
                    bucket.remove(0);
                    advanced = true;
                }
            }
            if !advanced {
                break;
            }
        }
        break;
    }

    survivors.sort_by(compare_population_candidates);
    survivors.truncate(population_size);
    for (index, candidate) in survivors.iter_mut().enumerate() {
        candidate.population_rank = index + 1;
    }
    survivors
}

pub(crate) fn pareto_fronts(candidates: &[EvolutionPopulationCandidate]) -> Vec<Vec<usize>> {
    let mut remaining = (0..candidates.len()).collect::<Vec<_>>();
    let mut fronts = Vec::new();

    while !remaining.is_empty() {
        let front = remaining
            .iter()
            .copied()
            .filter(|candidate_index| {
                !remaining.iter().copied().any(|other_index| {
                    other_index != *candidate_index
                        && population_candidate_dominates(
                            &candidates[other_index],
                            &candidates[*candidate_index],
                        )
                })
            })
            .collect::<Vec<_>>();
        remaining.retain(|index| !front.contains(index));
        fronts.push(front);
    }

    fronts
}

pub(crate) fn population_candidate_dominates(
    left: &EvolutionPopulationCandidate,
    right: &EvolutionPopulationCandidate,
) -> bool {
    let left_values = [
        left.objectives.detection_rate,
        left.objectives.false_positive_cost,
        left.objectives.speed,
        left.objectives.threat_class_coverage,
    ];
    let right_values = [
        right.objectives.detection_rate,
        right.objectives.false_positive_cost,
        right.objectives.speed,
        right.objectives.threat_class_coverage,
    ];
    left_values
        .iter()
        .zip(right_values.iter())
        .all(|(left, right)| left >= right)
        && left_values
            .iter()
            .zip(right_values.iter())
            .any(|(left, right)| left > right)
}

pub(crate) fn compare_population_candidates(
    left: &EvolutionPopulationCandidate,
    right: &EvolutionPopulationCandidate,
) -> std::cmp::Ordering {
    left.proposed_at_ms
        .is_some()
        .cmp(&right.proposed_at_ms.is_some())
        .then_with(|| {
            right
                .fitness
                .partial_cmp(&left.fitness)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .then_with(|| {
            right
                .ranking_score
                .partial_cmp(&left.ranking_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .then_with(|| left.strategy_id.cmp(&right.strategy_id))
}
