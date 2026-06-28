use super::*;

pub(crate) struct AutonomousGenerationSeed {
    pub(crate) reference: EvolutionMutationParentGenome,
    pub(crate) profile: SuspiciousProcessTreeProfile,
}

#[derive(Debug, Default)]
pub(crate) struct SuspiciousProcessTreeGapExpansion {
    pub(crate) suspicious_parents: Vec<String>,
    pub(crate) suspicious_children: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct MeasuredBenchmarkFitness {
    pub(crate) corpus_suite_name: String,
    pub(crate) corpus_version: String,
    pub(crate) measured_event_count: usize,
    pub(crate) detected_event_count: usize,
    pub(crate) catch_rate: f64,
    pub(crate) false_positive_rate: f64,
    pub(crate) false_positive_fitness: f64,
    pub(crate) max_detect_latency_us: u64,
    pub(crate) latency_budget_us: u64,
    pub(crate) latency_fitness: f64,
    pub(crate) verification_threat_class_coverage: f64,
    pub(crate) measured_fitness: f64,
}

pub(crate) fn load_autonomous_generation_parents(
    drafting: &DefaultEvolutionDraftingHarness,
    population: Option<&EvolutionPopulationState>,
    draft: &crate::drafting::EvolutionDraftReport,
    pressure: &EvolutionPressureReport,
    base_experiment_path_override: Option<&Path>,
) -> Result<Vec<AutonomousGenerationSeed>, EvolutionMutationError> {
    let mut parents = Vec::new();

    if let Some(population) = population {
        for candidate in &population.members {
            let Some(seed) = load_population_seed(drafting, candidate)? else {
                continue;
            };
            parents.push(seed);
            if parents.len() >= 3 {
                break;
            }
        }
    }

    if parents.is_empty() {
        parents.push(load_source_seed(
            drafting,
            draft,
            pressure,
            base_experiment_path_override,
        )?);
    }

    Ok(parents)
}

pub(crate) fn load_population_seed(
    drafting: &DefaultEvolutionDraftingHarness,
    candidate: &EvolutionPopulationCandidate,
) -> Result<Option<AutonomousGenerationSeed>, EvolutionMutationError> {
    let Some(materialization) = drafting.load_materialization(&candidate.materialization_id)?
    else {
        return Ok(None);
    };
    let manifest =
        load_detector_experiment_manifest(Path::new(&materialization.report.experiment_path))?;
    let profile = load_supported_profile(&manifest.candidate)?;
    Ok(Some(AutonomousGenerationSeed {
        reference: EvolutionMutationParentGenome {
            strategy_id: candidate.strategy_id.clone(),
            materialization_id: Some(candidate.materialization_id.clone()),
            experiment_id: candidate.experiment_id.clone(),
            experiment_path: materialization.report.experiment_path.clone(),
            generation: candidate.generation,
            population_rank: candidate.population_rank,
            fitness: candidate.fitness,
            genome_sha256: candidate_genome_hash(&manifest.candidate)?,
        },
        profile,
    }))
}

pub(crate) fn load_source_seed(
    drafting: &DefaultEvolutionDraftingHarness,
    draft: &crate::drafting::EvolutionDraftReport,
    pressure: &EvolutionPressureReport,
    base_experiment_path_override: Option<&Path>,
) -> Result<AutonomousGenerationSeed, EvolutionMutationError> {
    let base_experiment_path = base_experiment_path_override
        .map(Path::to_path_buf)
        .unwrap_or(infer_base_experiment_path(
            &drafting.config_path,
            &draft.draft_id,
            pressure,
        )?);
    let manifest = load_detector_experiment_manifest(&base_experiment_path)?;
    let profile = load_supported_profile(&manifest.candidate)?;
    Ok(AutonomousGenerationSeed {
        reference: EvolutionMutationParentGenome {
            strategy_id: draft.parent_strategy_id.clone(),
            materialization_id: None,
            experiment_id: pressure
                .experiment_id
                .clone()
                .unwrap_or_else(|| experiment_id_for_manifest(&manifest)),
            experiment_path: base_experiment_path.display().to_string(),
            generation: 0,
            population_rank: 0,
            fitness: 0.0,
            genome_sha256: candidate_genome_hash(&manifest.candidate)?,
        },
        profile,
    })
}

pub(crate) fn load_supported_profile(
    candidate: &DetectorCandidateManifest,
) -> Result<SuspiciousProcessTreeProfile, EvolutionMutationError> {
    match candidate {
        DetectorCandidateManifest::SuspiciousProcessTree { profile, .. } => Ok(profile.clone()),
        other => Err(ReplayHarnessError::UnsupportedDetector {
            strategy: format!(
                "autonomous mutation generation not yet supported for detector `{}`",
                other.strategy_id()
            ),
        }
        .into()),
    }
}

pub(crate) fn build_autonomous_variant_specs(
    strategy_root: &str,
    max_variants: usize,
    parents: &[AutonomousGenerationSeed],
    evasion_pressure: Option<&EvolutionEvasionPressureInput>,
) -> Result<Vec<EvolutionMutationVariantSpec>, EvolutionMutationError> {
    let base =
        parents
            .first()
            .ok_or_else(|| EvolutionMutationError::InvalidMutationSpecRequest {
                reason: "autonomous mutation generation requires at least one parent".to_string(),
            })?;
    let strategy_root = sanitize_id(strategy_root);
    let gap_summary = evasion_gap_summary(evasion_pressure);
    let nudge_multiplier = evasion_nudge_multiplier(evasion_pressure);
    let mut variants = Vec::new();

    variants.push(build_perturbation_variant(
        &strategy_root,
        base,
        1,
        nudge_multiplier,
        gap_summary.as_str(),
    ));

    if variants.len() < max_variants
        && let Some(variant) = build_gap_expansion_variant(
            &strategy_root,
            base,
            variants.len() + 1,
            gap_summary.as_str(),
            evasion_pressure,
        )?
    {
        variants.push(variant);
    }

    let mut donor_slot = 0usize;
    while variants.len() < max_variants {
        if let Some(donor) = parents.get(donor_slot + 1)
            && let Some(variant) =
                build_crossover_variant(&strategy_root, base, donor, variants.len() + 1)
        {
            variants.push(variant);
            donor_slot += 1;
            continue;
        }

        if variants.len() == 1 {
            variants.push(build_seed_control_variant(
                &strategy_root,
                base,
                variants.len() + 1,
            ));
            continue;
        }

        let step_index = variants
            .iter()
            .filter(|variant| variant.mutation == "autonomous_bounded_perturbation")
            .count()
            + 1;
        variants.push(build_perturbation_variant(
            &strategy_root,
            base,
            variants.len() + 1,
            nudge_multiplier * step_index as f64,
            gap_summary.as_str(),
        ));
    }

    Ok(variants)
}

pub(crate) fn build_seed_control_variant(
    strategy_root: &str,
    base: &AutonomousGenerationSeed,
    ordinal: usize,
) -> EvolutionMutationVariantSpec {
    let overrides = EvolutionMutationProfileOverrides::default();
    EvolutionMutationVariantSpec {
        variant_id: format!("seed-control-{ordinal}"),
        strategy_id: format!("{strategy_root}_seed_control_{ordinal}"),
        strategy_description: format!(
            "Autonomous seed control from {}",
            base.reference.strategy_id
        ),
        mutation: "autonomous_seed_control".to_string(),
        rationale: format!(
            "preserve top population candidate `{}` as a replayable control genome",
            base.reference.strategy_id
        ),
        mutation_dimensions: overrides.dimensions(),
        overrides,
        autonomous_lineage: Some(EvolutionAutonomousVariantLineage {
            recipe_kind: EvolutionAutonomousVariantRecipeKind::SeedControl,
            base_parent_strategy_id: base.reference.strategy_id.clone(),
            parent_strategy_ids: vec![base.reference.strategy_id.clone()],
            parent_materialization_ids: base.reference.materialization_id.iter().cloned().collect(),
            parent_genome_sha256: vec![base.reference.genome_sha256.clone()],
            inherited_suspicious_parents: Vec::new(),
            inherited_suspicious_children: Vec::new(),
            target_high_confidence_threshold: None,
            target_medium_confidence_threshold: None,
        }),
    }
}

pub(crate) fn build_perturbation_variant(
    strategy_root: &str,
    base: &AutonomousGenerationSeed,
    ordinal: usize,
    step_multiplier: f64,
    gap_summary: &str,
) -> EvolutionMutationVariantSpec {
    let overrides = threshold_nudge_overrides(
        base.profile.medium_confidence_threshold,
        base.profile.high_confidence_threshold,
        step_multiplier,
    );
    EvolutionMutationVariantSpec {
        variant_id: format!("bounded-perturbation-{ordinal}"),
        strategy_id: format!("{strategy_root}_bounded_perturbation_{ordinal}"),
        strategy_description: format!(
            "Autonomous bounded perturbation from {}",
            base.reference.strategy_id
        ),
        mutation: "autonomous_bounded_perturbation".to_string(),
        rationale: format!(
            "apply a bounded threshold perturbation to top population candidate `{}`{}",
            base.reference.strategy_id, gap_summary
        ),
        mutation_dimensions: overrides.dimensions(),
        autonomous_lineage: Some(EvolutionAutonomousVariantLineage {
            recipe_kind: EvolutionAutonomousVariantRecipeKind::BoundedPerturbation,
            base_parent_strategy_id: base.reference.strategy_id.clone(),
            parent_strategy_ids: vec![base.reference.strategy_id.clone()],
            parent_materialization_ids: base.reference.materialization_id.iter().cloned().collect(),
            parent_genome_sha256: vec![base.reference.genome_sha256.clone()],
            inherited_suspicious_parents: Vec::new(),
            inherited_suspicious_children: Vec::new(),
            target_high_confidence_threshold: overrides.high_confidence_threshold.clone(),
            target_medium_confidence_threshold: overrides.medium_confidence_threshold.clone(),
        }),
        overrides,
    }
}

pub(crate) fn build_gap_expansion_variant(
    strategy_root: &str,
    base: &AutonomousGenerationSeed,
    ordinal: usize,
    gap_summary: &str,
    evasion_pressure: Option<&EvolutionEvasionPressureInput>,
) -> Result<Option<EvolutionMutationVariantSpec>, EvolutionMutationError> {
    let Some(expansion) =
        derive_suspicious_process_tree_gap_expansion(&base.profile, evasion_pressure)?
    else {
        return Ok(None);
    };
    let overrides = EvolutionMutationProfileOverrides {
        add_suspicious_parents: expansion.suspicious_parents.clone(),
        remove_suspicious_parents: Vec::new(),
        add_suspicious_children: expansion.suspicious_children.clone(),
        remove_suspicious_children: Vec::new(),
        high_confidence_threshold: None,
        medium_confidence_threshold: None,
    };
    Ok(Some(EvolutionMutationVariantSpec {
        variant_id: format!("gap-expansion-{ordinal}"),
        strategy_id: format!("{strategy_root}_gap_expansion_{ordinal}"),
        strategy_description: format!(
            "Autonomous gap expansion from {}",
            base.reference.strategy_id
        ),
        mutation: "autonomous_gap_expansion".to_string(),
        rationale: format!(
            "apply a bounded process-tree coverage expansion to top population candidate `{}`{}",
            base.reference.strategy_id, gap_summary
        ),
        mutation_dimensions: overrides.dimensions(),
        autonomous_lineage: Some(EvolutionAutonomousVariantLineage {
            recipe_kind: EvolutionAutonomousVariantRecipeKind::GapExpansion,
            base_parent_strategy_id: base.reference.strategy_id.clone(),
            parent_strategy_ids: vec![base.reference.strategy_id.clone()],
            parent_materialization_ids: base.reference.materialization_id.iter().cloned().collect(),
            parent_genome_sha256: vec![base.reference.genome_sha256.clone()],
            inherited_suspicious_parents: expansion.suspicious_parents,
            inherited_suspicious_children: expansion.suspicious_children,
            target_high_confidence_threshold: None,
            target_medium_confidence_threshold: None,
        }),
        overrides,
    }))
}

pub(crate) fn build_crossover_variant(
    strategy_root: &str,
    base: &AutonomousGenerationSeed,
    donor: &AutonomousGenerationSeed,
    ordinal: usize,
) -> Option<EvolutionMutationVariantSpec> {
    let (overrides, inherited_parents, inherited_children) =
        bounded_crossover_overrides(&base.profile, &donor.profile);
    let mutation_dimensions = overrides.dimensions();
    if mutation_dimensions.len() == 1 && mutation_dimensions[0] == "profile_copy" {
        return None;
    }

    Some(EvolutionMutationVariantSpec {
        variant_id: format!("bounded-crossover-{ordinal}"),
        strategy_id: format!("{strategy_root}_bounded_crossover_{ordinal}"),
        strategy_description: format!(
            "Autonomous bounded crossover from {} and {}",
            base.reference.strategy_id, donor.reference.strategy_id
        ),
        mutation: "autonomous_bounded_crossover".to_string(),
        rationale: format!(
            "merge bounded profile features from top population genomes `{}` and `{}`",
            base.reference.strategy_id, donor.reference.strategy_id
        ),
        mutation_dimensions,
        autonomous_lineage: Some(EvolutionAutonomousVariantLineage {
            recipe_kind: EvolutionAutonomousVariantRecipeKind::BoundedCrossover,
            base_parent_strategy_id: base.reference.strategy_id.clone(),
            parent_strategy_ids: vec![
                base.reference.strategy_id.clone(),
                donor.reference.strategy_id.clone(),
            ],
            parent_materialization_ids: base
                .reference
                .materialization_id
                .iter()
                .chain(donor.reference.materialization_id.iter())
                .cloned()
                .collect(),
            parent_genome_sha256: vec![
                base.reference.genome_sha256.clone(),
                donor.reference.genome_sha256.clone(),
            ],
            inherited_suspicious_parents: inherited_parents,
            inherited_suspicious_children: inherited_children,
            target_high_confidence_threshold: overrides.high_confidence_threshold.clone(),
            target_medium_confidence_threshold: overrides.medium_confidence_threshold.clone(),
        }),
        overrides,
    })
}

pub(crate) fn bounded_crossover_overrides(
    base: &SuspiciousProcessTreeProfile,
    donor: &SuspiciousProcessTreeProfile,
) -> (EvolutionMutationProfileOverrides, Vec<String>, Vec<String>) {
    let inherited_parents =
        bounded_unique_entries(&base.suspicious_parents, &donor.suspicious_parents, 2);
    let inherited_children =
        bounded_unique_entries(&base.suspicious_children, &donor.suspicious_children, 2);
    let target_medium = midpoint_threshold(
        base.medium_confidence_threshold,
        donor.medium_confidence_threshold,
    );
    let target_high = midpoint_threshold(
        base.high_confidence_threshold,
        donor.high_confidence_threshold,
    );
    let high_confidence_threshold = target_high
        .filter(|value| (value - base.high_confidence_threshold).abs() > 0.000_5)
        .map(format_threshold);
    let medium_confidence_threshold = target_medium
        .filter(|value| (value - base.medium_confidence_threshold).abs() > 0.000_5)
        .map(format_threshold);
    (
        EvolutionMutationProfileOverrides {
            add_suspicious_parents: inherited_parents.clone(),
            remove_suspicious_parents: Vec::new(),
            add_suspicious_children: inherited_children.clone(),
            remove_suspicious_children: Vec::new(),
            high_confidence_threshold,
            medium_confidence_threshold,
        },
        inherited_parents,
        inherited_children,
    )
}

pub(crate) fn bounded_unique_entries(
    base: &[String],
    donor: &[String],
    limit: usize,
) -> Vec<String> {
    donor
        .iter()
        .filter(|entry| {
            !base
                .iter()
                .any(|current| current.eq_ignore_ascii_case(entry))
        })
        .map(|entry| entry.to_ascii_lowercase())
        .take(limit.max(1))
        .collect()
}

pub(crate) fn midpoint_threshold(base: f64, donor: f64) -> Option<f64> {
    let midpoint = ((base + donor) / 2.0).clamp(0.05, 0.99);
    if (midpoint - base).abs() <= 0.000_5 {
        None
    } else {
        Some(midpoint)
    }
}

pub(crate) fn format_threshold(value: f64) -> String {
    format!("{value:.3}")
}

pub(crate) fn threshold_nudge_overrides(
    base_medium: f64,
    base_high: f64,
    step_multiplier: f64,
) -> EvolutionMutationProfileOverrides {
    let step = 0.03 * step_multiplier.max(1.0);
    let nudged_medium = (base_medium - step).clamp(0.05, 0.95);
    let nudged_high = (base_high - step).clamp(nudged_medium, 0.99);
    EvolutionMutationProfileOverrides {
        add_suspicious_parents: Vec::new(),
        remove_suspicious_parents: Vec::new(),
        add_suspicious_children: Vec::new(),
        remove_suspicious_children: Vec::new(),
        high_confidence_threshold: Some(format_threshold(nudged_high)),
        medium_confidence_threshold: Some(format_threshold(nudged_medium)),
    }
}

pub(crate) fn derive_suspicious_process_tree_gap_expansion(
    base: &SuspiciousProcessTreeProfile,
    evasion_pressure: Option<&EvolutionEvasionPressureInput>,
) -> Result<Option<SuspiciousProcessTreeGapExpansion>, EvolutionMutationError> {
    let Some(evasion_pressure) = evasion_pressure else {
        return Ok(None);
    };
    let focused_scenarios =
        load_focused_evasion_scenarios(&evasion_pressure.suite_path, evasion_pressure)?;
    let mut expansion = SuspiciousProcessTreeGapExpansion::default();
    for scenario in focused_scenarios {
        for event in scenario.events {
            let TelemetryPayload::ProcessStart(process) = event.payload else {
                continue;
            };
            push_gap_entry(
                &mut expansion.suspicious_parents,
                &base.suspicious_parents,
                &process.parent_process,
                2,
            );
            push_gap_entry(
                &mut expansion.suspicious_children,
                &base.suspicious_children,
                &process.process_name,
                3,
            );
        }
    }
    if expansion.suspicious_parents.is_empty() && expansion.suspicious_children.is_empty() {
        Ok(None)
    } else {
        Ok(Some(expansion))
    }
}

pub(crate) fn push_gap_entry(
    derived: &mut Vec<String>,
    existing: &[String],
    candidate: &str,
    limit: usize,
) {
    if derived.len() >= limit.max(1) {
        return;
    }
    let candidate = candidate.to_ascii_lowercase();
    if existing
        .iter()
        .any(|entry| entry.eq_ignore_ascii_case(&candidate))
        || derived
            .iter()
            .any(|entry| entry.eq_ignore_ascii_case(&candidate))
    {
        return;
    }
    derived.push(candidate);
}

pub(crate) fn evasion_gap_summary(
    evasion_pressure: Option<&EvolutionEvasionPressureInput>,
) -> String {
    let Some(evasion_pressure) = evasion_pressure else {
        return String::new();
    };
    if evasion_pressure.gaps.is_empty() {
        return " across tracked evasion corpus".to_string();
    }
    let techniques = evasion_pressure
        .gaps
        .iter()
        .flat_map(|gap| gap.actionable_techniques.iter().cloned())
        .take(3)
        .collect::<Vec<_>>();
    let focus = if techniques.is_empty() {
        "measured evasion gaps".to_string()
    } else {
        format!("measured evasion gaps ({})", techniques.join(", "))
    };
    format!(" while targeting {focus}")
}

pub(crate) fn evasion_nudge_multiplier(
    evasion_pressure: Option<&EvolutionEvasionPressureInput>,
) -> f64 {
    let Some(evasion_pressure) = evasion_pressure else {
        return 1.0;
    };
    let gap_count = evasion_pressure.gaps.len() as f64;
    let average_gap_severity = evasion_pressure
        .gaps
        .iter()
        .map(|gap| gap.missed_payloads as f64 / gap.total_payloads.max(1) as f64)
        .sum::<f64>()
        / gap_count.max(1.0);
    (1.0 + average_gap_severity + (gap_count - 1.0).min(2.0) * 0.25).clamp(1.0, 2.0)
}
