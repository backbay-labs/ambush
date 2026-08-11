use super::*;

pub(crate) struct AutonomousGenerationSeed {
    pub(crate) reference: EvolutionMutationParentGenome,
    pub(crate) genome: EvolutionDetectorGenome,
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

    if let Some(detector) = parents
        .first()
        .map(|seed| seed.genome.strategy().to_string())
    {
        parents.retain(|seed| seed.genome.strategy() == detector);
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
    let genome = EvolutionDetectorGenome::from_candidate(&manifest.candidate)?;
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
        genome,
    }))
}

pub(crate) fn load_source_seed(
    drafting: &DefaultEvolutionDraftingHarness,
    draft: &crate::drafting::EvolutionDraftReport,
    pressure: &EvolutionPressureReport,
    base_experiment_path_override: Option<&Path>,
) -> Result<AutonomousGenerationSeed, EvolutionMutationError> {
    // `Option::unwrap_or` evaluates its argument eagerly, so the previous form
    // ran `infer_base_experiment_path` -- which scans and parses EVERY manifest
    // under the repo's `experiments/` directory -- even when the caller supplied
    // an override, and propagated that scan's `?` out of this function.
    let base_experiment_path = match base_experiment_path_override {
        Some(path) => path.to_path_buf(),
        None => infer_base_experiment_path(&drafting.config_path, &draft.draft_id, pressure)?,
    };
    let manifest = load_detector_experiment_manifest(&base_experiment_path)?;
    let genome = EvolutionDetectorGenome::from_candidate(&manifest.candidate)?;
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
        genome,
    })
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
    match &base.genome {
        EvolutionDetectorGenome::SuspiciousProcessTree { .. } => {
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
        EvolutionDetectorGenome::BehavioralAnomaly { .. } => {
            build_behavioral_autonomous_variant_specs(
                &strategy_root,
                max_variants,
                parents,
                nudge_multiplier,
            )
        }
        EvolutionDetectorGenome::FilelessExecution { .. } => {
            build_fileless_autonomous_variant_specs(
                &strategy_root,
                max_variants,
                parents,
                nudge_multiplier,
            )
        }
        EvolutionDetectorGenome::DnsExfiltration { .. } => build_dns_autonomous_variant_specs(
            &strategy_root,
            max_variants,
            parents,
            nudge_multiplier,
        ),
    }
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
        target_genome: None,
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
    let profile = match suspicious_process_tree_profile(base) {
        Some(profile) => profile,
        None => unreachable!("process-tree perturbation requires a process-tree parent genome"),
    };
    let overrides = threshold_nudge_overrides(
        profile.medium_confidence_threshold,
        profile.high_confidence_threshold,
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
        target_genome: None,
    }
}

pub(crate) fn build_gap_expansion_variant(
    strategy_root: &str,
    base: &AutonomousGenerationSeed,
    ordinal: usize,
    gap_summary: &str,
    evasion_pressure: Option<&EvolutionEvasionPressureInput>,
) -> Result<Option<EvolutionMutationVariantSpec>, EvolutionMutationError> {
    let profile = match suspicious_process_tree_profile(base) {
        Some(profile) => profile,
        None => {
            return Err(EvolutionMutationError::InvalidMutationSpecRequest {
                reason: "process-tree gap expansion requires a process-tree parent genome"
                    .to_string(),
            });
        }
    };
    let Some(expansion) = derive_suspicious_process_tree_gap_expansion(profile, evasion_pressure)?
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
        target_genome: None,
        overrides,
    }))
}

pub(crate) fn build_crossover_variant(
    strategy_root: &str,
    base: &AutonomousGenerationSeed,
    donor: &AutonomousGenerationSeed,
    ordinal: usize,
) -> Option<EvolutionMutationVariantSpec> {
    let (Some(base_profile), Some(donor_profile)) = (
        suspicious_process_tree_profile(base),
        suspicious_process_tree_profile(donor),
    ) else {
        return None;
    };
    let (overrides, inherited_parents, inherited_children) =
        bounded_crossover_overrides(base_profile, donor_profile);
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
        target_genome: None,
        overrides,
    })
}

pub(crate) fn build_behavioral_autonomous_variant_specs(
    strategy_root: &str,
    max_variants: usize,
    parents: &[AutonomousGenerationSeed],
    step_multiplier: f64,
) -> Result<Vec<EvolutionMutationVariantSpec>, EvolutionMutationError> {
    let base =
        parents
            .first()
            .ok_or_else(|| EvolutionMutationError::InvalidMutationSpecRequest {
                reason: "autonomous mutation generation requires at least one parent".to_string(),
            })?;
    let mut variants = vec![build_behavioral_perturbation_variant(
        strategy_root,
        base,
        1,
        step_multiplier,
    )?];
    let mut donor_slot = 0usize;

    while variants.len() < max_variants {
        if let Some(donor) = parents.get(donor_slot + 1)
            && let Some(variant) =
                build_behavioral_crossover_variant(strategy_root, base, donor, variants.len() + 1)?
        {
            variants.push(variant);
            donor_slot += 1;
            continue;
        }

        if variants.len() == 1 {
            variants.push(build_behavioral_seed_control_variant(
                strategy_root,
                base,
                variants.len() + 1,
            )?);
            continue;
        }

        let step_index = variants
            .iter()
            .filter(|variant| variant.mutation == "autonomous_bounded_perturbation")
            .count()
            + 1;
        variants.push(build_behavioral_perturbation_variant(
            strategy_root,
            base,
            variants.len() + 1,
            step_multiplier * step_index as f64,
        )?);
    }

    Ok(variants)
}

pub(crate) fn build_behavioral_seed_control_variant(
    strategy_root: &str,
    base: &AutonomousGenerationSeed,
    ordinal: usize,
) -> Result<EvolutionMutationVariantSpec, EvolutionMutationError> {
    build_typed_seed_control_variant(strategy_root, base, ordinal)
}

pub(crate) fn build_typed_seed_control_variant(
    strategy_root: &str,
    base: &AutonomousGenerationSeed,
    ordinal: usize,
) -> Result<EvolutionMutationVariantSpec, EvolutionMutationError> {
    let genome = base.genome.clone();
    Ok(EvolutionMutationVariantSpec {
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
        mutation_dimensions: mutation_dimensions_for_target_genome(&base.genome, &genome)?,
        overrides: EvolutionMutationProfileOverrides::default(),
        target_genome: Some(genome),
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
    })
}

pub(crate) fn build_behavioral_perturbation_variant(
    strategy_root: &str,
    base: &AutonomousGenerationSeed,
    ordinal: usize,
    step_multiplier: f64,
) -> Result<EvolutionMutationVariantSpec, EvolutionMutationError> {
    let profile = match behavioral_anomaly_profile(base) {
        Some(profile) => profile,
        None => {
            return Err(EvolutionMutationError::InvalidMutationSpecRequest {
                reason: "behavioral perturbation requires a behavioral-anomaly parent genome"
                    .to_string(),
            });
        }
    };
    let mut mutated = profile.clone();
    let step = step_multiplier.clamp(1.0, 3.0);
    mutated.high_confidence_z_score =
        (profile.high_confidence_z_score - (0.18 * step)).clamp(0.5, 10.0);
    mutated.min_feature_weight =
        (profile.min_feature_weight * (1.0 - 0.08 * step)).clamp(0.01, 1.0);
    mutated.min_host_observations = profile
        .min_host_observations
        .saturating_sub(step.ceil() as u64)
        .max(1);
    mutated.min_identity_observations = profile
        .min_identity_observations
        .saturating_sub(step.ceil() as u64)
        .max(1);
    mutated.min_peer_group_observations = profile
        .min_peer_group_observations
        .saturating_sub(step.ceil() as u64)
        .max(1);
    mutated.distribution_min_observations = profile
        .distribution_min_observations
        .saturating_sub(step.ceil() as u64)
        .max(1);
    mutated.high_confidence_threshold =
        (profile.high_confidence_threshold - (0.03 * step)).clamp(0.05, 0.99);
    mutated.medium_confidence_threshold = (profile.medium_confidence_threshold - (0.04 * step))
        .clamp(0.05, mutated.high_confidence_threshold);

    let target_genome = EvolutionDetectorGenome::BehavioralAnomaly { profile: mutated };
    let (high, medium) = target_genome.thresholds();
    Ok(EvolutionMutationVariantSpec {
        variant_id: format!("bounded-perturbation-{ordinal}"),
        strategy_id: format!("{strategy_root}_bounded_perturbation_{ordinal}"),
        strategy_description: format!(
            "Autonomous bounded perturbation from {}",
            base.reference.strategy_id
        ),
        mutation: "autonomous_bounded_perturbation".to_string(),
        rationale: format!(
            "apply a bounded behavioral-anomaly sensitivity perturbation to top population candidate `{}`",
            base.reference.strategy_id
        ),
        mutation_dimensions: mutation_dimensions_for_target_genome(&base.genome, &target_genome)?,
        overrides: EvolutionMutationProfileOverrides::default(),
        target_genome: Some(target_genome),
        autonomous_lineage: Some(EvolutionAutonomousVariantLineage {
            recipe_kind: EvolutionAutonomousVariantRecipeKind::BoundedPerturbation,
            base_parent_strategy_id: base.reference.strategy_id.clone(),
            parent_strategy_ids: vec![base.reference.strategy_id.clone()],
            parent_materialization_ids: base.reference.materialization_id.iter().cloned().collect(),
            parent_genome_sha256: vec![base.reference.genome_sha256.clone()],
            inherited_suspicious_parents: Vec::new(),
            inherited_suspicious_children: Vec::new(),
            target_high_confidence_threshold: Some(format_threshold(high)),
            target_medium_confidence_threshold: Some(format_threshold(medium)),
        }),
    })
}

pub(crate) fn build_behavioral_crossover_variant(
    strategy_root: &str,
    base: &AutonomousGenerationSeed,
    donor: &AutonomousGenerationSeed,
    ordinal: usize,
) -> Result<Option<EvolutionMutationVariantSpec>, EvolutionMutationError> {
    let (Some(base_profile), Some(donor_profile)) = (
        behavioral_anomaly_profile(base),
        behavioral_anomaly_profile(donor),
    ) else {
        return Ok(None);
    };
    let mut profile = base_profile.clone();
    profile
        .sensitive_parent_processes
        .extend(bounded_unique_entries(
            &base_profile.sensitive_parent_processes,
            &donor_profile.sensitive_parent_processes,
            2,
        ));
    profile
        .sensitive_child_processes
        .extend(bounded_unique_entries(
            &base_profile.sensitive_child_processes,
            &donor_profile.sensitive_child_processes,
            2,
        ));
    profile.rare_role_tools.extend(bounded_unique_entries(
        &base_profile.rare_role_tools,
        &donor_profile.rare_role_tools,
        2,
    ));
    profile
        .trusted_binary_prefixes
        .extend(bounded_unique_entries(
            &base_profile.trusted_binary_prefixes,
            &donor_profile.trusted_binary_prefixes,
            1,
        ));
    profile.high_confidence_z_score = midpoint_value(
        base_profile.high_confidence_z_score,
        donor_profile.high_confidence_z_score,
    )
    .unwrap_or(base_profile.high_confidence_z_score);
    profile.min_feature_weight = midpoint_value(
        base_profile.min_feature_weight,
        donor_profile.min_feature_weight,
    )
    .unwrap_or(base_profile.min_feature_weight);
    profile.baseline_half_life_secs = midpoint_value(
        base_profile.baseline_half_life_secs,
        donor_profile.baseline_half_life_secs,
    )
    .unwrap_or(base_profile.baseline_half_life_secs);
    profile.distribution_stddev_floor = midpoint_value(
        base_profile.distribution_stddev_floor,
        donor_profile.distribution_stddev_floor,
    )
    .unwrap_or(base_profile.distribution_stddev_floor);
    profile.high_confidence_threshold = midpoint_threshold(
        base_profile.high_confidence_threshold,
        donor_profile.high_confidence_threshold,
    )
    .unwrap_or(base_profile.high_confidence_threshold);
    profile.medium_confidence_threshold = midpoint_threshold(
        base_profile.medium_confidence_threshold,
        donor_profile.medium_confidence_threshold,
    )
    .unwrap_or(base_profile.medium_confidence_threshold);
    profile.min_host_observations = rounded_midpoint_count(
        base_profile.min_host_observations,
        donor_profile.min_host_observations,
    );
    profile.min_identity_observations = rounded_midpoint_count(
        base_profile.min_identity_observations,
        donor_profile.min_identity_observations,
    );
    profile.min_peer_group_observations = rounded_midpoint_count(
        base_profile.min_peer_group_observations,
        donor_profile.min_peer_group_observations,
    );
    profile.distribution_min_observations = rounded_midpoint_count(
        base_profile.distribution_min_observations,
        donor_profile.distribution_min_observations,
    );

    let target_genome = EvolutionDetectorGenome::BehavioralAnomaly { profile };
    let mutation_dimensions = mutation_dimensions_for_target_genome(&base.genome, &target_genome)?;
    if mutation_dimensions.len() == 1 && mutation_dimensions[0] == "profile_copy" {
        return Ok(None);
    }
    let (high, medium) = target_genome.thresholds();
    Ok(Some(EvolutionMutationVariantSpec {
        variant_id: format!("bounded-crossover-{ordinal}"),
        strategy_id: format!("{strategy_root}_bounded_crossover_{ordinal}"),
        strategy_description: format!(
            "Autonomous bounded crossover from {} and {}",
            base.reference.strategy_id, donor.reference.strategy_id
        ),
        mutation: "autonomous_bounded_crossover".to_string(),
        rationale: format!(
            "merge bounded behavioral-anomaly profile features from top population genomes `{}` and `{}`",
            base.reference.strategy_id, donor.reference.strategy_id
        ),
        mutation_dimensions,
        overrides: EvolutionMutationProfileOverrides::default(),
        target_genome: Some(target_genome),
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
            inherited_suspicious_parents: Vec::new(),
            inherited_suspicious_children: Vec::new(),
            target_high_confidence_threshold: Some(format_threshold(high)),
            target_medium_confidence_threshold: Some(format_threshold(medium)),
        }),
    }))
}

pub(crate) fn build_fileless_autonomous_variant_specs(
    strategy_root: &str,
    max_variants: usize,
    parents: &[AutonomousGenerationSeed],
    step_multiplier: f64,
) -> Result<Vec<EvolutionMutationVariantSpec>, EvolutionMutationError> {
    let base =
        parents
            .first()
            .ok_or_else(|| EvolutionMutationError::InvalidMutationSpecRequest {
                reason: "autonomous mutation generation requires at least one parent".to_string(),
            })?;
    let mut variants = vec![build_fileless_perturbation_variant(
        strategy_root,
        base,
        1,
        step_multiplier,
    )?];
    let mut donor_slot = 0usize;

    while variants.len() < max_variants {
        if let Some(donor) = parents.get(donor_slot + 1)
            && let Some(variant) =
                build_fileless_crossover_variant(strategy_root, base, donor, variants.len() + 1)?
        {
            variants.push(variant);
            donor_slot += 1;
            continue;
        }

        if variants.len() == 1 {
            variants.push(build_typed_seed_control_variant(
                strategy_root,
                base,
                variants.len() + 1,
            )?);
            continue;
        }

        let step_index = variants
            .iter()
            .filter(|variant| variant.mutation == "autonomous_bounded_perturbation")
            .count()
            + 1;
        variants.push(build_fileless_perturbation_variant(
            strategy_root,
            base,
            variants.len() + 1,
            step_multiplier * step_index as f64,
        )?);
    }

    Ok(variants)
}

pub(crate) fn build_fileless_perturbation_variant(
    strategy_root: &str,
    base: &AutonomousGenerationSeed,
    ordinal: usize,
    step_multiplier: f64,
) -> Result<EvolutionMutationVariantSpec, EvolutionMutationError> {
    let profile = match fileless_execution_profile(base) {
        Some(profile) => profile,
        None => {
            return Err(EvolutionMutationError::InvalidMutationSpecRequest {
                reason: "fileless perturbation requires a fileless-execution parent genome"
                    .to_string(),
            });
        }
    };
    let mut mutated = profile.clone();
    let step = step_multiplier.clamp(1.0, 3.0);
    mutated.min_region_size_bytes = ((profile.min_region_size_bytes as f64) * (1.0 - 0.18 * step))
        .round()
        .max(512.0) as u64;
    mutated.high_confidence_threshold =
        (profile.high_confidence_threshold - (0.03 * step)).clamp(0.05, 0.99);
    mutated.medium_confidence_threshold = (profile.medium_confidence_threshold - (0.04 * step))
        .clamp(0.05, mutated.high_confidence_threshold);

    let target_genome = EvolutionDetectorGenome::FilelessExecution { profile: mutated };
    let (high, medium) = target_genome.thresholds();
    Ok(EvolutionMutationVariantSpec {
        variant_id: format!("bounded-perturbation-{ordinal}"),
        strategy_id: format!("{strategy_root}_bounded_perturbation_{ordinal}"),
        strategy_description: format!(
            "Autonomous bounded perturbation from {}",
            base.reference.strategy_id
        ),
        mutation: "autonomous_bounded_perturbation".to_string(),
        rationale: format!(
            "apply a bounded fileless-execution sensitivity perturbation to top population candidate `{}`",
            base.reference.strategy_id
        ),
        mutation_dimensions: mutation_dimensions_for_target_genome(&base.genome, &target_genome)?,
        overrides: EvolutionMutationProfileOverrides::default(),
        target_genome: Some(target_genome),
        autonomous_lineage: Some(EvolutionAutonomousVariantLineage {
            recipe_kind: EvolutionAutonomousVariantRecipeKind::BoundedPerturbation,
            base_parent_strategy_id: base.reference.strategy_id.clone(),
            parent_strategy_ids: vec![base.reference.strategy_id.clone()],
            parent_materialization_ids: base.reference.materialization_id.iter().cloned().collect(),
            parent_genome_sha256: vec![base.reference.genome_sha256.clone()],
            inherited_suspicious_parents: Vec::new(),
            inherited_suspicious_children: Vec::new(),
            target_high_confidence_threshold: Some(format_threshold(high)),
            target_medium_confidence_threshold: Some(format_threshold(medium)),
        }),
    })
}

pub(crate) fn build_fileless_crossover_variant(
    strategy_root: &str,
    base: &AutonomousGenerationSeed,
    donor: &AutonomousGenerationSeed,
    ordinal: usize,
) -> Result<Option<EvolutionMutationVariantSpec>, EvolutionMutationError> {
    let (Some(base_profile), Some(donor_profile)) = (
        fileless_execution_profile(base),
        fileless_execution_profile(donor),
    ) else {
        return Ok(None);
    };
    let mut profile = base_profile.clone();
    profile
        .reflective_allocation_types
        .extend(bounded_unique_entries(
            &base_profile.reflective_allocation_types,
            &donor_profile.reflective_allocation_types,
            1,
        ));
    profile
        .executable_protection_flags
        .extend(bounded_unique_entries(
            &base_profile.executable_protection_flags,
            &donor_profile.executable_protection_flags,
            1,
        ));
    profile
        .reflective_call_stack_indicators
        .extend(bounded_unique_entries(
            &base_profile.reflective_call_stack_indicators,
            &donor_profile.reflective_call_stack_indicators,
            2,
        ));
    profile
        .encoded_command_indicators
        .extend(bounded_unique_entries(
            &base_profile.encoded_command_indicators,
            &donor_profile.encoded_command_indicators,
            1,
        ));
    profile
        .deobfuscation_indicators
        .extend(bounded_unique_entries(
            &base_profile.deobfuscation_indicators,
            &donor_profile.deobfuscation_indicators,
            2,
        ));
    profile
        .syscall_gadget_indicators
        .extend(bounded_unique_entries(
            &base_profile.syscall_gadget_indicators,
            &donor_profile.syscall_gadget_indicators,
            1,
        ));
    profile
        .privileged_target_processes
        .extend(bounded_unique_entries(
            &base_profile.privileged_target_processes,
            &donor_profile.privileged_target_processes,
            1,
        ));
    profile.min_region_size_bytes = rounded_midpoint_count(
        base_profile.min_region_size_bytes,
        donor_profile.min_region_size_bytes,
    );
    profile.high_confidence_threshold = midpoint_threshold(
        base_profile.high_confidence_threshold,
        donor_profile.high_confidence_threshold,
    )
    .unwrap_or(base_profile.high_confidence_threshold);
    profile.medium_confidence_threshold = midpoint_threshold(
        base_profile.medium_confidence_threshold,
        donor_profile.medium_confidence_threshold,
    )
    .unwrap_or(base_profile.medium_confidence_threshold);

    let target_genome = EvolutionDetectorGenome::FilelessExecution { profile };
    let mutation_dimensions = mutation_dimensions_for_target_genome(&base.genome, &target_genome)?;
    if mutation_dimensions.len() == 1 && mutation_dimensions[0] == "profile_copy" {
        return Ok(None);
    }
    let (high, medium) = target_genome.thresholds();
    Ok(Some(EvolutionMutationVariantSpec {
        variant_id: format!("bounded-crossover-{ordinal}"),
        strategy_id: format!("{strategy_root}_bounded_crossover_{ordinal}"),
        strategy_description: format!(
            "Autonomous bounded crossover from {} and {}",
            base.reference.strategy_id, donor.reference.strategy_id
        ),
        mutation: "autonomous_bounded_crossover".to_string(),
        rationale: format!(
            "merge bounded fileless-execution profile features from top population genomes `{}` and `{}`",
            base.reference.strategy_id, donor.reference.strategy_id
        ),
        mutation_dimensions,
        overrides: EvolutionMutationProfileOverrides::default(),
        target_genome: Some(target_genome),
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
            inherited_suspicious_parents: Vec::new(),
            inherited_suspicious_children: Vec::new(),
            target_high_confidence_threshold: Some(format_threshold(high)),
            target_medium_confidence_threshold: Some(format_threshold(medium)),
        }),
    }))
}

pub(crate) fn build_dns_autonomous_variant_specs(
    strategy_root: &str,
    max_variants: usize,
    parents: &[AutonomousGenerationSeed],
    step_multiplier: f64,
) -> Result<Vec<EvolutionMutationVariantSpec>, EvolutionMutationError> {
    let base =
        parents
            .first()
            .ok_or_else(|| EvolutionMutationError::InvalidMutationSpecRequest {
                reason: "autonomous mutation generation requires at least one parent".to_string(),
            })?;
    let mut variants = vec![build_dns_perturbation_variant(
        strategy_root,
        base,
        1,
        step_multiplier,
    )?];
    let mut donor_slot = 0usize;

    while variants.len() < max_variants {
        if let Some(donor) = parents.get(donor_slot + 1)
            && let Some(variant) =
                build_dns_crossover_variant(strategy_root, base, donor, variants.len() + 1)?
        {
            variants.push(variant);
            donor_slot += 1;
            continue;
        }

        if variants.len() == 1 {
            variants.push(build_typed_seed_control_variant(
                strategy_root,
                base,
                variants.len() + 1,
            )?);
            continue;
        }

        let step_index = variants
            .iter()
            .filter(|variant| variant.mutation == "autonomous_bounded_perturbation")
            .count()
            + 1;
        variants.push(build_dns_perturbation_variant(
            strategy_root,
            base,
            variants.len() + 1,
            step_multiplier * step_index as f64,
        )?);
    }

    Ok(variants)
}

pub(crate) fn build_dns_perturbation_variant(
    strategy_root: &str,
    base: &AutonomousGenerationSeed,
    ordinal: usize,
    step_multiplier: f64,
) -> Result<EvolutionMutationVariantSpec, EvolutionMutationError> {
    let profile = match dns_exfiltration_profile(base) {
        Some(profile) => profile,
        None => {
            return Err(EvolutionMutationError::InvalidMutationSpecRequest {
                reason: "dns perturbation requires a dns-exfiltration parent genome".to_string(),
            });
        }
    };
    let mut mutated = profile.clone();
    let step = step_multiplier.clamp(1.0, 3.0);
    mutated.entropy_threshold = (profile.entropy_threshold - (0.20 * step)).clamp(1.5, 8.0);
    mutated.min_subdomain_length = profile
        .min_subdomain_length
        .saturating_sub(step.ceil() as usize)
        .max(4);
    mutated.query_burst_threshold = profile
        .query_burst_threshold
        .saturating_sub((step.ceil() as usize).saturating_mul(2))
        .max(2);
    mutated.burst_window_ms =
        (profile.burst_window_ms + (15_000.0 * step).round() as i64).max(1_000);
    mutated.high_confidence_threshold =
        (profile.high_confidence_threshold - (0.03 * step)).clamp(0.05, 0.99);
    mutated.medium_confidence_threshold = (profile.medium_confidence_threshold - (0.04 * step))
        .clamp(0.05, mutated.high_confidence_threshold);

    let target_genome = EvolutionDetectorGenome::DnsExfiltration { profile: mutated };
    let (high, medium) = target_genome.thresholds();
    Ok(EvolutionMutationVariantSpec {
        variant_id: format!("bounded-perturbation-{ordinal}"),
        strategy_id: format!("{strategy_root}_bounded_perturbation_{ordinal}"),
        strategy_description: format!(
            "Autonomous bounded perturbation from {}",
            base.reference.strategy_id
        ),
        mutation: "autonomous_bounded_perturbation".to_string(),
        rationale: format!(
            "apply a bounded dns-exfiltration sensitivity perturbation to top population candidate `{}`",
            base.reference.strategy_id
        ),
        mutation_dimensions: mutation_dimensions_for_target_genome(&base.genome, &target_genome)?,
        overrides: EvolutionMutationProfileOverrides::default(),
        target_genome: Some(target_genome),
        autonomous_lineage: Some(EvolutionAutonomousVariantLineage {
            recipe_kind: EvolutionAutonomousVariantRecipeKind::BoundedPerturbation,
            base_parent_strategy_id: base.reference.strategy_id.clone(),
            parent_strategy_ids: vec![base.reference.strategy_id.clone()],
            parent_materialization_ids: base.reference.materialization_id.iter().cloned().collect(),
            parent_genome_sha256: vec![base.reference.genome_sha256.clone()],
            inherited_suspicious_parents: Vec::new(),
            inherited_suspicious_children: Vec::new(),
            target_high_confidence_threshold: Some(format_threshold(high)),
            target_medium_confidence_threshold: Some(format_threshold(medium)),
        }),
    })
}

pub(crate) fn build_dns_crossover_variant(
    strategy_root: &str,
    base: &AutonomousGenerationSeed,
    donor: &AutonomousGenerationSeed,
    ordinal: usize,
) -> Result<Option<EvolutionMutationVariantSpec>, EvolutionMutationError> {
    let (Some(base_profile), Some(donor_profile)) = (
        dns_exfiltration_profile(base),
        dns_exfiltration_profile(donor),
    ) else {
        return Ok(None);
    };
    let mut profile = base_profile.clone();
    profile
        .suspicious_query_types
        .extend(bounded_unique_entries_preserve_case(
            &base_profile.suspicious_query_types,
            &donor_profile.suspicious_query_types,
            1,
        ));
    profile
        .known_tunneling_patterns
        .extend(bounded_unique_entries(
            &base_profile.known_tunneling_patterns,
            &donor_profile.known_tunneling_patterns,
            1,
        ));
    profile.entropy_threshold = midpoint_value(
        base_profile.entropy_threshold,
        donor_profile.entropy_threshold,
    )
    .unwrap_or(base_profile.entropy_threshold);
    profile.min_subdomain_length = rounded_midpoint_usize(
        base_profile.min_subdomain_length,
        donor_profile.min_subdomain_length,
    );
    profile.query_burst_threshold = rounded_midpoint_usize(
        base_profile.query_burst_threshold,
        donor_profile.query_burst_threshold,
    );
    profile.burst_window_ms =
        rounded_midpoint_i64(base_profile.burst_window_ms, donor_profile.burst_window_ms)
            .max(1_000);
    profile.high_confidence_threshold = midpoint_threshold(
        base_profile.high_confidence_threshold,
        donor_profile.high_confidence_threshold,
    )
    .unwrap_or(base_profile.high_confidence_threshold);
    profile.medium_confidence_threshold = midpoint_threshold(
        base_profile.medium_confidence_threshold,
        donor_profile.medium_confidence_threshold,
    )
    .unwrap_or(base_profile.medium_confidence_threshold);

    let target_genome = EvolutionDetectorGenome::DnsExfiltration { profile };
    let mutation_dimensions = mutation_dimensions_for_target_genome(&base.genome, &target_genome)?;
    if mutation_dimensions.len() == 1 && mutation_dimensions[0] == "profile_copy" {
        return Ok(None);
    }
    let (high, medium) = target_genome.thresholds();
    Ok(Some(EvolutionMutationVariantSpec {
        variant_id: format!("bounded-crossover-{ordinal}"),
        strategy_id: format!("{strategy_root}_bounded_crossover_{ordinal}"),
        strategy_description: format!(
            "Autonomous bounded crossover from {} and {}",
            base.reference.strategy_id, donor.reference.strategy_id
        ),
        mutation: "autonomous_bounded_crossover".to_string(),
        rationale: format!(
            "merge bounded dns-exfiltration profile features from top population genomes `{}` and `{}`",
            base.reference.strategy_id, donor.reference.strategy_id
        ),
        mutation_dimensions,
        overrides: EvolutionMutationProfileOverrides::default(),
        target_genome: Some(target_genome),
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
            inherited_suspicious_parents: Vec::new(),
            inherited_suspicious_children: Vec::new(),
            target_high_confidence_threshold: Some(format_threshold(high)),
            target_medium_confidence_threshold: Some(format_threshold(medium)),
        }),
    }))
}

pub(crate) fn suspicious_process_tree_profile(
    seed: &AutonomousGenerationSeed,
) -> Option<&SuspiciousProcessTreeProfile> {
    match &seed.genome {
        EvolutionDetectorGenome::SuspiciousProcessTree { profile } => Some(profile),
        EvolutionDetectorGenome::BehavioralAnomaly { .. }
        | EvolutionDetectorGenome::FilelessExecution { .. }
        | EvolutionDetectorGenome::DnsExfiltration { .. } => None,
    }
}

pub(crate) fn behavioral_anomaly_profile(
    seed: &AutonomousGenerationSeed,
) -> Option<&BehavioralAnomalyProfile> {
    match &seed.genome {
        EvolutionDetectorGenome::BehavioralAnomaly { profile } => Some(profile),
        EvolutionDetectorGenome::SuspiciousProcessTree { .. }
        | EvolutionDetectorGenome::FilelessExecution { .. }
        | EvolutionDetectorGenome::DnsExfiltration { .. } => None,
    }
}

pub(crate) fn fileless_execution_profile(
    seed: &AutonomousGenerationSeed,
) -> Option<&FilelessExecutionProfile> {
    match &seed.genome {
        EvolutionDetectorGenome::FilelessExecution { profile } => Some(profile),
        EvolutionDetectorGenome::SuspiciousProcessTree { .. }
        | EvolutionDetectorGenome::BehavioralAnomaly { .. }
        | EvolutionDetectorGenome::DnsExfiltration { .. } => None,
    }
}

pub(crate) fn dns_exfiltration_profile(
    seed: &AutonomousGenerationSeed,
) -> Option<&DnsExfiltrationProfile> {
    match &seed.genome {
        EvolutionDetectorGenome::DnsExfiltration { profile } => Some(profile),
        EvolutionDetectorGenome::SuspiciousProcessTree { .. }
        | EvolutionDetectorGenome::BehavioralAnomaly { .. }
        | EvolutionDetectorGenome::FilelessExecution { .. } => None,
    }
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

pub(crate) fn bounded_unique_entries_preserve_case(
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
        .take(limit.max(1))
        .cloned()
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

pub(crate) fn midpoint_value(base: f64, donor: f64) -> Option<f64> {
    let midpoint = (base + donor) / 2.0;
    if (midpoint - base).abs() <= 0.000_5 {
        None
    } else {
        Some(midpoint)
    }
}

pub(crate) fn rounded_midpoint_count(base: u64, donor: u64) -> u64 {
    (((base as f64 + donor as f64) / 2.0).round() as u64).max(1)
}

pub(crate) fn rounded_midpoint_usize(base: usize, donor: usize) -> usize {
    (((base as f64 + donor as f64) / 2.0).round() as usize).max(1)
}

pub(crate) fn rounded_midpoint_i64(base: i64, donor: i64) -> i64 {
    ((base as f64 + donor as f64) / 2.0).round() as i64
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
