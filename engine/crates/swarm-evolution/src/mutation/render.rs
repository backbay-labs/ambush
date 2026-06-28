use super::*;

pub fn render_evolution_mutation_spec(report: &EvolutionMutationSpecReport) -> String {
    let mut lines = vec![
        "Evolution Mutation Spec".to_string(),
        format!("Mutation spec ID: {}", report.mutation_spec_id),
        format!("Source kind: {}", mutation_source_label(report.source_kind)),
        format!("Draft ID: {}", report.draft_id),
        format!(
            "Source strategy: {} | {}",
            report.source_strategy_id, report.source_strategy_description
        ),
        format!(
            "Source experiment: {} ({})",
            report.source_experiment_name, report.source_experiment_id
        ),
        format!("Base experiment path: {}", report.base_experiment_path),
        format!("Mutation rationale: {}", report.operator_rationale),
    ];

    if let Some(materialization_id) = &report.materialization_id {
        lines.push(format!("Source materialization: {}", materialization_id));
    }
    if let Some(queue_proposal_id) = &report.queue_proposal_id {
        lines.push(format!("Reviewed queue proposal: {}", queue_proposal_id));
    }
    if let Some(generation) = &report.autonomous_generation {
        lines.push(format!("Autonomous generator: {}", generation.generator));
        if let Some(ranking_id) = &generation.population_ranking_id {
            lines.push(format!("Population ranking: {}", ranking_id));
        }
        lines.push(format!(
            "Autonomous parents: {}",
            generation
                .parents
                .iter()
                .map(|parent| format!(
                    "{}(rank={} gen={} fitness={:.3})",
                    parent.strategy_id, parent.population_rank, parent.generation, parent.fitness
                ))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    if report.variants.is_empty() {
        lines.push("Variants: none".to_string());
    } else {
        lines.push("Variants:".to_string());
        for variant in &report.variants {
            lines.push(format!(
                "- {} | strategy={} | mutation={} | dims={}",
                variant.variant_id,
                variant.strategy_id,
                variant.mutation,
                variant.mutation_dimensions.join(",")
            ));
            if let Some(lineage) = &variant.autonomous_lineage {
                lines.push(format!(
                    "  parents={} | recipe={}",
                    lineage.parent_strategy_ids.join(","),
                    autonomous_recipe_label(lineage.recipe_kind)
                ));
            }
        }
    }

    lines.join("\n")
}

/// Render one mutation materialization batch.
pub fn render_evolution_mutation_materialization_batch(
    report: &EvolutionMutationMaterializationBatchReport,
) -> String {
    let mut lines = vec![
        "Evolution Mutation Materialization Batch".to_string(),
        format!("Batch ID: {}", report.batch_id),
        format!("Mutation spec ID: {}", report.mutation_spec_id),
        format!("Source strategy: {}", report.source_strategy_id),
        format!("Candidate count: {}", report.candidate_count),
        "Entries:".to_string(),
    ];
    for entry in &report.entries {
        lines.push(format!(
            "- {} | strategy={} | materialization={} | dims={}",
            entry.variant_id,
            entry.strategy_id,
            entry.materialization_id,
            entry.mutation_dimensions.join(",")
        ));
    }
    lines.join("\n")
}

/// Render one mutation validation batch.
pub fn render_evolution_mutation_validation_batch(
    report: &EvolutionMutationValidationBatchReport,
) -> String {
    let mut lines = vec![
        "Evolution Mutation Validation Batch".to_string(),
        format!("Validation batch ID: {}", report.validation_batch_id),
        format!("Mutation spec ID: {}", report.mutation_spec_id),
        format!(
            "Materialization batch ID: {}",
            report.materialization_batch_id
        ),
        format!(
            "Ready: {} | Blocked: {}",
            report.ready_count, report.blocked_count
        ),
        "Entries:".to_string(),
    ];
    for entry in &report.entries {
        lines.push(format!(
            "- {} | strategy={} | validation={} | status={} | proof={}",
            entry.variant_id,
            entry.strategy_id,
            entry.validation_bundle_id,
            validation_bundle_status_label(entry.status),
            proof_status_label(entry.proof_status)
        ));
    }
    lines.join("\n")
}

/// Render one candidate ranking report.
pub fn render_evolution_mutation_ranking(report: &EvolutionMutationRankingReport) -> String {
    let mut lines = vec![
        "Evolution Mutation Candidate Ranking".to_string(),
        format!("Ranking ID: {}", report.ranking_id),
        format!("Mutation spec ID: {}", report.mutation_spec_id),
        format!("Validation batch ID: {}", report.validation_batch_id),
        format!("Shortlist count: {}", report.shortlist_count),
        "Ranked candidates:".to_string(),
    ];
    for candidate in &report.ranked_candidates {
        lines.push(format!(
            "- #{} {} | strategy={} | score={:.3} | status={} | queue={} | assurance_cases={} | {}",
            candidate.rank,
            candidate.variant_id,
            candidate.strategy_id,
            candidate.score,
            validation_bundle_status_label(candidate.status),
            candidate
                .queue_review_state
                .map(review_state_label)
                .unwrap_or("none"),
            candidate.assurance_case_count,
            candidate.summary
        ));
    }
    lines.push("Review packets:".to_string());
    for packet in &report.review_packets {
        lines.push(format!(
            "- {} | rank={} | strategy={} | validation={} | assurance_cases={} | {}",
            packet.packet_id,
            packet.rank,
            packet.strategy_id,
            packet.validation_bundle_id,
            packet.assurance_case_count,
            packet.summary
        ));
    }
    lines.join("\n")
}

pub fn benchmark_fitness_delta(
    current: &EvolutionBenchmarkGenerationReport,
    baseline: &EvolutionBenchmarkGenerationReport,
) -> EvolutionBenchmarkFitnessDelta {
    EvolutionBenchmarkFitnessDelta {
        measured_fitness: current.leader_measured_fitness - baseline.leader_measured_fitness,
        catch_rate: current.leader_catch_rate - baseline.leader_catch_rate,
        false_positive_rate: current.leader_false_positive_rate
            - baseline.leader_false_positive_rate,
        false_positive_fitness: current.leader_false_positive_fitness
            - baseline.leader_false_positive_fitness,
        latency_fitness: current.leader_latency_fitness - baseline.leader_latency_fitness,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn summarize_evolution_benchmark_generation(
    benchmark_id: &str,
    generation: usize,
    created_at_ms: i64,
    draft_id: &str,
    mutation_spec_id: &str,
    materialization_batch_id: &str,
    validation_batch_id: &str,
    ranking_id: &str,
    population: &EvolutionPopulationState,
) -> Result<EvolutionBenchmarkGenerationReport, EvolutionMutationError> {
    let autonomous_candidates = population
        .members
        .iter()
        .filter_map(|candidate| {
            candidate
                .autonomous_fitness
                .as_ref()
                .map(|measurement| (candidate, measurement))
        })
        .collect::<Vec<_>>();
    if autonomous_candidates.is_empty() {
        return Err(EvolutionMutationError::InvalidMutationSpecRequest {
            reason: format!(
                "benchmark generation `{generation}` did not produce any autonomous fitness measurements"
            ),
        });
    }

    let leader = autonomous_candidates
        .iter()
        .copied()
        .max_by(|(left_candidate, left_measurement), (right_candidate, right_measurement)| {
            left_measurement
                .measured_fitness
                .partial_cmp(&right_measurement.measured_fitness)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    right_candidate
                        .population_rank
                        .cmp(&left_candidate.population_rank)
                })
                .then_with(|| {
                    left_candidate
                        .strategy_id
                        .cmp(&right_candidate.strategy_id)
                        .reverse()
                })
        })
        .ok_or_else(|| EvolutionMutationError::InvalidMutationSpecRequest {
            reason: format!(
                "benchmark generation `{generation}` could not resolve an autonomous population leader"
            ),
        })?;
    let mean_measured_fitness = autonomous_candidates
        .iter()
        .map(|(_, measurement)| measurement.measured_fitness)
        .sum::<f64>()
        / autonomous_candidates.len() as f64;

    Ok(EvolutionBenchmarkGenerationReport {
        benchmark_id: benchmark_id.to_string(),
        generation,
        created_at_ms,
        draft_id: draft_id.to_string(),
        mutation_spec_id: mutation_spec_id.to_string(),
        materialization_batch_id: materialization_batch_id.to_string(),
        validation_batch_id: validation_batch_id.to_string(),
        ranking_id: ranking_id.to_string(),
        tracked_candidate_count: autonomous_candidates.len(),
        leader_generation: leader.0.generation,
        leader_population_rank: leader.0.population_rank,
        leader_strategy_id: leader.0.strategy_id.clone(),
        leader_variant_id: leader.0.variant_id.clone(),
        leader_materialization_id: leader.0.materialization_id.clone(),
        leader_validation_bundle_id: leader.0.validation_bundle_id.clone(),
        leader_recipe_kind: leader.1.lineage.recipe_kind,
        leader_parent_strategy_ids: leader.1.lineage.parent_strategy_ids.clone(),
        corpus_suite_name: leader.1.corpus_suite_name.clone(),
        corpus_version: leader.1.corpus_version.clone(),
        measured_event_count: leader.1.measured_event_count,
        detected_event_count: leader.1.detected_event_count,
        leader_measured_fitness: leader.1.measured_fitness,
        mean_measured_fitness,
        leader_catch_rate: leader.1.catch_rate,
        leader_false_positive_rate: leader.1.false_positive_rate,
        leader_false_positive_fitness: leader.1.false_positive_fitness,
        leader_latency_fitness: leader.1.latency_fitness,
        leader_max_detect_latency_us: leader.1.max_detect_latency_us,
        leader_latency_budget_us: leader.1.latency_budget_us,
        delta_from_previous: None,
        delta_from_first: None,
    })
}

pub fn render_evolution_benchmark_run(report: &EvolutionBenchmarkRunReport) -> String {
    let mut lines = vec![
        "Evolution Benchmark Run".to_string(),
        format!("Benchmark ID: {}", report.benchmark_id),
        format!("Label: {}", report.label),
        format!("Detector: {}", report.detector),
        format!(
            "Generations: {}/{}",
            report.completed_generation_count, report.requested_generation_count
        ),
        format!(
            "Corpus: {}@{}",
            report.corpus_suite_name, report.corpus_version
        ),
        format!("Baseline experiment: {}", report.baseline_experiment_path),
        format!("Notes: {}", report.notes),
    ];

    if let Some(baseline) = &report.baseline {
        lines.push(format!(
            "Baseline metrics: strategy={} fitness={:.3} catch_rate={:.3} fp_rate={:.3} latency_fitness={:.3}",
            baseline.strategy_id,
            baseline.measured_fitness,
            baseline.catch_rate,
            baseline.false_positive_rate,
            baseline.latency_fitness
        ));
    }

    if report.generations.is_empty() {
        lines.push("Generation results: none".to_string());
        return lines.join("\n");
    }

    lines.push("Generation results:".to_string());
    for generation in &report.generations {
        lines.push(format!(
            "- gen={} leader={} fitness={:.3} catch_rate={:.3} fp_rate={:.3} latency_fitness={:.3} delta_prev={} delta_first={}",
            generation.generation,
            generation.leader_strategy_id,
            generation.leader_measured_fitness,
            generation.leader_catch_rate,
            generation.leader_false_positive_rate,
            generation.leader_latency_fitness,
            generation
                .delta_from_previous
                .as_ref()
                .map(|delta| format!("{:.3}", delta.measured_fitness))
                .unwrap_or_else(|| "n/a".to_string()),
            generation
                .delta_from_first
                .as_ref()
                .map(|delta| format!("{:.3}", delta.measured_fitness))
                .unwrap_or_else(|| "n/a".to_string()),
        ));
    }

    lines.join("\n")
}
