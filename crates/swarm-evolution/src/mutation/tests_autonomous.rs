use super::test_support::*;

#[tokio::test]
async fn mutation_ranking_orders_ready_candidate_first() {
    let root = unique_temp_dir("mutation-ranking");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verifications");
    let shadow_dir = root.join("shadows");
    let proof_dir = root.join("proofs");
    let memory_dir = root.join("memory");
    let scorecard_dir = root.join("scorecards");
    let pressure_dir = root.join("pressures");
    let draft_dir = root.join("drafts");
    let promotion_dir = root.join("promotions");
    let materialization_dir = root.join("materializations");
    let validation_dir = root.join("validation");
    let reconciliation_dir = root.join("reconciliations");
    let mutation_dir = root.join("mutations");
    let mutation_materialization_batch_dir = root.join("mutation-materialization-batches");
    let mutation_validation_batch_dir = root.join("mutation-validation-batches");
    let mutation_ranking_dir = root.join("mutation-rankings");
    let queue_dir = root.join("queue");
    let base_experiment = office_control_experiment();

    let config = sample_config();
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let proofs =
        DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proof_dir).unwrap();
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        "inline",
        config.clone(),
        &memory_dir,
        &scorecard_dir,
    )
    .unwrap();
    let scorecard = scorecards
        .create_scorecard(
            &replay,
            office_control_experiment(),
            &experiment_dir,
            &verification_dir,
            &verification.report.verification_id,
        )
        .await
        .unwrap();
    let drafting = DefaultEvolutionDraftingHarness::from_config(
        "inline",
        config,
        &pressure_dir,
        &draft_dir,
        &promotion_dir,
        &materialization_dir,
        &validation_dir,
        &reconciliation_dir,
    )
    .unwrap();
    let pressure = drafting
        .create_pressure_from_scorecard(&scorecards, &scorecard.report.scorecard_id)
        .unwrap();
    let draft = drafting
        .create_draft(EvolutionDraftCreateRequest {
            pressure_id: pressure.report.pressure_id.clone(),
            strategy_id: "suspicious_process_tree".to_string(),
            strategy_description: "ranking parent".to_string(),
            mutation: "guided_ranking_seed".to_string(),
            rationale: "rank a ready branch against a blocked branch".to_string(),
        })
        .unwrap();
    let promotion = drafting
        .promote_draft(
            &queue_dir,
            &draft.report.draft_id,
            "keep the reviewed queue reference attached",
        )
        .unwrap();
    let mutation = DefaultEvolutionMutationHarness::from_path(
        &mutation_dir,
        &mutation_materialization_batch_dir,
        &mutation_validation_batch_dir,
        &mutation_ranking_dir,
    )
    .unwrap();
    let spec = mutation
        .create_mutation_spec(
            &drafting,
            EvolutionMutationSpecCreateRequest {
                draft_id: Some(draft.report.draft_id.clone()),
                materialization_id: None,
                base_experiment_path: Some(base_experiment),
                rationale: "preserve one ready branch and one blocked branch".to_string(),
            },
        )
        .unwrap();
    let spec = mutation
        .append_variant(
            &spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("control-copy".to_string()),
                strategy_id: "office_ranking_control_v1".to_string(),
                strategy_description: "keep the control profile".to_string(),
                mutation: "copy_control_profile".to_string(),
                rationale: "ready branch".to_string(),
                overrides: EvolutionMutationProfileOverrides::default(),
            },
        )
        .unwrap();
    let spec = mutation
        .append_variant(
            &spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("python-parent".to_string()),
                strategy_id: "office_ranking_python_parent_v1".to_string(),
                strategy_description: "broaden suspicious parent matching to python".to_string(),
                mutation: "broaden_parent_set".to_string(),
                rationale: "blocked branch".to_string(),
                overrides: EvolutionMutationProfileOverrides {
                    add_suspicious_parents: vec!["python".to_string()],
                    ..EvolutionMutationProfileOverrides::default()
                },
            },
        )
        .unwrap();

    let batch = mutation
        .materialize_batch(&drafting, &spec.report.mutation_spec_id)
        .unwrap();
    let validation_batch = mutation
        .refresh_validation_batch(
            &drafting,
            &replay,
            &proofs,
            &scorecards,
            &experiment_dir,
            &verification_dir,
            &shadow_dir,
            &batch.report.batch_id,
        )
        .await
        .unwrap();
    let queue_store = FileEvolutionProposalStore::open(&queue_dir).unwrap();
    let mut proposal = queue_store
        .load(&promotion.report.queue_proposal_id)
        .unwrap()
        .unwrap();
    proposal.report.assurance = Some(EvolutionProposalAssuranceSummary {
        decision: EvolutionProposalAssuranceDecision::Blocked,
        coverage: EvolutionProposalAssuranceCoverageSummary {
            detector: "suspicious_process_tree".to_string(),
            suite_name: Some("evasion-breadth-v1".to_string()),
            corpus_version: Some("test".to_string()),
            required_catch_rate: 0.75,
            actual_catch_rate: Some(0.25),
            actionable_gap_count: 2,
        },
        solver: EvolutionProposalAssuranceSolverSummary {
            required: false,
            status: None,
            allowed_statuses: Vec::new(),
        },
        harvested_case_ids: vec!["case-a".to_string(), "case-b".to_string()],
        waiver: None,
    });
    queue_store.persist(&proposal.report).unwrap();
    let ranking = mutation
        .rank_candidates(&queue_dir, &validation_batch.report.validation_batch_id, 1)
        .unwrap();

    assert_eq!(ranking.report.ranked_candidates.len(), 2);
    assert_eq!(ranking.report.ranked_candidates[0].rank, 1);
    assert_eq!(
        ranking.report.ranked_candidates[0].strategy_id,
        "office_ranking_control_v1"
    );
    assert_eq!(ranking.report.review_packets.len(), 1);
    assert_eq!(
        ranking.report.review_packets[0]
            .queue_proposal_id
            .as_deref(),
        Some(promotion.report.queue_proposal_id.as_str())
    );
    assert_eq!(ranking.report.ranked_candidates[0].assurance_case_count, 2);
    assert_eq!(ranking.report.review_packets[0].assurance_case_count, 2);
    assert_eq!(
        ranking.report.ranked_candidates[0].assurance_case_ids,
        vec!["case-a".to_string(), "case-b".to_string()]
    );
    assert!(
        ranking.report.ranked_candidates[0]
            .summary
            .contains("assurance_cases=2")
    );
    assert!(
        render_evolution_mutation_ranking(&ranking.report)
            .contains("Evolution Mutation Candidate Ranking")
    );

    for entry in &batch.report.entries {
        let path = PathBuf::from(&entry.experiment_path);
        if path.exists() {
            fs::remove_file(path).unwrap();
        }
    }
}

#[tokio::test]
async fn population_refresh_persists_ready_candidates_and_tracks_proposals() {
    let root = unique_temp_dir("mutation-population");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verifications");
    let shadow_dir = root.join("shadows");
    let proof_dir = root.join("proofs");
    let memory_dir = root.join("memory");
    let scorecard_dir = root.join("scorecards");
    let pressure_dir = root.join("pressures");
    let draft_dir = root.join("drafts");
    let promotion_dir = root.join("promotions");
    let materialization_dir = root.join("materializations");
    let validation_dir = root.join("validation");
    let reconciliation_dir = root.join("reconciliations");
    let mutation_dir = root.join("mutations");
    let mutation_materialization_batch_dir = root.join("mutation-materialization-batches");
    let mutation_validation_batch_dir = root.join("mutation-validation-batches");
    let mutation_ranking_dir = root.join("mutation-rankings");
    let population_dir = root.join("population");
    let queue_dir = root.join("queue");
    let base_experiment = office_control_experiment();

    let config = sample_config();
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let proofs =
        DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proof_dir).unwrap();
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        "inline",
        config.clone(),
        &memory_dir,
        &scorecard_dir,
    )
    .unwrap();
    let scorecard = scorecards
        .create_scorecard(
            &replay,
            office_control_experiment(),
            &experiment_dir,
            &verification_dir,
            &verification.report.verification_id,
        )
        .await
        .unwrap();
    let drafting = DefaultEvolutionDraftingHarness::from_config(
        "inline",
        config.clone(),
        &pressure_dir,
        &draft_dir,
        &promotion_dir,
        &materialization_dir,
        &validation_dir,
        &reconciliation_dir,
    )
    .unwrap();
    let pressure = drafting
        .create_pressure_from_scorecard(&scorecards, &scorecard.report.scorecard_id)
        .unwrap();
    let draft = drafting
        .create_draft(EvolutionDraftCreateRequest {
            pressure_id: pressure.report.pressure_id.clone(),
            strategy_id: "suspicious_process_tree".to_string(),
            strategy_description: "population parent".to_string(),
            mutation: "guided_population_seed".to_string(),
            rationale: "persist the best ready candidate into the durable population".to_string(),
        })
        .unwrap();
    let mutation = DefaultEvolutionMutationHarness::from_path(
        &mutation_dir,
        &mutation_materialization_batch_dir,
        &mutation_validation_batch_dir,
        &mutation_ranking_dir,
    )
    .unwrap();
    let spec = mutation
        .create_mutation_spec(
            &drafting,
            EvolutionMutationSpecCreateRequest {
                draft_id: Some(draft.report.draft_id.clone()),
                materialization_id: None,
                base_experiment_path: Some(base_experiment),
                rationale: "preserve one ready branch and one blocked branch".to_string(),
            },
        )
        .unwrap();
    let spec = mutation
        .append_variant(
            &spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("control-copy".to_string()),
                strategy_id: "office_population_control_v1".to_string(),
                strategy_description: "keep the control profile".to_string(),
                mutation: "copy_control_profile".to_string(),
                rationale: "ready branch".to_string(),
                overrides: EvolutionMutationProfileOverrides::default(),
            },
        )
        .unwrap();
    let spec = mutation
        .append_variant(
            &spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("python-parent".to_string()),
                strategy_id: "office_population_python_parent_v1".to_string(),
                strategy_description: "broaden suspicious parent matching to python".to_string(),
                mutation: "broaden_parent_set".to_string(),
                rationale: "blocked branch".to_string(),
                overrides: EvolutionMutationProfileOverrides {
                    add_suspicious_parents: vec!["python".to_string()],
                    ..EvolutionMutationProfileOverrides::default()
                },
            },
        )
        .unwrap();

    let batch = mutation
        .materialize_batch(&drafting, &spec.report.mutation_spec_id)
        .unwrap();
    let validation_batch = mutation
        .refresh_validation_batch(
            &drafting,
            &replay,
            &proofs,
            &scorecards,
            &experiment_dir,
            &verification_dir,
            &shadow_dir,
            &batch.report.batch_id,
        )
        .await
        .unwrap();
    let ranking = mutation
        .rank_candidates(&queue_dir, &validation_batch.report.validation_batch_id, 1)
        .unwrap();
    let population = mutation
        .refresh_population(
            &population_dir,
            &drafting,
            &experiment_dir,
            &verification_dir,
            &ranking.report,
            1,
            2,
            &config.evolution.fitness_weights,
            None,
        )
        .unwrap();

    assert_eq!(population.members.len(), 1);
    assert_eq!(population.members[0].population_rank, 1);
    assert_eq!(
        population.members[0].strategy_id,
        "office_population_control_v1"
    );
    assert!(population.members[0].fitness > 0.0);
    assert!(population.members[0].objectives.detection_rate > 0.0);

    let selected = mutation
        .select_population_candidate(&population_dir, 2, 1_800_300_000_000)
        .unwrap()
        .unwrap();
    assert_eq!(selected.strategy_id, "office_population_control_v1");

    let marked = mutation
        .mark_population_candidate_proposed(
            &population_dir,
            &selected.strategy_id,
            1_800_300_001_000,
        )
        .unwrap()
        .unwrap();
    assert_eq!(marked.proposal_timestamps_ms.len(), 1);
    assert_eq!(marked.members[0].proposed_at_ms, Some(1_800_300_001_000));
    assert!(
        mutation
            .select_population_candidate(&population_dir, 2, 1_800_300_002_000)
            .unwrap()
            .is_none()
    );

    for entry in &batch.report.entries {
        let path = PathBuf::from(&entry.experiment_path);
        if path.exists() {
            fs::remove_file(path).unwrap();
        }
    }
}

#[tokio::test]
async fn evasion_population_refresh_persists_gap_pressure_metadata() {
    let root = unique_temp_dir("population-evasion");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verifications");
    let shadow_dir = root.join("shadow");
    let memory_dir = root.join("memory");
    let scorecard_dir = root.join("scorecards");
    let pressure_dir = root.join("pressures");
    let draft_dir = root.join("drafts");
    let promotion_dir = root.join("promotions");
    let materialization_dir = root.join("materializations");
    let validation_dir = root.join("validation");
    let reconciliation_dir = root.join("reconciliations");
    let queue_dir = root.join("queue");
    let mutation_dir = root.join("mutations");
    let mutation_materialization_batch_dir = root.join("mutation-materialization-batches");
    let mutation_validation_batch_dir = root.join("mutation-validation-batches");
    let mutation_ranking_dir = root.join("mutation-rankings");
    let population_dir = root.join("population");
    let base_experiment = copy_experiment_fixture(&root, "office-control-evasion");

    let config = sample_config();
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        "inline",
        config.clone(),
        &memory_dir,
        &scorecard_dir,
    )
    .unwrap();
    let scorecard = scorecards
        .create_scorecard(
            &replay,
            office_control_experiment(),
            &experiment_dir,
            &verification_dir,
            &verification.report.verification_id,
        )
        .await
        .unwrap();
    let proofs =
        DefaultEvolutionProofHarness::from_config("inline", config.clone(), root.join("proofs"))
            .unwrap();
    let drafting = DefaultEvolutionDraftingHarness::from_config(
        "inline",
        config.clone(),
        &pressure_dir,
        &draft_dir,
        &promotion_dir,
        &materialization_dir,
        &validation_dir,
        &reconciliation_dir,
    )
    .unwrap();
    let pressure = drafting
        .create_pressure_from_scorecard(&scorecards, &scorecard.report.scorecard_id)
        .unwrap();
    let draft = drafting
        .create_draft(EvolutionDraftCreateRequest {
            pressure_id: pressure.report.pressure_id.clone(),
            strategy_id: "suspicious_process_tree".to_string(),
            strategy_description: "population parent".to_string(),
            mutation: "guided_population_seed".to_string(),
            rationale: "persist the best ready candidate into the durable population".to_string(),
        })
        .unwrap();
    let mutation = DefaultEvolutionMutationHarness::from_path(
        &mutation_dir,
        &mutation_materialization_batch_dir,
        &mutation_validation_batch_dir,
        &mutation_ranking_dir,
    )
    .unwrap();
    let spec = mutation
        .create_mutation_spec(
            &drafting,
            EvolutionMutationSpecCreateRequest {
                draft_id: Some(draft.report.draft_id.clone()),
                materialization_id: None,
                base_experiment_path: Some(base_experiment),
                rationale: "preserve one ready branch for evasion pressure".to_string(),
            },
        )
        .unwrap();
    let spec = mutation
        .append_variant(
            &spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("control-copy".to_string()),
                strategy_id: "office_population_control_v1".to_string(),
                strategy_description: "keep the control profile".to_string(),
                mutation: "copy_control_profile".to_string(),
                rationale: "ready branch".to_string(),
                overrides: EvolutionMutationProfileOverrides::default(),
            },
        )
        .unwrap();
    let batch = mutation
        .materialize_batch(&drafting, &spec.report.mutation_spec_id)
        .unwrap();
    let validation_batch = mutation
        .refresh_validation_batch(
            &drafting,
            &replay,
            &proofs,
            &scorecards,
            &experiment_dir,
            &verification_dir,
            &shadow_dir,
            &batch.report.batch_id,
        )
        .await
        .unwrap();
    let ranking = mutation
        .rank_candidates(&queue_dir, &validation_batch.report.validation_batch_id, 1)
        .unwrap();
    let evasion_input = sample_evasion_pressure_input();
    let population = mutation
        .refresh_population(
            &population_dir,
            &drafting,
            &experiment_dir,
            &verification_dir,
            &ranking.report,
            1,
            2,
            &config.evolution.fitness_weights,
            Some(&evasion_input),
        )
        .unwrap();

    assert_eq!(population.members.len(), 1);
    assert!(population.members[0].baseline_fitness.is_some());
    let evasion_pressure = population.members[0]
        .evasion_pressure
        .as_ref()
        .expect("population member should retain evasion pressure");
    assert_eq!(evasion_pressure.detector, "suspicious_process_tree");
    assert_eq!(evasion_pressure.gap_count, evasion_input.gaps.len());
    assert!(evasion_pressure.focused_event_count > 0);
    assert_eq!(
        evasion_pressure.actionable_techniques[0],
        "T1055".to_string()
    );

    for entry in &batch.report.entries {
        let path = PathBuf::from(&entry.experiment_path);
        if path.exists() {
            fs::remove_file(path).unwrap();
        }
    }
}

#[tokio::test]
async fn autonomous_population_refresh_persists_measured_fitness_lineage() {
    let root = unique_temp_dir("population-autonomous-fitness");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verifications");
    let shadow_dir = root.join("shadow");
    let memory_dir = root.join("memory");
    let scorecard_dir = root.join("scorecards");
    let pressure_dir = root.join("pressures");
    let draft_dir = root.join("drafts");
    let promotion_dir = root.join("promotions");
    let materialization_dir = root.join("materializations");
    let validation_dir = root.join("validation");
    let reconciliation_dir = root.join("reconciliations");
    let queue_dir = root.join("queue");
    let mutation_dir = root.join("mutations");
    let mutation_materialization_batch_dir = root.join("mutation-materialization-batches");
    let mutation_validation_batch_dir = root.join("mutation-validation-batches");
    let mutation_ranking_dir = root.join("mutation-rankings");
    let population_dir = root.join("population");
    let base_experiment = copy_experiment_fixture(&root, "office-control-autonomous-fitness");

    let config = sample_config();
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        "inline",
        config.clone(),
        &memory_dir,
        &scorecard_dir,
    )
    .unwrap();
    let scorecard = scorecards
        .create_scorecard(
            &replay,
            office_control_experiment(),
            &experiment_dir,
            &verification_dir,
            &verification.report.verification_id,
        )
        .await
        .unwrap();
    let proofs =
        DefaultEvolutionProofHarness::from_config("inline", config.clone(), root.join("proofs"))
            .unwrap();
    let drafting = DefaultEvolutionDraftingHarness::from_config(
        "inline",
        config.clone(),
        &pressure_dir,
        &draft_dir,
        &promotion_dir,
        &materialization_dir,
        &validation_dir,
        &reconciliation_dir,
    )
    .unwrap();
    let pressure = drafting
        .create_pressure_from_scorecard(&scorecards, &scorecard.report.scorecard_id)
        .unwrap();
    let draft = drafting
        .create_draft(EvolutionDraftCreateRequest {
            pressure_id: pressure.report.pressure_id.clone(),
            strategy_id: "suspicious_process_tree".to_string(),
            strategy_description: "autonomous population parent".to_string(),
            mutation: "guided_population_seed".to_string(),
            rationale: "persist a measured autonomous lineage into the durable population"
                .to_string(),
        })
        .unwrap();
    let mutation = DefaultEvolutionMutationHarness::from_path(
        &mutation_dir,
        &mutation_materialization_batch_dir,
        &mutation_validation_batch_dir,
        &mutation_ranking_dir,
    )
    .unwrap();
    let spec = mutation
        .create_mutation_spec(
            &drafting,
            EvolutionMutationSpecCreateRequest {
                draft_id: Some(draft.report.draft_id.clone()),
                materialization_id: None,
                base_experiment_path: Some(base_experiment),
                rationale: "preserve a measured autonomous branch".to_string(),
            },
        )
        .unwrap();
    let spec = mutation
        .append_variant(
            &spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("autonomous-control".to_string()),
                strategy_id: "office_population_autonomous_v1".to_string(),
                strategy_description: "keep the autonomous control profile".to_string(),
                mutation: "copy_control_profile".to_string(),
                rationale: "ready autonomous branch".to_string(),
                overrides: EvolutionMutationProfileOverrides::default(),
            },
        )
        .unwrap();
    let mut persisted = mutation
        .load_mutation_spec(&spec.report.mutation_spec_id)
        .unwrap()
        .unwrap()
        .report;
    persisted.variants[0].autonomous_lineage = Some(EvolutionAutonomousVariantLineage {
        recipe_kind: EvolutionAutonomousVariantRecipeKind::BoundedPerturbation,
        base_parent_strategy_id: "suspicious_process_tree".to_string(),
        parent_strategy_ids: vec!["suspicious_process_tree".to_string()],
        parent_materialization_ids: Vec::new(),
        parent_genome_sha256: vec!["genome-parent".to_string()],
        inherited_suspicious_parents: Vec::new(),
        inherited_suspicious_children: Vec::new(),
        target_high_confidence_threshold: Some("0.880".to_string()),
        target_medium_confidence_threshold: Some("0.640".to_string()),
    });
    mutation.mutation_store.persist(&persisted).unwrap();

    let batch = mutation
        .materialize_batch(&drafting, &spec.report.mutation_spec_id)
        .unwrap();
    let validation_batch = mutation
        .refresh_validation_batch(
            &drafting,
            &replay,
            &proofs,
            &scorecards,
            &experiment_dir,
            &verification_dir,
            &shadow_dir,
            &batch.report.batch_id,
        )
        .await
        .unwrap();
    let ranking = mutation
        .rank_candidates(&queue_dir, &validation_batch.report.validation_batch_id, 1)
        .unwrap();
    let evasion_input = sample_evasion_pressure_input();
    let population = mutation
        .refresh_population(
            &population_dir,
            &drafting,
            &experiment_dir,
            &verification_dir,
            &ranking.report,
            1,
            2,
            &config.evolution.fitness_weights,
            Some(&evasion_input),
        )
        .unwrap();

    let autonomous = population.members[0]
        .autonomous_fitness
        .as_ref()
        .expect("autonomous lineage should persist measured fitness");
    assert_eq!(
        autonomous.lineage.parent_strategy_ids,
        vec!["suspicious_process_tree".to_string()]
    );
    assert_eq!(autonomous.corpus_suite_name, evasion_input.suite_name);
    assert_eq!(autonomous.corpus_version, evasion_input.corpus_version);
    assert!(autonomous.catch_rate > 0.0);
    assert!(autonomous.false_positive_fitness > 0.0);
    assert!(autonomous.latency_fitness > 0.0);
    assert_eq!(population.members[0].fitness, autonomous.measured_fitness);
}

#[test]
fn adversarial_pressure_persists_durable_episode_report() {
    let root = unique_temp_dir("population-episodes");
    let population_dir = root.join("population");
    let mutation = DefaultEvolutionMutationHarness::from_path(
        root.join("mutations"),
        root.join("mutation-materialization-batches"),
        root.join("mutation-validation-batches"),
        root.join("mutation-rankings"),
    )
    .unwrap();

    let result = mutation
        .evaluate_adversarial_pressure(
            &population_dir,
            EvolutionAdversarialPressureRequest {
                ranking_id: "ranking:test".to_string(),
                validation_batch_id: "validation:test".to_string(),
                generation: 7,
                evaluated_at_ms: 1_900_000_000_000,
                strategy_id: "office_baseline_control".to_string(),
                experiment_id: "experiment:office_baseline_control".to_string(),
                experiment_path: office_control_experiment(),
                materialization_id: "materialization:test".to_string(),
                validation_bundle_id: "validation-bundle:test".to_string(),
                autonomous_fitness: None,
                replay_fitness: 0.70,
                evasion_adjusted_fitness: 0.74,
                evasion_pressure_score: 0.74,
                evasion_gap_closure_rate: 0.74,
                evasion_focus_gap_count: 2,
                memory_adjusted_fitness: 0.82,
                deception_adjusted_fitness: 0.88,
                deception_signal_score: 0.91,
                adversarial_corpus_sequence_id: "generation-7".to_string(),
                adversarial_corpus_suite_name: "hellcat_office_v1".to_string(),
                adversarial_corpus_version: "2026-04-03".to_string(),
                adversarial_corpus_events: vec![
                    mock_process_start("evt-1", 1_900_000_000_000),
                    mock_dns_query("evt-2", 1_900_000_001_000),
                ],
            },
        )
        .unwrap();

    assert_eq!(result.episode.generation, 7);
    assert_eq!(
        result.episode.adversarial_corpus_version,
        "2026-04-03".to_string()
    );
    assert_eq!(result.episode.threat_class_coverage.len(), 2);
    assert!(
        result
            .episode
            .threat_class_coverage
            .iter()
            .any(|coverage| coverage.threat_class == ThreatClass::Execution
                && coverage.detected_events == 1)
    );
    assert!(
        result
            .episode
            .threat_class_coverage
            .iter()
            .any(
                |coverage| coverage.threat_class == ThreatClass::DataExfiltration
                    && coverage.detected_events == 0
            )
    );
    assert!(result.final_fitness > 0.0);
    assert!((result.episode.blue_fitness.final_fitness - result.final_fitness).abs() < 1e-9);
    assert_eq!(result.episode.blue_fitness.deception_adjusted_fitness, 0.88);
    assert_eq!(result.episode.blue_fitness.deception_signal_score, 0.91);

    let store = FileEvolutionEpisodeStore::open(population_dir.join("episodes")).unwrap();
    let latest = store.latest(1).unwrap();
    assert_eq!(latest.len(), 1);
    assert_eq!(latest[0].generation, 7);
    assert_eq!(
        latest[0].adversarial_corpus_sequence_id,
        "generation-7".to_string()
    );
    assert_eq!(
        latest[0].adversarial_corpus_version,
        "2026-04-03".to_string()
    );
    assert!(!latest[0].blue_genome_hash.is_empty());
}

#[test]
fn evasion_adversarial_pressure_persists_gap_adjusted_episode_fields() {
    let root = unique_temp_dir("population-evasion-episodes");
    let population_dir = root.join("population");
    let mutation = DefaultEvolutionMutationHarness::from_path(
        root.join("mutations"),
        root.join("mutation-materialization-batches"),
        root.join("mutation-validation-batches"),
        root.join("mutation-rankings"),
    )
    .unwrap();

    let result = mutation
        .evaluate_adversarial_pressure(
            &population_dir,
            EvolutionAdversarialPressureRequest {
                ranking_id: "ranking:test".to_string(),
                validation_batch_id: "validation:test".to_string(),
                generation: 7,
                evaluated_at_ms: 1_900_000_000_000,
                strategy_id: "office_baseline_control".to_string(),
                experiment_id: "experiment:office_baseline_control".to_string(),
                experiment_path: office_control_experiment(),
                materialization_id: "materialization:test".to_string(),
                validation_bundle_id: "validation-bundle:test".to_string(),
                autonomous_fitness: None,
                replay_fitness: 0.70,
                evasion_adjusted_fitness: 0.74,
                evasion_pressure_score: 0.74,
                evasion_gap_closure_rate: 0.74,
                evasion_focus_gap_count: 2,
                memory_adjusted_fitness: 0.82,
                deception_adjusted_fitness: 0.88,
                deception_signal_score: 0.91,
                adversarial_corpus_sequence_id: "generation-7".to_string(),
                adversarial_corpus_suite_name: "hellcat_office_v1".to_string(),
                adversarial_corpus_version: "2026-04-03".to_string(),
                adversarial_corpus_events: vec![
                    mock_process_start("evt-1", 1_900_000_000_000),
                    mock_dns_query("evt-2", 1_900_000_001_000),
                ],
            },
        )
        .unwrap();

    assert_eq!(result.episode.blue_fitness.evasion_adjusted_fitness, 0.74);
    assert_eq!(result.episode.blue_fitness.evasion_pressure_score, 0.74);
    assert_eq!(result.episode.blue_fitness.evasion_gap_closure_rate, 0.74);
    assert_eq!(result.episode.blue_fitness.evasion_focus_gap_count, 2);

    let store = FileEvolutionEpisodeStore::open(population_dir.join("episodes")).unwrap();
    let latest = store.latest(1).unwrap();
    assert_eq!(latest[0].evasion_pressure_score, 0.74);
    assert_eq!(latest[0].evasion_gap_closure_rate, 0.74);
    assert_eq!(latest[0].evasion_focus_gap_count, 2);
}

#[test]
fn population_selection_respects_hourly_proposal_limit() {
    let root = unique_temp_dir("population-throttle");
    let population_dir = root.join("population");
    let store = FileEvolutionPopulationStore::open(&population_dir).unwrap();
    let now_ms = 1_800_400_000_000_i64;
    store
        .persist(&EvolutionPopulationState {
            updated_at_ms: now_ms,
            ranking_id: "ranking:test".to_string(),
            validation_batch_id: "validation:test".to_string(),
            population_size: 2,
            pareto_tournament_size: 2,
            proposal_timestamps_ms: vec![now_ms - 1_000],
            members: vec![
                EvolutionPopulationCandidate {
                    generation: 1,
                    generation_created_at_ms: now_ms - 10_000,
                    population_rank: 1,
                    pareto_front: 1,
                    ranking_id: "ranking:test".to_string(),
                    validation_batch_id: "validation:test".to_string(),
                    variant_id: "variant-a".to_string(),
                    strategy_id: "candidate-a".to_string(),
                    materialization_id: "materialization-a".to_string(),
                    validation_bundle_id: "validation-a".to_string(),
                    experiment_id: "experiment-a".to_string(),
                    verification_id: "verification-a".to_string(),
                    ready_for_review: true,
                    status: EvolutionValidationBundleStatus::ReadyForQueue,
                    proof_status: crate::evolution::EvolutionProposalProofStatus::Proved,
                    queue_review_state: None,
                    advisory_recommendation: None,
                    blocking_reason_names: Vec::new(),
                    ranking_score: 101.0,
                    baseline_fitness: None,
                    fitness: 0.91,
                    evasion_pressure: None,
                    autonomous_fitness: None,
                    proposed_at_ms: None,
                    objectives: EvolutionPopulationFitnessObjectives {
                        detection_rate: 1.0,
                        false_positive_cost: 1.0,
                        speed: 0.8,
                        threat_class_coverage: 1.0,
                    },
                    summary: "candidate-a".to_string(),
                },
                EvolutionPopulationCandidate {
                    generation: 1,
                    generation_created_at_ms: now_ms - 10_000,
                    population_rank: 2,
                    pareto_front: 1,
                    ranking_id: "ranking:test".to_string(),
                    validation_batch_id: "validation:test".to_string(),
                    variant_id: "variant-b".to_string(),
                    strategy_id: "candidate-b".to_string(),
                    materialization_id: "materialization-b".to_string(),
                    validation_bundle_id: "validation-b".to_string(),
                    experiment_id: "experiment-b".to_string(),
                    verification_id: "verification-b".to_string(),
                    ready_for_review: true,
                    status: EvolutionValidationBundleStatus::ReadyForQueue,
                    proof_status: crate::evolution::EvolutionProposalProofStatus::Proved,
                    queue_review_state: None,
                    advisory_recommendation: None,
                    blocking_reason_names: Vec::new(),
                    ranking_score: 100.0,
                    baseline_fitness: None,
                    fitness: 0.90,
                    evasion_pressure: None,
                    autonomous_fitness: None,
                    proposed_at_ms: None,
                    objectives: EvolutionPopulationFitnessObjectives {
                        detection_rate: 0.9,
                        false_positive_cost: 1.0,
                        speed: 0.8,
                        threat_class_coverage: 1.0,
                    },
                    summary: "candidate-b".to_string(),
                },
            ],
        })
        .unwrap();

    let mutation = DefaultEvolutionMutationHarness::from_path(
        root.join("mutations"),
        root.join("mutation-materialization-batches"),
        root.join("mutation-validation-batches"),
        root.join("mutation-rankings"),
    )
    .unwrap();
    assert!(
        mutation
            .select_population_candidate(&population_dir, 1, now_ms)
            .unwrap()
            .is_none()
    );

    let selected = mutation
        .select_population_candidate(&population_dir, 1, now_ms + 3_600_001)
        .unwrap()
        .unwrap();
    assert_eq!(selected.strategy_id, "candidate-a");
}
