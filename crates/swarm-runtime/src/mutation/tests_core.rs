use super::test_support::*;

#[tokio::test]
async fn mutation_spec_from_reviewed_draft_persists() {
    let root = unique_temp_dir("mutation-spec-draft");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verifications");
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
    let base_experiment = copy_experiment_fixture(&root, "office-control-copy");

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
            strategy_id: "office_mutation_parent_v1".to_string(),
            strategy_description: "mutation parent draft for office control".to_string(),
            mutation: "guided_mutation_seed".to_string(),
            rationale: "operator wants to compare several explicit variants".to_string(),
        })
        .unwrap();
    let promotion = drafting
        .promote_draft(
            &queue_dir,
            &draft.report.draft_id,
            "review this parent draft first",
        )
        .unwrap();

    let mutation = DefaultEvolutionMutationHarness::from_path(
        &mutation_dir,
        &mutation_materialization_batch_dir,
        &mutation_validation_batch_dir,
        &mutation_ranking_dir,
        test_signing_key(),
    )
    .unwrap();
    let spec = mutation
        .create_mutation_spec(
            &drafting,
            EvolutionMutationSpecCreateRequest {
                draft_id: Some(draft.report.draft_id.clone()),
                materialization_id: None,
                base_experiment_path: Some(base_experiment),
                rationale: "package explicit parent and threshold mutations under one spec"
                    .to_string(),
            },
        )
        .unwrap();
    let spec = mutation
        .append_variant(
            &spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("tighter-thresholds".to_string()),
                strategy_id: "office_mutation_threshold_v1".to_string(),
                strategy_description: "raise confidence thresholds without changing parents"
                    .to_string(),
                mutation: "raise_thresholds".to_string(),
                rationale: "test whether stricter gating reduces replay regressions".to_string(),
                overrides: EvolutionMutationProfileOverrides {
                    high_confidence_threshold: Some("0.98".to_string()),
                    medium_confidence_threshold: Some("0.92".to_string()),
                    ..EvolutionMutationProfileOverrides::default()
                },
                target_genome: None,
            },
        )
        .unwrap();

    assert_eq!(spec.report.source_kind, EvolutionMutationSourceKind::Draft);
    assert_eq!(
        spec.report.queue_proposal_id.as_deref(),
        Some(promotion.report.queue_proposal_id.as_str())
    );
    assert_eq!(spec.report.variants.len(), 1);
    assert_eq!(
        spec.report.variants[0].mutation_dimensions,
        vec![
            "high_confidence_threshold".to_string(),
            "medium_confidence_threshold".to_string()
        ]
    );
    assert!(render_evolution_mutation_spec(&spec.report).contains("Evolution Mutation Spec"));

    let loaded = mutation
        .load_mutation_spec(&spec.report.mutation_spec_id)
        .unwrap()
        .unwrap();
    assert_eq!(loaded.report.variants.len(), 1);
}

#[tokio::test]
async fn mutation_spec_from_materialized_candidate_persists() {
    let root = unique_temp_dir("mutation-spec-materialization");
    let replay_dir = root.join("replay");
    let verification_dir = root.join("verifications");
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
    let base_experiment = copy_experiment_fixture(&root, "office-control-seed");

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
            &root.join("experiments"),
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
            strategy_id: "office_materialized_parent_v1".to_string(),
            strategy_description: "materialized parent draft".to_string(),
            mutation: "materialize_parent_for_guided_mutation".to_string(),
            rationale: "seed a later mutation bench from a concrete candidate".to_string(),
        })
        .unwrap();
    drafting
        .promote_draft(
            &queue_dir,
            &draft.report.draft_id,
            "review the parent draft before mutation",
        )
        .unwrap();
    let materialization = drafting
        .materialize_draft(EvolutionDraftMaterializationRequest {
            draft_id: draft.report.draft_id.clone(),
            base_experiment_path: Some(base_experiment),
            ..EvolutionDraftMaterializationRequest::default()
        })
        .unwrap();

    let mutation = DefaultEvolutionMutationHarness::from_path(
        &mutation_dir,
        &mutation_materialization_batch_dir,
        &mutation_validation_batch_dir,
        &mutation_ranking_dir,
        test_signing_key(),
    )
    .unwrap();
    let spec = mutation
        .create_mutation_spec(
            &drafting,
            EvolutionMutationSpecCreateRequest {
                draft_id: None,
                materialization_id: Some(materialization.report.materialization_id.clone()),
                base_experiment_path: None,
                rationale:
                    "branch explicit parent and child mutations from the materialized candidate"
                        .to_string(),
            },
        )
        .unwrap();
    let spec = mutation
        .append_variant(
            &spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("python-parent".to_string()),
                strategy_id: "office_python_parent_v2".to_string(),
                strategy_description: "broaden parent matching to python".to_string(),
                mutation: "broaden_parent_set".to_string(),
                rationale: "explicitly measure the broader parent signal".to_string(),
                overrides: EvolutionMutationProfileOverrides {
                    add_suspicious_parents: vec!["python".to_string()],
                    ..EvolutionMutationProfileOverrides::default()
                },
                target_genome: None,
            },
        )
        .unwrap();

    assert_eq!(
        spec.report.source_kind,
        EvolutionMutationSourceKind::Materialization
    );
    assert_eq!(
        spec.report.materialization_id.as_deref(),
        Some(materialization.report.materialization_id.as_str())
    );
    assert_eq!(
        spec.report.base_experiment_path,
        materialization.report.experiment_path
    );
    assert_eq!(spec.report.variants.len(), 1);
}

#[tokio::test]
async fn behavioral_anomaly_target_genome_materializes_typed_candidate() {
    let root = unique_temp_dir("mutation-behavioral-genome");
    let replay_dir = root.join("replay");
    let verification_dir = root.join("verifications");
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
    let base_experiment =
        copy_behavioral_anomaly_experiment_fixture(&root, "behavioral-anomaly-control");

    let mut config = sample_config();
    config.detection.strategy = "behavioral_anomaly".to_string();
    config.detection.strategies.clear();
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(&base_experiment, &verification_dir)
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
        .create_pressure_from_verification(
            &replay,
            &verification_dir,
            &verification.report.verification_id,
        )
        .unwrap();
    let draft = drafting
        .create_draft(EvolutionDraftCreateRequest {
            pressure_id: pressure.report.pressure_id.clone(),
            strategy_id: "behavioral_anomaly".to_string(),
            strategy_description: "behavioral anomaly mutation parent".to_string(),
            mutation: "guided_mutation_seed".to_string(),
            rationale: "package a typed behavioral-anomaly candidate".to_string(),
        })
        .unwrap();
    drafting
        .promote_draft(
            &queue_dir,
            &draft.report.draft_id,
            "review the behavioral anomaly parent draft",
        )
        .unwrap();

    let mutation = DefaultEvolutionMutationHarness::from_path(
        &mutation_dir,
        &mutation_materialization_batch_dir,
        &mutation_validation_batch_dir,
        &mutation_ranking_dir,
        test_signing_key(),
    )
    .unwrap();
    let spec = mutation
        .create_mutation_spec(
            &drafting,
            EvolutionMutationSpecCreateRequest {
                draft_id: Some(draft.report.draft_id.clone()),
                materialization_id: None,
                base_experiment_path: Some(base_experiment.clone()),
                rationale: "materialize a typed behavioral anomaly branch".to_string(),
            },
        )
        .unwrap();
    let perturbed_profile = BehavioralAnomalyProfile {
        high_confidence_z_score: 2.1,
        min_feature_weight: 0.12,
        min_host_observations: 2,
        min_identity_observations: 2,
        min_peer_group_observations: 2,
        distribution_min_observations: 2,
        high_confidence_threshold: 0.82,
        medium_confidence_threshold: 0.58,
        ..BehavioralAnomalyProfile::default()
    };
    let spec = mutation
        .append_variant(
            &spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("behavioral-perturbation".to_string()),
                strategy_id: "behavioral_anomaly_candidate_v1".to_string(),
                strategy_description: "typed behavioral anomaly perturbation".to_string(),
                mutation: "behavioral_genome_perturbation".to_string(),
                rationale: "measure a bounded behavioral anomaly sensitivity shift".to_string(),
                overrides: EvolutionMutationProfileOverrides::default(),
                target_genome: Some(EvolutionDetectorGenome::BehavioralAnomaly {
                    profile: perturbed_profile.clone(),
                }),
            },
        )
        .unwrap();

    assert_eq!(
        spec.report.variants[0].mutation_dimensions,
        vec![
            "high_confidence_threshold".to_string(),
            "high_confidence_z_score".to_string(),
            "medium_confidence_threshold".to_string(),
            "min_feature_weight".to_string(),
            "min_host_observations".to_string(),
            "min_identity_observations".to_string(),
            "min_peer_group_observations".to_string(),
        ]
    );

    let batch = mutation
        .materialize_batch(&drafting, &spec.report.mutation_spec_id)
        .unwrap();
    let materialization = drafting
        .load_materialization(&batch.report.entries[0].materialization_id)
        .unwrap()
        .unwrap();
    assert!(materialization.report.profile.is_none());
    assert!(matches!(
        materialization.report.genome,
        Some(EvolutionDetectorGenome::BehavioralAnomaly { .. })
    ));
    let manifest = crate::replay::load_detector_experiment_manifest(std::path::Path::new(
        &materialization.report.experiment_path,
    ))
    .unwrap();
    match manifest.candidate {
        DetectorCandidateManifest::BehavioralAnomaly { profile, .. } => {
            assert_eq!(profile, perturbed_profile);
        }
        other => panic!("expected behavioral anomaly candidate, got {other:?}"),
    }
}

#[tokio::test]
async fn fileless_execution_target_genome_materializes_typed_candidate() {
    let root = unique_temp_dir("mutation-fileless-genome");
    let replay_dir = root.join("replay");
    let verification_dir = root.join("verifications");
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
    let base_experiment = copy_fileless_execution_experiment_fixture(&root, "fileless-control");

    let mut config = sample_config();
    config.detection.strategy = "fileless_execution".to_string();
    config.detection.strategies.clear();
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(&base_experiment, &verification_dir)
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
        .create_pressure_from_verification(
            &replay,
            &verification_dir,
            &verification.report.verification_id,
        )
        .unwrap();
    let draft = drafting
        .create_draft(EvolutionDraftCreateRequest {
            pressure_id: pressure.report.pressure_id.clone(),
            strategy_id: "fileless_execution".to_string(),
            strategy_description: "fileless execution mutation parent".to_string(),
            mutation: "guided_mutation_seed".to_string(),
            rationale: "package a typed fileless-execution candidate".to_string(),
        })
        .unwrap();
    drafting
        .promote_draft(
            &queue_dir,
            &draft.report.draft_id,
            "review the fileless parent draft",
        )
        .unwrap();

    let mutation = DefaultEvolutionMutationHarness::from_path(
        &mutation_dir,
        &mutation_materialization_batch_dir,
        &mutation_validation_batch_dir,
        &mutation_ranking_dir,
        test_signing_key(),
    )
    .unwrap();
    let spec = mutation
        .create_mutation_spec(
            &drafting,
            EvolutionMutationSpecCreateRequest {
                draft_id: Some(draft.report.draft_id.clone()),
                materialization_id: None,
                base_experiment_path: Some(base_experiment.clone()),
                rationale: "materialize a typed fileless-execution perturbation".to_string(),
            },
        )
        .unwrap();
    let perturbed_profile = FilelessExecutionProfile {
        deobfuscation_indicators: vec![
            "iex".to_string(),
            "invoke-expression".to_string(),
            "invoke-assembly".to_string(),
        ],
        min_region_size_bytes: 1024,
        high_confidence_threshold: 0.84,
        medium_confidence_threshold: 0.60,
        ..FilelessExecutionProfile::default()
    };
    let spec = mutation
        .append_variant(
            &spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("fileless-perturbation".to_string()),
                strategy_id: "fileless_candidate_v1".to_string(),
                strategy_description: "typed fileless execution perturbation".to_string(),
                mutation: "fileless_genome_perturbation".to_string(),
                rationale: "measure a bounded fileless sensitivity shift".to_string(),
                overrides: EvolutionMutationProfileOverrides::default(),
                target_genome: Some(EvolutionDetectorGenome::FilelessExecution {
                    profile: perturbed_profile.clone(),
                }),
            },
        )
        .unwrap();

    assert!(
        spec.report.variants[0]
            .mutation_dimensions
            .contains(&"deobfuscation_indicators".to_string())
    );
    assert!(
        spec.report.variants[0]
            .mutation_dimensions
            .contains(&"min_region_size_bytes".to_string())
    );
    assert!(
        spec.report.variants[0]
            .mutation_dimensions
            .contains(&"high_confidence_threshold".to_string())
    );

    let batch = mutation
        .materialize_batch(&drafting, &spec.report.mutation_spec_id)
        .unwrap();
    let materialization = drafting
        .load_materialization(&batch.report.entries[0].materialization_id)
        .unwrap()
        .unwrap();
    assert!(materialization.report.profile.is_none());
    assert!(matches!(
        materialization.report.genome,
        Some(EvolutionDetectorGenome::FilelessExecution { .. })
    ));
    let manifest = crate::replay::load_detector_experiment_manifest(std::path::Path::new(
        &materialization.report.experiment_path,
    ))
    .unwrap();
    match manifest.candidate {
        DetectorCandidateManifest::FilelessExecution { profile, .. } => {
            assert_eq!(profile, perturbed_profile);
        }
        other => panic!("expected fileless execution candidate, got {other:?}"),
    }
}

#[tokio::test]
async fn dns_exfiltration_target_genome_materializes_typed_candidate() {
    let root = unique_temp_dir("mutation-dns-genome");
    let replay_dir = root.join("replay");
    let verification_dir = root.join("verifications");
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
    let base_experiment = copy_dns_exfiltration_experiment_fixture(&root, "dns-control");

    let mut config = sample_config();
    config.detection.strategy = "dns_exfiltration".to_string();
    config.detection.strategies.clear();
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(&base_experiment, &verification_dir)
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
        .create_pressure_from_verification(
            &replay,
            &verification_dir,
            &verification.report.verification_id,
        )
        .unwrap();
    let draft = drafting
        .create_draft(EvolutionDraftCreateRequest {
            pressure_id: pressure.report.pressure_id.clone(),
            strategy_id: "dns_exfiltration".to_string(),
            strategy_description: "dns exfiltration mutation parent".to_string(),
            mutation: "guided_mutation_seed".to_string(),
            rationale: "package a typed dns-exfiltration candidate".to_string(),
        })
        .unwrap();
    drafting
        .promote_draft(
            &queue_dir,
            &draft.report.draft_id,
            "review the dns parent draft",
        )
        .unwrap();

    let mutation = DefaultEvolutionMutationHarness::from_path(
        &mutation_dir,
        &mutation_materialization_batch_dir,
        &mutation_validation_batch_dir,
        &mutation_ranking_dir,
        test_signing_key(),
    )
    .unwrap();
    let spec = mutation
        .create_mutation_spec(
            &drafting,
            EvolutionMutationSpecCreateRequest {
                draft_id: Some(draft.report.draft_id.clone()),
                materialization_id: None,
                base_experiment_path: Some(base_experiment.clone()),
                rationale: "materialize a typed dns-exfiltration perturbation".to_string(),
            },
        )
        .unwrap();
    let perturbed_profile = DnsExfiltrationProfile {
        known_tunneling_patterns: vec![
            "dnscat".to_string(),
            "iodine".to_string(),
            "dns2tcp".to_string(),
        ],
        entropy_threshold: 3.1,
        query_burst_threshold: 6,
        high_confidence_threshold: 0.84,
        medium_confidence_threshold: 0.62,
        ..DnsExfiltrationProfile::default()
    };
    let spec = mutation
        .append_variant(
            &spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("dns-perturbation".to_string()),
                strategy_id: "dns_candidate_v1".to_string(),
                strategy_description: "typed dns exfiltration perturbation".to_string(),
                mutation: "dns_genome_perturbation".to_string(),
                rationale: "measure a bounded dns-exfiltration sensitivity shift".to_string(),
                overrides: EvolutionMutationProfileOverrides::default(),
                target_genome: Some(EvolutionDetectorGenome::DnsExfiltration {
                    profile: perturbed_profile.clone(),
                }),
            },
        )
        .unwrap();

    assert!(
        spec.report.variants[0]
            .mutation_dimensions
            .contains(&"known_tunneling_patterns".to_string())
    );
    assert!(
        spec.report.variants[0]
            .mutation_dimensions
            .contains(&"entropy_threshold".to_string())
    );
    assert!(
        spec.report.variants[0]
            .mutation_dimensions
            .contains(&"query_burst_threshold".to_string())
    );

    let batch = mutation
        .materialize_batch(&drafting, &spec.report.mutation_spec_id)
        .unwrap();
    let materialization = drafting
        .load_materialization(&batch.report.entries[0].materialization_id)
        .unwrap()
        .unwrap();
    assert!(materialization.report.profile.is_none());
    assert!(matches!(
        materialization.report.genome,
        Some(EvolutionDetectorGenome::DnsExfiltration { .. })
    ));
    let manifest = crate::replay::load_detector_experiment_manifest(std::path::Path::new(
        &materialization.report.experiment_path,
    ))
    .unwrap();
    match manifest.candidate {
        DetectorCandidateManifest::DnsExfiltration { profile, .. } => {
            assert_eq!(profile, perturbed_profile);
        }
        other => panic!("expected dns exfiltration candidate, got {other:?}"),
    }
}

#[tokio::test]
async fn autonomous_mutation_spec_generates_bounded_variants_from_population_winners() {
    let root = unique_temp_dir("mutation-autonomous");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verifications");
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
    let base_experiment = copy_experiment_fixture(&root, "office-control-autonomous");

    let mut config = sample_config();
    config.evolution.max_variants_per_cycle = 3;
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(&base_experiment, &verification_dir)
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
            &base_experiment,
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
    let population_draft = drafting
        .create_draft(EvolutionDraftCreateRequest {
            pressure_id: pressure.report.pressure_id.clone(),
            strategy_id: "office_population_seed_v1".to_string(),
            strategy_description: "population seed for autonomous mutation".to_string(),
            mutation: "population_seed".to_string(),
            rationale: "seed two durable winning genomes".to_string(),
        })
        .unwrap();
    drafting
        .promote_draft(
            &queue_dir,
            &population_draft.report.draft_id,
            "review the seed draft before autonomous generation",
        )
        .unwrap();
    let control_materialization = drafting
        .materialize_draft(EvolutionDraftMaterializationRequest {
            draft_id: population_draft.report.draft_id.clone(),
            base_experiment_path: Some(base_experiment.clone()),
            ..EvolutionDraftMaterializationRequest::default()
        })
        .unwrap();
    let crossover_materialization = drafting
        .materialize_draft(EvolutionDraftMaterializationRequest {
            draft_id: population_draft.report.draft_id.clone(),
            base_experiment_path: Some(base_experiment.clone()),
            add_suspicious_parents: vec!["python".to_string()],
            high_confidence_threshold: Some(0.94),
            medium_confidence_threshold: Some(0.84),
            ..EvolutionDraftMaterializationRequest::default()
        })
        .unwrap();
    assert_ne!(
        control_materialization.report.materialization_id,
        crossover_materialization.report.materialization_id,
        "back-to-back materializations of one draft must not alias"
    );
    assert_ne!(
        control_materialization.report.experiment_path,
        crossover_materialization.report.experiment_path,
        "back-to-back materializations must not overwrite one experiment manifest"
    );

    let population_store = FileEvolutionPopulationStore::open_signed(
        &population_dir,
        test_signer_agent_id(),
        test_signing_key(),
    )
    .unwrap();
    population_store
        .persist(&EvolutionPopulationState {
            updated_at_ms: 1_800_400_000_000,
            ranking_id: "ranking:autonomous".to_string(),
            validation_batch_id: "validation:autonomous".to_string(),
            population_size: 4,
            pareto_tournament_size: 2,
            proposal_timestamps_ms: Vec::new(),
            members: vec![
                EvolutionPopulationCandidate {
                    generation: 3,
                    generation_created_at_ms: 1_800_399_000_000,
                    population_rank: 1,
                    pareto_front: 1,
                    ranking_id: "ranking:autonomous".to_string(),
                    validation_batch_id: "validation:autonomous".to_string(),
                    variant_id: "winner-control".to_string(),
                    strategy_id: control_materialization.report.strategy_id.clone(),
                    materialization_id: control_materialization.report.materialization_id.clone(),
                    validation_bundle_id: "validation-bundle-control".to_string(),
                    experiment_id: control_materialization.report.experiment_id.clone(),
                    verification_id: verification.report.verification_id.clone(),
                    ready_for_review: true,
                    status: EvolutionValidationBundleStatus::ReadyForQueue,
                    proof_status: crate::evolution::EvolutionProposalProofStatus::Proved,
                    queue_review_state: None,
                    advisory_recommendation: None,
                    blocking_reason_names: Vec::new(),
                    ranking_score: 104.0,
                    baseline_fitness: Some(0.94),
                    fitness: 0.94,
                    evasion_pressure: None,
                    autonomous_fitness: None,
                    proposed_at_ms: None,
                    objectives: EvolutionPopulationFitnessObjectives {
                        detection_rate: 0.96,
                        false_positive_cost: 0.90,
                        threat_class_coverage: 0.92,
                    },
                    observations: None,
                    summary: "top control winner".to_string(),
                },
                EvolutionPopulationCandidate {
                    generation: 2,
                    generation_created_at_ms: 1_800_398_000_000,
                    population_rank: 2,
                    pareto_front: 1,
                    ranking_id: "ranking:autonomous".to_string(),
                    validation_batch_id: "validation:autonomous".to_string(),
                    variant_id: "winner-crossover".to_string(),
                    strategy_id: crossover_materialization.report.strategy_id.clone(),
                    materialization_id: crossover_materialization.report.materialization_id.clone(),
                    validation_bundle_id: "validation-bundle-crossover".to_string(),
                    experiment_id: crossover_materialization.report.experiment_id.clone(),
                    verification_id: verification.report.verification_id.clone(),
                    ready_for_review: true,
                    status: EvolutionValidationBundleStatus::ReadyForQueue,
                    proof_status: crate::evolution::EvolutionProposalProofStatus::Proved,
                    queue_review_state: None,
                    advisory_recommendation: None,
                    blocking_reason_names: Vec::new(),
                    ranking_score: 101.0,
                    baseline_fitness: Some(0.90),
                    fitness: 0.90,
                    evasion_pressure: None,
                    autonomous_fitness: None,
                    proposed_at_ms: None,
                    objectives: EvolutionPopulationFitnessObjectives {
                        detection_rate: 0.93,
                        false_positive_cost: 0.87,
                        threat_class_coverage: 0.91,
                    },
                    observations: None,
                    summary: "second winning genome".to_string(),
                },
            ],
        })
        .unwrap();

    let autonomous_draft = drafting
        .create_draft(EvolutionDraftCreateRequest {
            pressure_id: pressure.report.pressure_id.clone(),
            strategy_id: "office_autonomous_generation_v1".to_string(),
            strategy_description: "autonomous generator fixture".to_string(),
            mutation: "runtime_drift_response".to_string(),
            rationale: "derive bounded variants from the current winning population".to_string(),
        })
        .unwrap();
    let mutation = DefaultEvolutionMutationHarness::from_path(
        &mutation_dir,
        &mutation_materialization_batch_dir,
        &mutation_validation_batch_dir,
        &mutation_ranking_dir,
        test_signing_key(),
    )
    .unwrap();
    let spec = mutation
        .create_autonomous_mutation_spec(
            &drafting,
            &population_dir,
            EvolutionAutonomousMutationSpecCreateRequest {
                draft_id: autonomous_draft.report.draft_id.clone(),
                strategy_root: autonomous_draft.report.strategy_id.clone(),
                rationale: autonomous_draft.report.lineage_rationale.clone(),
                max_variants: 3,
                base_experiment_path: None,
                evasion_pressure: Some(sample_evasion_pressure_input()),
            },
        )
        .unwrap();

    assert_eq!(
        spec.report.source_kind,
        EvolutionMutationSourceKind::Autonomous
    );
    assert_eq!(
        spec.report.base_experiment_path,
        control_materialization.report.experiment_path
    );
    assert_eq!(
        spec.report
            .autonomous_generation
            .as_ref()
            .unwrap()
            .population_ranking_id
            .as_deref(),
        Some("ranking:autonomous")
    );
    assert_eq!(
        spec.report
            .autonomous_generation
            .as_ref()
            .unwrap()
            .parents
            .len(),
        2
    );
    assert!(
        spec.report
            .variants
            .iter()
            .any(|variant| variant.mutation == "autonomous_bounded_perturbation")
    );
    let crossover_variant = spec
        .report
        .variants
        .iter()
        .find(|variant| variant.mutation == "autonomous_bounded_crossover")
        .expect("autonomous spec should include a crossover variant");
    assert_eq!(
        crossover_variant
            .autonomous_lineage
            .as_ref()
            .unwrap()
            .parent_strategy_ids,
        vec![
            control_materialization.report.strategy_id.clone(),
            crossover_materialization.report.strategy_id.clone(),
        ]
    );
    assert!(render_evolution_mutation_spec(&spec.report).contains("Autonomous generator"));

    let batch = mutation
        .materialize_batch(&drafting, &spec.report.mutation_spec_id)
        .unwrap();
    let crossover_entry = batch
        .report
        .entries
        .iter()
        .find(|entry| entry.variant_id == crossover_variant.variant_id)
        .expect("crossover variant should materialize");
    let generated_crossover_materialization = drafting
        .load_materialization(&crossover_entry.materialization_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        generated_crossover_materialization
            .report
            .lineage
            .parent_strategy_id,
        "suspicious_process_tree".to_string()
    );
    assert!(
        generated_crossover_materialization
            .report
            .lineage
            .rationale
            .contains(&crossover_materialization.report.strategy_id)
            || crossover_variant
                .rationale
                .contains(&crossover_materialization.report.strategy_id)
    );
}

#[tokio::test]
async fn autonomous_mutation_spec_generates_behavioral_anomaly_variants() {
    let root = unique_temp_dir("mutation-autonomous-behavioral");
    let replay_dir = root.join("replay");
    let verification_dir = root.join("verifications");
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
    let base_experiment =
        copy_behavioral_anomaly_experiment_fixture(&root, "behavioral-autonomous-control");

    let mut config = sample_config();
    config.detection.strategy = "behavioral_anomaly".to_string();
    config.detection.strategies.clear();
    config.evolution.max_variants_per_cycle = 3;
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(&base_experiment, &verification_dir)
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
        .create_pressure_from_verification(
            &replay,
            &verification_dir,
            &verification.report.verification_id,
        )
        .unwrap();
    let population_draft = drafting
        .create_draft(EvolutionDraftCreateRequest {
            pressure_id: pressure.report.pressure_id.clone(),
            strategy_id: "behavioral_anomaly_seed_v1".to_string(),
            strategy_description: "behavioral anomaly seed for autonomous mutation".to_string(),
            mutation: "population_seed".to_string(),
            rationale: "seed two durable behavioral anomaly genomes".to_string(),
        })
        .unwrap();
    drafting
        .promote_draft(
            &queue_dir,
            &population_draft.report.draft_id,
            "review the behavioral seed draft before autonomous generation",
        )
        .unwrap();

    let mutation = DefaultEvolutionMutationHarness::from_path(
        &mutation_dir,
        &mutation_materialization_batch_dir,
        &mutation_validation_batch_dir,
        &mutation_ranking_dir,
        test_signing_key(),
    )
    .unwrap();
    let seed_spec = mutation
        .create_mutation_spec(
            &drafting,
            EvolutionMutationSpecCreateRequest {
                draft_id: Some(population_draft.report.draft_id.clone()),
                materialization_id: None,
                base_experiment_path: Some(base_experiment.clone()),
                rationale: "materialize two parent behavioral genomes".to_string(),
            },
        )
        .unwrap();
    let seed_spec = mutation
        .append_variant(
            &seed_spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("behavioral-control".to_string()),
                strategy_id: "behavioral_population_control_v1".to_string(),
                strategy_description: "behavioral anomaly control genome".to_string(),
                mutation: "copy_control_profile".to_string(),
                rationale: "control winner".to_string(),
                overrides: EvolutionMutationProfileOverrides::default(),
                target_genome: Some(EvolutionDetectorGenome::BehavioralAnomaly {
                    profile: BehavioralAnomalyProfile::default(),
                }),
            },
        )
        .unwrap();
    let donor_profile = BehavioralAnomalyProfile {
        sensitive_parent_processes: vec![
            "winword".to_string(),
            "excel".to_string(),
            "python".to_string(),
        ],
        sensitive_child_processes: vec![
            "powershell".to_string(),
            "pwsh".to_string(),
            "python".to_string(),
        ],
        rare_role_tools: vec!["rar".to_string(), "7z".to_string()],
        trusted_binary_prefixes: vec!["c:\\windows\\system32".to_string()],
        high_confidence_threshold: 0.84,
        medium_confidence_threshold: 0.60,
        min_feature_weight: 0.10,
        high_confidence_z_score: 2.0,
        ..BehavioralAnomalyProfile::default()
    };
    let seed_spec = mutation
        .append_variant(
            &seed_spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("behavioral-donor".to_string()),
                strategy_id: "behavioral_population_donor_v1".to_string(),
                strategy_description: "behavioral anomaly donor genome".to_string(),
                mutation: "behavioral_donor".to_string(),
                rationale: "second winning genome".to_string(),
                overrides: EvolutionMutationProfileOverrides::default(),
                target_genome: Some(EvolutionDetectorGenome::BehavioralAnomaly {
                    profile: donor_profile.clone(),
                }),
            },
        )
        .unwrap();
    let seed_batch = mutation
        .materialize_batch(&drafting, &seed_spec.report.mutation_spec_id)
        .unwrap();
    let control_materialization = drafting
        .load_materialization(&seed_batch.report.entries[0].materialization_id)
        .unwrap()
        .unwrap();
    let donor_materialization = drafting
        .load_materialization(&seed_batch.report.entries[1].materialization_id)
        .unwrap()
        .unwrap();

    let population_store = FileEvolutionPopulationStore::open_signed(
        &population_dir,
        test_signer_agent_id(),
        test_signing_key(),
    )
    .unwrap();
    population_store
        .persist(&EvolutionPopulationState {
            updated_at_ms: 1_800_500_000_000,
            ranking_id: "ranking:behavioral".to_string(),
            validation_batch_id: "validation:behavioral".to_string(),
            population_size: 4,
            pareto_tournament_size: 2,
            proposal_timestamps_ms: Vec::new(),
            members: vec![
                EvolutionPopulationCandidate {
                    generation: 3,
                    generation_created_at_ms: 1_800_499_000_000,
                    population_rank: 1,
                    pareto_front: 1,
                    ranking_id: "ranking:behavioral".to_string(),
                    validation_batch_id: "validation:behavioral".to_string(),
                    variant_id: "winner-control".to_string(),
                    strategy_id: control_materialization.report.strategy_id.clone(),
                    materialization_id: control_materialization.report.materialization_id.clone(),
                    validation_bundle_id: "validation-bundle-control".to_string(),
                    experiment_id: control_materialization.report.experiment_id.clone(),
                    verification_id: verification.report.verification_id.clone(),
                    ready_for_review: true,
                    status: EvolutionValidationBundleStatus::ReadyForQueue,
                    proof_status: crate::evolution::EvolutionProposalProofStatus::Proved,
                    queue_review_state: None,
                    advisory_recommendation: None,
                    blocking_reason_names: Vec::new(),
                    ranking_score: 103.0,
                    baseline_fitness: Some(0.90),
                    fitness: 0.90,
                    evasion_pressure: None,
                    autonomous_fitness: None,
                    proposed_at_ms: None,
                    objectives: EvolutionPopulationFitnessObjectives {
                        detection_rate: 0.91,
                        false_positive_cost: 0.88,
                        threat_class_coverage: 0.86,
                    },
                    observations: None,
                    summary: "behavioral control winner".to_string(),
                },
                EvolutionPopulationCandidate {
                    generation: 2,
                    generation_created_at_ms: 1_800_498_000_000,
                    population_rank: 2,
                    pareto_front: 1,
                    ranking_id: "ranking:behavioral".to_string(),
                    validation_batch_id: "validation:behavioral".to_string(),
                    variant_id: "winner-donor".to_string(),
                    strategy_id: donor_materialization.report.strategy_id.clone(),
                    materialization_id: donor_materialization.report.materialization_id.clone(),
                    validation_bundle_id: "validation-bundle-donor".to_string(),
                    experiment_id: donor_materialization.report.experiment_id.clone(),
                    verification_id: verification.report.verification_id.clone(),
                    ready_for_review: true,
                    status: EvolutionValidationBundleStatus::ReadyForQueue,
                    proof_status: crate::evolution::EvolutionProposalProofStatus::Proved,
                    queue_review_state: None,
                    advisory_recommendation: None,
                    blocking_reason_names: Vec::new(),
                    ranking_score: 101.0,
                    baseline_fitness: Some(0.88),
                    fitness: 0.88,
                    evasion_pressure: None,
                    autonomous_fitness: None,
                    proposed_at_ms: None,
                    objectives: EvolutionPopulationFitnessObjectives {
                        detection_rate: 0.89,
                        false_positive_cost: 0.86,
                        threat_class_coverage: 0.84,
                    },
                    observations: None,
                    summary: "behavioral donor winner".to_string(),
                },
            ],
        })
        .unwrap();

    let autonomous_draft = drafting
        .create_draft(EvolutionDraftCreateRequest {
            pressure_id: pressure.report.pressure_id.clone(),
            strategy_id: "behavioral_autonomous_generation_v1".to_string(),
            strategy_description: "behavioral autonomous generator fixture".to_string(),
            mutation: "runtime_drift_response".to_string(),
            rationale: "derive bounded behavioral anomaly variants from the current winners"
                .to_string(),
        })
        .unwrap();
    let spec = mutation
        .create_autonomous_mutation_spec(
            &drafting,
            &population_dir,
            EvolutionAutonomousMutationSpecCreateRequest {
                draft_id: autonomous_draft.report.draft_id.clone(),
                strategy_root: autonomous_draft.report.strategy_id.clone(),
                rationale: autonomous_draft.report.lineage_rationale.clone(),
                max_variants: 3,
                base_experiment_path: None,
                evasion_pressure: None,
            },
        )
        .unwrap();

    assert!(spec.report.variants.iter().all(|variant| matches!(
        variant.target_genome,
        Some(EvolutionDetectorGenome::BehavioralAnomaly { .. })
    )));
    assert!(
        spec.report
            .variants
            .iter()
            .any(|variant| variant.mutation == "autonomous_bounded_perturbation")
    );
    let crossover_variant = spec
        .report
        .variants
        .iter()
        .find(|variant| variant.mutation == "autonomous_bounded_crossover")
        .expect("behavioral autonomous spec should include a crossover variant");
    assert!(
        crossover_variant
            .mutation_dimensions
            .iter()
            .any(|dimension| dimension == "sensitive_parent_processes")
    );

    let batch = mutation
        .materialize_batch(&drafting, &spec.report.mutation_spec_id)
        .unwrap();
    let materialization = drafting
        .load_materialization(&batch.report.entries[0].materialization_id)
        .unwrap()
        .unwrap();
    assert!(matches!(
        materialization.report.genome,
        Some(EvolutionDetectorGenome::BehavioralAnomaly { .. })
    ));
}

#[tokio::test]
async fn autonomous_mutation_spec_generates_fileless_execution_variants() {
    let root = unique_temp_dir("mutation-autonomous-fileless");
    let replay_dir = root.join("replay");
    let verification_dir = root.join("verifications");
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
    let base_experiment = copy_fileless_execution_experiment_fixture(&root, "fileless-autonomous");

    let mut config = sample_config();
    config.detection.strategy = "fileless_execution".to_string();
    config.detection.strategies.clear();
    config.evolution.max_variants_per_cycle = 3;
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(&base_experiment, &verification_dir)
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
        .create_pressure_from_verification(
            &replay,
            &verification_dir,
            &verification.report.verification_id,
        )
        .unwrap();
    let population_draft = drafting
        .create_draft(EvolutionDraftCreateRequest {
            pressure_id: pressure.report.pressure_id.clone(),
            strategy_id: "fileless_seed_v1".to_string(),
            strategy_description: "fileless execution seed for autonomous mutation".to_string(),
            mutation: "population_seed".to_string(),
            rationale: "seed two durable fileless execution genomes".to_string(),
        })
        .unwrap();
    drafting
        .promote_draft(
            &queue_dir,
            &population_draft.report.draft_id,
            "review the fileless seed draft before autonomous generation",
        )
        .unwrap();

    let mutation = DefaultEvolutionMutationHarness::from_path(
        &mutation_dir,
        &mutation_materialization_batch_dir,
        &mutation_validation_batch_dir,
        &mutation_ranking_dir,
        test_signing_key(),
    )
    .unwrap();
    let seed_spec = mutation
        .create_mutation_spec(
            &drafting,
            EvolutionMutationSpecCreateRequest {
                draft_id: Some(population_draft.report.draft_id.clone()),
                materialization_id: None,
                base_experiment_path: Some(base_experiment.clone()),
                rationale: "capture the top fileless execution genomes before autonomous mutation"
                    .to_string(),
            },
        )
        .unwrap();
    let seed_spec = mutation
        .append_variant(
            &seed_spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("fileless-control".to_string()),
                strategy_id: "fileless_population_control_v1".to_string(),
                strategy_description: "fileless execution control genome".to_string(),
                mutation: "copy_control_profile".to_string(),
                rationale: "control winner".to_string(),
                overrides: EvolutionMutationProfileOverrides::default(),
                target_genome: Some(EvolutionDetectorGenome::FilelessExecution {
                    profile: FilelessExecutionProfile::default(),
                }),
            },
        )
        .unwrap();
    let donor_profile = FilelessExecutionProfile {
        reflective_call_stack_indicators: vec![
            "reflective".to_string(),
            "manualmap".to_string(),
            "ntmapviewofsection".to_string(),
        ],
        deobfuscation_indicators: vec![
            "iex".to_string(),
            "invoke-expression".to_string(),
            "invoke-assembly".to_string(),
        ],
        min_region_size_bytes: 2048,
        high_confidence_threshold: 0.84,
        medium_confidence_threshold: 0.60,
        ..FilelessExecutionProfile::default()
    };
    let seed_spec = mutation
        .append_variant(
            &seed_spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("fileless-donor".to_string()),
                strategy_id: "fileless_population_donor_v1".to_string(),
                strategy_description: "fileless execution donor genome".to_string(),
                mutation: "fileless_donor".to_string(),
                rationale: "second winning genome".to_string(),
                overrides: EvolutionMutationProfileOverrides::default(),
                target_genome: Some(EvolutionDetectorGenome::FilelessExecution {
                    profile: donor_profile,
                }),
            },
        )
        .unwrap();
    let seed_batch = mutation
        .materialize_batch(&drafting, &seed_spec.report.mutation_spec_id)
        .unwrap();
    let control_materialization = drafting
        .load_materialization(&seed_batch.report.entries[0].materialization_id)
        .unwrap()
        .unwrap();
    let donor_materialization = drafting
        .load_materialization(&seed_batch.report.entries[1].materialization_id)
        .unwrap()
        .unwrap();

    let population_store = FileEvolutionPopulationStore::open_signed(
        &population_dir,
        test_signer_agent_id(),
        test_signing_key(),
    )
    .unwrap();
    population_store
        .persist(&EvolutionPopulationState {
            updated_at_ms: 1_800_600_000_000,
            ranking_id: "ranking:fileless".to_string(),
            validation_batch_id: "validation:fileless".to_string(),
            population_size: 4,
            pareto_tournament_size: 2,
            proposal_timestamps_ms: Vec::new(),
            members: vec![
                EvolutionPopulationCandidate {
                    generation: 3,
                    generation_created_at_ms: 1_800_599_000_000,
                    population_rank: 1,
                    pareto_front: 1,
                    ranking_id: "ranking:fileless".to_string(),
                    validation_batch_id: "validation:fileless".to_string(),
                    variant_id: "winner-control".to_string(),
                    strategy_id: control_materialization.report.strategy_id.clone(),
                    materialization_id: control_materialization.report.materialization_id.clone(),
                    validation_bundle_id: "validation-bundle-control".to_string(),
                    experiment_id: control_materialization.report.experiment_id.clone(),
                    verification_id: "verification:fileless-control".to_string(),
                    ready_for_review: true,
                    status: EvolutionValidationBundleStatus::ReadyForQueue,
                    proof_status: crate::evolution::EvolutionProposalProofStatus::Proved,
                    queue_review_state: None,
                    advisory_recommendation: None,
                    blocking_reason_names: Vec::new(),
                    ranking_score: 104.0,
                    baseline_fitness: Some(0.91),
                    fitness: 0.91,
                    evasion_pressure: None,
                    autonomous_fitness: None,
                    proposed_at_ms: None,
                    objectives: EvolutionPopulationFitnessObjectives {
                        detection_rate: 0.92,
                        false_positive_cost: 0.88,
                        threat_class_coverage: 0.86,
                    },
                    observations: None,
                    summary: "fileless control winner".to_string(),
                },
                EvolutionPopulationCandidate {
                    generation: 2,
                    generation_created_at_ms: 1_800_598_000_000,
                    population_rank: 2,
                    pareto_front: 1,
                    ranking_id: "ranking:fileless".to_string(),
                    validation_batch_id: "validation:fileless".to_string(),
                    variant_id: "winner-donor".to_string(),
                    strategy_id: donor_materialization.report.strategy_id.clone(),
                    materialization_id: donor_materialization.report.materialization_id.clone(),
                    validation_bundle_id: "validation-bundle-donor".to_string(),
                    experiment_id: donor_materialization.report.experiment_id.clone(),
                    verification_id: "verification:fileless-donor".to_string(),
                    ready_for_review: true,
                    status: EvolutionValidationBundleStatus::ReadyForQueue,
                    proof_status: crate::evolution::EvolutionProposalProofStatus::Proved,
                    queue_review_state: None,
                    advisory_recommendation: None,
                    blocking_reason_names: Vec::new(),
                    ranking_score: 102.0,
                    baseline_fitness: Some(0.89),
                    fitness: 0.89,
                    evasion_pressure: None,
                    autonomous_fitness: None,
                    proposed_at_ms: None,
                    objectives: EvolutionPopulationFitnessObjectives {
                        detection_rate: 0.90,
                        false_positive_cost: 0.87,
                        threat_class_coverage: 0.85,
                    },
                    observations: None,
                    summary: "fileless donor winner".to_string(),
                },
            ],
        })
        .unwrap();

    let autonomous_draft = drafting
        .create_draft(EvolutionDraftCreateRequest {
            pressure_id: pressure.report.pressure_id.clone(),
            strategy_id: "fileless_autonomous_generation_v1".to_string(),
            strategy_description: "fileless autonomous generator fixture".to_string(),
            mutation: "runtime_drift_response".to_string(),
            rationale: "derive bounded fileless execution variants from the current winners"
                .to_string(),
        })
        .unwrap();
    let spec = mutation
        .create_autonomous_mutation_spec(
            &drafting,
            &population_dir,
            EvolutionAutonomousMutationSpecCreateRequest {
                draft_id: autonomous_draft.report.draft_id.clone(),
                strategy_root: autonomous_draft.report.strategy_id.clone(),
                rationale: autonomous_draft.report.lineage_rationale.clone(),
                max_variants: 3,
                base_experiment_path: None,
                evasion_pressure: None,
            },
        )
        .unwrap();

    assert!(spec.report.variants.iter().all(|variant| matches!(
        variant.target_genome,
        Some(EvolutionDetectorGenome::FilelessExecution { .. })
    )));
    assert!(
        spec.report
            .variants
            .iter()
            .any(|variant| variant.mutation == "autonomous_bounded_perturbation")
    );
    let crossover_variant = spec
        .report
        .variants
        .iter()
        .find(|variant| variant.mutation == "autonomous_bounded_crossover")
        .expect("fileless autonomous spec should include a crossover variant");
    assert!(
        crossover_variant
            .mutation_dimensions
            .iter()
            .any(|dimension| dimension == "deobfuscation_indicators")
    );

    let batch = mutation
        .materialize_batch(&drafting, &spec.report.mutation_spec_id)
        .unwrap();
    let materialization = drafting
        .load_materialization(&batch.report.entries[0].materialization_id)
        .unwrap()
        .unwrap();
    assert!(matches!(
        materialization.report.genome,
        Some(EvolutionDetectorGenome::FilelessExecution { .. })
    ));
}

#[tokio::test]
async fn autonomous_mutation_spec_generates_dns_exfiltration_variants() {
    let root = unique_temp_dir("mutation-autonomous-dns");
    let replay_dir = root.join("replay");
    let verification_dir = root.join("verifications");
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
    let base_experiment = copy_dns_exfiltration_experiment_fixture(&root, "dns-autonomous");

    let mut config = sample_config();
    config.detection.strategy = "dns_exfiltration".to_string();
    config.detection.strategies.clear();
    config.evolution.max_variants_per_cycle = 3;
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(&base_experiment, &verification_dir)
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
        .create_pressure_from_verification(
            &replay,
            &verification_dir,
            &verification.report.verification_id,
        )
        .unwrap();
    let population_draft = drafting
        .create_draft(EvolutionDraftCreateRequest {
            pressure_id: pressure.report.pressure_id.clone(),
            strategy_id: "dns_seed_v1".to_string(),
            strategy_description: "dns exfiltration seed for autonomous mutation".to_string(),
            mutation: "population_seed".to_string(),
            rationale: "seed two durable dns exfiltration genomes".to_string(),
        })
        .unwrap();
    drafting
        .promote_draft(
            &queue_dir,
            &population_draft.report.draft_id,
            "review the dns seed draft before autonomous generation",
        )
        .unwrap();

    let mutation = DefaultEvolutionMutationHarness::from_path(
        &mutation_dir,
        &mutation_materialization_batch_dir,
        &mutation_validation_batch_dir,
        &mutation_ranking_dir,
        test_signing_key(),
    )
    .unwrap();
    let seed_spec = mutation
        .create_mutation_spec(
            &drafting,
            EvolutionMutationSpecCreateRequest {
                draft_id: Some(population_draft.report.draft_id.clone()),
                materialization_id: None,
                base_experiment_path: Some(base_experiment.clone()),
                rationale: "capture the top dns exfiltration genomes before autonomous mutation"
                    .to_string(),
            },
        )
        .unwrap();
    let seed_spec = mutation
        .append_variant(
            &seed_spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("dns-control".to_string()),
                strategy_id: "dns_population_control_v1".to_string(),
                strategy_description: "dns exfiltration control genome".to_string(),
                mutation: "copy_control_profile".to_string(),
                rationale: "control winner".to_string(),
                overrides: EvolutionMutationProfileOverrides::default(),
                target_genome: Some(EvolutionDetectorGenome::DnsExfiltration {
                    profile: DnsExfiltrationProfile::default(),
                }),
            },
        )
        .unwrap();
    let donor_profile = DnsExfiltrationProfile {
        suspicious_query_types: vec!["TXT".to_string(), "NULL".to_string(), "MX".to_string()],
        known_tunneling_patterns: vec![
            "dnscat".to_string(),
            "iodine".to_string(),
            "dns2tcp".to_string(),
        ],
        entropy_threshold: 3.1,
        query_burst_threshold: 6,
        high_confidence_threshold: 0.84,
        medium_confidence_threshold: 0.62,
        ..DnsExfiltrationProfile::default()
    };
    let seed_spec = mutation
        .append_variant(
            &seed_spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("dns-donor".to_string()),
                strategy_id: "dns_population_donor_v1".to_string(),
                strategy_description: "dns exfiltration donor genome".to_string(),
                mutation: "dns_donor".to_string(),
                rationale: "second winning genome".to_string(),
                overrides: EvolutionMutationProfileOverrides::default(),
                target_genome: Some(EvolutionDetectorGenome::DnsExfiltration {
                    profile: donor_profile,
                }),
            },
        )
        .unwrap();
    let seed_batch = mutation
        .materialize_batch(&drafting, &seed_spec.report.mutation_spec_id)
        .unwrap();
    let control_materialization = drafting
        .load_materialization(&seed_batch.report.entries[0].materialization_id)
        .unwrap()
        .unwrap();
    let donor_materialization = drafting
        .load_materialization(&seed_batch.report.entries[1].materialization_id)
        .unwrap()
        .unwrap();

    let population_store = FileEvolutionPopulationStore::open_signed(
        &population_dir,
        test_signer_agent_id(),
        test_signing_key(),
    )
    .unwrap();
    population_store
        .persist(&EvolutionPopulationState {
            updated_at_ms: 1_800_700_000_000,
            ranking_id: "ranking:dns".to_string(),
            validation_batch_id: "validation:dns".to_string(),
            population_size: 4,
            pareto_tournament_size: 2,
            proposal_timestamps_ms: Vec::new(),
            members: vec![
                EvolutionPopulationCandidate {
                    generation: 3,
                    generation_created_at_ms: 1_800_699_000_000,
                    population_rank: 1,
                    pareto_front: 1,
                    ranking_id: "ranking:dns".to_string(),
                    validation_batch_id: "validation:dns".to_string(),
                    variant_id: "winner-control".to_string(),
                    strategy_id: control_materialization.report.strategy_id.clone(),
                    materialization_id: control_materialization.report.materialization_id.clone(),
                    validation_bundle_id: "validation-bundle-control".to_string(),
                    experiment_id: control_materialization.report.experiment_id.clone(),
                    verification_id: "verification:dns-control".to_string(),
                    ready_for_review: true,
                    status: EvolutionValidationBundleStatus::ReadyForQueue,
                    proof_status: crate::evolution::EvolutionProposalProofStatus::Proved,
                    queue_review_state: None,
                    advisory_recommendation: None,
                    blocking_reason_names: Vec::new(),
                    ranking_score: 104.0,
                    baseline_fitness: Some(0.90),
                    fitness: 0.90,
                    evasion_pressure: None,
                    autonomous_fitness: None,
                    proposed_at_ms: None,
                    objectives: EvolutionPopulationFitnessObjectives {
                        detection_rate: 0.91,
                        false_positive_cost: 0.88,
                        threat_class_coverage: 0.85,
                    },
                    observations: None,
                    summary: "dns control winner".to_string(),
                },
                EvolutionPopulationCandidate {
                    generation: 2,
                    generation_created_at_ms: 1_800_698_000_000,
                    population_rank: 2,
                    pareto_front: 1,
                    ranking_id: "ranking:dns".to_string(),
                    validation_batch_id: "validation:dns".to_string(),
                    variant_id: "winner-donor".to_string(),
                    strategy_id: donor_materialization.report.strategy_id.clone(),
                    materialization_id: donor_materialization.report.materialization_id.clone(),
                    validation_bundle_id: "validation-bundle-donor".to_string(),
                    experiment_id: donor_materialization.report.experiment_id.clone(),
                    verification_id: "verification:dns-donor".to_string(),
                    ready_for_review: true,
                    status: EvolutionValidationBundleStatus::ReadyForQueue,
                    proof_status: crate::evolution::EvolutionProposalProofStatus::Proved,
                    queue_review_state: None,
                    advisory_recommendation: None,
                    blocking_reason_names: Vec::new(),
                    ranking_score: 101.0,
                    baseline_fitness: Some(0.88),
                    fitness: 0.88,
                    evasion_pressure: None,
                    autonomous_fitness: None,
                    proposed_at_ms: None,
                    objectives: EvolutionPopulationFitnessObjectives {
                        detection_rate: 0.89,
                        false_positive_cost: 0.87,
                        threat_class_coverage: 0.84,
                    },
                    observations: None,
                    summary: "dns donor winner".to_string(),
                },
            ],
        })
        .unwrap();

    let autonomous_draft = drafting
        .create_draft(EvolutionDraftCreateRequest {
            pressure_id: pressure.report.pressure_id.clone(),
            strategy_id: "dns_autonomous_generation_v1".to_string(),
            strategy_description: "dns autonomous generator fixture".to_string(),
            mutation: "runtime_drift_response".to_string(),
            rationale: "derive bounded dns exfiltration variants from the current winners"
                .to_string(),
        })
        .unwrap();
    let spec = mutation
        .create_autonomous_mutation_spec(
            &drafting,
            &population_dir,
            EvolutionAutonomousMutationSpecCreateRequest {
                draft_id: autonomous_draft.report.draft_id.clone(),
                strategy_root: autonomous_draft.report.strategy_id.clone(),
                rationale: autonomous_draft.report.lineage_rationale.clone(),
                max_variants: 3,
                base_experiment_path: None,
                evasion_pressure: None,
            },
        )
        .unwrap();

    assert!(spec.report.variants.iter().all(|variant| matches!(
        variant.target_genome,
        Some(EvolutionDetectorGenome::DnsExfiltration { .. })
    )));
    assert!(
        spec.report
            .variants
            .iter()
            .any(|variant| variant.mutation == "autonomous_bounded_perturbation")
    );
    let crossover_variant = spec
        .report
        .variants
        .iter()
        .find(|variant| variant.mutation == "autonomous_bounded_crossover")
        .expect("dns autonomous spec should include a crossover variant");
    assert!(
        crossover_variant
            .mutation_dimensions
            .iter()
            .any(|dimension| dimension == "known_tunneling_patterns")
    );

    let batch = mutation
        .materialize_batch(&drafting, &spec.report.mutation_spec_id)
        .unwrap();
    let materialization = drafting
        .load_materialization(&batch.report.entries[0].materialization_id)
        .unwrap()
        .unwrap();
    assert!(matches!(
        materialization.report.genome,
        Some(EvolutionDetectorGenome::DnsExfiltration { .. })
    ));
}

#[tokio::test]
async fn mutation_batch_materializes_variants() {
    let root = unique_temp_dir("mutation-batch-materialize");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verifications");
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
    let base_experiment = copy_experiment_fixture(&root, "office-control-batch");

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
            strategy_id: "office_batch_parent_v1".to_string(),
            strategy_description: "batch mutation parent".to_string(),
            mutation: "guided_batch_seed".to_string(),
            rationale: "materialize two explicit variants from one spec".to_string(),
        })
        .unwrap();
    let promotion = drafting
        .promote_draft(
            &queue_dir,
            &draft.report.draft_id,
            "hold a reviewed parent queue ref",
        )
        .unwrap();
    let mutation = DefaultEvolutionMutationHarness::from_path(
        &mutation_dir,
        &mutation_materialization_batch_dir,
        &mutation_validation_batch_dir,
        &mutation_ranking_dir,
        test_signing_key(),
    )
    .unwrap();
    let spec = mutation
        .create_mutation_spec(
            &drafting,
            EvolutionMutationSpecCreateRequest {
                draft_id: Some(draft.report.draft_id.clone()),
                materialization_id: None,
                base_experiment_path: Some(base_experiment),
                rationale: "compare a control-preserving variant with a broader parent match"
                    .to_string(),
            },
        )
        .unwrap();
    let spec = mutation
        .append_variant(
            &spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("control-copy".to_string()),
                strategy_id: "office_batch_control_v1".to_string(),
                strategy_description: "preserve the control profile".to_string(),
                mutation: "copy_control_profile".to_string(),
                rationale: "keep one no-op control branch for comparison".to_string(),
                overrides: EvolutionMutationProfileOverrides::default(),
                target_genome: None,
            },
        )
        .unwrap();
    let _spec = mutation
        .append_variant(
            &spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("python-parent".to_string()),
                strategy_id: "office_batch_python_parent_v1".to_string(),
                strategy_description: "broaden suspicious parent matching to python".to_string(),
                mutation: "broaden_parent_set".to_string(),
                rationale: "explicitly compare a broader parent signal".to_string(),
                overrides: EvolutionMutationProfileOverrides {
                    add_suspicious_parents: vec!["python".to_string()],
                    ..EvolutionMutationProfileOverrides::default()
                },
                target_genome: None,
            },
        )
        .unwrap();

    let batch = mutation
        .materialize_batch(&drafting, &spec.report.mutation_spec_id)
        .unwrap();
    assert_eq!(batch.report.candidate_count, 2);
    assert!(
        batch
            .report
            .entries
            .iter()
            .all(|entry| entry.queue_proposal_id.as_deref()
                == Some(promotion.report.queue_proposal_id.as_str()))
    );
    assert!(
        render_evolution_mutation_materialization_batch(&batch.report)
            .contains("Evolution Mutation Materialization Batch")
    );
}

#[tokio::test]
async fn mutation_batch_refreshes_ready_and_blocked_validation() {
    let root = unique_temp_dir("mutation-batch-validation");
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
    let base_experiment = copy_experiment_fixture(&root, "office-control-validation");

    let config = sample_config();
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(&base_experiment, &verification_dir)
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
            &base_experiment,
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
            strategy_description: "validation parent".to_string(),
            mutation: "guided_validation_seed".to_string(),
            rationale: "refresh two variants through the existing validation lane".to_string(),
        })
        .unwrap();
    drafting
        .promote_draft(
            &queue_dir,
            &draft.report.draft_id,
            "hold the reviewed queue ref while validating variants",
        )
        .unwrap();
    let mutation = DefaultEvolutionMutationHarness::from_path(
        &mutation_dir,
        &mutation_materialization_batch_dir,
        &mutation_validation_batch_dir,
        &mutation_ranking_dir,
        test_signing_key(),
    )
    .unwrap();
    let spec = mutation
        .create_mutation_spec(
            &drafting,
            EvolutionMutationSpecCreateRequest {
                draft_id: Some(draft.report.draft_id.clone()),
                materialization_id: None,
                base_experiment_path: Some(base_experiment),
                rationale: "compare one ready variant and one blocked variant".to_string(),
            },
        )
        .unwrap();
    let spec = mutation
        .append_variant(
            &spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("control-copy".to_string()),
                strategy_id: "office_validation_control_v1".to_string(),
                strategy_description: "keep the control profile".to_string(),
                mutation: "copy_control_profile".to_string(),
                rationale: "preserve a ready branch".to_string(),
                overrides: EvolutionMutationProfileOverrides::default(),
                target_genome: None,
            },
        )
        .unwrap();
    let spec = mutation
        .append_variant(
            &spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("python-parent".to_string()),
                strategy_id: "office_validation_python_parent_v1".to_string(),
                strategy_description: "broaden suspicious parent matching to python".to_string(),
                mutation: "broaden_parent_set".to_string(),
                rationale: "preserve one explicitly blocked branch".to_string(),
                overrides: EvolutionMutationProfileOverrides {
                    add_suspicious_parents: vec!["python".to_string()],
                    ..EvolutionMutationProfileOverrides::default()
                },
                target_genome: None,
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

    assert_eq!(
        validation_batch.report.ready_count, 1,
        "validation entries: {:#?}",
        validation_batch.report.entries
    );
    assert_eq!(
        validation_batch.report.blocked_count, 1,
        "validation entries: {:#?}",
        validation_batch.report.entries
    );
    assert!(
        validation_batch
            .report
            .entries
            .iter()
            .any(|entry| entry.status == EvolutionValidationBundleStatus::Blocked)
    );
    assert!(
        render_evolution_mutation_validation_batch(&validation_batch.report)
            .contains("Evolution Mutation Validation Batch")
    );

    for entry in &batch.report.entries {
        let path = PathBuf::from(&entry.experiment_path);
        if path.exists() {
            fs::remove_file(path).unwrap();
        }
    }
}

fn latency_suite_report() -> crate::replay::ReplaySuiteReport {
    crate::replay::ReplaySuiteReport {
        source: "scenario-suites/hellcat-office-v1.yaml".to_string(),
        source_kind: crate::replay::ReplaySuiteSourceKind::SuiteManifest,
        suite_name: Some("hellcat_office_v1".to_string()),
        suite_description: Some("fitness invariance fixture".to_string()),
        corpus_version: Some("2026-04-03".to_string()),
        total_scenarios: 2,
        passed_scenarios: 2,
        failed_scenarios: 0,
        passed: true,
        scenario_reports: Vec::new(),
        technique_groups: Vec::new(),
    }
}

/// Two experiment reports that differ in exactly one field: the wall-clock
/// detect latency the harness happened to measure.
fn latency_experiment_report(
    max_detect_latency_us: u64,
) -> crate::replay::StrategyExperimentReport {
    let metrics = crate::replay::StrategyExperimentMetrics {
        total_scenarios: 2,
        adversarial_scenarios: 1,
        benign_scenarios: 1,
        true_positive_scenarios: 1,
        false_negative_scenarios: 0,
        true_negative_scenarios: 1,
        false_positive_scenarios: 0,
        detection_rate: 0.86,
        false_positive_rate: 0.02,
        max_detect_latency_us,
    };
    crate::replay::StrategyExperimentReport {
        experiment_id: "experiment:fitness-invariance".to_string(),
        experiment_name: "fitness-invariance".to_string(),
        description: "fitness invariance fixture".to_string(),
        created_at_ms: 1_700_000_000_000,
        suite_name: "hellcat_office_v1".to_string(),
        suite_path: "scenario-suites/hellcat-office-v1.yaml".to_string(),
        corpus_version: "2026-04-03".to_string(),
        lineage: crate::replay::ExperimentLineage {
            parent_strategy_id: "suspicious_process_tree".to_string(),
            mutation: "control".to_string(),
            rationale: "fitness invariance fixture".to_string(),
        },
        baseline_strategy_id: "suspicious_process_tree".to_string(),
        candidate_strategy_id: "suspicious_process_tree_variant".to_string(),
        candidate_description: "fitness invariance candidate".to_string(),
        baseline_report: latency_suite_report(),
        candidate_report: latency_suite_report(),
        comparison: crate::replay::StrategyExperimentComparison {
            baseline: metrics.clone(),
            candidate: metrics,
            delta: crate::replay::StrategyExperimentMetricDelta {
                detection_rate_delta: 0.0,
                false_positive_rate_delta: 0.0,
                max_detect_latency_delta_us: 0,
                false_positive_scenario_delta: 0,
            },
            scenario_regressions: Vec::new(),
            technique_regressions: Vec::new(),
        },
        gates: Vec::new(),
        observations: Vec::new(),
        passed: true,
    }
}

fn latency_verification_report() -> crate::replay::DetectorVerificationReport {
    crate::replay::DetectorVerificationReport {
        verification_id: "verification:fitness-invariance".to_string(),
        experiment_id: "experiment:fitness-invariance".to_string(),
        experiment_name: "fitness-invariance".to_string(),
        corpus_name: "office_detector_safety_v1".to_string(),
        corpus_path: repo_root()
            .join("verifications/office-detector-safety-v1.yaml")
            .display()
            .to_string(),
        created_at_ms: 1_700_000_000_100,
        lineage: crate::replay::ExperimentLineage {
            parent_strategy_id: "suspicious_process_tree".to_string(),
            mutation: "control".to_string(),
            rationale: "fitness invariance fixture".to_string(),
        },
        candidate_strategy_id: "suspicious_process_tree_variant".to_string(),
        candidate_description: "fitness invariance candidate".to_string(),
        // `threat_class_templates` with no counterexamples: full coverage, and
        // identical for both reports, so it cannot explain any difference.
        invariants: vec![crate::replay::VerificationInvariantResult {
            name: "threat_class_templates".to_string(),
            passed: true,
            expected: serde_json::json!(1),
            actual: serde_json::json!(1),
            details: "fitness invariance fixture".to_string(),
            counterexamples: Vec::new(),
        }],
        observations: Vec::new(),
        passed: true,
    }
}

/// `population_objectives` derives a `speed` objective from
/// `max_detect_latency_us` -- a wall-clock `Instant` delta -- and
/// `population_fitness` weights it into the scalar that ranks evolved detectors
/// and drives which candidate gets proposed for promotion.
///
/// Both reports below are byte-identical apart from that one measured number.
/// Every input the fixtures determine -- detection rate, false-positive rate,
/// threat-class template coverage -- is the same. So two operators replaying
/// the identical bundle on different hardware rank the same population
/// differently and can promote different detectors, with a green suite on both.
///
/// Fitness must be a function of fixture content alone.
#[test]
fn population_fitness_is_invariant_to_measured_detect_latency() {
    let verification = latency_verification_report();
    let fast = latency_experiment_report(600);
    let slow = latency_experiment_report(60_000);
    let weights = swarm_core::config::EvolutionFitnessWeightsConfig::default();

    let fast_measurement = crate::mutation::population_objectives(&fast, &verification).unwrap();
    let slow_measurement = crate::mutation::population_objectives(&slow, &verification).unwrap();
    let fast_objectives = fast_measurement.objectives;
    let slow_objectives = slow_measurement.objectives;

    // Everything the fixtures determine is identical; only the clock differs.
    assert_eq!(
        fast_objectives.detection_rate,
        slow_objectives.detection_rate
    );
    assert_eq!(
        fast_objectives.false_positive_cost,
        slow_objectives.false_positive_cost
    );
    assert_eq!(
        fast_objectives.threat_class_coverage,
        slow_objectives.threat_class_coverage
    );

    // We lose a gate, not the signal: the measurement each run made is still
    // read and still recorded, next to the budget it is measured against.
    assert_eq!(
        fast_measurement.observations.max_detect_latency_us,
        fast.comparison.candidate.max_detect_latency_us
    );
    assert_eq!(
        slow_measurement.observations.max_detect_latency_us,
        slow.comparison.candidate.max_detect_latency_us
    );
    assert_eq!(
        fast_measurement
            .observations
            .advisory_detect_latency_budget_us,
        slow_measurement
            .observations
            .advisory_detect_latency_budget_us
    );
    assert!(
        fast_measurement
            .observations
            .within_advisory_detect_latency_budget
    );
    assert!(
        !slow_measurement
            .observations
            .within_advisory_detect_latency_budget
    );

    let fast_fitness = crate::mutation::population_fitness(&fast_objectives, &weights);
    let slow_fitness = crate::mutation::population_fitness(&slow_objectives, &weights);

    assert_eq!(
        fast_fitness,
        slow_fitness,
        "population fitness moved from {fast_fitness} to {slow_fitness} because the detect stage \
         was measured at {}us instead of {}us over identical fixtures",
        slow.comparison.candidate.max_detect_latency_us,
        fast.comparison.candidate.max_detect_latency_us
    );
}

/// Removing an objective raises the question of what happens to the weight it
/// carried, and the answer is visible in the score of a perfect candidate.
///
/// This candidate is perfect on everything the fixtures determine: it catches
/// every scenario, raises no false positive, and covers every canonical threat
/// template. With the default weights summing to 1.00 it should score exactly
/// the configured total.
///
/// Before the fix it could not: `speed` held 0.15 of that total hostage to a
/// wall-clock reading, so a flawless candidate measured at 600us scored 0.9915
/// and one measured at 60_000us scored 0.8786.
///
/// The assertion also rules out the other removal option. Dropping `speed`'s
/// share outright would score this candidate 0.85 -- correct as a ranking, wrong
/// as a magnitude, because `fitness` is blended against 0..1 rates elsewhere
/// (`EVASION_PRESSURE_BLEND_WEIGHT` in the population refresh) and shrinking one
/// side of that blend silently re-weights it. Redistributing `speed`'s share
/// proportionally keeps the total the operator configured.
#[test]
fn perfect_candidate_scores_the_full_configured_weight_total() {
    let weights = swarm_core::config::EvolutionFitnessWeightsConfig::default();
    let configured_total = weights.detection_rate
        + weights.false_positive_cost
        + weights.speed
        + weights.threat_class_coverage;
    assert!((configured_total - 1.0).abs() < f64::EPSILON);

    let verification = latency_verification_report();
    let mut experiment = latency_experiment_report(600);
    experiment.comparison.candidate.detection_rate = 1.0;
    experiment.comparison.candidate.false_positive_rate = 0.0;

    let measurement = crate::mutation::population_objectives(&experiment, &verification).unwrap();
    assert_eq!(measurement.objectives.detection_rate, 1.0);
    assert_eq!(measurement.objectives.false_positive_cost, 1.0);
    assert_eq!(measurement.objectives.threat_class_coverage, 1.0);

    let fitness = crate::mutation::population_fitness(&measurement.objectives, &weights);
    assert_eq!(
        fitness, configured_total,
        "a candidate perfect on every fixture-determined objective scored {fitness} against a \
         configured weight total of {configured_total}"
    );
}

/// Population state written before `speed` left the objective vector must still
/// load. This is the durable artifact under `evolution.paths.population_results_dir`;
/// a runtime that cannot read its own history restarts evolution from nothing.
///
/// A compatibility guard rather than a behaviour test: it holds because
/// `EvolutionPopulationFitnessObjectives` is not `deny_unknown_fields`, and it
/// fails the moment someone adds that attribute.
#[test]
fn population_state_persisted_with_the_removed_speed_objective_still_loads() {
    let raw = r#"{
        "updated_at_ms": 1700000000000,
        "ranking_id": "ranking:legacy",
        "validation_batch_id": "batch:legacy",
        "population_size": 16,
        "pareto_tournament_size": 4,
        "proposal_timestamps_ms": [],
        "members": [
            {
                "generation": 1,
                "generation_created_at_ms": 1700000000000,
                "population_rank": 1,
                "pareto_front": 1,
                "ranking_id": "ranking:legacy",
                "validation_batch_id": "batch:legacy",
                "variant_id": "variant:legacy",
                "strategy_id": "suspicious_process_tree_legacy",
                "materialization_id": "materialization:legacy",
                "validation_bundle_id": "bundle:legacy",
                "experiment_id": "experiment:legacy",
                "verification_id": "verification:legacy",
                "ready_for_review": true,
                "status": "ready_for_queue",
                "proof_status": "proved",
                "queue_review_state": null,
                "advisory_recommendation": null,
                "blocking_reason_names": [],
                "ranking_score": 100.0,
                "fitness": 0.9,
                "proposed_at_ms": null,
                "objectives": {
                    "detection_rate": 0.9,
                    "false_positive_cost": 0.98,
                    "speed": 0.87,
                    "threat_class_coverage": 1.0
                },
                "summary": "legacy population member"
            }
        ]
    }"#;

    let state: EvolutionPopulationState = serde_json::from_str(raw).unwrap();
    let member = &state.members[0];
    assert_eq!(member.strategy_id, "suspicious_process_tree_legacy");
    assert_eq!(member.objectives.detection_rate, 0.9);
    assert_eq!(member.objectives.false_positive_cost, 0.98);
    assert_eq!(member.objectives.threat_class_coverage, 1.0);
    // No observations were recorded when this state was written; absence is not
    // an error, it is just an older artifact.
    assert!(member.observations.is_none());
}

/// The repository's own tracked ruleset carries `speed: 0.15` in its
/// `evolution.fitness_weights` block, and `EvolutionFitnessWeightsConfig` is
/// `deny_unknown_fields`. Deleting the weight would therefore have broken the
/// default config -- which could not have been fixed, because `rulesets/` is
/// covered by the signed `rulesets/attestation.json` and the signing key is
/// deliberately not in this repository.
///
/// `sample_config` parses that exact tracked file.
#[test]
fn tracked_default_ruleset_still_loads_with_its_speed_weight() {
    let config = sample_config();
    assert_eq!(config.evolution.fitness_weights.speed, 0.15);
    config.validate().unwrap();
}

/// The curated ruleset OMITS `promotion.require_solver_result_for_promotion`, and
/// must still resolve it to `true`.
///
/// `rulesets/default.yaml` cannot be given the key: its sha256 is inside the
/// ed25519-signed `rulesets/attestation.json`, asserted by
/// `startup_attestation::tests::repo_ruleset_attestation_matches_checked_in_files`
/// and verified at runtime startup, and the signing key is deliberately absent
/// from this repository. So "defaults true in the curated ruleset" can only mean
/// "a ruleset that omits the key resolves to true", and the serde default is the
/// mechanism rather than a shortcut.
///
/// This test is the guard on the real regression: someone writing
/// `#[serde(default)]` instead of `#[serde(default = "...")]` would silently ship
/// every deployment with the promotion solver gate OFF, and nothing else in the
/// suite would notice.
#[test]
fn tracked_default_ruleset_resolves_the_promotion_solver_gate_to_enabled() {
    let raw = std::fs::read_to_string(repo_root().join("rulesets/default.yaml")).unwrap();
    assert!(
        !raw.contains("require_solver_result_for_promotion"),
        "the curated ruleset must NOT carry this key -- it is frozen by the signed \
         attestation, and this test only means anything while the key is absent"
    );

    let config = sample_config();
    assert!(config.promotion.require_solver_result_for_promotion);
    config.validate().unwrap();
}

/// PINS A DELIBERATE, SURPRISING CONSEQUENCE: with the curated ruleset exactly as
/// shipped, the promotion solver gate refuses EVERY promotion.
///
/// The chain, each link measured rather than assumed:
///   1. `rulesets/default.yaml` names one invariant bundle,
///      `safety/office-detector-admission.yaml`.
///   2. That bundle declares only `coverage_floor`, `fp_ceiling`,
///      `latency_budget` and `parameter_bounds` invariants -- no `custom_z3`.
///   3. Solver artifacts are produced ONLY by the two `custom_z3` arms in
///      `evolution::formal_safety`, so the curated run produces none.
///   4. No artifacts -> `summarize_solver_artifacts` -> `None` -> assurance
///      records `solver.status: None`.
///   5. `require_solver_result_for_promotion` defaults true, so
///      `promotion_solver_block` returns `Missing { recorded_status: None }`.
///
/// `enable_z3: false` in the same ruleset closes the door a second time.
///
/// This is fail-closed, which is the direction CLAUDE.md requires, and it is what
/// ZGATE-02 literally asks for. But it means the automated promotion lane is OFF
/// in the shipped configuration until an operator adds a `custom_z3` invariant to
/// their admission bundle AND enables z3 -- and the curated ruleset cannot simply
/// be edited to do so, because its sha256 is inside the signed attestation.
///
/// Without this test the next person to touch the evolution lane spends a day on
/// "promotion never works" before finding the cause. If you are here because this
/// test failed, the shipped posture CHANGED: update the roadmap and STATE.md, do
/// not just re-point the assertion.
#[test]
fn curated_ruleset_produces_no_solver_result_so_promotion_is_refused() {
    let raw = std::fs::read_to_string(repo_root().join("rulesets/default.yaml")).unwrap();
    let curated: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();

    let safety_gate = &curated["evolution"]["safety_gate"];
    assert_eq!(
        safety_gate["enable_z3"].as_bool(),
        Some(false),
        "the curated ruleset is expected to ship with z3 disabled"
    );

    let bundles = safety_gate["invariant_bundle_paths"]
        .as_sequence()
        .expect("curated ruleset must name its invariant bundles");
    assert!(!bundles.is_empty(), "no bundles named at all");

    let mut declared_types = Vec::new();
    for bundle in bundles {
        let rel = bundle.as_str().expect("bundle path must be a string");
        let bundle_raw = std::fs::read_to_string(repo_root().join("rulesets").join(rel)).unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&bundle_raw).unwrap();
        for invariant in parsed["invariants"]
            .as_sequence()
            .expect("bundle must declare invariants")
        {
            declared_types.push(
                invariant["type"]
                    .as_str()
                    .expect("invariant must declare a type")
                    .to_string(),
            );
        }
    }

    assert!(
        !declared_types.iter().any(|kind| kind == "custom_z3"),
        "the curated bundles declare {declared_types:?}. If a `custom_z3` invariant \
         was added, the shipped promotion posture just changed from 'always refused' \
         to 'depends on the solver' -- update this test, the roadmap and STATE.md \
         deliberately rather than re-pointing the assertion"
    );

    // The consequence, stated as an assertion rather than left in prose: the gate
    // is on, and nothing in the curated configuration can satisfy it.
    let config = sample_config();
    assert!(
        config.promotion.require_solver_result_for_promotion,
        "gate must be on for this test to mean anything"
    );
}

fn latency_population_candidate(
    strategy_id: &str,
    objectives: EvolutionPopulationFitnessObjectives,
    fitness: f64,
) -> EvolutionPopulationCandidate {
    EvolutionPopulationCandidate {
        generation: 1,
        generation_created_at_ms: 1_700_000_000_000,
        population_rank: 0,
        pareto_front: 0,
        ranking_id: "ranking:selection".to_string(),
        validation_batch_id: "batch:selection".to_string(),
        variant_id: format!("variant:{strategy_id}"),
        strategy_id: strategy_id.to_string(),
        materialization_id: format!("materialization:{strategy_id}"),
        validation_bundle_id: format!("bundle:{strategy_id}"),
        experiment_id: format!("experiment:{strategy_id}"),
        verification_id: format!("verification:{strategy_id}"),
        ready_for_review: true,
        status: EvolutionValidationBundleStatus::ReadyForQueue,
        proof_status: crate::evolution::EvolutionProposalProofStatus::Proved,
        queue_review_state: None,
        advisory_recommendation: None,
        blocking_reason_names: Vec::new(),
        ranking_score: 100.0,
        baseline_fitness: Some(fitness),
        fitness,
        evasion_pressure: None,
        autonomous_fitness: None,
        proposed_at_ms: None,
        objectives,
        observations: None,
        summary: format!("selection fixture {strategy_id}"),
    }
}

/// The whole point, end to end: which detector gets promoted.
///
/// `broader` catches more of the corpus than `narrower` and is otherwise
/// identical -- same false-positive rate, same threat-class template coverage.
/// It is strictly the better detector on every fact the fixtures determine, and
/// it strictly Pareto-dominates the other. It should win selection anywhere.
///
/// The only thing separating them is that `broader` was measured at 60_000us and
/// `narrower` at 600us -- a difference in machine and load, not in detector.
/// Before the fix that inverted the result twice over: the latency-derived
/// `speed` objective put `narrower` ahead on the weighted score (0.930 vs 0.825)
/// AND broke the Pareto dominance that would otherwise have placed `broader`
/// alone on the first front, so `select_population_survivors` promoted the worse
/// detector. Run the same bundle on a machine where the measurements land the
/// other way round and you promote the other one, with a green suite both times.
#[test]
fn population_selection_promotes_the_better_detector_regardless_of_measured_latency() {
    let verification = latency_verification_report();
    let weights = swarm_core::config::EvolutionFitnessWeightsConfig::default();

    let mut broader_experiment = latency_experiment_report(60_000);
    broader_experiment.comparison.candidate.detection_rate = 0.90;
    let mut narrower_experiment = latency_experiment_report(600);
    narrower_experiment.comparison.candidate.detection_rate = 0.86;

    let broader_measurement =
        crate::mutation::population_objectives(&broader_experiment, &verification).unwrap();
    let narrower_measurement =
        crate::mutation::population_objectives(&narrower_experiment, &verification).unwrap();

    // Strictly better on every fixture-determined objective.
    assert!(
        broader_measurement.objectives.detection_rate
            > narrower_measurement.objectives.detection_rate
    );
    assert_eq!(
        broader_measurement.objectives.false_positive_cost,
        narrower_measurement.objectives.false_positive_cost
    );
    assert_eq!(
        broader_measurement.objectives.threat_class_coverage,
        narrower_measurement.objectives.threat_class_coverage
    );

    let broader = latency_population_candidate(
        "office_broader_coverage",
        broader_measurement.objectives.clone(),
        crate::mutation::population_fitness(&broader_measurement.objectives, &weights),
    );
    let narrower = latency_population_candidate(
        "office_narrower_coverage",
        narrower_measurement.objectives.clone(),
        crate::mutation::population_fitness(&narrower_measurement.objectives, &weights),
    );

    // Pareto path: strictly better on one objective, equal on the rest.
    assert!(crate::mutation::population_candidate_dominates(
        &broader, &narrower
    ));
    assert!(!crate::mutation::population_candidate_dominates(
        &narrower, &broader
    ));

    // Scalar path.
    assert!(broader.fitness > narrower.fitness);

    // And the selection that actually decides what gets proposed.
    let survivors = crate::mutation::select_population_survivors(vec![narrower, broader], 1, 1);
    assert_eq!(survivors.len(), 1);
    assert_eq!(survivors[0].strategy_id, "office_broader_coverage");
}
