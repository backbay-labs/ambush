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

    let config = sample_config();
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
                        speed: 0.88,
                        threat_class_coverage: 0.92,
                    },
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
                        speed: 0.86,
                        threat_class_coverage: 0.91,
                    },
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
                        speed: 0.87,
                        threat_class_coverage: 0.86,
                    },
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
                        speed: 0.85,
                        threat_class_coverage: 0.84,
                    },
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
                        speed: 0.87,
                        threat_class_coverage: 0.86,
                    },
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
                        speed: 0.86,
                        threat_class_coverage: 0.85,
                    },
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
                        speed: 0.87,
                        threat_class_coverage: 0.85,
                    },
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
                        speed: 0.86,
                        threat_class_coverage: 0.84,
                    },
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
