use super::*;

pub struct DefaultEvolutionMutationHarness {
    pub mutation_store: FileEvolutionMutationStore,
    pub materialization_batch_store: FileEvolutionMutationMaterializationBatchStore,
    pub validation_batch_store: FileEvolutionMutationValidationBatchStore,
    pub ranking_store: FileEvolutionMutationRankingStore,
}

impl DefaultEvolutionMutationHarness {
    pub fn from_path(
        mutation_results_dir: impl AsRef<Path>,
        materialization_batch_results_dir: impl AsRef<Path>,
        validation_batch_results_dir: impl AsRef<Path>,
        ranking_results_dir: impl AsRef<Path>,
    ) -> Result<Self, EvolutionMutationError> {
        Ok(Self {
            mutation_store: FileEvolutionMutationStore::open(mutation_results_dir)?,
            materialization_batch_store: FileEvolutionMutationMaterializationBatchStore::open(
                materialization_batch_results_dir,
            )?,
            validation_batch_store: FileEvolutionMutationValidationBatchStore::open(
                validation_batch_results_dir,
            )?,
            ranking_store: FileEvolutionMutationRankingStore::open(ranking_results_dir)?,
        })
    }

    pub fn create_mutation_spec(
        &self,
        drafting: &DefaultEvolutionDraftingHarness,
        request: EvolutionMutationSpecCreateRequest,
    ) -> Result<EvolutionMutationSpecLookup, EvolutionMutationError> {
        validate_create_request(&request)?;
        let created_at_ms = now_ms();

        let report = if let Some(draft_id) = request.draft_id {
            let draft = drafting.load_draft(&draft_id)?.ok_or_else(|| {
                EvolutionDraftingError::DraftNotFound {
                    draft_id: draft_id.clone(),
                }
            })?;
            let pressure = drafting
                .load_pressure(&draft.report.pressure_id)?
                .ok_or_else(|| EvolutionDraftingError::PressureNotFound {
                    pressure_id: draft.report.pressure_id.clone(),
                })?;
            let base_experiment_path = match request.base_experiment_path {
                Some(path) => path,
                None => infer_base_experiment_path(
                    &drafting.config_path,
                    &draft.report.draft_id,
                    &pressure.report,
                )?,
            };
            let base_manifest = load_detector_experiment_manifest(&base_experiment_path)?;
            let promotion = drafting
                .promotion_store
                .load_for_draft(&draft.report.draft_id)?;

            EvolutionMutationSpecReport {
                mutation_spec_id: mutation_spec_id(
                    EvolutionMutationSourceKind::Draft,
                    &draft.report.strategy_id,
                    created_at_ms,
                ),
                created_at_ms,
                source_kind: EvolutionMutationSourceKind::Draft,
                draft_id: draft.report.draft_id.clone(),
                materialization_id: None,
                pressure_id: draft.report.pressure_id.clone(),
                promotion_id: promotion
                    .as_ref()
                    .map(|lookup| lookup.report.promotion_id.clone()),
                queue_proposal_id: promotion
                    .as_ref()
                    .map(|lookup| lookup.report.queue_proposal_id.clone()),
                source_strategy_id: draft.report.strategy_id.clone(),
                source_strategy_description: draft.report.strategy_description.clone(),
                source_lineage: ExperimentLineage {
                    parent_strategy_id: draft.report.parent_strategy_id.clone(),
                    mutation: draft.report.lineage_mutation.clone(),
                    rationale: draft.report.lineage_rationale.clone(),
                },
                source_pressure_kind: pressure.report.source_kind,
                source_experiment_id: pressure
                    .report
                    .experiment_id
                    .clone()
                    .unwrap_or_else(|| format!("experiment:{}", base_manifest.name)),
                source_experiment_name: pressure
                    .report
                    .experiment_name
                    .clone()
                    .unwrap_or_else(|| base_manifest.name.clone()),
                base_experiment_path: base_experiment_path.display().to_string(),
                operator_rationale: request.rationale,
                variants: Vec::new(),
                autonomous_generation: None,
            }
        } else {
            let materialization_id = request.materialization_id.ok_or_else(|| {
                EvolutionMutationError::InvalidMutationSpecRequest {
                    reason: "exactly one of draft_id or materialization_id must be set".to_string(),
                }
            })?;
            let materialization = drafting
                .load_materialization(&materialization_id)?
                .ok_or_else(|| EvolutionDraftingError::MaterializationNotFound {
                    materialization_id: materialization_id.clone(),
                })?;
            let promotion = drafting
                .promotion_store
                .load_for_draft(&materialization.report.draft_id)?;

            EvolutionMutationSpecReport {
                mutation_spec_id: mutation_spec_id(
                    EvolutionMutationSourceKind::Materialization,
                    &materialization.report.strategy_id,
                    created_at_ms,
                ),
                created_at_ms,
                source_kind: EvolutionMutationSourceKind::Materialization,
                draft_id: materialization.report.draft_id.clone(),
                materialization_id: Some(materialization.report.materialization_id.clone()),
                pressure_id: materialization.report.pressure_id.clone(),
                promotion_id: promotion
                    .as_ref()
                    .map(|lookup| lookup.report.promotion_id.clone()),
                queue_proposal_id: promotion
                    .as_ref()
                    .map(|lookup| lookup.report.queue_proposal_id.clone()),
                source_strategy_id: materialization.report.strategy_id.clone(),
                source_strategy_description: materialization.report.strategy_description.clone(),
                source_lineage: materialization.report.lineage.clone(),
                source_pressure_kind: resolve_materialization_pressure_kind(
                    drafting,
                    &materialization,
                )?,
                source_experiment_id: materialization.report.experiment_id.clone(),
                source_experiment_name: materialization.report.experiment_name.clone(),
                base_experiment_path: request
                    .base_experiment_path
                    .unwrap_or_else(|| PathBuf::from(&materialization.report.experiment_path))
                    .display()
                    .to_string(),
                operator_rationale: request.rationale,
                variants: Vec::new(),
                autonomous_generation: None,
            }
        };

        let record = self.mutation_store.persist(&report)?;
        Ok(EvolutionMutationSpecLookup { record, report })
    }

    pub fn create_autonomous_mutation_spec(
        &self,
        drafting: &DefaultEvolutionDraftingHarness,
        population_results_dir: impl AsRef<Path>,
        request: EvolutionAutonomousMutationSpecCreateRequest,
    ) -> Result<EvolutionMutationSpecLookup, EvolutionMutationError> {
        validate_autonomous_create_request(&request)?;
        let created_at_ms = now_ms();
        let draft = drafting.load_draft(&request.draft_id)?.ok_or_else(|| {
            EvolutionDraftingError::DraftNotFound {
                draft_id: request.draft_id.clone(),
            }
        })?;
        let pressure = drafting
            .load_pressure(&draft.report.pressure_id)?
            .ok_or_else(|| EvolutionDraftingError::PressureNotFound {
                pressure_id: draft.report.pressure_id.clone(),
            })?;
        let promotion = drafting
            .promotion_store
            .load_for_draft(&draft.report.draft_id)?;

        let population_store = FileEvolutionPopulationStore::open(population_results_dir)?;
        let population = population_store.load()?;
        let selected_parents = load_autonomous_generation_parents(
            drafting,
            population.as_ref(),
            &draft.report,
            &pressure.report,
            request.base_experiment_path.as_deref(),
        )?;
        let base_parent = selected_parents.first().ok_or_else(|| {
            EvolutionMutationError::InvalidMutationSpecRequest {
                reason:
                    "autonomous mutation generation could not resolve a compatible parent genome"
                        .to_string(),
            }
        })?;
        let base_manifest =
            load_detector_experiment_manifest(Path::new(&base_parent.reference.experiment_path))?;
        let variants = build_autonomous_variant_specs(
            &request.strategy_root,
            request.max_variants,
            &selected_parents,
            request.evasion_pressure.as_ref(),
        )?;
        let report = EvolutionMutationSpecReport {
            mutation_spec_id: mutation_spec_id(
                EvolutionMutationSourceKind::Autonomous,
                &draft.report.strategy_id,
                created_at_ms,
            ),
            created_at_ms,
            source_kind: EvolutionMutationSourceKind::Autonomous,
            draft_id: draft.report.draft_id.clone(),
            materialization_id: None,
            pressure_id: draft.report.pressure_id.clone(),
            promotion_id: promotion
                .as_ref()
                .map(|lookup| lookup.report.promotion_id.clone()),
            queue_proposal_id: promotion
                .as_ref()
                .map(|lookup| lookup.report.queue_proposal_id.clone()),
            source_strategy_id: draft.report.strategy_id.clone(),
            source_strategy_description: draft.report.strategy_description.clone(),
            source_lineage: ExperimentLineage {
                parent_strategy_id: draft.report.parent_strategy_id.clone(),
                mutation: draft.report.lineage_mutation.clone(),
                rationale: draft.report.lineage_rationale.clone(),
            },
            source_pressure_kind: pressure.report.source_kind,
            source_experiment_id: base_parent.reference.experiment_id.clone(),
            source_experiment_name: base_manifest.name,
            base_experiment_path: base_parent.reference.experiment_path.clone(),
            operator_rationale: request.rationale,
            variants,
            autonomous_generation: Some(EvolutionAutonomousGenerationTrace {
                generator: "bounded_population_variants_v1".to_string(),
                requested_variant_count: request.max_variants,
                population_ranking_id: population.as_ref().map(|state| state.ranking_id.clone()),
                base_parent_strategy_id: base_parent.reference.strategy_id.clone(),
                parents: selected_parents
                    .iter()
                    .map(|seed| seed.reference.clone())
                    .collect(),
            }),
        };

        let record = self.mutation_store.persist(&report)?;
        Ok(EvolutionMutationSpecLookup { record, report })
    }

    pub fn append_variant(
        &self,
        mutation_spec_id: &str,
        request: EvolutionMutationVariantCreateRequest,
    ) -> Result<EvolutionMutationSpecLookup, EvolutionMutationError> {
        let mut lookup = self.mutation_store.load(mutation_spec_id)?.ok_or_else(|| {
            EvolutionMutationError::MutationSpecNotFound {
                mutation_spec_id: mutation_spec_id.to_string(),
            }
        })?;

        let variant_id = request
            .variant_id
            .unwrap_or_else(|| sanitize_id(&request.strategy_id));
        if lookup
            .report
            .variants
            .iter()
            .any(|variant| variant.variant_id == variant_id)
        {
            return Err(EvolutionMutationError::DuplicateVariantId {
                mutation_spec_id: mutation_spec_id.to_string(),
                variant_id,
            });
        }
        if lookup
            .report
            .variants
            .iter()
            .any(|variant| variant.strategy_id == request.strategy_id)
        {
            return Err(EvolutionMutationError::DuplicateStrategyId {
                mutation_spec_id: mutation_spec_id.to_string(),
                strategy_id: request.strategy_id,
            });
        }

        let _validation_request = request.overrides.to_materialization_request(
            lookup.report.draft_id.clone(),
            PathBuf::from(&lookup.report.base_experiment_path),
        )?;

        let variant = EvolutionMutationVariantSpec {
            variant_id,
            strategy_id: request.strategy_id,
            strategy_description: request.strategy_description,
            mutation: request.mutation,
            rationale: request.rationale,
            mutation_dimensions: request.overrides.dimensions(),
            overrides: request.overrides,
            autonomous_lineage: None,
        };

        lookup.report.variants.push(variant);
        let record = self.mutation_store.persist(&lookup.report)?;
        Ok(EvolutionMutationSpecLookup {
            record,
            report: lookup.report,
        })
    }

    pub fn load_mutation_spec(
        &self,
        mutation_spec_id: &str,
    ) -> Result<Option<EvolutionMutationSpecLookup>, EvolutionMutationError> {
        Ok(self.mutation_store.load(mutation_spec_id)?)
    }

    pub fn materialize_batch(
        &self,
        drafting: &DefaultEvolutionDraftingHarness,
        mutation_spec_id: &str,
    ) -> Result<EvolutionMutationMaterializationBatchLookup, EvolutionMutationError> {
        let spec = self.mutation_store.load(mutation_spec_id)?.ok_or_else(|| {
            EvolutionMutationError::MutationSpecNotFound {
                mutation_spec_id: mutation_spec_id.to_string(),
            }
        })?;
        if spec.report.variants.is_empty() {
            return Err(EvolutionMutationError::MutationSpecHasNoVariants {
                mutation_spec_id: mutation_spec_id.to_string(),
            });
        }

        let base_experiment_path = PathBuf::from(&spec.report.base_experiment_path);
        let created_at_ms = now_ms();
        let mut entries = Vec::new();

        for (index, variant) in spec.report.variants.iter().enumerate() {
            let request = variant.overrides.to_materialization_request(
                spec.report.draft_id.clone(),
                base_experiment_path.clone(),
            )?;
            let report = materialize_variant_report(
                &spec.report,
                variant,
                &request,
                created_at_ms + index as i64,
            )?;
            drafting.materialization_store.persist(&report)?;
            entries.push(EvolutionMutationMaterializationEntry {
                variant_id: variant.variant_id.clone(),
                strategy_id: variant.strategy_id.clone(),
                materialization_id: report.materialization_id,
                experiment_id: report.experiment_id,
                experiment_path: report.experiment_path,
                mutation_dimensions: variant.mutation_dimensions.clone(),
                promotion_id: spec.report.promotion_id.clone(),
                queue_proposal_id: spec.report.queue_proposal_id.clone(),
            });
        }

        let report = EvolutionMutationMaterializationBatchReport {
            batch_id: mutation_materialization_batch_id(
                &spec.report.mutation_spec_id,
                created_at_ms,
            ),
            mutation_spec_id: spec.report.mutation_spec_id.clone(),
            created_at_ms,
            source_strategy_id: spec.report.source_strategy_id.clone(),
            candidate_count: entries.len(),
            entries,
        };
        let record = self.materialization_batch_store.persist(&report)?;
        Ok(EvolutionMutationMaterializationBatchLookup { record, report })
    }

    pub fn load_materialization_batch(
        &self,
        batch_id: &str,
    ) -> Result<Option<EvolutionMutationMaterializationBatchLookup>, EvolutionMutationError> {
        Ok(self.materialization_batch_store.load(batch_id)?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn refresh_validation_batch(
        &self,
        drafting: &DefaultEvolutionDraftingHarness,
        replay_harness: &DefaultReplayHarness,
        proof_harness: &crate::evolution::DefaultEvolutionProofHarness,
        scorecard_harness: &DefaultStrategyScorecardHarness,
        experiment_results_dir: impl AsRef<Path>,
        verification_results_dir: impl AsRef<Path>,
        shadow_results_dir: impl AsRef<Path>,
        batch_id: &str,
    ) -> Result<EvolutionMutationValidationBatchLookup, EvolutionMutationError> {
        let batch = self
            .materialization_batch_store
            .load(batch_id)?
            .ok_or_else(|| EvolutionMutationError::MaterializationBatchNotFound {
                batch_id: batch_id.to_string(),
            })?;
        let created_at_ms = now_ms();
        let mut entries = Vec::new();

        for item in &batch.report.entries {
            let validation = drafting
                .refresh_validation_bundle(
                    replay_harness,
                    proof_harness,
                    scorecard_harness,
                    experiment_results_dir.as_ref(),
                    verification_results_dir.as_ref(),
                    shadow_results_dir.as_ref(),
                    &item.materialization_id,
                )
                .await?;
            entries.push(EvolutionMutationValidationEntry {
                variant_id: item.variant_id.clone(),
                strategy_id: item.strategy_id.clone(),
                materialization_id: item.materialization_id.clone(),
                validation_bundle_id: validation.report.validation_bundle_id.clone(),
                status: validation.report.status,
                proof_status: validation.report.proof_status,
                advisory: validation.report.advisory.clone(),
                promotion_id: item.promotion_id.clone(),
                queue_proposal_id: item.queue_proposal_id.clone(),
                blocking_reason_names: validation
                    .report
                    .blocking_reasons
                    .iter()
                    .map(|reason| reason.name.clone())
                    .collect(),
            });
        }

        let ready_count = entries
            .iter()
            .filter(|entry| entry.status == EvolutionValidationBundleStatus::ReadyForQueue)
            .count();
        let blocked_count = entries.len() - ready_count;
        let report = EvolutionMutationValidationBatchReport {
            validation_batch_id: mutation_validation_batch_id(
                &batch.report.mutation_spec_id,
                created_at_ms,
            ),
            mutation_spec_id: batch.report.mutation_spec_id.clone(),
            materialization_batch_id: batch.report.batch_id.clone(),
            created_at_ms,
            ready_count,
            blocked_count,
            entries,
        };
        let record = self.validation_batch_store.persist(&report)?;
        Ok(EvolutionMutationValidationBatchLookup { record, report })
    }

    pub fn load_validation_batch(
        &self,
        validation_batch_id: &str,
    ) -> Result<Option<EvolutionMutationValidationBatchLookup>, EvolutionMutationError> {
        Ok(self.validation_batch_store.load(validation_batch_id)?)
    }

    pub fn rank_candidates(
        &self,
        queue_results_dir: impl AsRef<Path>,
        validation_batch_id: &str,
        shortlist_count: usize,
    ) -> Result<EvolutionMutationRankingLookup, EvolutionMutationError> {
        let validation_batch = self
            .validation_batch_store
            .load(validation_batch_id)?
            .ok_or_else(|| EvolutionMutationError::ValidationBatchNotFound {
                validation_batch_id: validation_batch_id.to_string(),
            })?;
        let queue_store = FileEvolutionProposalStore::open(queue_results_dir)?;
        let created_at_ms = now_ms();
        let mut ranked_candidates = validation_batch
            .report
            .entries
            .iter()
            .map(|entry| {
                let queue_lookup = match entry.queue_proposal_id.as_deref() {
                    Some(proposal_id) => queue_store.load(proposal_id)?,
                    None => None,
                };
                let queue_review_state = queue_lookup
                    .as_ref()
                    .map(|lookup| lookup.report.review_state);
                let assurance_case_ids = queue_lookup
                    .as_ref()
                    .and_then(|lookup| lookup.report.assurance.as_ref())
                    .map(|assurance| assurance.harvested_case_ids.clone())
                    .unwrap_or_default();
                let assurance_case_count = assurance_case_ids.len();
                let score = candidate_score(entry, queue_review_state, assurance_case_count);
                let summary =
                    candidate_summary(entry, queue_review_state, assurance_case_count, score);
                Ok::<_, EvolutionMutationError>(EvolutionCandidateRankingEntry {
                    rank: 0,
                    variant_id: entry.variant_id.clone(),
                    strategy_id: entry.strategy_id.clone(),
                    materialization_id: entry.materialization_id.clone(),
                    validation_bundle_id: entry.validation_bundle_id.clone(),
                    queue_proposal_id: entry.queue_proposal_id.clone(),
                    queue_review_state,
                    score,
                    status: entry.status,
                    proof_status: entry.proof_status,
                    advisory_recommendation: entry.advisory.as_ref().map(|a| a.recommendation),
                    advisory_score_delta: entry.advisory.as_ref().map(|a| a.score_delta),
                    blocking_reason_names: entry.blocking_reason_names.clone(),
                    assurance_case_count,
                    assurance_case_ids,
                    ready_for_review: entry.status
                        == EvolutionValidationBundleStatus::ReadyForQueue,
                    summary,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        ranked_candidates.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.strategy_id.cmp(&right.strategy_id))
        });
        for (index, candidate) in ranked_candidates.iter_mut().enumerate() {
            candidate.rank = index + 1;
        }

        let shortlist_count = shortlist_count.max(1).min(ranked_candidates.len());
        let review_packets = ranked_candidates
            .iter()
            .take(shortlist_count)
            .map(|candidate| EvolutionCandidateReviewPacket {
                packet_id: review_packet_id(
                    &validation_batch.report.validation_batch_id,
                    candidate.rank,
                    &candidate.variant_id,
                ),
                rank: candidate.rank,
                variant_id: candidate.variant_id.clone(),
                strategy_id: candidate.strategy_id.clone(),
                materialization_id: candidate.materialization_id.clone(),
                validation_bundle_id: candidate.validation_bundle_id.clone(),
                queue_proposal_id: candidate.queue_proposal_id.clone(),
                queue_review_state: candidate.queue_review_state,
                advisory_scorecard_id: validation_batch
                    .report
                    .entries
                    .iter()
                    .find(|entry| entry.variant_id == candidate.variant_id)
                    .and_then(|entry| entry.advisory.as_ref().map(|a| a.scorecard_id.clone())),
                assurance_case_count: candidate.assurance_case_count,
                assurance_case_ids: candidate.assurance_case_ids.clone(),
                score: candidate.score,
                summary: candidate.summary.clone(),
            })
            .collect::<Vec<_>>();

        let report = EvolutionMutationRankingReport {
            ranking_id: mutation_ranking_id(
                &validation_batch.report.mutation_spec_id,
                &validation_batch.report.validation_batch_id,
                created_at_ms,
            ),
            mutation_spec_id: validation_batch.report.mutation_spec_id.clone(),
            validation_batch_id: validation_batch.report.validation_batch_id.clone(),
            created_at_ms,
            shortlist_count,
            ranked_candidates,
            review_packets,
        };
        let record = self.ranking_store.persist(&report)?;
        Ok(EvolutionMutationRankingLookup { record, report })
    }

    pub fn load_ranking(
        &self,
        ranking_id: &str,
    ) -> Result<Option<EvolutionMutationRankingLookup>, EvolutionMutationError> {
        Ok(self.ranking_store.load(ranking_id)?)
    }

    pub fn load_population(
        &self,
        population_results_dir: impl AsRef<Path>,
    ) -> Result<Option<EvolutionPopulationState>, EvolutionMutationError> {
        let store = FileEvolutionPopulationStore::open(population_results_dir)?;
        Ok(store.load()?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn refresh_population(
        &self,
        population_results_dir: impl AsRef<Path>,
        drafting: &DefaultEvolutionDraftingHarness,
        experiment_results_dir: impl AsRef<Path>,
        verification_results_dir: impl AsRef<Path>,
        ranking: &EvolutionMutationRankingReport,
        population_size: usize,
        pareto_tournament_size: usize,
        fitness_weights: &EvolutionFitnessWeightsConfig,
        evasion_pressure: Option<&EvolutionEvasionPressureInput>,
    ) -> Result<EvolutionPopulationState, EvolutionMutationError> {
        let store = FileEvolutionPopulationStore::open(population_results_dir)?;
        let existing = store.load()?;
        let mutation_spec = self.load_mutation_spec(&ranking.mutation_spec_id)?;
        let autonomous_lineage_by_variant = mutation_spec
            .as_ref()
            .map(|lookup| {
                lookup
                    .report
                    .variants
                    .iter()
                    .filter_map(|variant| {
                        variant
                            .autonomous_lineage
                            .clone()
                            .map(|lineage| (variant.variant_id.clone(), lineage))
                    })
                    .collect::<HashMap<_, _>>()
            })
            .unwrap_or_default();
        let ranking_index = self.ranking_store.read_index()?;
        let generation = generation_for_ranking(&ranking_index, &ranking.ranking_id);
        let experiment_store = FileExperimentStore::open(experiment_results_dir)?;
        let verification_store = FileVerificationStore::open(verification_results_dir)?;
        let mut pool = existing
            .as_ref()
            .map(|state| {
                state
                    .members
                    .iter()
                    .cloned()
                    .map(|candidate| (candidate.strategy_id.clone(), candidate))
            })
            .into_iter()
            .flatten()
            .collect::<HashMap<_, _>>();

        for candidate in ranking
            .ranked_candidates
            .iter()
            .filter(|candidate| candidate.ready_for_review)
        {
            let validation = drafting
                .load_validation_bundle(&candidate.validation_bundle_id)?
                .ok_or_else(|| EvolutionMutationError::InvalidMutationSpecRequest {
                    reason: format!(
                        "validation bundle `{}` was not found while refreshing the evolution population",
                        candidate.validation_bundle_id
                    ),
                })?;
            let experiment = experiment_store
                .load(&validation.report.experiment_report_id)?
                .ok_or_else(|| EvolutionMutationError::InvalidMutationSpecRequest {
                    reason: format!(
                        "experiment report `{}` was not found while refreshing the evolution population",
                        validation.report.experiment_report_id
                    ),
                })?;
            let verification = verification_store
                .load(&validation.report.verification_id)?
                .ok_or_else(|| EvolutionMutationError::InvalidMutationSpecRequest {
                    reason: format!(
                        "verification report `{}` was not found while refreshing the evolution population",
                        validation.report.verification_id
                    ),
                })?;
            let objectives = population_objectives(&experiment.report, &verification.report)?;
            let baseline_fitness = population_fitness(&objectives, fitness_weights);
            let measured_evasion_pressure = evasion_pressure
                .map(|input| {
                    evaluate_population_evasion_pressure(
                        Path::new(&validation.report.experiment_path),
                        input,
                    )
                })
                .transpose()?
                .flatten();
            let autonomous_fitness = autonomous_lineage_by_variant
                .get(&candidate.variant_id)
                .map(|lineage| {
                    measure_autonomous_fitness(
                        Path::new(&validation.report.experiment_path),
                        lineage,
                        &objectives,
                        &experiment.report,
                        &verification.report,
                        fitness_weights,
                        evasion_pressure,
                    )
                })
                .transpose()?
                .flatten();
            let fitness = autonomous_fitness
                .as_ref()
                .map(|measurement| measurement.measured_fitness)
                .or_else(|| {
                    measured_evasion_pressure.as_ref().map(|summary| {
                        baseline_fitness * (1.0 - EVASION_PRESSURE_BLEND_WEIGHT)
                            + summary.pressure_score * EVASION_PRESSURE_BLEND_WEIGHT
                    })
                })
                .unwrap_or(baseline_fitness);
            let proposed_at_ms = pool
                .get(&candidate.strategy_id)
                .and_then(|existing| existing.proposed_at_ms);
            pool.insert(
                candidate.strategy_id.clone(),
                EvolutionPopulationCandidate {
                    generation,
                    generation_created_at_ms: ranking.created_at_ms,
                    population_rank: 0,
                    pareto_front: 0,
                    ranking_id: ranking.ranking_id.clone(),
                    validation_batch_id: ranking.validation_batch_id.clone(),
                    variant_id: candidate.variant_id.clone(),
                    strategy_id: candidate.strategy_id.clone(),
                    materialization_id: candidate.materialization_id.clone(),
                    validation_bundle_id: candidate.validation_bundle_id.clone(),
                    experiment_id: validation.report.experiment_id.clone(),
                    verification_id: validation.report.verification_id.clone(),
                    ready_for_review: candidate.ready_for_review,
                    status: candidate.status,
                    proof_status: candidate.proof_status,
                    queue_review_state: candidate.queue_review_state,
                    advisory_recommendation: candidate.advisory_recommendation,
                    blocking_reason_names: candidate.blocking_reason_names.clone(),
                    ranking_score: candidate.score,
                    baseline_fitness: Some(baseline_fitness),
                    fitness,
                    evasion_pressure: measured_evasion_pressure,
                    autonomous_fitness,
                    proposed_at_ms,
                    objectives,
                    summary: candidate.summary.clone(),
                },
            );
        }

        let created_at_ms = now_ms();
        let members = select_population_survivors(
            pool.into_values().collect(),
            population_size,
            pareto_tournament_size,
        );
        let mut state = EvolutionPopulationState {
            updated_at_ms: created_at_ms,
            ranking_id: ranking.ranking_id.clone(),
            validation_batch_id: ranking.validation_batch_id.clone(),
            population_size,
            pareto_tournament_size,
            proposal_timestamps_ms: existing
                .map(|state| state.proposal_timestamps_ms)
                .unwrap_or_default(),
            members,
        };
        trim_population_proposal_history(&mut state, created_at_ms);
        store.persist(&state)?;
        Ok(state)
    }

    pub fn evaluate_adversarial_pressure(
        &self,
        population_results_dir: impl AsRef<Path>,
        request: EvolutionAdversarialPressureRequest,
    ) -> Result<EvolutionAdversarialPressureResult, EvolutionMutationError> {
        if request.adversarial_corpus_events.is_empty() {
            return Err(EvolutionMutationError::InvalidMutationSpecRequest {
                reason: "adversarial pressure requires at least one corpus event".to_string(),
            });
        }

        let manifest = load_detector_experiment_manifest(&request.experiment_path)?;
        let detector = build_detector_from_candidate(&manifest.candidate)?;
        let genome_hash = candidate_genome_hash(&manifest.candidate)?;
        let coverage = threat_class_coverage(&detector, &request.adversarial_corpus_events);
        let event_detection_rate = overall_event_detection_rate(&coverage);
        let threat_class_detection_rate = overall_threat_class_detection_rate(&coverage);
        let pressure_score =
            adversarial_pressure_score(event_detection_rate, threat_class_detection_rate);
        let final_fitness = request.deception_adjusted_fitness
            * (1.0 - ADVERSARIAL_PRESSURE_BLEND_WEIGHT)
            + pressure_score * ADVERSARIAL_PRESSURE_BLEND_WEIGHT;
        let report = EvolutionEpisodeReport {
            episode_id: evolution_episode_id(
                &request.ranking_id,
                &request.strategy_id,
                &request.adversarial_corpus_sequence_id,
            ),
            created_at_ms: request.evaluated_at_ms,
            generation: request.generation,
            ranking_id: request.ranking_id,
            validation_batch_id: request.validation_batch_id,
            strategy_id: request.strategy_id,
            experiment_id: request.experiment_id,
            materialization_id: request.materialization_id,
            validation_bundle_id: request.validation_bundle_id,
            adversarial_corpus_sequence_id: request.adversarial_corpus_sequence_id,
            adversarial_corpus_suite_name: request.adversarial_corpus_suite_name,
            adversarial_corpus_version: request.adversarial_corpus_version,
            blue_genome_hash: genome_hash,
            threat_class_coverage: coverage,
            autonomous_fitness: request.autonomous_fitness,
            blue_fitness: EvolutionEpisodeBlueFitnessVector {
                replay_fitness: request.replay_fitness,
                evasion_adjusted_fitness: request.evasion_adjusted_fitness,
                memory_adjusted_fitness: request.memory_adjusted_fitness,
                deception_adjusted_fitness: request.deception_adjusted_fitness,
                deception_signal_score: request.deception_signal_score,
                evasion_pressure_score: request.evasion_pressure_score,
                evasion_gap_closure_rate: request.evasion_gap_closure_rate,
                evasion_focus_gap_count: request.evasion_focus_gap_count,
                adversarial_pressure_score: pressure_score,
                adversarial_detection_rate: event_detection_rate,
                final_fitness,
            },
            red_fitness: EvolutionEpisodeRedFitnessVector {
                event_detection_rate,
                event_evasion_rate: 1.0 - event_detection_rate,
                threat_class_detection_rate,
                threat_class_evasion_rate: 1.0 - threat_class_detection_rate,
            },
        };
        let episode_store =
            FileEvolutionEpisodeStore::open(population_results_dir.as_ref().join("episodes"))?;
        episode_store.persist(&report)?;
        Ok(EvolutionAdversarialPressureResult {
            episode: report,
            pressure_score,
            final_fitness,
        })
    }

    pub fn select_population_candidate(
        &self,
        population_results_dir: impl AsRef<Path>,
        max_proposals_per_hour: usize,
        now_ms: i64,
    ) -> Result<Option<EvolutionPopulationCandidate>, EvolutionMutationError> {
        let store = FileEvolutionPopulationStore::open(population_results_dir)?;
        let Some(mut state) = store.load()? else {
            return Ok(None);
        };
        let history_len_before = state.proposal_timestamps_ms.len();
        trim_population_proposal_history(&mut state, now_ms);
        if state.proposal_timestamps_ms.len() != history_len_before {
            store.persist(&state)?;
        }
        if state.proposal_timestamps_ms.len() >= max_proposals_per_hour {
            return Ok(None);
        }
        Ok(state
            .members
            .iter()
            .find(|candidate| {
                candidate.ready_for_review
                    && candidate.proposed_at_ms.is_none()
                    && candidate.queue_review_state.is_none()
            })
            .cloned())
    }

    pub fn mark_population_candidate_proposed(
        &self,
        population_results_dir: impl AsRef<Path>,
        strategy_id: &str,
        now_ms: i64,
    ) -> Result<Option<EvolutionPopulationState>, EvolutionMutationError> {
        let store = FileEvolutionPopulationStore::open(population_results_dir)?;
        let Some(mut state) = store.load()? else {
            return Ok(None);
        };
        trim_population_proposal_history(&mut state, now_ms);
        let mut changed = false;
        if let Some(candidate) = state
            .members
            .iter_mut()
            .find(|candidate| candidate.strategy_id == strategy_id)
            && candidate.proposed_at_ms.is_none()
        {
            candidate.proposed_at_ms = Some(now_ms);
            state.proposal_timestamps_ms.push(now_ms);
            state.updated_at_ms = now_ms;
            changed = true;
        }
        if changed {
            store.persist(&state)?;
        }
        Ok(Some(state))
    }

    pub fn record_population_candidate_review_outcome(
        &self,
        population_results_dir: impl AsRef<Path>,
        strategy_id: &str,
        review_state: EvolutionProposalReviewState,
        summary: &str,
        blocking_reason_names: &[String],
        now_ms: i64,
    ) -> Result<Option<EvolutionPopulationState>, EvolutionMutationError> {
        let store = FileEvolutionPopulationStore::open(population_results_dir)?;
        let Some(mut state) = store.load()? else {
            return Ok(None);
        };
        let mut changed = false;
        if let Some(candidate) = state
            .members
            .iter_mut()
            .find(|candidate| candidate.strategy_id == strategy_id)
        {
            candidate.queue_review_state = Some(review_state);
            candidate.ready_for_review = false;
            candidate.summary = summary.to_string();
            if candidate.proposed_at_ms.is_none() {
                candidate.proposed_at_ms = Some(now_ms);
            }
            for reason in blocking_reason_names {
                if !candidate
                    .blocking_reason_names
                    .iter()
                    .any(|existing| existing == reason)
                {
                    candidate.blocking_reason_names.push(reason.clone());
                }
            }
            state.updated_at_ms = now_ms;
            changed = true;
        }
        if changed {
            store.persist(&state)?;
        }
        Ok(Some(state))
    }
}
