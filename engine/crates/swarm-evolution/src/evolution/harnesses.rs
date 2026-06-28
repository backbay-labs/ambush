use super::*;

/// Harness that builds and manages the verified evolution proposal queue.
pub struct DefaultEvolutionQueueHarness {
    pub config_path: PathBuf,
    pub config: SwarmConfig,
    pub store: FileEvolutionProposalStore,
}

impl DefaultEvolutionQueueHarness {
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
            store: FileEvolutionProposalStore::open(results_dir)?,
        })
    }

    pub async fn create_proposal(
        &self,
        replay_harness: &DefaultReplayHarness,
        scorecard_harness: &DefaultStrategyScorecardHarness,
        request: EvolutionProposalCreateRequest,
    ) -> Result<EvolutionProposalLookup, EvolutionQueueError> {
        let experiment_path = request.experiment_path.as_path();
        let manifest = load_detector_experiment_manifest(experiment_path)?;
        let experiment_id = experiment_id_for_manifest(&manifest);
        let created_at_ms = now_ms();
        let proposal_id = proposal_id(
            &manifest.name,
            manifest.candidate.strategy_id(),
            created_at_ms,
        );
        let mut blocking_reasons = Vec::new();

        let verification =
            load_verification_lookup(&request.verification_results_dir, &request.verification_id)?;
        let verification_valid = match verification.as_ref() {
            Some(lookup) if lookup.report.experiment_id != experiment_id => {
                blocking_reasons.push(EvolutionProposalBlockingReason {
                    source: "verification".to_string(),
                    name: "experiment_mismatch".to_string(),
                    details: format!(
                        "verification `{}` belongs to `{}` instead of `{}`",
                        request.verification_id, lookup.report.experiment_id, experiment_id
                    ),
                    references: vec![lookup.report.verification_id.clone()],
                });
                false
            }
            Some(lookup) if !lookup.report.passed => {
                blocking_reasons.push(EvolutionProposalBlockingReason {
                    source: "verification".to_string(),
                    name: "verification_failed".to_string(),
                    details: "verification invariants did not all pass".to_string(),
                    references: vec![lookup.report.verification_id.clone()],
                });
                false
            }
            Some(_) => true,
            None => {
                blocking_reasons.push(EvolutionProposalBlockingReason {
                    source: "verification".to_string(),
                    name: "missing_verification".to_string(),
                    details: format!(
                        "verification artifact `{}` could not be loaded",
                        request.verification_id
                    ),
                    references: vec![request.verification_id.clone()],
                });
                false
            }
        };

        let proof_store = FileEvolutionProofStore::open(&request.proof_results_dir)?;
        let proof = proof_store.load(&request.proof_id)?;
        let proof_status = assess_proof_status(
            &manifest,
            verification.as_ref().map(|lookup| &lookup.report),
            proof.as_ref().map(|lookup| &lookup.report),
            &mut blocking_reasons,
            &request.proof_id,
        )?;
        let mut assurance = evaluate_proposal_assurance(
            &self.config_path,
            &self.config,
            &manifest,
            proof.as_ref().map(|lookup| &lookup.report),
            &mut blocking_reasons,
        );
        assurance.harvested_case_ids = persist_harvested_assurance_cases(
            &self.config_path,
            &self.config,
            &proposal_id,
            created_at_ms,
            &manifest,
            verification.as_ref(),
            proof.as_ref().map(|lookup| &lookup.report),
            &assurance,
        )?;

        let advisory = if verification_valid {
            match scorecard_harness
                .create_scorecard(
                    replay_harness,
                    experiment_path,
                    &request.experiment_results_dir,
                    &request.verification_results_dir,
                    &request.verification_id,
                )
                .await
            {
                Ok(lookup) => Some(EvolutionProposalAdvisorySummary::from_scorecard(
                    &lookup.report,
                )),
                Err(error) => {
                    blocking_reasons.push(EvolutionProposalBlockingReason {
                        source: "advisory".to_string(),
                        name: "scorecard_generation_failed".to_string(),
                        details: error.to_string(),
                        references: vec![request.verification_id.clone()],
                    });
                    None
                }
            }
        } else {
            None
        };

        let review_state = if blocking_reasons.is_empty() {
            EvolutionProposalReviewState::PendingReview
        } else {
            EvolutionProposalReviewState::Blocked
        };
        let report = EvolutionProposalReport {
            proposal_id,
            experiment_id,
            experiment_name: manifest.name.clone(),
            experiment_path: experiment_path.display().to_string(),
            created_at_ms,
            strategy_id: manifest.candidate.strategy_id().to_string(),
            strategy_description: manifest.candidate.description().to_string(),
            lineage: manifest.lineage.clone(),
            verification_id: verification
                .as_ref()
                .map(|lookup| lookup.report.verification_id.clone()),
            verification_passed: verification_valid,
            proof_status,
            proof: proof.map(|lookup| EvolutionProposalProofSummary {
                proof_id: lookup.report.proof_id,
                proof_system: lookup.report.proof_system,
                attestation_sha256: lookup.report.attestation_sha256,
                invariant_count: lookup.report.invariants.len(),
            }),
            advisory,
            assurance: Some(assurance),
            review_state,
            blocking_reasons,
            decision_history: Vec::new(),
        };
        let record = self.store.persist(&report)?;
        Ok(EvolutionProposalLookup { record, report })
    }

    pub fn load_proposal(
        &self,
        proposal_id: &str,
    ) -> Result<Option<EvolutionProposalLookup>, EvolutionQueueError> {
        Ok(self.store.load(proposal_id)?)
    }

    pub fn list_proposals(
        &self,
        strategy_id: Option<&str>,
        review_state: Option<EvolutionProposalReviewState>,
    ) -> Result<EvolutionProposalList, EvolutionQueueError> {
        Ok(self.store.list(strategy_id, review_state)?)
    }

    pub fn record_decision(
        &self,
        proposal_id: &str,
        action: EvolutionProposalDecisionAction,
        reason: &str,
    ) -> Result<EvolutionProposalLookup, EvolutionQueueError> {
        if action == EvolutionProposalDecisionAction::ApplyAssuranceWaiver {
            return Err(EvolutionQueueError::InvalidDecision {
                proposal_id: proposal_id.to_string(),
                state: "n/a".to_string(),
                decision: decision_action_label(action).to_string(),
                reason: "use apply_assurance_waiver to attach a signed bounded waiver".to_string(),
            });
        }
        let mut lookup =
            self.store
                .load(proposal_id)?
                .ok_or_else(|| EvolutionQueueError::ProposalNotFound {
                    proposal_id: proposal_id.to_string(),
                })?;
        let current_time_ms = now_ms();

        let new_state = match (lookup.report.review_state, action) {
            (
                EvolutionProposalReviewState::PendingReview,
                EvolutionProposalDecisionAction::ApplyAssuranceWaiver,
            )
            | (
                EvolutionProposalReviewState::Deferred,
                EvolutionProposalDecisionAction::ApplyAssuranceWaiver,
            )
            | (
                EvolutionProposalReviewState::Blocked,
                EvolutionProposalDecisionAction::ApplyAssuranceWaiver,
            )
            | (
                EvolutionProposalReviewState::AcceptedForCanary,
                EvolutionProposalDecisionAction::ApplyAssuranceWaiver,
            )
            | (
                EvolutionProposalReviewState::Rejected,
                EvolutionProposalDecisionAction::ApplyAssuranceWaiver,
            ) => unreachable!("waiver decisions are handled before state transition matching"),
            (
                EvolutionProposalReviewState::PendingReview,
                EvolutionProposalDecisionAction::AcceptForCanary,
            )
            | (
                EvolutionProposalReviewState::Deferred,
                EvolutionProposalDecisionAction::AcceptForCanary,
            )
            | (
                EvolutionProposalReviewState::Blocked,
                EvolutionProposalDecisionAction::AcceptForCanary,
            ) => {
                if lookup.report.proof_status != EvolutionProposalProofStatus::Proved
                    || proposal_has_active_blocking_reasons(
                        &lookup.report,
                        &self.config,
                        current_time_ms,
                    )
                {
                    return Err(EvolutionQueueError::InvalidDecision {
                        proposal_id: proposal_id.to_string(),
                        state: review_state_label(lookup.report.review_state).to_string(),
                        decision: decision_action_label(action).to_string(),
                        reason:
                            "only proof-backed proposals with satisfied or actively waived assurance and no active blocking reasons can be accepted for canary"
                                .to_string(),
                    });
                }
                EvolutionProposalReviewState::AcceptedForCanary
            }
            (
                EvolutionProposalReviewState::PendingReview,
                EvolutionProposalDecisionAction::Defer,
            )
            | (EvolutionProposalReviewState::Deferred, EvolutionProposalDecisionAction::Defer) => {
                EvolutionProposalReviewState::Deferred
            }
            (
                EvolutionProposalReviewState::PendingReview,
                EvolutionProposalDecisionAction::Reject,
            )
            | (EvolutionProposalReviewState::Deferred, EvolutionProposalDecisionAction::Reject)
            | (EvolutionProposalReviewState::Blocked, EvolutionProposalDecisionAction::Reject) => {
                EvolutionProposalReviewState::Rejected
            }
            (EvolutionProposalReviewState::Blocked, _) => {
                return Err(EvolutionQueueError::InvalidDecision {
                    proposal_id: proposal_id.to_string(),
                    state: review_state_label(lookup.report.review_state).to_string(),
                    decision: decision_action_label(action).to_string(),
                    reason:
                        "blocked proposals may only be explicitly rejected unless an active assurance waiver clears rollout blockers"
                            .to_string(),
                });
            }
            (EvolutionProposalReviewState::AcceptedForCanary, _)
            | (EvolutionProposalReviewState::Rejected, _) => {
                return Err(EvolutionQueueError::InvalidDecision {
                    proposal_id: proposal_id.to_string(),
                    state: review_state_label(lookup.report.review_state).to_string(),
                    decision: decision_action_label(action).to_string(),
                    reason: "the proposal is already in a terminal review state".to_string(),
                });
            }
        };

        lookup.report.review_state = new_state;
        lookup
            .report
            .decision_history
            .push(EvolutionProposalDecisionRecord {
                decided_at_ms: now_ms(),
                action,
                reason: reason.to_string(),
            });
        let record = self.store.persist(&lookup.report)?;
        Ok(EvolutionProposalLookup {
            record,
            report: lookup.report,
        })
    }

    pub fn apply_assurance_waiver(
        &self,
        proposal_id: &str,
        request: EvolutionAssuranceWaiverRequest,
    ) -> Result<EvolutionProposalLookup, EvolutionQueueError> {
        let mut lookup =
            self.store
                .load(proposal_id)?
                .ok_or_else(|| EvolutionQueueError::ProposalNotFound {
                    proposal_id: proposal_id.to_string(),
                })?;
        let assurance = lookup.report.assurance.as_mut().ok_or_else(|| {
            EvolutionQueueError::InvalidAssuranceWaiver {
                proposal_id: proposal_id.to_string(),
                reason: "proposal does not carry assurance lineage".to_string(),
            }
        })?;
        if assurance.decision != EvolutionProposalAssuranceDecision::Blocked {
            return Err(EvolutionQueueError::InvalidAssuranceWaiver {
                proposal_id: proposal_id.to_string(),
                reason: "only blocked assurance decisions can be waived".to_string(),
            });
        }
        if request.reason.trim().is_empty() {
            return Err(EvolutionQueueError::InvalidAssuranceWaiver {
                proposal_id: proposal_id.to_string(),
                reason: "waiver reason must not be empty".to_string(),
            });
        }
        if request.ttl_secs == 0 {
            return Err(EvolutionQueueError::InvalidAssuranceWaiver {
                proposal_id: proposal_id.to_string(),
                reason: "waiver ttl must be greater than zero".to_string(),
            });
        }
        if request.ttl_secs > self.config.evolution.assurance.waiver.max_ttl_secs {
            return Err(EvolutionQueueError::InvalidAssuranceWaiver {
                proposal_id: proposal_id.to_string(),
                reason: format!(
                    "waiver ttl {} exceeds configured maximum {}",
                    request.ttl_secs, self.config.evolution.assurance.waiver.max_ttl_secs
                ),
            });
        }
        if assurance.coverage.actionable_gap_count
            > self
                .config
                .evolution
                .assurance
                .waiver
                .max_actionable_gap_count
        {
            return Err(EvolutionQueueError::InvalidAssuranceWaiver {
                proposal_id: proposal_id.to_string(),
                reason: format!(
                    "assurance gap count {} exceeds configured waiver limit {}",
                    assurance.coverage.actionable_gap_count,
                    self.config
                        .evolution
                        .assurance
                        .waiver
                        .max_actionable_gap_count
                ),
            });
        }

        let signer = Ed25519Signer::from_secret_material(&request.secret_material);
        let expected_operator_id =
            AgentId::from_public_key_hex(signer.public_key_hex()).to_string();
        if request.operator_id != expected_operator_id {
            return Err(EvolutionQueueError::InvalidAssuranceWaiver {
                proposal_id: proposal_id.to_string(),
                reason: format!(
                    "waiver operator `{}` does not match signer identity `{}`",
                    request.operator_id, expected_operator_id
                ),
            });
        }
        if !self
            .config
            .evolution
            .assurance
            .waiver
            .allowed_operator_ids
            .iter()
            .any(|candidate| candidate == &request.operator_id)
        {
            return Err(EvolutionQueueError::InvalidAssuranceWaiver {
                proposal_id: proposal_id.to_string(),
                reason: format!(
                    "operator `{}` is not allowed to issue assurance waivers",
                    request.operator_id
                ),
            });
        }

        let waiver = build_assurance_waiver_summary(
            proposal_id,
            assurance,
            &request.operator_id,
            &signer,
            now_ms(),
            request.ttl_secs,
            &request.reason,
        )
        .map_err(|reason| EvolutionQueueError::InvalidAssuranceWaiver {
            proposal_id: proposal_id.to_string(),
            reason,
        })?;
        assurance.waiver = Some(waiver.clone());
        lookup
            .report
            .decision_history
            .push(EvolutionProposalDecisionRecord {
                decided_at_ms: now_ms(),
                action: EvolutionProposalDecisionAction::ApplyAssuranceWaiver,
                reason: format!(
                    "{} | operator={} | waiver_id={} | expires_at={}",
                    request.reason.trim(),
                    waiver.operator_id,
                    waiver.waiver_id,
                    waiver.expires_at_ms
                ),
            });

        let record = self.store.persist(&lookup.report)?;
        Ok(EvolutionProposalLookup {
            record,
            report: lookup.report,
        })
    }
}

/// Harness that bridges accepted proposals into durable canary-launch handoff packets.
pub struct DefaultEvolutionHandoffHarness {
    pub config_path: PathBuf,
    pub config: SwarmConfig,
    pub store: FileEvolutionHandoffStore,
}

impl DefaultEvolutionHandoffHarness {
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
            store: FileEvolutionHandoffStore::open(results_dir)?,
        })
    }

    pub fn create_handoff(
        &self,
        queue_results_dir: impl AsRef<Path>,
        proposal_id: &str,
        shadow_results_dir: impl AsRef<Path>,
        shadow_id: &str,
    ) -> Result<EvolutionHandoffLookup, EvolutionQueueError> {
        let proposal_store = FileEvolutionProposalStore::open(queue_results_dir)?;
        let proposal = proposal_store.load(proposal_id)?.ok_or_else(|| {
            EvolutionQueueError::ProposalNotFound {
                proposal_id: proposal_id.to_string(),
            }
        })?;
        let current_time_ms = now_ms();

        let mut blocking_reasons = Vec::new();
        if proposal.report.review_state != EvolutionProposalReviewState::AcceptedForCanary {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "proposal".to_string(),
                name: "proposal_not_accepted_for_canary".to_string(),
                details: format!(
                    "proposal `{}` is in state `{}` instead of `accepted_for_canary`",
                    proposal.report.proposal_id,
                    review_state_label(proposal.report.review_state)
                ),
                references: vec![proposal.report.proposal_id.clone()],
            });
        }
        if proposal.report.proof_status != EvolutionProposalProofStatus::Proved {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "proposal".to_string(),
                name: "proposal_not_proved".to_string(),
                details: "proposal proof status is not `proved`".to_string(),
                references: vec![proposal.report.proposal_id.clone()],
            });
        }
        if proposal_has_active_blocking_reasons(&proposal.report, &self.config, current_time_ms) {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "proposal".to_string(),
                name: "proposal_already_blocked".to_string(),
                details: "proposal still carries blocking reasons and cannot enter handoff"
                    .to_string(),
                references: vec![proposal.report.proposal_id.clone()],
            });
        }
        if !proposal.report.verification_passed {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "proposal".to_string(),
                name: "verification_not_passed".to_string(),
                details: "proposal does not reference a passed verification result".to_string(),
                references: vec![proposal.report.proposal_id.clone()],
            });
        }
        if proposal.report.experiment_path.trim().is_empty() {
            blocking_reasons.push(EvolutionProposalBlockingReason {
                source: "proposal".to_string(),
                name: "missing_experiment_path".to_string(),
                details: "proposal does not preserve an experiment manifest path for canary entry"
                    .to_string(),
                references: vec![proposal.report.proposal_id.clone()],
            });
        }
        if assurance_rollout_state(
            proposal.report.assurance.as_ref(),
            &self.config,
            current_time_ms,
        ) == EvolutionAssuranceRolloutState::Blocked
        {
            blocking_reasons.push(proposal_assurance_blocking_reason(
                &proposal.report,
                &self.config,
                current_time_ms,
            ));
        }

        let shadow = load_shadow_lookup(shadow_results_dir, shadow_id)?;
        match shadow.as_ref() {
            Some(lookup) if lookup.report.experiment_id != proposal.report.experiment_id => {
                blocking_reasons.push(EvolutionProposalBlockingReason {
                    source: "shadow".to_string(),
                    name: "experiment_mismatch".to_string(),
                    details: format!(
                        "shadow `{}` belongs to `{}` instead of `{}`",
                        lookup.report.shadow_id,
                        lookup.report.experiment_id,
                        proposal.report.experiment_id
                    ),
                    references: vec![lookup.report.shadow_id.clone()],
                });
            }
            Some(lookup) if lookup.report.candidate_strategy_id != proposal.report.strategy_id => {
                blocking_reasons.push(EvolutionProposalBlockingReason {
                    source: "shadow".to_string(),
                    name: "strategy_mismatch".to_string(),
                    details: format!(
                        "shadow `{}` targets strategy `{}` instead of `{}`",
                        lookup.report.shadow_id,
                        lookup.report.candidate_strategy_id,
                        proposal.report.strategy_id
                    ),
                    references: vec![lookup.report.shadow_id.clone()],
                });
            }
            Some(lookup) if !lookup.report.passed => {
                blocking_reasons.push(EvolutionProposalBlockingReason {
                    source: "shadow".to_string(),
                    name: "shadow_failed".to_string(),
                    details: "shadow artifact did not pass its offline gates".to_string(),
                    references: vec![lookup.report.shadow_id.clone()],
                });
            }
            Some(_) => {}
            None => {
                blocking_reasons.push(EvolutionProposalBlockingReason {
                    source: "shadow".to_string(),
                    name: "missing_shadow".to_string(),
                    details: format!("shadow artifact `{shadow_id}` could not be loaded"),
                    references: vec![shadow_id.to_string()],
                });
            }
        }

        let created_at_ms = now_ms();
        let shadow = shadow.map(|lookup| lookup.report);
        let launch_status = if blocking_reasons.is_empty() {
            EvolutionHandoffStatus::PendingLaunch
        } else {
            EvolutionHandoffStatus::Blocked
        };
        let report = EvolutionHandoffReport {
            handoff_id: handoff_id(
                &proposal.report.proposal_id,
                &proposal.report.strategy_id,
                created_at_ms,
            ),
            proposal_id: proposal.report.proposal_id.clone(),
            experiment_id: proposal.report.experiment_id.clone(),
            experiment_name: proposal.report.experiment_name.clone(),
            experiment_path: proposal.report.experiment_path.clone(),
            created_at_ms,
            launched_at_ms: None,
            strategy_id: proposal.report.strategy_id.clone(),
            strategy_description: proposal.report.strategy_description.clone(),
            lineage: proposal.report.lineage.clone(),
            verification_id: proposal.report.verification_id.clone().unwrap_or_default(),
            proof: proposal
                .report
                .proof
                .clone()
                .unwrap_or(EvolutionProposalProofSummary {
                    proof_id: String::new(),
                    proof_system: String::new(),
                    attestation_sha256: String::new(),
                    invariant_count: 0,
                }),
            advisory: proposal.report.advisory.clone(),
            assurance: proposal.report.assurance.clone(),
            shadow_id: shadow
                .as_ref()
                .map(|report| report.shadow_id.clone())
                .unwrap_or_else(|| shadow_id.to_string()),
            shadow_passed: shadow.as_ref().map(|report| report.passed).unwrap_or(false),
            suite_name: shadow
                .as_ref()
                .map(|report| report.suite_name.clone())
                .unwrap_or_default(),
            corpus_version: shadow
                .as_ref()
                .map(|report| report.corpus_version.clone())
                .unwrap_or_default(),
            launch_status,
            blocking_reasons,
            canary_run_id: None,
        };
        let record = self.store.persist(&report)?;
        Ok(EvolutionHandoffLookup { record, report })
    }

    pub fn load_handoff(
        &self,
        handoff_id: &str,
    ) -> Result<Option<EvolutionHandoffLookup>, EvolutionQueueError> {
        Ok(self.store.load(handoff_id)?)
    }

    pub fn launch_canary(
        &self,
        canary_harness: &DefaultCanaryHarness,
        verification_results_dir: impl AsRef<Path>,
        shadow_results_dir: impl AsRef<Path>,
        handoff_id: &str,
    ) -> Result<EvolutionHandoffLookup, EvolutionQueueError> {
        let mut lookup =
            self.store
                .load(handoff_id)?
                .ok_or_else(|| EvolutionQueueError::HandoffNotFound {
                    handoff_id: handoff_id.to_string(),
                })?;

        if lookup.report.launch_status != EvolutionHandoffStatus::PendingLaunch {
            return Err(EvolutionQueueError::InvalidHandoffLaunch {
                handoff_id: handoff_id.to_string(),
                state: handoff_status_label(lookup.report.launch_status).to_string(),
                reason: "handoff is not in a launchable pending state".to_string(),
            });
        }
        if !lookup.report.blocking_reasons.is_empty() {
            return Err(EvolutionQueueError::InvalidHandoffLaunch {
                handoff_id: handoff_id.to_string(),
                state: handoff_status_label(lookup.report.launch_status).to_string(),
                reason: "handoff still carries blocking reasons".to_string(),
            });
        }
        if lookup.report.canary_run_id.is_some() {
            return Err(EvolutionQueueError::InvalidHandoffLaunch {
                handoff_id: handoff_id.to_string(),
                state: handoff_status_label(lookup.report.launch_status).to_string(),
                reason: "handoff already references a canary run".to_string(),
            });
        }
        if assurance_rollout_state(lookup.report.assurance.as_ref(), &self.config, now_ms())
            == EvolutionAssuranceRolloutState::Blocked
        {
            return Err(EvolutionQueueError::InvalidHandoffLaunch {
                handoff_id: handoff_id.to_string(),
                state: handoff_status_label(lookup.report.launch_status).to_string(),
                reason: assurance_gate_block_reason(
                    lookup.report.assurance.as_ref(),
                    &self.config,
                    now_ms(),
                    "rollout progression",
                )
                .unwrap_or_else(|| "handoff assurance lineage is missing or blocked".to_string()),
            });
        }

        let canary = canary_harness.start_run_with_assurance(
            PathBuf::from(&lookup.report.experiment_path),
            verification_results_dir,
            &lookup.report.verification_id,
            shadow_results_dir,
            &lookup.report.shadow_id,
            lookup.report.assurance.clone(),
        )?;
        lookup.report.launched_at_ms = Some(now_ms());
        lookup.report.launch_status = EvolutionHandoffStatus::CanaryLaunched;
        lookup.report.canary_run_id = Some(canary.report.run_id.clone());
        let record = self.store.persist(&lookup.report)?;
        Ok(EvolutionHandoffLookup {
            record,
            report: lookup.report,
        })
    }
}
