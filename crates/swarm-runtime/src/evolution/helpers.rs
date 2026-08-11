use super::*;

pub(crate) fn resolve_config_relative_path(config_path: &Path, referenced: &str) -> PathBuf {
    let candidate = PathBuf::from(referenced);
    if candidate.is_absolute() {
        candidate
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(candidate)
    }
}

pub(crate) fn resolve_relative_path_local(manifest_path: &Path, referenced: &str) -> PathBuf {
    let candidate = PathBuf::from(referenced);
    if candidate.is_absolute() {
        candidate
    } else {
        manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(candidate)
    }
}

pub(crate) fn normalize_existing_path(path: PathBuf) -> PathBuf {
    fs::canonicalize(&path).unwrap_or(path)
}

pub(crate) fn load_verification_lookup(
    verification_results_dir: impl AsRef<Path>,
    verification_id: &str,
) -> Result<Option<DetectorVerificationLookup>, EvolutionQueueError> {
    let store = FileVerificationStore::open(verification_results_dir)?;
    Ok(store.load(verification_id)?)
}

pub(crate) fn load_shadow_lookup(
    shadow_results_dir: impl AsRef<Path>,
    shadow_id: &str,
) -> Result<Option<StrategyShadowLookup>, EvolutionQueueError> {
    let store = FileShadowStore::open(shadow_results_dir)?;
    Ok(store.load(shadow_id)?)
}

pub(crate) fn assess_proof_status(
    manifest: &crate::replay::DetectorExperimentManifest,
    verification: Option<&DetectorVerificationReport>,
    proof: Option<&EvolutionProofReport>,
    blocking_reasons: &mut Vec<EvolutionProposalBlockingReason>,
    requested_proof_id: &str,
) -> Result<EvolutionProposalProofStatus, EvolutionQueueError> {
    let Some(proof) = proof else {
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "proof".to_string(),
            name: "missing_proof".to_string(),
            details: format!(
                "proof artifact `{}` could not be loaded",
                requested_proof_id
            ),
            references: vec![requested_proof_id.to_string()],
        });
        return Ok(EvolutionProposalProofStatus::Missing);
    };

    let mut inconsistent = false;
    let expected_experiment_id = experiment_id_for_manifest(manifest);
    if proof.experiment_id != expected_experiment_id {
        inconsistent = true;
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "proof".to_string(),
            name: "experiment_mismatch".to_string(),
            details: format!(
                "proof `{}` belongs to `{}` instead of `{}`",
                proof.proof_id, proof.experiment_id, expected_experiment_id
            ),
            references: vec![proof.proof_id.clone()],
        });
    }
    if proof.strategy_id != manifest.candidate.strategy_id() {
        inconsistent = true;
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "proof".to_string(),
            name: "strategy_mismatch".to_string(),
            details: format!(
                "proof `{}` targets strategy `{}` instead of `{}`",
                proof.proof_id,
                proof.strategy_id,
                manifest.candidate.strategy_id()
            ),
            references: vec![proof.proof_id.clone()],
        });
    }
    if proof.experiment_manifest_sha256 != sha256_hex(manifest)? {
        inconsistent = true;
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "proof".to_string(),
            name: "experiment_digest_mismatch".to_string(),
            details: "proof digest does not match the current experiment manifest".to_string(),
            references: vec![proof.proof_id.clone()],
        });
    }
    if proof.lineage_sha256 != sha256_hex(&manifest.lineage)? {
        inconsistent = true;
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "proof".to_string(),
            name: "lineage_digest_mismatch".to_string(),
            details: "proof lineage digest does not match the current experiment lineage"
                .to_string(),
            references: vec![proof.proof_id.clone()],
        });
    }

    let Some(verification) = verification else {
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "proof".to_string(),
            name: "missing_verification_reference".to_string(),
            details: "proof could not be cross-checked because verification evidence is missing"
                .to_string(),
            references: vec![proof.proof_id.clone()],
        });
        return Ok(EvolutionProposalProofStatus::Inconsistent);
    };

    if proof.verification_id != verification.verification_id {
        inconsistent = true;
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "proof".to_string(),
            name: "verification_mismatch".to_string(),
            details: format!(
                "proof `{}` references verification `{}` instead of `{}`",
                proof.proof_id, proof.verification_id, verification.verification_id
            ),
            references: vec![proof.proof_id.clone(), verification.verification_id.clone()],
        });
    }
    if proof.verification_report_sha256 != sha256_hex(verification)? {
        inconsistent = true;
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "proof".to_string(),
            name: "verification_digest_mismatch".to_string(),
            details: "proof digest does not match the persisted verification report".to_string(),
            references: vec![proof.proof_id.clone(), verification.verification_id.clone()],
        });
    }
    let verification_invariants = verification
        .invariants
        .iter()
        .map(|invariant| invariant.name.as_str())
        .collect::<Vec<_>>();
    let proof_invariants = proof
        .invariants
        .iter()
        .map(|invariant| invariant.name.as_str())
        .collect::<Vec<_>>();
    if verification_invariants != proof_invariants {
        inconsistent = true;
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "proof".to_string(),
            name: "invariant_coverage_mismatch".to_string(),
            details: "proof invariants do not line up with the verification report".to_string(),
            references: vec![proof.proof_id.clone(), verification.verification_id.clone()],
        });
    }
    if proof.corpus_name != verification.corpus_name {
        inconsistent = true;
        blocking_reasons.push(EvolutionProposalBlockingReason {
            source: "proof".to_string(),
            name: "corpus_mismatch".to_string(),
            details: format!(
                "proof corpus `{}` does not match verification corpus `{}`",
                proof.corpus_name, verification.corpus_name
            ),
            references: vec![proof.proof_id.clone(), verification.verification_id.clone()],
        });
    }

    Ok(if inconsistent {
        EvolutionProposalProofStatus::Inconsistent
    } else {
        EvolutionProposalProofStatus::Proved
    })
}

pub(crate) fn experiment_id_for_manifest(
    manifest: &crate::replay::DetectorExperimentManifest,
) -> String {
    format!(
        "experiment:{}:{}",
        manifest.name,
        manifest.candidate.strategy_id()
    )
}

pub(crate) fn proof_id(experiment_name: &str, strategy_id: &str, created_at_ms: i64) -> String {
    format!(
        "evolution_proof:{}:{}:{}",
        experiment_name, strategy_id, created_at_ms
    )
}

pub(crate) fn proposal_id(experiment_name: &str, strategy_id: &str, created_at_ms: i64) -> String {
    format!(
        "evolution_proposal:{}:{}:{}",
        experiment_name, strategy_id, created_at_ms
    )
}

pub(crate) fn handoff_id(proposal_id: &str, strategy_id: &str, created_at_ms: i64) -> String {
    format!(
        "evolution_handoff:{}:{}:{}",
        proposal_id, strategy_id, created_at_ms
    )
}

pub(crate) fn review_state_label(state: EvolutionProposalReviewState) -> &'static str {
    match state {
        EvolutionProposalReviewState::PendingReview => "pending_review",
        EvolutionProposalReviewState::AcceptedForCanary => "accepted_for_canary",
        EvolutionProposalReviewState::Deferred => "deferred",
        EvolutionProposalReviewState::Rejected => "rejected",
        EvolutionProposalReviewState::Blocked => "blocked",
    }
}

pub(crate) fn proof_status_label(status: EvolutionProposalProofStatus) -> &'static str {
    match status {
        EvolutionProposalProofStatus::Proved => "proved",
        EvolutionProposalProofStatus::Missing => "missing",
        EvolutionProposalProofStatus::Inconsistent => "inconsistent",
    }
}

pub(crate) fn assurance_decision_label(
    decision: EvolutionProposalAssuranceDecision,
) -> &'static str {
    match decision {
        EvolutionProposalAssuranceDecision::Passed => "passed",
        EvolutionProposalAssuranceDecision::Blocked => "blocked",
    }
}

pub(crate) fn solver_proof_status_label(status: EvolutionSolverProofStatus) -> &'static str {
    match status {
        EvolutionSolverProofStatus::Proved => "proved",
        EvolutionSolverProofStatus::Counterexample => "counterexample",
        EvolutionSolverProofStatus::Timeout => "timeout",
        EvolutionSolverProofStatus::Disabled => "disabled",
        EvolutionSolverProofStatus::Error => "error",
    }
}

pub(crate) fn map_assurance_solver_status(
    status: EvolutionAssuranceSolverStatusConfig,
) -> EvolutionSolverProofStatus {
    match status {
        EvolutionAssuranceSolverStatusConfig::Proved => EvolutionSolverProofStatus::Proved,
        EvolutionAssuranceSolverStatusConfig::Counterexample => {
            EvolutionSolverProofStatus::Counterexample
        }
        EvolutionAssuranceSolverStatusConfig::Timeout => EvolutionSolverProofStatus::Timeout,
        EvolutionAssuranceSolverStatusConfig::Disabled => EvolutionSolverProofStatus::Disabled,
        EvolutionAssuranceSolverStatusConfig::Error => EvolutionSolverProofStatus::Error,
    }
}

pub(crate) fn decision_action_label(action: EvolutionProposalDecisionAction) -> &'static str {
    match action {
        EvolutionProposalDecisionAction::AcceptForCanary => "accept_for_canary",
        EvolutionProposalDecisionAction::ApplyAssuranceWaiver => "apply_assurance_waiver",
        EvolutionProposalDecisionAction::Defer => "defer",
        EvolutionProposalDecisionAction::Reject => "reject",
    }
}

pub(crate) fn advisory_recommendation_label(
    recommendation: StrategyAdvisoryRecommendation,
) -> &'static str {
    match recommendation {
        StrategyAdvisoryRecommendation::RetainBaseline => "retain_baseline",
        StrategyAdvisoryRecommendation::CandidatePreferred => "candidate_preferred",
        StrategyAdvisoryRecommendation::CandidateAlreadyStableInProduction => {
            "candidate_already_stable_in_production"
        }
    }
}

pub(crate) fn handoff_status_label(status: EvolutionHandoffStatus) -> &'static str {
    match status {
        EvolutionHandoffStatus::PendingLaunch => "pending_launch",
        EvolutionHandoffStatus::CanaryLaunched => "canary_launched",
        EvolutionHandoffStatus::Blocked => "blocked",
    }
}

pub(crate) fn sha256_hex<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let raw = serde_json::to_vec(value)?;
    let digest = Sha256::digest(raw);
    Ok(format!("{digest:x}"))
}

pub(crate) fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
