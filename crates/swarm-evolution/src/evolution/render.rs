use super::*;

pub fn render_evolution_proof(report: &EvolutionProofReport) -> String {
    let mut lines = vec![
        "Evolution Safety Proof".to_string(),
        format!("Proof ID: {}", report.proof_id),
        format!(
            "Experiment: {} ({})",
            report.experiment_name, report.experiment_id
        ),
        format!("Verification: {}", report.verification_id),
        format!(
            "Strategy: {} | {}",
            report.strategy_id, report.candidate_description
        ),
        format!("Proof system: {}", report.proof_system),
        format!(
            "Digests: experiment={} verification={} lineage={}",
            report.experiment_manifest_sha256,
            report.verification_report_sha256,
            report.lineage_sha256
        ),
        format!("Attestation: {}", report.attestation_sha256),
        format!(
            "Lineage: parent={} mutation={} rationale={}",
            report.lineage.parent_strategy_id, report.lineage.mutation, report.lineage.rationale
        ),
        format!("Corpus: {}", report.corpus_name),
        format!("Invariant count: {}", report.invariants.len()),
    ];
    if let Some(solver) = &report.solver_summary {
        lines.push(format!(
            "Solver: {} | invariants={} | timeouts={} | counterexamples={}",
            solver_proof_status_label(solver.status),
            solver.invariant_count,
            solver.timed_out_count,
            solver.counterexample_invariant_count
        ));
    }
    for invariant in &report.invariants {
        lines.push(format!("- {}: {}", invariant.name, invariant.details));
    }
    for artifact in &report.solver_artifacts {
        lines.push(format!(
            "  solver:{} | status={} | timeout_ms={} | counterexamples={}",
            artifact.invariant_name,
            solver_proof_status_label(artifact.status),
            artifact.timeout_ms,
            artifact.counterexamples.len()
        ));
    }
    lines.join("\n")
}

/// Render one evolution proposal artifact.
pub fn render_evolution_proposal(report: &EvolutionProposalReport) -> String {
    let mut lines = vec![
        "Evolution Proposal".to_string(),
        format!("Proposal ID: {}", report.proposal_id),
        format!(
            "Experiment: {} ({})",
            report.experiment_name, report.experiment_id
        ),
        format!(
            "Strategy: {} | {}",
            report.strategy_id, report.strategy_description
        ),
        format!(
            "Review state: {} | proof status={}",
            review_state_label(report.review_state),
            proof_status_label(report.proof_status)
        ),
    ];

    if let Some(verification_id) = &report.verification_id {
        lines.push(format!(
            "Verification: {} | passed={}",
            verification_id, report.verification_passed
        ));
    } else {
        lines.push("Verification: missing".to_string());
    }

    if let Some(proof) = &report.proof {
        lines.push(format!(
            "Proof: {} | system={} | invariants={}",
            proof.proof_id, proof.proof_system, proof.invariant_count
        ));
    } else {
        lines.push("Proof: none attached".to_string());
    }

    if let Some(advisory) = &report.advisory {
        lines.push(format!(
            "Advisory: scorecard={} recommendation={} delta={:.3}",
            advisory.scorecard_id,
            advisory_recommendation_label(advisory.recommendation),
            advisory.score_delta
        ));
        lines.push(format!(
            "Scores: baseline={:.3} candidate={:.3} candidate_matching_memories={}",
            advisory.baseline_final_score,
            advisory.candidate_final_score,
            advisory.candidate_matching_memory_count
        ));
        if let Some(latest) = &advisory.latest_rollout_state {
            lines.push(format!(
                "Latest rollout state: {:?} via {:?} {}",
                latest.outcome_kind, latest.source_kind, latest.source_artifact_id
            ));
        }
    } else {
        lines.push("Advisory: unavailable".to_string());
    }

    if let Some(assurance) = &report.assurance {
        lines.extend(render_assurance_summary_lines(assurance));
    } else {
        lines.push("Assurance: unavailable".to_string());
    }

    if report.blocking_reasons.is_empty() {
        lines.push("Blocking reasons: none".to_string());
    } else {
        lines.push("Blocking reasons:".to_string());
        for reason in &report.blocking_reasons {
            lines.push(format!(
                "- [{}] {}: {}",
                reason.source, reason.name, reason.details
            ));
        }
    }

    if report.decision_history.is_empty() {
        lines.push("Decision history: none".to_string());
    } else {
        lines.push("Decision history:".to_string());
        for decision in &report.decision_history {
            lines.push(format!(
                "- {} at {}: {}",
                decision_action_label(decision.action),
                decision.decided_at_ms,
                decision.reason
            ));
        }
    }

    lines.join("\n")
}

/// Render a filtered proposal list for operator review.
pub fn render_evolution_proposal_list(list: &EvolutionProposalList) -> String {
    let mut lines = vec![
        "Evolution Queue".to_string(),
        format!("Total proposals: {}", list.total_count),
    ];
    if let Some(strategy_id) = &list.strategy_id {
        lines.push(format!("Strategy filter: {}", strategy_id));
    }
    if let Some(review_state) = list.review_state {
        lines.push(format!(
            "Review-state filter: {}",
            review_state_label(review_state)
        ));
    }
    if list.proposals.is_empty() {
        lines.push("No queued proposals matched the requested filters.".to_string());
        return lines.join("\n");
    }
    for proposal in &list.proposals {
        lines.push(format!(
            "- {} | strategy={} | state={} | proof={} | created_at={}",
            proposal.proposal_id,
            proposal.strategy_id,
            review_state_label(proposal.review_state),
            proof_status_label(proposal.proof_status),
            proposal.created_at_ms
        ));
    }
    lines.join("\n")
}

/// Render one durable queue-to-canary handoff packet.
pub fn render_evolution_handoff(report: &EvolutionHandoffReport) -> String {
    let mut lines = vec![
        "Evolution Canary Handoff".to_string(),
        format!("Handoff ID: {}", report.handoff_id),
        format!("Proposal: {}", report.proposal_id),
        format!(
            "Experiment: {} ({})",
            report.experiment_name, report.experiment_id
        ),
        format!(
            "Strategy: {} | {}",
            report.strategy_id, report.strategy_description
        ),
        format!(
            "Launch status: {} | canary_run_id={}",
            handoff_status_label(report.launch_status),
            report.canary_run_id.as_deref().unwrap_or("none")
        ),
        format!(
            "Verification: {} | Proof: {} | Shadow: {} (passed={})",
            report.verification_id, report.proof.proof_id, report.shadow_id, report.shadow_passed
        ),
        format!(
            "Context: suite={} corpus={}",
            report.suite_name, report.corpus_version
        ),
    ];

    if let Some(advisory) = &report.advisory {
        lines.push(format!(
            "Advisory: scorecard={} recommendation={} delta={:.3}",
            advisory.scorecard_id,
            advisory_recommendation_label(advisory.recommendation),
            advisory.score_delta
        ));
    } else {
        lines.push("Advisory: unavailable".to_string());
    }
    if let Some(assurance) = &report.assurance {
        lines.extend(render_assurance_summary_lines(assurance));
    } else {
        lines.push("Assurance: unavailable".to_string());
    }

    if report.blocking_reasons.is_empty() {
        lines.push("Blocking reasons: none".to_string());
    } else {
        lines.push("Blocking reasons:".to_string());
        for reason in &report.blocking_reasons {
            lines.push(format!(
                "- [{}] {}: {}",
                reason.source, reason.name, reason.details
            ));
        }
    }

    lines.join("\n")
}
