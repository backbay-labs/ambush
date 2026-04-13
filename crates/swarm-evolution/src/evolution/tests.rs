#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{
    DefaultEvolutionHandoffHarness, DefaultEvolutionProofHarness, DefaultEvolutionQueueHarness,
    DefaultFormalSafetyGate, EvolutionAssuranceRolloutState, EvolutionAssuranceWaiverSummary,
    EvolutionHandoffStatus, EvolutionProposalAssuranceCoverageSummary,
    EvolutionProposalAssuranceDecision, EvolutionProposalAssuranceSolverSummary,
    EvolutionProposalAssuranceSummary, EvolutionProposalBlockingReason,
    EvolutionProposalCreateRequest, EvolutionProposalDecisionAction, EvolutionProposalProofStatus,
    EvolutionProposalReviewState, EvolutionSolverProofStatus, FileEvolutionProofStore,
    FileEvolutionProposalStore, FormalSafetyGate, StrategyGenome, assurance_gate_block_reason,
    assurance_rollout_state, build_assurance_waiver_summary, render_evolution_handoff,
    render_evolution_proof, render_evolution_proposal, render_evolution_proposal_list,
    validate_assurance_waiver,
};
use crate::canary::DefaultCanaryHarness;
use crate::replay::{DefaultReplayHarness, FileVerificationStore};
use crate::strategy::DefaultStrategyScorecardHarness;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::ThreatClass;
use swarm_core::config::{PolicyRuleConfig, PolicyRuleDecision, SwarmConfig};
use swarm_core::types::{AgentId, Severity};
use swarm_crypto::Ed25519Signer;

fn sample_config() -> SwarmConfig {
    let mut config: SwarmConfig =
        serde_yaml::from_str(include_str!("../../../../rulesets/default.yaml")).unwrap();
    config.policy.rules = permissive_policy_rules();
    config.evolution.assurance.min_detector_catch_rate = 0.0;
    config
}

fn passed_assurance_summary() -> EvolutionProposalAssuranceSummary {
    EvolutionProposalAssuranceSummary {
        decision: EvolutionProposalAssuranceDecision::Passed,
        coverage: EvolutionProposalAssuranceCoverageSummary {
            detector: "office_baseline_control".to_string(),
            suite_name: Some("evasion-breadth-v1".to_string()),
            corpus_version: Some("2026-04-03".to_string()),
            required_catch_rate: 0.75,
            actual_catch_rate: Some(1.0),
            actionable_gap_count: 0,
        },
        solver: EvolutionProposalAssuranceSolverSummary {
            required: false,
            status: None,
            allowed_statuses: Vec::new(),
        },
        harvested_case_ids: Vec::new(),
        waiver: None,
    }
}

fn permissive_policy_rules() -> Vec<PolicyRuleConfig> {
    use ThreatClass::{
        CommandAndControl, CredentialAccess, DataExfiltration, DefenseEvasion, Discovery,
        Execution, Impact, InitialAccess, LateralMovement, Persistence, PrivilegeEscalation,
        SupplyChain,
    };

    [
        Execution,
        CommandAndControl,
        CredentialAccess,
        DataExfiltration,
        DefenseEvasion,
        Discovery,
        Impact,
        InitialAccess,
        LateralMovement,
        Persistence,
        PrivilegeEscalation,
        SupplyChain,
    ]
    .into_iter()
    .map(|threat_class| PolicyRuleConfig {
        name: format!("evolution-test-allow-{threat_class:?}"),
        decision: PolicyRuleDecision::Allow,
        threat_class,
        actions: Vec::new(),
        min_severity: Severity::Low,
        max_severity: Severity::Critical,
        time_window_utc: None,
        max_actions_per_agent_per_minute: None,
        reason: Some("evolution tests allow replay and verification responses".to_string()),
    })
    .collect()
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn office_control_experiment() -> PathBuf {
    repo_root().join("experiments/office-baseline-control.yaml")
}

fn unique_temp_dir(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "swarm-runtime-evolution-{label}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn persist_passed_verification(
    verification_results_dir: &Path,
    report: &crate::replay::DetectorVerificationReport,
) -> crate::replay::DetectorVerificationReport {
    let mut report = report.clone();
    report.passed = true;
    FileVerificationStore::open(verification_results_dir)
        .unwrap()
        .persist(&report)
        .unwrap();
    report
}

fn operator_id_for_secret(secret_material: &str) -> String {
    let signer = Ed25519Signer::from_secret_material(secret_material);
    AgentId::from_public_key_hex(signer.public_key_hex()).to_string()
}

fn persist_blocked_assurance_proposal(queue_dir: &Path, proposal_id: &str) {
    let store = FileEvolutionProposalStore::open(queue_dir).unwrap();
    let mut tampered = store.load(proposal_id).unwrap().unwrap().report;
    let mut assurance = tampered.assurance.unwrap();
    assurance.decision = EvolutionProposalAssuranceDecision::Blocked;
    assurance.coverage.actual_catch_rate = Some(0.25);
    assurance.coverage.actionable_gap_count = 2;
    assurance.harvested_case_ids = vec!["case-a".to_string(), "case-b".to_string()];
    assurance.waiver = None;
    tampered.assurance = Some(assurance);
    tampered.review_state = EvolutionProposalReviewState::Blocked;
    tampered.blocking_reasons = vec![EvolutionProposalBlockingReason {
        source: "assurance".to_string(),
        name: "assurance_gate_unsatisfied".to_string(),
        details: "assurance decision `blocked` does not permit rollout progression".to_string(),
        references: vec![proposal_id.to_string()],
    }];
    store.persist(&tampered).unwrap();
}

fn write_custom_z3_bundle(root: &Path, name: &str, query: &str) -> PathBuf {
    let bundle_path = root.join(format!("{name}.yaml"));
    fs::write(
            &bundle_path,
            format!(
                "schema_version: 1\nname: {name}\ndescription: test custom z3 bundle\ninvariants:\n  - name: {name}\n    type: custom_z3\n    query: |\n{}\n",
                query
                    .lines()
                    .map(|line| format!("      {line}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        )
        .unwrap();
    bundle_path
}

async fn verified_strategy_genome(
    root: &Path,
    config_path: &Path,
    config: &SwarmConfig,
) -> StrategyGenome {
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verification");
    let shadow_dir = root.join("shadows");
    let replay =
        DefaultReplayHarness::from_config(config_path, config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let (_, shadow) = replay
        .evaluate_experiment_and_shadow_path(
            office_control_experiment(),
            &experiment_dir,
            &shadow_dir,
        )
        .await
        .unwrap();
    let experiment =
        crate::replay::load_detector_experiment_manifest(office_control_experiment()).unwrap();

    StrategyGenome {
        strategy_id: experiment.candidate.strategy_id().to_string(),
        experiment_path: office_control_experiment(),
        experiment,
        verification: verification.report,
        shadow: shadow.report,
    }
}

#[tokio::test]
async fn evolution_proof_persists_for_passed_verification() {
    let root = unique_temp_dir("proof");
    let replay_dir = root.join("replay");
    let verification_dir = root.join("verification");
    let proofs_dir = root.join("proofs");
    let config = sample_config();
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let harness = DefaultEvolutionProofHarness::from_config("inline", config, &proofs_dir).unwrap();

    let proof = harness
        .create_proof(
            office_control_experiment(),
            &verification_dir,
            &verification.report.verification_id,
        )
        .unwrap();

    assert_eq!(proof.report.strategy_id, "office_baseline_control");
    assert_eq!(
        proof.report.verification_id,
        verification.report.verification_id
    );
    assert!(!proof.report.attestation_sha256.is_empty());
    assert!(render_evolution_proof(&proof.report).contains("Evolution Safety Proof"));
}

#[tokio::test]
async fn formal_safety_gate_accepts_repo_owned_bundle_for_verified_candidate() {
    let root = unique_temp_dir("formal-safety-pass");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verification");
    let shadow_dir = root.join("shadows");
    let config = sample_config();
    let config_path = repo_root().join("rulesets/default.yaml");
    let replay =
        DefaultReplayHarness::from_config(&config_path, config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let (_, shadow) = replay
        .evaluate_experiment_and_shadow_path(
            office_control_experiment(),
            &experiment_dir,
            &shadow_dir,
        )
        .await
        .unwrap();
    let experiment =
        crate::replay::load_detector_experiment_manifest(office_control_experiment()).unwrap();
    let gate = DefaultFormalSafetyGate::from_config(config_path, config);

    let report = gate
        .verify(&StrategyGenome {
            strategy_id: experiment.candidate.strategy_id().to_string(),
            experiment_path: office_control_experiment(),
            experiment,
            verification: verification.report.clone(),
            shadow: shadow.report.clone(),
        })
        .unwrap();

    assert!(report.passed);
    assert_eq!(report.bundle_paths.len(), 1);
    assert!(report.invariants.len() >= 5);
    assert!(report.invariants.iter().all(|invariant| invariant.passed));
}

#[tokio::test]
async fn formal_safety_gate_rejects_candidate_when_parameter_bounds_violate_repo_policy() {
    let root = unique_temp_dir("formal-safety-bounds");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verification");
    let shadow_dir = root.join("shadows");
    let config = sample_config();
    let config_path = repo_root().join("rulesets/default.yaml");
    let replay =
        DefaultReplayHarness::from_config(&config_path, config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let (_, shadow) = replay
        .evaluate_experiment_and_shadow_path(
            office_control_experiment(),
            &experiment_dir,
            &shadow_dir,
        )
        .await
        .unwrap();
    let mut experiment =
        crate::replay::load_detector_experiment_manifest(office_control_experiment()).unwrap();
    if let crate::replay::DetectorCandidateManifest::SuspiciousProcessTree { profile, .. } =
        &mut experiment.candidate
    {
        profile.medium_confidence_threshold = 0.10;
    } else {
        panic!("expected suspicious process tree fixture");
    }
    let gate = DefaultFormalSafetyGate::from_config(config_path, config);

    let report = gate
        .verify(&StrategyGenome {
            strategy_id: experiment.candidate.strategy_id().to_string(),
            experiment_path: office_control_experiment(),
            experiment,
            verification: verification.report.clone(),
            shadow: shadow.report.clone(),
        })
        .unwrap();

    assert!(!report.passed);
    assert!(
        report
            .invariants
            .iter()
            .any(|invariant| { invariant.name == "medium_confidence_bounds" && !invariant.passed })
    );
}

#[cfg(not(feature = "z3"))]
#[tokio::test]
async fn z3_custom_invariant_fails_closed_without_feature() {
    let root = unique_temp_dir("z3-disabled");
    let proofs_dir = root.join("proofs");
    let config_path = repo_root().join("rulesets/default.yaml");
    let bundle_path = write_custom_z3_bundle(
        &root,
        "z3_disabled_guardrail",
        "(declare-const medium_confidence Real)\n(assert (= medium_confidence {{/candidate/profile/medium_confidence_threshold}}))\n(assert (> medium_confidence 1.5))",
    );
    let mut config = sample_config();
    config.evolution.safety_gate.enable_z3 = true;
    config.evolution.safety_gate.invariant_bundle_paths = vec![bundle_path.display().to_string()];
    config.evolution.paths.evolution_proof_results_dir = proofs_dir.display().to_string();
    let candidate = verified_strategy_genome(&root, &config_path, &config).await;
    let gate = DefaultFormalSafetyGate::from_config(config_path, config);

    let report = gate.verify(&candidate).unwrap();

    assert!(!report.passed);
    assert_eq!(
        report.solver_summary.as_ref().map(|summary| summary.status),
        Some(EvolutionSolverProofStatus::Disabled)
    );
    let proof_store = FileEvolutionProofStore::open(&proofs_dir).unwrap();
    let proof = proof_store
        .load(report.persisted_proof_id.as_deref().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        proof
            .report
            .solver_summary
            .as_ref()
            .map(|summary| summary.status),
        Some(EvolutionSolverProofStatus::Disabled)
    );
}

#[cfg(feature = "z3")]
#[tokio::test]
async fn z3_custom_invariant_proves_unsat_and_persists_proof() {
    let root = unique_temp_dir("z3-proved");
    let proofs_dir = root.join("proofs");
    let config_path = repo_root().join("rulesets/default.yaml");
    let bundle_path = write_custom_z3_bundle(
        &root,
        "z3_proved_guardrail",
        "(declare-const medium_confidence Real)\n(assert (= medium_confidence {{/candidate/profile/medium_confidence_threshold}}))\n(assert (> medium_confidence 1.5))",
    );
    let mut config = sample_config();
    config.evolution.safety_gate.enable_z3 = true;
    config.evolution.safety_gate.invariant_bundle_paths = vec![bundle_path.display().to_string()];
    config.evolution.paths.evolution_proof_results_dir = proofs_dir.display().to_string();
    let candidate = verified_strategy_genome(&root, &config_path, &config).await;
    let gate = DefaultFormalSafetyGate::from_config(config_path, config);

    let report = gate.verify(&candidate).unwrap();

    assert!(report.passed);
    assert_eq!(
        report.solver_summary.as_ref().map(|summary| summary.status),
        Some(EvolutionSolverProofStatus::Proved)
    );
    let proof_store = FileEvolutionProofStore::open(&proofs_dir).unwrap();
    let proof = proof_store
        .load(report.persisted_proof_id.as_deref().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        proof
            .report
            .solver_summary
            .as_ref()
            .map(|summary| summary.status),
        Some(EvolutionSolverProofStatus::Proved)
    );
    assert!(render_evolution_proof(&proof.report).contains("Solver: proved"));
}

#[cfg(feature = "z3")]
#[tokio::test]
async fn z3_proof_persists_machine_readable_counterexample() {
    let root = unique_temp_dir("z3-counterexample");
    let proofs_dir = root.join("proofs");
    let config_path = repo_root().join("rulesets/default.yaml");
    let bundle_path = write_custom_z3_bundle(
        &root,
        "z3_counterexample_guardrail",
        "(declare-const medium_confidence Real)\n(assert (= medium_confidence {{/candidate/profile/medium_confidence_threshold}}))\n(assert (< medium_confidence 1.5))",
    );
    let mut config = sample_config();
    config.evolution.safety_gate.enable_z3 = true;
    config.evolution.safety_gate.invariant_bundle_paths = vec![bundle_path.display().to_string()];
    config.evolution.paths.evolution_proof_results_dir = proofs_dir.display().to_string();
    let candidate = verified_strategy_genome(&root, &config_path, &config).await;
    let gate = DefaultFormalSafetyGate::from_config(config_path, config);

    let report = gate.verify(&candidate).unwrap();

    assert!(!report.passed);
    assert_eq!(
        report.solver_summary.as_ref().map(|summary| summary.status),
        Some(EvolutionSolverProofStatus::Counterexample)
    );
    let proof_store = FileEvolutionProofStore::open(&proofs_dir).unwrap();
    let proof = proof_store
        .load(report.persisted_proof_id.as_deref().unwrap())
        .unwrap()
        .unwrap();
    let artifact = proof.report.solver_artifacts.first().unwrap();
    assert_eq!(artifact.status, EvolutionSolverProofStatus::Counterexample);
    assert!(!artifact.counterexamples.is_empty());
    assert_eq!(artifact.counterexamples[0].name, "medium_confidence");
    assert!(!artifact.attestation_sha256.is_empty());
}

#[tokio::test]
async fn evolution_queue_creates_pending_review_proposal() {
    let root = unique_temp_dir("queue-create");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verification");
    let memory_dir = root.join("memory");
    let scorecard_dir = root.join("scorecards");
    let proofs_dir = root.join("proofs");
    let queue_dir = root.join("queue");
    let config = sample_config();
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let proof_harness =
        DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proofs_dir).unwrap();
    let proof = proof_harness
        .create_proof(
            office_control_experiment(),
            &verification_dir,
            &verification.report.verification_id,
        )
        .unwrap();
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        "inline",
        config.clone(),
        &memory_dir,
        &scorecard_dir,
    )
    .unwrap();
    let queue = DefaultEvolutionQueueHarness::from_config("inline", config, &queue_dir).unwrap();

    let proposal = queue
        .create_proposal(
            &replay,
            &scorecards,
            EvolutionProposalCreateRequest {
                experiment_path: office_control_experiment(),
                experiment_results_dir: experiment_dir.clone(),
                verification_results_dir: verification_dir.clone(),
                verification_id: verification.report.verification_id.clone(),
                proof_results_dir: proofs_dir.clone(),
                proof_id: proof.report.proof_id.clone(),
            },
        )
        .await
        .unwrap();

    assert_eq!(
        proposal.report.review_state,
        EvolutionProposalReviewState::PendingReview
    );
    assert_eq!(
        proposal.report.proof_status,
        EvolutionProposalProofStatus::Proved
    );
    assert!(proposal.report.advisory.is_some());
    assert_eq!(
        proposal
            .report
            .assurance
            .as_ref()
            .map(|summary| summary.decision),
        Some(EvolutionProposalAssuranceDecision::Passed)
    );
    assert!(render_evolution_proposal(&proposal.report).contains("Evolution Proposal"));
}

#[tokio::test]
async fn evolution_queue_blocks_missing_proof() {
    let root = unique_temp_dir("queue-blocked");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verification");
    let memory_dir = root.join("memory");
    let scorecard_dir = root.join("scorecards");
    let proofs_dir = root.join("proofs");
    let queue_dir = root.join("queue");
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
    let queue = DefaultEvolutionQueueHarness::from_config("inline", config, &queue_dir).unwrap();

    let proposal = queue
        .create_proposal(
            &replay,
            &scorecards,
            EvolutionProposalCreateRequest {
                experiment_path: office_control_experiment(),
                experiment_results_dir: experiment_dir.clone(),
                verification_results_dir: verification_dir.clone(),
                verification_id: verification.report.verification_id.clone(),
                proof_results_dir: proofs_dir.clone(),
                proof_id: "missing-proof".to_string(),
            },
        )
        .await
        .unwrap();

    assert_eq!(
        proposal.report.review_state,
        EvolutionProposalReviewState::Blocked
    );
    assert_eq!(
        proposal.report.proof_status,
        EvolutionProposalProofStatus::Missing
    );
    assert_eq!(proposal.report.blocking_reasons.len(), 1);
}

#[tokio::test]
async fn evolution_queue_blocks_when_assurance_coverage_floor_is_not_met() {
    let root = unique_temp_dir("queue-assurance-coverage");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verification");
    let memory_dir = root.join("memory");
    let scorecard_dir = root.join("scorecards");
    let proofs_dir = root.join("proofs");
    let queue_dir = root.join("queue");
    let mut config = sample_config();
    config.evolution.assurance.coverage_overrides = vec![
        swarm_core::config::EvolutionAssuranceCoverageOverrideConfig {
            detector: "suspicious_process_tree".to_string(),
            min_catch_rate: 1.0,
        },
    ];
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let proof_harness =
        DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proofs_dir).unwrap();
    let proof = proof_harness
        .create_proof(
            office_control_experiment(),
            &verification_dir,
            &verification.report.verification_id,
        )
        .unwrap();
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        "inline",
        config.clone(),
        &memory_dir,
        &scorecard_dir,
    )
    .unwrap();
    let queue = DefaultEvolutionQueueHarness::from_config("inline", config, &queue_dir).unwrap();

    let proposal = queue
        .create_proposal(
            &replay,
            &scorecards,
            EvolutionProposalCreateRequest {
                experiment_path: office_control_experiment(),
                experiment_results_dir: experiment_dir.clone(),
                verification_results_dir: verification_dir.clone(),
                verification_id: verification.report.verification_id.clone(),
                proof_results_dir: proofs_dir.clone(),
                proof_id: proof.report.proof_id.clone(),
            },
        )
        .await
        .unwrap();

    assert_eq!(
        proposal.report.review_state,
        EvolutionProposalReviewState::Blocked
    );
    assert_eq!(
        proposal
            .report
            .assurance
            .as_ref()
            .map(|summary| summary.decision),
        Some(EvolutionProposalAssuranceDecision::Blocked)
    );
    assert!(
        proposal.report.blocking_reasons.iter().any(|reason| {
            reason.source == "assurance" && reason.name == "coverage_floor_not_met"
        })
    );
}

#[tokio::test]
async fn evolution_queue_blocks_when_solver_summary_is_required() {
    let root = unique_temp_dir("queue-assurance-solver");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verification");
    let memory_dir = root.join("memory");
    let scorecard_dir = root.join("scorecards");
    let proofs_dir = root.join("proofs");
    let queue_dir = root.join("queue");
    let mut config = sample_config();
    config.evolution.assurance.require_solver_summary = true;
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let proof_harness =
        DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proofs_dir).unwrap();
    let proof = proof_harness
        .create_proof(
            office_control_experiment(),
            &verification_dir,
            &verification.report.verification_id,
        )
        .unwrap();
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        "inline",
        config.clone(),
        &memory_dir,
        &scorecard_dir,
    )
    .unwrap();
    let queue = DefaultEvolutionQueueHarness::from_config("inline", config, &queue_dir).unwrap();

    let proposal = queue
        .create_proposal(
            &replay,
            &scorecards,
            EvolutionProposalCreateRequest {
                experiment_path: office_control_experiment(),
                experiment_results_dir: experiment_dir.clone(),
                verification_results_dir: verification_dir.clone(),
                verification_id: verification.report.verification_id.clone(),
                proof_results_dir: proofs_dir.clone(),
                proof_id: proof.report.proof_id.clone(),
            },
        )
        .await
        .unwrap();

    assert_eq!(
        proposal.report.review_state,
        EvolutionProposalReviewState::Blocked
    );
    assert_eq!(
        proposal
            .report
            .assurance
            .as_ref()
            .map(|summary| summary.decision),
        Some(EvolutionProposalAssuranceDecision::Blocked)
    );
    assert!(
        proposal.report.blocking_reasons.iter().any(|reason| {
            reason.source == "assurance" && reason.name == "missing_solver_summary"
        })
    );
    assert!(render_evolution_proposal(&proposal.report).contains("Assurance: blocked"));
}

#[tokio::test]
async fn evolution_queue_harvests_replayable_coverage_gap_cases() {
    let root = unique_temp_dir("queue-assurance-harvest-coverage");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verification");
    let memory_dir = root.join("memory");
    let scorecard_dir = root.join("scorecards");
    let proofs_dir = root.join("proofs");
    let queue_dir = root.join("queue");
    let harvest_dir = root.join("assurance-cases");
    let mut config = sample_config();
    config.evolution.assurance.harvest.results_dir = harvest_dir.display().to_string();
    config.evolution.assurance.harvest.max_cases_per_proposal = 2;
    config.evolution.assurance.harvest.max_events_per_case = 1;
    config.evolution.assurance.coverage_overrides = vec![
        swarm_core::config::EvolutionAssuranceCoverageOverrideConfig {
            detector: "suspicious_process_tree".to_string(),
            min_catch_rate: 1.0,
        },
    ];
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let proof_harness =
        DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proofs_dir).unwrap();
    let proof = proof_harness
        .create_proof(
            office_control_experiment(),
            &verification_dir,
            &verification.report.verification_id,
        )
        .unwrap();
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        "inline",
        config.clone(),
        &memory_dir,
        &scorecard_dir,
    )
    .unwrap();
    let queue = DefaultEvolutionQueueHarness::from_config("inline", config, &queue_dir).unwrap();

    let proposal = queue
        .create_proposal(
            &replay,
            &scorecards,
            EvolutionProposalCreateRequest {
                experiment_path: office_control_experiment(),
                experiment_results_dir: experiment_dir.clone(),
                verification_results_dir: verification_dir.clone(),
                verification_id: verification.report.verification_id.clone(),
                proof_results_dir: proofs_dir.clone(),
                proof_id: proof.report.proof_id.clone(),
            },
        )
        .await
        .unwrap();

    let harvested_case_ids = proposal
        .report
        .assurance
        .as_ref()
        .unwrap()
        .harvested_case_ids
        .clone();
    assert!(!harvested_case_ids.is_empty());
    let scenario_paths = fs::read_dir(harvest_dir.join("scenarios"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    assert_eq!(scenario_paths.len(), harvested_case_ids.len());
    let harvested = crate::replay::load_scenario_manifest(&scenario_paths[0]).unwrap();
    assert!(
        harvested
            .manifest
            .metadata
            .tags
            .contains(&"assurance_case".to_string())
    );
    assert!(
        harvested
            .manifest
            .receipt_chain
            .contains(&proposal.report.proposal_id)
    );
    match harvested.manifest.input {
        crate::replay::ReplayScenarioInput::Events { events } => {
            assert_eq!(events.len(), 1);
        }
        crate::replay::ReplayScenarioInput::ReplayBundles { .. } => {
            panic!("coverage harvest should regenerate event-based scenarios");
        }
    }
    assert!(render_evolution_proposal(&proposal.report).contains("Assurance harvested cases"));
}

#[cfg(feature = "z3")]
#[tokio::test]
async fn evolution_queue_harvests_solver_counterexample_cases() {
    let root = unique_temp_dir("queue-assurance-harvest-solver");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verification");
    let memory_dir = root.join("memory");
    let scorecard_dir = root.join("scorecards");
    let proofs_dir = root.join("proofs");
    let queue_dir = root.join("queue");
    let harvest_dir = root.join("assurance-cases");
    let config_path = repo_root().join("rulesets/default.yaml");
    let bundle_path = write_custom_z3_bundle(
        &root,
        "z3_queue_counterexample_guardrail",
        "(declare-const medium_confidence Real)\n(assert (= medium_confidence {{/candidate/profile/medium_confidence_threshold}}))\n(assert (< medium_confidence 1.5))",
    );
    let mut config = sample_config();
    config.evolution.assurance.harvest.results_dir = harvest_dir.display().to_string();
    config.evolution.safety_gate.enable_z3 = true;
    config.evolution.safety_gate.invariant_bundle_paths = vec![bundle_path.display().to_string()];
    config.evolution.paths.evolution_proof_results_dir = proofs_dir.display().to_string();
    let replay =
        DefaultReplayHarness::from_config(&config_path, config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let candidate = verified_strategy_genome(&root, &config_path, &config).await;
    let gate = DefaultFormalSafetyGate::from_config(&config_path, config.clone());
    let proof_report = gate.verify(&candidate).unwrap();
    let proof_store = FileEvolutionProofStore::open(&proofs_dir).unwrap();
    let proof = proof_store
        .load(proof_report.persisted_proof_id.as_deref().unwrap())
        .unwrap()
        .unwrap();
    assert!(
        proof
            .report
            .solver_artifacts
            .iter()
            .any(|artifact| !artifact.counterexamples.is_empty())
    );
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        &config_path,
        config.clone(),
        &memory_dir,
        &scorecard_dir,
    )
    .unwrap();
    let queue =
        DefaultEvolutionQueueHarness::from_config(&config_path, config, &queue_dir).unwrap();

    let proposal = queue
        .create_proposal(
            &replay,
            &scorecards,
            EvolutionProposalCreateRequest {
                experiment_path: office_control_experiment(),
                experiment_results_dir: experiment_dir.clone(),
                verification_results_dir: verification_dir.clone(),
                verification_id: verification.report.verification_id.clone(),
                proof_results_dir: proofs_dir.clone(),
                proof_id: proof.report.proof_id.clone(),
            },
        )
        .await
        .unwrap();

    let harvested_case_ids = proposal
        .report
        .assurance
        .as_ref()
        .unwrap()
        .harvested_case_ids
        .clone();
    assert!(!harvested_case_ids.is_empty());
    let scenario_paths = fs::read_dir(harvest_dir.join("scenarios"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    assert!(!scenario_paths.is_empty());
    let harvested = crate::replay::load_scenario_manifest(&scenario_paths[0]).unwrap();
    match harvested.manifest.input {
        crate::replay::ReplayScenarioInput::ReplayBundles { paths } => {
            assert_eq!(paths.len(), 1);
            assert!(PathBuf::from(&paths[0]).exists());
        }
        crate::replay::ReplayScenarioInput::Events { .. } => {
            panic!("solver harvest should preserve replay-bundle input");
        }
    }
}

#[tokio::test]
async fn evolution_queue_lists_and_accepts_pending_proposal() {
    let root = unique_temp_dir("queue-decide");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verification");
    let memory_dir = root.join("memory");
    let scorecard_dir = root.join("scorecards");
    let proofs_dir = root.join("proofs");
    let queue_dir = root.join("queue");
    let config = sample_config();
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let proof_harness =
        DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proofs_dir).unwrap();
    let proof = proof_harness
        .create_proof(
            office_control_experiment(),
            &verification_dir,
            &verification.report.verification_id,
        )
        .unwrap();
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        "inline",
        config.clone(),
        &memory_dir,
        &scorecard_dir,
    )
    .unwrap();
    let queue = DefaultEvolutionQueueHarness::from_config("inline", config, &queue_dir).unwrap();
    let proposal = queue
        .create_proposal(
            &replay,
            &scorecards,
            EvolutionProposalCreateRequest {
                experiment_path: office_control_experiment(),
                experiment_results_dir: experiment_dir.clone(),
                verification_results_dir: verification_dir.clone(),
                verification_id: verification.report.verification_id.clone(),
                proof_results_dir: proofs_dir.clone(),
                proof_id: proof.report.proof_id.clone(),
            },
        )
        .await
        .unwrap();

    let list = queue
        .list_proposals(
            Some("office_baseline_control"),
            Some(EvolutionProposalReviewState::PendingReview),
        )
        .unwrap();
    assert_eq!(list.total_count, 1);
    assert!(render_evolution_proposal_list(&list).contains("pending_review"));

    let decided = queue
        .record_decision(
            &proposal.report.proposal_id,
            EvolutionProposalDecisionAction::AcceptForCanary,
            "control candidate is ready for bounded canary",
        )
        .unwrap();
    assert_eq!(
        decided.report.review_state,
        EvolutionProposalReviewState::AcceptedForCanary
    );
    assert_eq!(decided.report.decision_history.len(), 1);
}

#[tokio::test]
async fn evolution_handoff_persists_pending_launch_packet() {
    let root = unique_temp_dir("handoff-create");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verification");
    let shadow_dir = root.join("shadows");
    let memory_dir = root.join("memory");
    let scorecard_dir = root.join("scorecards");
    let proofs_dir = root.join("proofs");
    let queue_dir = root.join("queue");
    let handoff_dir = root.join("handoffs");
    let config = sample_config();
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let verification_report = persist_passed_verification(&verification_dir, &verification.report);
    let shadow = replay
        .evaluate_shadow_path(office_control_experiment(), &shadow_dir)
        .await
        .unwrap();
    let proof_harness =
        DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proofs_dir).unwrap();
    let proof = proof_harness
        .create_proof(
            office_control_experiment(),
            &verification_dir,
            &verification_report.verification_id,
        )
        .unwrap();
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        "inline",
        config.clone(),
        &memory_dir,
        &scorecard_dir,
    )
    .unwrap();
    let queue =
        DefaultEvolutionQueueHarness::from_config("inline", config.clone(), &queue_dir).unwrap();
    let proposal = queue
        .create_proposal(
            &replay,
            &scorecards,
            EvolutionProposalCreateRequest {
                experiment_path: office_control_experiment(),
                experiment_results_dir: experiment_dir.clone(),
                verification_results_dir: verification_dir.clone(),
                verification_id: verification_report.verification_id.clone(),
                proof_results_dir: proofs_dir.clone(),
                proof_id: proof.report.proof_id.clone(),
            },
        )
        .await
        .unwrap();

    // Supply assurance lineage so the proposal passes the v1.51 assurance gate.
    {
        let store = FileEvolutionProposalStore::open(&queue_dir).unwrap();
        let mut report = store
            .load(&proposal.report.proposal_id)
            .unwrap()
            .unwrap()
            .report;
        report.assurance = Some(passed_assurance_summary());
        report.blocking_reasons.retain(|r| r.source != "assurance");
        if report.blocking_reasons.is_empty() {
            report.review_state = EvolutionProposalReviewState::PendingReview;
        }
        store.persist(&report).unwrap();
    }

    let accepted = queue
        .record_decision(
            &proposal.report.proposal_id,
            EvolutionProposalDecisionAction::AcceptForCanary,
            "ready for queue handoff",
        )
        .unwrap();
    let handoff =
        DefaultEvolutionHandoffHarness::from_config("inline", config, &handoff_dir).unwrap();

    let lookup = handoff
        .create_handoff(
            &queue_dir,
            &accepted.report.proposal_id,
            &shadow_dir,
            &shadow.report.shadow_id,
        )
        .unwrap();

    assert_eq!(
        lookup.report.launch_status,
        EvolutionHandoffStatus::PendingLaunch
    );
    assert!(lookup.report.blocking_reasons.is_empty());
    assert_eq!(lookup.report.shadow_id, shadow.report.shadow_id);
    assert!(render_evolution_handoff(&lookup.report).contains("Evolution Canary Handoff"));
    assert!(render_evolution_handoff(&lookup.report).contains("Assurance: passed"));
}

#[tokio::test]
async fn evolution_handoff_blocks_unaccepted_proposal() {
    let root = unique_temp_dir("handoff-blocked");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verification");
    let shadow_dir = root.join("shadows");
    let memory_dir = root.join("memory");
    let scorecard_dir = root.join("scorecards");
    let proofs_dir = root.join("proofs");
    let queue_dir = root.join("queue");
    let handoff_dir = root.join("handoffs");
    let config = sample_config();
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let verification_report = persist_passed_verification(&verification_dir, &verification.report);
    let shadow = replay
        .evaluate_shadow_path(office_control_experiment(), &shadow_dir)
        .await
        .unwrap();
    let proof_harness =
        DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proofs_dir).unwrap();
    let proof = proof_harness
        .create_proof(
            office_control_experiment(),
            &verification_dir,
            &verification_report.verification_id,
        )
        .unwrap();
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        "inline",
        config.clone(),
        &memory_dir,
        &scorecard_dir,
    )
    .unwrap();
    let queue =
        DefaultEvolutionQueueHarness::from_config("inline", config.clone(), &queue_dir).unwrap();
    let proposal = queue
        .create_proposal(
            &replay,
            &scorecards,
            EvolutionProposalCreateRequest {
                experiment_path: office_control_experiment(),
                experiment_results_dir: experiment_dir.clone(),
                verification_results_dir: verification_dir.clone(),
                verification_id: verification_report.verification_id.clone(),
                proof_results_dir: proofs_dir.clone(),
                proof_id: proof.report.proof_id.clone(),
            },
        )
        .await
        .unwrap();
    let handoff =
        DefaultEvolutionHandoffHarness::from_config("inline", config, &handoff_dir).unwrap();

    let lookup = handoff
        .create_handoff(
            &queue_dir,
            &proposal.report.proposal_id,
            &shadow_dir,
            &shadow.report.shadow_id,
        )
        .unwrap();

    assert_eq!(lookup.report.launch_status, EvolutionHandoffStatus::Blocked);
    assert!(!lookup.report.blocking_reasons.is_empty());
    assert_eq!(lookup.report.canary_run_id, None);
}

#[tokio::test]
async fn evolution_handoff_blocks_when_assurance_lineage_is_unsatisfied() {
    let root = unique_temp_dir("handoff-assurance-blocked");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verification");
    let shadow_dir = root.join("shadows");
    let memory_dir = root.join("memory");
    let scorecard_dir = root.join("scorecards");
    let proofs_dir = root.join("proofs");
    let queue_dir = root.join("queue");
    let handoff_dir = root.join("handoffs");
    let config = sample_config();
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let verification_report = persist_passed_verification(&verification_dir, &verification.report);
    let shadow = replay
        .evaluate_shadow_path(office_control_experiment(), &shadow_dir)
        .await
        .unwrap();
    let proof_harness =
        DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proofs_dir).unwrap();
    let proof = proof_harness
        .create_proof(
            office_control_experiment(),
            &verification_dir,
            &verification_report.verification_id,
        )
        .unwrap();
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        "inline",
        config.clone(),
        &memory_dir,
        &scorecard_dir,
    )
    .unwrap();
    let queue =
        DefaultEvolutionQueueHarness::from_config("inline", config.clone(), &queue_dir).unwrap();
    let proposal = queue
        .create_proposal(
            &replay,
            &scorecards,
            EvolutionProposalCreateRequest {
                experiment_path: office_control_experiment(),
                experiment_results_dir: experiment_dir.clone(),
                verification_results_dir: verification_dir.clone(),
                verification_id: verification_report.verification_id.clone(),
                proof_results_dir: proofs_dir.clone(),
                proof_id: proof.report.proof_id.clone(),
            },
        )
        .await
        .unwrap();
    let accepted = queue
        .record_decision(
            &proposal.report.proposal_id,
            EvolutionProposalDecisionAction::AcceptForCanary,
            "ready for queue handoff",
        )
        .unwrap();
    let store = FileEvolutionProposalStore::open(&queue_dir).unwrap();
    let mut tampered = store
        .load(&accepted.report.proposal_id)
        .unwrap()
        .unwrap()
        .report;
    let mut assurance = tampered.assurance.unwrap();
    assurance.decision = EvolutionProposalAssuranceDecision::Blocked;
    assurance.harvested_case_ids = vec!["case-a".to_string()];
    tampered.assurance = Some(assurance);
    tampered.blocking_reasons = Vec::new();
    store.persist(&tampered).unwrap();
    let handoff =
        DefaultEvolutionHandoffHarness::from_config("inline", config, &handoff_dir).unwrap();

    let lookup = handoff
        .create_handoff(
            &queue_dir,
            &accepted.report.proposal_id,
            &shadow_dir,
            &shadow.report.shadow_id,
        )
        .unwrap();

    assert_eq!(lookup.report.launch_status, EvolutionHandoffStatus::Blocked);
    assert!(
        lookup
            .report
            .blocking_reasons
            .iter()
            .any(|reason| reason.source == "assurance")
    );
}

#[tokio::test]
async fn evolution_queue_applies_signed_assurance_waiver_and_allows_accept_for_canary() {
    let root = unique_temp_dir("queue-assurance-waiver");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verification");
    let memory_dir = root.join("memory");
    let scorecard_dir = root.join("scorecards");
    let proofs_dir = root.join("proofs");
    let queue_dir = root.join("queue");
    let secret_material = "phase-175-waiver-operator";
    let operator_id = operator_id_for_secret(secret_material);
    let mut config = sample_config();
    config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let verification_report = persist_passed_verification(&verification_dir, &verification.report);
    let proof_harness =
        DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proofs_dir).unwrap();
    let proof = proof_harness
        .create_proof(
            office_control_experiment(),
            &verification_dir,
            &verification_report.verification_id,
        )
        .unwrap();
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        "inline",
        config.clone(),
        &memory_dir,
        &scorecard_dir,
    )
    .unwrap();
    let queue = DefaultEvolutionQueueHarness::from_config("inline", config, &queue_dir).unwrap();
    let proposal = queue
        .create_proposal(
            &replay,
            &scorecards,
            EvolutionProposalCreateRequest {
                experiment_path: office_control_experiment(),
                experiment_results_dir: experiment_dir.clone(),
                verification_results_dir: verification_dir.clone(),
                verification_id: verification_report.verification_id.clone(),
                proof_results_dir: proofs_dir.clone(),
                proof_id: proof.report.proof_id.clone(),
            },
        )
        .await
        .unwrap();
    persist_blocked_assurance_proposal(&queue_dir, &proposal.report.proposal_id);

    let waived = queue
        .apply_assurance_waiver(
            &proposal.report.proposal_id,
            super::EvolutionAssuranceWaiverRequest {
                operator_id,
                secret_material: secret_material.to_string(),
                reason: "bounded review waiver for assurance backlog".to_string(),
                ttl_secs: 300,
            },
        )
        .unwrap();
    let waiver = waived
        .report
        .assurance
        .as_ref()
        .and_then(|summary| summary.waiver.as_ref())
        .unwrap();
    assert_eq!(
        waived.report.review_state,
        EvolutionProposalReviewState::Blocked
    );
    assert_eq!(
        waived.report.decision_history.last().unwrap().action,
        EvolutionProposalDecisionAction::ApplyAssuranceWaiver
    );
    assert!(render_evolution_proposal(&waived.report).contains("Assurance waiver:"));
    assert!(
        render_evolution_proposal(&waived.report)
            .contains("bounded review waiver for assurance backlog")
    );
    assert_eq!(waiver.waived_gap_count, 2);

    let accepted = queue
        .record_decision(
            &proposal.report.proposal_id,
            EvolutionProposalDecisionAction::AcceptForCanary,
            "waived assurance gaps are bounded and ready for canary",
        )
        .unwrap();
    assert_eq!(
        accepted.report.review_state,
        EvolutionProposalReviewState::AcceptedForCanary
    );
}

#[tokio::test]
async fn evolution_handoff_preserves_waived_assurance_lineage() {
    let root = unique_temp_dir("handoff-waived-assurance");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verification");
    let shadow_dir = root.join("shadows");
    let memory_dir = root.join("memory");
    let scorecard_dir = root.join("scorecards");
    let proofs_dir = root.join("proofs");
    let queue_dir = root.join("queue");
    let handoff_dir = root.join("handoffs");
    let secret_material = "phase-175-handoff-waiver";
    let operator_id = operator_id_for_secret(secret_material);
    let mut config = sample_config();
    config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let verification_report = persist_passed_verification(&verification_dir, &verification.report);
    let shadow = replay
        .evaluate_shadow_path(office_control_experiment(), &shadow_dir)
        .await
        .unwrap();
    let proof_harness =
        DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proofs_dir).unwrap();
    let proof = proof_harness
        .create_proof(
            office_control_experiment(),
            &verification_dir,
            &verification_report.verification_id,
        )
        .unwrap();
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        "inline",
        config.clone(),
        &memory_dir,
        &scorecard_dir,
    )
    .unwrap();
    let queue =
        DefaultEvolutionQueueHarness::from_config("inline", config.clone(), &queue_dir).unwrap();
    let proposal = queue
        .create_proposal(
            &replay,
            &scorecards,
            EvolutionProposalCreateRequest {
                experiment_path: office_control_experiment(),
                experiment_results_dir: experiment_dir.clone(),
                verification_results_dir: verification_dir.clone(),
                verification_id: verification_report.verification_id.clone(),
                proof_results_dir: proofs_dir.clone(),
                proof_id: proof.report.proof_id.clone(),
            },
        )
        .await
        .unwrap();
    persist_blocked_assurance_proposal(&queue_dir, &proposal.report.proposal_id);
    queue
        .apply_assurance_waiver(
            &proposal.report.proposal_id,
            super::EvolutionAssuranceWaiverRequest {
                operator_id,
                secret_material: secret_material.to_string(),
                reason: "handoff lineage waiver".to_string(),
                ttl_secs: 300,
            },
        )
        .unwrap();
    let accepted = queue
        .record_decision(
            &proposal.report.proposal_id,
            EvolutionProposalDecisionAction::AcceptForCanary,
            "waived assurance lineage is ready for handoff",
        )
        .unwrap();
    let handoff =
        DefaultEvolutionHandoffHarness::from_config("inline", config, &handoff_dir).unwrap();

    let lookup = handoff
        .create_handoff(
            &queue_dir,
            &accepted.report.proposal_id,
            &shadow_dir,
            &shadow.report.shadow_id,
        )
        .unwrap();

    assert_eq!(
        lookup.report.launch_status,
        EvolutionHandoffStatus::PendingLaunch
    );
    assert!(
        lookup
            .report
            .assurance
            .as_ref()
            .and_then(|summary| summary.waiver.as_ref())
            .is_some()
    );
    assert!(render_evolution_handoff(&lookup.report).contains("Assurance waiver:"));
    assert!(
        render_evolution_handoff(&lookup.report).contains("Waiver reason: handoff lineage waiver")
    );
}

#[tokio::test]
async fn evolution_handoff_launches_canary_and_persists_run_id() {
    let root = unique_temp_dir("handoff-launch");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verification");
    let shadow_dir = root.join("shadows");
    let memory_dir = root.join("memory");
    let scorecard_dir = root.join("scorecards");
    let proofs_dir = root.join("proofs");
    let queue_dir = root.join("queue");
    let handoff_dir = root.join("handoffs");
    let canary_dir = root.join("canaries");
    let config = sample_config();
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let verification_report = persist_passed_verification(&verification_dir, &verification.report);
    let shadow = replay
        .evaluate_shadow_path(office_control_experiment(), &shadow_dir)
        .await
        .unwrap();
    let proof_harness =
        DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proofs_dir).unwrap();
    let proof = proof_harness
        .create_proof(
            office_control_experiment(),
            &verification_dir,
            &verification_report.verification_id,
        )
        .unwrap();
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        "inline",
        config.clone(),
        &memory_dir,
        &scorecard_dir,
    )
    .unwrap();
    let queue =
        DefaultEvolutionQueueHarness::from_config("inline", config.clone(), &queue_dir).unwrap();
    let proposal = queue
        .create_proposal(
            &replay,
            &scorecards,
            EvolutionProposalCreateRequest {
                experiment_path: office_control_experiment(),
                experiment_results_dir: experiment_dir.clone(),
                verification_results_dir: verification_dir.clone(),
                verification_id: verification_report.verification_id.clone(),
                proof_results_dir: proofs_dir.clone(),
                proof_id: proof.report.proof_id.clone(),
            },
        )
        .await
        .unwrap();
    let accepted = queue
        .record_decision(
            &proposal.report.proposal_id,
            EvolutionProposalDecisionAction::AcceptForCanary,
            "ready for queue handoff",
        )
        .unwrap();
    let handoff_harness =
        DefaultEvolutionHandoffHarness::from_config("inline", config.clone(), &handoff_dir)
            .unwrap();
    let handoff = handoff_harness
        .create_handoff(
            &queue_dir,
            &accepted.report.proposal_id,
            &shadow_dir,
            &shadow.report.shadow_id,
        )
        .unwrap();
    let canary_harness = DefaultCanaryHarness::from_config("inline", config, &canary_dir).unwrap();

    let launched = handoff_harness
        .launch_canary(
            &canary_harness,
            &verification_dir,
            &shadow_dir,
            &handoff.report.handoff_id,
        )
        .unwrap();

    assert_eq!(
        launched.report.launch_status,
        EvolutionHandoffStatus::CanaryLaunched
    );
    assert!(launched.report.canary_run_id.is_some());
    let canary_run = canary_harness
        .load_run(launched.report.canary_run_id.as_deref().unwrap())
        .unwrap();
    assert!(canary_run.is_some());
}

#[tokio::test]
async fn evolution_handoff_launch_rejects_missing_assurance_lineage() {
    let root = unique_temp_dir("handoff-launch-missing-assurance");
    let replay_dir = root.join("replay");
    let experiment_dir = root.join("experiments");
    let verification_dir = root.join("verification");
    let shadow_dir = root.join("shadows");
    let memory_dir = root.join("memory");
    let scorecard_dir = root.join("scorecards");
    let proofs_dir = root.join("proofs");
    let queue_dir = root.join("queue");
    let handoff_dir = root.join("handoffs");
    let canary_dir = root.join("canaries");
    let config = sample_config();
    let replay = DefaultReplayHarness::from_config("inline", config.clone(), &replay_dir).unwrap();
    let verification = replay
        .evaluate_verification_path(office_control_experiment(), &verification_dir)
        .await
        .unwrap();
    let verification_report = persist_passed_verification(&verification_dir, &verification.report);
    let shadow = replay
        .evaluate_shadow_path(office_control_experiment(), &shadow_dir)
        .await
        .unwrap();
    let proof_harness =
        DefaultEvolutionProofHarness::from_config("inline", config.clone(), &proofs_dir).unwrap();
    let proof = proof_harness
        .create_proof(
            office_control_experiment(),
            &verification_dir,
            &verification_report.verification_id,
        )
        .unwrap();
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        "inline",
        config.clone(),
        &memory_dir,
        &scorecard_dir,
    )
    .unwrap();
    let queue =
        DefaultEvolutionQueueHarness::from_config("inline", config.clone(), &queue_dir).unwrap();
    let proposal = queue
        .create_proposal(
            &replay,
            &scorecards,
            EvolutionProposalCreateRequest {
                experiment_path: office_control_experiment(),
                experiment_results_dir: experiment_dir.clone(),
                verification_results_dir: verification_dir.clone(),
                verification_id: verification_report.verification_id.clone(),
                proof_results_dir: proofs_dir.clone(),
                proof_id: proof.report.proof_id.clone(),
            },
        )
        .await
        .unwrap();
    let accepted = queue
        .record_decision(
            &proposal.report.proposal_id,
            EvolutionProposalDecisionAction::AcceptForCanary,
            "ready for queue handoff",
        )
        .unwrap();
    let handoff_harness =
        DefaultEvolutionHandoffHarness::from_config("inline", config.clone(), &handoff_dir)
            .unwrap();
    let handoff = handoff_harness
        .create_handoff(
            &queue_dir,
            &accepted.report.proposal_id,
            &shadow_dir,
            &shadow.report.shadow_id,
        )
        .unwrap();
    let mut tampered = handoff.report.clone();
    tampered.assurance = None;
    handoff_harness.store.persist(&tampered).unwrap();
    let canary_harness = DefaultCanaryHarness::from_config("inline", config, &canary_dir).unwrap();

    let error = handoff_harness
        .launch_canary(
            &canary_harness,
            &verification_dir,
            &shadow_dir,
            &handoff.report.handoff_id,
        )
        .unwrap_err();

    assert!(matches!(
        error,
        super::EvolutionQueueError::InvalidHandoffLaunch { .. }
    ));
}

// --- Assurance gate unit tests ---

fn blocked_assurance_summary(gap_count: usize) -> EvolutionProposalAssuranceSummary {
    EvolutionProposalAssuranceSummary {
        decision: EvolutionProposalAssuranceDecision::Blocked,
        coverage: EvolutionProposalAssuranceCoverageSummary {
            detector: "office_baseline_control".to_string(),
            suite_name: Some("evasion-breadth-v1".to_string()),
            corpus_version: Some("2026-04-03".to_string()),
            required_catch_rate: 0.75,
            actual_catch_rate: Some(0.50),
            actionable_gap_count: gap_count,
        },
        solver: EvolutionProposalAssuranceSolverSummary {
            required: false,
            status: None,
            allowed_statuses: Vec::new(),
        },
        harvested_case_ids: Vec::new(),
        waiver: None,
    }
}

fn waiver_config() -> SwarmConfig {
    let mut config = sample_config();
    config.evolution.assurance.waiver.allowed_operator_ids =
        vec!["swarm:ed25519:waiver-test-operator".to_string()];
    config.evolution.assurance.waiver.max_actionable_gap_count = 5;
    config
}

fn build_valid_waiver(
    assurance: &EvolutionProposalAssuranceSummary,
    operator_id: &str,
    secret_material: &str,
    issued_at_ms: i64,
    ttl_secs: u64,
) -> EvolutionAssuranceWaiverSummary {
    let signer = Ed25519Signer::from_secret_material(secret_material);
    build_assurance_waiver_summary(
        "test-proposal-id",
        assurance,
        operator_id,
        &signer,
        issued_at_ms,
        ttl_secs,
        "justified test waiver",
    )
    .unwrap()
}

#[test]
fn rollout_state_clear_when_assurance_passed() {
    let config = sample_config();
    let assurance = passed_assurance_summary();
    let state = assurance_rollout_state(Some(&assurance), &config, 1_000_000);
    assert_eq!(state, EvolutionAssuranceRolloutState::Clear);
}

#[test]
fn rollout_state_blocked_when_no_assurance() {
    let config = sample_config();
    let state = assurance_rollout_state(None, &config, 1_000_000);
    assert_eq!(state, EvolutionAssuranceRolloutState::Blocked);
}

#[test]
fn rollout_state_blocked_when_decision_blocked_without_waiver() {
    let config = sample_config();
    let assurance = blocked_assurance_summary(2);
    let state = assurance_rollout_state(Some(&assurance), &config, 1_000_000);
    assert_eq!(state, EvolutionAssuranceRolloutState::Blocked);
}

#[test]
fn gate_block_reason_none_when_passed() {
    let config = sample_config();
    let assurance = passed_assurance_summary();
    let reason = assurance_gate_block_reason(Some(&assurance), &config, 1_000_000, "test");
    assert!(reason.is_none());
}

#[test]
fn gate_block_reason_present_when_no_assurance() {
    let config = sample_config();
    let reason = assurance_gate_block_reason(None, &config, 1_000_000, "queue proposal");
    assert!(reason.is_some());
    assert!(
        reason
            .unwrap()
            .contains("missing durable assurance lineage")
    );
}

#[test]
fn gate_block_reason_present_when_blocked_without_waiver() {
    let config = sample_config();
    let assurance = blocked_assurance_summary(2);
    let reason =
        assurance_gate_block_reason(Some(&assurance), &config, 1_000_000, "canary admission");
    assert!(reason.is_some());
    assert!(reason.unwrap().contains("canary admission"));
}

#[test]
fn validate_waiver_rejects_empty_reason() {
    let config = waiver_config();
    let signer = Ed25519Signer::from_secret_material("waiver-key");
    let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
    let mut wconfig = config.clone();
    wconfig.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
    let mut assurance = blocked_assurance_summary(2);
    let mut waiver = build_valid_waiver(&assurance, &operator_id, "waiver-key", 1000, 3600);
    waiver.reason = "   ".to_string();
    assurance.waiver = Some(waiver);
    let result = validate_assurance_waiver(&assurance, &wconfig, 2000);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("reason must not be empty"));
}

#[test]
fn validate_waiver_rejects_expired_waiver() {
    let signer = Ed25519Signer::from_secret_material("waiver-key");
    let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
    let mut config = waiver_config();
    config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
    let mut assurance = blocked_assurance_summary(2);
    let waiver = build_valid_waiver(&assurance, &operator_id, "waiver-key", 1000, 60);
    assurance.waiver = Some(waiver);
    // current_time well past expiry (1000 + 60*1000 = 61000, query at 100_000)
    let result = validate_assurance_waiver(&assurance, &config, 100_000);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("expired"));
}

#[test]
fn validate_waiver_rejects_unauthorized_operator() {
    let signer = Ed25519Signer::from_secret_material("waiver-key");
    let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
    let config = waiver_config(); // allowed_operator_ids doesn't include our signer
    let mut assurance = blocked_assurance_summary(2);
    let waiver = build_valid_waiver(&assurance, &operator_id, "waiver-key", 1000, 3600);
    assurance.waiver = Some(waiver);
    let result = validate_assurance_waiver(&assurance, &config, 2000);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not allowed"));
}

#[test]
fn validate_waiver_rejects_gap_count_above_limit() {
    let signer = Ed25519Signer::from_secret_material("waiver-key");
    let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
    let mut config = waiver_config();
    config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
    config.evolution.assurance.waiver.max_actionable_gap_count = 1; // limit is 1
    let mut assurance = blocked_assurance_summary(3); // 3 gaps > 1
    let waiver = build_valid_waiver(&assurance, &operator_id, "waiver-key", 1000, 3600);
    assurance.waiver = Some(waiver);
    let result = validate_assurance_waiver(&assurance, &config, 2000);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .contains("exceeds configured waiver limit")
    );
}

#[test]
fn validate_waiver_rejects_mismatched_gap_count() {
    let signer = Ed25519Signer::from_secret_material("waiver-key");
    let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
    let mut config = waiver_config();
    config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
    let assurance_at_sign_time = blocked_assurance_summary(2);
    let mut waiver = build_valid_waiver(
        &assurance_at_sign_time,
        &operator_id,
        "waiver-key",
        1000,
        3600,
    );
    // Tamper: the waiver was signed for 2 gaps but lineage now carries 4
    let mut assurance = blocked_assurance_summary(4);
    waiver.waived_gap_count = 2; // stale from original signing
    assurance.waiver = Some(waiver);
    let result = validate_assurance_waiver(&assurance, &config, 2000);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("waived gaps"));
}

#[test]
fn validate_waiver_rejects_tampered_signature() {
    let signer = Ed25519Signer::from_secret_material("waiver-key");
    let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
    let mut config = waiver_config();
    config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
    let mut assurance = blocked_assurance_summary(2);
    let mut waiver = build_valid_waiver(&assurance, &operator_id, "waiver-key", 1000, 3600);
    // Tamper with the signature
    waiver.signature.signature_hex = "deadbeef".repeat(16);
    assurance.waiver = Some(waiver);
    let result = validate_assurance_waiver(&assurance, &config, 2000);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .contains("signature verification failed")
    );
}

#[test]
fn validate_waiver_accepts_valid_waiver_within_window() {
    let signer = Ed25519Signer::from_secret_material("waiver-key");
    let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
    let mut config = waiver_config();
    config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
    let mut assurance = blocked_assurance_summary(2);
    let waiver = build_valid_waiver(&assurance, &operator_id, "waiver-key", 1000, 3600);
    assurance.waiver = Some(waiver);
    let result = validate_assurance_waiver(&assurance, &config, 2000);
    assert!(result.is_ok());
}

#[test]
fn rollout_state_waived_when_blocked_with_valid_waiver() {
    let signer = Ed25519Signer::from_secret_material("waiver-key");
    let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
    let mut config = waiver_config();
    config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
    let mut assurance = blocked_assurance_summary(2);
    let waiver = build_valid_waiver(&assurance, &operator_id, "waiver-key", 1000, 3600);
    assurance.waiver = Some(waiver);
    let state = assurance_rollout_state(Some(&assurance), &config, 2000);
    assert_eq!(state, EvolutionAssuranceRolloutState::Waived);
}

#[test]
fn gate_allows_when_blocked_with_valid_waiver() {
    let signer = Ed25519Signer::from_secret_material("waiver-key");
    let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
    let mut config = waiver_config();
    config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
    let mut assurance = blocked_assurance_summary(2);
    let waiver = build_valid_waiver(&assurance, &operator_id, "waiver-key", 1000, 3600);
    assurance.waiver = Some(waiver);
    let reason = assurance_gate_block_reason(Some(&assurance), &config, 2000, "canary");
    assert!(reason.is_none());
}

#[test]
fn gate_blocks_when_waiver_expired() {
    let signer = Ed25519Signer::from_secret_material("waiver-key");
    let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
    let mut config = waiver_config();
    config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
    let mut assurance = blocked_assurance_summary(2);
    let waiver = build_valid_waiver(&assurance, &operator_id, "waiver-key", 1000, 60);
    assurance.waiver = Some(waiver);
    // well past expiry
    let reason = assurance_gate_block_reason(Some(&assurance), &config, 200_000, "promotion");
    assert!(reason.is_some());
}

#[test]
fn validate_waiver_rejects_not_yet_active() {
    let signer = Ed25519Signer::from_secret_material("waiver-key");
    let operator_id = AgentId::from_public_key_hex(&signer.public_key_hex()).to_string();
    let mut config = waiver_config();
    config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
    let mut assurance = blocked_assurance_summary(2);
    let waiver = build_valid_waiver(&assurance, &operator_id, "waiver-key", 10_000, 3600);
    assurance.waiver = Some(waiver);
    // current_time before issuance
    let result = validate_assurance_waiver(&assurance, &config, 5_000);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not active until"));
}
