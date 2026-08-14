//! ZGATE-03 and ZGATE-05: what the production promotion boundary accepts as a
//! solver proof, measured end to end through persisted artifacts.
//!
//! The unit tests in `promotion.rs` reach the gate with in-crate fixtures built
//! by `assurance_summary_for_tests`, which is `#[cfg(test)] pub(crate)` and
//! deliberately unreachable from here. This file goes the other way round: it
//! writes a canary artifact to disk, opens it with the same `FileCanaryStore` the
//! runtime uses, and asserts on the concrete `ProductionPromotionError` variant
//! the harness returns -- never on log or report text for the deny cases.
//!
//! ZGATE-05's three obligations, one test each, plus two more:
//!
//! 1. denied-missing-summary: the lineage records no solver status at all.
//! 2. denied-feature-disabled: the status comes from the REAL formal-safety gate
//!    run over a `custom_z3` bundle with the solver lane switched off, not from
//!    a hand-typed literal.
//! 3. allowed-with-proof: a `proved` lineage starts a run.
//! 4. the assurance allow-list cannot authorize a promotion, which is the only
//!    form ZGATE-03 can take while `rulesets/default.yaml` is frozen.
//! 5. the operator recipe in `docs/EVOLUTION.md` actually works. Its `custom_z3`
//!    query is READ OUT OF THE DOC rather than copied, so the page and the code
//!    cannot drift. Compiled only under `--features z3`; the default lane reads
//!    the same block through test 2.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use swarm_core::config::SwarmConfig;
use swarm_runtime::canary::{
    CanaryAssignment, CanaryRecommendation, CanaryRunReport, CanaryRunStatus, FileCanaryStore,
};
use swarm_runtime::evolution::{
    DefaultFormalSafetyGate, EvolutionProposalAssuranceCoverageSummary,
    EvolutionProposalAssuranceDecision, EvolutionProposalAssuranceSolverSummary,
    EvolutionSolverProofStatus, FormalSafetyGate, StrategyGenome,
};
use swarm_runtime::promotion::{
    DefaultProductionPromotionHarness, ProductionPromotionError, ProductionPromotionStatus,
    render_production_promotion_report,
};
use swarm_runtime::replay::{
    DefaultReplayHarness, DetectorCandidateManifest, ExperimentLineage,
    load_detector_experiment_manifest,
};
use swarm_whisker::SuspiciousProcessTreeProfile;

/// `<pid>-<nanos>-<counter>`, following the collision-proof fixture identity
/// wave 3 introduced in `swarm-response`. A label plus a pid is not enough: two
/// copies of this binary running concurrently share the label, and two temp dirs
/// created inside the same nanosecond share everything but the counter.
static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "swarm-runtime-promotion-solver-gate-{label}-{}-{nanos}-{counter}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn curated_ruleset_path() -> PathBuf {
    repo_root().join("rulesets/default.yaml")
}

/// The SHIPPED config, parsed from the tracked file rather than written down
/// here. `promotion.require_solver_result_for_promotion` is absent from that
/// file, so this also carries the serde default the whole gate depends on.
fn curated_config() -> SwarmConfig {
    let raw = std::fs::read_to_string(curated_ruleset_path()).unwrap();
    serde_yaml::from_str(&raw).unwrap()
}

fn promoted_candidate() -> DetectorCandidateManifest {
    DetectorCandidateManifest::SuspiciousProcessTree {
        strategy_id: "office_python_parent_broadening".to_string(),
        description: "broaden parent set with python".to_string(),
        profile: SuspiciousProcessTreeProfile {
            suspicious_parents: vec![
                "winword".to_string(),
                "excel".to_string(),
                "outlook".to_string(),
                "python".to_string(),
            ],
            ..SuspiciousProcessTreeProfile::default()
        },
    }
}

/// One assurance lineage, as JSON.
///
/// `EvolutionProposalAssuranceSummary` has private `decision` and `provenance`
/// fields and no public constructor -- that is the fabricated-attestation fix,
/// and it is why this file cannot build one directly. Deserialization is the
/// legitimate second route (the summary a promotion reads always came off disk),
/// so this test writes the artifact an operator's canary store would hold and
/// lets the store restore it. The gate must hold for a hand-written artifact too.
fn assurance_lineage_json(
    decision: EvolutionProposalAssuranceDecision,
    solver: EvolutionProposalAssuranceSolverSummary,
) -> serde_json::Value {
    let coverage = EvolutionProposalAssuranceCoverageSummary {
        detector: "suspicious_process_tree".to_string(),
        suite_name: Some("evasion-breadth-v1".to_string()),
        corpus_version: Some("2026-04-03".to_string()),
        required_catch_rate: 0.25,
        actual_catch_rate: Some(1.0),
        actionable_gap_count: 0,
    };
    serde_json::json!({
        "decision": serde_json::to_value(decision).unwrap(),
        "coverage": serde_json::to_value(coverage).unwrap(),
        "solver": serde_json::to_value(solver).unwrap(),
    })
}

/// A completed, promotion-ready canary run carrying `assurance`, persisted
/// through the real store so `start_run` reads it back the way production does.
fn persist_ready_canary(
    root: &Path,
    config: &SwarmConfig,
    assurance: serde_json::Value,
) -> (PathBuf, String) {
    let candidate = promoted_candidate();
    let baseline_strategy_id = config
        .canary
        .strategy_id
        .clone()
        .unwrap_or_else(|| config.detection.strategy.clone());
    let report = CanaryRunReport {
        run_id: format!(
            "canary:{}:{}:1700000000000",
            config.canary.slot_id,
            candidate.strategy_id()
        ),
        slot_id: config.canary.slot_id.clone(),
        created_at_ms: 1_700_000_000_000,
        updated_at_ms: 1_700_000_000_100,
        status: CanaryRunStatus::Completed,
        recommendation: CanaryRecommendation::ReadyForPromotionReview,
        assignment: CanaryAssignment {
            experiment_id: format!("experiment:zgate:{}", candidate.strategy_id()),
            experiment_name: "zgate".to_string(),
            experiment_path: "experiments/office-baseline-control.yaml".to_string(),
            suite_name: "hellcat_office_v1".to_string(),
            corpus_version: "2026-04-03".to_string(),
            baseline_strategy_id: baseline_strategy_id.clone(),
            candidate_strategy_id: candidate.strategy_id().to_string(),
            candidate_description: candidate.description().to_string(),
            candidate: candidate.clone(),
            lineage: ExperimentLineage {
                parent_strategy_id: baseline_strategy_id,
                mutation: "broaden_parents".to_string(),
                rationale: "zgate fixture".to_string(),
            },
            verification_id: format!("verification:zgate:{}", candidate.strategy_id()),
            verification_passed: true,
            shadow_id: format!("shadow:zgate:{}", candidate.strategy_id()),
            shadow_passed: true,
            // Injected below, because it cannot be constructed here.
            assurance: None,
            canary: config.canary.clone(),
        },
        metrics: Default::default(),
        threshold_results: Vec::new(),
        observations: Vec::new(),
        recent_candidate_findings: Vec::new(),
        rollback_history: Vec::new(),
    };

    let mut value = serde_json::to_value(&report).unwrap();
    value["assignment"]["assurance"] = assurance;
    let report: CanaryRunReport = serde_json::from_value(value).unwrap();

    let canaries_dir = root.join("canaries");
    let store = FileCanaryStore::open(&canaries_dir).unwrap();
    let record = store.persist(&report).unwrap();
    (canaries_dir, record.run_id)
}

fn promotion_harness(root: &Path, config: SwarmConfig) -> DefaultProductionPromotionHarness {
    DefaultProductionPromotionHarness::from_config(
        curated_ruleset_path(),
        config,
        root.join("promotions"),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// 1. denied-missing-summary
// ---------------------------------------------------------------------------

/// No solver status at all: the shape the curated ruleset actually produces,
/// because its one invariant bundle declares no `custom_z3` invariant and solver
/// artifacts come only from the `custom_z3` arms.
#[test]
fn promotion_is_denied_when_the_lineage_records_no_solver_summary() {
    let root = unique_temp_dir("missing-summary");
    let config = curated_config();
    assert!(
        config.promotion.require_solver_result_for_promotion,
        "the shipped ruleset must resolve the gate to enabled, or this test proves nothing"
    );
    let (canaries_dir, run_id) = persist_ready_canary(
        &root,
        &config,
        assurance_lineage_json(
            EvolutionProposalAssuranceDecision::Passed,
            EvolutionProposalAssuranceSolverSummary {
                required: false,
                status: None,
                allowed_statuses: vec![EvolutionSolverProofStatus::Proved],
            },
        ),
    );

    let error = promotion_harness(&root, config)
        .start_run(&canaries_dir, &run_id)
        .unwrap_err();

    assert!(
        matches!(
            error,
            ProductionPromotionError::SolverResultMissing {
                recorded_status: None,
                ref promoted_strategy_id,
                ..
            } if promoted_strategy_id == "office_python_parent_broadening"
        ),
        "got {error:?}"
    );
}

// ---------------------------------------------------------------------------
// 2. denied-feature-disabled
// ---------------------------------------------------------------------------

/// The `custom_z3` invariant READ OUT OF `docs/EVOLUTION.md`, not copied from it.
///
/// A recipe nobody executes is a guess, and a recipe executed from a copy drifts
/// away from the page an operator actually reads. So the bundle below is built
/// from the documented snippet itself: edit the doc and this is what runs.
///
/// `office-baseline-control` carries `medium_confidence_threshold: 0.7`, so the
/// documented assertion is UNSAT and the property holds -- the solver proves by
/// refuting the bad case.
fn recipe_invariant_from_docs() -> String {
    let doc = std::fs::read_to_string(repo_root().join("docs/EVOLUTION.md")).unwrap();
    let blocks = doc
        .split("```yaml")
        .skip(1)
        .filter_map(|rest| rest.split("```").next())
        .filter(|body| body.contains("type: custom_z3"))
        .map(|body| body.trim_start_matches('\n').to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        blocks.len(),
        1,
        "docs/EVOLUTION.md must contain exactly one ```yaml block declaring a \
         custom_z3 invariant -- the recipe this test executes. Found {}",
        blocks.len()
    );
    blocks.into_iter().next().unwrap()
}

/// Run the REAL formal-safety gate over the documented `custom_z3` bundle and
/// return what this build records: `(report.passed, solver status)`.
async fn recipe_bundle_solver_result(
    root: &Path,
    enable_z3: bool,
) -> (bool, Option<EvolutionSolverProofStatus>) {
    let bundle_path = root.join("zgate-custom-z3.yaml");
    std::fs::write(
        &bundle_path,
        format!(
            concat!(
                "schema_version: 1\n",
                "name: zgate_recipe_bundle\n",
                "description: the custom_z3 invariant docs/EVOLUTION.md tells operators to add\n",
                "invariants:\n",
                "{}",
            ),
            recipe_invariant_from_docs()
        ),
    )
    .unwrap();

    let config_path = curated_ruleset_path();
    let mut config = curated_config();
    config.evolution.safety_gate.invariant_bundle_paths = vec![bundle_path.display().to_string()];
    config.evolution.safety_gate.enable_z3 = enable_z3;
    config.evolution.paths.evolution_proof_results_dir = root.join("proofs").display().to_string();

    let experiment_path = repo_root().join("experiments/office-baseline-control.yaml");
    let replay =
        DefaultReplayHarness::from_config(&config_path, config.clone(), root.join("replay"))
            .unwrap();
    let verification = replay
        .evaluate_verification_path(&experiment_path, root.join("verifications"))
        .await
        .unwrap();
    let (_, shadow) = replay
        .evaluate_experiment_and_shadow_path(
            &experiment_path,
            root.join("experiments"),
            root.join("shadows"),
        )
        .await
        .unwrap();
    let experiment = load_detector_experiment_manifest(&experiment_path).unwrap();

    let genome = StrategyGenome {
        strategy_id: experiment.candidate.strategy_id().to_string(),
        experiment_path: experiment_path.clone(),
        experiment,
        verification: verification.report,
        shadow: shadow.report,
    };
    let report = DefaultFormalSafetyGate::from_config(config_path, config)
        .verify(&genome)
        .unwrap();

    (
        report.passed,
        report.solver_summary.map(|summary| summary.status),
    )
}

/// A `custom_z3` bundle evaluated with the solver lane off must be refused at
/// promotion through the SAME variant as an absent solver result: a stub is not
/// evidence. `recorded_status` is what keeps the audit record able to tell the
/// two apart without the gate treating them differently.
///
/// The two build lanes disable the solver in different places and must land on
/// the same status, so the assertion is not lane-specific:
///
/// * default build (no `z3` feature): the BUILD has no solver, so the config asks
///   for one (`enable_z3 = true`) and the `#[cfg(not(feature = "z3"))]` arm is
///   what refuses. This is the ZGATE-03 case.
/// * `--features z3` (the `solver-z3` CI job): the build HAS a solver, so the
///   CONFIG switches it off (`enable_z3 = false`) and the runtime arm refuses.
#[tokio::test]
async fn promotion_is_denied_when_the_solver_lane_was_disabled() {
    let root = unique_temp_dir("feature-disabled");
    let (passed, status) = recipe_bundle_solver_result(&root, cfg!(not(feature = "z3"))).await;
    // The verdict fails closed one layer up as well. Asserted here so a change
    // that quietly made a disabled solver "pass" upstream is caught rather than
    // making the promotion assertion below vacuous.
    assert!(
        !passed,
        "a solver that never ran must not produce a passing formal-safety report"
    );
    assert_eq!(
        status,
        Some(EvolutionSolverProofStatus::Disabled),
        "a disabled solver lane must record `disabled`, not nothing and not a proof"
    );

    let config = curated_config();
    let (canaries_dir, run_id) = persist_ready_canary(
        &root,
        &config,
        assurance_lineage_json(
            EvolutionProposalAssuranceDecision::Passed,
            EvolutionProposalAssuranceSolverSummary {
                required: false,
                status,
                allowed_statuses: vec![EvolutionSolverProofStatus::Proved],
            },
        ),
    );

    let error = promotion_harness(&root, config)
        .start_run(&canaries_dir, &run_id)
        .unwrap_err();

    assert!(
        matches!(
            error,
            ProductionPromotionError::SolverResultMissing {
                recorded_status: Some(EvolutionSolverProofStatus::Disabled),
                ..
            }
        ),
        "got {error:?}"
    );
}

// ---------------------------------------------------------------------------
// 3. allowed-with-proof
// ---------------------------------------------------------------------------

/// The gate is refusable AND satisfiable. Without this the three deny tests
/// above would still pass against a gate that refused unconditionally.
#[test]
fn promotion_is_allowed_when_the_lineage_records_a_proved_solver_result() {
    let root = unique_temp_dir("proved");
    let config = curated_config();
    let (canaries_dir, run_id) = persist_ready_canary(
        &root,
        &config,
        assurance_lineage_json(
            EvolutionProposalAssuranceDecision::Passed,
            EvolutionProposalAssuranceSolverSummary {
                required: true,
                status: Some(EvolutionSolverProofStatus::Proved),
                allowed_statuses: vec![EvolutionSolverProofStatus::Proved],
            },
        ),
    );

    let lookup = promotion_harness(&root, config)
        .start_run(&canaries_dir, &run_id)
        .unwrap();

    assert_eq!(lookup.report.status, ProductionPromotionStatus::Active);
    assert_eq!(
        lookup
            .report
            .assignment
            .assurance
            .as_ref()
            .and_then(|assurance| assurance.solver.status),
        Some(EvolutionSolverProofStatus::Proved)
    );
    // ZGATE-04's operator-facing half, checked only on the ALLOW path: the deny
    // tests above assert on variants precisely so no verdict here rests on text.
    assert!(
        render_production_promotion_report(&lookup.report).contains("Solver result: proved"),
        "the promotion report must state the evidence it promoted on"
    );
}

/// THE DOCUMENTED RECIPE, EXECUTED.
///
/// `docs/EVOLUTION.md` tells an operator that adding its documented `custom_z3`
/// invariant to their admission bundle, setting `enable_z3: true` and building
/// with the `z3` feature yields a `proved` result that promotes. This runs that,
/// with the query text read out of the doc itself: real solver, real promotion
/// harness, so the page cannot promise something the code will not do.
///
/// Only compiled under `--features z3`, i.e. in the `solver-z3` CI job -- the
/// default build has no solver and its half of the story is the test above.
#[cfg(feature = "z3")]
#[tokio::test]
async fn the_documented_recipe_produces_a_proof_that_promotes() {
    let root = unique_temp_dir("recipe");
    let (passed, status) = recipe_bundle_solver_result(&root, true).await;
    assert!(
        passed,
        "the documented recipe must yield a PASSING formal-safety report"
    );
    assert_eq!(
        status,
        Some(EvolutionSolverProofStatus::Proved),
        "the documented recipe must yield `proved`, which is the only status the \
         promotion gate accepts"
    );

    let config = curated_config();
    let (canaries_dir, run_id) = persist_ready_canary(
        &root,
        &config,
        assurance_lineage_json(
            EvolutionProposalAssuranceDecision::Passed,
            EvolutionProposalAssuranceSolverSummary {
                required: true,
                status,
                allowed_statuses: vec![EvolutionSolverProofStatus::Proved],
            },
        ),
    );

    let lookup = promotion_harness(&root, config)
        .start_run(&canaries_dir, &run_id)
        .unwrap();

    assert_eq!(lookup.report.status, ProductionPromotionStatus::Active);
    assert!(
        render_production_promotion_report(&lookup.report)
            .contains("Solver result: proved | required_for_promotion=true"),
        "the recipe's promotion report must state the proof it promoted on"
    );
}

// ---------------------------------------------------------------------------
// 4. ZGATE-03's implementable half: the assurance allow-list is not authority
// ---------------------------------------------------------------------------

/// `rulesets/default.yaml` lists `disabled` among
/// `evolution.assurance.allowed_solver_statuses`, and that file cannot be edited
/// here -- its sha256 is inside the ed25519-signed `rulesets/attestation.json`
/// and the signing key is deliberately absent from this repository. So ZGATE-03
/// cannot be closed by removing the entry. It is closed by making the promotion
/// gate provably indifferent to it.
///
/// The first assertion reads the shipped file so the test cannot go vacuous: if
/// `disabled` ever leaves the allow-list, this fails and says the premise moved.
/// The second gives the lineage the exact allow-list the shipped ruleset carries
/// AND records the status as allowed, then requires the refusal anyway.
///
/// If someone "simplifies" `promotion_solver_block` to consult
/// `config.evolution.assurance.allowed_solver_statuses` -- the field whose name
/// invites exactly that -- a disabled stub becomes a passing proof in every
/// shipped deployment, and this is the test that fails.
#[test]
fn the_assurance_allow_list_cannot_authorize_a_promotion() {
    let raw = std::fs::read_to_string(curated_ruleset_path()).unwrap();
    let curated: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
    let allowed = curated["evolution"]["assurance"]["allowed_solver_statuses"]
        .as_sequence()
        .expect("the curated ruleset must declare allowed_solver_statuses")
        .iter()
        .filter_map(|entry| entry.as_str().map(str::to_string))
        .collect::<Vec<_>>();
    assert!(
        allowed.iter().any(|status| status == "disabled"),
        "this test exists because the frozen ruleset allows `disabled` at the \
         ASSURANCE layer; the shipped list is now {allowed:?}, so re-derive the \
         posture rather than re-pointing the assertion"
    );

    let root = unique_temp_dir("allow-list-is-not-authority");
    let mut config = curated_config();
    // Belt and braces: the promotion gate does not read this field, and the
    // assertion below is what proves it.
    config.evolution.assurance.allowed_solver_statuses = vec![
        swarm_core::config::EvolutionAssuranceSolverStatusConfig::Proved,
        swarm_core::config::EvolutionAssuranceSolverStatusConfig::Disabled,
    ];
    let (canaries_dir, run_id) = persist_ready_canary(
        &root,
        &config,
        assurance_lineage_json(
            EvolutionProposalAssuranceDecision::Passed,
            EvolutionProposalAssuranceSolverSummary {
                required: false,
                status: Some(EvolutionSolverProofStatus::Disabled),
                // Mirrors the shipped ruleset: `disabled` IS an allowed
                // assurance status, recorded as such in the durable lineage.
                allowed_statuses: vec![
                    EvolutionSolverProofStatus::Proved,
                    EvolutionSolverProofStatus::Disabled,
                ],
            },
        ),
    );

    let error = promotion_harness(&root, config)
        .start_run(&canaries_dir, &run_id)
        .unwrap_err();

    assert!(
        matches!(
            error,
            ProductionPromotionError::SolverResultMissing {
                recorded_status: Some(EvolutionSolverProofStatus::Disabled),
                ..
            }
        ),
        "an assurance policy that allows `disabled` must not make a disabled \
         solver promotable, got {error:?}"
    );
}
