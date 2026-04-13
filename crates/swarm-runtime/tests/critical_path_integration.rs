use async_trait::async_trait;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::SwarmConfig;
use swarm_core::types::{AgentId, ResponseAction};
use swarm_policy::static_gate::StaticApprovalGate;
use swarm_policy::{
    ActionRequest, ApprovalContext, ApprovalError, ApprovalGate, CapabilityLease, PolicyDecision,
};
use swarm_response::adapters::SandboxExecutor;
use swarm_runtime::StrategyProposalRouteError;
use swarm_runtime::config::load_config;
use swarm_runtime::control::build_composite_detector;
use swarm_runtime::dispatcher::{StrategyProposalOutcome, StrategyProposalRoute};
use swarm_runtime::drafting::{DefaultEvolutionDraftingHarness, EvolutionDraftCreateRequest};
use swarm_runtime::evasion_coverage::{
    actionable_gaps_for_detector, evaluate_repo_evasion_coverage,
};
use swarm_runtime::evolution::DefaultEvolutionProofHarness;
use swarm_runtime::ingest::IngestState;
use swarm_runtime::investigation::{
    InvestigationOutcome, InvestigationStrategy, SummaryInvestigator,
};
use swarm_runtime::mutation::{
    DefaultEvolutionMutationHarness, EvolutionEvasionGapFocus, EvolutionEvasionPressureInput,
    EvolutionMutationProfileOverrides, EvolutionMutationSpecCreateRequest,
    EvolutionMutationVariantCreateRequest,
};
use swarm_runtime::replay::{
    DefaultReplayHarness, ReplayScenarioInput, ReplayScenarioStep, load_scenario_manifest,
};
use swarm_runtime::service::{ConfiguredRuntimeStack, EventExecutionContext};
use swarm_runtime::strategy::DefaultStrategyScorecardHarness;
use swarm_whisker::{ProcessStartEvent, TelemetryEvent, TelemetryPayload};

#[derive(Clone)]
struct DenyAllGate;

impl ApprovalGate for DenyAllGate {
    fn evaluate(
        &self,
        _request: &ActionRequest,
        _context: &ApprovalContext,
    ) -> Result<PolicyDecision, ApprovalError> {
        Ok(PolicyDecision::deny("denied for integration coverage"))
    }

    fn issue_lease(
        &self,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<CapabilityLease, ApprovalError> {
        Ok(CapabilityLease {
            capability_id: format!("deny:{}", request.hunt_id.0),
            expires_at_ms: context.now_ms + 1_000,
            action: request.action.kind().to_string(),
            scope: None,
        })
    }
}

#[derive(Clone)]
struct NoOpInvestigation;

#[async_trait]
impl InvestigationStrategy for NoOpInvestigation {
    fn id(&self) -> &str {
        "no_op"
    }

    async fn investigate(
        &self,
        _replay: &swarm_spine::ReplayBundle,
    ) -> Result<InvestigationOutcome, String> {
        Ok(InvestigationOutcome {
            summary: "no-op".to_string(),
            evidence_points: Vec::new(),
            correlation_keys: Vec::new(),
            candidate_interpretations: Vec::new(),
            vote_lineage: Vec::new(),
        })
    }
}

fn config() -> Result<SwarmConfig, Box<dyn std::error::Error>> {
    Ok(load_config(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../rulesets/default.yaml"
    ))?)
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn office_control_experiment() -> PathBuf {
    repo_root().join("experiments/office-baseline-control.yaml")
}

fn temp_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "swarm-runtime-critical-path-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn configure_evolution_paths(config: &mut SwarmConfig, root: &Path) {
    config.evolution.enabled = true;
    config.canary.enabled = true;
    config.evolution.paths.replay_results_dir = root.join("replay").display().to_string();
    config.evolution.paths.experiment_results_dir = root.join("experiments").display().to_string();
    config.evolution.paths.verification_results_dir =
        root.join("verifications").display().to_string();
    config.evolution.paths.shadow_results_dir = root.join("shadows").display().to_string();
    config.evolution.paths.strategy_memory_results_dir =
        root.join("strategy-memory").display().to_string();
    config.evolution.paths.strategy_scorecard_results_dir =
        root.join("strategy-scorecards").display().to_string();
    config.evolution.paths.evolution_proof_results_dir =
        root.join("evolution-proofs").display().to_string();
    config.evolution.paths.evolution_queue_results_dir =
        root.join("evolution-queue").display().to_string();
    config.evolution.paths.evolution_selection_results_dir =
        root.join("evolution-selections").display().to_string();
    config.evolution.paths.evolution_bridge_results_dir = root
        .join("evolution-selection-bridges")
        .display()
        .to_string();
    config.evolution.paths.evolution_handoff_results_dir =
        root.join("evolution-handoffs").display().to_string();
    config.evolution.paths.evolution_pressure_results_dir =
        root.join("evolution-pressures").display().to_string();
    config.evolution.paths.evolution_draft_results_dir =
        root.join("evolution-drafts").display().to_string();
    config.evolution.paths.evolution_draft_promotion_results_dir = root
        .join("evolution-draft-promotions")
        .display()
        .to_string();
    config.evolution.paths.evolution_materialization_results_dir = root
        .join("evolution-materializations")
        .display()
        .to_string();
    config.evolution.paths.evolution_validation_results_dir = root
        .join("evolution-validation-bundles")
        .display()
        .to_string();
    config.evolution.paths.evolution_reconciliation_results_dir =
        root.join("evolution-reconciliations").display().to_string();
    config.evolution.paths.evolution_mutation_results_dir =
        root.join("evolution-mutations").display().to_string();
    config
        .evolution
        .paths
        .evolution_mutation_materialization_batch_results_dir = root
        .join("evolution-mutation-materialization-batches")
        .display()
        .to_string();
    config
        .evolution
        .paths
        .evolution_mutation_validation_batch_results_dir = root
        .join("evolution-mutation-validation-batches")
        .display()
        .to_string();
    config.evolution.paths.evolution_ranking_results_dir =
        root.join("evolution-rankings").display().to_string();
    config.evolution.paths.evolution_population_results_dir =
        root.join("evolution-population").display().to_string();
    config.evolution.paths.canary_results_dir = root.join("canaries").display().to_string();
}

fn suspicious_event(event_id: &str) -> TelemetryEvent {
    TelemetryEvent {
        source: "integration".to_string(),
        event_id: event_id.to_string(),
        timestamp: 1_700_000_000_000,
        host_id: Some("host-1".to_string()),
        payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
            parent_process: "winword".to_string(),
            process_name: "powershell".to_string(),
            command_line: "powershell.exe -enc AAA=".to_string(),
            user: Some("alice".to_string()),
            executable_path: None,
            signer: None,
            signature_valid: None,
        }),
    }
}

fn benign_event() -> TelemetryEvent {
    TelemetryEvent {
        source: "integration".to_string(),
        event_id: "benign-evt".to_string(),
        timestamp: 1_700_000_000_001,
        host_id: Some("host-2".to_string()),
        payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
            parent_process: "explorer".to_string(),
            process_name: "notepad".to_string(),
            command_line: "notepad.exe notes.txt".to_string(),
            user: Some("bob".to_string()),
            executable_path: None,
            signer: None,
            signature_valid: None,
        }),
    }
}

fn execution_context() -> (AgentId, ApprovalContext, ed25519_dalek::SigningKey) {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    (
        AgentId::from_verifying_key(&signing_key.verifying_key()),
        ApprovalContext {
            live_mode: false,
            receipt_chain: vec!["seed-receipt".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_000_500,
        },
        signing_key,
    )
}

fn config_with_strategy(strategy: &str) -> Result<SwarmConfig, Box<dyn std::error::Error>> {
    let mut cfg = config()?;
    cfg.detection.strategy = strategy.to_string();
    Ok(cfg)
}

fn load_single_event_scenario(
    relative_path: &str,
) -> Result<
    (
        swarm_runtime::replay::ReplayScenarioMetadata,
        ReplayScenarioStep,
    ),
    Box<dyn std::error::Error>,
> {
    let scenario = load_scenario_manifest(format!(
        "{}/../../scenarios/{relative_path}",
        env!("CARGO_MANIFEST_DIR")
    ))?;
    let metadata = scenario.manifest.metadata.clone();
    let step = match scenario.manifest.input {
        ReplayScenarioInput::Events { events } => events
            .into_iter()
            .next()
            .ok_or("scenario fixture had no events")?,
        ReplayScenarioInput::ReplayBundles { .. } => {
            return Err("expected event-based scenario fixture".into());
        }
    };
    Ok((metadata, step))
}

async fn run_scenario_with_strategy(
    strategy: &str,
    relative_path: &str,
) -> Result<
    Option<swarm_runtime::service::PersistedReplayBundleWithInvestigation>,
    Box<dyn std::error::Error>,
> {
    let cfg = config_with_strategy(strategy)?;
    let detector = build_composite_detector(&cfg.detection)?;
    let stack = ConfiguredRuntimeStack::from_components(
        cfg,
        StaticApprovalGate::default(),
        SandboxExecutor,
        SummaryInvestigator,
    )?;
    let (_, step) = load_single_event_scenario(relative_path)?;
    let (agent_id, approval, signing_key) = execution_context();
    Ok(stack
        .process_event(
            &detector,
            &step.event,
            EventExecutionContext {
                agent_id: &agent_id,
                approval: &approval,
                signing_key: &signing_key,
            },
            |_| Some(step.action.clone()),
        )
        .await?)
}

#[tokio::test]
async fn full_critical_path_detect_to_receipt() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config()?;
    let detector = build_composite_detector(&cfg.detection)?;
    let stack = ConfiguredRuntimeStack::from_components(
        cfg,
        StaticApprovalGate::default(),
        SandboxExecutor,
        SummaryInvestigator,
    )?;
    let event = suspicious_event("suspicious-evt");
    let (agent_id, approval, signing_key) = execution_context();
    let result = stack
        .process_event(
            &detector,
            &event,
            EventExecutionContext {
                agent_id: &agent_id,
                approval: &approval,
                signing_key: &signing_key,
            },
            |_| {
                Some(ResponseAction::BlockEgress {
                    target: "198.51.100.20".to_string(),
                })
            },
        )
        .await?
        .ok_or("expected persisted replay bundle")?;

    assert!(!result.replay.bundle.findings.is_empty());
    assert!(!result.replay.bundle.deposits.is_empty());
    assert!(matches!(
        result.replay.bundle.action_request.action,
        ResponseAction::BlockEgress { .. }
    ));
    assert_ne!(
        result.replay.bundle.audit.policy.verdict,
        swarm_policy::PolicyVerdict::Deny
    );
    assert!(matches!(
        result.replay.bundle.audit.response,
        swarm_spine::AuditResponseRecord::Success(_)
    ));
    assert!(!result.replay.record.bundle_id.is_empty());
    assert_eq!(result.replay.record.hunt_id, "suspicious-evt");
    Ok(())
}

#[tokio::test]
async fn benign_event_produces_no_bundle() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config()?;
    let detector = build_composite_detector(&cfg.detection)?;
    let stack = ConfiguredRuntimeStack::from_components(
        cfg,
        StaticApprovalGate::default(),
        SandboxExecutor,
        NoOpInvestigation,
    )?;
    let event = benign_event();
    let (agent_id, approval, signing_key) = execution_context();
    let result = stack
        .process_event(
            &detector,
            &event,
            EventExecutionContext {
                agent_id: &agent_id,
                approval: &approval,
                signing_key: &signing_key,
            },
            |_| {
                Some(ResponseAction::BlockEgress {
                    target: "198.51.100.20".to_string(),
                })
            },
        )
        .await?;

    assert!(result.is_none());
    Ok(())
}

#[tokio::test]
async fn full_path_with_scenario_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let mut cfg = config_with_strategy("suspicious_process_tree")?;
    cfg.audit.bundle_store = swarm_core::config::BundleStoreConfig::Memory;
    cfg.investigation.enabled = true;
    cfg.investigation.bundle_store = swarm_core::config::BundleStoreConfig::Memory;
    cfg.correlation.enabled = true;
    cfg.correlation.incident_store = swarm_core::config::BundleStoreConfig::Memory;
    let detector = build_composite_detector(&cfg.detection)?;
    let stack = ConfiguredRuntimeStack::from_components(
        cfg,
        StaticApprovalGate::default(),
        SandboxExecutor,
        SummaryInvestigator,
    )?;
    let (_, step) = load_single_event_scenario("office-dropper-correlation.yaml")?;
    let (agent_id, approval, signing_key) = execution_context();
    let result = stack
        .process_event(
            &detector,
            &step.event,
            EventExecutionContext {
                agent_id: &agent_id,
                approval: &approval,
                signing_key: &signing_key,
            },
            |_| Some(step.action.clone()),
        )
        .await?
        .ok_or("expected scenario bundle")?;

    assert!(!result.replay.bundle.findings.is_empty());
    assert!(!result.replay.bundle.deposits.is_empty());
    assert!(matches!(
        result.replay.bundle.audit.response,
        swarm_spine::AuditResponseRecord::Success(_)
    ));
    assert_eq!(result.replay.record.hunt_id, "hunt-evt-1");

    let investigation = result
        .investigation
        .as_ref()
        .ok_or("expected queued investigation")?;

    let status = stack.operator_review_status(&detector).await?;
    assert!(status.async_lane.enabled);
    assert!(status.async_lane.recent_investigations >= 1);
    assert_eq!(
        status.async_lane.latest_investigation_id.as_deref(),
        Some(investigation.investigation_id.as_str())
    );
    Ok(())
}

#[test]
fn composite_detector_factory_covers_all_runtime_strategies()
-> Result<(), Box<dyn std::error::Error>> {
    for strategy in [
        "suspicious_process_tree",
        "dns_exfiltration",
        "lateral_movement",
        "credential_access",
        "suspicious_scripting",
        "persistence",
        "supply_chain",
        "network_connect",
    ] {
        let cfg = config_with_strategy(strategy)?;
        assert!(
            build_composite_detector(&cfg.detection).is_ok(),
            "{strategy}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn dns_tunneling_fixture_produces_dns_exfiltration_finding()
-> Result<(), Box<dyn std::error::Error>> {
    let (metadata, _) = load_single_event_scenario("dns-tunneling-exfil.yaml")?;
    assert!(
        metadata
            .techniques
            .iter()
            .any(|technique| technique == "T1071.004")
    );

    let result = run_scenario_with_strategy("dns_exfiltration", "dns-tunneling-exfil.yaml")
        .await?
        .ok_or("expected dns replay bundle")?;

    assert_eq!(
        result.replay.bundle.findings[0].strategy_id,
        "dns_exfiltration"
    );
    Ok(())
}

#[tokio::test]
async fn wmi_fixture_produces_lateral_movement_finding() -> Result<(), Box<dyn std::error::Error>> {
    let (metadata, _) = load_single_event_scenario("lateral-movement-wmi.yaml")?;
    assert!(
        metadata
            .techniques
            .iter()
            .any(|technique| technique == "T1047")
    );

    let result = run_scenario_with_strategy("lateral_movement", "lateral-movement-wmi.yaml")
        .await?
        .ok_or("expected wmi replay bundle")?;

    assert_eq!(
        result.replay.bundle.findings[0].strategy_id,
        "lateral_movement"
    );
    Ok(())
}

#[tokio::test]
async fn lsass_fixture_produces_credential_access_finding() -> Result<(), Box<dyn std::error::Error>>
{
    let (metadata, _) = load_single_event_scenario("credential-access-lsass.yaml")?;
    assert!(
        metadata
            .techniques
            .iter()
            .any(|technique| technique == "T1003.001")
    );

    let result = run_scenario_with_strategy("credential_access", "credential-access-lsass.yaml")
        .await?
        .ok_or("expected credential replay bundle")?;

    assert_eq!(
        result.replay.bundle.findings[0].strategy_id,
        "credential_access"
    );
    Ok(())
}

#[tokio::test]
async fn encoded_powershell_fixture_produces_suspicious_scripting_finding()
-> Result<(), Box<dyn std::error::Error>> {
    let (metadata, _) = load_single_event_scenario("scripting-encoded-powershell.yaml")?;
    assert!(
        metadata
            .techniques
            .iter()
            .any(|technique| technique == "T1059.001")
    );

    let result =
        run_scenario_with_strategy("suspicious_scripting", "scripting-encoded-powershell.yaml")
            .await?
            .ok_or("expected scripting replay bundle")?;

    assert_eq!(
        result.replay.bundle.findings[0].strategy_id,
        "suspicious_scripting"
    );
    Ok(())
}

#[tokio::test]
async fn benign_dns_fixture_produces_no_detections() -> Result<(), Box<dyn std::error::Error>> {
    let result = run_scenario_with_strategy("dns_exfiltration", "benign-dns-baseline.yaml").await?;
    assert!(result.is_none());
    Ok(())
}

#[tokio::test]
async fn evasion_to_canary_routes_gap_driven_candidate_into_existing_lane()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("evasion-canary");
    let config_path = repo_root().join("rulesets/default.yaml");
    let mut config = load_config(&config_path)?;
    configure_evolution_paths(&mut config, &root);

    let snapshot = evaluate_repo_evasion_coverage(&config, &repo_root())?;
    let measured_gaps = actionable_gaps_for_detector(&snapshot, "suspicious_process_tree");
    assert!(
        !measured_gaps.is_empty(),
        "suspicious_process_tree should have at least one measurable evasion gap"
    );
    let evasion_input = EvolutionEvasionPressureInput {
        detector: "suspicious_process_tree".to_string(),
        suite_name: snapshot.suite_name.clone(),
        suite_path: PathBuf::from(snapshot.suite_path.clone()),
        corpus_version: snapshot.corpus_version.clone(),
        gaps: measured_gaps
            .into_iter()
            .map(|gap| EvolutionEvasionGapFocus {
                threat_class: gap.threat_class,
                total_payloads: gap.total_payloads,
                missed_payloads: gap.missed_payloads,
                catch_rate: gap.catch_rate,
                actionable_techniques: gap.actionable_techniques,
            })
            .collect(),
    };

    let state = IngestState::from_config(&config_path, config.clone())?;
    let replay = DefaultReplayHarness::from_config(
        &config_path,
        config.clone(),
        &config.evolution.paths.replay_results_dir,
    )?;
    let verification = replay
        .evaluate_verification_path(
            office_control_experiment(),
            &config.evolution.paths.verification_results_dir,
        )
        .await?;
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        &config_path,
        config.clone(),
        &config.evolution.paths.strategy_memory_results_dir,
        &config.evolution.paths.strategy_scorecard_results_dir,
    )?;
    let scorecard = scorecards
        .create_scorecard(
            &replay,
            office_control_experiment(),
            &config.evolution.paths.experiment_results_dir,
            &config.evolution.paths.verification_results_dir,
            &verification.report.verification_id,
        )
        .await?;
    let drafting = DefaultEvolutionDraftingHarness::from_config(
        &config_path,
        config.clone(),
        &config.evolution.paths.evolution_pressure_results_dir,
        &config.evolution.paths.evolution_draft_results_dir,
        &config.evolution.paths.evolution_draft_promotion_results_dir,
        &config.evolution.paths.evolution_materialization_results_dir,
        &config.evolution.paths.evolution_validation_results_dir,
        &config.evolution.paths.evolution_reconciliation_results_dir,
    )?;
    let mutation = DefaultEvolutionMutationHarness::from_path(
        &config.evolution.paths.evolution_mutation_results_dir,
        &config
            .evolution
            .paths
            .evolution_mutation_materialization_batch_results_dir,
        &config
            .evolution
            .paths
            .evolution_mutation_validation_batch_results_dir,
        &config.evolution.paths.evolution_ranking_results_dir,
    )?;
    let proofs = DefaultEvolutionProofHarness::from_config(
        &config_path,
        config.clone(),
        &config.evolution.paths.evolution_proof_results_dir,
    )?;
    let pressure =
        drafting.create_pressure_from_scorecard(&scorecards, &scorecard.report.scorecard_id)?;
    let draft = drafting.create_draft(EvolutionDraftCreateRequest {
        pressure_id: pressure.report.pressure_id.clone(),
        strategy_id: "suspicious_process_tree".to_string(),
        strategy_description: "evasion canary fixture".to_string(),
        mutation: "guided_evasion_seed".to_string(),
        rationale: "prove that a measured evasion gap survives to canary routing".to_string(),
    })?;
    let spec = mutation.create_mutation_spec(
        &drafting,
        EvolutionMutationSpecCreateRequest {
            draft_id: Some(draft.report.draft_id.clone()),
            materialization_id: None,
            base_experiment_path: Some(office_control_experiment()),
            rationale: "carry measured evasion pressure into canary admission".to_string(),
        },
    )?;
    let spec = mutation.append_variant(
        &spec.report.mutation_spec_id,
        EvolutionMutationVariantCreateRequest {
            variant_id: Some("evasion-threshold-nudge".to_string()),
            strategy_id: "office_router_candidate".to_string(),
            strategy_description: "Runtime router evasion candidate".to_string(),
            mutation: "lower_confidence_thresholds".to_string(),
            rationale: "target the measured evasion miss".to_string(),
            overrides: EvolutionMutationProfileOverrides {
                high_confidence_threshold: Some("0.78".to_string()),
                medium_confidence_threshold: Some("0.48".to_string()),
                ..EvolutionMutationProfileOverrides::default()
            },
        },
    )?;
    let batch = mutation.materialize_batch(&drafting, &spec.report.mutation_spec_id)?;
    let validation_batch = mutation
        .refresh_validation_batch(
            &drafting,
            &replay,
            &proofs,
            &scorecards,
            &config.evolution.paths.experiment_results_dir,
            &config.evolution.paths.verification_results_dir,
            &config.evolution.paths.shadow_results_dir,
            &batch.report.batch_id,
        )
        .await?;
    let ranking = mutation.rank_candidates(
        &config.evolution.paths.evolution_queue_results_dir,
        &validation_batch.report.validation_batch_id,
        1,
    )?;
    let population = mutation.refresh_population(
        &config.evolution.paths.evolution_population_results_dir,
        &drafting,
        &config.evolution.paths.experiment_results_dir,
        &config.evolution.paths.verification_results_dir,
        &ranking.report,
        config.evolution.population_size,
        config.evolution.pareto_tournament_size,
        &config.evolution.fitness_weights,
        Some(&evasion_input),
    )?;
    let candidate = population
        .members
        .iter()
        .find(|candidate| candidate.strategy_id == "office_router_candidate")
        .ok_or("expected evasion candidate in the durable population")?;
    assert!(candidate.evasion_pressure.is_some());
    mutation.mark_population_candidate_proposed(
        &config.evolution.paths.evolution_population_results_dir,
        "office_router_candidate",
        1_900_100_000_000,
    )?;

    let router = state.current_strategy_proposal_router();
    let report = router
        .route_proposal(StrategyProposalRoute {
            proposed_by: AgentId("kitten-primary".to_string()),
            strategy_id: "office_router_candidate".to_string(),
            strategy: json!({
                "source": "kitten_population_candidate",
                "selection_source": "evasion_to_canary",
                "ranking_id": candidate.ranking_id,
                "validation_batch_id": candidate.validation_batch_id,
                "validation_bundle_id": candidate.validation_bundle_id,
                "materialization_id": candidate.materialization_id,
                "experiment_id": candidate.experiment_id,
                "experiment_path": office_control_experiment(),
                "population_fitness": candidate.fitness,
                "population_fitness_replay": candidate.baseline_fitness,
                "population_fitness_evasion": candidate.fitness,
                "evasion_pressure": candidate.evasion_pressure.clone(),
            }),
            fitness: candidate.fitness,
        })
        .await?;

    assert_eq!(report.outcome, StrategyProposalOutcome::Accepted);
    assert!(report.selection_id.is_some());
    assert!(report.bridge_id.is_some());
    assert!(report.handoff_id.is_some());
    assert!(report.canary_run_id.is_some());

    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[tokio::test]
async fn strategy_proposal_router_rejects_malformed_payload_without_panicking()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("malformed-strategy-proposal");
    let config_path = root.join("runtime.yaml");
    let state = IngestState::from_config(
        &config_path,
        config_with_strategy("suspicious_process_tree")?,
    )?;
    let router = state.current_strategy_proposal_router();
    let error = router
        .route_proposal(StrategyProposalRoute {
            proposed_by: AgentId("kitten-primary".to_string()),
            strategy_id: "office_router_candidate".to_string(),
            strategy: json!({
                "source": "kitten_population_candidate",
                "ranking_id": 7,
            }),
            fitness: 0.95,
        })
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        StrategyProposalRouteError::InvalidPayload(_)
    ));
    assert_eq!(error.boundary(), "payload");

    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[tokio::test]
async fn policy_deny_produces_bundle_with_skipped_response()
-> Result<(), Box<dyn std::error::Error>> {
    let cfg = config()?;
    let detector = build_composite_detector(&cfg.detection)?;
    let stack = ConfiguredRuntimeStack::from_components(
        cfg,
        DenyAllGate,
        SandboxExecutor,
        NoOpInvestigation,
    )?;
    let event = suspicious_event("deny-evt");
    let (agent_id, approval, signing_key) = execution_context();
    let result = stack
        .process_event(
            &detector,
            &event,
            EventExecutionContext {
                agent_id: &agent_id,
                approval: &approval,
                signing_key: &signing_key,
            },
            |_| {
                Some(ResponseAction::IsolateHost {
                    host_id: "host-1".to_string(),
                })
            },
        )
        .await?
        .ok_or("expected denied bundle")?;

    assert_eq!(result.replay.record.hunt_id, "deny-evt");
    assert!(matches!(
        result.replay.bundle.audit.response,
        swarm_spine::AuditResponseRecord::Skipped { .. }
    ));
    Ok(())
}
