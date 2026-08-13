#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::SwarmConfig;
use swarm_core::types::AgentId;
use swarm_ingest_runtime::control::build_composite_detector;
use swarm_policy::ApprovalContext;
use swarm_policy::static_gate::StaticApprovalGate;
use swarm_response::adapters::SandboxExecutor;
use swarm_runtime::config::load_config;
use swarm_runtime::evasion_coverage::summarize_repo_adversary_emulation_coverage;
use swarm_runtime::investigation::SummaryInvestigator;
use swarm_runtime::replay::{
    ReplayScenarioClass, ReplayScenarioInput, ReplayScenarioStep, load_replay_suite_manifest,
    load_scenario_manifest, resolve_manifest_relative_path,
};
use swarm_runtime::service::{ConfiguredRuntimeStack, EventExecutionContext};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn config_with_strategy(strategy: &str) -> Result<SwarmConfig, Box<dyn std::error::Error>> {
    let mut config = load_config(repo_root().join("rulesets/default.yaml"))?;
    config.detection.strategy = strategy.to_string();
    config.detection.strategies.clear();
    Ok(config)
}

fn execution_context() -> (AgentId, ApprovalContext, ed25519_dalek::SigningKey) {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[24u8; 32]);
    (
        AgentId::from_verifying_key(&signing_key.verifying_key()),
        ApprovalContext {
            live_mode: false,
            receipt_chain: vec!["adversary-emulation-seed".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_000_500,
        },
        signing_key,
    )
}

fn mapped_detector_for_scenario(name: &str) -> Option<&'static str> {
    match name {
        "evasion_execution_office_chains" => Some("suspicious_process_tree"),
        "evasion_defense_evasion_fileless" => Some("fileless_execution"),
        "evasion_command_and_control_network" => Some("network_connect"),
        "evasion_data_exfiltration_dns" => Some("dns_exfiltration"),
        "evasion_lateral_movement_remote_admin" => Some("lateral_movement"),
        "evasion_credential_access_harvest" => Some("credential_access"),
        "evasion_persistence_autostart" => Some("persistence"),
        _ => None,
    }
}

fn temp_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "swarm-runtime-adversary-emulation-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn configure_runtime_artifacts(config: &mut SwarmConfig, root: &Path) {
    config.audit.bundle_store = swarm_core::config::BundleStoreConfig::LocalFiles {
        directory: root.join("replay").display().to_string(),
    };
    config.investigation.enabled = false;
    config.correlation.enabled = false;
}

async fn replay_scenario_with_strategy(
    strategy: &str,
    steps: &[ReplayScenarioStep],
) -> Result<usize, Box<dyn std::error::Error>> {
    let root = temp_root(strategy);
    let mut config = config_with_strategy(strategy)?;
    configure_runtime_artifacts(&mut config, &root);
    let detector = build_composite_detector(&config.detection)?;
    let stack = ConfiguredRuntimeStack::from_components(
        config,
        StaticApprovalGate::default(),
        SandboxExecutor,
        SummaryInvestigator,
    )?;
    let (agent_id, approval, signing_key) = execution_context();

    let mut detections = 0usize;
    for step in steps {
        if stack
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
            .is_some()
        {
            detections += 1;
        }
    }
    Ok(detections)
}

#[tokio::test]
async fn adversary_emulation_suite_replays_with_documented_detector_mapping()
-> Result<(), Box<dyn std::error::Error>> {
    let repo_root = repo_root();
    let suite_path = repo_root.join("scenario-suites/evasion-breadth-v1.yaml");
    let suite = load_replay_suite_manifest(&suite_path)?;
    let mut technique_ids = std::collections::BTreeSet::new();
    let mut adversarial_scenarios = 0usize;

    for scenario_ref in &suite.scenarios {
        let scenario_path = resolve_manifest_relative_path(&suite_path, scenario_ref);
        let loaded = load_scenario_manifest(&scenario_path)?;
        if loaded.manifest.metadata.class != ReplayScenarioClass::Adversarial {
            continue;
        }
        adversarial_scenarios += 1;
        technique_ids.extend(loaded.manifest.metadata.techniques.iter().cloned());
        let detector = mapped_detector_for_scenario(&loaded.manifest.name)
            .ok_or_else(|| format!("missing mapped detector for `{}`", loaded.manifest.name))?;
        let ReplayScenarioInput::Events { events } = loaded.manifest.input else {
            return Err(format!(
                "scenario `{}` must stay event-backed for adversary emulation replay",
                loaded.manifest.name
            )
            .into());
        };
        let detections = replay_scenario_with_strategy(detector, &events).await?;
        assert!(
            detections > 0,
            "expected `{}` to trigger `{detector}` at least once",
            loaded.manifest.name
        );
    }

    assert_eq!(adversarial_scenarios, 7);
    assert!(
        technique_ids.len() >= 20,
        "expected at least twenty ATT&CK techniques in the adversary corpus, got {}",
        technique_ids.len()
    );
    Ok(())
}

#[test]
fn adversary_emulation_report_meets_sixty_percent_coverage_floor()
-> Result<(), Box<dyn std::error::Error>> {
    let repo_root = repo_root();
    let config = load_config(repo_root.join("rulesets/default.yaml"))?;
    let report = summarize_repo_adversary_emulation_coverage(&config, &repo_root)?;

    assert!(
        report.coverage_percent >= 0.60,
        "expected technique coverage floor >= 0.60, got {}",
        report.coverage_percent
    );
    assert!(
        report
            .techniques
            .iter()
            .any(|entry| entry.technique == "T1047"),
        "expected WMI technique coverage in the report"
    );
    Ok(())
}
