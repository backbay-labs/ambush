use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::SwarmConfig;
use swarm_runtime::config::load_config;
use swarm_runtime::replay::DefaultReplayHarness;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn default_config() -> Result<SwarmConfig, Box<dyn std::error::Error>> {
    Ok(load_config(repo_root().join("rulesets/default.yaml"))?)
}

fn rules_path() -> String {
    repo_root()
        .join("sequences/kill-chain-v1.yaml")
        .display()
        .to_string()
}

fn suite_path() -> PathBuf {
    repo_root().join("scenario-suites/kill-chain-sequences-v1.yaml")
}

fn scenario_paths() -> Vec<PathBuf> {
    vec![
        repo_root().join("scenarios/outlook-mshta-transfer-chain.yaml"),
        repo_root().join("scenarios/remote-service-stager-chain.yaml"),
        repo_root().join("scenarios/msbuild-installutil-transfer-chain.yaml"),
    ]
}

fn temp_results_dir(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "swarm-runtime-sequence-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn single_event_only_config() -> Result<SwarmConfig, Box<dyn std::error::Error>> {
    let mut cfg = default_config()?;
    cfg.detection.strategy = "suspicious_process_tree".to_string();
    cfg.detection.strategies = vec![
        "suspicious_process_tree".to_string(),
        "fileless_execution".to_string(),
        "dns_exfiltration".to_string(),
        "lateral_movement".to_string(),
        "credential_access".to_string(),
        "suspicious_scripting".to_string(),
        "persistence".to_string(),
        "supply_chain".to_string(),
        "network_connect".to_string(),
        "infrastructure_anomaly".to_string(),
    ];
    cfg.canary.enabled = false;
    cfg.promotion.enabled = false;
    Ok(cfg)
}

fn kill_chain_config() -> Result<SwarmConfig, Box<dyn std::error::Error>> {
    let mut cfg = single_event_only_config()?;
    cfg.detection
        .strategies
        .push("kill_chain_sequence".to_string());
    cfg.detection.profiles.kill_chain_sequence = Some(json!({
        "rules_path": rules_path(),
    }));
    Ok(cfg)
}

#[tokio::test]
async fn kill_chain_scenarios_stay_quiet_under_single_event_detectors()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = DefaultReplayHarness::from_config(
        "inline",
        single_event_only_config()?,
        temp_results_dir("single-event"),
    )?;

    for scenario_path in scenario_paths() {
        let run = harness.run_scenario_path(&scenario_path).await?;
        assert_eq!(
            run.bundle.deterministic_summary.replay_bundle_count,
            0,
            "expected no single-event detections for {}",
            scenario_path.display()
        );
        assert_eq!(run.bundle.deterministic_summary.investigation_count, 0);
        assert_eq!(run.bundle.deterministic_summary.incident_count, 0);
    }

    Ok(())
}

#[tokio::test]
async fn kill_chain_sequence_suite_detects_all_chain_only_scenarios()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = DefaultReplayHarness::from_config(
        "inline",
        kill_chain_config()?,
        temp_results_dir("suite"),
    )?;
    let report = harness.evaluate_suite_path(suite_path()).await?;

    assert!(report.passed);
    assert_eq!(report.total_scenarios, 3);
    assert_eq!(report.passed_scenarios, 3);
    for scenario in report.scenario_reports {
        assert_eq!(
            scenario
                .evaluation
                .deterministic_summary
                .replay_bundle_count,
            2
        );
        assert_eq!(
            scenario
                .evaluation
                .deterministic_summary
                .investigation_count,
            2
        );
        assert_eq!(scenario.evaluation.deterministic_summary.incident_count, 1);
    }

    Ok(())
}

#[tokio::test]
async fn kill_chain_sequence_partial_and_full_matches_share_the_pheromone_lane()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = DefaultReplayHarness::from_config(
        "inline",
        kill_chain_config()?,
        temp_results_dir("partial-full"),
    )?;
    let run = harness
        .run_scenario_path(repo_root().join("scenarios/outlook-mshta-transfer-chain.yaml"))
        .await?;
    let bundles = &run.bundle.replay_bundles;

    assert_eq!(bundles.len(), 2);
    let partial = &bundles[0];
    let full = &bundles[1];

    assert_eq!(partial.findings[0].strategy_id, "kill_chain_sequence");
    assert_eq!(partial.findings[0].evidence["match_kind"], "partial");
    assert_eq!(full.findings[0].strategy_id, "kill_chain_sequence");
    assert_eq!(full.findings[0].evidence["match_kind"], "full");
    assert!(
        partial
            .deposits
            .iter()
            .all(|deposit| deposit.agent_id.0.ends_with(":kill_chain_sequence"))
    );
    assert!(
        full.deposits
            .iter()
            .all(|deposit| deposit.agent_id.0.ends_with(":kill_chain_sequence"))
    );
    assert!(partial.deposits[0].confidence < full.deposits[0].confidence);
    assert_eq!(run.bundle.deterministic_summary.incident_count, 1);

    Ok(())
}
