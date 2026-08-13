pub(super) use super::{
    DefaultEvolutionMutationHarness, EvolutionAdversarialPressureRequest,
    EvolutionAutonomousMutationSpecCreateRequest, EvolutionAutonomousVariantLineage,
    EvolutionAutonomousVariantRecipeKind, EvolutionDetectorGenome,
    EvolutionDraftMaterializationRequest, EvolutionEvasionGapFocus, EvolutionEvasionPressureInput,
    EvolutionMutationProfileOverrides, EvolutionMutationSourceKind,
    EvolutionMutationSpecCreateRequest, EvolutionMutationVariantCreateRequest,
    EvolutionPopulationCandidate, EvolutionPopulationFitnessObjectives, EvolutionPopulationState,
    EvolutionValidationBundleStatus, FileEvolutionEpisodeStore, FileEvolutionPopulationStore,
    render_evolution_mutation_materialization_batch, render_evolution_mutation_ranking,
    render_evolution_mutation_spec, render_evolution_mutation_validation_batch,
};
pub(super) use crate::drafting::{DefaultEvolutionDraftingHarness, EvolutionDraftCreateRequest};
pub(super) use crate::evolution::{
    DefaultEvolutionProofHarness, EvolutionProposalAssuranceCoverageSummary,
    EvolutionProposalAssuranceDecision, EvolutionProposalAssuranceSolverSummary,
    FileEvolutionProposalStore,
};
pub(super) use crate::replay::{DefaultReplayHarness, DetectorCandidateManifest};
pub(super) use crate::strategy::DefaultStrategyScorecardHarness;
pub(super) use ed25519_dalek::SigningKey;
pub(super) use std::fs;
pub(super) use std::path::PathBuf;
pub(super) use swarm_core::ThreatClass;
pub(super) use swarm_core::config::{PolicyRuleConfig, PolicyRuleDecision, SwarmConfig};
pub(super) use swarm_core::types::Severity;
pub(super) use swarm_whisker::{
    BehavioralAnomalyProfile, DnsExfiltrationProfile, DnsQueryEvent, FilelessExecutionProfile,
    ProcessStartEvent, TelemetryEvent, TelemetryPayload,
};

pub(super) fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap()
        .to_path_buf()
}

pub(super) fn sample_config() -> SwarmConfig {
    let mut config: SwarmConfig =
        serde_yaml::from_str(include_str!("../../../../rulesets/default.yaml")).unwrap();
    config.policy.rules = permissive_policy_rules();
    config.evolution.assurance.min_detector_catch_rate = 0.0;
    config
}

pub(super) fn permissive_policy_rules() -> Vec<PolicyRuleConfig> {
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
        name: format!("mutation-test-allow-{threat_class:?}"),
        decision: PolicyRuleDecision::Allow,
        threat_class,
        actions: Vec::new(),
        min_severity: Severity::Low,
        max_severity: Severity::Critical,
        time_window_utc: None,
        max_actions_per_agent_per_minute: None,
        reason: Some("mutation tests allow replay and verification responses".to_string()),
    })
    .collect()
}

pub(super) fn office_control_experiment() -> PathBuf {
    repo_root().join("experiments/office-baseline-control.yaml")
}

pub(super) fn unique_temp_dir(label: &str) -> PathBuf {
    static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "swarm-team-six-{}-{}-{}",
        label,
        NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

pub(super) fn copy_experiment_fixture(root: &std::path::Path, name: &str) -> PathBuf {
    let path = root.join(format!("{name}.yaml"));
    let raw = fs::read_to_string(office_control_experiment()).unwrap();
    let mut manifest: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
    manifest["name"] = serde_yaml::Value::String(name.to_string());
    manifest["corpus"]["suite"] = serde_yaml::Value::String(
        repo_root()
            .join("scenario-suites/hellcat-office-v1.yaml")
            .display()
            .to_string(),
    );
    manifest["verification"]["corpus"] = serde_yaml::Value::String(
        repo_root()
            .join("verifications/office-detector-safety-v1.yaml")
            .display()
            .to_string(),
    );
    manifest["gates"]["max_detect_latency_delta_us"] = serde_yaml::Value::Number(10_000.into());
    fs::write(&path, serde_yaml::to_string(&manifest).unwrap()).unwrap();
    path
}

pub(super) fn copy_experiment_fixture_with_candidate(
    root: &std::path::Path,
    name: &str,
    candidate: DetectorCandidateManifest,
) -> PathBuf {
    let path = copy_experiment_fixture(root, name);
    let raw = fs::read_to_string(&path).unwrap();
    let mut manifest: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
    manifest["candidate"] = serde_yaml::to_value(&candidate).unwrap();
    manifest["lineage"]["parent_strategy_id"] = serde_yaml::Value::String(match &candidate {
        DetectorCandidateManifest::SuspiciousProcessTree { .. } => {
            "suspicious_process_tree".to_string()
        }
        DetectorCandidateManifest::BehavioralAnomaly { .. } => "behavioral_anomaly".to_string(),
        DetectorCandidateManifest::FilelessExecution { .. } => "fileless_execution".to_string(),
        DetectorCandidateManifest::DnsExfiltration { .. } => "dns_exfiltration".to_string(),
        other => other.strategy_id().to_string(),
    });
    fs::write(&path, serde_yaml::to_string(&manifest).unwrap()).unwrap();
    path
}

pub(super) fn copy_behavioral_anomaly_experiment_fixture(
    root: &std::path::Path,
    name: &str,
) -> PathBuf {
    copy_experiment_fixture_with_candidate(
        root,
        name,
        DetectorCandidateManifest::BehavioralAnomaly {
            strategy_id: name.to_string(),
            description: "Behavioral anomaly control fixture".to_string(),
            profile: BehavioralAnomalyProfile::default(),
        },
    )
}

pub(super) fn copy_fileless_execution_experiment_fixture(
    root: &std::path::Path,
    name: &str,
) -> PathBuf {
    copy_experiment_fixture_with_candidate(
        root,
        name,
        DetectorCandidateManifest::FilelessExecution {
            strategy_id: name.to_string(),
            description: "Fileless execution control fixture".to_string(),
            profile: FilelessExecutionProfile::default(),
        },
    )
}

pub(super) fn copy_dns_exfiltration_experiment_fixture(
    root: &std::path::Path,
    name: &str,
) -> PathBuf {
    copy_experiment_fixture_with_candidate(
        root,
        name,
        DetectorCandidateManifest::DnsExfiltration {
            strategy_id: name.to_string(),
            description: "DNS exfiltration control fixture".to_string(),
            profile: DnsExfiltrationProfile::default(),
        },
    )
}

pub(super) fn mock_process_start(event_id: &str, timestamp: i64) -> TelemetryEvent {
    TelemetryEvent {
        source: "test".to_string(),
        event_id: event_id.to_string(),
        timestamp,
        host_id: Some("host-red".to_string()),
        payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
            parent_process: "WINWORD".to_string(),
            process_name: "powershell".to_string(),
            command_line: "powershell.exe -enc AAA=".to_string(),
            user: Some("alice".to_string()),
            executable_path: None,
            signer: None,
            signature_valid: None,
        }),
    }
}

pub(super) fn mock_dns_query(event_id: &str, timestamp: i64) -> TelemetryEvent {
    TelemetryEvent {
        source: "test".to_string(),
        event_id: event_id.to_string(),
        timestamp,
        host_id: Some("host-red".to_string()),
        payload: TelemetryPayload::DnsQuery(DnsQueryEvent {
            process_name: Some("powershell".to_string()),
            query_name: "aaaaaaaaaaaaaaaa.exfil.example".to_string(),
            query_type: "TXT".to_string(),
            source_ip: Some("10.0.0.7".to_string()),
            response_code: Some("NOERROR".to_string()),
        }),
    }
}

pub(super) fn sample_evasion_pressure_input() -> EvolutionEvasionPressureInput {
    EvolutionEvasionPressureInput {
        detector: "suspicious_process_tree".to_string(),
        suite_name: "evasion_breadth_v1".to_string(),
        suite_path: repo_root().join("scenario-suites/evasion-breadth-v1.yaml"),
        corpus_version: "2026-04-10".to_string(),
        gaps: vec![
            EvolutionEvasionGapFocus {
                threat_class: ThreatClass::Execution,
                total_payloads: 2,
                missed_payloads: 1,
                catch_rate: 0.5,
                actionable_techniques: vec!["T1204.002".to_string()],
            },
            EvolutionEvasionGapFocus {
                threat_class: ThreatClass::DefenseEvasion,
                total_payloads: 1,
                missed_payloads: 1,
                catch_rate: 0.0,
                actionable_techniques: vec!["T1055".to_string()],
            },
        ],
    }
}

pub(super) fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[31u8; 32])
}

pub(super) fn test_signer_agent_id() -> swarm_core::types::AgentId {
    swarm_core::types::AgentId::from_verifying_key(&test_signing_key().verifying_key())
}
