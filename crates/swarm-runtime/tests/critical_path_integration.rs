use async_trait::async_trait;
use swarm_core::config::SwarmConfig;
use swarm_core::types::{AgentId, ResponseAction};
use swarm_policy::static_gate::StaticApprovalGate;
use swarm_policy::{
    ActionRequest, ApprovalContext, ApprovalError, ApprovalGate, CapabilityLease, PolicyDecision,
};
use swarm_response::adapters::SandboxExecutor;
use swarm_runtime::config::load_config;
use swarm_runtime::control::supported_detector;
use swarm_runtime::investigation::{
    InvestigationOutcome, InvestigationStrategy, SummaryInvestigator,
};
use swarm_runtime::replay::{ReplayScenarioInput, ReplayScenarioStep, load_scenario_manifest};
use swarm_runtime::service::{ConfiguredRuntimeStack, EventExecutionContext};
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
        })
    }
}

fn config() -> Result<SwarmConfig, Box<dyn std::error::Error>> {
    Ok(load_config(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../rulesets/default.yaml"
    ))?)
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

fn execution_context() -> (AgentId, ApprovalContext) {
    (
        AgentId("integration-agent".to_string()),
        ApprovalContext {
            live_mode: false,
            receipt_chain: vec!["seed-receipt".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_000_500,
        },
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
    let detector = supported_detector(&cfg.detection)?;
    let stack = ConfiguredRuntimeStack::from_components(
        cfg,
        StaticApprovalGate::default(),
        SandboxExecutor,
        SummaryInvestigator,
    )?;
    let (_, step) = load_single_event_scenario(relative_path)?;
    let (agent_id, approval) = execution_context();
    Ok(stack
        .process_event(
            &detector,
            &step.event,
            EventExecutionContext {
                agent_id: &agent_id,
                approval: &approval,
            },
            |_| Some(step.action.clone()),
        )
        .await?)
}

#[tokio::test]
async fn full_critical_path_detect_to_receipt() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config()?;
    let detector = supported_detector(&cfg.detection)?;
    let stack = ConfiguredRuntimeStack::from_components(
        cfg,
        StaticApprovalGate::default(),
        SandboxExecutor,
        SummaryInvestigator,
    )?;
    let event = suspicious_event("suspicious-evt");
    let (agent_id, approval) = execution_context();
    let result = stack
        .process_event(
            &detector,
            &event,
            EventExecutionContext {
                agent_id: &agent_id,
                approval: &approval,
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
    let detector = supported_detector(&cfg.detection)?;
    let stack = ConfiguredRuntimeStack::from_components(
        cfg,
        StaticApprovalGate::default(),
        SandboxExecutor,
        NoOpInvestigation,
    )?;
    let event = benign_event();
    let (agent_id, approval) = execution_context();
    let result = stack
        .process_event(
            &detector,
            &event,
            EventExecutionContext {
                agent_id: &agent_id,
                approval: &approval,
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
    let result =
        run_scenario_with_strategy("suspicious_process_tree", "office-dropper-correlation.yaml")
            .await?
            .ok_or("expected scenario bundle")?;

    assert!(!result.replay.bundle.findings.is_empty());
    assert!(!result.replay.bundle.deposits.is_empty());
    assert!(matches!(
        result.replay.bundle.audit.response,
        swarm_spine::AuditResponseRecord::Success(_)
    ));
    assert_eq!(result.replay.record.hunt_id, "hunt-evt-1");
    Ok(())
}

#[test]
fn supported_detector_factory_covers_all_runtime_strategies()
-> Result<(), Box<dyn std::error::Error>> {
    for strategy in [
        "suspicious_process_tree",
        "dns_exfiltration",
        "lateral_movement",
        "credential_access",
        "suspicious_scripting",
        "persistence",
        "supply_chain",
    ] {
        let cfg = config_with_strategy(strategy)?;
        assert!(supported_detector(&cfg.detection).is_ok(), "{strategy}");
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
async fn policy_deny_produces_bundle_with_skipped_response()
-> Result<(), Box<dyn std::error::Error>> {
    let cfg = config()?;
    let detector = supported_detector(&cfg.detection)?;
    let stack = ConfiguredRuntimeStack::from_components(
        cfg,
        DenyAllGate,
        SandboxExecutor,
        NoOpInvestigation,
    )?;
    let event = suspicious_event("deny-evt");
    let (agent_id, approval) = execution_context();
    let result = stack
        .process_event(
            &detector,
            &event,
            EventExecutionContext {
                agent_id: &agent_id,
                approval: &approval,
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
