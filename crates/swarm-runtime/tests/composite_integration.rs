#![allow(clippy::unwrap_used)]

use ed25519_dalek::SigningKey;
use swarm_core::config::{DetectionConfig, DetectorProfilesConfig, SwarmConfig};
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::AgentId;
use swarm_pheromone::{InMemoryPheromoneSubstrate, PheromoneSubstrate};
use swarm_runtime::config::load_config;
use swarm_runtime::control::build_composite_detector;
use swarm_runtime::detection::detect_and_deposit;
use swarm_whisker::{
    CompositeDetector, DetectionStrategy, DnsExfiltrationDetector, DnsQueryEvent,
    ProcessStartEvent, SuspiciousProcessTreeDetector, TelemetryEvent, TelemetryPayload,
};

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn runtime_config() -> Result<SwarmConfig, Box<dyn std::error::Error>> {
    Ok(load_config(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../rulesets/default.yaml"
    ))?)
}

fn process_event() -> TelemetryEvent {
    TelemetryEvent {
        source: "integration".to_string(),
        event_id: "process-evt".to_string(),
        timestamp: 1_700_000_000,
        host_id: Some("host-process".to_string()),
        payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
            parent_process: "WINWORD".to_string(),
            process_name: "powershell".to_string(),
            command_line: "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ=="
                .to_string(),
            user: Some("alice".to_string()),
            executable_path: None,
            signer: None,
            signature_valid: None,
        }),
    }
}

fn dns_event() -> TelemetryEvent {
    TelemetryEvent {
        source: "integration".to_string(),
        event_id: "dns-evt".to_string(),
        timestamp: 1_700_000_001,
        host_id: Some("host-dns".to_string()),
        payload: TelemetryPayload::DnsQuery(DnsQueryEvent {
            query_name: "abcdefghijklabcdefghijkl.example.com".to_string(),
            query_type: "TXT".to_string(),
            source_ip: Some("10.0.0.4".to_string()),
            process_name: Some("powershell".to_string()),
            response_code: Some("NOERROR".to_string()),
        }),
    }
}

fn composite_detector() -> CompositeDetector {
    CompositeDetector::new(vec![
        Box::new(SuspiciousProcessTreeDetector::default()),
        Box::new(DnsExfiltrationDetector::default()),
    ])
}

fn multi_strategy_detection_config() -> DetectionConfig {
    DetectionConfig {
        strategy: "suspicious_process_tree".to_string(),
        strategies: vec![
            "suspicious_process_tree".to_string(),
            "dns_exfiltration".to_string(),
        ],
        high_confidence_threshold: 0.9,
        medium_confidence_threshold: 0.6,
        profiles: DetectorProfilesConfig::default(),
    }
}

fn legacy_detection_config() -> DetectionConfig {
    DetectionConfig {
        strategy: "suspicious_process_tree".to_string(),
        strategies: Vec::new(),
        high_confidence_threshold: 0.9,
        medium_confidence_threshold: 0.6,
        profiles: DetectorProfilesConfig::default(),
    }
}

#[test]
fn composite_detector_merges_findings_from_multiple_strategies() {
    let detector = composite_detector();

    let process_findings = detector.evaluate(&process_event());
    assert_eq!(process_findings.len(), 1);
    assert_eq!(process_findings[0].strategy_id, "suspicious_process_tree");

    let dns_findings = detector.evaluate(&dns_event());
    assert_eq!(dns_findings.len(), 1);
    assert_eq!(dns_findings[0].strategy_id, "dns_exfiltration");
}

#[tokio::test]
async fn composite_detector_deposits_from_both_strategies() -> Result<(), Box<dyn std::error::Error>>
{
    let config = runtime_config()?;
    let detector = composite_detector();
    let substrate = InMemoryPheromoneSubstrate::new(config.pheromone.clone());

    let agent_id = AgentId::from_verifying_key(&test_signing_key().verifying_key());
    let process_outcome = detect_and_deposit(
        &detector,
        &substrate,
        &process_event(),
        &agent_id,
        &config.pheromone,
        &test_signing_key(),
    )
    .await?;
    assert_eq!(process_outcome.findings.len(), 1);

    let dns_outcome = detect_and_deposit(
        &detector,
        &substrate,
        &dns_event(),
        &agent_id,
        &config.pheromone,
        &test_signing_key(),
    )
    .await?;
    assert_eq!(dns_outcome.findings.len(), 1);

    let deposits = substrate.recent_deposits(10).await?;
    assert!(
        deposits
            .iter()
            .any(|deposit| deposit.threat_class == ThreatClass::Execution)
    );
    assert!(
        deposits
            .iter()
            .any(|deposit| deposit.threat_class == ThreatClass::DataExfiltration)
    );

    Ok(())
}

#[test]
fn build_composite_from_multi_strategy_config() {
    let detector = build_composite_detector(&multi_strategy_detection_config()).unwrap();

    let findings = detector.evaluate(&process_event());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].strategy_id, "suspicious_process_tree");
}

#[test]
fn build_composite_from_legacy_single_strategy_config() {
    let detector = build_composite_detector(&legacy_detection_config()).unwrap();

    let process_findings = detector.evaluate(&process_event());
    assert_eq!(process_findings.len(), 1);
    assert_eq!(process_findings[0].strategy_id, "suspicious_process_tree");

    let dns_findings = detector.evaluate(&dns_event());
    assert!(dns_findings.is_empty());
}
