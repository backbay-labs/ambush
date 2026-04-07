use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeSet;
use swarm_core::config::PheromoneConfig;
use swarm_core::pheromone::{PheromoneDeposit, ThreatIntelEntry, ThreatIntelIndicatorType};
use swarm_core::telemetry::TelemetryPayload;
use swarm_core::types::AgentId;
use swarm_pheromone::{DepositSigningPayload, PheromoneSubstrate, SubstrateError};
use swarm_whisker::stream::evaluate_event;
use swarm_whisker::{DetectionFinding, DetectionStrategy, TelemetryEvent};

/// Output of the fast detection lane for a single event.
#[derive(Debug, Clone)]
pub struct DetectionPipelineOutcome {
    pub event: TelemetryEvent,
    pub findings: Vec<DetectionFinding>,
    pub deposits: Vec<PheromoneDeposit>,
}

/// Errors raised while executing the fast detection lane.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error(transparent)]
    Substrate(#[from] SubstrateError),
}

/// Evaluate one telemetry event and persist any resulting pheromone deposits.
///
/// Every deposit is signed with `signing_key` before being submitted to the substrate.
pub async fn detect_and_deposit<D, S>(
    detector: &D,
    substrate: &S,
    event: &TelemetryEvent,
    agent_id: &AgentId,
    pheromone: &PheromoneConfig,
    signing_key: &SigningKey,
) -> Result<DetectionPipelineOutcome, PipelineError>
where
    D: DetectionStrategy,
    S: PheromoneSubstrate,
{
    let findings =
        enrich_findings_with_threat_intel(substrate, event, evaluate_event(detector, event))
            .await?;
    let mut deposits = resolve_deposits(substrate, &findings, event, agent_id, pheromone).await?;

    for deposit in &mut deposits {
        sign_deposit(deposit, signing_key);
        substrate.deposit(deposit.clone()).await?;
    }

    Ok(DetectionPipelineOutcome {
        event: event.clone(),
        findings,
        deposits,
    })
}

/// Sign a [`PheromoneDeposit`] in place using an Ed25519 signing key.
fn sign_deposit(deposit: &mut PheromoneDeposit, signing_key: &SigningKey) {
    let payload = DepositSigningPayload {
        indicator: &deposit.indicator,
        threat_class: &deposit.threat_class,
        severity: &deposit.severity,
        confidence: deposit.confidence,
        timestamp: deposit.timestamp,
        decay_half_life: deposit.decay_half_life,
        agent_id: &deposit.agent_id,
    };
    let payload_bytes =
        serde_json::to_vec(&payload).expect("deposit signing payload serialization must succeed");
    let sig = signing_key.sign(&payload_bytes);
    deposit.signature = sig.to_bytes().to_vec();
    deposit.agent_key = signing_key.verifying_key().to_bytes().to_vec();
}

async fn enrich_findings_with_threat_intel<S>(
    substrate: &S,
    event: &TelemetryEvent,
    findings: Vec<DetectionFinding>,
) -> Result<Vec<DetectionFinding>, SubstrateError>
where
    S: PheromoneSubstrate,
{
    let matches = threat_intel_matches_for_event(substrate, event).await?;
    if matches.is_empty() {
        return Ok(findings);
    }

    let confidence_boost = matches
        .iter()
        .map(|entry| entry.confidence)
        .fold(0.0, f64::max);
    Ok(findings
        .into_iter()
        .map(|finding| {
            let base_confidence = finding.confidence;
            let enriched_confidence = (base_confidence + confidence_boost).min(1.0);
            let evidence = annotate_threat_intel_evidence(
                finding.evidence,
                &matches,
                base_confidence,
                confidence_boost,
                enriched_confidence,
            );
            DetectionFinding {
                confidence: enriched_confidence,
                evidence,
                ..finding
            }
        })
        .collect())
}

async fn threat_intel_matches_for_event<S>(
    substrate: &S,
    event: &TelemetryEvent,
) -> Result<Vec<ThreatIntelEntry>, SubstrateError>
where
    S: PheromoneSubstrate,
{
    let lookup_time_ms = normalized_timestamp_ms(event.timestamp);
    let mut matches = Vec::new();

    for (indicator_type, value) in candidate_threat_intel_queries(event) {
        if let Some(entry) = substrate
            .query_threat_intel_entry(&indicator_type, &value, lookup_time_ms)
            .await?
        {
            matches.push(entry);
        }
    }

    Ok(matches)
}

fn candidate_threat_intel_queries(
    event: &TelemetryEvent,
) -> BTreeSet<(ThreatIntelIndicatorType, String)> {
    let mut candidates = BTreeSet::new();

    match &event.payload {
        TelemetryPayload::DnsQuery(dns) => {
            for value in candidate_domain_values(&dns.query_name) {
                candidates.insert((ThreatIntelIndicatorType::Domain, value));
            }
        }
        TelemetryPayload::NetworkConnect(connection) => {
            let destination_ip = connection.destination_ip.trim().to_ascii_lowercase();
            if !destination_ip.is_empty() {
                candidates.insert((ThreatIntelIndicatorType::IpAddress, destination_ip));
            }
        }
        TelemetryPayload::ProcessStart(_)
        | TelemetryPayload::RegistryAccess(_)
        | TelemetryPayload::RegistryPersistence(_)
        | TelemetryPayload::FilePersistence(_)
        | TelemetryPayload::AuthenticationEvent(_) => {}
    }

    candidates
}

fn candidate_domain_values(query_name: &str) -> Vec<String> {
    let normalized = query_name.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return Vec::new();
    }

    let labels = normalized
        .split('.')
        .filter(|label| !label.is_empty())
        .collect::<Vec<_>>();
    if labels.len() <= 1 {
        return vec![normalized];
    }

    let mut values = Vec::with_capacity(labels.len().saturating_sub(1));
    for index in 0..labels.len() - 1 {
        values.push(labels[index..].join("."));
    }
    values
}

fn annotate_threat_intel_evidence(
    evidence: serde_json::Value,
    matches: &[ThreatIntelEntry],
    base_confidence: f64,
    confidence_boost: f64,
    enriched_confidence: f64,
) -> serde_json::Value {
    match evidence {
        serde_json::Value::Object(mut object) => {
            object.insert(
                "threat_intel_matches".to_string(),
                serde_json::json!(matches),
            );
            object.insert(
                "threat_intel_base_confidence".to_string(),
                serde_json::json!(base_confidence),
            );
            object.insert(
                "threat_intel_confidence_boost".to_string(),
                serde_json::json!(confidence_boost),
            );
            object.insert(
                "threat_intel_enriched_confidence".to_string(),
                serde_json::json!(enriched_confidence),
            );
            serde_json::Value::Object(object)
        }
        other => serde_json::json!({
            "evidence": other,
            "threat_intel_matches": matches,
            "threat_intel_base_confidence": base_confidence,
            "threat_intel_confidence_boost": confidence_boost,
            "threat_intel_enriched_confidence": enriched_confidence,
        }),
    }
}

fn normalized_timestamp_ms(timestamp: i64) -> i64 {
    if timestamp.abs() < 100_000_000_000 {
        timestamp.saturating_mul(1_000)
    } else {
        timestamp
    }
}

async fn resolve_deposits<S>(
    substrate: &S,
    findings: &[DetectionFinding],
    event: &TelemetryEvent,
    agent_id: &AgentId,
    pheromone: &PheromoneConfig,
) -> Result<Vec<PheromoneDeposit>, SubstrateError>
where
    S: PheromoneSubstrate,
{
    let mut deposits = Vec::with_capacity(findings.len());
    for finding in findings {
        let threat_class_config = substrate
            .query_threat_class_config(&finding.threat_class)
            .await?;
        let policy = pheromone.resolve_threat_class_policy(threat_class_config.as_ref());
        deposits.push(PheromoneDeposit {
            indicator: serde_json::json!({
                "event_id": finding.event_id,
                "source": event.source,
                "evidence": finding.evidence.clone(),
            }),
            threat_class: finding.threat_class.clone(),
            severity: finding.severity,
            confidence: finding.confidence,
            timestamp: event.timestamp,
            decay_half_life: policy.half_life_secs,
            agent_id: agent_id.clone(),
            signature: Vec::new(),
            agent_key: Vec::new(),
        });
    }
    Ok(deposits)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::detect_and_deposit;
    use ed25519_dalek::SigningKey;
    use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig};
    use swarm_core::pheromone::{ThreatClassConfig, ThreatIntelEntry, ThreatIntelIndicatorType};
    use swarm_core::types::AgentId;
    use swarm_pheromone::{InMemoryPheromoneSubstrate, PheromoneSubstrate};
    use swarm_whisker::{
        DnsExfiltrationDetector, DnsQueryEvent, ProcessStartEvent, SuspiciousProcessTreeDetector,
        TelemetryEvent, TelemetryPayload,
    };

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn pheromone_config() -> PheromoneConfig {
        PheromoneConfig {
            default_half_life_secs: 3600.0,
            evaporation_threshold: 0.01,
            min_sources_for_escalation: 2,
            alert_threshold: 2.0,
            incident_threshold: 5.0,
            backend: PheromoneBackendConfig::InMemory,
        }
    }

    #[tokio::test]
    async fn detector_findings_are_deposited_into_substrate() {
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(pheromone_config());
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-1".to_string(),
            timestamp: 1_700_000_000,
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
        };

        let outcome = detect_and_deposit(
            &detector,
            &substrate,
            &event,
            &AgentId("whisker-a".to_string()),
            &pheromone_config(),
            &test_signing_key(),
        )
        .await
        .unwrap();

        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.deposits.len(), 1);
        assert_eq!(substrate.recent_deposits(1).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn detector_findings_use_threat_class_half_life_override() {
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(pheromone_config());
        substrate
            .store_threat_class_config(ThreatClassConfig {
                threat_class: swarm_core::pheromone::ThreatClass::Execution,
                half_life_secs: 120.0,
                evaporation_threshold: 0.01,
                alert_threshold: 2.0,
                incident_threshold: 5.0,
            })
            .await
            .unwrap();
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-override".to_string(),
            timestamp: 1_700_000_000,
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
        };

        let outcome = detect_and_deposit(
            &detector,
            &substrate,
            &event,
            &AgentId("whisker-a".to_string()),
            &pheromone_config(),
            &test_signing_key(),
        )
        .await
        .unwrap();

        assert_eq!(outcome.deposits.len(), 1);
        assert_eq!(outcome.deposits[0].decay_half_life, 120.0);
    }

    #[tokio::test]
    async fn dns_findings_are_enriched_by_matching_threat_intel() {
        let detector = DnsExfiltrationDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(pheromone_config());
        substrate
            .store_threat_intel_entry(ThreatIntelEntry {
                indicator_type: ThreatIntelIndicatorType::Domain,
                value: "evil.com".to_string(),
                confidence: 0.25,
                expires_at: 1_700_000_000_500,
            })
            .await
            .unwrap();
        let event = TelemetryEvent {
            source: "dns".to_string(),
            event_id: "evt-intel".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::DnsQuery(DnsQueryEvent {
                query_name: "abcdefghijklabcdefghijkl.evil.com".to_string(),
                query_type: "A".to_string(),
                source_ip: Some("10.0.0.4".to_string()),
                process_name: Some("powershell".to_string()),
                response_code: Some("NOERROR".to_string()),
            }),
        };

        let outcome = detect_and_deposit(
            &detector,
            &substrate,
            &event,
            &AgentId("whisker-dns".to_string()),
            &pheromone_config(),
            &test_signing_key(),
        )
        .await
        .unwrap();

        assert_eq!(outcome.findings.len(), 1);
        assert!((outcome.findings[0].confidence - 0.95).abs() < 1e-9);
        assert_eq!(
            outcome.findings[0].evidence["threat_intel_matches"][0]["value"],
            "evil.com"
        );
        assert_eq!(
            outcome.findings[0].evidence["threat_intel_confidence_boost"],
            0.25
        );
        assert!((outcome.deposits[0].confidence - 0.95).abs() < 1e-9);
    }
}
