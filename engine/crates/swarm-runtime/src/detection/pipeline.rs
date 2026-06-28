use crate::detector_factory::RuntimeDetector;
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeSet;
use swarm_core::agent::AgentRole;
use swarm_core::config::PheromoneConfig;
use swarm_core::pheromone::{PheromoneDeposit, ThreatIntelEntry, ThreatIntelIndicatorType};
use swarm_core::telemetry::TelemetryPayload;
use swarm_core::types::AgentId;
use swarm_pheromone::{DepositSigningPayload, PheromoneSubstrate, SubstrateError};
use swarm_whisker::stream::{evaluate_event, strategy_scoped_agent_id};
use swarm_whisker::{CompositeDetector, DetectionFinding, DetectionStrategy, TelemetryEvent};

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
    detect_and_deposit_with_role(
        detector,
        substrate,
        event,
        agent_id,
        infer_agent_role(agent_id),
        pheromone,
        signing_key,
    )
    .await
}

pub async fn detect_and_deposit_with_role<D, S>(
    detector: &D,
    substrate: &S,
    event: &TelemetryEvent,
    agent_id: &AgentId,
    agent_role: Option<AgentRole>,
    pheromone: &PheromoneConfig,
    signing_key: &SigningKey,
) -> Result<DetectionPipelineOutcome, PipelineError>
where
    D: DetectionStrategy,
    S: PheromoneSubstrate,
{
    hydrate_stateful_detectors(detector, substrate).await?;
    let findings =
        enrich_findings_with_threat_intel(substrate, event, evaluate_event(detector, event))
            .await?;
    persist_stateful_detectors(detector, substrate).await?;
    let mut deposits =
        resolve_deposits(substrate, &findings, event, agent_id, agent_role, pheromone).await?;

    for deposit in &mut deposits {
        sign_deposit(deposit, signing_key, agent_role)?;
        substrate.deposit(deposit.clone()).await?;
    }

    Ok(DetectionPipelineOutcome {
        event: event.clone(),
        findings,
        deposits,
    })
}

async fn hydrate_stateful_detectors<D, S>(detector: &D, substrate: &S) -> Result<(), PipelineError>
where
    D: DetectionStrategy,
    S: PheromoneSubstrate,
{
    if let Some(composite) = detector.as_any().downcast_ref::<CompositeDetector>() {
        for strategy in composite.strategies() {
            hydrate_runtime_detector(strategy, substrate).await?;
        }
    } else {
        hydrate_runtime_detector(detector, substrate).await?;
    }
    Ok(())
}

async fn hydrate_runtime_detector<D, S>(detector: &D, substrate: &S) -> Result<(), PipelineError>
where
    D: DetectionStrategy + ?Sized,
    S: PheromoneSubstrate,
{
    let Some(runtime_detector) = detector.as_any().downcast_ref::<RuntimeDetector>() else {
        return Ok(());
    };
    let Some((strategy_id, detector)) = runtime_detector.behavioral_anomaly_detector() else {
        return Ok(());
    };
    if detector.needs_hydration() {
        let snapshot = substrate
            .query_behavioral_baseline_snapshot(strategy_id)
            .await?;
        detector.hydrate_from_snapshot(snapshot);
    }
    Ok(())
}

async fn persist_stateful_detectors<D, S>(detector: &D, substrate: &S) -> Result<(), PipelineError>
where
    D: DetectionStrategy,
    S: PheromoneSubstrate,
{
    if let Some(composite) = detector.as_any().downcast_ref::<CompositeDetector>() {
        for strategy in composite.strategies() {
            persist_runtime_detector(strategy, substrate).await?;
        }
    } else {
        persist_runtime_detector(detector, substrate).await?;
    }
    Ok(())
}

async fn persist_runtime_detector<D, S>(detector: &D, substrate: &S) -> Result<(), PipelineError>
where
    D: DetectionStrategy + ?Sized,
    S: PheromoneSubstrate,
{
    let Some(runtime_detector) = detector.as_any().downcast_ref::<RuntimeDetector>() else {
        return Ok(());
    };
    let Some((strategy_id, detector)) = runtime_detector.behavioral_anomaly_detector() else {
        return Ok(());
    };
    let Some(snapshot) = detector.snapshot_if_dirty(strategy_id) else {
        return Ok(());
    };
    substrate
        .store_behavioral_baseline_snapshot(snapshot)
        .await?;
    detector.mark_persisted();
    Ok(())
}

/// Sign a [`PheromoneDeposit`] in place using an Ed25519 signing key.
pub(crate) fn sign_deposit(
    deposit: &mut PheromoneDeposit,
    signing_key: &SigningKey,
    agent_role: Option<AgentRole>,
) -> Result<(), PipelineError> {
    deposit.agent_identity = AgentId::from_verifying_key(&signing_key.verifying_key()).0;
    deposit.agent_role = agent_role;
    let payload = DepositSigningPayload {
        schema_version: deposit.schema_version,
        indicator: &deposit.indicator,
        threat_class: &deposit.threat_class,
        severity: &deposit.severity,
        confidence: deposit.confidence,
        timestamp: deposit.timestamp,
        decay_half_life: deposit.decay_half_life,
        agent_id: &deposit.agent_id,
        agent_identity: &deposit.agent_identity,
        agent_role: deposit.agent_role,
    };
    let payload_bytes = serde_json::to_vec(&payload).map_err(|source| {
        PipelineError::Substrate(SubstrateError::Encode {
            context: "deposit signing payload".into(),
            source,
        })
    })?;
    let sig = signing_key.sign(&payload_bytes);
    deposit.signature = sig.to_bytes().to_vec();
    deposit.agent_key = signing_key.verifying_key().to_bytes().to_vec();
    Ok(())
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
        | TelemetryPayload::ProcessMemoryAccess(_)
        | TelemetryPayload::RegistryAccess(_)
        | TelemetryPayload::RegistryPersistence(_)
        | TelemetryPayload::FilePersistence(_)
        | TelemetryPayload::AuthenticationEvent(_)
        | TelemetryPayload::InfrastructureHealth(_)
        | TelemetryPayload::ThermalAnomaly(_)
        | TelemetryPayload::ResourceExhaustion(_) => {}
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

pub(crate) async fn resolve_deposits<S>(
    substrate: &S,
    findings: &[DetectionFinding],
    event: &TelemetryEvent,
    agent_id: &AgentId,
    agent_role: Option<AgentRole>,
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
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator: serde_json::json!({
                "event_id": finding.event_id,
                "host_id": event.host_id,
                "source": event.source,
                "evidence": finding.evidence.clone(),
            }),
            threat_class: finding.threat_class.clone(),
            severity: finding.severity,
            confidence: finding.confidence,
            timestamp: event.timestamp,
            decay_half_life: policy.half_life_secs,
            agent_id: strategy_scoped_agent_id(agent_id, &finding.strategy_id),
            agent_identity: String::new(),
            agent_role,
            signature: Vec::new(),
            agent_key: Vec::new(),
        });
    }
    Ok(deposits)
}

pub(crate) fn infer_agent_role(agent_id: &AgentId) -> Option<AgentRole> {
    let value = agent_id.0.as_str();
    if value.starts_with("whisker-") {
        Some(AgentRole::Whisker)
    } else if value.starts_with("stalker-") {
        Some(AgentRole::Stalker)
    } else if value.starts_with("weaver-") {
        Some(AgentRole::Weaver)
    } else if value.starts_with("pounce-") || value.starts_with("pouncer-") {
        Some(AgentRole::Pouncer)
    } else if value.starts_with("tom-") {
        Some(AgentRole::Tom)
    } else if value.starts_with("kitten-") {
        Some(AgentRole::Kitten)
    } else if value.starts_with("sphinx-") {
        Some(AgentRole::Sphinx)
    } else if value.starts_with("calico-") {
        Some(AgentRole::Calico)
    } else {
        None
    }
}

pub(crate) async fn persist_findings_as_deposits<S>(
    substrate: &S,
    findings: &[DetectionFinding],
    event: &TelemetryEvent,
    agent_id: &AgentId,
    agent_role: Option<AgentRole>,
    pheromone: &PheromoneConfig,
    signing_key: &SigningKey,
) -> Result<Vec<PheromoneDeposit>, PipelineError>
where
    S: PheromoneSubstrate,
{
    let mut deposits =
        resolve_deposits(substrate, findings, event, agent_id, agent_role, pheromone).await?;
    for deposit in &mut deposits {
        sign_deposit(deposit, signing_key, agent_role)?;
        substrate.deposit(deposit.clone()).await?;
    }
    Ok(deposits)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::detect_and_deposit;
    use crate::config::parse_config;
    use crate::detector_factory::build_detector_from_strategy;
    use ed25519_dalek::SigningKey;
    use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig};
    use swarm_core::pheromone::{
        ThreatClass, ThreatClassConfig, ThreatIntelEntry, ThreatIntelIndicatorType,
    };
    use swarm_core::types::{AgentId, Severity};
    use swarm_pheromone::substrate::validate_deposit_signature;
    use swarm_pheromone::{
        InMemoryPheromoneSubstrate, LocalJournalPheromoneSubstrate, PheromoneSubstrate,
    };
    use swarm_whisker::{
        DetectionFinding, DetectionStrategy, DnsExfiltrationDetector, DnsQueryEvent,
        FilelessExecutionDetector, NetworkConnectDetector, NetworkConnectEvent,
        NetworkConnectProfile, ProcessMemoryAccessEvent, ProcessStartEvent,
        SuspiciousProcessTreeDetector, TelemetryEvent, TelemetryPayload,
    };

    #[derive(Clone)]
    struct StaticDetector {
        findings: Vec<DetectionFinding>,
    }

    impl DetectionStrategy for StaticDetector {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn id(&self) -> &str {
            "static"
        }

        fn evaluate(&self, _event: &TelemetryEvent) -> Vec<DetectionFinding> {
            self.findings.clone()
        }
    }

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
            deescalation_cooldown_secs: 300,
            response_playbook: Default::default(),
            backend: PheromoneBackendConfig::InMemory,
        }
    }

    fn finding(strategy_id: &str, finding_id: &str) -> DetectionFinding {
        DetectionFinding {
            finding_id: finding_id.to_string(),
            event_id: "evt-1".to_string(),
            threat_class: ThreatClass::Execution,
            severity: Severity::Critical,
            confidence: 0.9,
            evidence: serde_json::json!({"strategy_id": strategy_id}),
            strategy_id: strategy_id.to_string(),
        }
    }

    fn network_event(
        event_id: &str,
        destination_ip: &str,
        destination_port: u16,
    ) -> TelemetryEvent {
        TelemetryEvent {
            source: "network".to_string(),
            event_id: event_id.to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::NetworkConnect(NetworkConnectEvent {
                process_name: "curl".to_string(),
                destination_ip: destination_ip.to_string(),
                destination_port,
                protocol: "TCP".to_string(),
            }),
        }
    }

    fn memory_access_event(event_id: &str, target_process: &str) -> TelemetryEvent {
        TelemetryEvent {
            source: "memory".to_string(),
            event_id: event_id.to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessMemoryAccess(ProcessMemoryAccessEvent {
                source_process: "powershell.exe".to_string(),
                target_process: target_process.to_string(),
                allocation_type: "private".to_string(),
                protection_flags: vec!["PAGE_EXECUTE_READWRITE".to_string()],
                region_size: 16384,
                call_stack_hint: Some("ReflectiveLoader -> HellsGate".to_string()),
            }),
        }
    }

    fn process_start_event(
        event_id: &str,
        timestamp: i64,
        parent_process: &str,
        process_name: &str,
        executable_path: Option<&str>,
    ) -> TelemetryEvent {
        TelemetryEvent {
            source: "process".to_string(),
            event_id: event_id.to_string(),
            timestamp,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: parent_process.to_string(),
                process_name: process_name.to_string(),
                command_line: format!("{process_name} --synthetic"),
                user: Some("alice".to_string()),
                executable_path: executable_path.map(|path| path.to_string()),
                signer: None,
                signature_valid: None,
            }),
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
            &AgentId::from_verifying_key(&test_signing_key().verifying_key()),
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
            &AgentId::from_verifying_key(&test_signing_key().verifying_key()),
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
            &AgentId::from_verifying_key(&test_signing_key().verifying_key()),
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

    #[tokio::test]
    async fn network_findings_are_enriched_by_matching_ip_threat_intel() {
        let detector = NetworkConnectDetector::from_profile(NetworkConnectProfile {
            suspicious_ports: vec![4444],
            ..NetworkConnectProfile::default()
        })
        .unwrap();
        let substrate = InMemoryPheromoneSubstrate::new(pheromone_config());
        substrate
            .store_threat_intel_entry(ThreatIntelEntry {
                indicator_type: ThreatIntelIndicatorType::IpAddress,
                value: "198.51.100.42".to_string(),
                confidence: 0.15,
                expires_at: 1_700_000_000_500,
            })
            .await
            .unwrap();
        let event = network_event("evt-network-intel", "198.51.100.42", 4444);

        let outcome = detect_and_deposit(
            &detector,
            &substrate,
            &event,
            &AgentId::from_verifying_key(&test_signing_key().verifying_key()),
            &pheromone_config(),
            &test_signing_key(),
        )
        .await
        .unwrap();

        assert_eq!(outcome.findings.len(), 1);
        assert!((outcome.findings[0].confidence - 0.85).abs() < 1e-9);
        assert_eq!(
            outcome.findings[0].evidence["threat_intel_matches"][0]["value"],
            "198.51.100.42"
        );
        assert_eq!(
            outcome.findings[0].evidence["threat_intel_confidence_boost"],
            0.15
        );
        assert!((outcome.deposits[0].confidence - 0.85).abs() < 1e-9);
    }

    #[tokio::test]
    async fn multi_strategy_runtime_deposits_are_scoped_before_signing() {
        let detector = StaticDetector {
            findings: vec![
                finding("suspicious_process_tree", "finding-1"),
                finding("dns_exfiltration", "finding-2"),
            ],
        };
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

        let base_agent_id = AgentId::from_verifying_key(&test_signing_key().verifying_key());
        let outcome = detect_and_deposit(
            &detector,
            &substrate,
            &event,
            &base_agent_id,
            &pheromone_config(),
            &test_signing_key(),
        )
        .await
        .unwrap();

        let persisted = substrate.recent_deposits(10).await.unwrap();

        assert_eq!(outcome.deposits.len(), 2);
        assert_eq!(persisted.len(), 2);
        assert_ne!(outcome.deposits[0].agent_id, outcome.deposits[1].agent_id);
        assert_eq!(
            outcome.deposits[0].agent_id.0,
            format!("{}:suspicious_process_tree", base_agent_id)
        );
        assert_eq!(
            outcome.deposits[1].agent_id.0,
            format!("{}:dns_exfiltration", base_agent_id)
        );
        for deposit in &outcome.deposits {
            validate_deposit_signature(deposit).unwrap();
        }
    }

    #[tokio::test]
    async fn fileless_memory_access_event_deposits_defense_evasion_pheromone() {
        let detector = FilelessExecutionDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(pheromone_config());
        let event = memory_access_event("evt-fileless-defense", "explorer.exe");
        let findings = detector.evaluate(&event);
        let mut deposits = super::resolve_deposits(
            &substrate,
            &findings,
            &event,
            &AgentId("whisker-fileless".to_string()),
            Some(swarm_core::agent::AgentRole::Whisker),
            &pheromone_config(),
        )
        .await
        .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::DefenseEvasion);
        assert_eq!(deposits.len(), 1);
        assert_eq!(deposits[0].threat_class, ThreatClass::DefenseEvasion);

        super::sign_deposit(
            &mut deposits[0],
            &test_signing_key(),
            Some(swarm_core::agent::AgentRole::Whisker),
        )
        .unwrap();

        assert_eq!(
            deposits[0].agent_id.0,
            "whisker-fileless:fileless_execution"
        );
        assert!(!deposits[0].signature.is_empty());
        assert_eq!(
            deposits[0].agent_identity,
            AgentId::from_verifying_key(&test_signing_key().verifying_key()).0
        );
    }

    #[tokio::test]
    async fn fileless_privileged_target_event_deposits_privilege_escalation_pheromone() {
        let detector = FilelessExecutionDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(pheromone_config());
        let event = memory_access_event("evt-fileless-priv", "lsass.exe");
        let findings = detector.evaluate(&event);
        let mut deposits = super::resolve_deposits(
            &substrate,
            &findings,
            &event,
            &AgentId("whisker-fileless".to_string()),
            Some(swarm_core::agent::AgentRole::Whisker),
            &pheromone_config(),
        )
        .await
        .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::PrivilegeEscalation);
        assert_eq!(deposits.len(), 1);
        assert_eq!(deposits[0].threat_class, ThreatClass::PrivilegeEscalation);

        super::sign_deposit(
            &mut deposits[0],
            &test_signing_key(),
            Some(swarm_core::agent::AgentRole::Whisker),
        )
        .unwrap();

        assert_eq!(
            deposits[0].agent_id.0,
            "whisker-fileless:fileless_execution"
        );
        assert!(!deposits[0].signature.is_empty());
        assert_eq!(
            deposits[0].agent_identity,
            AgentId::from_verifying_key(&test_signing_key().verifying_key()).0
        );
    }

    #[tokio::test]
    async fn behavioral_anomaly_detector_hydrates_persisted_baseline_after_restart() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let journal_path =
            std::env::temp_dir().join(format!("swarm-behavioral-baseline-pipeline-{unique}.jsonl"));
        let escalation_path = journal_path.with_extension("escalations.jsonl");
        let config_path = journal_path.with_extension("threat-class-configs.jsonl");
        let threat_intel_path = journal_path.with_extension("threat-intel.jsonl");
        let behavioral_baseline_path = journal_path.with_extension("behavioral-baselines.jsonl");
        let yaml = format!(
            r#"
name: test
description: test
runtime:
  mode: detect_only
  telemetry_sources:
    - name: synthetic
      subject: telemetry.synthetic
  max_in_flight_actions: 2
detection:
  strategy: behavioral_anomaly
  high_confidence_threshold: 0.93
  medium_confidence_threshold: 0.74
  profiles:
    behavioral_anomaly:
      min_host_observations: 2
      min_identity_observations: 2
      min_peer_group_observations: 2
      min_feature_weight: 0.5
      baseline_half_life_secs: 7200
pheromone:
  default_half_life_secs: 3600.0
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
  backend:
    kind: local_journal
    path: {}
policy:
  human_gate_severity: HIGH
  lease_ttl_ms: 60000
"#,
            journal_path.display()
        );
        let config = parse_config(&yaml, "inline").unwrap();
        let runtime_agent_id = AgentId::from_verifying_key(&test_signing_key().verifying_key());

        {
            let substrate =
                LocalJournalPheromoneSubstrate::open(config.pheromone.clone(), &journal_path)
                    .unwrap();
            let detector =
                build_detector_from_strategy("behavioral_anomaly", &config.detection).unwrap();

            let warm_events = [
                process_start_event(
                    "evt-warm-1",
                    1_700_000_100,
                    "explorer.exe",
                    "notepad.exe",
                    Some("C:\\Windows\\System32\\notepad.exe"),
                ),
                process_start_event(
                    "evt-warm-2",
                    1_700_000_200,
                    "explorer.exe",
                    "notepad.exe",
                    Some("C:\\Windows\\System32\\notepad.exe"),
                ),
            ];

            for event in warm_events {
                let outcome = detect_and_deposit(
                    &detector,
                    &substrate,
                    &event,
                    &runtime_agent_id,
                    &config.pheromone,
                    &test_signing_key(),
                )
                .await
                .unwrap();
                assert!(outcome.findings.is_empty());
            }

            let snapshot = substrate
                .query_behavioral_baseline_snapshot("behavioral_anomaly")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(snapshot.hosts.len(), 1);
            assert_eq!(snapshot.hosts[0].observation_count, 2);
            assert_eq!(snapshot.identities.len(), 1);
            assert_eq!(snapshot.identities[0].identity_id, "alice");
            assert_eq!(snapshot.identities[0].observation_count, 2);
            assert_eq!(snapshot.peer_groups.len(), 1);
            assert_eq!(snapshot.peer_groups[0].peer_group_id, "role:interactive");
            assert_eq!(snapshot.peer_groups[0].observation_count, 2);
        }

        let substrate =
            LocalJournalPheromoneSubstrate::open(config.pheromone.clone(), &journal_path).unwrap();
        let detector =
            build_detector_from_strategy("behavioral_anomaly", &config.detection).unwrap();
        let anomaly_event = process_start_event(
            "evt-anomaly",
            1_700_000_300,
            "winword.exe",
            "powershell.exe",
            Some("C:\\Users\\alice\\AppData\\Local\\Temp\\powershell.exe"),
        );

        let outcome = detect_and_deposit(
            &detector,
            &substrate,
            &anomaly_event,
            &runtime_agent_id,
            &config.pheromone,
            &test_signing_key(),
        )
        .await
        .unwrap();

        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(
            outcome.findings[0].threat_class,
            ThreatClass::DefenseEvasion
        );
        assert_eq!(
            outcome.findings[0].strategy_id,
            "behavioral_anomaly".to_string()
        );
        assert_eq!(
            outcome.findings[0].evidence["baseline_scope_hits"],
            serde_json::json!(["host", "identity", "peer_group"])
        );
        assert_eq!(outcome.deposits.len(), 1);
        assert_eq!(
            outcome.deposits[0].agent_id.0,
            format!("{}:behavioral_anomaly", runtime_agent_id.0)
        );

        let snapshot = substrate
            .query_behavioral_baseline_snapshot("behavioral_anomaly")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.hosts.len(), 1);
        assert_eq!(snapshot.hosts[0].observation_count, 3);
        assert_eq!(snapshot.identities.len(), 1);
        assert_eq!(snapshot.identities[0].observation_count, 3);
        assert_eq!(snapshot.peer_groups.len(), 1);
        assert_eq!(snapshot.peer_groups[0].observation_count, 3);

        let _ = std::fs::remove_file(journal_path);
        let _ = std::fs::remove_file(escalation_path);
        let _ = std::fs::remove_file(config_path);
        let _ = std::fs::remove_file(threat_intel_path);
        let _ = std::fs::remove_file(behavioral_baseline_path);
    }
}
