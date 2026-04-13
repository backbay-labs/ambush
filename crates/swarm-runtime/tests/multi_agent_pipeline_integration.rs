use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use swarm_core::config::{
    AuditConfig, BundleStoreConfig, CanaryConfig, CorrelationConfig, DetectionConfig,
    DetectorProfilesConfig, InvestigationConfig, OperatorSurfaceConfig, PheromoneBackendConfig,
    PheromoneConfig, PolicyConfig, PromotionConfig, RuntimeMode, RuntimeSettings, SwarmConfig,
    TelemetrySourceConfig,
};
use swarm_core::types::{AgentId, ResponseAction, Severity};
use swarm_pheromone::PheromoneSubstrate;
use swarm_policy::ApprovalContext;
use swarm_runtime::control::build_composite_detector;
use swarm_runtime::dispatcher::{AgentDispatcher, AgentDispatcherConfig};
use swarm_runtime::investigation::SummaryInvestigator;
use swarm_runtime::service::{ConfiguredRuntimeStack, EventExecutionContext};
use swarm_runtime::stalker_agent::StalkerAgent;
use swarm_runtime::weaver_agent::WeaverAgent;
use swarm_runtime::whisker_agent::WhiskerAgent;
use swarm_spine::IncidentStore;
use swarm_whisker::{ProcessStartEvent, TelemetryEvent, TelemetryPayload};

fn is_strategy_scoped_whisker_deposit(agent_id: &str) -> bool {
    agent_id.contains(":whisker-primary:") && agent_id.ends_with("suspicious_process_tree")
}

fn integration_config() -> SwarmConfig {
    SwarmConfig {
        schema_version: 1,
        name: "multi-agent".to_string(),
        description: "multi-agent integration".to_string(),
        runtime: RuntimeSettings {
            mode: RuntimeMode::DetectOnly,
            demo_mode: false,
            telemetry_sources: vec![TelemetrySourceConfig {
                name: "synthetic".to_string(),
                subject: "telemetry.synthetic.process".to_string(),
                bridge: None,
            }],
            max_in_flight_actions: 4,
            drain_timeout_ms: 30_000,
            require_durable_live_response: false,
            max_heap_pressure: 0.90,
            secret_dir: None,
            anti_tamper: Default::default(),
            temporal_event_window: swarm_core::config::TemporalEventWindowConfig::default(),
            agent_tick_timeout_ms: 500,
            governance_degraded_tick_threshold: 3,
            partition_contingency_lease_ttl_ms: 300_000,
            partition_contingency_blast_radius_cap: 1,
            max_dead_letter_bytes: None,
        },
        detection: DetectionConfig {
            strategy: "suspicious_process_tree".to_string(),
            strategies: Vec::new(),
            high_confidence_threshold: 0.9,
            medium_confidence_threshold: 0.7,
            profiles: DetectorProfilesConfig::default(),
        },
        pheromone: PheromoneConfig {
            default_half_life_secs: 3600.0,
            evaporation_threshold: 0.01,
            min_sources_for_escalation: 2,
            alert_threshold: 2.0,
            incident_threshold: 5.0,
            deescalation_cooldown_secs: 300,
            response_playbook: Default::default(),
            backend: PheromoneBackendConfig::InMemory,
        },
        policy: PolicyConfig {
            human_gate_severity: Severity::High,
            lease_ttl_ms: 60_000,
            ..PolicyConfig::default()
        },
        response_adapter: swarm_core::config::ResponseAdapterConfig::Sandbox,
        siem_forward: None,
        notification_channels: std::collections::BTreeMap::new(),
        notification_routing: swarm_core::config::NotificationRoutingConfig::default(),
        audit: AuditConfig {
            bundle_store: BundleStoreConfig::Memory,
            recent_decisions_limit: 20,
        },
        investigation: InvestigationConfig {
            enabled: true,
            worker_count: 1,
            max_pending_jobs: 8,
            time_budget_ms: 250,
            bundle_store: BundleStoreConfig::Memory,
            ..InvestigationConfig::default()
        },
        correlation: CorrelationConfig {
            enabled: true,
            time_window_ms: 300_000,
            min_shared_keys: 1,
            candidate_limit: 32,
            incident_store: BundleStoreConfig::Memory,
        },
        canary: CanaryConfig::default(),
        promotion: PromotionConfig::default(),
        evolution: swarm_core::config::EvolutionConfig::default(),
        deception: swarm_core::config::DeceptionConfig::default(),
        memory: swarm_core::config::MemoryConfig::default(),
        identity: swarm_core::config::IdentityConfig::default(),
        platform_api: Default::default(),
        operator: OperatorSurfaceConfig::default(),
        tls: None,
    }
}

fn suspicious_event(event_id: &str) -> TelemetryEvent {
    TelemetryEvent {
        source: "synthetic".to_string(),
        event_id: event_id.to_string(),
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
    }
}

#[tokio::test]
async fn full_multi_agent_pipeline() -> Result<(), Box<dyn Error>> {
    let config = integration_config();
    let detector = build_composite_detector(&config.detection)?;
    let stack = ConfiguredRuntimeStack::from_config(config.clone(), SummaryInvestigator)?;
    let event = suspicious_event("evt-multi-1");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let detect_agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
    let approval = ApprovalContext {
        live_mode: false,
        receipt_chain: Vec::new(),
        correlation_id: None,
        now_ms: event.timestamp,
    };

    let persisted = stack
        .process_event(
            &detector,
            &event,
            EventExecutionContext {
                agent_id: &detect_agent_id,
                approval: &approval,
                signing_key: &signing_key,
            },
            |_| {
                Some(ResponseAction::DeployDecoy {
                    decoy_type: "honeypot".to_string(),
                    target_zone: "dmz".to_string(),
                })
            },
        )
        .await?;
    assert!(persisted.is_some());

    let (telemetry_tx, telemetry_rx) = tokio::sync::mpsc::channel(8);
    telemetry_tx.send(event.clone()).await?;
    drop(telemetry_tx);

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let health_state = Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new()));
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig {
            tick_interval_ms: 10,
            ..AgentDispatcherConfig::default()
        },
        shutdown_rx,
        stack.substrate.clone(),
        Arc::clone(&health_state),
    );
    dispatcher.register(Box::new(WhiskerAgent::new(
        AgentId::new("whisker", "primary"),
        telemetry_rx,
        Arc::new(detector),
        stack.substrate.clone(),
        config.pheromone.clone(),
    )))?;
    dispatcher.register(Box::new(StalkerAgent::new(
        AgentId::new("stalker", "primary"),
        stack.replay_store.clone(),
        stack.investigation.clone(),
        stack.substrate.clone(),
        config.pheromone.clone(),
    )))?;
    dispatcher.register(Box::new(WeaverAgent::new(
        AgentId::new("weaver", "primary"),
        stack.correlation.clone(),
        stack.investigation_store.clone(),
        stack.incident_store.clone(),
    )))?;

    let handle = tokio::spawn(async move {
        dispatcher.run().await;
    });

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let deposits = stack.substrate.recent_deposits(20).await?;
            let incident = stack.incident_store.load_by_hunt_id("evt-multi-1")?;
            if deposits
                .iter()
                .any(|deposit| deposit.agent_id.0.ends_with(":stalker-primary"))
                && incident.is_some()
            {
                break Ok::<(), Box<dyn Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;

    shutdown_tx.send(true)?;
    tokio::time::timeout(Duration::from_secs(1), handle).await??;

    let deposits = stack.substrate.recent_deposits(20).await?;
    assert!(
        deposits
            .iter()
            .any(|deposit| is_strategy_scoped_whisker_deposit(&deposit.agent_id.0))
    );
    assert!(
        deposits
            .iter()
            .any(|deposit| deposit.agent_id.0.ends_with(":stalker-primary"))
    );
    let incident = stack.incident_store.load_by_hunt_id("evt-multi-1")?;
    assert!(incident.is_some());
    let incident = incident.expect("correlated incident");
    assert!(incident.incident.confidence_score > 0.5);
    assert!(
        incident
            .incident
            .graph_dimensions
            .iter()
            .any(|dimension| matches!(dimension, swarm_spine::IncidentGraphDimension::Entity))
    );
    let status_detector = build_composite_detector(&config.detection)?;
    let status = stack.operator_review_status(&status_detector).await?;
    assert!(status.async_lane.enabled);
    assert!(status.async_lane.recent_investigations >= 1);
    assert_eq!(status.async_lane.recent_incidents, 1);
    assert_eq!(
        status.async_lane.latest_incident_id.as_deref(),
        Some(incident.record.incident_id.as_str())
    );
    assert!(
        status
            .async_lane
            .latest_incident_graph_dimensions
            .iter()
            .any(|dimension| matches!(dimension, swarm_spine::IncidentGraphDimension::Entity))
    );

    Ok(())
}
